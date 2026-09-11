"""
Builds the DDoS classifier dataset from training/capture/sessions_ddos.json
+ training/zeek-logs/conn.log (captured by the isolated zeek_ml_capture
container, see training/capture/docker-compose.yml).

Feature set matches exactly what the real DDoSDetector
(backend/detectors/ddos.py) reads over its 10s rolling window:
  - packet_rate: connections in the trailing WINDOW_SECONDS=10s window.
  - unique_dst_ports, dst_port_entropy.
  - mean_inter_arrival / std_inter_arrival: timing regularity -- a
    programmatic flood's connection timing is far more mechanically
    regular than a human-paced benign session.
Uses backend/detectors/features.py's shannon_entropy/interval_stats
directly (not a re-implementation) so train-time and serve-time feature
math can never drift apart.

2026-09-12 update (PS 26145 gap-closing): unique_src_ips / src_ip_entropy
are now included -- see capture_ddos_udp_spoof.py, which adds real UDP
flood and real hping3 `--rand-source` (genuinely varied, non-local source
addresses) sessions specifically to give this feature real signal, lifting
the original "single test host" constraint that made it zero-variance.
Filtering below is now by DESTINATION (`id.resp_h == TARGET_IP`), not
origin -- a spoofed-source session's events have TARGET_IP as the
destination but a different address on every packet as the origin.

IMPORTANT HONESTY NOTE (matches recon-ml-poc's build_dataset_v3.py): at
this snapshot density, adjacent rows within a session are heavily
autocorrelated. The genuine diversity comes from the number of distinct
sessions, not the row count -- this is exactly why evaluation stays
grouped by session (GroupKFold), never a random row split.

Run: backend/.venv/bin/python3 training/build_dataset_ddos.py
Reads: training/capture/sessions_ddos.json, training/zeek-logs/conn.log
Writes: training/dataset_ddos.csv
"""
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.features import shannon_entropy, interval_stats  # noqa: E402

CONN_LOG = REPO_ROOT / "training" / "zeek-logs" / "conn.log"
SESSIONS_FILE = REPO_ROOT / "training" / "capture" / "sessions_ddos.json"
OUT_CSV = REPO_ROOT / "training" / "dataset_ddos.csv"

WINDOW_SECONDS = 10       # matches ddos.py's WINDOW_SECONDS exactly
SNAPSHOT_STEP = 0.14
BOUNDARY_MARGIN = 0.5
TARGET_IP = "127.0.0.1"   # filter by destination, not origin -- see module docstring


def load_sessions(path):
    with open(path) as f:
        marks = json.load(f)
    sessions = []
    i = 0
    while i < len(marks):
        start, end = marks[i], marks[i + 1]
        label_name = start["label"].replace("_start", "")
        assert end["label"] == label_name + "_end", f"mismatched marks in {path} at {i}"
        cls = 1 if label_name.startswith("ddos") else 0
        sessions.append({
            "session_id": label_name, "class": cls,
            "start": start["ts"] + BOUNDARY_MARGIN,
            "end": end["ts"] - BOUNDARY_MARGIN,
        })
        i += 2
    return sessions


def load_conn_events():
    events = []
    with open(CONN_LOG) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if d.get("id.resp_h") != TARGET_IP:
                continue
            try:
                events.append({
                    "ts": float(d["ts"]),
                    "dst_port": int(d.get("id.resp_p", 0)),
                    "src_ip": d.get("id.orig_h", ""),
                })
            except (KeyError, ValueError, TypeError):
                continue
    events.sort(key=lambda e: e["ts"])
    return events


def features_for_window(window):
    ports = [e["dst_port"] for e in window]
    src_ips = [e["src_ip"] for e in window]
    mean_iat, std_iat = interval_stats(e["ts"] for e in window)
    return {
        "packet_rate": len(window),
        "unique_dst_ports": len(set(ports)),
        "dst_port_entropy": round(shannon_entropy(ports), 4),
        "mean_inter_arrival": round(mean_iat, 4),
        "std_inter_arrival": round(std_iat, 4),
        "unique_src_ips": len(set(src_ips)),
        "src_ip_entropy": round(shannon_entropy(src_ips), 4),
    }


def build():
    sessions = load_sessions(SESSIONS_FILE)
    events = load_conn_events()
    print(f"Loaded {len(events)} connection events targeting {TARGET_IP}")

    dropped = sum(1 for s in sessions if not any(s["start"] <= e["ts"] <= s["end"] for e in events))
    if dropped:
        print(f"NOTE: {dropped}/{len(sessions)} sessions have no matching conn.log entries "
              f"(too short, or log rotation) -- skipped rather than producing empty-window rows.")

    rows = []
    for sess in sessions:
        sess_events = [e for e in events if sess["start"] <= e["ts"] <= sess["end"]]
        if not sess_events:
            continue
        t = sess["start"]
        while t <= sess["end"]:
            window_start = max(sess["start"], t - WINDOW_SECONDS)
            window = [e for e in sess_events if window_start <= e["ts"] <= t]
            if window:
                row = {"session_id": sess["session_id"], "label": sess["class"], "ts": t}
                row.update(features_for_window(window))
                rows.append(row)
            t += SNAPSHOT_STEP

    df = pd.DataFrame(rows)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"Sessions: {df['session_id'].nunique()}  |  "
          f"benign rows: {(df['label']==0).sum()}  |  ddos rows: {(df['label']==1).sum()}")


if __name__ == "__main__":
    build()
