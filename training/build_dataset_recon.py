"""
Builds the recon classifier dataset from training/capture/sessions_recon.json
+ training/zeek-logs/conn.log (isolated zeek_ml_capture container).

Feature set matches exactly what the real ReconDetector
(backend/detectors/recon.py) reads over its 60s per-source window:
unique_ports, unique_hosts, connection_count, port_entropy,
port_range_span, mean_inter_arrival, std_inter_arrival. Uses
backend/detectors/features.py's shannon_entropy/interval_stats directly
so train-time and serve-time feature math can never drift apart.

IMPORTANT HONESTY NOTE (see ML_MODELS.md): at this snapshot density,
adjacent rows within a session are heavily autocorrelated -- the genuine
diversity comes from the number of distinct sessions (varied port
ranges/rates/durations), not the row count. Evaluation stays grouped by
session (GroupKFold), never a random row split.

Run: backend/.venv/bin/python3 training/build_dataset_recon.py
Reads: training/capture/sessions_recon.json, training/zeek-logs/conn.log
Writes: training/dataset_recon.csv
"""
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.features import shannon_entropy, interval_stats  # noqa: E402

CONN_LOG = REPO_ROOT / "training" / "zeek-logs" / "conn.log"
SESSIONS_FILE = REPO_ROOT / "training" / "capture" / "sessions_recon.json"
OUT_CSV = REPO_ROOT / "training" / "dataset_recon.csv"

WINDOW_SECONDS = 60       # matches recon.py's WINDOW_SECONDS exactly
SNAPSHOT_STEP = 0.15
BOUNDARY_MARGIN = 1.0
SRC_IP = "127.0.0.1"


def load_sessions(path):
    with open(path) as f:
        marks = json.load(f)
    sessions = []
    i = 0
    while i < len(marks):
        start, end = marks[i], marks[i + 1]
        label_name = start["label"].replace("_start", "")
        assert end["label"] == label_name + "_end", f"mismatched marks in {path} at {i}"
        cls = 1 if label_name.startswith("recon") else 0
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
            if d.get("id.orig_h") != SRC_IP:
                continue
            try:
                events.append({
                    "ts": float(d["ts"]),
                    "dst_ip": d.get("id.resp_h", ""),
                    "dst_port": int(d.get("id.resp_p", 0)),
                })
            except (KeyError, ValueError, TypeError):
                continue
    events.sort(key=lambda e: e["ts"])
    return events


def features_for_window(window):
    ports = [e["dst_port"] for e in window]
    hosts = [e["dst_ip"] for e in window]
    mean_iat, std_iat = interval_stats(e["ts"] for e in window)
    return {
        "unique_ports": len(set(ports)),
        "unique_hosts": len(set(hosts)),
        "connection_count": len(window),
        "port_entropy": round(shannon_entropy(ports), 4),
        "port_range_span": (max(ports) - min(ports)) if ports else 0,
        "mean_inter_arrival": round(mean_iat, 4),
        "std_inter_arrival": round(std_iat, 4),
    }


def build():
    sessions = load_sessions(SESSIONS_FILE)
    events = load_conn_events()
    print(f"Loaded {len(events)} connection events from {SRC_IP}")

    dropped = sum(1 for s in sessions if not any(s["start"] <= e["ts"] <= s["end"] for e in events))
    if dropped:
        print(f"NOTE: {dropped}/{len(sessions)} sessions have no matching conn.log entries -- skipped.")

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
          f"benign rows: {(df['label']==0).sum()}  |  recon rows: {(df['label']==1).sum()}")


if __name__ == "__main__":
    build()
