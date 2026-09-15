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

# P10 multi-host retrain -- see build_dataset_recon.py's identical section
# for the full rationale (unseen_test isolated by which file it lands in;
# loopback reused from the existing committed CSV rather than recomputed,
# since training/zeek-logs/conn.log is shared across capture campaigns and
# was confirmed stale for recon on 2026-09-14).
MULTIHOST_CONN_LOG = REPO_ROOT / "training" / "zeek-logs-multihost" / "conn.log"
MULTIHOST_SCENARIOS_DIR = REPO_ROOT / "training" / "scenarios" / "ddos"
MULTIHOST_CAPTURE_DIR = REPO_ROOT / "training" / "capture"
UNSEEN_CSV = REPO_ROOT / "training" / "dataset_ddos_unseen.csv"

WINDOW_SECONDS = 10       # matches ddos.py's WINDOW_SECONDS exactly
SNAPSHOT_STEP = 0.14
BOUNDARY_MARGIN = 0.5
TARGET_IP = "127.0.0.1"   # filter by destination, not origin -- see module docstring

# 2026-09-12 dataset-plan retrofit: every row now carries provenance/subtype
# columns keyed to a manifest in training/scenarios/ddos/ -- see that
# directory's README.md for the schema. All ddos scenarios are real
# (hping3/TCP connect() capture), never synthetic.
def _scenario_for(session_id: str) -> tuple[str, str | None]:
    """(scenario_id, attack_subtype) for a session_id -- longer/more
    specific prefixes checked first since e.g. "benign_" is a prefix of
    "benign_udpspoof_"."""
    if session_id.startswith("benign_udpspoof_"):
        return "ddos_benign_udpspoof_baseline", None
    if session_id.startswith("benign_http_"):
        return "ddos_benign_http_baseline", None
    if session_id.startswith("benign_"):
        return "ddos_benign_baseline", None
    if session_id.startswith("ddos_udpflood_"):
        return "ddos_udp_flood", "udp_flood"
    if session_id.startswith("ddos_spoofed_"):
        return "ddos_spoofed_source", "spoofed_source"
    if session_id.startswith("ddos_"):
        return "ddos_syn_flood", "syn_flood"
    raise ValueError(f"no scenario mapping for session_id={session_id!r}")


def load_sessions(path, prefix=""):
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
            "session_id": prefix + label_name, "class": cls,
            "start": start["ts"] + BOUNDARY_MARGIN,
            "end": end["ts"] - BOUNDARY_MARGIN,
        })
        i += 2
    return sessions


def load_conn_events(conn_log_path, target_ips):
    """target_ips: iterable of destination IPs to match (a single-IP set
    for the loopback default; multiple for e.g. ddos_multi_01's 2-victim
    fan-out). Filters by DESTINATION, not origin -- see module docstring
    on spoofed-source floods varying id.orig_h, never id.resp_h."""
    target_ips = set(target_ips)
    events = []
    with open(conn_log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if d.get("id.resp_h") not in target_ips:
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


def load_multihost_scenarios():
    train, unseen = [], []
    for manifest_path in sorted(MULTIHOST_SCENARIOS_DIR.glob("ddos_multi_*.json")):
        with open(manifest_path) as f:
            m = json.load(f)
        sessions_path = MULTIHOST_CAPTURE_DIR / f"sessions_ddos_{m['scenario_id']}.json"
        if not sessions_path.exists():
            print(f"  WARNING: no sessions file for {m['scenario_id']} -- skipping")
            continue
        entry = {
            "scenario_id": m["scenario_id"], "attack_subtype": m["attack_subtype"],
            "environment": m["environment"], "victim_ips": m["victim_ips"],
            "sessions_path": sessions_path,
        }
        (unseen if m.get("split") == "unseen_test" else train).append(entry)
    return train, unseen


def rows_for_sessions(sessions, events, environment, scenario_override=None, attack_subtype_override=None):
    rows = []
    dropped = sum(1 for s in sessions if not any(s["start"] <= e["ts"] <= s["end"] for e in events))
    if dropped:
        print(f"  NOTE: {dropped}/{len(sessions)} sessions have no matching conn.log entries -- skipped.")
    for sess in sessions:
        sess_events = [e for e in events if sess["start"] <= e["ts"] <= sess["end"]]
        if not sess_events:
            continue
        t = sess["start"]
        while t <= sess["end"]:
            window_start = max(sess["start"], t - WINDOW_SECONDS)
            window = [e for e in sess_events if window_start <= e["ts"] <= t]
            if window:
                if scenario_override:
                    scenario_id = scenario_override
                    attack_subtype = attack_subtype_override if sess["class"] == 1 else None
                else:
                    scenario_id, attack_subtype = _scenario_for(sess["session_id"])
                row = {"session_id": sess["session_id"], "label": sess["class"], "ts": t,
                       "source": "real", "scenario_id": scenario_id,
                       "attack_subtype": attack_subtype, "label_method": "generator_ground_truth",
                       "environment": environment}
                row.update(features_for_window(window))
                rows.append(row)
            t += SNAPSHOT_STEP
    return rows


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
    # --- Loopback source: reuse the existing committed CSV, don't
    # recompute from conn.log -- see build_dataset_recon.py's identical
    # note (2026-09-14 finding: the shared conn.log is stale/overwritten).
    if OUT_CSV.exists():
        existing_df = pd.read_csv(OUT_CSV)
        if "environment" not in existing_df.columns:
            existing_df["environment"] = "loopback"
        rows = existing_df.to_dict("records")
        print(f"Loopback: reusing {len(rows)} existing rows from {OUT_CSV} "
              f"(NOT recomputed from conn.log)")
    else:
        sessions = load_sessions(SESSIONS_FILE)
        events = load_conn_events(CONN_LOG, [TARGET_IP])
        print(f"Loopback: loaded {len(events)} connection events targeting {TARGET_IP}")
        rows = rows_for_sessions(sessions, events, environment="loopback")

    # --- Multi-host sources (P10) ---
    train_scenarios, unseen_scenarios = load_multihost_scenarios()
    print(f"\nMulti-host: {len(train_scenarios)} train/validation scenario(s), "
          f"{len(unseen_scenarios)} unseen_test scenario(s)")
    for sc in train_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_events = load_conn_events(MULTIHOST_CONN_LOG, sc["victim_ips"])
        sc_rows = rows_for_sessions(mh_sessions, mh_events, environment=sc["environment"],
                                     scenario_override=sc["scenario_id"],
                                     attack_subtype_override=sc["attack_subtype"])
        print(f"  {sc['scenario_id']}: {len(sc_rows)} rows")
        rows += sc_rows

    df = pd.DataFrame(rows)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"\nWrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"Sessions: {df['session_id'].nunique()}  |  "
          f"benign rows: {(df['label']==0).sum()}  |  ddos rows: {(df['label']==1).sum()}")

    unseen_rows = []
    for sc in unseen_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_events = load_conn_events(MULTIHOST_CONN_LOG, sc["victim_ips"])
        sc_rows = rows_for_sessions(mh_sessions, mh_events, environment=sc["environment"],
                                     scenario_override=sc["scenario_id"],
                                     attack_subtype_override=sc["attack_subtype"])
        print(f"  UNSEEN {sc['scenario_id']}: {len(sc_rows)} rows")
        unseen_rows += sc_rows
    if unseen_rows:
        udf = pd.DataFrame(unseen_rows)
        udf.to_csv(UNSEEN_CSV, index=False)
        print(f"Wrote {len(udf)} UNSEEN samples to {UNSEEN_CSV} (never used for training)")


if __name__ == "__main__":
    build()
