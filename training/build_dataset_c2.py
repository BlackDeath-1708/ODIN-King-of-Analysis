"""
Builds the C2 beaconing classifier dataset from
training/capture/sessions_c2.json + training/zeek-logs/conn.log (isolated
zeek_ml_capture container).

Feature set matches exactly what the real C2Detector
(backend/detectors/c2.py) computes per (src, dst, dst_port) key:
observation_count, mean_interval, std_interval, cv -- capped at the same
20 most-recent observations the real detector keeps.

Both session types target a single fixed (host, port) for their entire
duration (see capture/capture_c2.py), so there is no unique-ports/hosts
feature to compute here -- it would be a constant (=1) by construction,
which is the whole point of isolating the timing-regularity signal
cleanly from the recon detector's fan-out signal.

IMPORTANT HONESTY NOTE, stronger than for ddos/recon: C2 beaconing is a
genuinely low-frequency signal -- real wall-clock time must pass between
each beacon (seconds), unlike recon/ddos where dozens of real connection
events can occur within a fraction of a second. Dense time-snapshotting
is still applied to reach a usable row count, but most of those rows are
IDENTICAL feature vectors repeated at every tick between two real
beacons, since nothing about the (mean/std/cv/count) state changes until
the next actual connection arrives. The genuine information content is
bounded by the number of real connection EVENTS captured, not the row
count -- this script prints both counts explicitly so the gap is visible.

Run: backend/.venv/bin/python3 training/build_dataset_c2.py
Reads: training/capture/sessions_c2.json, training/zeek-logs/conn.log
Writes: training/dataset_c2.csv
"""
import json
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
CONN_LOG = REPO_ROOT / "training" / "zeek-logs" / "conn.log"
SESSIONS_FILE = REPO_ROOT / "training" / "capture" / "sessions_c2.json"
OUT_CSV = REPO_ROOT / "training" / "dataset_c2.csv"

MAX_OBSERVATIONS = 20    # matches c2.py's own history cap
SNAPSHOT_STEP = 0.22
BOUNDARY_MARGIN = 0.5
SRC_IP = "127.0.0.1"
# Must match capture_c2.py's pools exactly -- see load_conn_events().
# C2_PORT_POOL was moved off 9080-9110 (overlapped live Kafka 9092/9093 --
# see capture_c2.py's note) to a range verified free of any listener.
BENIGN_PORT_POOL = range(8080, 8130)
C2_PORT_POOL = range(19110, 19140)


def load_sessions(path):
    with open(path) as f:
        marks = json.load(f)
    sessions = []
    i = 0
    while i < len(marks):
        start, end = marks[i], marks[i + 1]
        label_name = start["label"].replace("_start", "")
        assert end["label"] == label_name + "_end", f"mismatched marks in {path} at {i}"
        cls = 1 if label_name.startswith("c2") else 0
        sessions.append({
            "session_id": label_name, "class": cls,
            "start": start["ts"] + BOUNDARY_MARGIN,
            "end": end["ts"] - BOUNDARY_MARGIN,
        })
        i += 2
    return sessions


def load_conn_events(port_pool):
    """Events from SRC_IP to a destination port in port_pool only -- this
    is a dev machine with plenty of its own ambient 127.0.0.1 traffic
    (dev servers, local DNS) that has nothing to do with this capture and
    would otherwise dominate the sparse beacon-timing history."""
    events = []
    with open(CONN_LOG) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if d.get("id.orig_h") != SRC_IP:
                continue
            if d.get("id.resp_p") not in port_pool:
                continue
            try:
                events.append(float(d["ts"]))
            except (KeyError, ValueError, TypeError):
                continue
    events.sort()
    return events


def stats_for(timestamps):
    if len(timestamps) < 3:
        return None
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    n = len(intervals)
    mean = sum(intervals) / n
    variance = sum((x - mean) ** 2 for x in intervals) / n
    std = variance ** 0.5
    cv = std / mean if mean > 0 else float("inf")
    return {
        "observation_count": len(timestamps),
        "mean_interval": round(mean, 4),
        "std_interval": round(std, 4),
        "cv": round(cv, 4),
    }


def build():
    sessions = load_sessions(SESSIONS_FILE)
    benign_events = load_conn_events(BENIGN_PORT_POOL)
    c2_events = load_conn_events(C2_PORT_POOL)
    print(f"Loaded {len(benign_events)} benign-port-pool events, "
          f"{len(c2_events)} c2-port-pool events from {SRC_IP}")

    def events_for(sess):
        return c2_events if sess["class"] == 1 else benign_events

    dropped = sum(1 for s in sessions if not any(s["start"] <= e <= s["end"] for e in events_for(s)))
    if dropped:
        print(f"NOTE: {dropped}/{len(sessions)} sessions have no matching conn.log entries -- skipped.")

    rows = []
    total_real_events = 0
    for sess in sessions:
        sess_events = sorted(e for e in events_for(sess) if sess["start"] <= e <= sess["end"])
        if not sess_events:
            continue
        total_real_events += len(sess_events)
        t = sess["start"]
        while t <= sess["end"]:
            history = [e for e in sess_events if e <= t][-MAX_OBSERVATIONS:]
            stats = stats_for(history)
            if stats:
                row = {"session_id": sess["session_id"], "label": sess["class"], "ts": t}
                row.update(stats)
                rows.append(row)
            t += SNAPSHOT_STEP

    df = pd.DataFrame(rows)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"Sessions: {df['session_id'].nunique()}  |  "
          f"benign rows: {(df['label']==0).sum()}  |  c2 rows: {(df['label']==1).sum()}")
    print(f"\nHONESTY CHECK: {total_real_events} real connection EVENTS were captured across all "
          f"sessions, versus {len(df)} dense time-snapshot ROWS in the CSV above. Each real event "
          f"is repeated across ~{len(df) / max(total_real_events, 1):.0f} rows on average until "
          f"the next event arrives -- the dataset's genuine behavioral diversity is bounded by the "
          f"event count and the {df['session_id'].nunique()} session count, not by the row count.")


if __name__ == "__main__":
    build()
