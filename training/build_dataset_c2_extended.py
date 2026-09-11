"""
Builds the C2 range-extension rows (see capture/capture_c2_extended.py,
ML_MODELS.md's "C2's range gate" section) from
training/capture/sessions_c2_extended.json + the isolated
training/zeek-logs-c2ext/conn.log, and appends them onto
training/dataset_c2_original.csv -- writing the combined result to
training/dataset_c2.csv.

Why a separate script instead of teaching build_dataset_c2.py to read two
conn.log sources: an earlier attempt at exactly that (this session) turned
out unsafe in practice. training/zeek-logs/conn.log is a single,
ever-growing file shared across every ddos/recon/c2/tls/quic capture
campaign this project has ever run (see ML_MODELS.md's capture history);
several later, unrelated campaigns reused the same Zeek container/log path
after the original C2 dataset was already built and committed, and at some
point the raw conn.log evidence underlying the ORIGINAL C2 sessions'
timestamp windows was silently overwritten -- discovered when a from-
scratch rebuild found 0 matching events on the C2 port pool in the current
file. training/dataset_c2_original.csv is a frozen snapshot of the
already-validated, git-committed 16,262-row dataset (taken before this
extension), so this script never depends on that raw evidence still being
recoverable -- it only ever needs the ORIGINAL csv (a durable derived
artifact) plus the EXTENSION capture's own isolated, never-shared conn.log.

Feature set and computation (stats_for, snapshot step, boundary margin)
match build_dataset_c2.py exactly -- see that file for the full rationale.

Run: backend/.venv/bin/python3 training/build_dataset_c2_extended.py
Reads: training/dataset_c2_original.csv, training/capture/sessions_c2_extended.json,
       training/zeek-logs-c2ext/conn.log
Writes: training/dataset_c2.csv (original rows + extended rows)
"""
import json
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
ORIGINAL_CSV = REPO_ROOT / "training" / "dataset_c2_original.csv"
CONN_LOG = REPO_ROOT / "training" / "zeek-logs-c2ext" / "conn.log"
SESSIONS_FILE = REPO_ROOT / "training" / "capture" / "sessions_c2_extended.json"
OUT_CSV = REPO_ROOT / "training" / "dataset_c2.csv"

MAX_OBSERVATIONS = 20    # matches c2.py's own history cap
SNAPSHOT_STEP = 0.22
BOUNDARY_MARGIN = 0.5
SRC_IP = "127.0.0.1"
# Same pools as capture_c2.py/capture_c2_extended.py -- safe to reuse here
# since this conn.log is isolated to only this extension capture.
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
    original_df = pd.read_csv(ORIGINAL_CSV)
    print(f"Original dataset: {len(original_df)} rows, {original_df['session_id'].nunique()} sessions")

    sessions = load_sessions(SESSIONS_FILE)
    benign_events = load_conn_events(BENIGN_PORT_POOL)
    c2_events = load_conn_events(C2_PORT_POOL)
    print(f"Extension capture: loaded {len(benign_events)} benign-port-pool events, "
          f"{len(c2_events)} c2-port-pool events from {SRC_IP}")

    def events_for(sess):
        return c2_events if sess["class"] == 1 else benign_events

    dropped = sum(1 for s in sessions if not any(s["start"] <= e <= s["end"] for e in events_for(s)))
    if dropped:
        print(f"NOTE: {dropped}/{len(sessions)} extended sessions have no matching conn.log entries -- skipped.")

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

    extended_df = pd.DataFrame(rows)
    print(f"Extension dataset: {len(extended_df)} rows, {extended_df['session_id'].nunique()} sessions "
          f"({total_real_events} real connection events)")

    combined_df = pd.concat([original_df, extended_df], ignore_index=True)
    combined_df.to_csv(OUT_CSV, index=False)
    print(f"\nWrote {len(combined_df)} total rows to {OUT_CSV} "
          f"({combined_df['session_id'].nunique()} sessions: "
          f"{original_df['session_id'].nunique()} original + {extended_df['session_id'].nunique()} extended)")
    print(f"benign rows: {(combined_df['label']==0).sum()}  |  c2 rows: {(combined_df['label']==1).sum()}")

    # Blind-spot check, same as train_c2.py's -- run here too so the effect
    # of the extension is visible immediately, before even retraining.
    high_count = combined_df[combined_df["observation_count"] >= 12]
    print(f"\n[blind-spot check] observation_count>=12: {len(high_count)} rows, "
          f"labels present: {sorted(high_count['label'].unique())}")
    high_interval = combined_df[combined_df["mean_interval"] > 7.0]
    print(f"[blind-spot check] mean_interval>7.0: {len(high_interval)} rows, "
          f"labels present: {sorted(high_interval['label'].unique())}")


if __name__ == "__main__":
    build()
