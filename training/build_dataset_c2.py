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

# P10 multi-host retrain -- see build_dataset_recon.py's identical section
# for the full rationale.
MULTIHOST_CONN_LOG = REPO_ROOT / "training" / "zeek-logs-multihost" / "conn.log"
MULTIHOST_SCENARIOS_DIR = REPO_ROOT / "training" / "scenarios" / "c2"
MULTIHOST_CAPTURE_DIR = REPO_ROOT / "training" / "capture"
UNSEEN_CSV = REPO_ROOT / "training" / "dataset_c2_unseen.csv"

MAX_OBSERVATIONS = 20    # matches c2.py's own history cap
SNAPSHOT_STEP = 0.22
BOUNDARY_MARGIN = 0.5
SRC_IP = "127.0.0.1"
# Must match capture_c2.py's pools exactly -- see load_conn_events().
# C2_PORT_POOL was moved off 9080-9110 (overlapped live Kafka 9092/9093 --
# see capture_c2.py's note) to a range verified free of any listener.
BENIGN_PORT_POOL = range(8080, 8130)
C2_PORT_POOL = range(19110, 19140)

# 2026-09-12 dataset-plan retrofit: see training/scenarios/c2/README.md.
def _scenario_for(session_id: str) -> tuple[str, str | None]:
    if session_id.startswith("benign_http_"):
        return "c2_benign_http_baseline", None
    if session_id.startswith("benign_"):
        return "c2_benign_baseline", None
    if session_id.startswith("c2_"):
        return "c2_periodic_beacon", "periodic_beacon"
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
        cls = 1 if label_name.startswith("c2") else 0
        sessions.append({
            "session_id": prefix + label_name, "class": cls,
            "start": start["ts"] + BOUNDARY_MARGIN,
            "end": end["ts"] - BOUNDARY_MARGIN,
        })
        i += 2
    return sessions


def load_conn_events(conn_log_path, src_ip, port_pool):
    """Events from src_ip to a destination port in port_pool only -- this
    is a dev machine with plenty of its own ambient 127.0.0.1 traffic
    (dev servers, local DNS) that has nothing to do with this capture and
    would otherwise dominate the sparse beacon-timing history."""
    events = []
    with open(conn_log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if d.get("id.orig_h") != src_ip:
                continue
            if d.get("id.resp_p") not in port_pool:
                continue
            try:
                events.append(float(d["ts"]))
            except (KeyError, ValueError, TypeError):
                continue
    events.sort()
    return events


def load_multihost_scenarios():
    train, unseen = [], []
    for manifest_path in sorted(MULTIHOST_SCENARIOS_DIR.glob("c2_multi_*.json")):
        with open(manifest_path) as f:
            m = json.load(f)
        sessions_path = MULTIHOST_CAPTURE_DIR / f"sessions_c2_{m['scenario_id']}.json"
        if not sessions_path.exists():
            print(f"  WARNING: no sessions file for {m['scenario_id']} -- skipping")
            continue
        entry = {
            "scenario_id": m["scenario_id"], "attack_subtype": m["attack_subtype"],
            "environment": m["environment"], "attacker_ip": m["attacker_ip"],
            "sessions_path": sessions_path,
        }
        (unseen if m.get("split") == "unseen_test" else train).append(entry)
    return train, unseen


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


def rows_for_sessions(sessions, benign_events, c2_events, environment,
                       scenario_override=None, attack_subtype_override=None):
    def events_for(sess):
        return c2_events if sess["class"] == 1 else benign_events

    dropped = sum(1 for s in sessions if not any(s["start"] <= e <= s["end"] for e in events_for(s)))
    if dropped:
        print(f"  NOTE: {dropped}/{len(sessions)} sessions have no matching conn.log entries -- skipped.")

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
                if scenario_override:
                    scenario_id = scenario_override
                    attack_subtype = attack_subtype_override if sess["class"] == 1 else None
                else:
                    scenario_id, attack_subtype = _scenario_for(sess["session_id"])
                row = {"session_id": sess["session_id"], "label": sess["class"], "ts": t,
                       "source": "real", "scenario_id": scenario_id,
                       "attack_subtype": attack_subtype, "label_method": "generator_ground_truth",
                       "environment": environment}
                row.update(stats)
                rows.append(row)
            t += SNAPSHOT_STEP
    return rows, total_real_events


def build():
    # --- Loopback source: reuse the existing committed CSV -- see
    # build_dataset_recon.py's identical note.
    if OUT_CSV.exists():
        existing_df = pd.read_csv(OUT_CSV)
        if "environment" not in existing_df.columns:
            existing_df["environment"] = "loopback"
        rows = existing_df.to_dict("records")
        total_real_events = None  # unknown for reused rows -- honesty check below adapts
        print(f"Loopback: reusing {len(rows)} existing rows from {OUT_CSV} "
              f"(NOT recomputed from conn.log)")
    else:
        sessions = load_sessions(SESSIONS_FILE)
        benign_events = load_conn_events(CONN_LOG, SRC_IP, BENIGN_PORT_POOL)
        c2_events = load_conn_events(CONN_LOG, SRC_IP, C2_PORT_POOL)
        print(f"Loopback: loaded {len(benign_events)} benign-port-pool events, "
              f"{len(c2_events)} c2-port-pool events from {SRC_IP}")
        rows, total_real_events = rows_for_sessions(sessions, benign_events, c2_events, environment="loopback")

    # --- Multi-host sources (P10) ---
    train_scenarios, unseen_scenarios = load_multihost_scenarios()
    print(f"\nMulti-host: {len(train_scenarios)} train/validation scenario(s), "
          f"{len(unseen_scenarios)} unseen_test scenario(s)")
    mh_real_events = 0
    for sc in train_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_benign = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"], BENIGN_PORT_POOL)
        mh_c2 = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"], C2_PORT_POOL)
        sc_rows, sc_events = rows_for_sessions(mh_sessions, mh_benign, mh_c2, environment=sc["environment"],
                                                scenario_override=sc["scenario_id"],
                                                attack_subtype_override=sc["attack_subtype"])
        print(f"  {sc['scenario_id']}: {len(sc_rows)} rows ({sc_events} real events)")
        rows += sc_rows
        mh_real_events += sc_events

    df = pd.DataFrame(rows)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"\nWrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"Sessions: {df['session_id'].nunique()}  |  "
          f"benign rows: {(df['label']==0).sum()}  |  c2 rows: {(df['label']==1).sum()}")
    if total_real_events is not None:
        print(f"\nHONESTY CHECK (loopback + new multihost only, excludes reused-row events): "
              f"{total_real_events + mh_real_events} real connection EVENTS captured, versus "
              f"{len(df)} dense time-snapshot ROWS. Behavioral diversity is bounded by event/session "
              f"count, not row count.")
    else:
        print(f"\nHONESTY CHECK: {mh_real_events} real connection EVENTS captured in this run's new "
              f"multi-host scenarios (loopback rows reused from the existing CSV, not recounted here).")

    unseen_rows = []
    for sc in unseen_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_benign = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"], BENIGN_PORT_POOL)
        mh_c2 = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"], C2_PORT_POOL)
        sc_rows, sc_events = rows_for_sessions(mh_sessions, mh_benign, mh_c2, environment=sc["environment"],
                                                scenario_override=sc["scenario_id"],
                                                attack_subtype_override=sc["attack_subtype"])
        print(f"  UNSEEN {sc['scenario_id']}: {len(sc_rows)} rows ({sc_events} real events)")
        unseen_rows += sc_rows
    if unseen_rows:
        udf = pd.DataFrame(unseen_rows)
        udf.to_csv(UNSEEN_CSV, index=False)
        print(f"Wrote {len(udf)} UNSEEN samples to {UNSEEN_CSV} (never used for training)")


if __name__ == "__main__":
    build()
