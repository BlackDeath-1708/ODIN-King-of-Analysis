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

# P10 (multi-host retrain, ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md
# Phase 11): the 19 P5-P8 scenario manifests each carry their own split
# ("train"/"validation"/"unseen_test", added in P9) -- unseen_test rows go
# to a SEPARATE csv (never read by train_recon.py) rather than a filtered
# column in the same file, so the P9 isolation requirement is enforced by
# which file exists, not by remembering to filter a column correctly.
MULTIHOST_CONN_LOG = REPO_ROOT / "training" / "zeek-logs-multihost" / "conn.log"
MULTIHOST_SCENARIOS_DIR = REPO_ROOT / "training" / "scenarios" / "recon"
MULTIHOST_CAPTURE_DIR = REPO_ROOT / "training" / "capture"
UNSEEN_CSV = REPO_ROOT / "training" / "dataset_recon_unseen.csv"

WINDOW_SECONDS = 60       # matches recon.py's WINDOW_SECONDS exactly
SNAPSHOT_STEP = 0.15
BOUNDARY_MARGIN = 1.0
SRC_IP = "127.0.0.1"

# 2026-09-12 dataset-plan retrofit: see training/scenarios/recon/README.md.
def _scenario_for(session_id: str) -> tuple[str, str | None]:
    if session_id.startswith("benign_http_"):
        return "recon_benign_http_baseline", None
    if session_id.startswith("benign_"):
        return "recon_benign_baseline", None
    if session_id.startswith("recon_"):
        return "recon_port_scan", "port_scan"
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
        cls = 1 if label_name.startswith("recon") else 0
        sessions.append({
            # prefix disambiguates session_id across multiple multihost
            # scenario sessions files -- every one reuses names like
            # "recon_0"/"benign_3", which would silently collide (and break
            # GroupKFold grouping) without it. Loopback keeps prefix="".
            "session_id": prefix + label_name, "class": cls,
            "start": start["ts"] + BOUNDARY_MARGIN,
            "end": end["ts"] - BOUNDARY_MARGIN,
        })
        i += 2
    return sessions


def load_conn_events(conn_log_path, src_ip):
    events = []
    with open(conn_log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if d.get("id.orig_h") != src_ip:
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


def load_multihost_scenarios():
    """Returns (train_and_validation, unseen_test) -- each a list of dicts
    with scenario_id/attack_subtype/environment/attacker_ip/sessions_path,
    read from every training/scenarios/recon/recon_multi_*.json manifest.
    Split into two return values (rather than one list with a split field
    the caller must remember to filter) so a caller can't accidentally
    merge unseen_test into the training set by forgetting a filter step."""
    train, unseen = [], []
    for manifest_path in sorted(MULTIHOST_SCENARIOS_DIR.glob("recon_multi_*.json")):
        with open(manifest_path) as f:
            m = json.load(f)
        sessions_path = MULTIHOST_CAPTURE_DIR / f"sessions_recon_{m['scenario_id']}.json"
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


def rows_for_sessions(sessions, events, environment, scenario_override=None, attack_subtype_override=None):
    """Shared session-windowing + feature-extraction loop, used for both the
    loopback source and every multihost scenario -- identical math to the
    original single-source build(), just parameterized so it can run once
    per source instead of being hand-copied for multihost."""
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
    # --- Loopback source: reuse the EXISTING committed dataset_recon.csv
    # rather than recomputing from conn.log. training/zeek-logs/conn.log is
    # a single file shared across every ddos/recon/c2/tls/quic capture
    # campaign this project has run (the exact same root cause
    # SCALING_BACKLOG.md documents for C2's raw evidence) and has since
    # been overwritten by later, unrelated campaigns -- confirmed live
    # 2026-09-14: recomputing from the CURRENT conn.log produced only 1,687
    # loopback rows versus the existing committed file's 17,760, a ~90%
    # data loss that would have silently destroyed already-validated real
    # capture data if merged in. The existing CSV is the authoritative
    # record of that capture; only NEW multihost rows are computed fresh.
    if OUT_CSV.exists():
        existing_df = pd.read_csv(OUT_CSV)
        if "environment" not in existing_df.columns:
            existing_df["environment"] = "loopback"
        rows = existing_df.to_dict("records")
        print(f"Loopback: reusing {len(rows)} existing rows from {OUT_CSV} "
              f"(NOT recomputed from conn.log -- see build()'s docstring note "
              f"on conn.log staleness)")
    else:
        sessions = load_sessions(SESSIONS_FILE)
        events = load_conn_events(CONN_LOG, SRC_IP)
        print(f"Loopback: loaded {len(events)} connection events from {SRC_IP}")
        rows = rows_for_sessions(sessions, events, environment="loopback")

    # --- Multi-host sources (P10) ---
    train_scenarios, unseen_scenarios = load_multihost_scenarios()
    print(f"\nMulti-host: {len(train_scenarios)} train/validation scenario(s), "
          f"{len(unseen_scenarios)} unseen_test scenario(s)")
    for sc in train_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_events = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"])
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
          f"benign rows: {(df['label']==0).sum()}  |  recon rows: {(df['label']==1).sum()}")

    # --- Unseen test scenarios: written separately, never merged into OUT_CSV ---
    unseen_rows = []
    for sc in unseen_scenarios:
        mh_sessions = load_sessions(sc["sessions_path"], prefix=f"{sc['scenario_id']}__")
        mh_events = load_conn_events(MULTIHOST_CONN_LOG, sc["attacker_ip"])
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
