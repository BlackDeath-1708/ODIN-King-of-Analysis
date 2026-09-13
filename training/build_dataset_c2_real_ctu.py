"""
Builds REAL malicious C2-beaconing rows from CTU-13 (Stratosphere Lab)
malware-capture scenarios -- the C2 detector's dataset was, until now,
100% self-generated (see docs/baselines/2026-09-12/BASELINE_SUMMARY.md).
Sibling to build_dataset_tls_seq.py's real-evidence arm: same
ground-truth-5-tuple-matching approach, applied to conn.log timing instead
of packet sequences.

Feature computation reuses build_dataset_c2.py's stats_for() directly, so
this stays comparable to the synthetic dataset it will eventually be
merged into -- see merge step in training/scenarios/c2/README.md once run.

Deliberately writes to its OWN output file (dataset_c2_real_ctu.csv), NOT
dataset_c2.csv -- the fresh-recapture rebuild in progress at the time this
was written will regenerate dataset_c2.csv from scratch and would clobber
anything appended here directly. Merge happens as an explicit later step.

Label file format note: CTU-13 scenarios are NOT all the same binetflow
column layout -- Botnet-42's label file is the classic no-header argus
binetflow (positional columns), but Scenario 48's is the newer
"2format" export (header row present, different column order entirely:
SrcAddr,DstAddr,Proto,Sport,Dport,...,Label). This script parses by
COLUMN NAME (csv.DictReader) for exactly that reason -- a positional
parser tuned for one format would silently misread the other.

Run: backend/.venv/bin/python3 training/build_dataset_c2_real_ctu.py
Reads: training/zeek-logs-tls-malicious/<scenario>/conn.log,
       training/malicious_pcaps_raw/<scenario>_labels_botnet_only.csv
Writes: training/dataset_c2_real_ctu.csv
"""
import csv
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "training"))

from build_dataset_c2 import stats_for  # noqa: E402 -- exact feature parity

MALICIOUS_ROOT = REPO_ROOT / "training" / "zeek-logs-tls-malicious"
LABELS_DIR = REPO_ROOT / "training" / "malicious_pcaps_raw"
OUT_CSV = REPO_ROOT / "training" / "dataset_c2_real_ctu.csv"

MAX_OBSERVATIONS = 20     # matches c2.py's own history cap / build_dataset_c2.py
SNAPSHOT_STEP = 0.22
MIN_EVENTS = 3            # matches stats_for()'s own floor

# Manual scenario -> (label file, header format). "2format" = new export
# with a header row and SrcAddr/DstAddr/Sport/Dport/Label columns; classic
# argus binetflow (no header) is not handled here since no scenario using
# it has been added for C2 yet -- add a format branch if one is.
SCENARIOS = {
    "sogou48": "sogou48_labels_botnet_only.csv",
    "rbot52": "rbot52_labels_botnet_only.csv",
}


def _load_jsonl_by_field(path: Path):
    with open(path) as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _load_botnet_triples_2format(label_csv: Path) -> set:
    """(src_ip, dst_ip, dst_port) triples from a "2format" CTU-13 label
    file -- deliberately drops the ephemeral source port that a strict
    5-tuple match would require. argus (which produced these labels) and
    Zeek (which produced conn.log) split/account for flows differently,
    so the exact ephemeral sport frequently disagrees between the two
    tools for the SAME real connection -- verified on rbot52: all 3
    labeled bot IPs are present in conn.log, but 0/21 5-tuple-exact
    matches met the >=3-event bar, while the (src,dst,dport) triple --
    the actual C2-channel identity (who, talks to which server, on which
    port) -- is stable across both tools' accounting."""
    triples = set()
    with open(label_csv, newline="") as f:
        for row in csv.DictReader(f):
            label = row.get("Label", "")
            if "botnet" not in label.lower():
                continue
            try:
                src, dst, dport = row["SrcAddr"], row["DstAddr"], int(row["Dport"])
            except (KeyError, ValueError):
                continue
            triples.add((src, dst, dport))
    return triples


def build_real_rows_for_scenario(scenario: str, label_file: str) -> list:
    conn_log = MALICIOUS_ROOT / scenario / "conn.log"
    botnet_triples = _load_botnet_triples_2format(LABELS_DIR / label_file)
    print(f"[{scenario}] {len(botnet_triples)} ground-truth Botnet (src,dst,dport) triples loaded")

    matched_events = []
    total = 0
    for d in _load_jsonl_by_field(conn_log):
        total += 1
        key = (d.get("id.orig_h"), d.get("id.resp_h"), d.get("id.resp_p"))
        if key not in botnet_triples:
            continue
        try:
            ts = float(d["ts"])
        except (KeyError, ValueError, TypeError):
            continue
        matched_events.append({
            "ts": ts, "orig_h": d.get("id.orig_h"),
            "resp_h": d.get("id.resp_h"), "resp_p": d.get("id.resp_p"),
        })
    print(f"[{scenario}] conn.log: {total} total connections, "
          f"{len(matched_events)} matched to ground-truth Botnet 5-tuples")

    groups = {}
    for e in matched_events:
        key = (e["orig_h"], e["resp_h"], e["resp_p"])
        groups.setdefault(key, []).append(e["ts"])

    rows = []
    for (orig_h, resp_h, resp_p), timestamps in groups.items():
        timestamps = sorted(timestamps)
        if len(timestamps) < MIN_EVENTS:
            continue
        session_id = f"c2_real_{scenario}_{orig_h}_{resp_h}_{resp_p}"
        t = timestamps[0]
        while t <= timestamps[-1]:
            history = [ts for ts in timestamps if ts <= t][-MAX_OBSERVATIONS:]
            stats = stats_for(history)
            if stats:
                rows.append({
                    "session_id": session_id, "label": 1, "ts": t,
                    "source": "real_public_dataset",
                    "scenario_id": f"c2_real_ctu13_{scenario}",
                    "attack_subtype": "periodic_beacon",
                    "label_method": "dataset_ground_truth",
                    **stats,
                })
            t += SNAPSHOT_STEP
        print(f"[{scenario}]   group {orig_h}->{resp_h}:{resp_p}: "
              f"{len(timestamps)} real events over {timestamps[-1]-timestamps[0]:.0f}s")

    return rows


def build() -> None:
    all_rows = []
    for scenario, label_file in SCENARIOS.items():
        if not (MALICIOUS_ROOT / scenario / "conn.log").exists():
            print(f"[{scenario}] conn.log not found -- skipping (run build_malicious_pcap_logs.py first)")
            continue
        all_rows.extend(build_real_rows_for_scenario(scenario, label_file))

    df = pd.DataFrame(all_rows)
    df.to_csv(OUT_CSV, index=False)
    print(f"\nWrote {len(df)} REAL malicious C2 rows to {OUT_CSV} "
          f"({df['session_id'].nunique() if len(df) else 0} distinct (src,dst,port) groups)")


if __name__ == "__main__":
    build()
