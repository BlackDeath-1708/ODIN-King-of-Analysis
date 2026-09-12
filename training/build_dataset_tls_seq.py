"""
Builds the Tier-2 seq-CNN dataset (backend/detectors/tier2_model.py):
raw pkt_sizes/pkt_gaps sequences, NOT the scalar aggregates
train_tls_flow.py/build_dataset_tls.py use. Sibling to build_dataset_tls.py,
does not modify it.

  - BENIGN (label=0): REAL, from training/zeek-logs-tls/pkt_seq.log (the
    same real HTTPS/QUIC captures build_dataset_tls.py already uses).
  - MALICIOUS (label=1): two provenance arms, kept side by side via the
    `provenance` column rather than one replacing the other:
      "real" -- from training/zeek-logs-tls-malicious/<scenario>/, produced
        by training/build_malicious_pcap_logs.py from a real malware pcap
        (currently CTU-13 scenario botnet42/Neris -- see SCENARIO_LABELS
        below), filtered down to only the 5-tuples that scenario's own
        ground-truth argus labels call "Botnet" (not Normal/Background).
      "synthetic" -- the existing beacon/bulk-upload generator, imported
        from build_dataset_tls.py rather than duplicated.
  This split is the built-in sanity check train_tier2.py uses: a model that
  scores well only on "synthetic" and collapses on "real" has learned the
  generator's artifacts, not real malicious behavior.

Run: backend/.venv/bin/python3 training/build_dataset_tls_seq.py
Reads: training/zeek-logs-tls/pkt_seq.log,
       training/zeek-logs-tls-malicious/<scenario>/{conn,ssl,pkt_seq}.log,
       training/malicious_pcaps_raw/<scenario>_labels_botnet_only.csv
Writes: training/dataset_tls_seq.npz
"""
import csv
import json
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.tier2_features import pack_sequence  # noqa: E402

from build_dataset_tls import _synth_beacon_pktseq, _synth_bulk_pktseq  # noqa: E402

BENIGN_LOG_DIR = REPO_ROOT / "training" / "zeek-logs-tls"
MALICIOUS_ROOT = REPO_ROOT / "training" / "zeek-logs-tls-malicious"
LABELS_DIR = REPO_ROOT / "training" / "malicious_pcaps_raw"
OUT_NPZ = REPO_ROOT / "training" / "dataset_tls_seq.npz"

# Manual scenario -> ground-truth-labels-file mapping. Each new scenario
# training/build_malicious_pcap_logs.py processes needs one entry here --
# deliberately not auto-discovered, since the label file format/columns
# aren't guaranteed identical across every public source (CTU-13 argus
# binetflow vs a malware-traffic-analysis.net write-up, say).
SCENARIO_LABELS = {
    "botnet42_neris": "botnet42_labels_botnet_only.csv",
}

random_synth_n = 4000  # matches build_dataset_tls.py's rough real/synthetic balance intent


def _load_jsonl_by_uid(path: Path) -> dict:
    out = {}
    if not path.exists():
        return out
    with open(path) as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            uid = d.get("uid")
            if uid:
                out[uid] = d
    return out


def build_benign_rows() -> list:
    pktseq_by_uid = _load_jsonl_by_uid(BENIGN_LOG_DIR / "pkt_seq.log")
    ssl_by_uid = _load_jsonl_by_uid(BENIGN_LOG_DIR / "ssl.log")
    quic_by_uid = _load_jsonl_by_uid(BENIGN_LOG_DIR / "quic.log")
    rows = []
    for uid, d in pktseq_by_uid.items():
        domain = (ssl_by_uid.get(uid) or quic_by_uid.get(uid) or {}).get("server_name") or f"unknown_{uid[:6]}"
        seq, mask = pack_sequence(d.get("sizes", []), d.get("gaps", []))
        if not mask.any():
            continue
        rows.append({"seq": seq, "mask": mask, "label": 0, "provenance": "real", "group": domain})
    print(f"Real benign rows (from pkt_seq.log): {len(rows)}")
    return rows


def _load_botnet_5tuples(label_csv: Path) -> set:
    """Ground-truth argus rows already pre-filtered to Botnet-labeled by
    the download step (grep -i botnet) -- just parse the 5-tuple out of
    each. Matches both flow directions since argus's Src/Dst side doesn't
    always line up with Zeek's id.orig_h/id.resp_h (whoever it considers
    the flow initiator can differ)."""
    tuples = set()
    if not label_csv.exists():
        return tuples
    with open(label_csv, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 8:
                continue
            try:
                src, sport, dst, dport = row[3], int(row[4]), row[6], int(row[7])
            except (ValueError, IndexError):
                continue
            tuples.add((src, sport, dst, dport))
            tuples.add((dst, dport, src, sport))  # direction-agnostic
    return tuples


def build_real_malicious_rows() -> list:
    rows = []
    for scenario, label_file in SCENARIO_LABELS.items():
        scenario_dir = MALICIOUS_ROOT / scenario
        botnet_tuples = _load_botnet_5tuples(LABELS_DIR / label_file)
        if not botnet_tuples:
            print(f"[{scenario}] no ground-truth Botnet 5-tuples available yet -- skipping "
                  f"(label file still downloading/filtering, or not present)")
            continue

        conn_by_uid = _load_jsonl_by_uid(scenario_dir / "conn.log")
        pktseq_by_uid = _load_jsonl_by_uid(scenario_dir / "pkt_seq.log")
        matched = 0
        for uid, pktseq in pktseq_by_uid.items():
            conn = conn_by_uid.get(uid)
            if conn is None:
                continue
            key = (conn.get("id.orig_h"), conn.get("id.orig_p"), conn.get("id.resp_h"), conn.get("id.resp_p"))
            if key not in botnet_tuples:
                continue
            seq, mask = pack_sequence(pktseq.get("sizes", []), pktseq.get("gaps", []))
            if not mask.any():
                continue
            rows.append({"seq": seq, "mask": mask, "label": 1, "provenance": "real", "group": scenario})
            matched += 1
        print(f"[{scenario}] real malicious TLS/QUIC flows matched to ground-truth Botnet label: {matched} "
              f"(of {len(pktseq_by_uid)} total ssl/quic flows with a packet sequence)")
    return rows


def build_synthetic_malicious_rows(n: int) -> list:
    rows = []
    for i in range(n // 2):
        sizes, gaps = _synth_beacon_pktseq()
        seq, mask = pack_sequence(sizes, gaps)
        rows.append({"seq": seq, "mask": mask, "label": 1, "provenance": "synthetic", "group": f"synth_beacon_{i}"})
    for i in range(n - n // 2):
        sizes, gaps = _synth_bulk_pktseq()
        seq, mask = pack_sequence(sizes, gaps)
        rows.append({"seq": seq, "mask": mask, "label": 1, "provenance": "synthetic", "group": f"synth_bulk_{i}"})
    return rows


def build() -> None:
    benign = build_benign_rows()
    real_malicious = build_real_malicious_rows()
    synthetic_malicious = build_synthetic_malicious_rows(max(len(benign) - len(real_malicious), random_synth_n))
    all_rows = benign + real_malicious + synthetic_malicious

    seq = np.stack([r["seq"] for r in all_rows]).astype(np.float32)
    mask = np.stack([r["mask"] for r in all_rows]).astype(np.float32)
    label = np.array([r["label"] for r in all_rows], dtype=np.int64)
    provenance = np.array([r["provenance"] for r in all_rows])
    group = np.array([r["group"] for r in all_rows])

    np.savez(OUT_NPZ, seq=seq, mask=mask, label=label, provenance=provenance, group=group)
    print(f"\nWrote {len(all_rows)} rows to {OUT_NPZ}")
    print(f"benign={len(benign)}  real_malicious={len(real_malicious)}  synthetic_malicious={len(synthetic_malicious)}")


if __name__ == "__main__":
    build()
