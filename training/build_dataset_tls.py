"""
Builds the TLS/QUIC-malware flow-stats classifier dataset:
  - BENIGN (label=0): REAL rows, from training/zeek-logs-tls/conn.log +
    ssl.log + quic.log (training/capture/capture_tls.py's real HTTPS
    requests to ~126 diverse real domains, and training/capture/capture_quic.py's
    real aioquic handshakes to ~25 real HTTP/3 hosts). Joined by Zeek's
    shared `uid` -- the exact same join backend/stream_consumer.py's
    FlowByteEnricher performs at serve time (batch version here since this
    is offline dataset-building, not a live stream), so train-time and
    serve-time feature computation stay consistent by construction.
    2026-09-13: also joins pkt_seq.log (zeek/scripts/pkt_seq.zeek) the
    same way, for PS 26145 (d)'s "packet-size and timing sequences" --
    previously this dataset had zero real QUIC rows and zero packet-
    sequence data at all.
  - MALICIOUS (label=1): mostly SYNTHETIC, plus a REAL arm added
    2026-09-13. No ethical real-world source exists for a large volume of
    genuine malware-over-TLS/QUIC traffic (see ML_MODELS.md), so the bulk
    remains synthetic, shaped to reflect published characteristics of
    TLS-based C2/malware flows: small, bursty, tightly-regular exchanges
    (beacon-style) or one-sided large uploads (bulk-exfil-style) -- and,
    new in this pass, plausible packet-size/timing sequences for each
    shape: beacon flows use a small number of near-uniform small packets
    at regular intervals (a fixed heartbeat protocol), bulk-upload flows
    use mostly near-MTU-sized packets with low size variance (a bulk
    transfer, not varied human browsing). Both shapes are generated for
    each protocol (ssl and quic) so is_quic doesn't accidentally become a
    proxy for the label. build_real_malicious_rows() adds 22 REAL flows
    from a real 2024 Latrodectus/Lumma Stealer infection pcap (see its own
    docstring) -- this was previously a hard zero for this dataset (only
    the tier2 seq-CNN's separate dataset had any real-malicious TLS rows,
    from CTU-13's Neris).

Feature extraction reuses TLSMalwareDetector._flow_features() directly from
backend/detectors/tls_malware.py, so train-time and serve-time feature
computation are identical by construction.

Run: backend/.venv/bin/python3 training/build_dataset_tls.py
Reads: training/zeek-logs-tls/{conn,ssl,quic,pkt_seq}.log
Writes: training/dataset_tls.csv
"""
import json
import random
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.tls_malware import TLSMalwareDetector  # noqa: E402

LOG_DIR = REPO_ROOT / "training" / "zeek-logs-tls"
CONN_LOG = LOG_DIR / "conn.log"
SSL_LOG = LOG_DIR / "ssl.log"
QUIC_LOG = LOG_DIR / "quic.log"
PKTSEQ_LOG = LOG_DIR / "pkt_seq.log"
OUT_CSV = REPO_ROOT / "training" / "dataset_tls.csv"

FEATURE_NAMES = [
    "orig_bytes", "resp_bytes", "duration", "byte_ratio", "total_bytes", "bytes_per_sec",
    "pkt_size_mean", "pkt_size_std", "pkt_gap_mean", "pkt_gap_std", "pkt_count", "is_quic",
]

random.seed(21)


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


def build_real_rows() -> list:
    conn_by_uid = _load_jsonl_by_uid(CONN_LOG)
    pktseq_by_uid = _load_jsonl_by_uid(PKTSEQ_LOG)
    rows = []
    matched = unmatched = 0

    def process_log(path: Path, log_type: str):
        nonlocal matched, unmatched
        for uid, d in _load_jsonl_by_uid(path).items():
            conn = conn_by_uid.get(uid)
            if conn is None:
                unmatched += 1
                continue
            matched += 1
            pktseq = pktseq_by_uid.get(uid)
            event = {
                "orig_bytes": conn.get("orig_bytes", 0) or 0,
                "resp_bytes": conn.get("resp_bytes", 0) or 0,
                "duration": conn.get("duration", 0.0) or 0.0,
                "log_type": log_type,
                "pkt_sizes": pktseq.get("sizes", []) if pktseq else [],
                "pkt_gaps": pktseq.get("gaps", []) if pktseq else [],
            }
            total_bytes = event["orig_bytes"] + event["resp_bytes"]
            if event["duration"] < 0.05 or total_bytes < 50:
                continue  # too little data to be a meaningful sample either way
            feat = TLSMalwareDetector._flow_features(event)
            # 2026-09-12 dataset-plan retrofit: see training/scenarios/tls/README.md.
            scenario_id = "tls_benign_real_https" if log_type == "ssl" else "tls_benign_real_quic"
            rows.append({
                "label": 0,
                "domain": d.get("server_name") or f"unknown_{log_type}",
                "source": "real", "scenario_id": scenario_id,
                "attack_subtype": None, "label_method": "generator_ground_truth",
                **dict(zip(FEATURE_NAMES, feat)),
            })

    process_log(SSL_LOG, "ssl")
    process_log(QUIC_LOG, "quic")
    print(f"conn.log-joined rows: {matched}, unmatched (dropped): {unmatched}, "
          f"pkt_seq-joined: {sum(1 for r in rows if r['pkt_count'] > 0)}/{len(rows)}")
    return rows


MALICIOUS_LOG_ROOT = REPO_ROOT / "training" / "zeek-logs-tls-malicious"

# Real 2024-03-07 Latrodectus/Lumma Stealer infection, sourced from
# malware-traffic-analysis.net (a well-known, write-up-annotated malware
# pcap repository) and processed through the same Zeek pipeline as the
# live demo (training/build_malicious_pcap_logs.py). Domains below are
# copied verbatim from that post's own analyst-confirmed IOC file
# (REDIRECTS TO FAKE AZURE WEB PAGE / LATRODECTUS C2 / LUMMA STEALER C2
# sections) -- not inferred from traffic patterns. Two domains seen in the
# same pcap are deliberately EXCLUDED: firebasestorage.googleapis.com is
# legitimate Google infrastructure abused for payload hosting (its TLS
# fingerprint is indistinguishable from any benign Firebase user -- labeling
# it malicious would be actively wrong), and lufyfeo.org (the initial
# email-link redirect) is not named under the IOC file's own C2/malicious-
# infra sections, so it's left out rather than assumed guilty by
# association. See ML_MODELS.md's "TLS real-malicious-data addition"
# section for the full sourcing story, including two other 2024 samples
# (SSLoad/Cobalt Strike, DarkGate) that were pulled and found to use plain
# HTTP -- not TLS -- for their actual C2 in this specific capture, so they
# contribute nothing here.
REAL_MALICIOUS_SCENARIOS = {
    "latrodectus_lumma_2024": {
        "confirmed_malicious_domains": {
            "horaot.org", "aytobusesre.com", "popfealt.one", "auctiondecadecontaii.shop",
        },
        "attack_subtype": "tls_c2_real",
    },
}


def build_real_malicious_rows() -> list:
    rows = []
    for scenario, cfg in REAL_MALICIOUS_SCENARIOS.items():
        scenario_dir = MALICIOUS_LOG_ROOT / scenario
        conn_by_uid = _load_jsonl_by_uid(scenario_dir / "conn.log")
        pktseq_by_uid = _load_jsonl_by_uid(scenario_dir / "pkt_seq.log")
        matched = 0
        for uid, ssl_d in _load_jsonl_by_uid(scenario_dir / "ssl.log").items():
            domain = ssl_d.get("server_name")
            if domain not in cfg["confirmed_malicious_domains"]:
                continue
            conn = conn_by_uid.get(uid)
            if conn is None:
                continue
            pktseq = pktseq_by_uid.get(uid)
            event = {
                "orig_bytes": conn.get("orig_bytes", 0) or 0,
                "resp_bytes": conn.get("resp_bytes", 0) or 0,
                "duration": conn.get("duration", 0.0) or 0.0,
                "log_type": "ssl",
                "pkt_sizes": pktseq.get("sizes", []) if pktseq else [],
                "pkt_gaps": pktseq.get("gaps", []) if pktseq else [],
            }
            feat = TLSMalwareDetector._flow_features(event)
            rows.append({
                "label": 1, "domain": domain,
                "source": "real_public_dataset", "scenario_id": f"tls_malicious_real_{scenario}",
                "attack_subtype": cfg["attack_subtype"], "label_method": "dataset_ground_truth",
                **dict(zip(FEATURE_NAMES, feat)),
            })
            matched += 1
        print(f"[{scenario}] real malicious TLS flows matched to analyst-confirmed domains: {matched}")
    return rows


def _synth_beacon_pktseq() -> tuple:
    """Small number of near-uniform small packets at regular intervals --
    a fixed heartbeat protocol, distinct from the size/timing variety of
    genuine human browsing."""
    n = random.randint(4, 8)
    sizes = [max(40, round(random.gauss(180, 25))) for _ in range(n)]
    gaps = [max(0.001, random.gauss(0.05, 0.015)) for _ in range(n - 1)]
    return sizes, gaps


def _synth_bulk_pktseq() -> tuple:
    """Mostly near-MTU-sized packets with low size variance -- a bulk
    transfer, plus a couple of small ACK-like packets, unlike the mixed
    request/response sizes of real page loads."""
    n = random.randint(8, 12)
    sizes = []
    for _ in range(n):
        sizes.append(round(random.gauss(60, 10)) if random.random() < 0.2
                     else round(random.gauss(1400, 60)))
    sizes = [max(40, s) for s in sizes]
    gaps = [max(0.0001, random.gauss(0.002, 0.001)) for _ in range(n - 1)]
    return sizes, gaps


def gen_malicious_rows(n: int) -> list:
    """Synthetic malicious TLS/QUIC flows -- two byte-volume shapes drawn
    from published malware-over-TLS behavior (beacon-style, bulk-upload-
    style), each now also given a matching synthetic packet-size/timing
    sequence (see _synth_beacon_pktseq/_synth_bulk_pktseq) and generated
    for both protocols so is_quic can't become a label shortcut. Each row
    gets its own group id (see the original version of this function /
    ML_MODELS.md for why: GroupKFold fold-starvation from too few shared
    group labels)."""
    rows = []
    half = n // 2
    for i in range(half):
        for proto in ("ssl", "quic"):
            ob = random.uniform(200, 3000)
            rb = random.uniform(200, 3000)
            dur = random.uniform(0.05, 2.0)
            sizes, gaps = _synth_beacon_pktseq()
            event = {"orig_bytes": ob, "resp_bytes": rb, "duration": dur,
                     "log_type": proto, "pkt_sizes": sizes, "pkt_gaps": gaps}
            feat = TLSMalwareDetector._flow_features(event)
            rows.append({"label": 1, "domain": f"synthetic_beacon_{proto}_{i}",
                         "source": "synthetic", "scenario_id": "tls_malicious_synthetic_beacon",
                         "attack_subtype": "tls_c2_beacon", "label_method": "generator_ground_truth",
                         **dict(zip(FEATURE_NAMES, feat))})
    for i in range(n - half):
        for proto in ("ssl", "quic"):
            ob = random.uniform(50_000, 2_000_000)
            rb = random.uniform(100, 5000)
            dur = random.uniform(1.0, 60.0)
            sizes, gaps = _synth_bulk_pktseq()
            event = {"orig_bytes": ob, "resp_bytes": rb, "duration": dur,
                     "log_type": proto, "pkt_sizes": sizes, "pkt_gaps": gaps}
            feat = TLSMalwareDetector._flow_features(event)
            rows.append({"label": 1, "domain": f"synthetic_bulk_upload_{proto}_{i}",
                         "source": "synthetic", "scenario_id": "tls_malicious_synthetic_bulk_upload",
                         "attack_subtype": "tls_bulk_exfil", "label_method": "generator_ground_truth",
                         **dict(zip(FEATURE_NAMES, feat))})
    return rows


def build():
    real_rows = build_real_rows()
    real_malicious_rows = build_real_malicious_rows()
    n_malicious = max(len(real_rows), 9000)
    malicious = gen_malicious_rows(n_malicious // 2 * 2)  # even, since gen doubles per-proto

    df = pd.DataFrame(real_rows + real_malicious_rows + malicious)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"benign (real) rows: {(df['label']==0).sum()}  |  "
          f"malicious (real): {(df['source']=='real_public_dataset').sum()}  |  "
          f"malicious (synthetic): {((df['label']==1) & (df['source']=='synthetic')).sum()}")
    print(f"distinct real domains represented: {df[df['label']==0]['domain'].nunique()}")
    print(f"benign rows by protocol: "
          f"ssl={((df['label']==0) & (df['is_quic']==0)).sum()}, "
          f"quic={((df['label']==0) & (df['is_quic']==1)).sum()}")


if __name__ == "__main__":
    build()
