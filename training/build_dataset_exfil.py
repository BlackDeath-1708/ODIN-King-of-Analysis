"""
Builds the data-exfiltration classifier dataset from REAL captured traffic:
  - training/zeek-logs/conn.log (loopback container): benign local HTTP
    GETs (label=0) and HIGH_UPLOAD-shaped local HTTP POSTs (label=1),
    port 8199 -- see training/capture/capture_exfil.py.
  - training/zeek-logs-tls/conn.log (real-interface container):
    ICMP_COVERT-shaped real pings (label=1, proto=icmp) and
    DNS_EXFIL-shaped real UDP bursts to port 53 on real public resolvers
    (label=1) -- also from capture_exfil.py.

IMPORTANT FIX THIS SESSION: both captures required Zeek's -C (ignore
checksums) flag -- Linux defers checksum computation for loopback traffic,
so libpcap-captured loopback packets have invalid/absent checksums and
Zeek silently produces zero-byte "OTH" connection stubs without it. This
was found affecting BOTH training captures and the live production
zeek_monitor container (99.9% of real conn.log rows had orig_bytes=0) --
see ML_MODELS.md and docker-compose.yml (repo root) for the production fix.

No separate "benign, real-world-representative bulk transfer" real class
was captured (would need a real large legitimate transfer, e.g. a big real
file download, to contrast against the exfil-shaped uploads) -- the
existing rule/feature design already treats "large + asymmetric + long" as
exfil-shaped regardless of intent, matching exfil.py's own rule thresholds,
so this is consistent with what the detector actually looks for, not a
gap introduced by this dataset.

Feature extraction reuses ExfilDetector._extract() directly from
backend/detectors/exfil.py, so train-time and serve-time feature
computation are identical by construction.

Run: backend/.venv/bin/python3 training/build_dataset_exfil.py
Reads: training/zeek-logs/conn.log, training/zeek-logs-tls/conn.log
Writes: training/dataset_exfil.csv
"""
import json
import random
import sys
from pathlib import Path

import pandas as pd

random.seed(41)

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.exfil import ExfilDetector  # noqa: E402

LOOPBACK_LOG = REPO_ROOT / "training" / "zeek-logs" / "conn.log"
EXTERNAL_LOG = REPO_ROOT / "training" / "zeek-logs-tls" / "conn.log"
OUT_CSV = REPO_ROOT / "training" / "dataset_exfil.csv"

LOCAL_HTTP_PORT = 8199
EXTERNAL_HOSTS = {"8.8.8.8", "1.1.1.1", "9.9.9.9"}

FEATURE_NAMES = ["orig_bytes", "resp_bytes", "byte_ratio", "duration",
                  "orig_pkts", "resp_pkts", "bytes_per_sec", "is_icmp", "to_dns", "to_common_port"]


def _row_from_conn(d: dict, label: int, group: str) -> dict | None:
    event = {
        "orig_bytes": d.get("orig_bytes", 0) or 0,
        "resp_bytes": d.get("resp_bytes", 0) or 0,
        "duration": d.get("duration", 0.0) or 0.0,
        "orig_pkts": d.get("orig_pkts", 0) or 0,
        "resp_pkts": d.get("resp_pkts", 0) or 0,
        "proto": d.get("proto", ""),
        "dst_port": d.get("id.resp_p", 0) or 0,
    }
    feat, _ = ExfilDetector._extract(event)
    return {"label": label, "group": group, **dict(zip(FEATURE_NAMES, feat))}


def build_local_rows() -> tuple[list, list]:
    # Unique group id per row -- these are independent random requests (own
    # randomized body size per call), not systematically near-duplicate the
    # way TLS's same-domain page fetches were, but kept unique anyway per
    # this session's TLS lesson: shared group labels across thousands of
    # rows starve most GroupKFold folds of that class entirely.
    benign, high_upload = [], []
    with open(LOOPBACK_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("id.resp_p") != LOCAL_HTTP_PORT or d.get("conn_state") != "SF":
                continue
            ob = d.get("orig_bytes", 0) or 0
            if ob >= 500_000:
                high_upload.append(_row_from_conn(d, 1, f"local_high_upload_{len(high_upload)}"))
            elif 0 < ob < 10_000:
                benign.append(_row_from_conn(d, 0, f"local_benign_{len(benign)}"))
    return benign, high_upload


def build_external_rows() -> tuple[list, list]:
    icmp_rows, dns_rows = [], []
    with open(EXTERNAL_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            dst = d.get("id.resp_h", "")
            if d.get("proto") == "icmp" and dst in EXTERNAL_HOSTS:
                ob = d.get("orig_ip_bytes", d.get("orig_bytes", 0)) or 0
                if ob < 1000:
                    continue
                row = _row_from_conn({**d, "orig_bytes": ob}, 1, f"real_icmp_covert_{len(icmp_rows)}")
                icmp_rows.append(row)
            elif d.get("proto") == "udp" and d.get("id.resp_p") == 53 and dst in EXTERNAL_HOSTS:
                ob = d.get("orig_bytes", 0) or 0
                if ob < 2000:
                    continue
                dns_rows.append(_row_from_conn(d, 1, f"real_dns_exfil_{len(dns_rows)}"))
    return icmp_rows, dns_rows


COMMON_PORTS = [80, 443, 8080]


def _synthetic_row(orig, resp, dur, orig_pkts, resp_pkts, dst_port, label, group, proto="tcp"):
    event = {"orig_bytes": orig, "resp_bytes": resp, "duration": dur,
              "orig_pkts": orig_pkts, "resp_pkts": resp_pkts, "proto": proto, "dst_port": dst_port}
    feat, _ = ExfilDetector._extract(event)
    return {"label": label, "group": group, **dict(zip(FEATURE_NAMES, feat))}


def gen_synthetic_benign(n: int) -> list:
    """Supplements the real local-HTTP benign class with more volume/port
    diversity than a single local port can realistically provide."""
    out = []
    for i in range(n):
        orig = random.uniform(100, 50_000)
        resp = orig / random.uniform(0.01, 1.5)
        dur = random.uniform(0.1, 60)
        port = random.choice(COMMON_PORTS + [22, 25, 3306])
        out.append(_synthetic_row(orig, resp, dur, random.randint(5, 50), random.randint(5, 50),
                                    port, 0, f"synthetic_benign_{i}"))
    return out


def gen_synthetic_bulk(n: int) -> list:
    out = []
    for i in range(n):
        orig = random.uniform(100_000, 10_000_000)
        resp = orig / random.uniform(2.0, 50.0)
        dur = random.uniform(10, 600)
        port = random.choice(COMMON_PORTS + [21, 8443])
        out.append(_synthetic_row(orig, resp, dur, random.randint(100, 2000), random.randint(20, 200),
                                    port, 1, f"synthetic_bulk_{i}"))
    return out


def gen_synthetic_icmp(n: int) -> list:
    """Real ICMP_COVERT rows were thin (Zeek aggregates repeated pings to
    the same host into very few long-lived flows -- see module docstring)
    -- supplemented here for class volume/diversity, matching the same
    published-pattern shape (orig_bytes >> resp_bytes, moderate duration)."""
    out = []
    for i in range(n):
        orig = random.uniform(1_500, 50_000)
        resp = orig * random.uniform(0.05, 0.3)
        dur = random.uniform(5, 120)
        out.append(_synthetic_row(orig, resp, dur, random.randint(50, 500), random.randint(10, 100),
                                    0, 1, f"synthetic_icmp_{i}", proto="icmp"))
    return out


def gen_synthetic_dns(n: int) -> list:
    out = []
    for i in range(n):
        orig = random.uniform(6_000, 200_000)
        resp = orig * random.uniform(0.1, 0.5)
        dur = random.uniform(5, 200)
        out.append(_synthetic_row(orig, resp, dur, random.randint(50, 1000), random.randint(50, 1000),
                                    53, 1, f"synthetic_dns_{i}"))
    return out


def build():
    benign, high_upload = build_local_rows()
    icmp_rows, dns_rows = build_external_rows()
    real_rows = benign + high_upload + icmp_rows + dns_rows

    synthetic_benign = gen_synthetic_benign(2000)
    synthetic_malicious = gen_synthetic_bulk(4000) + gen_synthetic_icmp(1500) + gen_synthetic_dns(1000)

    rows = real_rows + synthetic_benign + synthetic_malicious
    df = pd.DataFrame(rows)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"REAL -- benign: {len(benign)}  high_upload: {len(high_upload)}  "
          f"icmp_covert: {len(icmp_rows)}  dns_exfil: {len(dns_rows)}  (total real: {len(real_rows)})")
    print(f"SYNTHETIC -- benign: {len(synthetic_benign)}  malicious: {len(synthetic_malicious)}")
    print(f"total benign rows: {(df['label']==0).sum()}  |  total exfil rows: {(df['label']==1).sum()}")


if __name__ == "__main__":
    build()
