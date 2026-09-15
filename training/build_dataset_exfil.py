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

# P10 multi-host retrain -- see build_dataset_recon.py's identical section
# for the isolation rationale. LOOPBACK_LOG above is the same shared,
# stale conn.log confirmed overwritten for recon on 2026-09-14, so build()
# below reuses the existing committed CSV rather than re-scanning it.
MULTIHOST_CONN_LOG = REPO_ROOT / "training" / "zeek-logs-multihost" / "conn.log"
MULTIHOST_SCENARIOS_DIR = REPO_ROOT / "training" / "scenarios" / "exfil"
MULTIHOST_CAPTURE_DIR = REPO_ROOT / "training" / "capture"
UNSEEN_CSV = REPO_ROOT / "training" / "dataset_exfil_unseen.csv"
MULTIHOST_EXTERNAL_IP = "10.10.0.40"
FLUSH_MARGIN_S = 65  # matches training/capture/validate_scenario.py's constant

LOCAL_HTTP_PORT = 8199
EXTERNAL_HOSTS = {"8.8.8.8", "1.1.1.1", "9.9.9.9"}

FEATURE_NAMES = ["orig_bytes", "resp_bytes", "byte_ratio", "duration",
                  "orig_pkts", "resp_pkts", "bytes_per_sec", "is_icmp", "to_dns", "to_common_port"]

# 2026-09-12 dataset-plan retrofit: see training/scenarios/exfil/README.md.
# group prefixes are fixed by this file's own row-builders below, so this
# mapping is exhaustive by construction (an unmatched prefix is a bug).
_SCENARIO_BY_PREFIX = {
    "local_benign_": ("exfil_local_benign", None, "real"),
    "local_high_upload_": ("exfil_local_high_upload", "bulk_exfil", "real"),
    "real_icmp_covert_": ("exfil_real_icmp_covert", "icmp_covert", "real"),
    "real_dns_exfil_": ("exfil_real_dns_exfil", "dns_tunnel_exfil", "real"),
    "synthetic_benign_": ("exfil_synthetic_benign", None, "synthetic"),
    "synthetic_bulk_": ("exfil_synthetic_bulk", "bulk_exfil", "synthetic"),
    "synthetic_icmp_": ("exfil_synthetic_icmp", "icmp_covert", "synthetic"),
    "synthetic_dns_": ("exfil_synthetic_dns", "dns_tunnel_exfil", "synthetic"),
}


def _scenario_for(group: str) -> tuple[str, str | None, str]:
    for prefix, info in _SCENARIO_BY_PREFIX.items():
        if group.startswith(prefix):
            return info
    raise ValueError(f"no scenario mapping for group={group!r}")


def _row_from_conn(d: dict, label: int, group: str, scenario_id_override=None,
                    attack_subtype_override=None, environment="loopback") -> dict | None:
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
    if scenario_id_override:
        scenario_id = scenario_id_override
        attack_subtype = attack_subtype_override if label == 1 else None
        source = "real"
    else:
        scenario_id, attack_subtype, source = _scenario_for(group)
    return {"label": label, "group": group, "source": source, "scenario_id": scenario_id,
            "attack_subtype": attack_subtype, "label_method": "generator_ground_truth",
            "environment": environment,
            **dict(zip(FEATURE_NAMES, feat))}


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
    scenario_id, attack_subtype, source = _scenario_for(group)
    return {"label": label, "group": group, "source": source, "scenario_id": scenario_id,
            "attack_subtype": attack_subtype, "label_method": "generator_ground_truth",
            "environment": "synthetic", **dict(zip(FEATURE_NAMES, feat))}


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


def load_multihost_scenarios():
    """Returns (train_and_validation, unseen_test) entries, each carrying
    the scenario's own [min_ts, max_ts+FLUSH_MARGIN_S] time window (from
    sessions_exfil_<id>.json) -- required since exfil_multi_01/02/03 share
    ONE continuously-growing conn.log, unlike recon/ddos/c2 which isolate
    naturally via per-session start/end marks alone (see build_dataset_recon
    .py); here the row-matchers below scan by port/proto/dst, which would
    otherwise mix all three scenarios' traffic together, including pulling
    the unseen scenario's own benign rows into training -- a real leak
    avoided only by this windowing."""
    all_entries = []
    for manifest_path in sorted(MULTIHOST_SCENARIOS_DIR.glob("exfil_multi_*.json")):
        with open(manifest_path) as f:
            m = json.load(f)
        sessions_path = MULTIHOST_CAPTURE_DIR / f"sessions_exfil_{m['scenario_id']}.json"
        if not sessions_path.exists():
            print(f"  WARNING: no sessions file for {m['scenario_id']} -- skipping")
            continue
        with open(sessions_path) as f:
            marks = json.load(f)
        timestamps = [mk["ts"] for mk in marks if "ts" in mk]
        if not timestamps:
            print(f"  WARNING: empty sessions file for {m['scenario_id']} -- skipping")
            continue
        all_entries.append({
            "scenario_id": m["scenario_id"], "attack_subtype": m["attack_subtype"],
            "environment": m["environment"], "split": m.get("split", "train"),
            "raw_start": min(timestamps), "raw_end": max(timestamps),
        })

    # Clamp each scenario's flush-margin-extended window so it never
    # crosses into the NEXT scenario's own start. These captures ran
    # back-to-back with no inter-scenario delay -- a naive +FLUSH_MARGIN_S
    # on every scenario silently bled into whichever ran right after it
    # (confirmed live 2026-09-14: exfil_multi_01's unclamped window pulled
    # in exfil_multi_02's dns/icmp-verification traffic, corrupting both
    # the row counts and, more seriously, threatening the unseen-scenario
    # isolation requirement). Sorted chronologically so "next" is correct
    # regardless of glob order.
    all_entries.sort(key=lambda e: e["raw_start"])
    for i, e in enumerate(all_entries):
        hi = e["raw_end"] + FLUSH_MARGIN_S
        if i + 1 < len(all_entries):
            hi = min(hi, all_entries[i + 1]["raw_start"])
        e["window"] = (e["raw_start"], hi)

    train = [e for e in all_entries if e["split"] != "unseen_test"]
    unseen = [e for e in all_entries if e["split"] == "unseen_test"]
    return train, unseen


def build_multihost_rows(scenario):
    """Scans MULTIHOST_CONN_LOG restricted to this scenario's own time
    window, applying the same four exfil.py shape-matchers build_local_rows
    /build_external_rows use -- whichever phases the scenario actually ran
    (see capture_exfil.py's --phases) are the only ones that produce rows;
    the others simply find nothing, which is correct, not an error."""
    lo, hi = scenario["window"]
    sid, subtype, env = scenario["scenario_id"], scenario["attack_subtype"], scenario["environment"]
    benign, high_upload, icmp_rows, dns_rows = [], [], [], []
    with open(MULTIHOST_CONN_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = d.get("ts")
            if ts is None or not (lo <= ts <= hi):
                continue
            if d.get("id.resp_h") != MULTIHOST_EXTERNAL_IP:
                continue
            if d.get("id.resp_p") == LOCAL_HTTP_PORT and d.get("conn_state") == "SF":
                ob = d.get("orig_bytes", 0) or 0
                if ob >= 500_000:
                    high_upload.append(_row_from_conn(d, 1, f"mh_{sid}_high_upload_{len(high_upload)}",
                                                       scenario_id_override=sid, attack_subtype_override=subtype,
                                                       environment=env))
                elif 0 < ob < 10_000:
                    benign.append(_row_from_conn(d, 0, f"mh_{sid}_benign_{len(benign)}",
                                                  scenario_id_override=sid, environment=env))
            elif d.get("proto") == "icmp":
                ob = d.get("orig_ip_bytes", d.get("orig_bytes", 0)) or 0
                if ob < 1000:
                    continue
                icmp_rows.append(_row_from_conn({**d, "orig_bytes": ob}, 1, f"mh_{sid}_icmp_{len(icmp_rows)}",
                                                 scenario_id_override=sid, attack_subtype_override=subtype,
                                                 environment=env))
            elif d.get("proto") == "udp" and d.get("id.resp_p") == 53:
                ob = d.get("orig_bytes", 0) or 0
                if ob < 2000:
                    continue
                dns_rows.append(_row_from_conn(d, 1, f"mh_{sid}_dns_{len(dns_rows)}",
                                                scenario_id_override=sid, attack_subtype_override=subtype,
                                                environment=env))
    return benign, high_upload, icmp_rows, dns_rows


def build():
    # --- Non-multihost source: reuse the existing committed CSV rather
    # than recomputing -- LOOPBACK_LOG is the same shared, stale conn.log
    # confirmed overwritten for recon on 2026-09-14 (see module note).
    if OUT_CSV.exists():
        existing_df = pd.read_csv(OUT_CSV)
        if "environment" not in existing_df.columns:
            existing_df["environment"] = "loopback"
        rows = existing_df.to_dict("records")
        print(f"Existing (loopback+external+synthetic): reusing {len(rows)} rows from {OUT_CSV} "
              f"(NOT recomputed from conn.log)")
    else:
        benign, high_upload = build_local_rows()
        icmp_rows, dns_rows = build_external_rows()
        real_rows = benign + high_upload + icmp_rows + dns_rows
        synthetic_benign = gen_synthetic_benign(2000)
        synthetic_malicious = gen_synthetic_bulk(4000) + gen_synthetic_icmp(1500) + gen_synthetic_dns(1000)
        rows = real_rows + synthetic_benign + synthetic_malicious
        print(f"REAL -- benign: {len(benign)}  high_upload: {len(high_upload)}  "
              f"icmp_covert: {len(icmp_rows)}  dns_exfil: {len(dns_rows)}  (total real: {len(real_rows)})")
        print(f"SYNTHETIC -- benign: {len(synthetic_benign)}  malicious: {len(synthetic_malicious)}")

    # --- Multi-host sources (P10) ---
    train_scenarios, unseen_scenarios = load_multihost_scenarios()
    print(f"\nMulti-host: {len(train_scenarios)} train/validation scenario(s), "
          f"{len(unseen_scenarios)} unseen_test scenario(s)")
    for sc in train_scenarios:
        benign, high_upload, icmp_rows, dns_rows = build_multihost_rows(sc)
        sc_rows = benign + high_upload + icmp_rows + dns_rows
        print(f"  {sc['scenario_id']}: {len(sc_rows)} rows "
              f"(benign={len(benign)} upload={len(high_upload)} icmp={len(icmp_rows)} dns={len(dns_rows)})")
        rows += sc_rows

    df = pd.DataFrame(rows)
    df.to_csv(OUT_CSV, index=False)
    print(f"\nWrote {len(df)} labeled samples to {OUT_CSV}")
    print(f"total benign rows: {(df['label']==0).sum()}  |  total exfil rows: {(df['label']==1).sum()}")

    unseen_rows = []
    for sc in unseen_scenarios:
        benign, high_upload, icmp_rows, dns_rows = build_multihost_rows(sc)
        sc_rows = benign + high_upload + icmp_rows + dns_rows
        print(f"  UNSEEN {sc['scenario_id']}: {len(sc_rows)} rows "
              f"(benign={len(benign)} upload={len(high_upload)} icmp={len(icmp_rows)} dns={len(dns_rows)})")
        unseen_rows += sc_rows
    if unseen_rows:
        udf = pd.DataFrame(unseen_rows)
        udf.to_csv(UNSEEN_CSV, index=False)
        print(f"Wrote {len(udf)} UNSEEN samples to {UNSEEN_CSV} (never used for training)")


if __name__ == "__main__":
    build()
