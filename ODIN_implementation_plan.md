# ODIN — SIH Implementation Plan
## One-way Detection and Intelligence Network
### Problem 26145 — NTRO | Team: Cyber Phoenix
### Claude Code Feed — Continue From Prototype

**Status legend:** ✅ DONE &nbsp; ⚠️ PARTIAL / DONE DIFFERENTLY &nbsp; ❌ NOT STARTED

> **Updated 2026-09-08** — this plan was written against an older snapshot of the prototype. It has been re-audited against the actual code in `ntro-prototype/` (through commit `1db1789`, "Wire ML models into all three detectors, add replay/throughput demo features") and every task below is now tagged with real status. Several "Phase 0 bugs" turned out to be already fixed, and the C2 model turned out to be already trained — don't redo that work. See `README.md` and `ML_MODELS.md` for the current, honest state of what's shipped.

---

## HOW TO USE THIS DOCUMENT

This is a complete, phase-ordered build plan for Claude Code. Each phase has:
- **Context** — what already exists and what is being added
- **Tasks** — exact files to create or modify
- **Acceptance criteria** — how to verify the phase is complete before moving to the next

Do not skip phases. Each phase depends on the previous one. Start by finishing the ❌/⚠️ items — don't re-implement anything marked ✅.

---

## EXISTING PROTOTYPE — WHAT IS ALREADY BUILT (Phase 0 — DONE)

The following is confirmed working from the college-level prototype. Do not rebuild these.

### Infrastructure
- Zeek NSM installed and running, tailing live traffic → producing `conn.log`, `dns.log`, `ssl.log`
- Apache Kafka broker running in KRaft mode (no ZooKeeper)
- `kafka_producer.py` — tails Zeek log files and publishes JSON events to Kafka topics
- `stream_consumer.py` — Kafka consumer with `normalize_event()` abstraction seam

### Detectors (Trained and Working)
- **DDoS detector** — Random Forest, 5 features (`packet_rate`, `unique_dst_ports`, `dst_port_entropy`, `mean_inter_arrival`, `std_inter_arrival`), F1=0.994 vs rule baseline F1=0.921. ✅ Trained and wired in (`backend/detectors/ddos.py`, `backend/ml_models/ddos_model.joblib`).
- **Recon/Port Scan detector** — Random Forest v3, GroupKFold CV (prevents temporal leakage), F1=1.000. ✅ Trained and wired in (`backend/detectors/recon.py`, `backend/ml_models/recon_model_v3.joblib`). Already has a per-source alert cooldown (`ALERT_COOLDOWN`).
- **C2 Beaconing detector** — ✅ **Model IS trained and wired in** (`backend/ml_models/c2_model.joblib`), F1=0.966 vs rule baseline F1=0.739. Uses a range-gated approach instead of a raw threshold: the model is only trusted while `observation_count <= 11` and `mean_interval <= 7.0s` (both blind spots in the training data, found and fixed after a live false-positive stress test — see `ML_MODELS.md`). Outside that range it falls back to the original CV-based rule. This supersedes the plan's original "train it" task below — see Phase 2.1/2.2 status.

### Frontend / API
- Flask API with SSE streaming endpoint
- `/api/stats` endpoint with pipeline status (diode status field present)
- `/api/throughput` endpoint — ✅ already implemented (see Phase 1.1 status)
- `/api/replay/<threat>` — ✅ PCAP replay already implemented, via a different mechanism than originally planned (see Phase 6.2 status)
- React frontend with Architecture page, Overview page, StatusBar (shows live throughput), and Recharts dashboard

### Known Bugs — UPDATED STATUS
1. ~~Throughput metric shows `0.0`~~ — ✅ **FIXED**. `stream_consumer.py` maintains a rolling window and writes to `.throughput`; `/api/throughput` in `app.py` serves it; `StatusBar.jsx` displays `events_per_sec`.
2. ~~Destination IPs show as "UNKNOWN"~~ — ✅ **FIXED**. `stream_consumer.py`'s `normalize_event()` already maps `id.resp_h` → `dst_ip`, `id.orig_h` → `src_ip`, etc.
3. **DDoS detector fires on every `conn.log` line — no cooldown logic between alerts** — ❌ **STILL OPEN**. Unlike `recon.py` (which has `ALERT_COOLDOWN`/`_last_alerted`), `backend/detectors/ddos.py` has no per-source cooldown dict. This is the one real carry-over bug from the original plan — see Phase 1, Task 1.3.

---

## PHASE 1 — BUG FIXES + BASELINE STABILISATION
**Goal:** Make the existing three detectors production-stable before adding anything new.
**Time estimate:** 4–6 hours → **remaining work: ~1–2 hours** (most of this phase is already done)

### Task 1.1 — Fix Throughput Counter — ✅ DONE

Already implemented in `stream_consumer.py` (`write_throughput()`) and exposed via `/api/throughput` in `app.py`. Note: it's a separate endpoint rather than nested under `/api/stats` as the original spec suggested — functionally equivalent, no change needed.

### Task 1.2 — Fix Destination IP Parsing — ✅ DONE

`normalize_event()` in `stream_consumer.py` already extracts `id.resp_h`/`id.resp_p`/`id.orig_h`/`id.orig_p` correctly for conn.log-derived events.

**Remaining check:** confirm dns.log and ssl.log events (once the DGA/TLS detectors exist in Phase 2) go through the same mapping — verify when those detectors are built, not before.

### Task 1.3 — Add DDoS Alert Cooldown — ❌ NOT DONE (do this first)

**File:** `backend/detectors/ddos.py`

```
Problem: DDoS detector fires an alert for every window it triggers on, with
no dedup — unlike recon.py, which already tracks _last_alerted per source_ip.

Fix: Add a per-source cooldown dict, following the same pattern already
proven in recon.py:
  - ALERT_COOLDOWN = 30  # seconds
  - self._last_alerted = {}  # dict: src_ip -> last alert timestamp

Before returning an alert for src_ip:
  if ts - self._last_alerted.get(src_ip, 0) < ALERT_COOLDOWN:
      return None
  self._last_alerted[src_ip] = ts
  # ... then build and return the alert as today
```

Note: `src_ip` on a spoofed/randomized-source flood only reflects the *most recent* packet (see existing evidence line in `ddos.py`), so the cooldown key should probably be scoped to `(dst_ip, dst_port)` instead of `src_ip` for genuinely distributed floods — decide based on what the demo pcaps actually look like. Keep it simple (single dict, one constant) either way.

### Task 1.4 — Unified Alert Schema — ⚠️ PARTIALLY DONE, DECISION NEEDED

**Current state:** `backend/detectors/base.py`'s `Detector.alert()` already produces a consistent dict shared by all three existing detectors (`timestamp`, `flow_id`, `src_ip`/`port`, `dst_ip`/`port`, `threat_class`, `threat_label`, `severity`, `confidence`, `evidence`, `detector`, `window_seconds`). This is simpler than the `odin/schema.py` dataclass the original plan proposed (no `detector_version`, no `pipeline_stage`, evidence is a list of human-readable strings rather than a structured sub-object, threat classes are lowercase strings rather than an enum).

**Decision for this phase:** don't build a second, parallel schema. Either:
- (a) Extend the existing `Detector.alert()` in `base.py` with the two missing fields (`detector_version`, `pipeline_stage`) and keep the current shape — least disruptive, keeps all 3 working detectors unchanged; **or**
- (b) Migrate to the plan's original `odin/schema.py` dataclass now, before building 3 more detectors on top of the old shape.

Recommendation: **(a)**. The frontend (`ActiveDetectors.jsx`, alert feed) already consumes the current shape; a schema migration now is a larger, riskier change than the value it adds this close to a demo deadline. Revisit only if judges specifically ask about calibration/versioning provenance.

### Acceptance Criteria — Phase 1
- [x] `/api/throughput` (or `/api/stats`) returns a non-zero `flows_per_second`/`events_per_sec` when traffic is flowing
- [x] Alert records show real destination IPs, not "UNKNOWN"
- [ ] DDoS detector emits at most one alert per 30-second window per source (or per dst_ip/dst_port — see Task 1.3 note)
- [x] All existing detectors emit alerts using a consistent shared format (`Detector.alert()`)

---

## PHASE 2 — COMPLETE THE SIX DETECTORS
**Goal:** Bring all six threat classes from "missing" to "working with trained models."
**Time estimate:** 12–16 hours → **remaining work: ~10–13 hours** (DDoS/Recon/C2 already done — see below)

### Task 2.1 — C2 Beaconing: Train the Model — ✅ DONE (superseded)

The model is already trained and wired in (`backend/ml_models/c2_model.joblib`), using a different (and better-validated) approach than the plan's synthetic-dataset spec: real captured sessions, GroupKFold by capture session, F1=0.966, with an explicit, documented range gate (`MODEL_MAX_OBSERVATIONS=11`, `MODEL_MAX_MEAN_INTERVAL=7.0`) found by stress-testing the deployed model against out-of-range synthetic benign traffic. See `ML_MODELS.md` "C2's range gate — two real bugs found and fixed after training" for the full writeup. **No further work needed here** unless you want to widen the validated range with more training captures (optional, not blocking).

### Task 2.2 — C2 Detector: Upgrade to Lomb-Scargle Periodogram — ❌ NOT DONE, OPTIONAL

The plan's periodogram-based innovation was not implemented; the shipped solution (range-gated CV rule + RandomForest) already solves the same underlying problem (jittered beacon detection) and has been empirically stress-tested. Treat this as a **stretch goal**, not a blocker:
- Pro: still a legitimate "paper → practice" talking point for judges if time allows.
- Con: real implementation + retraining risk this close to a deadline, when the current approach is already validated and demo-ready.

Recommendation: skip unless Phases 2.3–2.5 (the three genuinely missing detectors) are finished with time to spare.

### Task 2.3 — DGA / DNS Tunnelling Detector — ❌ NOT STARTED

No `backend/detectors/dga_detector.py` exists yet, and no dns.log Kafka topic wiring for it. Build as originally specified:
- `backend/detectors/dga_detector.py` (entropy, n-gram, word-boundary features; rule-based tunnel/DGA/dict-DGA signals)
- `scripts/build_trigram_model.py` → `data/trigram_model.json`
- `train_dga_detector.py` → `models/dga_model.joblib`

See original task body below (unchanged from prior plan version) for full feature/detection spec.

```python
"""
DGA and DNS Tunnelling Detector
Source: Zeek dns.log events from Kafka topic 'dns-events'

Features extracted per DNS query:
  - shannon_entropy: float — entropy of the query name (high = random/DGA)
  - query_length: int — total length of the FQDN
  - subdomain_length: int — length of the leftmost label
  - numeric_ratio: float — fraction of characters that are digits
  - consonant_ratio: float — fraction of alpha chars that are consonants
  - ngram_score: float — mean trigram log-probability against English corpus
  - has_known_tld: bool — whether the TLD is in the Alexa top-1M TLD list
  - word_boundary_score: float — fraction of substrings matching NLTK English words (dictionary DGA defence)
  - query_type: str — A, AAAA, TXT, MX, CNAME (TXT with long names = tunnel signal)
  - payload_ratio: float — for TXT records: answer length / query length

Detection logic (rule-based with ML score):
  TUNNEL signal: query_type == 'TXT' AND query_length > 50 AND payload_ratio > 3.0
  DGA signal: shannon_entropy > 3.5 AND ngram_score < -4.0 AND NOT is_known_domain
  DICTIONARY DGA signal: word_boundary_score > 0.7 AND ngram_score > -2.0 AND query_length > 30

Confidence scoring:
  - Use a pre-trained Random Forest for DGA (train on UNSW-NB15 DNS features + DGArchive)
  - Tunnel: rule-based confidence = min(1.0, (query_length / 100) * payload_ratio * 0.3)

Output alert evidence sub-object:
  {
    "query": "<the full DNS query string>",
    "query_type": "TXT",
    "shannon_entropy": 4.21,
    "ngram_score": -5.3,
    "word_boundary_score": 0.12,
    "detection_path": "DGA" | "TUNNEL" | "DICT_DGA"
  }
"""

import math
import re
from collections import Counter

# English trigram log-probabilities — load from a precomputed file
# Generate with: python scripts/build_trigram_model.py --corpus english_words.txt
# Saves to data/trigram_model.json
# Format: {"the": -2.1, "ing": -2.3, ...}

VOWELS = set('aeiouAEIOU')
KNOWN_TLDS = {'com', 'net', 'org', 'gov', 'edu', 'io', 'co', 'uk', 'de', 'fr'}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def consonant_ratio(s: str) -> float:
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    consonants = [c for c in alpha if c not in VOWELS]
    return len(consonants) / len(alpha)

def numeric_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)

def word_boundary_score(domain: str, wordlist: set) -> float:
    """Check what fraction of the domain can be decomposed into known English words."""
    label = domain.split('.')[0].lower()  # leftmost subdomain only
    if not label:
        return 0.0
    matched_chars = 0
    i = 0
    while i < len(label):
        found = False
        for length in range(min(12, len(label) - i), 2, -1):
            substring = label[i:i+length]
            if substring in wordlist:
                matched_chars += length
                i += length
                found = True
                break
        if not found:
            i += 1
    return matched_chars / len(label)

def extract_dga_features(dns_event: dict, trigram_model: dict, wordlist: set) -> dict:
    query = dns_event.get('query', '')
    qtype = dns_event.get('qtype_name', 'A')
    answer = dns_event.get('answers', '')

    labels = query.rstrip('.').split('.')
    subdomain = labels[0] if labels else ''
    tld = labels[-1].lower() if len(labels) > 1 else ''

    entropy = shannon_entropy(subdomain)
    ql = len(query)
    sl = len(subdomain)
    nr = numeric_ratio(subdomain)
    cr = consonant_ratio(subdomain)
    wbs = word_boundary_score(query, wordlist)

    # Trigram score on the subdomain
    trigrams = [subdomain[i:i+3].lower() for i in range(len(subdomain) - 2)]
    ngram_score = sum(trigram_model.get(t, -10.0) for t in trigrams) / max(len(trigrams), 1)

    payload_ratio = len(str(answer)) / max(ql, 1) if qtype == 'TXT' else 0.0

    return {
        'shannon_entropy': round(entropy, 3),
        'query_length': ql,
        'subdomain_length': sl,
        'numeric_ratio': round(nr, 3),
        'consonant_ratio': round(cr, 3),
        'ngram_score': round(ngram_score, 3),
        'has_known_tld': tld in KNOWN_TLDS,
        'word_boundary_score': round(wbs, 3),
        'query_type': qtype,
        'payload_ratio': round(payload_ratio, 3)
    }
```

**File:** `scripts/build_trigram_model.py` (new)

```
Build an English trigram frequency model from a wordlist.
Use the NLTK words corpus (nltk.corpus.words.words()).
Compute log-probability for each trigram.
Save to data/trigram_model.json
```

**File:** `train_dga_detector.py` (new)

```
Dataset: Use UNSW-NB15 DNS feature subset + generate synthetic DGA queries using DGArchive families.
Synthetic DGA families to simulate:
  - Random-char DGA (Conficker-style): random lowercase strings of length 8-16
  - Dictionary DGA (Suppobox-style): concatenated English words, length 15-30
  - Subdomain-tunnel (dnscat2-style): base64-like payloads in TXT queries, length 40-80

Benign: Alexa top-10k domain names as negative samples.

Feature columns: shannon_entropy, query_length, subdomain_length, numeric_ratio,
                 consonant_ratio, ngram_score, word_boundary_score, payload_ratio

Train RandomForestClassifier(n_estimators=200, class_weight='balanced').
Report F1 per class (benign, random_dga, dict_dga, tunnel).
Save to models/dga_model.joblib.
```

### Task 2.4 — TLS Malware Detector — ❌ NOT STARTED

No `backend/detectors/tls_detector.py` exists, and the `ja3` Zeek package is not installed. Build as originally specified:

```python
"""
TLS Malware Detector via JA3/JA4 Fingerprinting
Source: Zeek ssl.log events from Kafka topic 'ssl-events'

JA3 computation (from Zeek ssl.log fields):
  Zeek provides these fields in ssl.log:
    - ssl_version (as integer)
    - cipher (cipher suite code)
    - curve (elliptic curve id)
    - client_certs_len (number of client certs)
    - subject, issuer (cert fields)

  NOTE: Zeek does NOT provide raw ClientHello bytes in ssl.log by default.
  However, the ja3 Zeek package (available via zkg) adds ja3 and ja3s fields directly.

  Installation: zkg install zeek/salesforce/ja3
  After install, ssl.log will contain 'ja3' and 'ja3s' fields directly.
  Use these fields directly — do not recompute JA3 manually.

Detection logic:
  1. Hash lookup: check computed ja3 against known-bad JA3 hash database
     - Load from data/ja3_blacklist.json at startup (offline, no live queries)
     - Sources: SSL Blacklist (sslbl.abuse.ch), Emerging Threats JA3 list
  2. Flow statistics scoring (for unknown hashes):
     - Features: bytes_out, bytes_in, duration, byte_ratio, packet_count
     - Run pre-trained RandomForest on flow stats

Output alert evidence:
  {
    "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
    "ja3s_hash": "...",
    "detection_method": "blacklist" | "flow_stats_ml",
    "matched_malware_family": "Emotet" | null,
    "server_name": "suspicious-domain.ru",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "tls_version": "TLSv1.3",
    "bytes_out": 4821,
    "bytes_in": 12043,
    "byte_ratio": 0.40
  }
"""

import json
import hashlib
import joblib
from pathlib import Path

class TLSDetector:
    def __init__(self, blacklist_path='data/ja3_blacklist.json',
                 model_path='models/tls_flow_model.joblib'):
        with open(blacklist_path) as f:
            data = json.load(f)
            # Format: {"<ja3_hash>": {"family": "Emotet", "severity": "high"}, ...}
            self.blacklist = data
        self.flow_model = joblib.load(model_path) if Path(model_path).exists() else None

    def detect(self, ssl_event: dict) -> dict | None:
        ja3 = ssl_event.get('ja3', '')
        ja3s = ssl_event.get('ja3s', '')

        # Method 1: Blacklist lookup
        if ja3 and ja3 in self.blacklist:
            entry = self.blacklist[ja3]
            return {
                'detected': True,
                'confidence': 0.95,
                'detection_method': 'blacklist',
                'matched_malware_family': entry.get('family', 'Unknown'),
                'ja3_hash': ja3,
                'ja3s_hash': ja3s,
                'server_name': ssl_event.get('server_name', ''),
                'tls_version': ssl_event.get('version', ''),
                'bytes_out': ssl_event.get('orig_bytes', 0),
                'bytes_in': ssl_event.get('resp_bytes', 0),
                'byte_ratio': self._byte_ratio(ssl_event)
            }

        # Method 2: Flow statistics ML (for unknown hashes)
        if self.flow_model and ja3:
            features = self._extract_flow_features(ssl_event)
            proba = self.flow_model.predict_proba([features])[0][1]
            if proba > 0.70:
                return {
                    'detected': True,
                    'confidence': round(proba, 4),
                    'detection_method': 'flow_stats_ml',
                    'matched_malware_family': None,
                    'ja3_hash': ja3,
                    'ja3s_hash': ja3s,
                    'server_name': ssl_event.get('server_name', ''),
                    'tls_version': ssl_event.get('version', ''),
                    'bytes_out': ssl_event.get('orig_bytes', 0),
                    'bytes_in': ssl_event.get('resp_bytes', 0),
                    'byte_ratio': self._byte_ratio(ssl_event)
                }
        return None

    def _byte_ratio(self, e):
        ob, rb = e.get('orig_bytes', 0), e.get('resp_bytes', 1)
        return round(ob / max(rb, 1), 4)

    def _extract_flow_features(self, e):
        ob = e.get('orig_bytes', 0)
        rb = e.get('resp_bytes', 0)
        dur = e.get('duration', 1.0)
        return [ob, rb, dur, ob / max(rb, 1), ob + rb, dur / max(ob + rb, 1)]
```

**File:** `scripts/download_ja3_blacklist.py` (new)

```
Download JA3 blacklist from SSL Abuse (https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv).
Parse CSV: fields are Firstseen, ja3_md5, Malware_type.
Convert to JSON format: {"<ja3_hash>": {"family": "<Malware_type>", "severity": "high"}}
Save to data/ja3_blacklist.json.

Note: This is a one-time offline download. The detector loads it at startup.
It does NOT query the internet at runtime — fully compliant with one-way constraint.
```

**File:** `train_tls_flow_detector.py` (new)

```
Dataset: CICIDS2017 — use the 'Infiltration' and 'HTTPS LDOS' subsets for malicious class.
         Use normal HTTPS traffic flows as benign class.
Features: orig_bytes, resp_bytes, duration, byte_ratio, total_bytes, bytes_per_second
Train RandomForestClassifier(n_estimators=100).
Save to models/tls_flow_model.joblib.
```

### Task 2.5 — Data Exfiltration Detector — ❌ NOT STARTED

No `backend/detectors/exfil_detector.py` exists. Build as originally specified:

```python
"""
Data Exfiltration Detector
Source: Zeek conn.log events from Kafka topic 'conn-events'

Features per flow:
  - orig_bytes: bytes sent by source (upload volume)
  - resp_bytes: bytes received by source (download volume)
  - byte_ratio: orig_bytes / resp_bytes — HIGH means more upload than download (exfil signal)
  - duration: connection duration in seconds
  - orig_pkts: packet count from source
  - resp_pkts: packet count from destination
  - bytes_per_second: orig_bytes / duration
  - proto: tcp | udp | icmp

Exfiltration heuristics:
  - byte_ratio > 2.0 AND orig_bytes > 100000 → high-volume upload
  - duration > 300s AND byte_ratio > 1.5 → sustained upload
  - proto == 'icmp' AND orig_bytes > 1000 → ICMP tunnel (covert channel)
  - dst_port in [53, 80, 443] AND byte_ratio > 5.0 → covert exfil over common ports

Detection: RandomForestClassifier trained on CICIDS2017 exfiltration flows.

Output alert evidence:
  {
    "orig_bytes": 2481920,
    "resp_bytes": 8192,
    "byte_ratio": 303.0,
    "duration": 421.3,
    "bytes_per_second": 5893.2,
    "proto": "tcp",
    "dst_port": 443,
    "exfil_pattern": "HIGH_UPLOAD" | "SUSTAINED_UPLOAD" | "ICMP_TUNNEL" | "COVERT_PORT"
  }
"""
```

**File:** `train_exfil_detector.py` (new)

```
Dataset: CICIDS2017 — Infiltration subset for exfiltration class.
         Normal traffic flows as benign class.
Features: orig_bytes, resp_bytes, byte_ratio, duration, orig_pkts, resp_pkts,
          bytes_per_second (computed), is_icmp (binary), is_common_port (binary)
Train RandomForestClassifier(n_estimators=100, class_weight='balanced').
GroupKFold on dst_ip to prevent same-destination leakage.
Save to models/exfil_model.joblib.
Print F1, precision, recall.
```

### Acceptance Criteria — Phase 2
- [x] `models/c2_model.joblib` exists and C2 detector loads it without error
- [ ] `models/dga_model.joblib` exists and DGA detector correctly classifies random-char vs dictionary DGA
- [ ] `models/tls_flow_model.joblib` exists; TLS detector identifies at least one entry from the JA3 blacklist when fed a matching ssl.log event
- [ ] `models/exfil_model.joblib` exists and fires on a flow with byte_ratio > 5.0
- [x] Existing detectors (DDoS, Recon, C2) emit alerts using the shared `Detector.alert()` format from Phase 1 — new detectors must match the same format
- [ ] Lomb-Scargle periodogram — optional stretch goal, not required (see Task 2.2)

---

## PHASE 3 — CONFIDENCE CALIBRATION (Paper → Practice Innovation #1)
**Goal:** Make confidence scores mean something real, not just raw model probabilities.
**Time estimate:** 3–4 hours
**Status:** ❌ NOT STARTED

This is a genuine paper-to-practice contribution. No published passive NIDS does this. Unchanged from original plan — proceed after Phase 2's remaining three detectors are trained (calibrating models that don't exist yet is wasted work).

### Task 3.1 — Apply Platt Scaling to All Trained Models

**File:** `calibration/calibrate_models.py` (new)

```python
"""
Post-hoc confidence calibration using Platt Scaling.

After training each RandomForest model, we apply a CalibratedClassifierCV wrapper
using the sigmoid method (Platt scaling). This makes the output probability scores
correspond to actual empirical precision — i.e., an output of 0.87 means 87% of
alerts at that confidence level are true positives.

Why this matters for judges: The problem statement requires 'confidence scores'.
Raw sklearn predict_proba() outputs are NOT calibrated — they are biased high for
Random Forests (they cluster around 0.8-0.9 even for uncertain predictions).
Platt scaling corrects this.

How to calibrate:
  from sklearn.calibration import CalibratedClassifierCV, calibration_curve

  # For each model (ddos, recon, c2, dga, exfil):
  base_model = RandomForestClassifier(...)
  base_model.fit(X_train, y_train)

  # Calibrate on held-out calibration set (different from test set)
  # Split: 60% train, 20% calibration, 20% test
  calibrated_model = CalibratedClassifierCV(base_model, method='sigmoid', cv='prefit')
  calibrated_model.fit(X_cal, y_cal)

  # Verify calibration with reliability diagram
  prob_true, prob_pred = calibration_curve(y_test,
                                           calibrated_model.predict_proba(X_test)[:,1],
                                           n_bins=10)
  # prob_true should approximately equal prob_pred if well calibrated

  # Save calibrated model (replaces uncalibrated version)
  joblib.dump(calibrated_model, 'models/ddos_model_calibrated.joblib')

Run this for: ddos_model, c2_model, dga_model, exfil_model, tls_flow_model
(recon is F1=1.000 — calibration is trivial but apply it for consistency)
"""
```

**File:** `calibration/plot_reliability_diagrams.py` (new)

```
For each calibrated model, generate a reliability diagram (calibration curve plot).
Save as PNG to docs/calibration_plots/<model_name>_calibration.png
These are judge-facing evidence that confidence scores are meaningful.

Use matplotlib:
  plt.plot(prob_pred, prob_true, 's-', label=model_name)
  plt.plot([0,1],[0,1], 'k--', label='Perfect calibration')
  plt.xlabel('Mean predicted confidence')
  plt.ylabel('Fraction of true positives')
  plt.title(f'{model_name} — Calibration Curve (Platt Scaling)')
  plt.savefig(f'docs/calibration_plots/{model_name}_calibration.png')
```

### Task 3.2 — Replace Uncalibrated Models in Detectors

```
In each detector, load the calibrated model instead of the base model:
  - models/ddos_model_calibrated.joblib
  - models/c2_model_calibrated.joblib
  - models/dga_model_calibrated.joblib
  - models/exfil_model_calibrated.joblib
  - models/tls_flow_model_calibrated.joblib
  - models/recon_model_calibrated.joblib

The detector code does not need to change — only the model path changes.

Note: c2.py's range-gating logic (Phase 2.1) must stay in place around the
calibrated model the same way it wraps the uncalibrated one today.
```

### Acceptance Criteria — Phase 3
- [ ] All 6 models have `_calibrated.joblib` versions saved in `models/`
- [ ] Reliability diagrams exist in `docs/calibration_plots/`
- [ ] When fed a known DDoS attack flow, the DDoS detector returns confidence ≥ 0.85
- [ ] When fed a clearly benign flow, all detectors return confidence ≤ 0.30

---

## PHASE 4 — ADAPTIVE ENTROPY THRESHOLD FOR DDoS (Paper → Practice Innovation #2)
**Goal:** Fix the known open problem in DDoS detection — flash crowd vs. actual attack.
**Time estimate:** 3–4 hours
**Status:** ❌ NOT STARTED

**Re-scoped note:** the current DDoS detector already replaced the plan's original "hardcoded entropy threshold" with a trained RandomForest classifier (see Phase 0), so the specific bug this phase targets (static `entropy < 2.0` cutoff) no longer exists verbatim. The `AdaptiveEntropyBaseline` idea is still valuable as a **complementary, explainable signal** — e.g. as an additional evidence field, a supplementary trigger when the ML model is in its own low-confidence band, or the fallback rule's replacement (currently the fallback is still a flat `packet_rate > 200` threshold, which has the same flash-crowd weakness the original bug described). Treat this as **optional, lower priority than Phase 2's missing detectors.**

### Task 4.1 — Replace Static Entropy Threshold with Rolling Baseline

**File:** `detectors/ddos_detector.py` (modify existing)

```python
"""
Current problem: DDoS detector uses a hardcoded entropy threshold (e.g., entropy < 2.0).
This generates false positives during legitimate traffic surges (flash crowds).

Fix: Implement an adaptive baseline using a rolling window of historical entropy values.
Alert only when current entropy deviates > 2 standard deviations from the rolling baseline.

Implementation:
"""

from collections import deque
import statistics
import time

class AdaptiveEntropyBaseline:
    """
    Tracks a rolling 10-minute baseline of source-IP entropy values.
    Alerts when current entropy deviates beyond 2σ from baseline.
    """
    WINDOW_SECONDS = 600  # 10-minute rolling window
    MIN_SAMPLES = 10      # Need at least 10 samples before alerting
    SIGMA_THRESHOLD = 2.0 # Alert threshold in standard deviations

    def __init__(self):
        # Deque of (timestamp, entropy_value) tuples
        self._history = deque()

    def _prune(self):
        """Remove entries older than WINDOW_SECONDS."""
        cutoff = time.time() - self.WINDOW_SECONDS
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def update(self, entropy_value: float) -> None:
        self._history.append((time.time(), entropy_value))
        self._prune()

    def is_anomalous(self, current_entropy: float) -> tuple[bool, float]:
        """
        Returns (is_anomalous, sigma_deviation).
        is_anomalous = True if current_entropy is a statistically significant outlier.
        """
        self._prune()
        if len(self._history) < self.MIN_SAMPLES:
            # Not enough history — fall back to hardcoded threshold
            return current_entropy < 1.5, 0.0

        values = [v for _, v in self._history]
        mean = statistics.mean(values)
        stdev = statistics.stdev(values)

        if stdev < 0.01:
            # Traffic is very stable — any deviation is suspicious
            stdev = 0.01

        deviation = abs(current_entropy - mean) / stdev
        return deviation > self.SIGMA_THRESHOLD, round(deviation, 2)

# Usage in ddos_detector.py:
# baseline = AdaptiveEntropyBaseline()  # singleton, persist across events
# baseline.update(current_entropy)
# anomalous, sigma = baseline.is_anomalous(current_entropy)
# if anomalous:
#     confidence = min(0.99, 0.60 + (sigma - 2.0) * 0.10)  # scale with deviation
#     emit alert with evidence["sigma_deviation"] = sigma
```

### Acceptance Criteria — Phase 4
- [ ] DDoS detector's fallback rule (or an added evidence field) uses `AdaptiveEntropyBaseline` instead of the flat `packet_rate > 200` fallback
- [ ] Detector does NOT alert during the first 10 samples (insufficient baseline)
- [ ] Evidence sub-object includes `"sigma_deviation"` field
- [ ] `sigma_deviation > 2.0` for synthetic DDoS test, `< 1.0` for normal traffic surge test

---

## PHASE 5 — CROSS-THREAT CORRELATION ENGINE (Paper → Practice Innovation #3)
**Goal:** First known open-source implementation of cross-threat correlation in a passive one-way pipeline.
**Time estimate:** 4–5 hours
**Status:** ❌ NOT STARTED — no `correlation/` directory exists

Unchanged from original plan. Blocked on Phase 2's three missing detectors — a correlation engine has nothing to correlate against with only DDoS/Recon/C2 (only Pattern A, Recon → DDoS, is even reachable today).

### Task 5.1 — Correlation Engine

**File:** `correlation/correlator.py` (new)

```python
"""
Cross-Threat Correlation Engine

Consumes alerts from all six detectors and identifies multi-vector attack patterns.
Emits a composite "MULTI_VECTOR" alert when correlated threats are detected
from the same source within a time window.

Correlation patterns:
  Pattern A — Recon → DDoS (reconnaissance followed by DDoS):
    RECON alert from src_ip, then within 300 seconds, DDOS alert from same src_ip
    → MULTI_VECTOR alert: "RECON_DDOS" with boosted confidence

  Pattern B — C2 → Exfil (command and control leading to data theft):
    C2_BEACON alert (any src → dst), then within 600 seconds, EXFIL alert from same src_ip
    → MULTI_VECTOR alert: "C2_EXFIL" with boosted confidence

  Pattern C — DGA → C2 (domain generation followed by beaconing):
    DGA_DNS alert from src_ip, then within 120 seconds, C2_BEACON alert from same src_ip
    → MULTI_VECTOR alert: "DGA_C2" — likely botnet infection

  Pattern D — Full kill chain (recon → C2 → exfil within 10 minutes):
    RECON + C2_BEACON + EXFIL from same src_ip within 600 seconds
    → MULTI_VECTOR alert: "KILL_CHAIN" with confidence 0.95 (highest priority)
"""

import time
from collections import defaultdict
from odin.schema import ODINAlert, make_alert

CORRELATION_WINDOW = 600  # seconds

class CorrelationEngine:
    def __init__(self):
        # Per-source alert history: {src_ip: [(timestamp, threat_class, alert), ...]}
        self._history = defaultdict(list)

    def _prune(self, src_ip: str):
        cutoff = time.time() - CORRELATION_WINDOW
        self._history[src_ip] = [
            (ts, tc, alert) for ts, tc, alert in self._history[src_ip]
            if ts > cutoff
        ]

    def ingest_alert(self, alert: ODINAlert) -> ODINAlert | None:
        """
        Ingest a single alert. Returns a correlated MULTI_VECTOR alert if a pattern matches,
        or None if no correlation detected.
        """
        src = alert.src_ip
        self._history[src].append((time.time(), alert.threat_class, alert))
        self._prune(src)

        classes_seen = {tc for _, tc, _ in self._history[src]}

        # Pattern D: Kill chain (highest priority, check first)
        if {'RECON', 'C2_BEACON', 'EXFIL'}.issubset(classes_seen):
            return self._make_correlated(src, 'KILL_CHAIN', 0.97, self._history[src])

        # Pattern B: C2 → Exfil
        if {'C2_BEACON', 'EXFIL'}.issubset(classes_seen):
            return self._make_correlated(src, 'C2_EXFIL', 0.92, self._history[src])

        # Pattern C: DGA → C2
        if {'DGA_DNS', 'C2_BEACON'}.issubset(classes_seen):
            return self._make_correlated(src, 'DGA_C2', 0.88, self._history[src])

        # Pattern A: Recon → DDoS
        if {'RECON', 'DDOS'}.issubset(classes_seen):
            return self._make_correlated(src, 'RECON_DDOS', 0.85, self._history[src])

        return None

    def _make_correlated(self, src_ip, pattern, confidence, history):
        contributing = [
            {'threat_class': tc, 'timestamp': ts}
            for ts, tc, _ in history
        ]
        latest = max(history, key=lambda x: x[0])
        _, _, ref_alert = latest
        return make_alert(
            threat_class='MULTI_VECTOR',
            confidence=confidence,
            src_ip=src_ip,
            dst_ip=ref_alert.dst_ip,
            src_port=ref_alert.src_port,
            dst_port=ref_alert.dst_port,
            evidence={
                'pattern': pattern,
                'contributing_alerts': contributing,
                'correlation_window_seconds': CORRELATION_WINDOW
            },
            detector_version='correlator_v1'
        )
```

**Note:** the `from odin.schema import ODINAlert, make_alert` import assumes Phase 1's original `odin/schema.py` design was adopted. Since Phase 1 (Task 1.4) instead recommends keeping the existing `Detector.alert()` dict format, adapt this module to consume/produce plain dicts (`alert["threat_class"]`, `alert["src_ip"]`, etc.) instead of the `ODINAlert` dataclass, unless the schema migration (option b in Task 1.4) is done first.

### Task 5.2 — Wire Correlation Engine into Stream Consumer

**File:** `stream_consumer.py` (modify)

```
After each detector emits an alert, pass it to the CorrelationEngine:

from correlation.correlator import CorrelationEngine
correlator = CorrelationEngine()  # singleton

def handle_alert(alert):
    # Publish to alerts.json / dashboard as normal
    publish_alert(alert)

    # Check for cross-threat correlation
    correlated = correlator.ingest_alert(alert)
    if correlated:
        publish_alert(correlated)  # emit MULTI_VECTOR alert as a separate alert record
```

### Acceptance Criteria — Phase 5
- [ ] `CorrelationEngine.ingest_alert()` returns a MULTI_VECTOR alert when RECON + DDoS alerts arrive from same src_ip within 300s
- [ ] KILL_CHAIN pattern fires when RECON + C2_BEACON + EXFIL arrive within 600s
- [ ] MULTI_VECTOR alerts appear in the dashboard with `threat_class = "MULTI_VECTOR"`
- [ ] Evidence sub-object lists all contributing alerts with their timestamps

---

## PHASE 6 — DASHBOARD + API COMPLETION
**Goal:** Make the frontend complete and judge-demo ready.
**Time estimate:** 6–8 hours → **remaining work: ~3–5 hours** (throughput panel, replay, and README already done)

### Task 6.1 — Fix Dashboard Metrics Display — ⚠️ PARTIAL

**File:** React frontend (existing dashboard component)

- [x] **THROUGHPUT PANEL** — done. `StatusBar.jsx` shows `events_per_sec`, sourced from `/api/throughput`.
- [ ] **DETECTOR STATUS PANEL** (6 boxes, one per threat class) — only meaningful for the 3 existing detectors today (`ActiveDetectors.jsx` exists but reflects only DDoS/Recon/C2). Extend once Phase 2's remaining detectors exist; no point building placeholder boxes for detectors that don't run yet.
- [ ] **ALERT FEED evidence display** — verify current alert cards render the `evidence` list from `Detector.alert()`; extend to handle the new detectors' evidence shape (kept as a list of strings per Task 1.4's decision, not a sub-object) once built.
- [ ] **MULTI_VECTOR "⚡ KILL CHAIN" badge** — blocked on Phase 5.
- [ ] **CALIBRATION CONFIDENCE INDICATOR** ("(calibrated)" label/tooltip) — blocked on Phase 3.

### Task 6.2 — PCAP Replay Mode (Addresses PS Requirement F6) — ✅ DONE, DIFFERENT IMPLEMENTATION

Implemented as `/api/replay/<threat>` in `app.py` rather than a standalone `scripts/pcap_replay.py` CLI script. It re-reads a bundled pcap offline through the already-running `zeek_monitor` container (`zeek -r`) and appends the resulting `conn.log` lines into the live log the real pipeline tails, with timestamps shifted so the earliest lands at "now". This avoids needing raw-socket privileges / passwordless sudo for `tcpreplay`, which the original plan's script would have required. See `ML_MODELS.md` "Replay for demo" section for the full mechanism.

Demo pcaps already exist in `traffic_pcaps/`: `attack_syn_flood.pcap`, `attack_recon.pcap`, `attack_c2.pcap`, `attack_dns_tunnel.pcap` (ready for the DGA detector once built), `benign.pcap`. **No further work needed** unless a kill-chain-specific combined pcap is wanted for the Phase 5 demo (optional, generate once correlation engine exists).

### Task 6.3 — README and Documentation — ✅ DONE

`README.md` already exists and is written to the same standard this plan should be held to: it explicitly states only 3/6 detectors are implemented, includes a "Threat Coverage matrix", and doesn't overclaim. `ML_MODELS.md` covers the detector-specific documentation (F1 scores, validation methodology, honest limitations) that the plan's README template asked for. Update both as Phase 2's remaining detectors and Phase 3's calibration land — no full rewrite needed, just incremental additions to the existing tables.

### Acceptance Criteria — Phase 6
- [x] Dashboard shows non-zero throughput when traffic is flowing
- [ ] All 6 detector status boxes show GREEN when models are loaded (only 3 exist today)
- [ ] MULTI_VECTOR alerts render with special badge (blocked on Phase 5)
- [x] PCAP replay mode produces alerts on the dashboard within 30 seconds of starting
- [x] README documents implemented detectors with their F1 scores and model files (update as new detectors land)

---

## PHASE 7 — BENCHMARKING + THROUGHPUT DEMONSTRATION
**Goal:** Produce the stated throughput number required by the problem statement (F4).
**Time estimate:** 2–3 hours
**Status:** ❌ NOT STARTED

Unchanged from original plan.

### Task 7.1 — Throughput Benchmark Script

**File:** `scripts/benchmark_throughput.py` (new)

```
Measure end-to-end pipeline throughput.

Method:
  1. Generate a synthetic conn.log with 100,000 rows at the FASTEST rate Kafka will accept
  2. Publish all rows to Kafka using kafka_producer.py in benchmark mode
  3. stream_consumer.py processes them and counts flows_processed_total
  4. Measure: elapsed_time = time from first publish to last consumer acknowledgement
  5. throughput = 100000 / elapsed_time flows/sec

Report:
  - Sustained throughput (flows/sec)
  - Peak throughput (burst of 10,000 flows)
  - Per-detector latency: time from Kafka publish to alert emit for each threat class

Target: demonstrate > 5,000 flows/sec on commodity laptop hardware.
This is the number that goes in README and F4 evidence.

Save results to docs/benchmark_results.json
```

### Acceptance Criteria — Phase 7
- [ ] `docs/benchmark_results.json` exists with real measured numbers
- [ ] README states the throughput number from benchmark results
- [ ] Per-detector latency is measured for at least DDoS and Recon

---

## FILE STRUCTURE — CURRENT vs. FINAL STATE

```
ntro-prototype/
├── README.md                          ✅ exists (Phase 6.3)
├── ML_MODELS.md                       ✅ exists — detector-specific docs (not in original plan, better than it)
├── backend/
│   ├── app.py                         ✅ exists — /api/stats, /api/throughput, /api/replay/<threat>
│   ├── stream_consumer.py             ✅ exists — normalize_event(), throughput counter; ❌ correlator not wired (Phase 5)
│   ├── kafka_producer.py              ✅ exists
│   ├── detectors/
│   │   ├── base.py                    ✅ exists — Detector.alert() unified format
│   │   ├── ddos.py                    ✅ trained model wired; ❌ cooldown missing (Phase 1.3)
│   │   ├── recon.py                   ✅ trained model wired, has cooldown
│   │   ├── c2.py                      ✅ trained model wired, range-gated
│   │   ├── dga_detector.py            ❌ Phase 2.3 (new)
│   │   ├── tls_detector.py            ❌ Phase 2.4 (new)
│   │   └── exfil_detector.py          ❌ Phase 2.5 (new)
│   └── ml_models/
│       ├── ddos_model.joblib          ✅
│       ├── recon_model_v3.joblib      ✅
│       ├── c2_model.joblib            ✅
│       ├── dga_model.joblib           ❌ Phase 2.3
│       ├── tls_flow_model.joblib      ❌ Phase 2.4
│       └── exfil_model.joblib         ❌ Phase 2.5
├── correlation/
│   └── correlator.py                  ❌ Phase 5 (new)
├── calibration/
│   ├── calibrate_models.py            ❌ Phase 3
│   └── plot_reliability_diagrams.py   ❌ Phase 3
├── data/
│   ├── ja3_blacklist.json             ❌ Phase 2.4
│   ├── trigram_model.json             ❌ Phase 2.3
│   └── ...
├── traffic_pcaps/                     ✅ exists — attack_syn_flood, attack_recon, attack_c2, attack_dns_tunnel, benign
├── scripts/
│   ├── build_trigram_model.py         ❌ Phase 2.3
│   ├── download_ja3_blacklist.py      ❌ Phase 2.4
│   └── benchmark_throughput.py        ❌ Phase 7
├── training/
│   ├── train_dga_detector.py          ❌ Phase 2.3
│   ├── train_tls_flow_detector.py     ❌ Phase 2.4
│   └── train_exfil_detector.py        ❌ Phase 2.5
├── docs/
│   ├── calibration_plots/             ❌ Phase 3
│   └── benchmark_results.json         ❌ Phase 7
└── frontend/                          ✅ exists — Overview/Architecture pages, StatusBar, ActiveDetectors
```

---

## EXECUTION ORDER SUMMARY

| Phase | What | Status | Remaining Time | Blocker For |
|---|---|---|---|---|
| 1 | Bug fixes + unified schema | ⚠️ DDoS cooldown open, schema decision needed | ~1–2h | Everything |
| 2 | Train 3 missing detectors (DGA, TLS, Exfil) | ⚠️ 3/6 done (DDoS/Recon/C2) | ~10–13h | Phase 3, 5 |
| 3 | Platt scaling calibration | ❌ not started | 3–4h | Phase 6 dashboard |
| 4 | Adaptive entropy threshold | ❌ not started, optional/lower priority | 3–4h | None (self-contained) |
| 5 | Cross-threat correlation | ❌ not started | 4–5h | Phase 6 dashboard |
| 6 | Dashboard + PCAP replay + README | ⚠️ replay & README done, status panel/badges pending | ~3–5h | Phase 7 |
| 7 | Throughput benchmark | ❌ not started | 2–3h | README F4 claim |

**Remaining estimated effort: ~27–36 hours** (down from the original 34–46h — Phase 0/1 groundwork and the C2 model are already done).

---

## JUDGE DEMO SCRIPT (What to Show in 10 Minutes)

1. Start PCAP replay: use the existing `/api/replay/<threat>` endpoint (or a future combined kill-chain pcap once Phase 5 lands)
2. Show dashboard: recon alert fires → C2 beacon alert fires → (once built) exfil alert fires → (once built) KILL_CHAIN MULTI_VECTOR alert fires
3. Click on DDoS detector card → show `sigma_deviation` evidence field (once Phase 4's adaptive baseline is added) or today's ML confidence + supporting entropy evidence
4. Click on C2 detector card → show the range-gated model's evidence lines (mean interval, CV, observation count) — the *already-shipped* "paper → practice" story, not the periodogram
5. Click on any alert → show confidence score, with "(calibrated)" label once Phase 3 lands
6. Show README throughput number once Phase 7's benchmark is run
7. Show `docs/calibration_plots/ddos_calibration.png` once Phase 3 lands

**Key talking points (update as phases land):**
- "We selected different models per threat because each threat has a different statistical structure"
- "Our C2 detector's range-gating was found and fixed by stress-testing the deployed model, not just cross-validation — see ML_MODELS.md for the full story"
- "The correlation engine detects kill chains — no individual detector can do this alone" (once Phase 5 lands)
- "The entire pipeline is passive — nothing goes back through the diode"
