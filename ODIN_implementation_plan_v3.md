# ODIN — Implementation Plan v3 (merged)
## One-way Detection and Intelligence Network
### Problem 26145 — NTRO | Team: Cyber Phoenix
### Merges v1 (status-accurate but templated) and v2 (implementation-ready but with 3 verified defects) — September 2026

---

## WHAT CHANGED FROM v2 (read this before implementing anything)

v2 was more implementation-ready than v1 (better correlation-engine correctness, more realistic detector edge-case handling), but four things in it were checked against the actual running code and found wrong or missing. This document keeps everything v2 got right and fixes these:

1. **DDoS cooldown used the wrong clock.** v2's Task 1.1 claimed to mirror `recon.py` exactly but used `time.time()` (wall clock). `recon.py` actually keys its cooldown off the event's own `ts` field. Under PCAP replay — the pipeline's main demo mechanism — Zeek processes a pre-recorded pcap far faster than the traffic it represents, so a wall-clock cooldown desyncs from the simulated timeline. Fixed in Phase 1 below to use `ts`, matching `recon.py` exactly.
2. **Phase 4's premise was stale.** v2 stated "DDoS detector uses a hardcoded entropy threshold" as verified fact. It's false: `ddos.py`'s fallback (used only if the ML model fails to load) is a flat `packet_rate > 200` check; entropy is computed only for evidence text, never as a trigger. Phase 4 below is re-scoped to what's actually true.
3. **New detectors didn't fit the pipeline's actual dispatch contract.** `backend/stream_consumer.py` instantiates every class in `detectors/__init__.py`'s `ACTIVE_DETECTORS` list and calls `.process(event)` on each, expecting the exact dict shape `Detector.alert()` (in `backend/detectors/base.py`) produces. v2's `DGADetector`/`TLSMalwareDetector`/`ExfilDetector` didn't subclass `Detector`, implemented `.detect()` instead of `.process()`, and returned a different dict shape — despite v2's own acceptance criteria requiring `Detector.alert()` compliance. As written, they would never fire. Fixed below: all three now subclass `Detector`, implement `process()`, and call `self.alert()`.
4. **No DNS/SSL event pipeline exists yet.** Both v1 and v2 wrote DGA/TLS detector docstrings assuming Kafka topics `dns-events`/`ssl-events` already deliver normalized DNS/SSL events. Checked against the actual code: `kafka_producer.py` only tails `conn.log` and publishes to a single topic, `zeek-conn`; `stream_consumer.py`'s `normalize_event()` only understands conn.log fields. There is currently no DNS or SSL event path into the pipeline at all. This is now an explicit task (Phase 2, Task 2.0) — without it, the DGA and TLS detectors have nothing to consume regardless of how well they're written.
5. **File paths corrected to match the actual repo layout.** v1/v2 both referenced a top-level `models/`, `detectors/`, `correlation/`. The real repo keeps runtime code and models under `backend/` (`backend/detectors/`, `backend/ml_models/`) because that's what `Path(__file__).parent.parent / "ml_models" / ...`-style loading in the existing detectors resolves against, and because `stream_consumer.py`'s `from detectors import ACTIVE_DETECTORS` / a future `from correlation.correlator import CorrelationEngine` only resolve if those packages live inside `backend/` alongside it. Paths below are corrected accordingly. One-off tooling (training scripts, the JA3/trigram downloaders, the benchmark script, calibration scripts) stays at repo-root `training/`, `scripts/`, `calibration/` — those aren't imported by the running app, they just need to write into `backend/ml_models/` and `backend/data/`.

Evidence rendering note (does not require a fix): the frontend's `AlertFeed.jsx` already normalizes `evidence` whether it's a list of strings (the pattern `ddos.py`/`recon.py`/`c2.py` use today) or a plain object (what v2's new detectors produce) — `normalizeEvidence()` converts an object to `"key: value"` lines automatically. So the new detectors' structured-evidence-object style is fine to keep; no schema fight here.

---

## VERIFIED BASELINE — WHAT IS CONFIRMED WORKING

Do not touch these. They are correct.

| Component | Status | Notes |
|---|---|---|
| Zeek NSM | ✅ Running | Producing conn.log, dns.log, ssl.log on disk |
| Kafka KRaft broker | ✅ Running | `kafka_producer.py` tails **conn.log only** today, topic `zeek-conn` |
| `stream_consumer.py` | ✅ Working | `normalize_event()` handles conn.log fields only (see gap #4 above) |
| Throughput counter | ✅ Done | `/api/throughput`, shown in `StatusBar.jsx` |
| dst_ip / id.resp_h parsing | ✅ Fixed | Destination IPs resolve correctly for conn.log events |
| `backend/detectors/base.py` `Detector.alert()` | ✅ Working | Shared alert format; `process(event) -> dict\|None` is the required interface |
| `detectors/__init__.py` `ACTIVE_DETECTORS` | ✅ Working | Currently `[DDoSDetector, ReconDetector, C2Detector]` — this list is how `stream_consumer.py` discovers detectors |
| DDoS detector | ✅ Trained | RF, 5 features, F1=0.994. Fallback (model-load-failure only) is a flat `packet_rate > 200` rule, **not** an entropy threshold |
| Recon detector | ✅ Trained | RF v3, GroupKFold, F1=1.000. Has a working per-source cooldown keyed on event `ts` — the reference pattern for Phase 1 |
| C2 detector | ✅ Trained | `c2_model.joblib` exists, range-gated (`observation_count<=11`, `mean_interval<=7.0s`), blind-spot documented in `ML_MODELS.md` |
| PCAP replay | ✅ Working | `/api/replay/<threat>` re-reads pcaps through the live Zeek container, injects into the real `conn.log` — processing happens much faster than the traffic's original timescale |
| React dashboard | ✅ Working | Overview/Architecture pages, `StatusBar`, `AlertFeed` (evidence renders lists or objects) |
| README | ✅ Written | Honestly documents 3/6 detectors with real F1 scores |
| DNS/SSL event pipeline | ❌ Does not exist | No Kafka topic for dns.log/ssl.log, no normalization for those fields — required before the DGA/TLS detectors can receive any events |

---

## PHASE 1 — ONE REMAINING BUG FIX
**Goal:** Close the last known bug before adding new detectors.
**Estimated time:** 1 hour
**Dependency:** None — do this first.

### Actual State
- `recon.py` has a per-source cooldown dict keyed on the **event's own `ts`** field (`self._last_alerted.get(src_ip, 0)`, compared against `ts`, not wall-clock time) — this is deliberate and correct: it makes the cooldown track simulated/event time, so it behaves the same whether traffic arrives live or via a fast PCAP replay.
- `ddos.py` has no cooldown at all — it fires once per triggering event, independently, every time the window's ML/rule check comes back positive.

### Task 1.1 — Add Per-Source Cooldown to `ddos.py`

**File:** `backend/detectors/ddos.py`

Mirror `recon.py`'s implementation exactly — same key (`ts`, not `time.time()`), same shape (an instance dict, not a module-level one).

```python
# In DDoSDetector.__init__, alongside self._window = deque():
self._last_alerted: dict[str, float] = {}

# Module-level constant, next to the other tuning constants:
ALERT_COOLDOWN = 30   # one alert per src_ip per 30s of *event* time -- matches recon.py

# In process(), immediately after "if not triggered: return None" and before
# building `evidence`/`severity`/calling self.alert():
if ts - self._last_alerted.get(src_ip, 0) < ALERT_COOLDOWN:
    return None
self._last_alerted[src_ip] = ts
```

**Why `ts` and not `time.time()`:** `ddos.py`'s own rolling window already uses the event's `ts` for its cutoff math (`cutoff = ts - WINDOW_SECONDS`). Using wall-clock time for the cooldown while using event time for the window would make the two pieces of logic disagree about what "recent" means, and would desync badly under PCAP replay, where real elapsed time and simulated elapsed time are different by design.

**Known limitation, not a blocker:** keying the cooldown by `src_ip` means a genuinely multi-source spoofed flood (many different source IPs, each seen once or twice) won't be meaningfully deduplicated by this cooldown — each new spoofed IP is a cache miss. This is fine for the current demo pcaps: per `ML_MODELS.md`, all three training/demo captures run against a single host (`127.0.0.1`), so `attack_syn_flood.pcap` is single-source. If a genuinely multi-source flood scenario is added later, consider keying by `(dst_ip, dst_port)` instead — not needed now.

### Acceptance Criteria — Phase 1
- [ ] DDoS detector emits at most one alert per `src_ip` per 30 seconds of **event** time (verify by feeding synthetic events with compressed real-time spacing but 30s+ of `ts` spacing — cooldown should still gate correctly)
- [ ] Structure of `_last_alerted` in `ddos.py` matches `recon.py`'s `_last_alerted` pattern (instance dict, keyed on `ts`)
- [ ] Existing DDoS F1=0.994 result is unaffected (cooldown is post-inference, not pre — the ML decision itself is untouched)
- [ ] No other files modified in this phase

---

## PHASE 2 — THREE MISSING DETECTORS
**Goal:** Bring detector count from 3/6 to 6/6 with trained models, wired into the real dispatch pipeline.
**Estimated time:** 16–20 hours total (was 14–18h in v2 — add ~2h for the Kafka wiring gap v2 missed)
**Dependency:** Phase 1 complete

### Actual State
- DGA/DNS tunnel, TLS/JA3 malware, and Data exfiltration: zero code, zero training data, zero model.
- `kafka_producer.py` tails **conn.log only**; there is no `dns-events`/`ssl-events` topic and no DNS/SSL field normalization anywhere in `stream_consumer.py`. Without Task 2.0, DGA and TLS detectors would have code but no events to consume.
- All three new detectors must subclass `backend/detectors/base.py`'s `Detector`, implement `process(self, event: dict) -> dict | None`, and return `self.alert(...)` — exactly like `ddos.py`/`recon.py`/`c2.py` do. `stream_consumer.py`'s dispatch loop (`for detector in detectors: alert = detector.process(event)`) is not changing, so the detectors must fit it, not the other way around.
- Because the dispatch loop runs **every** detector against **every** event regardless of source log, each new detector must self-filter by a `log_type` field as the first line of `process()` (added by Task 2.0's normalization work) and return `None` immediately for event types it doesn't handle.

---

### Task 2.0 — Wire DNS and SSL Events Into the Pipeline (new — missing from both prior versions)

**File:** `backend/kafka_producer.py` (modify)

```
Currently this file tails backend/zeek-logs/conn.log and publishes each JSON
line to the "zeek-conn" Kafka topic. Add two more tailers, mirroring the
existing conn.log loop exactly (same tailing mechanism, same JSON-line
publish pattern):

  - Tail backend/zeek-logs/dns.log -> publish to Kafka topic "zeek-dns"
  - Tail backend/zeek-logs/ssl.log -> publish to Kafka topic "zeek-ssl"

Topic names follow the existing "zeek-<logname>" convention already used by
"zeek-conn" -- do not use "dns-events"/"ssl-events" naming from earlier plan
drafts, which doesn't match what's actually running.

If the current tailing code is a single function, refactor to a small
(log_path, topic_name) list and run one tailer per entry, so a fourth log
type is a one-line addition later.
```

**File:** `backend/stream_consumer.py` (modify)

```
1. Subscribe to all three topics in one consumer (kafka-python's KafkaConsumer
   accepts multiple topic names as positional args):

     consumer = KafkaConsumer(
         "zeek-conn", "zeek-dns", "zeek-ssl",
         bootstrap_servers=KAFKA_BOOTSTRAP, ...
     )

2. Give normalize_event() a log_type per-record. The Kafka message itself
   doesn't carry which topic it came from once deserialized generically --
   use consumer.poll() -> record.topic, or (simpler) branch inside
   normalize_event() on which fields are present in the raw dict:

     - conn.log rows have "proto"/"conn_state" -> log_type = "conn" (existing shape, unchanged)
     - dns.log rows have "query"/"qtype_name"   -> log_type = "dns"
     - ssl.log rows have "version"/"cipher"      -> log_type = "ssl"

3. Extend normalize_event() to add, for dns rows:
     event["log_type"]    = "dns"
     event["query"]       = raw.get("query", "")
     event["qtype_name"]  = raw.get("qtype_name", "A")
     event["answers"]     = raw.get("answers", "")
   and for ssl rows:
     event["log_type"]     = "ssl"
     event["ja3"]          = raw.get("ja3", "")
     event["ja3s"]         = raw.get("ja3s", "")
     event["version"]      = raw.get("version", "")
     event["server_name"]  = raw.get("server_name", "")
     event["orig_bytes"]   = raw.get("orig_bytes", 0)
     event["resp_bytes"]   = raw.get("resp_bytes", 0)
     event["duration"]     = raw.get("duration", 0.0)
   conn.log rows keep their existing shape plus event["log_type"] = "conn".

4. Do NOT change the dispatch loop (`for detector in detectors: alert =
   detector.process(event)`). Every detector now runs against every event;
   each detector is responsible for ignoring event shapes it doesn't handle
   via a log_type check as the first line of process() (see 2.1-2.3 below).
```

**File:** `backend/detectors/__init__.py` (modify, at the end of Phase 2 once all three exist)

```python
from .ddos import DDoSDetector
from .recon import ReconDetector
from .c2 import C2Detector
from .dga import DGADetector
from .tls_malware import TLSMalwareDetector
from .exfil import ExfilDetector

ACTIVE_DETECTORS = [
    DDoSDetector, ReconDetector, C2Detector,
    DGADetector, TLSMalwareDetector, ExfilDetector,
]
```

**Note on the JA3 fields:** `ssl_event.get('ja3')`/`ja3s` will be empty until the `ja3` Zeek package is installed (`zkg install zeek/salesforce/ja3`, then restart Zeek) — see Task 2.2's setup note. Until then, ssl.log rows flow through the pipeline fine, just without a JA3 hash to look up (the blacklist path silently finds no match; the flow-stats ML path still works since it doesn't need JA3).

---

### Task 2.1 — DGA / DNS Tunnelling Detector

#### 2.1a — Detector

**File:** `backend/detectors/dga.py` (new)

```python
"""
DGA and DNS Tunnelling Detector
Consumes normalized events with log_type == "dns" (see Phase 2, Task 2.0).

DETECTION PATH A -- DNS TUNNEL (rule-based):
  Signal: TXT/NULL queries with unusually long names carrying encoded payload.
  Trigger when ALL of:
    - qtype_name in ['TXT', 'NULL']
    - len(query) > 50
    - payload_ratio > 3.0   (answer bytes / query bytes)
  Confidence = min(0.97, 0.60 + (query_length / 200) + (payload_ratio / 20))

DETECTION PATH B -- DGA (ML classifier):
  Features (extract for every DNS query):
    shannon_entropy, query_length, subdomain_length, numeric_ratio,
    consonant_ratio, ngram_score, word_boundary_score, has_known_tld
  Model: RandomForest loaded from backend/ml_models/dga_model.joblib
  Threshold: emit if predict_proba[:,1] > 0.70
  detection_path evidence field: "DICT_DGA" if word_boundary_score > 0.65 else "RANDOM_DGA"

Do NOT alert on:
  - Queries shorter than 10 characters (too short to classify reliably)
  - qtype_name == 'PTR' (reverse DNS -- high false positive rate)
  - Queries ending in '.local', '.internal', '.arpa' (mDNS / internal DNS)

If the model or its supporting data files are missing, the ML path (B) is
disabled but the rule-based tunnel path (A) still runs -- same
fail-gracefully pattern as ddos.py/recon.py/c2.py's model-load fallback.
"""

import math
import json
from collections import Counter
from pathlib import Path

from .base import Detector

KNOWN_TLDS = {'com', 'net', 'org', 'gov', 'edu', 'io', 'co', 'uk', 'de', 'fr', 'us'}
SKIP_QTYPES = {'PTR'}
SKIP_SUFFIXES = ('.local', '.internal', '.arpa')

MODEL_PATH    = Path(__file__).parent.parent / "ml_models" / "dga_model.joblib"
TRIGRAM_PATH  = Path(__file__).parent.parent / "data" / "trigram_model.json"
WORDLIST_PATH = Path(__file__).parent.parent / "data" / "english_wordlist.txt"

FEATURE_NAMES = [
    'shannon_entropy', 'query_length', 'subdomain_length',
    'numeric_ratio', 'consonant_ratio', 'ngram_score',
    'word_boundary_score', 'has_known_tld',
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def consonant_ratio(s: str) -> float:
    vowels = set('aeiou')
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c not in vowels) / len(alpha)


def numeric_ratio(s: str) -> float:
    return sum(1 for c in s if c.isdigit()) / max(len(s), 1)


def ngram_score(s: str, trigram_model: dict) -> float:
    s = s.lower()
    trigrams = [s[i:i + 3] for i in range(len(s) - 2)]
    if not trigrams:
        return -10.0
    return sum(trigram_model.get(t, -10.0) for t in trigrams) / len(trigrams)


def word_boundary_score(domain: str, wordlist: set) -> float:
    """Fraction of the leftmost subdomain decomposable into known English words.
    High = dictionary DGA (Suppobox-style). Low = random DGA."""
    label = domain.split('.')[0].lower()
    if not label:
        return 0.0
    matched, i = 0, 0
    while i < len(label):
        found = False
        for length in range(min(12, len(label) - i), 2, -1):
            if label[i:i + length] in wordlist:
                matched += length
                i += length
                found = True
                break
        if not found:
            i += 1
    return matched / len(label)


def extract_features(query: str, trigram_model: dict, wordlist: set) -> list:
    labels = query.split('.')
    subdomain = labels[0] if labels else ''
    tld = labels[-1].lower() if len(labels) > 1 else ''
    return [
        shannon_entropy(query),
        len(query),
        len(subdomain),
        numeric_ratio(subdomain),
        consonant_ratio(subdomain),
        ngram_score(subdomain, trigram_model),
        word_boundary_score(query, wordlist),
        int(tld in KNOWN_TLDS),
    ]


class DGADetector(Detector):
    name = "dga"
    threat_class = "dga"
    threat_label = "DGA / DNS Tunnelling"

    def __init__(self):
        self.model = self._load_model()
        self.trigram_model = self._load_json(TRIGRAM_PATH)
        self.wordlist = self._load_wordlist()

    @staticmethod
    def _load_model():
        try:
            import joblib
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[dga] ML model unavailable ({e}) -- DGA path disabled, tunnel rule still active")
            return None

    @staticmethod
    def _load_json(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def _load_wordlist():
        try:
            with open(WORDLIST_PATH) as f:
                return set(w.strip().lower() for w in f if len(w.strip()) > 2)
        except Exception:
            return set()

    def process(self, event: dict) -> dict | None:
        if event.get("log_type") != "dns":
            return None

        query = event.get("query", "").rstrip(".")
        qtype = event.get("qtype_name", "A")
        answers = event.get("answers", "")
        src_ip, dst_ip, dst_port = event.get("src_ip"), event.get("dst_ip"), event.get("dst_port")

        if len(query) < 10 or qtype in SKIP_QTYPES or any(query.endswith(s) for s in SKIP_SUFFIXES):
            return None

        # Path A: tunnel (rule-based, checked first, doesn't need the model)
        if qtype in ('TXT', 'NULL'):
            payload_ratio = len(str(answers)) / max(len(query), 1)
            if len(query) > 50 and payload_ratio > 3.0:
                confidence = min(0.97, 0.60 + (len(query) / 200) + (payload_ratio / 20))
                evidence = {
                    "detection_path": "TUNNEL", "query": query,
                    "query_length": len(query), "payload_ratio": round(payload_ratio, 3),
                    "qtype": qtype,
                }
                return self.alert(
                    src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
                    flow_id=event.get("uid"), severity="HIGH", confidence=confidence,
                    evidence=evidence, window_seconds=0,
                )

        # Path B: DGA ML classifier
        if self.model is None:
            return None
        features = extract_features(query, self.trigram_model, self.wordlist)
        proba = float(self.model.predict_proba([features])[0][1])
        if proba <= 0.70:
            return None

        feat_dict = dict(zip(FEATURE_NAMES, features))
        detection_path = "DICT_DGA" if feat_dict["word_boundary_score"] > 0.65 else "RANDOM_DGA"
        severity = "HIGH" if proba > 0.85 else "MEDIUM"
        evidence = {
            "detection_path": detection_path, "query": query, "query_type": qtype,
            **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in feat_dict.items()},
        }
        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=proba,
            evidence=evidence, window_seconds=0,
        )
```

`window_seconds=0` reflects that this is a per-query detection with no rolling window, unlike ddos.py/recon.py's windowed checks — keep it, don't invent a fake window value.

#### 2.1b — Trigram model builder

**File:** `scripts/build_trigram_model.py` (new, repo root)

```python
"""
Build English character trigram log-probability model.
Run once before training: python scripts/build_trigram_model.py
Output: backend/data/trigram_model.json
Format: {"the": -2.14, "ing": -2.31, ...}  (log2 probabilities)
"""
import json, math
from collections import Counter
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "backend" / "data" / "trigram_model.json"

def build():
    try:
        import nltk
        nltk.download('words', quiet=True)
        from nltk.corpus import words as nltk_words
        corpus = ' '.join(nltk_words.words()).lower()
    except ImportError:
        with open('/usr/share/dict/words') as f:
            corpus = ' '.join(f.read().splitlines()).lower()

    counts = Counter(corpus[i:i+3] for i in range(len(corpus) - 2) if corpus[i:i+3].isalpha())
    total = sum(counts.values())
    model = {tg: round(math.log2(c / total), 4) for tg, c in counts.items()}

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(model, f)
    print(f"Wrote {len(model)} trigrams to {OUTPUT}")

if __name__ == '__main__':
    build()
```

#### 2.1c — English wordlist

```
Generate backend/data/english_wordlist.txt -- one lowercase word per line:

  python -c "import nltk; nltk.download('words');
    from nltk.corpus import words;
    open('backend/data/english_wordlist.txt','w').write('\n'.join(words.words()))"

Used by word_boundary_score() for dictionary-DGA detection.
```

#### 2.1d — Training script

**File:** `training/train_dga.py` (new, repo root)

```
Dataset construction:
  BENIGN (label=0): Alexa top-10k / Majestic Million domains, ~5000 samples.
  RANDOM DGA (label=1, RANDOM_DGA): random lowercase strings length 8-16 + common
    TLDs (.com, .net, .ru, .cn), ~3000 samples.
  DICTIONARY DGA (label=1, DICT_DGA): concatenate 2-4 random English words from
    backend/data/english_wordlist.txt, e.g. "sunshinevalleycloud.com", ~2000 samples.

Feature extraction: reuse extract_features() from backend/detectors/dga.py
directly (import it) rather than reimplementing it here -- keeps train/serve
feature computation identical by construction.

Training:
  RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
  GroupKFold(n_splits=5), grouped by round(query_length / 5) * 5 to prevent
  domain-length leakage across folds.
  80/20 stratified train/test split for the final held-out evaluation.
  Print classification_report(target_names=['benign', 'dga']).

  Before saving, split off a calibration set (see Phase 3) and persist it:
    np.savez('backend/ml_models/dga_cal_data.npz', X=X_cal, y=y_cal, X_test=X_test, y_test=y_test)

  Save to backend/ml_models/dga_model.joblib
  Update ML_MODELS.md with F1, precision, recall, training set composition, date.

Target F1 > 0.90 on held-out test. If dictionary-DGA F1 < 0.80, check that
word_boundary_score is actually loading a non-empty wordlist -- that's the
one feature doing the work entropy-based detection misses for this class.
```

---

### Task 2.2 — TLS Malware Detector

#### 2.2a — JA3 package setup

```
zkg install zeek/salesforce/ja3
zeekctl deploy   (or restart the zeek_monitor container)
Verify: tail -f backend/zeek-logs/ssl.log | head -5   -- should show ja3/ja3s fields.

If zkg is unavailable, the detector still runs on flow-stats ML alone (Path B
below) -- the blacklist path (Path A) just never matches until ja3 is populated.
```

#### 2.2b — Offline JA3 blacklist

**File:** `scripts/download_ja3_blacklist.py` (new, repo root)

```python
"""
Download JA3 blacklist from SSL Abuse and save offline. Run ONCE before
starting the detector -- never called at runtime, fully compliant with the
one-way constraint.
Source: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
Output: backend/data/ja3_blacklist.json
Format: {"<md5_hash>": {"family": "<Malware_type>", "severity": "high"}, ...}
"""
import csv, json, urllib.request
from pathlib import Path

URL = 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv'
OUTPUT = Path(__file__).parent.parent / "backend" / "data" / "ja3_blacklist.json"

def download():
    result = {}
    with urllib.request.urlopen(URL) as resp:
        lines = resp.read().decode('utf-8').splitlines()
    reader = csv.DictReader(l for l in lines if not l.startswith('#'))
    for row in reader:
        h = row.get('ja3_md5', '').strip()
        if h:
            result[h] = {'family': row.get('Malware_type', 'Unknown').strip(), 'severity': 'high'}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Saved {len(result)} JA3 entries to {OUTPUT}")

if __name__ == '__main__':
    download()
```

#### 2.2c — Detector

**File:** `backend/detectors/tls_malware.py` (new)

```python
"""
TLS Malware Detector via JA3/JA4 Fingerprinting
Consumes normalized events with log_type == "ssl" (see Phase 2, Task 2.0).

PATH A -- JA3 blacklist lookup (rule-based, high confidence):
  Check event['ja3'] against backend/data/ja3_blacklist.json, loaded at startup.
  Match -> confidence 0.95, detection_method = 'ja3_blacklist'.

PATH B -- flow statistics ML (catches unknown malware not in the blacklist):
  Features: orig_bytes, resp_bytes, duration, byte_ratio, total_bytes, bytes_per_sec
  Model: backend/ml_models/tls_flow_model.joblib
  Threshold: predict_proba[:,1] > 0.72, detection_method = 'flow_stats_ml'

Do NOT alert on:
  - Internal RFC1918 server IPs (10.x, 172.16-31.x, 192.168.x) -- high FP rate
  - Sessions with duration < 0.1s or total_bytes < 100 (too little data to classify)
"""
import json, joblib
from pathlib import Path

from .base import Detector

BLACKLIST_PATH = Path(__file__).parent.parent / "data" / "ja3_blacklist.json"
MODEL_PATH     = Path(__file__).parent.parent / "ml_models" / "tls_flow_model.joblib"

RFC1918_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                    '172.30.', '172.31.', '192.168.')


class TLSMalwareDetector(Detector):
    name = "tls"
    threat_class = "tls"
    threat_label = "TLS Malware (JA3)"

    def __init__(self):
        self.blacklist = self._load_blacklist()
        self.flow_model = self._load_model()

    @staticmethod
    def _load_blacklist():
        try:
            with open(BLACKLIST_PATH) as f:
                return json.load(f)
        except Exception as e:
            print(f"[tls] JA3 blacklist unavailable ({e}) -- blacklist path disabled")
            return {}

    @staticmethod
    def _load_model():
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[tls] flow-stats model unavailable ({e}) -- ML path disabled")
            return None

    @staticmethod
    def _is_internal(ip: str) -> bool:
        return any((ip or "").startswith(p) for p in RFC1918_PREFIXES)

    @staticmethod
    def _flow_features(e: dict) -> list:
        ob = float(e.get('orig_bytes', 0) or 0)
        rb = float(e.get('resp_bytes', 0) or 0)
        dur = float(e.get('duration', 0.001) or 0.001)
        total = ob + rb
        return [ob, rb, dur, ob / max(rb, 1), total, total / dur]

    def process(self, event: dict) -> dict | None:
        if event.get("log_type") != "ssl":
            return None

        dst_ip = event.get("dst_ip", "")
        duration = float(event.get("duration", 0) or 0)
        orig_bytes = int(event.get("orig_bytes", 0) or 0)
        resp_bytes = int(event.get("resp_bytes", 0) or 0)
        total_bytes = orig_bytes + resp_bytes

        if self._is_internal(dst_ip) or duration < 0.1 or total_bytes < 100:
            return None

        ja3 = event.get('ja3', '') or ''
        base_evidence = {
            'ja3_hash': ja3, 'matched_malware_family': None,
            'server_name': event.get('server_name', ''), 'tls_version': event.get('version', ''),
            'orig_bytes': orig_bytes, 'resp_bytes': resp_bytes,
            'byte_ratio': round(orig_bytes / max(resp_bytes, 1), 4),
        }

        if ja3 and ja3 in self.blacklist:
            entry = self.blacklist[ja3]
            evidence = {**base_evidence, 'detection_method': 'ja3_blacklist',
                        'matched_malware_family': entry.get('family', 'Unknown')}
            return self.alert(
                src_ip=event.get("src_ip"), src_port=None, dst_ip=dst_ip, dst_port=event.get("dst_port"),
                flow_id=event.get("uid"), severity="HIGH", confidence=0.95,
                evidence=evidence, window_seconds=0,
            )

        if self.flow_model is not None:
            proba = float(self.flow_model.predict_proba([self._flow_features(event)])[0][1])
            if proba > 0.72:
                evidence = {**base_evidence, 'detection_method': 'flow_stats_ml'}
                severity = "HIGH" if proba > 0.85 else "MEDIUM"
                return self.alert(
                    src_ip=event.get("src_ip"), src_port=None, dst_ip=dst_ip, dst_port=event.get("dst_port"),
                    flow_id=event.get("uid"), severity=severity, confidence=proba,
                    evidence=evidence, window_seconds=0,
                )

        return None
```

#### 2.2d — Training script

**File:** `training/train_tls_flow.py` (new, repo root)

```
Dataset: CICIDS2017 'Infiltration'/'HTTPS LDOS' subsets as malicious class;
normal HTTPS flows as benign. If unavailable locally, generate synthetic:
  Malicious: orig_bytes in [50k, 5M], byte_ratio in [0.5, 10.0], duration in [0.1, 300s]
  Benign:    orig_bytes in [1k, 100k], byte_ratio in [0.05, 1.0], duration in [0.5, 30s]

Features: orig_bytes, resp_bytes, duration, byte_ratio, total_bytes, bytes_per_sec
RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
80/20 stratified split, print classification_report().

Persist calibration split: np.savez('backend/ml_models/tls_flow_cal_data.npz', ...)
Save to backend/ml_models/tls_flow_model.joblib
Update ML_MODELS.md.
```

---

### Task 2.3 — Data Exfiltration Detector

#### 2.3a — Detector

**File:** `backend/detectors/exfil.py` (new)

```python
"""
Data Exfiltration Detector
Consumes normalized events with log_type == "conn" (same topic as ddos.py/recon.py/c2.py).

Rule-based pre-filter (adds a human-readable pattern label; ML makes the final call):
  ICMP covert channel : proto == 'icmp' AND orig_bytes > 1000
  DNS exfil            : dst_port == 53  AND orig_bytes > 5000
  High-volume upload    : byte_ratio > 5.0 AND orig_bytes > 500_000
  Sustained upload      : duration > 300 AND byte_ratio > 2.0

If any rule fires AND ML confidence > 0.60 -> emit alert.
If only ML fires (no rule pattern) -> require confidence > 0.80 to emit
  (raises the bar when there's no human-checkable pattern backing the ML call).

Do NOT alert on:
  - Internal-to-internal flows (both src and dst are RFC1918)
  - Flows with orig_bytes < 1000 (too small to be meaningful exfil)
"""
import joblib
from pathlib import Path

from .base import Detector

MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "exfil_model.joblib"

RFC1918_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                    '172.30.', '172.31.', '192.168.')


class ExfilDetector(Detector):
    name = "exfil"
    threat_class = "exfil"
    threat_label = "Data Exfiltration"

    def __init__(self):
        self.model = self._load_model()

    @staticmethod
    def _load_model():
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[exfil] ML model unavailable ({e}) -- detector disabled (no fixed-threshold fallback; "
                  f"byte-ratio rules alone are too noisy to run standalone)")
            return None

    @staticmethod
    def _is_internal(ip: str) -> bool:
        return any((ip or "").startswith(p) for p in RFC1918_PREFIXES)

    @staticmethod
    def _extract(event: dict) -> tuple[list, dict]:
        ob = float(event.get('orig_bytes', 0) or 0)
        rb = float(event.get('resp_bytes', 0) or 0)
        dur = float(event.get('duration', 0.001) or 0.001)
        op = int(event.get('orig_pkts', 0) or 0)
        rp = int(event.get('resp_pkts', 0) or 0)
        proto = str(event.get('proto', '')).lower()
        dst_port = int(event.get('dst_port', 0) or 0)

        byte_ratio = ob / max(rb, 1)
        bps = ob / dur
        is_icmp = int(proto == 'icmp')
        to_dns = int(dst_port == 53)

        features = [ob, rb, byte_ratio, dur, op, rp, bps, is_icmp, to_dns, int(dst_port in {80, 443, 8080})]
        meta = {
            'orig_bytes': int(ob), 'resp_bytes': int(rb), 'byte_ratio': round(byte_ratio, 4),
            'duration': round(dur, 3), 'bytes_per_sec': round(bps, 2), 'proto': proto,
            'dst_port': dst_port, 'is_icmp': is_icmp, 'to_dns': to_dns,
        }
        return features, meta

    @staticmethod
    def _rule_pattern(meta: dict) -> str | None:
        if meta['is_icmp'] and meta['orig_bytes'] > 1000:
            return 'ICMP_COVERT'
        if meta['to_dns'] and meta['orig_bytes'] > 5000:
            return 'DNS_EXFIL'
        if meta['byte_ratio'] > 5.0 and meta['orig_bytes'] > 500_000:
            return 'HIGH_UPLOAD'
        if meta['duration'] > 300 and meta['byte_ratio'] > 2.0:
            return 'SUSTAINED_UPLOAD'
        return None

    def process(self, event: dict) -> dict | None:
        if event.get("log_type", "conn") != "conn":
            return None
        if self.model is None:
            return None

        src, dst = event.get("src_ip", ""), event.get("dst_ip", "")
        ob = float(event.get('orig_bytes', 0) or 0)
        if (self._is_internal(src) and self._is_internal(dst)) or ob < 1000:
            return None

        features, meta = self._extract(event)
        pattern = self._rule_pattern(meta)
        ml_confidence = float(self.model.predict_proba([features])[0][1])

        threshold = 0.60 if pattern else 0.80
        if ml_confidence < threshold:
            return None

        confidence = max(ml_confidence, 0.70) if pattern else ml_confidence
        severity = "CRITICAL" if pattern == "ICMP_COVERT" else ("HIGH" if confidence > 0.85 else "MEDIUM")
        evidence = {
            'orig_bytes': meta['orig_bytes'], 'resp_bytes': meta['resp_bytes'],
            'byte_ratio': meta['byte_ratio'], 'duration': meta['duration'],
            'bytes_per_sec': meta['bytes_per_sec'], 'proto': meta['proto'], 'dst_port': meta['dst_port'],
            'exfil_pattern': pattern or 'ML_ONLY',
        }
        return self.alert(
            src_ip=src, src_port=None, dst_ip=dst, dst_port=event.get("dst_port"),
            flow_id=event.get("uid"), severity=severity, confidence=round(confidence, 4),
            evidence=evidence, window_seconds=0,
        )
```

Note vs. v2: `conn.log`-derived events don't currently carry `orig_bytes`/`resp_bytes`/`orig_pkts`/`resp_pkts`/`duration` in `normalize_event()`'s existing output (today's shape only has `ts, uid, src_ip, src_port, dst_ip, dst_port, proto, conn_state`). Extend `normalize_event()`'s conn branch (Task 2.0) to also pass these fields through from the raw Zeek conn.log JSON (`orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `duration` are already present in Zeek's conn.log — they're just not being forwarded today).

#### 2.3b — Training script

**File:** `training/train_exfil.py` (new, repo root)

```
Dataset: CICIDS2017 'Infiltration' subset as label=1; normal flows as label=0.
If unavailable, generate synthetic:
  Exfil:  orig_bytes in [100k, 10M], byte_ratio in [2.0, 50.0], duration in [10s, 600s]
  Normal: orig_bytes in [100, 50k],  byte_ratio in [0.01, 1.5], duration in [0.1, 60s]
Add ICMP-covert and DNS-exfil synthetic samples to the malicious class.

Features: orig_bytes, resp_bytes, byte_ratio, duration, orig_pkts, resp_pkts,
          bytes_per_sec, is_icmp, to_dns_port, to_common_port
RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
GroupKFold(n_splits=5), grouped by dst_port to prevent same-port leakage.
Print classification_report().

Persist calibration split: np.savez('backend/ml_models/exfil_cal_data.npz', ...)
Save to backend/ml_models/exfil_model.joblib
Update ML_MODELS.md.
```

### Acceptance Criteria — Phase 2

**Wiring (Task 2.0):**
- [x] `kafka_producer.py` tails dns.log and ssl.log in addition to conn.log, publishing to `zeek-dns`/`zeek-ssl`
- [x] `stream_consumer.py`'s consumer subscribes to all three topics; `normalize_event()` tags every event with `log_type`
- [x] `normalize_event()`'s conn branch forwards `orig_bytes`/`resp_bytes`/`orig_pkts`/`resp_pkts`/`duration` (needed by `exfil.py`)
- [x] `detectors/__init__.py`'s `ACTIVE_DETECTORS` includes all 6 detector classes
- [x] (found during implementation, not in the original task list) `recon.py`/`c2.py` needed an explicit `log_type == "conn"` guard added — they had no protocol filter at all before, unlike `ddos.py`'s incidental `proto == "tcp"` check, so DNS/SSL events would have silently polluted their state. Verified via a regression test feeding all 6 detectors both event types.

**DGA detector:**
- [x] `backend/detectors/dga.py` subclasses `Detector`, implements `process()`, returns via `self.alert()`
- [x] `backend/data/trigram_model.json` (6,989 trigrams) and `backend/data/english_wordlist.txt` (73,445 words, from `/usr/share/dict/words`) exist
- [x] `backend/ml_models/dga_model.joblib` exists, F1 = 1.00 on held-out test (see `ML_MODELS.md` for the synthetic-data caveat this number carries)
- [x] Verified: `DICT_DGA` for "sunshinevalleycloud.com", `RANDOM_DGA` for "xjkqmzpwl.ru", `TUNNEL` for a long TXT query with high payload ratio, `None` for "google.com"
- [x] `ML_MODELS.md` updated with DGA F1, training composition, blind spots

**TLS detector:**
- [ ] `zkg install zeek/salesforce/ja3` — **not done**, requires a real Zeek install to run against (this coding session only has the Python side); ssl.log rows flow through with `ja3=""` until this is run on the actual deployment, so the blacklist path is dormant but harmless until then
- [x] `backend/data/ja3_blacklist.json` (97 real entries from sslbl.abuse.ch) and `backend/ml_models/tls_flow_model.joblib` exist
- [x] `backend/detectors/tls_malware.py` subclasses `Detector`; verified confidence=0.95 for a blacklisted hash, `None` for the same hash against an internal-to-internal flow

**Exfil detector:**
- [x] `backend/detectors/exfil.py` subclasses `Detector`; `backend/ml_models/exfil_model.joblib` exists
- [x] Verified: fires (confidence 0.99, pattern `HIGH_UPLOAD`) for orig_bytes=2M/resp_bytes=10k/duration=60s; `None` for the same flow made internal-to-internal; `None` for orig_bytes=500

**All three:**
- [x] Each subclasses `Detector`, implements `process(event)`, calls `self.alert()` — verified by feeding one conn/dns/ssl event of the *wrong* log_type to each and confirming it returns `None` immediately
- [x] All 6 detectors instantiate and process all 3 event shapes without error (full integration smoke test); evidence-as-object renders fine in `AlertFeed.jsx` per its existing `normalizeEvidence()` — no frontend change needed

---

## PHASE 3 — CONFIDENCE CALIBRATION
**Goal:** Make confidence scores empirically meaningful. Paper → practice innovation #1.
**Estimated time:** 3–4 hours
**Dependency:** Phase 2 fully complete (all 6 models trained)

### Actual State
No calibration applied to any model currently; raw `predict_proba()` outputs are used directly everywhere. This is the real open problem: "0.87 confidence" doesn't currently mean anything specific.

### Task 3.1 — Calibrate All Six ML Models

**File:** `calibration/calibrate_models.py` (new, repo root)

```python
"""
Calibrate all ODIN RandomForest models using Platt scaling (sigmoid).
Run after all training scripts complete. Each training script (existing
ones too, if not already) must save its calibration split alongside the
model -- add if missing:
  np.savez('backend/ml_models/<name>_cal_data.npz', X=X_cal, y=y_cal, X_test=X_test, y_test=y_test)

For each model in [ddos, recon, c2, dga, exfil, tls_flow]:
  1. base = joblib.load(f'backend/ml_models/{name}_model.joblib')
  2. data = np.load(f'backend/ml_models/{name}_cal_data.npz')
  3. cal = CalibratedClassifierCV(base, method='sigmoid', cv='prefit')
     cal.fit(data['X'], data['y'])
  4. joblib.dump(cal, f'backend/ml_models/{name}_model_calibrated.joblib')
  5. Reliability diagram from calibration_curve(data['y_test'], cal.predict_proba(data['X_test'])[:,1], n_bins=10)
     -> save to docs/calibration_plots/{name}_calibration.png
"""
```

### Task 3.2 — Update Detectors to Load Calibrated Models

```python
# In each detector's model-loading method, try calibrated first:
calibrated_path = Path(__file__).parent.parent / "ml_models" / "ddos_model_calibrated.joblib"
base_path = Path(__file__).parent.parent / "ml_models" / "ddos_model.joblib"
return joblib.load(calibrated_path if calibrated_path.exists() else base_path)
```

Apply to: `ddos.py`, `recon.py`, `c2.py`, `dga.py`, `exfil.py`, `tls_malware.py`. `c2.py`'s range-gating logic must stay in place around whichever model (calibrated or not) it ends up loading — the gate is orthogonal to calibration.

### Task 3.3 — Surface Calibration in Dashboard

In `AlertFeed.jsx`'s confidence display: add a small "(calibrated)" label under the percentage, with a tooltip "Platt-calibrated — reflects empirical precision, not raw model output." Two-line change, don't redesign the card.

### Acceptance Criteria — Phase 3
- [x] (revised scope, not in original task list) `docs/calibration_plots/` contains 3 PNGs, not 6 — ddos/recon/c2 have no `*_cal_data.npz` in this repo (trained in the external `recon-ml-poc/` repo, which never persisted a calibration split here); calibrating them against a synthetic stand-in would misrepresent their real calibration, so they're honestly skipped instead. See `ML_MODELS.md`'s new "Phase 3" section.
- [x] (revised scope) 3 of 6 `*_model_calibrated.joblib` files exist (dga, tls_flow, exfil) — same reason as above for the other 3
- [x] Each detector's `_load_model()` checks for `<name>_model_calibrated.joblib` first, falls back to the base model otherwise — implemented identically across all 6, verified via a smoke test instantiating all 6 and confirming `self.calibrated` is `True` for dga/tls/exfil and `False` for ddos/recon/c2
- [x] Dashboard (`AlertFeed.jsx`) shows "(calibrated)" with a tooltip under the confidence percentage, conditioned on the new `alert.calibrated` field from `Detector.alert()`
- [ ] No detector's confidence changes by more than 0.15 from its uncalibrated value — **tls_flow violates this** (0.204 max shift). Documented in `ML_MODELS.md` rather than silently accepted: read as the base model being meaningfully overconfident on its own synthetic hold-out, corrected in the honest direction, but still a real caveat since the calibration set is small/synthetic.

---

## PHASE 4 — ADAPTIVE ENTROPY BASELINE FOR DDoS (re-scoped from v2)
**Goal:** Give the DDoS detector's fallback path flash-crowd resistance, and surface an adaptive-baseline evidence field for judge visibility — without pretending the ML path has a threshold problem it doesn't have.
**Estimated time:** 2–3 hours
**Dependency:** Phase 1

### Actual State (corrected — verified against `ddos.py`, not assumed)
The ML path (used whenever `ddos_model.joblib` loads successfully, which is the normal case) already outperforms any hand-tuned threshold, entropy-based or otherwise — F1=0.994. There is no hardcoded entropy threshold anywhere in the current code to "fix." The only threshold left in `ddos.py` is the **fallback rule**, used solely if the model fails to load: a flat `packet_rate > PACKET_RATE_THRESHOLD` (200) check — which has exactly the flash-crowd weakness the adaptive-baseline idea is meant to solve, just expressed as a rate cutoff instead of an entropy cutoff.

Two honest goals, not one overclaimed one:
1. Give the **fallback rule** (not the ML path) the adaptive-baseline treatment, so a model-load failure doesn't quietly reintroduce the flash-crowd problem.
2. Surface `sigma_deviation` as an additional evidence field on every DDoS alert (ML- or rule-triggered) — genuine "paper → practice" demo value, without claiming it's gating a decision it isn't.

### Task 4.1 — `AdaptiveEntropyBaseline` class

**File:** `backend/detectors/ddos.py` (modify existing — add this class, don't create a new file)

```python
from collections import deque
import statistics, time

class AdaptiveEntropyBaseline:
    """
    Tracks a rolling 10-minute window of observed dst-port-entropy values.
    Flags a value as anomalous when it deviates > 2 sigma from the rolling mean.
    Falls back to a fixed threshold until MIN_SAMPLES accumulate.
    """
    WINDOW_SECONDS = 600
    MIN_SAMPLES = 10
    SIGMA_THRESHOLD = 2.0
    FALLBACK_THRESHOLD = 1.5

    def __init__(self):
        self._history: deque = deque()  # (ts, entropy_value) -- keyed on event ts, not wall clock

    def _prune(self, now: float):
        cutoff = now - self.WINDOW_SECONDS
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def update(self, ts: float, entropy_value: float) -> None:
        self._history.append((ts, entropy_value))
        self._prune(ts)

    def is_anomalous(self, ts: float, current_entropy: float) -> tuple[bool, float]:
        self._prune(ts)
        if len(self._history) < self.MIN_SAMPLES:
            return current_entropy < self.FALLBACK_THRESHOLD, 0.0
        values = [v for _, v in self._history]
        mean = statistics.mean(values)
        stdev = max(statistics.stdev(values), 0.01)
        deviation = abs(current_entropy - mean) / stdev
        return deviation > self.SIGMA_THRESHOLD, round(deviation, 3)
```

Note the class now takes `ts` explicitly (event time), matching the fix in Phase 1 — don't let this one drift to wall-clock time either.

### Task 4.2 — Wire it into `process()`

```python
# In DDoSDetector.__init__:
self._entropy_baseline = AdaptiveEntropyBaseline()

# In process(), right after computing `feat`:
self._entropy_baseline.update(ts, feat["dst_port_entropy"])
_, sigma = self._entropy_baseline.is_anomalous(ts, feat["dst_port_entropy"])

if self.model is not None:
    # ... existing ML trigger logic, UNCHANGED ...
else:
    anomalous, _ = self._entropy_baseline.is_anomalous(ts, feat["dst_port_entropy"])
    triggered = anomalous              # replaces the flat packet_rate > 200 fallback
    confidence = 0.6 + min(sigma / 10, 0.35)
    detection_line = "Detection reason: entropy deviates from adaptive rolling baseline (fallback rule)"

if not triggered:
    return None

# ... existing cooldown check from Phase 1 goes here ...

evidence.append(f"Entropy deviation from rolling baseline: {sigma}sigma")
```

The ML path's trigger decision is untouched; `sigma` is computed and surfaced either way, for evidence only when the ML path fires.

### Acceptance Criteria — Phase 4
- [x] DDoS alert evidence includes an entropy-deviation (`sigma`) line regardless of which path (ML or fallback) triggered — verified in the smoke test
- [x] Verified with the model forced unavailable: a synthetic flash-crowd (same port-entropy distribution as the established baseline, just higher volume) produced zero false alerts once the baseline warmed up (20 samples), while a genuine entropy-shift attack fired correctly at 3.4 sigma
- [x] Existing ML-path F1=0.994 result is unaffected — the ML trigger block in `process()` is byte-identical to before this change; only the fallback `else` branch and the always-computed `sigma` evidence line were touched

---

## PHASE 5 — CROSS-THREAT CORRELATION ENGINE
**Goal:** Detect multi-vector attack patterns across all six threat classes.
**Estimated time:** 4–5 hours
**Dependency:** Phase 2 (all 6 detectors working)

### Actual State
No correlation logic exists. v2's version of this file correctly fixed a real bug that both the original plan and an earlier draft of this rewrite carried over uncritically: checking `classes_seen` against the *entire* pruned (600s) history instead of each pattern's own (shorter) window, which would let e.g. a DGA alert from 500 seconds ago and a fresh C2 alert incorrectly satisfy the 120-second `DGA_C2` pattern. Keep that per-pattern-window fix. What's changed here vs. v2: correct import path (this module lives under `backend/`, like `detectors/`, so `stream_consumer.py`'s `from correlation.correlator import CorrelationEngine` actually resolves), and a correlated-alert dict that carries the same fields `Detector.alert()` produces (so the dashboard doesn't need special-case handling beyond the badge).

### Task 5.1 — Correlation Engine

**File:** `backend/correlation/correlator.py` (new — note: under `backend/`, not repo root, so it's importable the same way `detectors` is)

```python
"""
Cross-Threat Correlation Engine

Ingests alerts (the dicts Detector.alert() produces) from all six detectors.
Tracks per-source alert history. Emits a MULTI_VECTOR correlated alert when a
known pattern is detected -- in addition to, never instead of, the individual
alerts that triggered it.

Patterns (priority order, highest first):
  KILL_CHAIN  : RECON + C2_BEACON + EXFIL within 600s -> confidence 0.97
  C2_EXFIL    : C2_BEACON + EXFIL within 600s          -> confidence 0.92
  DGA_C2      : DGA_DNS + C2_BEACON within 120s        -> confidence 0.88
  RECON_DDOS  : RECON + DDOS within 300s               -> confidence 0.85

Note: pattern class names above use the problem-statement-style labels; map
them to this codebase's actual threat_class strings ('recon', 'ddos', 'c2',
'dga', 'exfil') when matching -- see PATTERNS below.
"""

import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict

CORRELATION_WINDOW = 600  # seconds -- the outer prune bound; each pattern also has its own window


class CorrelationEngine:
    PATTERNS = [
        # (pattern_name, required_threat_classes, window_seconds, confidence, severity)
        ('KILL_CHAIN', {'recon', 'c2', 'exfil'}, 600, 0.97, 'CRITICAL'),
        ('C2_EXFIL',   {'c2', 'exfil'},          600, 0.92, 'CRITICAL'),
        ('DGA_C2',     {'dga', 'c2'},            120, 0.88, 'HIGH'),
        ('RECON_DDOS', {'recon', 'ddos'},        300, 0.85, 'HIGH'),
    ]

    def __init__(self):
        self._history: dict = defaultdict(list)  # {src_ip: [(ts, threat_class, alert_dict), ...]}

    def _prune(self, src_ip: str):
        cutoff = time.time() - CORRELATION_WINDOW
        self._history[src_ip] = [(ts, tc, al) for ts, tc, al in self._history[src_ip] if ts > cutoff]

    def ingest(self, alert: dict) -> dict | None:
        src = alert.get('src_ip', '')
        tc = alert.get('threat_class', '')
        if not src or not tc:
            return None

        self._history[src].append((time.time(), tc, alert))
        self._prune(src)

        classes_present = {tc for _, tc, _ in self._history[src]}

        for pattern_name, required, window, confidence, severity in self.PATTERNS:
            if not required.issubset(classes_present):
                continue
            cutoff = time.time() - window
            classes_in_window = {tc for ts, tc, _ in self._history[src] if ts > cutoff and tc in required}
            if not required.issubset(classes_in_window):
                continue  # pattern's own window, not just the outer 600s prune -- the v2 fix, kept

            contributing_records = [(ts, tc, al) for ts, tc, al in self._history[src] if tc in required]
            return self._make_correlated(src, pattern_name, confidence, severity, window, contributing_records)

        return None

    def _make_correlated(self, src_ip, pattern, confidence, severity, window, records) -> dict:
        contributing = [
            {'threat_class': tc, 'timestamp': ts, 'confidence': al.get('confidence')}
            for ts, tc, al in records
        ]
        latest_alert = max(records, key=lambda r: r[0])[2]
        return {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'flow_id': str(uuid.uuid4()),
            'src_ip': src_ip,
            'src_port': None,
            'dst_ip': latest_alert.get('dst_ip', ''),
            'dst_port': latest_alert.get('dst_port'),
            'threat_class': 'MULTI_VECTOR',
            'threat_label': f'Multi-Vector Attack ({pattern})',
            'severity': severity,
            'confidence': confidence,
            'evidence': {
                'pattern': pattern,
                'contributing_alerts': contributing,
                'correlation_window_seconds': window,
            },
            'detector': 'correlator',
            'window_seconds': window,
        }
```

This dict is a superset-compatible shape with what `Detector.alert()` produces (same field names: `timestamp`, `flow_id`, `src_ip`/`port`, `dst_ip`/`port`, `threat_class`, `threat_label`, `severity`, `confidence`, `evidence`, `detector`, `window_seconds`), so `AlertFeed.jsx` renders it with no special-casing beyond the badge in Task 5.3.

### Task 5.2 — Wire into `stream_consumer.py`

```python
from correlation.correlator import CorrelationEngine
_correlator = CorrelationEngine()

# Wherever an alert dict currently gets appended to alerts.json today:
def emit_alert(alert: dict):
    write_to_alerts_file(alert)          # existing path, unchanged
    correlated = _correlator.ingest(alert)
    if correlated:
        write_to_alerts_file(correlated)  # MULTI_VECTOR as a second, separate alert record
```

### Task 5.3 — Dashboard: MULTI_VECTOR badge

In `AlertFeed.jsx`'s alert card:
```jsx
{alert.threat_class === 'MULTI_VECTOR' && (
  <span className="kill-chain-badge">⚡ {alert.evidence?.pattern}</span>
)}
```
Add a `.kill-chain-badge` CSS class (red background, white text). No other dashboard changes needed this phase.

### Acceptance Criteria — Phase 5
- [x] `backend/correlation/correlator.py` exists under `backend/` and imports cleanly from `backend/stream_consumer.py` — verified by importing `stream_consumer` directly and instantiating `CorrelationEngine` alongside all 6 detectors
- [x] `CorrelationEngine.ingest()` returns a MULTI_VECTOR alert when RECON then DDOS (or RECON+C2+EXFIL for KILL_CHAIN) arrive from the same `src_ip` within window — verified with a direct unit test covering all 4 patterns
- [x] Returns `None` when the two alerts come from different `src_ip`s, or when DGA and C2 are more than 120s apart (verifies the per-pattern-window fix actually works, not just the outer prune) — both cases directly tested
- [x] KILL_CHAIN fires when RECON + C2 + EXFIL all present within 600s, confidence 0.97
- [x] MULTI_VECTOR alerts render with the "⚡ pattern" badge (`AlertFeed.jsx`'s `.kill-chain-badge`); individual contributing alerts are NOT suppressed — `stream_consumer.py` writes the original alert via `write_alert()` before calling `correlator.ingest()`, and writes the correlated alert as a second, separate record only if one comes back
- [x] (found during implementation, not in the original task list) `THREAT_META` in `AlertFeed.jsx` never had entries for `dga`/`tls`/`exfil` since Phase 2 built those detectors — their real alerts were rendering as "UNKNOWN". Added alongside the MULTI_VECTOR badge work since both touch the same threat-badge rendering path; the CSS variables (`--threat-dga` etc.) already existed in `index.css` from before Phase 2, just unused by the JS.
- [x] (found by code review, not in the original task list) The plan's own `CorrelationEngine` spec keys history on wall-clock `time.time()`. A review caught that this breaks under this project's own primary demo path (offline PCAP replay collapses wall-clock time), the same bug class Phase 1/4 already fixed once. Corrected to key on a new `event_ts` field threaded through all 6 detectors' `alert()` calls (see `ML_MODELS.md`'s Phase 5 section for the full writeup).
- [x] (found by a second code-review round on the fix above) A flat time-based dedup (`{(src_ip, pattern): last_fired}`) for the duplicate-firing fix could itself reuse a stale alert to silently suppress a second, genuinely independent attack chain from the same source — a false negative. Fixed with identity-based dedup (tracks which specific `flow_id`s contributed, only suppresses when nothing new has contributed since); a `_history`/`_fired` leak fix was also corrected the same way after the first attempt turned out to be dead code (see `ML_MODELS.md`).

---

## PHASE 6 — DASHBOARD COMPLETION + DOCS
**Goal:** Demo-ready frontend and complete documentation.
**Estimated time:** 4–5 hours
**Dependency:** Phase 5 complete

### Actual State
PCAP replay (`/api/replay/<threat>`) and README already work — don't touch. Missing: calibration labels (Phase 3), MULTI_VECTOR badge (Phase 5), a 6-detector status grid, and a throughput sparkline.

### Task 6.1 — Throughput Sparkline

Add a compact (60px-tall) Recharts `LineChart` to the existing throughput panel in `StatusBar.jsx` or `OverviewPage.jsx`: poll `/api/throughput` every 5s, keep the last 60 samples client-side, no visible axes — this is a glanceable trend line, not the main visual.

### Task 6.2 — 6-Detector Status Grid

**New endpoint:** `GET /api/detector_status` in `backend/app.py`

```python
@app.route("/api/detector_status")
def detector_status():
    checks = {
        "ddos":  "ml_models/ddos_model_calibrated.joblib",
        "recon": "ml_models/recon_model_v3_calibrated.joblib",
        "c2":    "ml_models/c2_model_calibrated.joblib",
        "dga":   "ml_models/dga_model_calibrated.joblib",
        "tls":   "ml_models/tls_flow_model_calibrated.joblib",
        "exfil": "ml_models/exfil_model_calibrated.joblib",
    }
    result = {}
    for name, rel_path in checks.items():
        path = Path(rel_path)
        if not path.exists():
            result[name] = {"status": "model_missing"}
            continue
        try:
            joblib.load(path)
            result[name] = {"status": "ok"}
        except Exception as e:
            result[name] = {"status": "error", "detail": str(e)}
    return jsonify(result)
```

Falls back to the uncalibrated filename if the calibrated one doesn't exist yet (Phase 3 not done) — check both, prefer calibrated. React side: 6 coloured boxes (green=ok, orange=model_missing, red=error) with detector name and F1 (hardcode F1 from `ML_MODELS.md` alongside the status, or add it to this endpoint's response too).

### Task 6.3 — Update README

Add a completed detector table (name, method, model file, F1, calibrated y/n) and an "Innovations Implemented" section listing: Platt-calibrated confidence, adaptive entropy baseline (fallback-path scope, stated honestly), word-boundary dictionary-DGA scoring, cross-threat correlation / kill-chain detection, C2 range-gating (the blind-spot story already in `ML_MODELS.md`). Keep `ML_MODELS.md` as the detailed per-model doc; README stays the summary.

### Acceptance Criteria — Phase 6
- [x] Throughput sparkline visible (hand-rolled inline SVG, not Recharts — no charting library existed in this project and one axis-less 60px sparkline didn't justify adding one); samples on its own fixed 2s interval rather than only on value-change, so a flat/idle reading still renders (a real bug found via live browser testing and fixed)
- [x] `/api/detector_status` returns real status for all 6 detectors (checks calibrated-then-base model path, matching each detector's own loader); dashboard (`ActiveDetectors.jsx`) shows 6 coloured dots, verified live in a browser
- [x] README table lists all 6 detectors with real F1 scores; Innovations Implemented section covers calibration, adaptive baseline, word-boundary DGA, correlation engine, C2 range-gating — each scoped honestly, no overclaiming
- [x] (found during implementation, not in the original task list) `ThreatCoverageMatrix.jsx`/`threatMatrix.js`, `ThreatChart.jsx`, and two `ArchitecturePage.jsx`/`pipelineStages.js` prose strings all still said 3 of 6 threat classes were "designed, not built" — stale since Phase 2. Fixed alongside this work since it's the same underlying gap (Phase 2 additions never propagated to every dashboard surface).

---

## PHASE 7 — THROUGHPUT BENCHMARK
**Goal:** Produce a real measured number for PS requirement F4.
**Estimated time:** 1–2 hours
**Dependency:** All 6 detectors loaded (Phase 2 minimum)

### Task 7.1 — Benchmark script

**File:** `scripts/benchmark_throughput.py` (new, repo root)

```
Generate a synthetic conn.log with 10,000 rows (mix of benign/attack flows).
Publish via kafka_producer in a benchmark mode; measure wall-clock time from
first publish to last consumer ACK. throughput = 10000 / elapsed_seconds.

Also measure per-detector latency: 100 synthetic attack events per detector,
median time from publish to alert emit.

Save to docs/benchmark_results.json:
{
  "sustained_flows_per_sec": <float>,
  "test_event_count": 10000,
  "elapsed_seconds": <float>,
  "per_detector_latency_ms": {"ddos": .., "recon": .., "c2": .., "dga": .., "tls": .., "exfil": ..},
  "hardware": "<fill manually>",
  "timestamp": "<ISO8601>"
}
```

### Acceptance Criteria — Phase 7
- [x] (revised scope) `docs/benchmark_results.json` exists with real numbers — but measures the Python detection-pipeline's own processing throughput, not a Kafka-broker round-trip: no live Kafka broker was running in this environment (port 9092 unreachable, no container up), and this repo's docker-compose.yml isn't set up for a headless benchmark run. Documented explicitly in the script and the results file rather than faked.
- [x] README updated with the measured throughput: 44.8 sustained flows/sec (10,000 synthetic events, 223.3s, 12-core Intel i7-1255U). Real finding surfaced, not buried: the bottleneck is scikit-learn's per-call `predict()`+`predict_proba()` overhead (~12ms/call), not this codebase's own Python logic.
- [x] Per-detector latency reported for all 6, and — after a code review caught that the first ddos/recon "attack" sequences never actually crossed either model's decision boundary (verified against the real .joblib models directly) — corrected to sequences confirmed to fire: ddos 40.8ms, recon 81.6ms, c2 13.7ms, dga 7.5ms, tls 4.1ms, exfil 4.0ms. The benchmark script now asserts every sequence fires at least once and raises if not, so this can't silently regress again.

---

## EXECUTION SUMMARY

| Phase | What | Time | Dependency |
|---|---|---|---|
| **1** | DDoS cooldown fix (event-`ts`-keyed, matching `recon.py` exactly) | 1h | None — do first |
| **2** | DNS/SSL Kafka wiring (new) + DGA + TLS + Exfil detectors, all as real `Detector` subclasses | 16–20h | Phase 1 |
| **3** | Platt calibration on all 6 models | 3–4h | Phase 2 done |
| **4** | Adaptive entropy baseline — fallback-rule scope only | 2–3h | Phase 1 |
| **5** | Cross-threat correlation engine (per-pattern-window correct) | 4–5h | Phase 2 |
| **6** | Dashboard status grid + sparkline + README | 4–5h | Phases 3, 4, 5 |
| **7** | Throughput benchmark | 1–2h | Phase 2 minimum |

**Total: 31–40 hours** (v2 estimated 29–38h without the Kafka-wiring gap; adjusted up ~2h to account for it).

Phases 3, 4, and 5 can be worked in parallel once Phase 2 is done. Phase 4 is independent of Phase 2.

---

## FINAL FILE CHECKLIST

```
backend/
  detectors/
    base.py              existing, unchanged
    ddos.py              Phase 1 (cooldown) + Phase 4 (adaptive baseline, fallback-rule scope)
    recon.py             existing, unchanged
    c2.py                existing, load calibrated model (Phase 3)
    dga.py               Phase 2 (new) -- subclasses Detector
    tls_malware.py       Phase 2 (new) -- subclasses Detector
    exfil.py             Phase 2 (new) -- subclasses Detector
    __init__.py           Phase 2 -- ACTIVE_DETECTORS grows to 6
  ml_models/
    ddos_model.joblib, recon_model_v3.joblib, c2_model.joblib   existing
    dga_model.joblib, tls_flow_model.joblib, exfil_model.joblib  Phase 2
    *_cal_data.npz (per model)                                    Phase 2/3 (calibration hold-out)
    *_model_calibrated.joblib (per model)                         Phase 3
  data/
    trigram_model.json, english_wordlist.txt   Phase 2.1
    ja3_blacklist.json                          Phase 2.2
  correlation/
    correlator.py         Phase 5 (new) -- lives under backend/ so imports resolve
  kafka_producer.py       Phase 2, Task 2.0 -- add dns.log/ssl.log tailing
  stream_consumer.py      Phase 2 (multi-topic + log_type normalization) + Phase 5 (wire correlator)
  app.py                  Phase 6 -- add /api/detector_status

training/            (repo root -- one-off scripts, not imported by the app)
  train_dga.py, train_tls_flow.py, train_exfil.py

scripts/              (repo root)
  build_trigram_model.py, download_ja3_blacklist.py, benchmark_throughput.py

calibration/           (repo root)
  calibrate_models.py

docs/
  calibration_plots/*.png      Phase 3
  benchmark_results.json        Phase 7

ML_MODELS.md   update after each training run (Phase 2, 3)
README.md      Phase 6
```

---

## JUDGE DEMO SCRIPT (10 minutes)

```
1. Start PCAP replay: POST /api/replay/kill_chain (or chain individual
   /api/replay/<threat> calls once a combined kill-chain pcap exists)

2. Watch dashboard:
   - Recon alert fires (fan-out from single source)
   - C2_BEACON alert fires (range-gated CV detection)
   - EXFIL alert fires (byte-ratio anomaly)
   - MULTI_VECTOR "KILL_CHAIN" badge fires (correlation engine)

3. Click any DDoS alert -> show evidence's entropy-deviation line
   Say: "This runs alongside our RandomForest, not instead of it -- it's the
        safety net if the model can't load, and it's evidence either way."

4. Click any DGA alert -> show word_boundary_score in evidence
   Say: "Dictionary DGA families fool character-level entropy. Word-boundary
        scoring catches them -- that's the DICT_DGA result here."

5. Click any alert -> show confidence with "(calibrated)" label
   Say: "0.87 means 87% of alerts at this level are true positives -- Platt
        scaling gets us there; raw sklearn output doesn't guarantee it."

6. Show /api/detector_status -> 6 green boxes.
   Say: "All six threat classes from the problem statement, all models loaded."

7. Show benchmark_results.json throughput number.

Key verbal defences if challenged:
  Q: "Why range-gating instead of Lomb-Scargle for C2?"
  A: "Range-gating came from stress-testing the deployed model, not just
     cross-validation -- 93% of its output fell outside the input domain it
     was actually trained on. We fixed the real, measured problem first."

  Q: "Why Random Forest instead of deep learning?"
  A: "Each detector matches the model to that threat's statistical structure.
     Recon is a feature-relationship problem -- RF gets F1=1.000 on it."

  Q: "Can this scale to real NTRO traffic volumes?"
  A: "Kafka + a Flink-equivalent consumer is validated at very high throughput
     in production elsewhere; we've measured X,XXX flows/sec on commodity
     hardware here, and the architecture scales horizontally from there."
```
