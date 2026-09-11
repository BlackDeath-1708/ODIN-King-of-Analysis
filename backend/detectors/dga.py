"""
DGA and DNS Tunnelling Detector
Consumes normalized events with log_type == "dns" (see stream_consumer.py).

DETECTION PATH A -- DNS TUNNEL (rule-based):
  Signal: TXT/NULL queries with unusually long names carrying encoded
  payload, in EITHER direction -- validated directly against a real
  iodine tunnel (2026-09-13, iodine 0.7.0, see training/capture/ notes in
  ML_MODELS.md), which exposed a real bug: the original rule only checked
  answer_bytes/query_bytes ("DOWNSTREAM" -- a C2 pushing a large encoded
  command down in the answer, small query). Real iodine's upload/exfil
  traffic is the mirror image ("UPSTREAM" -- the payload is encoded into
  the long query name itself, with a small ack-sized answer): real
  captured queries up to 678 chars scored ~0.03 under the
  answer/query-only formula, never crossing 3.0. Both directions are now
  checked; whichever ratio is larger wins and is recorded as
  evidence.tunnel_direction.
  Trigger when ALL of:
    - qtype_name in ['TXT', 'NULL']
    - len(query) > 50
    - payload_ratio > 3.0   (max of answer/query and query/answer byte ratio)
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

BASE_MODEL_PATH       = Path(__file__).parent.parent / "ml_models" / "dga_model.joblib"
CALIBRATED_MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "dga_model_calibrated.joblib"
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
        self.model, self.calibrated = self._load_model()
        self.trigram_model = self._load_json(TRIGRAM_PATH)
        self.wordlist = self._load_wordlist()

    @staticmethod
    def _load_model():
        try:
            import joblib
            if CALIBRATED_MODEL_PATH.exists():
                return joblib.load(CALIBRATED_MODEL_PATH), True
            return joblib.load(BASE_MODEL_PATH), False
        except Exception as e:
            print(f"[dga] ML model unavailable ({e}) -- DGA path disabled, tunnel rule still active")
            return None, False

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
        ts = event.get("ts", 0.0)

        if len(query) < 10 or qtype in SKIP_QTYPES or any(query.endswith(s) for s in SKIP_SUFFIXES):
            return None

        # Path A: tunnel (rule-based, checked first, doesn't need the model)
        if qtype in ('TXT', 'NULL'):
            query_len = len(query)
            answer_len = len(str(answers))
            # Bidirectional: a C2 pushing commands down encodes them in the
            # ANSWER (small query, large answer -- the original ratio_down
            # this rule shipped with); a tool exfiltrating/uploading data
            # (real iodine, validated directly -- see ML_MODELS.md) encodes
            # it in the QUERY NAME instead, with a tiny ack-sized answer --
            # the mirror-image ratio_up, previously unchecked and confirmed
            # to silently miss 100% of a real iodine upload's tunnel
            # queries (query lengths up to 678 chars, payload_ratio using
            # only the original answer/query direction ~0.03, nowhere near
            # the >3.0 threshold).
            ratio_down = answer_len / max(query_len, 1)
            ratio_up = query_len / max(answer_len, 1)
            payload_ratio = max(ratio_down, ratio_up)
            direction = "DOWNSTREAM" if ratio_down >= ratio_up else "UPSTREAM"
            if query_len > 50 and payload_ratio > 3.0:
                confidence = min(0.97, 0.60 + (query_len / 200) + (payload_ratio / 20))
                evidence = {
                    "detection_path": "TUNNEL", "query": query,
                    "query_length": query_len, "payload_ratio": round(payload_ratio, 3),
                    "tunnel_direction": direction, "qtype": qtype,
                }
                return self.alert(
                    src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
                    flow_id=event.get("uid"), severity="HIGH", confidence=confidence,
                    evidence=evidence, window_seconds=0, event_ts=ts,
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
            evidence=evidence, window_seconds=0, event_ts=ts, calibrated=self.calibrated,
        )
