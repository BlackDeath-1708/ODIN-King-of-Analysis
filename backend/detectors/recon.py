"""
Reconnaissance / Port Scan Detector
-----------------------------------
Stateful per-source aggregation: tracks unique destination ports and hosts
each source IP touches within a rolling window, exactly as before. The
trigger condition is now a trained RandomForestClassifier
(../../training/train_recon.py, real nmap+socket traffic captured via
../../training/capture/capture_recon.py, GroupKFold-validated: F1 1.000 vs
the old fixed-threshold rule's F1 0.983 on 17,674 rows/175 sessions -- see
../../ML_MODELS.md) instead of the hand-picked
`unique_ports > 15 OR unique_hosts > 10` threshold.

Feature vector matches ../../training/build_dataset_recon.py's
features_for_window() exactly -- unique_ports, unique_hosts,
connection_count, port_entropy, port_range_span, mean_inter_arrival,
std_inter_arrival over the same 60s window this detector already
maintains. Getting this vector wrong (wrong order, wrong window) would
silently feed the model inputs it was never trained on.

If the model file is missing or fails to load (e.g. scikit-learn not
installed), falls back to the original fixed-threshold rule rather than
disabling the detector -- a live demo failing is worse than a slightly
less accurate detector.
"""

from collections import defaultdict
from pathlib import Path

from .base import Detector
from .features import shannon_entropy, interval_stats, feature_contributions

WINDOW_SECONDS = 60
ALERT_COOLDOWN = 20   # don't re-alert the same source more than once per this many seconds

# Fallback-only thresholds, used solely if the ML model can't be loaded.
PORT_THRESHOLD = 15
HOST_THRESHOLD = 10

BASE_MODEL_PATH       = Path(__file__).parent.parent / "ml_models" / "recon_model_v3.joblib"
CALIBRATED_MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "recon_model_v3_calibrated.joblib"
FEATURES = [
    "unique_ports", "unique_hosts", "connection_count",
    "port_entropy", "port_range_span", "mean_inter_arrival", "std_inter_arrival",
]


class ReconDetector(Detector):
    name = "recon"
    threat_class = "recon"
    threat_label = "Reconnaissance"

    def __init__(self):
        self._state = defaultdict(list)   # src_ip -> [(ts, dst_port, dst_ip)]
        self._last_alerted = {}
        self.model, self.calibrated = self._load_model()

    @staticmethod
    def _load_model():
        try:
            import joblib
            if CALIBRATED_MODEL_PATH.exists():
                return joblib.load(CALIBRATED_MODEL_PATH), True
            return joblib.load(BASE_MODEL_PATH), False
        except Exception as e:
            print(f"[recon] ML model unavailable ({e}) -- falling back to fixed-threshold rule")
            return None, False

    def _features(self, entries):
        ports = [e[1] for e in entries]
        hosts = [e[2] for e in entries]
        mean_iat, std_iat = interval_stats(e[0] for e in entries)
        return {
            "unique_ports": len(set(ports)),
            "unique_hosts": len(set(hosts)),
            "connection_count": len(entries),
            "port_entropy": shannon_entropy(ports),
            "port_range_span": (max(ports) - min(ports)) if ports else 0,
            "mean_inter_arrival": mean_iat,
            "std_inter_arrival": std_iat,
        }

    def process(self, event: dict) -> dict | None:
        ctx = self._prepare(event)
        if ctx is None:
            return None
        if self.model is not None:
            vector = [[ctx["feat"][name] for name in FEATURES]]
            confidence = float(self.model.predict_proba(vector)[0][1])
            return self._finish(ctx, confidence > 0.5, confidence, self._ml_detection_line(confidence), True)
        return self._finish(ctx, *self._fallback_decision(ctx["feat"]), False)

    def process_batch(self, events: list) -> list:
        """See base.Detector.process_batch: per-source window state
        (self._state) is still updated for every event, in order, via
        _prepare() -- only the model call is deferred and batched."""
        results = [None] * len(events)
        prepared = []  # [(index, ctx), ...]
        for i, event in enumerate(events):
            ctx = self._prepare(event)
            if ctx is not None:
                prepared.append((i, ctx))

        if not prepared:
            return results

        if self.model is not None:
            vectors = [[ctx["feat"][name] for name in FEATURES] for _, ctx in prepared]
            probas = self.model.predict_proba(vectors)[:, 1]
            for (i, ctx), p in zip(prepared, probas):
                confidence = float(p)
                results[i] = self._finish(ctx, confidence > 0.5, confidence, self._ml_detection_line(confidence), True)
        else:
            for i, ctx in prepared:
                results[i] = self._finish(ctx, *self._fallback_decision(ctx["feat"]), False)
        return results

    @staticmethod
    def _ml_detection_line(confidence: float) -> str:
        return f"ML classifier (RandomForest) flagged this window as reconnaissance (model confidence: {confidence:.0%})"

    @staticmethod
    def _fallback_decision(feat: dict) -> tuple:
        triggered = feat["unique_ports"] > PORT_THRESHOLD or feat["unique_hosts"] > HOST_THRESHOLD
        confidence = 0.6 + min(feat["unique_ports"] / PORT_THRESHOLD * 0.3, 0.35)
        detection_line = "Detection reason: horizontal/vertical scanning behavior (fixed-threshold rule)"
        return triggered, confidence, detection_line

    def _prepare(self, event: dict) -> dict | None:
        """State update (self._state) + feature computation, identical
        whether reached via process() or process_batch(). Returns None if
        this event doesn't qualify at all."""
        if event.get("log_type", "conn") != "conn":
            return None

        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]
        ts       = event["ts"]

        if not src_ip or not dst_port:
            return None

        self._state[src_ip].append((ts, dst_port, dst_ip))
        cutoff = ts - WINDOW_SECONDS
        self._state[src_ip] = [e for e in self._state[src_ip] if e[0] >= cutoff]

        entries = self._state[src_ip]
        feat = self._features(entries)
        return {"ts": ts, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                "flow_id": event.get("uid"), "feat": feat}

    def _finish(self, ctx: dict, triggered: bool, confidence: float, detection_line: str, used_ml: bool):
        if not triggered:
            return None

        ts, src_ip = ctx["ts"], ctx["src_ip"]
        if ts - self._last_alerted.get(src_ip, 0) < ALERT_COOLDOWN:
            return None
        self._last_alerted[src_ip] = ts

        feat = ctx["feat"]
        evidence = [
            detection_line,
            f"Unique destination ports: {feat['unique_ports']}",
            f"Unique destination hosts: {feat['unique_hosts']}",
            f"Connection attempts: {feat['connection_count']}",
            f"Port entropy: {feat['port_entropy']:.2f} bits",
            f"Observation window: {WINDOW_SECONDS}s",
        ]

        severity = "MEDIUM" if feat["unique_ports"] <= PORT_THRESHOLD * 2 else "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=ctx["dst_ip"], dst_port=ctx["dst_port"],
            flow_id=ctx["flow_id"], severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=WINDOW_SECONDS, event_ts=ts,
            calibrated=(self.calibrated if used_ml else False),
            detection_method=("ml" if used_ml else "rule_fallback_no_model"),
            feature_contributions=(feature_contributions(self.model, FEATURES, feat) if used_ml else None),
        )
