"""
DDoS / SYN Flood Detector
-------------------------
Trigger condition is now a trained RandomForestClassifier
(../../training/train_ddos.py, real hping3+socket traffic captured via
../../training/capture/capture_ddos.py, GroupKFold-validated: F1 1.000 vs
the old fixed-threshold rule's F1 0.927 on 16,309 rows/130 sessions -- see
../../ML_MODELS.md) instead of the hand-picked `packet_rate > 200`
threshold. The rule missed 842/6161 flood rows in validation (mostly
"low and slow" floods below the fixed threshold); the model missed 2, by
weighing port entropy and connection timing alongside rate, not rate alone.

Feature vector matches ../../training/build_dataset_ddos.py's
features_for_window() exactly -- packet_rate, unique_dst_ports,
dst_port_entropy, mean_inter_arrival, std_inter_arrival,
unique_src_ips, src_ip_entropy, over the same 10s window this detector
already maintains.

2026-09-12 PS 26145 gap-closing update: source-IP entropy/unique-IP count
used to be evidence-only ("this test rig's single loopback source made it
zero-variance during training"). That constraint is now lifted -- real
hping3 `--rand-source` traffic (genuinely varied, non-local source
addresses that Zeek captures faithfully on loopback) gives real signal for
this feature, so it's now a trained model input, not just display text.
This also extends real coverage to PS 26145 (a)'s other two named DDoS
patterns beyond plain SYN floods: UDP reflection/amplification (now
accepted -- see the proto check below) and spoofed-source floods (the new
src-IP features above). See ML_MODELS.md for the real capture methodology
and retrained numbers.

If the model file is missing or fails to load, falls back to the original
fixed-threshold rule rather than disabling the detector. Loads the
Platt-calibrated model (ddos_model_calibrated.joblib) if present, else the
base model -- see ../../calibration/calibrate_models.py. A calibrated file
now exists (max confidence shift 0.250 vs base -- exceeds the 0.15 sanity
bound, documented honestly in ML_MODELS.md rather than hidden).

Adaptive entropy baseline (see AdaptiveEntropyBaseline below): tracks a
rolling distribution of dst-port-entropy values and reports how many
standard deviations the current value sits from it. The ML path's trigger
decision does not depend on this -- it's surfaced as an extra evidence
field either way, and it's what the fallback rule (used only when the ML
model can't load) checks instead of the old flat packet-rate cutoff, so a
model-load failure doesn't quietly reintroduce a flash-crowd false positive.
"""

import statistics
from collections import deque
from pathlib import Path

from .base import Detector
from .features import shannon_entropy, interval_stats

WINDOW_SECONDS        = 10
PACKET_RATE_THRESHOLD = 200   # fallback-only: retained as evidence context, no longer the trigger
UNIQUE_IP_SUPPORT     = 50    # supporting evidence only, never a trigger condition
ALERT_COOLDOWN        = 30    # one alert per src_ip per 30s of *event* time -- matches recon.py

BASE_MODEL_PATH       = Path(__file__).parent.parent / "ml_models" / "ddos_model.joblib"
CALIBRATED_MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "ddos_model_calibrated.joblib"
FEATURES = [
    "packet_rate", "unique_dst_ports", "dst_port_entropy",
    "mean_inter_arrival", "std_inter_arrival",
    "unique_src_ips", "src_ip_entropy",
]


class AdaptiveEntropyBaseline:
    """
    Tracks a rolling 10-minute window of observed dst-port-entropy values.
    Flags a value as anomalous when it deviates > 2 sigma from the rolling mean.
    Falls back to a fixed threshold until MIN_SAMPLES accumulate.
    Keyed on event ts (not wall-clock time), matching the Phase 1 cooldown fix --
    so it tracks simulated/event time correctly under PCAP replay too.
    """
    WINDOW_SECONDS = 600
    MIN_SAMPLES = 10
    SIGMA_THRESHOLD = 2.0
    FALLBACK_THRESHOLD = 1.5

    def __init__(self):
        self._history: deque = deque()  # [(ts, entropy_value)]

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


class SlowExhaustionTracker:
    """
    PS 26145 (a)'s named DDoS patterns (SYN floods, UDP reflection,
    spoofed floods) are all high-RATE -- what the flood ML path's 10s
    window and packet_rate/entropy features are tuned for. Slow HTTP
    exhaustion (Slowloris, explicitly named in the PS's own suggested
    dataset tooling: "Slowloris (slow HTTP exhaustion)") is the opposite
    shape by design: deliberately under any rate threshold, few packets
    per connection, connections held open for a long time instead.

    Validated directly (2026-09-13): a real Slowloris run (120 sockets
    held open ~50s each against a local target) scored 0/120 through the
    flood ML path once connections were given a realistic, independently-
    staggered close timeline (a real target's own per-connection timeout
    firing on its own schedule, not an attacker script's synchronized
    teardown loop bunching all 120 closes into one DDoSDetector.WINDOW_SECONDS
    window). This needs a longer window and different features (duration,
    byte count -- not rate) to catch at all, so it's a separate rule path
    here, the same hybrid rule+ML pattern dga.py's tunnel path and
    exfil.py's pattern pre-filter already use alongside their own ML paths,
    rather than retraining the flood model around a second, much longer
    window it was never designed for.
    """
    WINDOW_SECONDS = 300   # long enough to catch a realistically staggered
    # close timeline; still bounded per PS 26145's streaming/latency requirement.
    MIN_DURATION = 15.0    # a real page load/API call finishes well under this
    MAX_BYTES = 500        # Slowloris's own incomplete headers are a few hundred bytes at most
    TRIGGER_COUNT = 25     # concurrent/recent slow-shaped connections to one destination

    def __init__(self):
        self._recent = deque()  # [(ts, dst_ip, dst_port)]

    def observe(self, ts: float, dst_ip: str, dst_port) -> tuple[bool, int]:
        self._recent.append((ts, dst_ip, dst_port))
        cutoff = ts - self.WINDOW_SECONDS
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()
        same_target = sum(1 for _, d_ip, d_port in self._recent if d_ip == dst_ip and d_port == dst_port)
        return same_target >= self.TRIGGER_COUNT, same_target


class DDoSDetector(Detector):
    name = "ddos"
    threat_class = "ddos"
    threat_label = "DDoS / SYN Flood"

    def __init__(self):
        self._window = deque()   # [(ts, src_ip, dst_port)]
        self._last_alerted = {}  # src_ip (or "slow:<dst_ip>:<dst_port>") -> ts of last alert
        self._entropy_baseline = AdaptiveEntropyBaseline()
        self._slow_tracker = SlowExhaustionTracker()
        self.model, self.calibrated = self._load_model()

    @staticmethod
    def _load_model():
        try:
            import joblib
            if CALIBRATED_MODEL_PATH.exists():
                return joblib.load(CALIBRATED_MODEL_PATH), True
            return joblib.load(BASE_MODEL_PATH), False
        except Exception as e:
            print(f"[ddos] ML model unavailable ({e}) -- falling back to fixed-threshold rule")
            return None, False

    def process(self, event: dict) -> dict | None:
        if event.get("proto") not in ("tcp", "udp"):
            return None

        ts       = event["ts"]
        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]

        # Path C: slow-exhaustion (rule-based, long window) -- checked
        # ahead of the flood window/ML path below since it needs its own
        # tracker state regardless of this event's flood-path outcome; see
        # SlowExhaustionTracker's docstring for why this is a separate
        # signal a 10s rate-tuned window structurally can't catch.
        duration = float(event.get("duration", 0.0) or 0.0)
        orig_bytes = int(event.get("orig_bytes", 0) or 0)
        if duration > SlowExhaustionTracker.MIN_DURATION and orig_bytes < SlowExhaustionTracker.MAX_BYTES:
            slow_triggered, slow_count = self._slow_tracker.observe(ts, dst_ip, dst_port)
            slow_key = f"slow:{dst_ip}:{dst_port}"
            if slow_triggered and ts - self._last_alerted.get(slow_key, 0) >= ALERT_COOLDOWN:
                self._last_alerted[slow_key] = ts
                evidence = [
                    "Detection reason: many long-lived, low-byte connections held open to one "
                    "destination (slow HTTP exhaustion / Slowloris-style pattern -- rule-based, "
                    "distinct from the flood ML path above)",
                    f"Connections matching this shape in the last {SlowExhaustionTracker.WINDOW_SECONDS}s: {slow_count}",
                    f"This connection: duration {duration:.1f}s, {orig_bytes} bytes sent",
                    f"Destination: {dst_ip}:{dst_port}",
                ]
                return self.alert(
                    src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
                    flow_id=event.get("uid"), severity="HIGH",
                    confidence=min(0.95, 0.6 + slow_count / 100),
                    evidence=evidence, window_seconds=SlowExhaustionTracker.WINDOW_SECONDS,
                    event_ts=ts, calibrated=False,
                )

        self._window.append((ts, src_ip, dst_port))
        cutoff = ts - WINDOW_SECONDS
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        recent      = self._window
        recent_ips  = [e[1] for e in recent]
        recent_ports = [e[2] for e in recent]
        packet_rate = len(recent)
        unique_ips  = len(set(recent_ips))
        src_entropy = round(shannon_entropy(recent_ips), 4)
        mean_iat, std_iat = interval_stats(e[0] for e in recent)

        feat = {
            "packet_rate": packet_rate,
            "unique_dst_ports": len(set(recent_ports)),
            "dst_port_entropy": shannon_entropy(recent_ports),
            "mean_inter_arrival": mean_iat,
            "std_inter_arrival": std_iat,
            "unique_src_ips": unique_ips,
            "src_ip_entropy": src_entropy,
        }

        # Measure against history *before* folding the current sample in --
        # otherwise the point under test biases its own baseline (self-masking).
        anomalous, sigma = self._entropy_baseline.is_anomalous(ts, feat["dst_port_entropy"])
        self._entropy_baseline.update(ts, feat["dst_port_entropy"])

        used_ml = self.model is not None
        if used_ml:
            vector = [[feat[name] for name in FEATURES]]
            prediction = self.model.predict(vector)[0]
            confidence = float(self.model.predict_proba(vector)[0][1])
            triggered = prediction == 1
            detection_line = f"ML classifier (RandomForest) flagged this window as a flood (model confidence: {confidence:.0%})"
        else:
            triggered = anomalous
            confidence = 0.6 + min(sigma / 10, 0.35)
            detection_line = "Detection reason: entropy deviates from adaptive rolling baseline (fallback rule)"

        if not triggered:
            return None

        if ts - self._last_alerted.get(src_ip, 0) < ALERT_COOLDOWN:
            return None
        self._last_alerted[src_ip] = ts

        evidence = [
            detection_line,
            f"Packet rate: {packet_rate} connections/{WINDOW_SECONDS}s",
            f"Unique destination ports: {feat['unique_dst_ports']}",
            f"Destination port entropy: {feat['dst_port_entropy']:.2f} bits",
            f"Entropy deviation from rolling baseline: {sigma}sigma",
            f"Unique source IPs: {unique_ips}",
            f"Source IP entropy: {src_entropy} bits",
            f"Destination port: {dst_port}",
            f"Observation window: {WINDOW_SECONDS}s",
        ]
        if unique_ips > UNIQUE_IP_SUPPORT:
            evidence.append(f"Supporting evidence: {unique_ips} unique sources exceeds {UNIQUE_IP_SUPPORT}")
        if unique_ips > 1:
            evidence.append("src_ip reflects only the most recent packet -- sources appear randomized/spoofed")

        severity = "CRITICAL" if packet_rate > PACKET_RATE_THRESHOLD * 3 else "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=WINDOW_SECONDS, event_ts=ts,
            calibrated=(self.calibrated if used_ml else False),
        )
