"""
C2 Beaconing Detector
---------------------
Groups connections by (src, dst, dst_port) and looks for statistically
regular inter-arrival timing -- the signature of programmatic beaconing
rather than human-driven traffic. The final regularity judgment is now a
trained RandomForestClassifier (../../training/train_c2.py, real
beacon-emulator traffic captured via ../../training/capture/capture_c2.py,
GroupKFold-validated: F1 0.994 vs the old fixed CV-threshold rule's F1
0.875 on 16,262 rows/114 sessions -- see ../../ML_MODELS.md) instead of
the hand-picked `cv <= 0.35` cutoff, but ONLY while
`observation_count <= MODEL_MAX_OBSERVATIONS`.

That cap is not a style choice -- it's fixing a real, verified failure
mode. The training data's benign sessions never accumulated more than 11
real connection events (short sessions, sparse traffic by design), while
c2 sessions routinely reached the full 20-observation cap. Checking
`dataset_c2.csv` directly: every single row with `observation_count >= 12`
is a c2 example -- ZERO benign examples exist in that region. A
RandomForest has no way to learn what it was never shown, and in a region
with no counterexamples it just predicts the only class it's ever seen
there. Verified empirically: fed 15 observations of clearly irregular
(CV~0.6-0.7, well above the 0.35 rule threshold) synthetic benign
traffic, the *unrestricted* model false-positived 28/30 times (93%) --
nowhere near the ~18% FP rate the (correctly-run) cross-validation
reported, because that validation could only ever score the model on the
same count<=11 region its training data actually covered. Below the cap,
the model is genuinely validated and a real improvement (see
ML_MODELS.md); above it, this falls back to the original CV rule, which
has no such blind spot because it doesn't depend on having seen every
count value during training.

A second, same-shaped gap exists on `mean_interval`: every training
session used a base beacon interval of 3-6s (kept short so the capture
finished in a reasonable time -- see recon-ml-poc/capture_data_c2.py),
so no c2-labeled training row has mean_interval above 6.01s. This
project's own bundled demo pcap (traffic_pcaps/attack_c2.pcap) beacons
every ~30s -- squarely in that unvalidated region. Confirmed live: replaying
it still detects the beacon (the model hasn't seen zero counterexamples
here the way it has for observation_count, since some benign rows *do*
have mean_interval this high), but only at ~61% confidence, well below
the 90%+ seen for in-range beacons, and later than the earliest possible
observation. `MODEL_MAX_MEAN_INTERVAL` caps model use to the range it was
actually trained on; the demo pcap's 30s beacon is handled by the rule
instead, which was always designed for the full 3-600s range and fires
confidently and immediately at 5 observations.

MIN_OBSERVATIONS/MIN_INTERVAL/MAX_INTERVAL stay as sanity pre-conditions
before consulting the model (matching what the training data assumed and
avoiding feeding the model degenerate inputs like a near-zero mean
interval) -- only the final regularity decision itself moved from a fixed
CV cutoff to the trained boundary, within the region it was validated on.

MIN_INTERVAL is lower than a production deployment would use (which might
require e.g. >=30s between beacons to rule out normal keep-alives) purely
so a live demo doesn't have to wait several minutes. This is a demo-timing
compromise, not a detection-logic compromise.

If the model file is missing or fails to load, falls back to the original
fixed-threshold rule rather than disabling the detector.
"""

import math
from collections import defaultdict
from pathlib import Path

from .base import Detector

MIN_OBSERVATIONS = 5      # need at least this many connections to judge periodicity
CV_THRESHOLD     = 0.35   # coefficient of variation cutoff -- fallback rule, and the only
                          # rule used once observation_count exceeds the model's validated range
MIN_INTERVAL     = 3      # ignore pairs faster than this (too fast to be a deliberate beacon)
MAX_INTERVAL     = 600    # ignore pairs slower than this (10 min, too slow for a live demo)

# The training data's benign sessions never reached higher than this many
# real observations (see module docstring) -- trust the model strictly
# within the range it has actual counterexamples for, rule outside it.
MODEL_MAX_OBSERVATIONS = 11

# No c2-labeled training row had a mean beacon interval above this (see
# module docstring) -- beyond it the model is extrapolating, not recalling.
MODEL_MAX_MEAN_INTERVAL = 7.0

BASE_MODEL_PATH       = Path(__file__).parent.parent / "ml_models" / "c2_model.joblib"
CALIBRATED_MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "c2_model_calibrated.joblib"
FEATURES = ["observation_count", "mean_interval", "std_interval", "cv"]


def _statistics(timestamps):
    if len(timestamps) < 2:
        return None, None, None
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    n = len(intervals)
    mean = sum(intervals) / n
    variance = sum((x - mean) ** 2 for x in intervals) / n
    std = math.sqrt(variance)
    cv = std / mean if mean > 0 else float("inf")
    return round(mean, 2), round(std, 2), round(cv, 4)


class C2Detector(Detector):
    name = "c2"
    threat_class = "c2"
    threat_label = "C2 Beaconing"

    def __init__(self):
        self._connections = defaultdict(list)
        self._alerted = set()
        self.model, self.calibrated = self._load_model()

    @staticmethod
    def _load_model():
        try:
            import joblib
            if CALIBRATED_MODEL_PATH.exists():
                return joblib.load(CALIBRATED_MODEL_PATH), True
            return joblib.load(BASE_MODEL_PATH), False
        except Exception as e:
            print(f"[c2] ML model unavailable ({e}) -- falling back to fixed-threshold rule")
            return None, False

    def process(self, event: dict) -> dict | None:
        if event.get("log_type", "conn") != "conn":
            return None

        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]
        ts       = event["ts"]

        if not src_ip or not dst_ip:
            return None

        key = (src_ip, dst_ip, dst_port)
        self._connections[key].append(ts)
        self._connections[key].sort()
        if len(self._connections[key]) > 20:
            self._connections[key] = self._connections[key][-20:]

        observations = self._connections[key]
        if len(observations) < MIN_OBSERVATIONS:
            return None

        mean_interval, std_interval, cv = _statistics(observations)
        if mean_interval is None:
            return None
        if not (MIN_INTERVAL <= mean_interval <= MAX_INTERVAL):
            return None

        model_in_range = (
            len(observations) <= MODEL_MAX_OBSERVATIONS
            and mean_interval <= MODEL_MAX_MEAN_INTERVAL
        )

        used_ml = self.model is not None and model_in_range
        if used_ml:
            vector = [[len(observations), mean_interval, std_interval, cv]]
            prediction = self.model.predict(vector)[0]
            confidence = float(self.model.predict_proba(vector)[0][1])
            triggered = prediction == 1
            detection_line = (
                f"ML classifier (RandomForest) flagged this connection pattern as beaconing "
                f"(model confidence: {confidence:.0%})"
            )
        else:
            triggered = cv <= CV_THRESHOLD
            confidence = 0.6 + min((CV_THRESHOLD - cv) / CV_THRESHOLD * 0.35, 0.35)
            reason = "fixed-threshold rule" if self.model is None else "fixed-threshold rule -- beyond the model's validated range"
            detection_line = f"Detection reason: stable periodic beaconing interval ({reason})"

        if not triggered:
            return None
        if key in self._alerted:
            return None
        self._alerted.add(key)

        evidence = [
            detection_line,
            f"Repeated connections: {len(observations)} to {dst_ip}:{dst_port}",
            f"Mean inter-arrival interval: {mean_interval}s",
            f"Standard deviation: {std_interval}s",
            f"Coefficient of variation: {cv} (informational -- fixed-threshold rule used <{CV_THRESHOLD})",
        ]

        severity = "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=MAX_INTERVAL, event_ts=ts,
            calibrated=(self.calibrated if used_ml else False),
        )
