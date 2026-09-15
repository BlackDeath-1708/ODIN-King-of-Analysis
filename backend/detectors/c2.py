"""
C2 Beaconing Detector
---------------------
Groups connections by (src, dst, dst_port) and looks for statistically
regular inter-arrival timing -- the signature of programmatic beaconing
rather than human-driven traffic. The final regularity judgment is a
trained RandomForestClassifier (../../training/train_c2.py, real
beacon-emulator traffic -- see ../../ML_MODELS.md) instead of the
hand-picked `cv <= 0.35` cutoff, but only while
`observation_count <= MODEL_MAX_OBSERVATIONS` and
`mean_interval <= MODEL_MAX_MEAN_INTERVAL`.

RANGE-GATE HISTORY (why these constants exist at all, and why they
changed): the original training data's benign sessions never accumulated
more than 11 real connection events, and no c2-labeled row had a mean
beacon interval above ~6s (both by construction of a short, unattended
bulk-capture run). A RandomForest given a region with zero counterexamples
just predicts the only class it's ever seen there -- verified empirically
at the time: 15 observations of clearly irregular (CV~0.6-0.7) synthetic
benign traffic false-positived 28/30 times (93%) once forced outside that
box, nowhere near the ~18% FP rate cross-validation reported (which could
only ever score the region its training data covered).

EXTENSION (2026-09-11, ../../training/capture/capture_c2_extended.py):
closed both blind spots with two new real session types -- "benign_long"
(60-100s duration, long enough that some real benign sessions genuinely
reach 12-20 observations) and "c2_slow" (8-45s base interval, +-15%
jitter). Re-verified directly, the same way the original gap was found:
`dataset_c2.csv` now has BOTH labels present in the `observation_count>=12`
and `mean_interval>7.0` regions (previously one-class-only in each), the
retrained model's held-out F1 in those specific regions is 1.000 (no
degradation from the original range), and the same 93%-FP-style stress
test (clearly-irregular, high-CV synthetic benign traffic) produced ZERO
false positives when re-run across the newly-covered region -- feature
importances (cv=0.60, std_interval=0.20, mean_interval=0.20,
observation_count=0.006) suggest the model has genuinely learned a
CV-based, largely scale-invariant regularity rule rather than memorizing
the old training box, which is consistent with that result.

This does NOT close the rule's full nominal 3-600s range -- the capture
only reached 45s intervals in a background-runnable time budget (a single
600s-interval session would take over an hour by itself; see
capture_c2_extended.py's docstring). `MODEL_MAX_MEAN_INTERVAL=45.0`
reflects exactly what was captured and stress-tested, not the rule's own
theoretical ceiling. `MODEL_MAX_OBSERVATIONS=20` is no longer a meaningful
gate in practice (observations are already capped at 20 below), kept as a
named constant so the range-validation intent stays documented rather than
silently disappearing. Revisit with a longer capture budget if a future
stress test finds a new blind spot beyond 45s.

MIN_OBSERVATIONS/MIN_INTERVAL/MAX_INTERVAL stay as sanity pre-conditions
before consulting the model (matching what the training data assumed and
avoiding feeding the model degenerate inputs like a near-zero mean
interval) -- only the final regularity decision itself moved from a fixed
CV cutoff to the trained boundary, within the range it was validated on.

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
from .features import feature_contributions

MIN_OBSERVATIONS = 5      # need at least this many connections to judge periodicity
CV_THRESHOLD     = 0.35   # coefficient of variation cutoff -- fallback rule, and the only
                          # rule used once observation_count exceeds the model's validated range
MIN_INTERVAL     = 3      # ignore pairs faster than this (too fast to be a deliberate beacon)
MAX_INTERVAL     = 600    # ignore pairs slower than this (10 min, too slow for a live demo)

# Validated range after the 2026-09-11 capture extension (see module
# docstring) -- both regions now have real counterexamples of both labels,
# re-verified with the same stress-test methodology that found the
# original gap. 20 is the detector's own observation-history cap (below),
# so this is no longer a binding constraint in practice; kept named so the
# range-validation intent doesn't silently disappear.
MODEL_MAX_OBSERVATIONS = 20

# Matches the range the extended capture actually reached (8-45s base
# interval) -- beyond it the model is extrapolating, not recalling. Not
# the rule's own 600s theoretical ceiling; see module docstring.
MODEL_MAX_MEAN_INTERVAL = 45.0

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
        ctx = self._prepare(event)
        if ctx is None:
            return None
        if self.model is not None and ctx["model_in_range"]:
            vector = [[ctx["observation_count"], ctx["mean_interval"], ctx["std_interval"], ctx["cv"]]]
            confidence = float(self.model.predict_proba(vector)[0][1])
            return self._finish(ctx, confidence > 0.5, confidence, self._ml_detection_line(confidence),
                                 self.calibrated, "ml")
        triggered, confidence, detection_line, detection_method = self._fallback_decision(ctx)
        return self._finish(ctx, triggered, confidence, detection_line, False, detection_method)

    def process_batch(self, events: list) -> list:
        """See base.Detector.process_batch. Unlike ddos.py/recon.py, whether
        a given event is ML-eligible (model_in_range) varies per-event within
        one batch (it depends on each key's own observation_count/mean_interval,
        not a fixed instance-wide flag) -- so this scores the ML-eligible
        subset in one batched predict_proba() call up front, WITHOUT calling
        _finish() yet, then finishes every prepared event in original
        chronological order. That ordering matters here specifically: _finish
        mutates self._alerted (a per-key one-shot dedup, not a time cooldown),
        so finishing out of order could let a later event in the batch
        "claim" a key's one alert before an earlier event in the same batch
        does -- a different outcome than calling process() one at a time.
        """
        results = [None] * len(events)
        prepared = []  # [(index, ctx), ...], in original event order
        for i, event in enumerate(events):
            ctx = self._prepare(event)
            if ctx is not None:
                prepared.append((i, ctx))

        if not prepared:
            return results

        ml_confidence = {}  # index -> confidence, for the subset scored by the model
        ml_entries = [(i, ctx) for i, ctx in prepared if self.model is not None and ctx["model_in_range"]]
        if ml_entries:
            vectors = [[ctx["observation_count"], ctx["mean_interval"], ctx["std_interval"], ctx["cv"]]
                       for _, ctx in ml_entries]
            probas = self.model.predict_proba(vectors)[:, 1]
            for (i, _), p in zip(ml_entries, probas):
                ml_confidence[i] = float(p)

        for i, ctx in prepared:
            if i in ml_confidence:
                confidence = ml_confidence[i]
                results[i] = self._finish(ctx, confidence > 0.5, confidence, self._ml_detection_line(confidence),
                                           self.calibrated, "ml")
            else:
                triggered, confidence, detection_line, detection_method = self._fallback_decision(ctx)
                results[i] = self._finish(ctx, triggered, confidence, detection_line, False, detection_method)
        return results

    @staticmethod
    def _ml_detection_line(confidence: float) -> str:
        return (f"ML classifier (RandomForest) flagged this connection pattern as beaconing "
                f"(model confidence: {confidence:.0%})")

    def _fallback_decision(self, ctx: dict) -> tuple:
        cv = ctx["cv"]
        triggered = cv <= CV_THRESHOLD
        confidence = 0.6 + min((CV_THRESHOLD - cv) / CV_THRESHOLD * 0.35, 0.35)
        reason = "fixed-threshold rule" if self.model is None else "fixed-threshold rule -- beyond the model's validated range"
        detection_line = f"Detection reason: stable periodic beaconing interval ({reason})"
        # Distinguishes WHY the rule fallback ran, not just that it did --
        # "out_of_range" is the interesting case (model loaded fine, but
        # this specific input sits beyond MODEL_MAX_OBSERVATIONS/
        # MODEL_MAX_MEAN_INTERVAL, see module docstring's range-gate
        # history) vs "no_model" (model file missing/failed to load
        # entirely). Surfaced as its own top-level alert field so the
        # frontend can show this distinction without parsing evidence text.
        detection_method = "rule_fallback_out_of_range" if self.model is not None else "rule_fallback_no_model"
        return triggered, confidence, detection_line, detection_method

    def _prepare(self, event: dict) -> dict | None:
        """State update (self._connections) + range gating, identical
        whether reached via process() or process_batch()."""
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

        return {
            # observation_count is a snapshot int, NOT a reference to
            # self._connections[key] -- that list keeps growing as later
            # events for the same key are prepared, and in process_batch()
            # every event's _prepare() runs before any event's _finish()
            # (see process_batch()'s docstring), so a live list reference
            # here would read the batch's FINAL count for every earlier
            # event sharing this key instead of the count at that event's
            # own moment. Caught by tests/test_batch_inference.py.
            "ts": ts, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "flow_id": event.get("uid"),
            "key": key, "observation_count": len(observations), "mean_interval": mean_interval,
            "std_interval": std_interval, "cv": cv, "model_in_range": model_in_range,
        }

    def _finish(self, ctx: dict, triggered: bool, confidence: float, detection_line: str,
                calibrated: bool, detection_method: str):
        if not triggered:
            return None
        key = ctx["key"]
        if key in self._alerted:
            return None
        self._alerted.add(key)

        observation_count = ctx["observation_count"]
        evidence = [
            detection_line,
            f"Repeated connections: {observation_count} to {ctx['dst_ip']}:{ctx['dst_port']}",
            f"Mean inter-arrival interval: {ctx['mean_interval']}s",
            f"Standard deviation: {ctx['std_interval']}s",
            f"Coefficient of variation: {ctx['cv']} (informational -- fixed-threshold rule used <{CV_THRESHOLD})",
        ]

        severity = "HIGH"
        used_ml = detection_method == "ml"
        feat_values = {
            "observation_count": observation_count, "mean_interval": ctx["mean_interval"],
            "std_interval": ctx["std_interval"], "cv": ctx["cv"],
        }

        return self.alert(
            src_ip=ctx["src_ip"], src_port=None, dst_ip=ctx["dst_ip"], dst_port=ctx["dst_port"],
            flow_id=ctx["flow_id"], severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=MAX_INTERVAL, event_ts=ctx["ts"],
            calibrated=calibrated, detection_method=detection_method,
            feature_contributions=(feature_contributions(self.model, FEATURES, feat_values) if used_ml else None),
        )
