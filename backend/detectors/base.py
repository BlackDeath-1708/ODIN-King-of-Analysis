"""
Common detector interface.

A detector only needs a normalized event dict in, and an alert dict (or
None) out. Everything else -- state, windowing, thresholds -- is the
detector's own business. This is deliberate: it's what lets the processing
layer underneath (currently a plain Python Kafka consumer) be swapped for
Apache Flink/Spark in production without changing a single line of
detection logic or the alert contract the dashboard consumes.
"""

from datetime import datetime, timezone


class Detector:
    name = "base"
    threat_class = "unknown"
    threat_label = "Unknown"

    def process(self, event: dict) -> dict | None:
        """event is a normalized flow record (see stream_consumer.normalize_event).
        Return a standardized alert dict, or None if nothing fired."""
        raise NotImplementedError

    def process_batch(self, events: list) -> list:
        """Default: loop process() per event. Detectors that score events with
        a scikit-learn model override this to call predict_proba() once for
        the whole batch instead of once per event -- sklearn's per-call
        overhead (~12ms, see docs/benchmark_results.json's bottleneck_finding)
        otherwise dominates sustained throughput. Overriding detectors must
        still apply every event's state updates in list order (unchanged from
        process()) -- only the model call itself is deferred and batched, so
        results are identical to calling process() once per event, just
        faster. See tests/test_batch_inference.py for the equivalence check
        this promise is verified against."""
        return [self.process(event) for event in events]

    def alert(self, *, src_ip, src_port, dst_ip, dst_port, flow_id,
              severity, confidence, evidence, window_seconds, event_ts, calibrated=False,
              detection_method=None, feature_contributions=None):
        return {
            # "timestamp" is wall-clock (when this alert was emitted) -- for
            # display/sort order. "event_ts" is the underlying event's own
            # ts (event["ts"], e.g. Zeek's pcap-relative clock) -- required
            # so consumers like CorrelationEngine can window correctly under
            # fast PCAP replay, where wall-clock time desyncs from it.
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_ts": event_ts,
            "flow_id": flow_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "threat_class": self.threat_class,
            "threat_label": self.threat_label,
            "severity": severity,
            "confidence": round(min(confidence, 0.99), 2),
            "calibrated": calibrated,
            "evidence": evidence,
            "detector": self.name,
            "window_seconds": window_seconds,
            # Top-level (not buried in `evidence`) so the frontend can render
            # one consistent badge across all six detectors' differing
            # evidence shapes (list vs dict) -- see AlertFeed.jsx. Values:
            # "ml", "rule_based", "rule_fallback_no_model",
            # "rule_fallback_out_of_range", "ja3_blacklist", "ja4_blacklist",
            # "flow_stats_ml", "flow_stats_ml+tier2_seq_cnn",
            # "ml_rule_confirmed", "ml_only" -- see each detector's process().
            "detection_method": detection_method,
            # Per-alert "why was this flagged" breakdown: the trained
            # model's own global feature_importances_ paired with this
            # alert's actual observed feature values, sorted strongest
            # first -- see detectors/features.py's feature_contributions().
            # None/[] when the alert came from a rule path or blacklist
            # match rather than a RandomForest prediction.
            "feature_contributions": feature_contributions,
        }
