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

BASE_MODEL_PATH       = Path(__file__).parent.parent / "ml_models" / "exfil_model.joblib"
CALIBRATED_MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "exfil_model_calibrated.joblib"

RFC1918_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                    '172.30.', '172.31.', '192.168.')


class ExfilDetector(Detector):
    name = "exfil"
    threat_class = "exfil"
    threat_label = "Data Exfiltration"

    def __init__(self):
        self.model, self.calibrated = self._load_model()

    @staticmethod
    def _load_model():
        try:
            if CALIBRATED_MODEL_PATH.exists():
                return joblib.load(CALIBRATED_MODEL_PATH), True
            return joblib.load(BASE_MODEL_PATH), False
        except Exception as e:
            print(f"[exfil] ML model unavailable ({e}) -- detector disabled (no fixed-threshold fallback; "
                  f"byte-ratio rules alone are too noisy to run standalone)")
            return None, False

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
        ts = event.get("ts", 0.0)
        ob = float(event.get('orig_bytes', 0) or 0)
        if (self._is_internal(src) and self._is_internal(dst)) or ob < 1000:
            return None

        features, meta = self._extract(event)
        pattern = self._rule_pattern(meta)
        ml_confidence = float(self.model.predict_proba([features])[0][1])

        threshold = 0.60 if pattern else 0.80
        if ml_confidence < threshold:
            return None

        confidence_floored = bool(pattern) and ml_confidence < 0.70
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
            evidence=evidence, window_seconds=0, event_ts=ts,
            calibrated=(self.calibrated and not confidence_floored),
        )
