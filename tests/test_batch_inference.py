"""
Equivalence test for the batch-inference change (ODIN throughput plan, Phase
A1): process_batch() must produce EXACTLY the same alerts as calling
process() once per event, in order -- only the underlying ML model call is
allowed to change (one predict_proba() call per batch instead of one per
event). This is the correctness gate for the whole optimization; a batching
bug that changes *what* fires, not just *how fast*, would silently corrupt
every detector's output.

Run: backend/.venv/bin/python3 -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from detectors.ddos import DDoSDetector      # noqa: E402
from detectors.recon import ReconDetector    # noqa: E402
from detectors.c2 import C2Detector          # noqa: E402
from detectors.exfil import ExfilDetector    # noqa: E402
from detectors.tls_malware import TLSMalwareDetector  # noqa: E402
from detectors.base import Detector          # noqa: E402


def _conn(ts, src_ip, dst_ip, dst_port, proto="tcp", **overrides):
    event = {
        "log_type": "conn", "ts": ts, "uid": f"C{ts}-{src_ip}-{dst_port}",
        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto,
        "orig_bytes": 500, "resp_bytes": 300, "orig_pkts": 5, "resp_pkts": 4, "duration": 1.0,
    }
    event.update(overrides)
    return event


def _ssl(ts, src_ip, dst_ip, **overrides):
    event = {
        "log_type": "ssl", "ts": ts, "uid": f"S{ts}-{src_ip}", "src_ip": src_ip, "dst_ip": dst_ip,
        "dst_port": 443, "ja3": "", "ja3s": "", "ja4": "", "version": "TLSv12",
        "server_name": "example.com", "orig_bytes": 5000, "resp_bytes": 5000, "duration": 2.0,
    }
    event.update(overrides)
    return event


def _assert_batch_matches_sequential(detector_cls, events):
    """Two independent, freshly-constructed detector instances: one driven
    event-by-event through process(), one driven once through
    process_batch() with the whole list. Results must match exactly,
    index-for-index (None counts as a match too)."""
    seq_detector = detector_cls()
    sequential = [seq_detector.process(e) for e in events]

    batch_detector = detector_cls()
    batched = batch_detector.process_batch(events)

    assert len(sequential) == len(batched) == len(events)
    for i, (seq_alert, batch_alert) in enumerate(zip(sequential, batched)):
        assert (seq_alert is None) == (batch_alert is None), (
            f"[{detector_cls.__name__}] event {i}: sequential={'alert' if seq_alert else None} "
            f"but batched={'alert' if batch_alert else None}"
        )
        if seq_alert is not None:
            # "timestamp" (wall-clock alert-emission time) is the one field
            # allowed to differ, since the two runs happen microseconds apart.
            for key in seq_alert:
                if key == "timestamp":
                    continue
                assert seq_alert[key] == batch_alert[key], (
                    f"[{detector_cls.__name__}] event {i} field {key!r}: "
                    f"sequential={seq_alert[key]!r} != batched={batch_alert[key]!r}"
                )


def _mixed_ddos_stream():
    """Background traffic across several sources, then a clear flood burst
    from one source, recovery traffic, then a second later flood from a
    different source -- exercises window state and cooldown across a batch
    boundary, not just a single isolated trigger."""
    events = []
    ts = 1_000_000.0
    for i in range(40):
        ts += 1.5
        events.append(_conn(ts, f"10.0.0.{i % 5 + 1}", "192.168.1.50", 8000 + (i % 3)))
    for i in range(200):
        ts += 0.02
        events.append(_conn(ts, "6.6.6.6", "1.1.1.1", 80))
    for i in range(20):
        ts += 1.5
        events.append(_conn(ts, f"10.0.1.{i % 5 + 1}", "192.168.1.51", 9000 + (i % 3)))
    for i in range(200):
        ts += 0.02
        events.append(_conn(ts, "7.7.7.7", "1.1.1.1", 80))
    return events


def _recon_scan_stream():
    events = []
    ts = 2_000_000.0
    for i in range(30):
        ts += 2.0
        events.append(_conn(ts, f"10.0.2.{i % 4 + 1}", "192.168.1.52", 8000 + (i % 3)))
    for i in range(60):
        ts += 0.5
        events.append(_conn(ts, "9.9.9.9", "10.0.0.5", i + 1))
    return events


def _c2_beacon_stream():
    """Two independent beaconing sources reaching MIN_OBSERVATIONS at
    different, interleaved points -- exercises the per-event model_in_range
    gate this file's plan specifically calls out as order-sensitive for
    process_batch()."""
    events = []
    for i in range(10):
        events.append(_conn(3_000_000.0 + i * 4.0, "6.6.6.6", "5.5.5.5", 443))
    for i in range(10):
        events.append(_conn(3_000_001.0 + i * 6.0, "8.8.4.4", "5.5.5.6", 8443))
    events.sort(key=lambda e: e["ts"])
    return events


def _exfil_stream():
    events = []
    ts = 4_000_000.0
    for i in range(15):
        ts += 3.0
        events.append(_conn(ts, f"10.0.3.{i % 4 + 1}", "192.168.1.53", 443, orig_bytes=400, resp_bytes=300))
    events.append(_conn(ts + 5, "10.0.3.9", "1.2.3.4", 443, orig_bytes=2_000_000, resp_bytes=10_000, duration=60))
    events.append(_conn(ts + 10, "10.0.3.10", "1.2.3.5", 443, orig_bytes=2_500_000, resp_bytes=5_000, duration=90))
    return events


def _tls_stream():
    events = []
    ts = 5_000_000.0
    for i in range(10):
        ts += 4.0
        events.append(_ssl(ts, f"10.0.4.{i % 3 + 1}", "192.168.1.54", orig_bytes=4000, resp_bytes=4200))
    events.append(_ssl(ts + 5, "10.0.4.9", "3.3.3.3", orig_bytes=200000, resp_bytes=1000))
    events.append(_ssl(ts + 10, "10.0.4.10", "3.3.3.4", orig_bytes=250000, resp_bytes=800))
    return events


def test_ddos_batch_matches_sequential():
    _assert_batch_matches_sequential(DDoSDetector, _mixed_ddos_stream())


def test_recon_batch_matches_sequential():
    _assert_batch_matches_sequential(ReconDetector, _recon_scan_stream())


def test_c2_batch_matches_sequential():
    _assert_batch_matches_sequential(C2Detector, _c2_beacon_stream())


def test_exfil_batch_matches_sequential():
    _assert_batch_matches_sequential(ExfilDetector, _exfil_stream())


def test_tls_batch_matches_sequential():
    _assert_batch_matches_sequential(TLSMalwareDetector, _tls_stream())


def test_default_process_batch_falls_back_to_process():
    """base.Detector's default process_batch() (used by dga.py, which has
    no ML model call worth batching) must still just loop process()."""

    class _Toy(Detector):
        name = "toy"
        threat_class = "toy"
        threat_label = "Toy"

        def process(self, event):
            return {"seen": event["x"]} if event["x"] > 5 else None

    events = [{"x": i} for i in range(10)]
    expected = [({"seen": i} if i > 5 else None) for i in range(10)]
    assert _Toy().process_batch(events) == expected
