"""
Tests for the adaptive statistical correlation layer (ODIN plan Phase C):
backend/correlation/baseline.py's AlertRateBaseline, exercised through
CorrelationEngine.ingest() the same way stream_consumer.py drives it.

Two behaviors matter most:
  1. False-positive control: classes that are each individually frequent
     shouldn't get flagged just because they happen to land in the same
     window -- that's expected, not surprising.
  2. Genuine detection: classes that are each individually rare, but land
     together at one source, should get flagged -- that combination
     wouldn't be expected by chance given their own background rates.

Run: backend/.venv/bin/python3 -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from correlation.correlator import CorrelationEngine  # noqa: E402


def _alert(threat_class, src_ip, event_ts, confidence=0.9):
    return {
        "event_ts": event_ts, "src_ip": src_ip, "threat_class": threat_class,
        "confidence": confidence, "dst_ip": "9.9.9.9", "dst_port": 443,
        "flow_id": f"{threat_class}-{src_ip}-{event_ts}",
    }


def test_no_anomaly_when_classes_are_individually_frequent():
    """tls+ddos isn't one of the 4 named patterns, so this only ever
    reaches the adaptive layer. Both classes fire every ~16s here --
    ordinary background tempo, not rare -- so seeing them at the same
    source within a window should NOT be flagged."""
    engine = CorrelationEngine()
    ts = 1_000_000.0

    for i in range(30):
        ts += 8.0
        cls = "tls" if i % 2 == 0 else "ddos"
        result = engine.ingest(_alert(cls, f"10.0.0.{i}", ts))
        assert result is None

    result1 = engine.ingest(_alert("tls", "6.6.6.6", ts + 5))
    assert result1 is None
    result2 = engine.ingest(_alert("ddos", "6.6.6.6", ts + 15))
    assert result2 is None, f"expected no adaptive anomaly for a frequent-class co-occurrence, got {result2}"


def test_fires_when_rare_classes_co_occur():
    """A busy 'recon' background (every 5s, from distinct decoy sources)
    keeps the adaptive window at its 60s floor. tls/ddos decoys are
    injected much more rarely (every ~400s per class) -- individually
    unsurprising, but a new source firing BOTH within the 60s window is
    exactly the "wouldn't happen by chance" signal this layer exists for."""
    engine = CorrelationEngine()
    ts = 2_000_000.0
    rare_i = 0

    for i in range(600):
        ts += 5.0
        if i % 40 == 39:
            cls = "tls" if rare_i % 2 == 0 else "ddos"
            engine.ingest(_alert(cls, f"10.0.2.{rare_i}", ts))
            rare_i += 1
        else:
            engine.ingest(_alert("recon", f"10.0.3.{i}", ts))

    engine.ingest(_alert("tls", "7.7.7.7", ts + 10))
    result = engine.ingest(_alert("ddos", "7.7.7.7", ts + 25))

    assert result is not None
    assert result["threat_class"] == "MULTI_VECTOR_ANOMALY"
    assert set(result["evidence"]["classes"]) == {"tls", "ddos"}
    assert 0.5 <= result["confidence"] <= 0.99
    assert result["src_ip"] == "7.7.7.7"


def test_named_patterns_still_take_priority_over_adaptive_layer():
    """Regression check: the curated KILL_CHAIN pattern (recon+c2+exfil)
    must still fire as MULTI_VECTOR, not get shadowed by the new adaptive
    layer added underneath it."""
    engine = CorrelationEngine()
    ts = 3_000_000.0
    engine.ingest(_alert("recon", "8.8.8.8", ts))
    engine.ingest(_alert("c2", "8.8.8.8", ts + 30))
    result = engine.ingest(_alert("exfil", "8.8.8.8", ts + 60))

    assert result is not None
    assert result["threat_class"] == "MULTI_VECTOR"
    assert result["evidence"]["pattern"] == "KILL_CHAIN"


def test_unknown_classes_never_trigger_anomaly_on_their_own():
    """A class with fewer than MIN_OBSERVATIONS background samples defaults
    to probability_in_window()==1.0 (i.e. "not rare") -- two brand-new
    classes co-occurring should never manufacture a high surprise score
    purely from cold-start ignorance."""
    engine = CorrelationEngine()
    ts = 4_000_000.0
    engine.ingest(_alert("dga", "5.5.5.5", ts))
    result = engine.ingest(_alert("tls", "5.5.5.5", ts + 10))
    assert result is None
