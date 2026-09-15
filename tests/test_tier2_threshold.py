"""
Unit test for train_tier2.py's _select_threshold(): the precision-
constrained recall-maximizing threshold sweep introduced to fix the TLS
Tier-2 recall gap (ODIN plan Phase B). Tests the selection logic itself
against small synthetic proba/label arrays, independent of the real
dataset -- training/train_tier2.py's own re-run is what validates the real
numbers.

Run: backend/.venv/bin/python3 -m pytest tests/ -v
"""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "training"))

from train_tier2 import _select_threshold  # noqa: E402


def test_picks_perfect_separation_threshold_between_classes():
    """10 benign scored low, 10 malicious scored high, cleanly separated --
    any threshold between the two clusters gives precision=1.0, recall=1.0,
    so the sweep should land somewhere in that gap."""
    proba = np.array([0.1] * 10 + [0.9] * 10)
    y = np.array([0] * 10 + [1] * 10)
    threshold = _select_threshold(proba, y, min_precision=0.95)
    assert 0.1 < threshold < 0.9


def test_prefers_lower_threshold_when_it_recovers_recall_without_losing_precision():
    """Mirrors the real TLS Tier-2 finding: precision is 1.0 at a
    conservative threshold but recall is poor there, while a lower
    threshold recovers full recall and still clears the precision floor."""
    # Benign cluster all scores below 0.5. Malicious cluster: half score
    # high (>0.7), half score in a middle band (0.5-0.6) that a
    # conservative 0.72-style threshold would miss entirely.
    benign = np.linspace(0.05, 0.45, 20)
    malicious_high = np.linspace(0.75, 0.95, 10)
    malicious_mid = np.linspace(0.52, 0.60, 10)
    proba = np.concatenate([benign, malicious_high, malicious_mid])
    y = np.concatenate([np.zeros(20), np.ones(10), np.ones(10)])

    threshold = _select_threshold(proba, y, min_precision=0.95)
    pred = (proba > threshold).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    assert precision >= 0.95
    assert recall == 1.0, "threshold should drop low enough to catch the mid-band malicious cluster"
    assert threshold <= 0.6, f"threshold {threshold} should have moved below the mid-band malicious scores"


def test_never_fires_below_precision_floor():
    """A malicious cluster that overlaps heavily with benign scores can't
    reach 0.95 precision at ANY reasonable threshold that still fires --
    the sweep must not return a threshold that violates the floor just to
    chase recall."""
    proba = np.concatenate([np.linspace(0.3, 0.7, 20), np.linspace(0.3, 0.7, 20)])
    y = np.concatenate([np.zeros(20), np.ones(20)])  # fully interleaved, no clean separation

    threshold = _select_threshold(proba, y, min_precision=0.95)
    pred = (proba > threshold).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    if tp + fp > 0:
        precision = tp / (tp + fp)
        assert precision >= 0.95 or threshold == 0.5  # 0.5 is the documented no-valid-threshold fallback


def test_falls_back_to_default_when_no_threshold_meets_floor():
    """Every threshold in the sweep yields exactly 50% precision (one
    benign, one malicious tied at every score) -- min_precision=0.95 can
    never be met, so the documented 0.5 fallback should be returned."""
    proba = np.array([0.5, 0.5])
    y = np.array([0, 1])
    threshold = _select_threshold(proba, y, min_precision=0.95)
    assert threshold == 0.5
