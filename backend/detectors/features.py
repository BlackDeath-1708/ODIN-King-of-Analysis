"""
Shared feature math for the ML-backed detectors. Split out because both
ddos.py and recon.py need Shannon entropy and inter-arrival timing stats,
and they must compute them EXACTLY the way recon-ml-poc's
build_dataset_v3.py / build_dataset_ddos.py did when training the models
those detectors load -- any drift here silently mismatches production
inputs against what the model was trained on.
"""
import math
from collections import Counter


def shannon_entropy(values):
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def interval_stats(timestamps):
    """mean/std of inter-arrival gaps between sorted timestamps.
    Returns (0.0, 0.0) for fewer than 2 points -- matches how
    build_dataset_v3.py/build_dataset_ddos.py handle empty `intervals`."""
    ts = sorted(timestamps)
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    if not intervals:
        return 0.0, 0.0
    mean = sum(intervals) / len(intervals)
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    return mean, variance ** 0.5
