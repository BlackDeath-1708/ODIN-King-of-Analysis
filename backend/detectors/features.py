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


def base_estimator_of(model):
    """Unwrap a CalibratedClassifierCV(FrozenEstimator(base)) down to
    whichever object actually exposes feature_importances_, so per-alert
    explainability keeps working whether a detector loaded the calibrated
    or the base model at runtime -- see calibration/calibrate_models.py for
    the wrapper shape. Verified directly against a real calibrated .joblib
    (2026-09-15): CalibratedClassifierCV.calibrated_classifiers_[0].estimator
    is the FrozenEstimator, and FrozenEstimator itself already forwards
    feature_importances_ from the wrapped RandomForestClassifier -- no
    second unwrap needed."""
    if hasattr(model, "feature_importances_"):
        return model
    calibrated_classifiers = getattr(model, "calibrated_classifiers_", None)
    if calibrated_classifiers:
        return calibrated_classifiers[0].estimator
    return model


def feature_contributions(model, feature_names, feature_values: dict) -> list:
    """Per-alert 'why was this flagged' breakdown: each input feature's
    observed value on this alert next to the trained model's own global
    importance for it (RandomForestClassifier.feature_importances_),
    sorted so the strongest driver of the model's decision shows first.

    These are real numbers read straight off the fitted model, not a
    fabricated explanation -- but they're GLOBAL feature importances (how
    much each feature mattered across all of training), not a per-instance
    SHAP/LIME attribution for this specific prediction. No shap dependency
    is added here (same reasoning alert_export.py gives for skipping the
    stix2 library -- avoiding an unverified new dependency when a simpler,
    honestly-labeled approach covers the actual need). The frontend labels
    this accordingly; see AlertFeed.jsx.
    """
    estimator = base_estimator_of(model)
    importances = getattr(estimator, "feature_importances_", None)
    if importances is None:
        return []
    contributions = [
        {"feature": name, "value": feature_values.get(name), "importance": round(float(imp), 4)}
        for name, imp in zip(feature_names, importances)
    ]
    contributions.sort(key=lambda c: -c["importance"])
    return contributions
