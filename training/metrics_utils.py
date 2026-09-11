"""
Shared helper for exporting standardized per-detector evaluation metrics.

Every train_*.py script fits a "final_model" (the exact artifact that gets
joblib-dumped and loaded by the live detector) and evaluates it on a
genuinely held-out test set (X_test/y_test, grouped so no session/domain/
group leaks between train and test). Until now that evaluation was only
ever printed to stdout via classification_report -- useful for a human
reading training output, useless for a judge asking "how many false
positives do you generate" and needing an immediate quantitative answer.

This module computes precision/recall/F1/false-positive-rate/false-
negative-rate/confusion-matrix from the final model's own held-out
predictions (not the pooled cross-validation numbers used for model
comparison during training, which score temporarily-refit models per fold,
not the exact deployed artifact) and writes one JSON file per detector to
docs/metrics/<name>.json. backend/app.py's /api/model_metrics endpoint
reads these plus docs/benchmark_results.json's per-detector latency at
request time, so there is exactly one place (this function) that decides
what "the model's metrics" means, and no separate aggregation step that can
silently go stale relative to the model file it describes.

Rates are computed directly from the confusion matrix, not sklearn's
classification_report, so false_positive_rate/false_negative_rate (which
classification_report doesn't expose at all) are defined the same way as
precision/recall here -- explicit division, None (not a crash) on an empty
denominator.
"""
import json
import time
from pathlib import Path

import numpy as np

METRICS_DIR = Path(__file__).parent.parent / "docs" / "metrics"


def _safe_div(numerator: float, denominator: float):
    return round(numerator / denominator, 4) if denominator else None


def compute_metrics(y_true, y_pred, positive_label=1) -> dict:
    """Binary confusion matrix + derived rates, computed by hand (not
    sklearn.metrics.confusion_matrix) so the exact TP/FP/TN/FN definitions
    used for every rate below are visible in one place."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    tp = int(np.sum((y_true == positive_label) & (y_pred == positive_label)))
    tn = int(np.sum((y_true != positive_label) & (y_pred != positive_label)))
    fp = int(np.sum((y_true != positive_label) & (y_pred == positive_label)))
    fn = int(np.sum((y_true == positive_label) & (y_pred != positive_label)))

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)            # a.k.a. true positive rate
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision and recall and (precision + recall) > 0
        else None
    )
    false_positive_rate = _safe_div(fp, fp + tn)   # benign traffic wrongly alerted
    false_negative_rate = _safe_div(fn, fn + tp)   # real attacks missed
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "accuracy": accuracy,
        "test_set_size": int(len(y_true)),
    }


def save_metrics(
    detector: str,
    y_true,
    y_pred,
    *,
    n_train_rows: int,
    n_test_rows: int,
    grouping: str,
    notes: str = "",
) -> dict:
    """Computes metrics for the final (deployed) model's held-out
    predictions and writes docs/metrics/<detector>.json. Returns the dict
    that was written, so callers can also print it."""
    metrics = compute_metrics(y_true, y_pred)
    metrics.update({
        "detector": detector,
        "n_train_rows": int(n_train_rows),
        "n_test_rows": int(n_test_rows),
        "grouping": grouping,  # what the GroupKFold/train_test_split grouped by, e.g. "session_id"
        "notes": notes,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = METRICS_DIR / f"{detector}.json"
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved held-out metrics to {out_path}")
    print(
        f"  precision={metrics['precision']} recall={metrics['recall']} f1={metrics['f1']} "
        f"FPR={metrics['false_positive_rate']} FNR={metrics['false_negative_rate']}"
    )
    return metrics
