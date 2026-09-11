"""
Trains the C2 beaconing RandomForest classifier from
training/dataset_c2.csv (real beacon-emulator traffic captured via
training/capture/capture_c2.py -- see that file and
training/build_dataset_c2.py for methodology and its honesty note on
row count vs real event count).

Same evaluation discipline as train_ddos.py/train_recon.py: GroupKFold by
session_id, pooled confusion matrix across folds.

Also persists a Platt-calibration hold-out split (c2_cal_data.npz),
matching the dga/tls_flow/exfil convention -- closes the gap noted in
ML_MODELS.md where ddos/recon/c2 (trained outside this repo) had no
calibration split available.

NOTE: backend/detectors/c2.py only trusts this model within a validated
input range (observation_count <= 11, mean_interval <= 7.0 -- see that
module's docstring for the two blind spots that were found and fixed
after the original model was wired in). This retraining uses the same
capture parameters (base interval 3-6s, up to 20 observations) as the
original, so those same range-gate constants should still apply -- verify
against the new dataset_c2.csv (e.g. `df[df.observation_count>=12].label`)
before assuming otherwise.

Run: backend/.venv/bin/python3 training/train_c2.py
Reads: training/dataset_c2.csv
Saves: backend/ml_models/c2_model.joblib, backend/ml_models/c2_cal_data.npz
Updates: ML_MODELS.md is NOT auto-updated -- update it by hand with the
printed classification report after this runs.
"""
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import confusion_matrix

REPO_ROOT = Path(__file__).parent.parent
DATASET = REPO_ROOT / "training" / "dataset_c2.csv"
MODEL_OUT = REPO_ROOT / "backend" / "ml_models" / "c2_model.joblib"
CAL_DATA_OUT = REPO_ROOT / "backend" / "ml_models" / "c2_cal_data.npz"

FEATURES = ["observation_count", "mean_interval", "std_interval", "cv"]

# Exact thresholds from backend/detectors/c2.py's fallback rule
MIN_OBSERVATIONS = 5
CV_THRESHOLD = 0.35
MIN_INTERVAL = 3
MAX_INTERVAL = 600

df = pd.read_csv(DATASET)
X = df[FEATURES].values
y = df["label"].values
groups = df["session_id"].values
n_sessions = df["session_id"].nunique()

print(f"Dataset: {len(df)} rows across {n_sessions} sessions "
      f"({(y==0).sum()} benign rows, {(y==1).sum()} c2 rows)")

# Blind-spot check (see module docstring) -- print rather than assert, so
# training doesn't hard-fail if the capture parameters ever change; a
# human should read this before trusting c2.py's existing range-gate
# constants (MODEL_MAX_OBSERVATIONS=11, MODEL_MAX_MEAN_INTERVAL=7.0)
# against this new dataset.
high_count = df[df["observation_count"] >= 12]
if len(high_count):
    print(f"[blind-spot check] observation_count>=12: {len(high_count)} rows, "
          f"labels present: {sorted(high_count['label'].unique())} "
          f"(c2.py's MODEL_MAX_OBSERVATIONS=11 assumes this region is c2-only)")
high_interval = df[df["mean_interval"] > 7.0]
if len(high_interval):
    print(f"[blind-spot check] mean_interval>7.0: {len(high_interval)} rows, "
          f"labels present: {sorted(high_interval['label'].unique())} "
          f"(c2.py's MODEL_MAX_MEAN_INTERVAL=7.0 assumes benign has no counterexamples above this)")

N_SPLITS = 10
gkf = GroupKFold(n_splits=N_SPLITS)


def rule_baseline_predict(X_fold):
    count = X_fold[:, FEATURES.index("observation_count")]
    mean_iv = X_fold[:, FEATURES.index("mean_interval")]
    cv = X_fold[:, FEATURES.index("cv")]
    return (
        (count >= MIN_OBSERVATIONS)
        & (mean_iv >= MIN_INTERVAL) & (mean_iv <= MAX_INTERVAL)
        & (cv <= CV_THRESHOLD)
    ).astype(int)


MODELS = {
    "Rule baseline (existing detector logic)": None,
    "Logistic Regression": Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=1000)),
    ]),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=6, class_weight="balanced", random_state=42
    ),
    "Gradient Boosting": HistGradientBoostingClassifier(
        max_depth=4, max_iter=150, class_weight="balanced", random_state=42
    ),
}

confusions = {name: np.zeros((2, 2), dtype=int) for name in MODELS}

for fold_i, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups)):
    X_train, X_test_fold = X[train_idx], X[test_idx]
    y_train, y_test_fold = y[train_idx], y[test_idx]

    for name, model in MODELS.items():
        if model is None:
            y_pred = rule_baseline_predict(X_test_fold)
        else:
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test_fold)
        confusions[name] += confusion_matrix(y_test_fold, y_pred, labels=[0, 1])

    print(f"Fold {fold_i + 1}/{N_SPLITS} done ({len(set(groups[test_idx]))} sessions held out)")

print(f"\n{'Model':<40} {'Precision':>10} {'Recall':>10} {'F1':>10}")
print("-" * 70)
for name in MODELS:
    tn, fp, fn, tp = confusions[name].ravel()
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    print(f"{name:<40} {prec:>10.3f} {rec:>10.3f} {f1:>10.3f}")

print("\nPooled confusion matrices (across all 10 folds) [benign, c2]:")
for name in MODELS:
    print(f"\n{name}:")
    print(confusions[name])

unique_groups = df["session_id"].unique()
train_groups, test_groups = train_test_split(unique_groups, test_size=0.2, random_state=42)
train_mask = df["session_id"].isin(train_groups).values
test_mask = df["session_id"].isin(test_groups).values
X_train_final, y_train_final = X[train_mask], y[train_mask]
X_test, y_test = X[test_mask], y[test_mask]

final_model = RandomForestClassifier(n_estimators=200, max_depth=6, class_weight="balanced", random_state=42)
final_model.fit(X_train_final, y_train_final)

fit_groups, cal_groups = train_test_split(train_groups, test_size=0.25, random_state=42)
fit_mask = df["session_id"].isin(fit_groups).values
cal_mask = df["session_id"].isin(cal_groups).values
np.savez(CAL_DATA_OUT, X=X[cal_mask], y=y[cal_mask], X_test=X_test, y_test=y_test)
print(f"\nSaved calibration hold-out data to {CAL_DATA_OUT}")

MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(final_model, MODEL_OUT)
print(f"Saved model to {MODEL_OUT}")

print("\nFeature importances (final model):")
for fname, imp in sorted(zip(FEATURES, final_model.feature_importances_), key=lambda x: -x[1]):
    print(f"  {fname}: {imp:.3f}")
