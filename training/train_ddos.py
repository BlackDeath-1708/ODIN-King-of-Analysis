"""
Trains the DDoS / SYN-flood RandomForest classifier from
training/dataset_ddos.csv (real hping3+socket traffic captured via
training/capture/capture_ddos.py -- see that file and
training/build_dataset_ddos.py for methodology).

Same evaluation discipline as the other in-repo detectors: GroupKFold by
session_id (never a random row split -- adjacent rows within one session
are dense, overlapping-window snapshots, not independent observations),
pooled confusion matrix across folds (not per-fold score averaging, which
breaks when a held-out fold happens to be single-class).

Also persists a Platt-calibration hold-out split (<name>_cal_data.npz),
matching the convention used for dga/tls_flow/exfil in Phase 3 -- so
calibration/calibrate_models.py can calibrate this model too, closing the
gap noted in ML_MODELS.md where ddos/recon/c2 (trained outside this repo)
had no calibration split available.

Run: backend/.venv/bin/python3 training/train_ddos.py
Reads: training/dataset_ddos.csv
Saves: backend/ml_models/ddos_model.joblib, backend/ml_models/ddos_cal_data.npz
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
DATASET = REPO_ROOT / "training" / "dataset_ddos.csv"
MODEL_OUT = REPO_ROOT / "backend" / "ml_models" / "ddos_model.joblib"
CAL_DATA_OUT = REPO_ROOT / "backend" / "ml_models" / "ddos_cal_data.npz"

FEATURES = [
    "packet_rate", "unique_dst_ports", "dst_port_entropy",
    "mean_inter_arrival", "std_inter_arrival",
    "unique_src_ips", "src_ip_entropy",
]
PACKET_RATE_THRESHOLD = 200   # exact threshold from backend/detectors/ddos.py's fallback rule

df = pd.read_csv(DATASET)
X = df[FEATURES].values
y = df["label"].values
groups = df["session_id"].values
n_sessions = df["session_id"].nunique()

print(f"Dataset: {len(df)} rows across {n_sessions} sessions "
      f"({(y==0).sum()} benign rows, {(y==1).sum()} ddos rows)")

N_SPLITS = 10
gkf = GroupKFold(n_splits=N_SPLITS)


def rule_baseline_predict(X_fold):
    rate = X_fold[:, FEATURES.index("packet_rate")]
    return (rate > PACKET_RATE_THRESHOLD).astype(int)


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

print("\nPooled confusion matrices (across all 10 folds) [benign, ddos]:")
for name in MODELS:
    print(f"\n{name}:")
    print(confusions[name])

# Final model trained on a held-out-aware split (mirrors dga/tls/exfil's
# convention) so a genuine test set + calibration split both exist,
# grouped by session to avoid leaking near-duplicate snapshot rows.
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
