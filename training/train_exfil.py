"""
Train the data-exfiltration RandomForest classifier.

Reads training/dataset_exfil.csv, built by training/build_dataset_exfil.py
from REAL captured traffic (local asymmetric HTTP transfers, real ICMP
pings, real UDP bursts to real public resolvers -- see that script's
docstring, including the Zeek `-C` checksum-offload bug found and fixed
this session) plus a synthetic top-up for volume/class balance.

Features (order must match ExfilDetector._extract() in backend/detectors/exfil.py):
  orig_bytes, resp_bytes, byte_ratio, duration, orig_pkts, resp_pkts,
  bytes_per_sec, is_icmp, to_dns_port, to_common_port

GroupKFold grouped by `group` (unique per real row; unique per synthetic
row too -- see build_dataset_exfil.py's note on why shared category labels
would starve most folds of that class).

Run: backend/.venv/bin/python3 training/train_exfil.py
Reads: training/dataset_exfil.csv
Saves: backend/ml_models/exfil_model.joblib, backend/ml_models/exfil_cal_data.npz
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.metrics import classification_report, confusion_matrix

REPO_ROOT    = Path(__file__).parent.parent
DATASET      = REPO_ROOT / "training" / "dataset_exfil.csv"
MODEL_OUT    = REPO_ROOT / "backend" / "ml_models" / "exfil_model.joblib"
CAL_DATA_OUT = REPO_ROOT / "backend" / "ml_models" / "exfil_cal_data.npz"

FEATURES = ["orig_bytes", "resp_bytes", "byte_ratio", "duration",
            "orig_pkts", "resp_pkts", "bytes_per_sec", "is_icmp", "to_dns", "to_common_port"]


def main():
    df = pd.read_csv(DATASET)
    X = df[FEATURES].values
    y = df["label"].values
    groups = df["group"].values
    print(f"Dataset: {len(df)} rows across {df['group'].nunique()} groups "
          f"({(y==0).sum()} benign rows, {(y==1).sum()} exfil rows)")

    gkf = GroupKFold(n_splits=10)
    confusion = np.zeros((2, 2), dtype=int)
    for fold_i, (tr_idx, te_idx) in enumerate(gkf.split(X, y, groups)):
        clf = RandomForestClassifier(n_estimators=150, max_depth=10, class_weight='balanced', random_state=42)
        clf.fit(X[tr_idx], y[tr_idx])
        preds = clf.predict(X[te_idx])
        confusion += confusion_matrix(y[te_idx], preds, labels=[0, 1])
        print(f"Fold {fold_i + 1}/10 done ({len(set(groups[te_idx]))} groups held out)")

    tn, fp, fn, tp = confusion.ravel()
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    print(f"\nPooled GroupKFold: precision={prec:.4f} recall={rec:.4f} F1={f1:.4f}")
    print(f"Confusion matrix [benign, exfil]:\n{confusion}")

    unique_groups = df["group"].unique()
    train_groups, test_groups = train_test_split(unique_groups, test_size=0.2, random_state=42)
    train_mask = df["group"].isin(train_groups).values
    test_mask = df["group"].isin(test_groups).values
    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    final_model = RandomForestClassifier(n_estimators=150, max_depth=10, class_weight='balanced', random_state=42)
    final_model.fit(X_train, y_train)
    preds = final_model.predict(X_test)
    print("\nHeld-out test set classification report:")
    print(classification_report(y_test, preds, target_names=['benign', 'exfil'], zero_division=0))

    fit_groups, cal_groups = train_test_split(train_groups, test_size=0.25, random_state=42)
    fit_mask = df["group"].isin(fit_groups).values
    cal_mask = df["group"].isin(cal_groups).values
    np.savez(CAL_DATA_OUT, X=X[cal_mask], y=y[cal_mask], X_test=X_test, y_test=y_test)
    print(f"\nSaved calibration hold-out data to {CAL_DATA_OUT}")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, MODEL_OUT)
    print(f"Saved model to {MODEL_OUT}")

    print("\nFeature importances (final model):")
    for fname, imp in sorted(zip(FEATURES, final_model.feature_importances_), key=lambda x: -x[1]):
        print(f"  {fname}: {imp:.3f}")


if __name__ == '__main__':
    main()
