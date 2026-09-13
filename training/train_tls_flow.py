"""
Train the TLS flow-statistics RandomForest classifier (Path B of tls_malware.py,
used when a session's JA3 hash isn't in the offline blacklist).

Reads training/dataset_tls.csv, built by training/build_dataset_tls.py from:
  - BENIGN (label=0): REAL rows -- actual HTTPS requests to ~140 diverse
    real domains, captured via training/capture/capture_tls.py and joined
    to their conn.log byte/duration data via Zeek's uid (see
    backend/stream_consumer.py's SSLByteEnricher for why that join is
    needed at all -- real ssl.log has no byte/duration fields natively).
  - MALICIOUS (label=1): SYNTHETIC (no ethical real-malware-traffic source
    exists) -- see build_dataset_tls.py's gen_malicious_rows() for the two
    published-behavior shapes used (beacon-style, bulk-upload-style), given
    deliberate numeric overlap with the real benign distribution rather
    than the old non-overlapping-range generator this replaces.

GroupKFold grouped by `domain` (real domain name, or the synthetic
malicious sub-type) -- prevents the same domain's near-identical response
size from leaking across train/test folds, the same principle as
ddos/recon/c2's session grouping and the original exfil dst_port grouping.

Features: orig_bytes, resp_bytes, duration, byte_ratio, total_bytes,
  bytes_per_sec, pkt_size_mean, pkt_size_std, pkt_gap_mean, pkt_gap_std,
  pkt_count, is_quic (must match TLSMalwareDetector._flow_features() in
  backend/detectors/tls_malware.py exactly). The last six were added
  2026-09-13 for PS 26145 (d)'s "packet-size and timing sequences" and for
  real (not just TLS-trained-hoping-to-generalize) QUIC coverage -- see
  build_dataset_tls.py and ML_MODELS.md.

Run: backend/.venv/bin/python3 training/train_tls_flow.py
Reads: training/dataset_tls.csv
Saves: backend/ml_models/tls_flow_model.joblib, backend/ml_models/tls_flow_cal_data.npz
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from metrics_utils import save_metrics

REPO_ROOT    = Path(__file__).parent.parent
DATASET      = REPO_ROOT / "training" / "dataset_tls.csv"
MODEL_OUT    = REPO_ROOT / "backend" / "ml_models" / "tls_flow_model.joblib"
CAL_DATA_OUT = REPO_ROOT / "backend" / "ml_models" / "tls_flow_cal_data.npz"

FEATURES = [
    "orig_bytes", "resp_bytes", "duration", "byte_ratio", "total_bytes", "bytes_per_sec",
    "pkt_size_mean", "pkt_size_std", "pkt_gap_mean", "pkt_gap_std", "pkt_count", "is_quic",
]


def main():
    df = pd.read_csv(DATASET)
    X = df[FEATURES].values
    y = df["label"].values
    groups = df["domain"].values
    print(f"Dataset: {len(df)} rows across {df['domain'].nunique()} distinct domains/sub-types "
          f"({(y==0).sum()} benign rows, {(y==1).sum()} malicious rows)")

    gkf = GroupKFold(n_splits=10)
    confusion = np.zeros((2, 2), dtype=int)
    for fold_i, (tr_idx, te_idx) in enumerate(gkf.split(X, y, groups)):
        clf = RandomForestClassifier(n_estimators=150, max_depth=8, class_weight='balanced', random_state=42)
        clf.fit(X[tr_idx], y[tr_idx])
        preds = clf.predict(X[te_idx])
        confusion += confusion_matrix(y[te_idx], preds, labels=[0, 1])
        print(f"Fold {fold_i + 1}/10 done ({len(set(groups[te_idx]))} groups held out)")

    tn, fp, fn, tp = confusion.ravel()
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    print(f"\nPooled GroupKFold: precision={prec:.4f} recall={rec:.4f} F1={f1:.4f}")
    print(f"Confusion matrix [benign, malicious]:\n{confusion}")

    unique_groups = df["domain"].unique()
    train_groups, test_groups = train_test_split(unique_groups, test_size=0.2, random_state=42)
    train_mask = df["domain"].isin(train_groups).values
    test_mask = df["domain"].isin(test_groups).values
    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    model = RandomForestClassifier(n_estimators=150, max_depth=8, class_weight='balanced', random_state=42)
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    print("\nHeld-out test set classification report:")
    print(classification_report(y_test, preds, target_names=['benign', 'malicious'], zero_division=0))

    save_metrics(
        "tls", y_test, preds,
        n_train_rows=len(X_train), n_test_rows=len(X_test), grouping="domain",
        notes=(
            "Benign REAL (actual HTTPS/QUIC sessions to ~157 distinct real domains). "
            "Malicious class mostly SYNTHETIC (no ethical source for volume malware-over-TLS "
            "traffic) plus 22 REAL flows (added 2026-09-13) from a real 2024 Latrodectus/Lumma "
            "Stealer infection pcap, matched to analyst-confirmed C2/malicious-infra domains -- "
            "see ML_MODELS.md's 'TLS real-malicious-data addition' section."
        ),
    )

    fit_groups, cal_groups = train_test_split(train_groups, test_size=0.25, random_state=42)
    fit_mask = df["domain"].isin(fit_groups).values
    cal_mask = df["domain"].isin(cal_groups).values
    np.savez(CAL_DATA_OUT, X=X[cal_mask], y=y[cal_mask], X_test=X_test, y_test=y_test)
    print(f"\nSaved calibration hold-out data to {CAL_DATA_OUT}")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT)
    print(f"Saved model to {MODEL_OUT}")

    print("\nFeature importances (final model):")
    for fname, imp in sorted(zip(FEATURES, model.feature_importances_), key=lambda x: -x[1]):
        print(f"  {fname}: {imp:.3f}")


if __name__ == '__main__':
    main()
