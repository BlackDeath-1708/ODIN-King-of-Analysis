"""
Train the Tier-2 seq-CNN (backend/detectors/tier2_model.py), the confidence-
gated refinement TLSMalwareDetector consults only when Tier 1's calibrated
RandomForest probability lands in the ambiguous 0.4-0.7 band.

Reads training/dataset_tls_seq.npz, built by training/build_dataset_tls_seq.py:
  - BENIGN (label=0): REAL raw pkt_sizes/pkt_gaps sequences, from actual
    HTTPS/QUIC captures (training/zeek-logs-tls/pkt_seq.log).
  - MALICIOUS (label=1): a mix of REAL sequences (once
    training/build_malicious_pcap_logs.py + build_dataset_tls_seq.py have
    processed real malicious pcaps -- see ML_MODELS.md) and SYNTHETIC
    sequences (the existing beacon/bulk-upload generator from
    build_dataset_tls.py, kept as a comparison arm via the `provenance`
    column rather than deleted). Until real-malicious rows exist, this
    trains on real-benign + synthetic-malicious only -- a deliberate
    placeholder (see tier2_model.py's docstring) that validates the whole
    pipeline's mechanics; rerunning this script after regenerating the
    dataset with real rows is the entire "swap in better data" step, no
    code changes.

Uses the exact same network (_build_net(), tier2_model.py) for training and
serving, so there is exactly one architecture definition to keep in sync --
same principle as _flow_features() being imported rather than duplicated.

Run: backend/.venv/bin/python3 training/train_tier2.py
Reads: training/dataset_tls_seq.npz
Saves: backend/ml_models/tls_tier2_model.pt
"""
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, train_test_split

from metrics_utils import save_metrics

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from detectors.tier2_model import _build_net  # noqa: E402

DATASET = REPO_ROOT / "training" / "dataset_tls_seq.npz"
MODEL_OUT = REPO_ROOT / "backend" / "ml_models" / "tls_tier2_model.pt"
CALIBRATION_OUT = REPO_ROOT / "backend" / "ml_models" / "tls_tier2_calibration.npz"
EPOCHS = 40
LR = 1e-3


def _train_one(net, X_tr, M_tr, y_tr, epochs=EPOCHS):
    opt = torch.optim.Adam(net.parameters(), lr=LR)
    loss_fn = torch.nn.BCEWithLogitsLoss()
    net.train()
    for _ in range(epochs):
        opt.zero_grad()
        logits = net(X_tr, M_tr)
        loss = loss_fn(logits, y_tr)
        loss.backward()
        opt.step()
    net.eval()
    return net


def main():
    data = np.load(DATASET, allow_pickle=True)
    seq, mask, label, provenance, group = (
        data["seq"], data["mask"], data["label"], data["provenance"], data["group"],
    )
    n_real_mal = int(((label == 1) & (provenance == "real")).sum())
    n_syn_mal = int(((label == 1) & (provenance == "synthetic")).sum())
    print(f"Dataset: {len(label)} rows ({int((label==0).sum())} benign, "
          f"{n_real_mal} real-malicious, {n_syn_mal} synthetic-malicious), "
          f"{len(np.unique(group))} groups")

    X = torch.from_numpy(seq.astype(np.float32))
    M = torch.from_numpy(mask.astype(np.float32))
    y = torch.from_numpy(label.astype(np.float32))

    unique_groups = np.unique(group)
    n_splits = min(10, len(unique_groups))
    gkf = GroupKFold(n_splits=n_splits)
    confusion = np.zeros((2, 2), dtype=int)
    for fold_i, (tr_idx, te_idx) in enumerate(gkf.split(X.numpy(), y.numpy(), group)):
        net = _build_net()
        _train_one(net, X[tr_idx], M[tr_idx], y[tr_idx])
        with torch.no_grad():
            preds = (torch.sigmoid(net(X[te_idx], M[te_idx])) > 0.5).float().numpy()
        for t, p in zip(y[te_idx].numpy().astype(int), preds.astype(int)):
            confusion[t, p] += 1
        print(f"Fold {fold_i + 1}/{n_splits} done ({len(set(group[te_idx]))} groups held out)")

    tn, fp, fn, tp = confusion.ravel()
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    print(f"\nPooled GroupKFold: precision={prec:.4f} recall={rec:.4f} F1={f1:.4f}")
    print(f"Confusion matrix [benign, malicious]:\n{confusion}")

    train_groups, test_groups = train_test_split(unique_groups, test_size=0.2, random_state=42)
    train_mask = np.isin(group, train_groups)
    test_mask = np.isin(group, test_groups)

    net = _build_net()
    _train_one(net, X[train_mask], M[train_mask], y[train_mask])
    with torch.no_grad():
        test_proba = torch.sigmoid(net(X[test_mask], M[test_mask])).numpy()
    preds = (test_proba > 0.5).astype(int)
    y_test = y[test_mask].numpy().astype(int)

    save_metrics(
        "tls_tier2", y_test, preds,
        n_train_rows=int(train_mask.sum()), n_test_rows=int(test_mask.sum()), grouping="group",
        notes=(
            "Confidence-gated Tier-2 seq-CNN over raw pkt_sizes/pkt_gaps. "
            f"Held-out malicious rows: {n_real_mal} real, {n_syn_mal} synthetic total in dataset -- "
            "see per-provenance breakdown below for whether this model actually "
            "generalizes to real traffic or only fits the synthetic generator."
        ),
    )

    prov_test = provenance[test_mask]
    for prov in ("real", "synthetic"):
        prov_sel = (prov_test == prov) & (y_test == 1)
        if prov_sel.sum() == 0:
            print(f"  [{prov} malicious] no held-out rows -- skipped")
            continue
        recall_prov = float((preds[prov_sel] == 1).mean())
        print(f"  [{prov} malicious] held-out recall: {recall_prov:.4f} (n={int(prov_sel.sum())})")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    torch.save(net.state_dict(), MODEL_OUT)
    print(f"Saved model to {MODEL_OUT}")

    # Platt scaling, same pattern calibration/calibrate_models.py uses for
    # the other 6 (sklearn) detectors: freeze this trained net, fit a 1-D
    # logistic regression (calibrated_logit = a*raw_logit + b) against a
    # held-out slice of train_groups -- so tls_malware.py's 0.72/0.85
    # thresholds (tuned for Tier 1's calibrated proba) stay meaningful once
    # Tier 2 overrides proba, instead of comparing a calibrated score
    # against a raw, differently-distributed sigmoid output.
    fit_groups, cal_groups = train_test_split(train_groups, test_size=0.25, random_state=42)
    cal_mask = np.isin(group, cal_groups)
    y_cal = y[cal_mask].numpy()
    if len(np.unique(y_cal)) < 2:
        print("\nCalibration split has only one class present -- skipping Platt fit "
              "(tier2_model.py will serve raw uncalibrated sigmoid until this dataset grows).")
    else:
        with torch.no_grad():
            cal_logits = net(X[cal_mask], M[cal_mask]).numpy()
        platt = LogisticRegression(C=1e10, solver="lbfgs")
        platt.fit(cal_logits.reshape(-1, 1), y_cal)
        a, b = float(platt.coef_[0][0]), float(platt.intercept_[0])
        print(f"\nPlatt scaling fit on {len(y_cal)} held-out rows: "
              f"calibrated_logit = {a:.4f}*raw_logit + {b:.4f}")
        np.savez(CALIBRATION_OUT, a=a, b=b)
        print(f"Saved calibration to {CALIBRATION_OUT}")


if __name__ == "__main__":
    main()
