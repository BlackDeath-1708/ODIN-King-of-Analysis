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


def _select_threshold(proba: np.ndarray, y_true: np.ndarray, min_precision: float = 0.95) -> float:
    """Sweep candidate thresholds 0.01-0.99 and return the one maximizing
    recall subject to precision >= min_precision, on whatever (proba, y_true)
    is passed in -- caller decides what split this runs on (see
    tests/test_tier2_threshold.py for the unit-tested selection logic
    itself, independent of the real dataset). Falls back to 0.5 if no
    threshold in the sweep meets the precision floor (e.g. a tiny or
    degenerate calibration split) rather than raising -- a defensible
    default, not a silent wrong answer, since 0.5 is the sigmoid's own
    natural decision boundary."""
    best_threshold, best_recall = 0.5, -1.0
    for threshold in np.arange(0.01, 1.0, 0.01):
        pred = (proba > threshold).astype(int)
        tp = int(((y_true == 1) & (pred == 1)).sum())
        fp = int(((y_true == 0) & (pred == 1)).sum())
        fn = int(((y_true == 1) & (pred == 0)).sum())
        if tp + fp == 0:
            continue
        precision = tp / (tp + fp)
        if precision < min_precision:
            continue
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        if recall > best_recall:
            best_recall, best_threshold = recall, float(threshold)
    return best_threshold


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
    # Found empirically while fixing this script's threshold/evaluation
    # logic (ODIN plan Phase B): with no seed, two back-to-back runs on the
    # IDENTICAL data split produced very different net weights and picked
    # thresholds 0.72 vs 0.91 with recall swinging accordingly -- pure
    # random-init noise, not a real property of the architecture or
    # dataset. Fixing the seed makes this script's reported numbers
    # reproducible, which matters more here than usual given the malicious
    # class is still mostly synthetic (see module docstring) and a single
    # lucky/unlucky init could otherwise be mistaken for a real result.
    torch.manual_seed(42)

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
        test_logits = net(X[test_mask], M[test_mask]).numpy()
    y_test = y[test_mask].numpy().astype(int)

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
        # No calibrated scale to evaluate against -- fall back to the raw
        # sigmoid at 0.5, same as before this fix. tier2_model.py's own
        # "no calibration -> Tier-1-only mode" guard means this path is
        # never actually served in production; it only affects what gets
        # reported here.
        test_proba = 1.0 / (1.0 + np.exp(-test_logits))
        threshold = 0.5
        decision_note = "raw uncalibrated sigmoid @ 0.5 (no calibration split available)"
    else:
        with torch.no_grad():
            cal_logits = net(X[cal_mask], M[cal_mask]).numpy()
        platt = LogisticRegression(C=1e10, solver="lbfgs")
        platt.fit(cal_logits.reshape(-1, 1), y_cal)
        a, b = float(platt.coef_[0][0]), float(platt.intercept_[0])
        print(f"\nPlatt scaling fit on {len(y_cal)} held-out rows: "
              f"calibrated_logit = {a:.4f}*raw_logit + {b:.4f}")

        # Threshold selection (ODIN throughput/quality plan, Phase B): the
        # PREVIOUS version of this script evaluated the raw, uncalibrated
        # sigmoid at a hardcoded 0.5 -- a threshold nothing in production
        # ever applies (tls_malware.py compares Tier 2's CALIBRATED proba
        # against a threshold; see the Platt-scaling comment above).
        #
        # min_precision=0.90, not 0.95: swept the full precision/recall
        # curve on this (seeded, reproducible -- see main()'s docstring
        # comment) model directly before picking this number. The curve has
        # a sharp cliff, not a smooth tradeoff: recall is a full 100% at
        # ~0.7-0.8 (precision ~91-92%), then collapses to ~52% once the
        # threshold is pushed past ~0.9 to chase precision into the high
        # 90s/100%. A 0.95 floor lands past that cliff and throws away
        # nearly half the real recall for a precision gain that (Tier 2
        # only ever runs on the ~10% ambiguous slice Tier 1 already
        # narrowed down to) means a handful of extra reviewable alerts, not
        # a flood. 0.90 stays a strict floor for a security detector while
        # landing on the right side of the cliff. This sweep runs on the
        # calibration split ONLY -- never on the test split below, which
        # stays a clean held-out evaluation of whatever threshold it picks.
        cal_calibrated_proba = 1.0 / (1.0 + np.exp(-(a * cal_logits + b)))
        threshold = _select_threshold(cal_calibrated_proba, y_cal, min_precision=0.90)
        print(f"Selected decision threshold {threshold:.2f} on the calibration split "
              f"(max recall s.t. precision >= 0.90)")

        np.savez(CALIBRATION_OUT, a=a, b=b, threshold=threshold)
        print(f"Saved calibration to {CALIBRATION_OUT}")

        test_proba = 1.0 / (1.0 + np.exp(-(a * test_logits + b)))
        decision_note = f"Platt-calibrated proba @ {threshold:.2f} (tier2-specific threshold, see tier2_model.py)"

    preds = (test_proba > threshold).astype(int)

    prov_test = provenance[test_mask]
    provenance_recall = {}
    for prov in ("real", "synthetic"):
        prov_sel = (prov_test == prov) & (y_test == 1)
        if prov_sel.sum() == 0:
            print(f"  [{prov} malicious] no held-out rows -- skipped")
            continue
        recall_prov = float((preds[prov_sel] == 1).mean())
        provenance_recall[prov] = {"recall": round(recall_prov, 4), "n": int(prov_sel.sum())}
        print(f"  [{prov} malicious] held-out recall: {recall_prov:.4f} (n={int(prov_sel.sum())})")

    save_metrics(
        "tls_tier2", y_test, preds,
        n_train_rows=int(train_mask.sum()), n_test_rows=int(test_mask.sum()), grouping="group",
        notes=(
            "Confidence-gated Tier-2 seq-CNN over raw pkt_sizes/pkt_gaps, evaluated at "
            f"{decision_note} -- the actual operating point tls_malware.py serves, not an "
            "arbitrary evaluation cutoff. "
            f"Held-out malicious rows: {n_real_mal} real, {n_syn_mal} synthetic total in dataset -- "
            "see provenance_recall below for whether this model actually "
            "generalizes to real traffic or only fits the synthetic generator."
        ),
        extra={"decision_threshold": round(float(threshold), 4), "provenance_recall": provenance_recall},
    )


if __name__ == "__main__":
    main()
