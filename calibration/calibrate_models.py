"""
Calibrate ODIN RandomForest models with Platt scaling (sigmoid).

Run once, after training: python calibration/calibrate_models.py

For each model this writes:
  backend/ml_models/<name>_model_calibrated.joblib
  docs/calibration_plots/<name>_calibration.png   (reliability diagram, base vs calibrated)

Requires a "<name>_cal_data.npz" file (X, y, X_test, y_test) next to the base
model -- produced by that model's training script. All six models are now
trained entirely inside this repo (training/train_*.py) and all six persist
a calibration split, so all six get calibrated here -- ddos/recon/c2 were
originally trained in a sibling repo (recon-ml-poc/) and skipped calibration
for lack of a persisted split; that gap was closed when they were retrained
in-repo on real traffic (see ML_MODELS.md's "Real-traffic retraining"). A
model would still be skipped here (with an explicit message, not a faked
synthetic split) if its cal_data.npz were ever missing -- a calibration
curve fit on data that doesn't match the original training distribution
would silently misrepresent how well-calibrated the model actually is,
worse than staying uncalibrated and saying so.
"""
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.frozen import FrozenEstimator

ML_MODELS_DIR = Path(__file__).parent.parent / "backend" / "ml_models"
PLOTS_DIR = Path(__file__).parent.parent / "docs" / "calibration_plots"

# name -> base model filename (mirrors each detector's MODEL_PATH)
MODEL_FILES = {
    "ddos": "ddos_model.joblib",
    "recon": "recon_model_v3.joblib",
    "c2": "c2_model.joblib",
    "dga": "dga_model.joblib",
    "tls_flow": "tls_flow_model.joblib",
    "exfil": "exfil_model.joblib",
}


def _calibrated_path(base_filename: str) -> Path:
    return ML_MODELS_DIR / base_filename.replace(".joblib", "_calibrated.joblib")


def _plot_reliability(name: str, y_test, base_proba, cal_proba) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    base_frac, base_mean = calibration_curve(y_test, base_proba, n_bins=10, strategy="uniform")
    cal_frac, cal_mean = calibration_curve(y_test, cal_proba, n_bins=10, strategy="uniform")

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "k--", label="Perfectly calibrated")
    ax.plot(base_mean, base_frac, "s-", label="Base model")
    ax.plot(cal_mean, cal_frac, "o-", label="Platt-calibrated")
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Fraction of positives")
    ax.set_title(f"{name} — reliability diagram")
    ax.legend(loc="lower right")
    fig.tight_layout()

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PLOTS_DIR / f"{name}_calibration.png"
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"  wrote {out_path}")


def calibrate_one(name: str, base_filename: str) -> dict:
    base_path = ML_MODELS_DIR / base_filename
    cal_data_path = ML_MODELS_DIR / f"{name}_cal_data.npz"

    if not base_path.exists():
        print(f"[{name}] SKIP -- base model not found at {base_path}")
        return {"name": name, "status": "base_model_missing"}

    if not cal_data_path.exists():
        print(f"[{name}] SKIP -- no {cal_data_path.name} "
              f"(trained outside this repo, no calibration split persisted here)")
        return {"name": name, "status": "no_calibration_data"}

    try:
        base_model = joblib.load(base_path)
        data = np.load(cal_data_path)
        X, y, X_test, y_test = data["X"], data["y"], data["X_test"], data["y_test"]

        calibrated = CalibratedClassifierCV(FrozenEstimator(base_model), method="sigmoid")
        calibrated.fit(X, y)

        base_proba = base_model.predict_proba(X_test)[:, 1]
        cal_proba = calibrated.predict_proba(X_test)[:, 1]
        max_shift = float(np.max(np.abs(base_proba - cal_proba)))

        out_path = _calibrated_path(base_filename)
        joblib.dump(calibrated, out_path)
        print(f"[{name}] wrote {out_path} (max confidence shift vs base: {max_shift:.4f})")

        _plot_reliability(name, y_test, base_proba, cal_proba)
    except Exception as e:
        print(f"[{name}] ERROR -- {e!r} -- skipping, remaining models still run")
        return {"name": name, "status": "error", "error": str(e)}

    return {"name": name, "status": "calibrated", "max_confidence_shift": round(max_shift, 4)}


def main():
    results = [calibrate_one(name, filename) for name, filename in MODEL_FILES.items()]

    calibrated = [r for r in results if r["status"] == "calibrated"]
    skipped = [r for r in results if r["status"] != "calibrated"]

    print("\n=== Summary ===")
    print(f"Calibrated: {[r['name'] for r in calibrated]}")
    print(f"Skipped:    {[(r['name'], r['status']) for r in skipped]}")

    for r in calibrated:
        if r["max_confidence_shift"] > 0.15:
            print(f"WARNING [{r['name']}]: confidence shifted by {r['max_confidence_shift']} "
                  f"(>0.15) -- calibration set may be too small, consider a larger hold-out")


if __name__ == "__main__":
    main()
