"""
Tier-2 deep model: a compact 1D-CNN over the raw packet-size/gap sequence,
invoked by TLSMalwareDetector only when Tier 1's calibrated RandomForest
probability lands in the ambiguous band (0.4 <= P <= 0.7 -- see
tls_malware.py). 12 timesteps is too short for a recurrent net's
sequential-dependency modeling to earn its keep over a CNN's local-pattern
matching, and a small CNN is easier to keep well-regularized on a dataset
that (until training/build_dataset_tls_seq.py's real-malicious rows land)
is still partly synthetic -- see training/train_tier2.py and the plan this
was built from.

load_tier2_model() follows the exact same graceful-degrade-to-None contract
TLSMalwareDetector._load_model() already uses for Tier 1: any failure
(missing file, corrupt weights, torch not installed) returns None, and the
detector just runs Tier-1-only. This means the confidence gate in
tls_malware.py needs zero cleanup once this file/the trained weights land --
the guard is already the right shape.
"""
from pathlib import Path

import numpy as np

from .tier2_features import MAX_PKTS, pack_sequence

MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "tls_tier2_model.pt"
CALIBRATION_PATH = Path(__file__).parent.parent / "ml_models" / "tls_tier2_calibration.npz"


def _build_net():
    import torch.nn as nn

    class Tier2CNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = nn.Conv1d(2, 16, kernel_size=3, padding=1)
            self.conv2 = nn.Conv1d(16, 32, kernel_size=3, padding=1)
            self.fc1 = nn.Linear(32, 16)
            self.fc2 = nn.Linear(16, 1)

        def forward(self, x, mask):
            import torch

            h = torch.relu(self.conv1(x))
            h = torch.relu(self.conv2(h))              # (B, 32, MAX_PKTS)
            mask_exp = mask.unsqueeze(1)                 # (B, 1, MAX_PKTS)
            h = h.masked_fill(mask_exp == 0, float("-inf"))
            pooled, _ = h.max(dim=2)                     # (B, 32)
            # A fully-empty sequence (mask all zero) makes every position
            # -inf -- max() over an all -inf row is -inf, not a crash, but
            # feeding -inf into fc1 would poison the output, so zero it.
            pooled = torch.where(torch.isinf(pooled), torch.zeros_like(pooled), pooled)
            out = torch.relu(self.fc1(pooled))
            return self.fc2(out).squeeze(-1)             # (B,) logit

    return Tier2CNN()


class Tier2Model:
    """Thin wrapper: packs raw (sizes, gaps) -> tensors -> a single
    probability, or None if there's nothing usable to refine with.

    `calibrated` mirrors TLSMalwareDetector's own `self.calibrated` for
    Tier 1 (base.py's `calibrated` alert field, surfaced by the frontend's
    "(calibrated)" badge) -- exists so tls_malware.py never has to claim a
    raw CNN sigmoid is a Platt-calibrated probability when calibration.a/b
    weren't found. With no calibration file, `a=1, b=0` is the identity
    transform (proba stays the model's raw uncalibrated sigmoid) and
    `calibrated=False`.
    """

    def __init__(self, net, a: float = 1.0, b: float = 0.0, calibrated: bool = False):
        self._net = net
        self._a = a
        self._b = b
        self.calibrated = calibrated

    def predict(self, sizes: list, gaps: list):
        import torch

        seq, mask = pack_sequence(sizes, gaps)
        if not mask.any():
            return None  # empty sequence -- Tier 2 has nothing to add

        with torch.no_grad():
            x = torch.from_numpy(seq).unsqueeze(0)          # (1, 2, MAX_PKTS)
            m = torch.from_numpy(mask).unsqueeze(0)          # (1, MAX_PKTS)
            logit = self._net(x, m).item()
            # Platt scaling: calibrated_logit = a*raw_logit + b, fit in
            # train_tier2.py against held-out data the exact same way
            # calibration/calibrate_models.py calibrates the other 6
            # models -- this is *why* the same 0.72/0.85 thresholds
            # tls_malware.py already applies to Tier 1 remain meaningful
            # once Tier 2 overrides proba: both are now Platt-calibrated
            # probabilities on the same scale, not a raw score vs a
            # calibrated one.
            proba = 1.0 / (1.0 + np.exp(-(self._a * logit + self._b)))
        return float(proba)


def load_tier2_model(path: Path = MODEL_PATH, calibration_path: Path = CALIBRATION_PATH):
    try:
        import torch

        net = _build_net()
        state_dict = torch.load(path, map_location="cpu", weights_only=True)
        net.load_state_dict(state_dict)
        net.eval()
    except Exception as e:
        print(f"[tls] tier2 seq-CNN unavailable ({e}) -- Tier-1-only mode")
        return None

    try:
        cal = np.load(calibration_path)
        return Tier2Model(net, a=float(cal["a"]), b=float(cal["b"]), calibrated=True)
    except Exception as e:
        print(f"[tls] tier2 calibration unavailable ({e}) -- serving raw uncalibrated sigmoid")
        return Tier2Model(net, calibrated=False)
