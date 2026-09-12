"""
Shared packet-sequence packing for the TLS/QUIC Tier-2 deep model.

Tier 1 (tls_malware.py's RandomForest) collapses each flow's raw
pkt_sizes/pkt_gaps (zeek/scripts/pkt_seq.zeek, capped at the first 12
packets) into mean/std scalars. Tier 2 looks at the raw sequence itself --
so both training (training/build_dataset_tls_seq.py) and serving
(backend/detectors/tls_malware.py) need the *exact* same normalize/pad/mask
function, the same reason TLSMalwareDetector._flow_features() is imported
directly into build_dataset_tls.py rather than reimplemented.

No torch import here on purpose: this module is pure NumPy so it stays
usable from the dataset-builder even before torch/tier2_model.py's
dependency situation is settled, and so a unit test never needs a model
file or a GPU/CPU backend to exercise the packing logic in isolation.
"""
import numpy as np

MAX_PKTS = 12          # must match zeek/scripts/pkt_seq.zeek's max_pkts
SIZE_NORM = 1500.0      # typical MTU -- keeps normalized sizes near [0, 1]
GAP_LOG_NORM = np.log1p(2.0)  # a 2s inter-packet gap is already very long
                              # for a 12-packet handshake window


def pack_sequence(sizes: list, gaps: list) -> tuple:
    """Normalize + right-pad (sizes, gaps) to length MAX_PKTS.

    Returns (seq, mask):
      seq  -- float32 array, shape (2, MAX_PKTS): row 0 = normalized sizes,
              row 1 = normalized gaps (gaps has one fewer real element than
              sizes for a flow with N packets -- see note below -- so it's
              padded with the same trailing-zero convention).
      mask -- float32 array, shape (MAX_PKTS,): 1.0 for a real *size*
              position, 0.0 for padding. Gaps don't get their own mask
              (there are always len(sizes)-1 of them); global max-pool over
              the model's time axis already makes padded positions inert
              (see tier2_model.py), so one shared mask is enough.

    An empty/too-short input degrades to an all-zero, all-masked-out
    sequence rather than raising -- callers (tier2_model.predict) treat an
    all-zero mask as "nothing to refine" and skip Tier-2 entirely.
    """
    sizes = list(sizes or [])[:MAX_PKTS]
    gaps = list(gaps or [])[:MAX_PKTS]

    n = len(sizes)
    seq = np.zeros((2, MAX_PKTS), dtype=np.float32)
    mask = np.zeros(MAX_PKTS, dtype=np.float32)

    if n:
        seq[0, :n] = np.asarray(sizes, dtype=np.float32) / SIZE_NORM
        n_gaps = min(len(gaps), n)
        if n_gaps:
            gap_arr = np.asarray(gaps[:n_gaps], dtype=np.float32)
            seq[1, :n_gaps] = np.log1p(np.clip(gap_arr, 0, None)) / GAP_LOG_NORM
        mask[:n] = 1.0

    return seq, mask
