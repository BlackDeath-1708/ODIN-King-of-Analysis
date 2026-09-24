# ODIN Dataset & Model Baseline — 2026-09-12

Frozen before the provenance/scenario-manifest retrofit (see `training/scenarios/README.md`)
so later dataset changes can be compared against a known-good starting point.

**Git commit at freeze time:** `45b11804817cc3d612b7b6a16d5f7620d0be27f9`

## Dataset row counts (at freeze time)

| Detector | Rows | Source file | Notes |
|---|---:|---|---|
| ddos | 29,845 | `training/dataset_ddos.csv` | |
| c2 | 31,219 | `training/dataset_c2.csv` | includes `dataset_c2_original.csv` (16,263) + range-extension rows |
| recon | 17,675 | `training/dataset_recon.csv` | |
| exfil | 15,502 | `training/dataset_exfil.csv` | |
| tls (flow-stats) | 23,778 | `training/dataset_tls.csv` | |
| tls_tier2 (seq-CNN) | 10,830 | `training/dataset_tls_seq.npz` | 8,396 train + 2,434 test rows per `docs/metrics/tls_tier2.json` |
| dga | 25,000 | *(none — generated in-memory by `train_dga.py`, not persisted to a CSV)* | 20,000 train + 5,000 test rows per `docs/metrics/dga.json` |

**Combined (persisted CSVs only): ~134,282 rows.**

## Model metrics (copied verbatim from `docs/metrics/*.json`)

See `metrics/*.json` in this directory for the full confusion matrices. Headline numbers:

| Detector | Precision | Recall | F1 | FP rate | Test rows |
|---|---:|---:|---:|---:|---:|
| ddos | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 6,143 |
| recon | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 4,051 |
| exfil | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 3,101 |
| tls (flow-stats) | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 4,817 |
| c2 | 0.9988 | 1.0000 | 0.9994 | 0.0067 | 7,737 |
| dga | 0.9965 | 0.9915 | 0.9940 | 0.0037 | 5,000 |
| tls_tier2 (seq-CNN) | 1.0000 | 0.5195 | 0.6838 | 0.0000 | 2,434 |

## Model artifacts frozen

All `*.joblib`, `*.npz`, `*.pt` files from `backend/ml_models/` at freeze time — see `ml_models/` in this directory (20 files).

## Known caveats already documented (unchanged by this freeze)

- `tls` (flow-stats) malicious class is 100% synthetic — no ethical real-malware-over-TLS source existed at the time.
- `tls_tier2` malicious class is 13 real (CTU-13 botnet42/Neris) + synthetic top-up — the seq-CNN's real recall (0.52) is genuinely lower than its overall reported precision, reflecting the real scarcity constraint, not a bug.
- `c2` dataset is 100% self-generated (no real botnet-capture C2 traffic yet) — flagged for CTU-13 expansion in the dataset plan.
- `dga` malicious class is 100% synthetic, drawn from 9 published DGA algorithm families.
