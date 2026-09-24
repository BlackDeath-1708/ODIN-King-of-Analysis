# ODIN Dataset & Model Baseline — 2026-09-13

Frozen immediately before starting `ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md` (Phase 0), so multi-host retraining can be compared against a known-good starting point. Supersedes `docs/baselines/2026-09-12/`, which predates the DGA real-data (UMUDGA) and TLS real-malicious-flow additions in commit `71b12b8`.

**Git commit at freeze time:** `96a5409547686dcbadb58672d3e2574cb36583ef`

## Dataset row counts (at freeze time)

See `dataset_counts.json` for the machine-readable version.

| Detector | Rows | Source file |
|---|---:|---|
| ddos | 32,296 | `training/dataset_ddos.csv` |
| c2 | 33,121 | `training/dataset_c2.csv` |
| recon | 17,760 | `training/dataset_recon.csv` |
| exfil | 11,600 | `training/dataset_exfil.csv` |
| tls (flow-stats) | 18,231 | `training/dataset_tls.csv` |
| tls_tier2 (seq-CNN) | — | `training/dataset_tls_seq.npz` (packed tensors; 8,396 train / 2,434 test rows per `docs/metrics/tls_tier2.json`) |
| dga | — | in-memory only; 24,800 train / 6,200 test rows per `docs/metrics/dga.json` |

**Combined (persisted CSVs only): 113,008 rows.**

## Model metrics (copied verbatim from `docs/metrics/*.json` at freeze time)

See `metrics/*.json` in this directory for full confusion matrices.

| Detector | Precision | Recall | F1 | FP rate | Test rows |
|---|---:|---:|---:|---:|---:|
| ddos | 0.9993 | 0.9960 | 0.9976 | 0.0005 | 6,787 |
| c2 | 0.9982 | 1.0000 | 0.9991 | 0.0088 | 7,276 |
| recon | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 4,051 |
| exfil | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 2,320 |
| tls (flow-stats) | 0.9981 | 1.0000 | 0.9990 | 0.0565 | 3,723 |
| tls_tier2 (seq-CNN) | 1.0000 | 0.5195 | 0.6838 | 0.0000 | 2,434 |
| dga | 0.9984 | 0.9921 | 0.9952 | 0.0025 | 6,200 |

## GroupKFold configuration (at freeze time)

| Detector | n_splits | Grouping key |
|---|---:|---|
| ddos | 10 | session/group id (see `train_ddos.py`) |
| c2 | 10 | session/group id (see `train_c2.py`) |
| recon | 10 | `session_id` |
| exfil | 10 | `group` (unique per real row; unique per synthetic session) |
| tls (flow-stats) | 10 | `domain` |
| tls_tier2 (seq-CNN) | min(10, unique groups) | same grouping as flow-stats, adapted for small real-sample count |
| dga | 5 | query-length bucket |

## Throughput

**44.8 flows/sec** (10,000 synthetic events, 223.3s isolated-loop benchmark) — see `ML_MODELS.md` for methodology. Not re-measured in this freeze; tracked as a separate opportunistic optimization track per the multi-host plan §20, not blocked on or by this baseline.

## Model artifacts frozen

All `*.joblib`, `*.npz`, `*.pt` files from `backend/ml_models/` at freeze time — see `ml_models/` in this directory (19 files).

## What changed since the 2026-09-12 baseline

- DGA: added 6,000 real UMUDGA malware-DGA domains (previously 100% synthetic); recall reflects the added real-domain difficulty (0.9921).
- TLS (flow-stats): added 22 real malicious flows from a 2024 Latrodectus/Lumma Stealer infection pcap (previously 100% synthetic malicious class); dataset row count dropped from 23,778 to 18,231 as part of the same rebuild (see `ML_MODELS.md` for the TLS real-malicious-data addition notes).
- tls_tier2: model file unchanged (md5-identical) since the 2026-09-12 freeze.
- ddos/c2/recon/exfil model files changed (byte-for-byte) since 2026-09-12 despite similar headline metrics — recalibration/JA4-blacklist-related retraining touched these too; treat this baseline, not the 2026-09-12 one, as the pre-multi-host reference point.

## Known caveats already documented (unchanged by this freeze)

- `tls` (flow-stats) malicious class is still mostly synthetic (22 real flows added, not yet the majority).
- `tls_tier2` malicious class is 13 real (CTU-13 botnet42/Neris) + synthetic top-up — real recall (0.52) is genuinely lower than overall reported precision, reflecting real-sample scarcity, not a bug.
- `c2` dataset is 100% self-generated (no real botnet-capture C2 traffic yet).
- `dga` malicious class is now real UMUDGA domains + 9 synthetic published-DGA-family generators (majority real by count, 6,000 of ~24,800+6,200).
