# Scenario Manifests

Each JSON file in this directory documents one behavioral scenario **family** used to
build ODIN's training datasets — a generator/config, not a single capture run. This is
what makes the "scenario diversity" claims in the dataset plan auditable: for any row
in `training/dataset_*.csv` (once the provenance retrofit lands), its `scenario_id`
resolves to a real file here, not a free-text label.

## Schema

```json
{
  "scenario_id": "c2_periodic_beacon",
  "threat_class": "c2",
  "is_malicious": true,
  "attack_subtype": "periodic_beacon",
  "source": "real",
  "label_method": "generator_ground_truth",
  "generator": "training/capture/capture_c2.py",
  "configuration": { "base_interval_sec": [3, 6], "jitter_pct": 15, "beacon_count": [10, 15] },
  "expected_behavior": { "cv": "low (~0.1-0.2)", "periodicity_score": "high" },
  "repetitions": 65,
  "applies_to_datasets": ["training/dataset_c2.csv (via dataset_c2_original.csv)"],
  "notes": "..."
}
```

| Field | Meaning |
|---|---|
| `scenario_id` | Unique key; this is the value a dataset row's `scenario_id` column should carry once the provenance retrofit lands. |
| `threat_class` | Matches ODIN's production `threat_class` values exactly: `ddos, recon, c2, dga, tls, exfil`. |
| `is_malicious` / `attack_subtype` | `attack_subtype` is `null` for benign scenarios. Subtype vocabulary matches what the detectors/correlator would recognize, not an invented taxonomy. |
| `source` | `real` (genuine traffic from a local generator/tool), `synthetic` (fabricated feature values), or `real_public_dataset` (a public malware-capture corpus, e.g. CTU-13). |
| `label_method` | `generator_ground_truth` (label = generator intent, not a fired rule), `dataset_ground_truth` (label from an external dataset's own ground truth, e.g. CTU-13's argus labels). |
| `generator` | Path to the script that produced this scenario's traffic/rows. |
| `configuration` | The actual parameters/ranges used — not a target, a record of what ran. |
| `expected_behavior` | What the resulting flows should measure as, given the configuration — the basis for an optional future check comparing this against what the built dataset actually measures. |
| `repetitions` | How many times this scenario was independently run to produce the rows currently in the dataset(s) below. `null` where the source code doesn't fix a count (e.g. exfil's real captures, which depend on how many matching real connections happened to occur). |
| `applies_to_datasets` | Which dataset file(s) this scenario's rows ended up in — deliberately explicit, since e.g. `tls_malicious_real_ctu13_botnet42_neris` feeds `dataset_tls_seq.npz` only, never `dataset_tls.csv`. |

## Current inventory (retroactive — documents what already exists, 2026-09-12)

| Threat class | Scenarios | Real | Synthetic | Real public dataset |
|---|---:|---:|---:|---:|
| ddos | 6 | 6 | 0 | 0 |
| c2 | 5 | 4 | 0 | 1 |
| recon | 2 | 2 | 0 | 0 |
| exfil | 8 | 4 | 4 | 0 |
| dga | 12 | 1 | 10 | 1 |
| tls | 6 | 2 | 2 | 2 |

**39 scenarios total.** Every new scenario going forward should get a manifest here
*before* generation, per the dataset plan's Step 5 (scale by scenario diversity, not
raw rows).

## Known gaps this inventory makes visible

- **c2**: `c2_real_ctu13_sogou48` (2026-09-12) closed the "zero real evidence" gap —
  1,904 real rows from 2 real (src,dst,port) groups, CTU-13 Scenario 48 (Sogou). A
  real ceiling, not a target: 2 of 4 candidate groups in that scenario were too sparse
  (3 events each) to produce usable rows. Scenario 52 (RBot, 3 hosts, 268k connections)
  was also pulled for diversity but contributed 0 usable rows: only 21 of 268,676
  conn.log connections matched its 12 ground-truth (src,dst,dport) destinations, and
  none formed a group with >=3 repeated real events. Tried relaxing the match from a
  strict 5-tuple (incl. ephemeral src port) to (src,dst,dport) in case argus/Zeek flow
  accounting disagreed on ports -- no change, so the limitation is genuinely that this
  particular truncated capture doesn't contain enough repeated traffic to the labeled
  destinations, not a port-matching bug. Documented rather than worked around further.
- **tls**: 2 real-malicious scenarios as of 2026-09-13. CTU-13 Neris (13 flows) was
  joined by `tls_malicious_real_latrodectus_lumma_2024` (22 flows, from
  malware-traffic-analysis.net, analyst-confirmed C2 domains) — this closed the
  "zero real-malicious coverage" gap for the flow-stats model (`dataset_tls.csv`),
  which now has 22 real malicious rows alongside its 209 real benign ones. Adding
  the same 22 rows to the *separate* tier2 seq-CNN dataset and retraining produced
  a verified calibration regression (see ML_MODELS.md's "TLS real-malicious-data
  addition" section) — that retrain was reverted, so the tier2 model itself still
  ships on the original 13-real-row basis. Checked 8 CTU-13 scenario READMEs for a
  dedicated HTTPS/TLS C2 candidate (2026-09-12) — none exists there; two other 2024
  malware-traffic-analysis.net samples (SSLoad/Cobalt Strike, DarkGate) were also
  checked and found to use plain HTTP, not TLS, for their actual C2.
- **dga**: 10 of 12 scenarios are synthetic by nature (published-algorithm generators,
  not a scarcity problem). `dga_real_umudga` (2026-09-13) closed the "no real malware
  DGA corpus used" gap with 6,000 domains from UMUDGA (MIT licensed, DOI
  10.17632/y8ph45msv8.1) — the literal output of 12 real malware families' own DGA
  code, sampled evenly across the dataset's folder listing. UMUDGA's own API exposes
  only opaque per-family folder UUIDs, not official family names, so these rows carry
  a real source folder ID and a descriptive shape hint rather than an asserted family
  name — see `scripts/download_umudga_dga.py`. The other real scenario,
  `dga_benign_real_domains`, is real *observed benign* domain traffic, a separate
  thing from real malware DGA samples.
- **benign diversity**: ddos/recon/c2 all captured benign traffic the same single way
  (plain TCP `connect()` bursts) until 2026-09-13, when `ddos_benign_http_baseline`
  added a real, shared HTTP-based benign shape. Recon and C2 deliberately did **not**
  get this addition in the same round — a container restart between the main
  recapture and the benign-HTTP capture truncated the shared `training/zeek-logs/
  conn.log` (Zeek does not append across a container stop/start, only within one
  continuous run), which broke `dataset_ddos.csv` (0 ddos rows) until ddos's capture
  was redone. Redoing recon's/c2's own multi-hour captures a second time just to add
  one benign shape was judged not worth repeating that risk, so this stays a known,
  documented gap rather than a silent one. See `docs/DATASET_STRUCTURE.md`.
