# ODIN Dataset Structure & Architecture

This document exists to keep the dataset plan honest and traceable: what data
exists, where it came from, and exactly where the real evidence runs out. It
does not replace `ML_MODELS.md` (per-model detail) — it's the map for
everything *around* the models: raw captures, scenario provenance, and how
data actually flows through the pipeline that consumes it.

---

## 1. Directory taxonomy

```text
training/
├── capture/                        # capture scripts + session-mark files
│   ├── capture_ddos.py             # real hping3 SYN flood + benign baseline
│   ├── capture_ddos_udp_spoof.py   # real hping3 UDP flood + spoofed-source
│   ├── capture_recon.py            # real nmap -sT port scans + benign baseline
│   ├── capture_c2.py               # real periodic-beacon emulator + benign
│   ├── capture_c2_extended.py      # range-extension (isolated log dir)
│   ├── capture_exfil.py            # real local HTTP + real ICMP/DNS to public hosts
│   ├── capture_tls.py / capture_quic.py   # real HTTPS/QUIC to real domains/hosts
│   ├── capture_shared_benign_http.py      # shared 2nd benign shape (ddos/recon/c2)
│   ├── sessions_*.json             # session start/end marks (ground truth)
│   └── docker-compose*.yml         # isolated Zeek capture containers
│
├── zeek-logs/                      # loopback capture (ddos/recon/c2 raw evidence)
├── zeek-logs-c2ext/                # isolated range-extension log (never shared)
├── zeek-logs-tls/                  # real-egress-interface capture (tls/quic/exfil-external)
├── malicious_pcaps_raw/            # downloaded public malware pcaps + ground-truth labels
├── zeek-logs-tls-malicious/        # Zeek output for each malicious pcap, by scenario name
├── scenarios/                      # scenario manifests -- see scenarios/README.md
│
├── build_dataset_*.py              # raw logs -> per-threat labeled CSV/NPZ
├── build_dataset_c2_real_ctu.py    # public-dataset real evidence -> dataset_c2_real_ctu.csv
├── build_malicious_pcap_logs.py    # public pcap -> Zeek logs (generic, any scenario)
├── train_*.py                      # CSV/NPZ -> calibrated model + docs/metrics/*.json
└── dataset_*.csv / dataset_*.npz   # final labeled datasets (git-tracked, not gitignored)

backend/ml_models/                  # trained + calibrated model artifacts
docs/metrics/                       # per-detector confusion matrix + precision/recall/F1
docs/baselines/<date>/              # frozen before/after comparison points
```

**Provenance columns** (`source`, `scenario_id`, `attack_subtype`, `label_method`)
exist on every row of `dataset_ddos.csv`, `dataset_recon.csv`, `dataset_c2.csv`,
`dataset_exfil.csv`, and `dataset_tls.csv` — `scenario_id` resolves to a file in
`training/scenarios/<threat_class>/`. This is what makes "N distinct scenarios"
a checkable claim rather than a documentation assertion.

---

## 2. Architecture-accurate data flow

The dataset plan's earlier draft showed Tier-1/Tier-2 confidence gating as a
pipeline-wide stage. **It isn't** — Tier-2 (the confidence-gated seq-CNN) exists
only for TLS. This is the corrected diagram:

```text
                        Passive Traffic (unidirectional tap)
                                    |
                     Zeek Flow Extraction (-C, JSON logs)
                                    |
                          Kafka (flow event stream)
                                    |
                         Per-Detector Feature Pipeline
                                    |
        +----------+----------+----------+----------+----------+
        |          |          |          |          |          |
      DDoS       Recon        C2        DGA       Exfil       TLS
    (RF, flow) (RF, flow) (RF, flow) (RF, lexical)(RF, flow) (RF, flow)
        |          |          |          |          |          |
        |          |          |          |          |     Tier-1 confidence
        |          |          |          |          |          |
        |          |          |          |          |    conf in [0.4, 0.7]?
        |          |          |          |          |      /         \
        |          |          |          |          |    no          yes
        |          |          |          |          |     |           |
        |          |          |          |          |     |    Tier-2 seq-CNN
        |          |          |          |          |     |    (raw pkt size/gap
        |          |          |          |          |     |     sequence, TLS only)
        |          |          |          |          |     |           |
        +----------+----------+----------+----------+-----+-----------+
                                    |
                    Platt Calibration (per-detector, independent)
                                    |
              Correlation Engine (KILL_CHAIN, C2_EXFIL, DGA_C2, RECON_DDOS)
                                    |
                    Unified Alert Schema (JSONL, base.py contract)
                                    |
                  STIX 2.1 bundle export  /  CEF line export
                                    |
                         Dashboard  /  SOC-facing SIEM/TIP
```

Every one of DDoS/Recon/C2/DGA/Exfil/TLS runs its **own independently-trained,
independently-calibrated** RandomForest. TLS is the only detector with a
second, deeper stage, and only for the ambiguous confidence band — this
exists because TLS is the one class where flow statistics alone are weakest
(no plaintext signal at all) and the raw packet-size/timing sequence carries
information the scalar aggregates lose.

---

## 3. Real-evidence ceilings (documented, not worked around)

Some classes have a hard, real ceiling on how much genuine evidence exists —
this section exists so nobody has to discover that mid-demo.

| Class | Real evidence | Ceiling reason |
|---|---|---|
| **TLS malicious (flow-stats)** | **0 rows** | No ethical real-world source for malware-over-TLS exists; the flow-stats model (`dataset_tls.csv`) is 100% synthetic on the malicious side. |
| **TLS malicious (Tier-2 seq-CNN)** | **13 rows** | CTU-13 Scenario 42 (Neris) — the only real malware-capture source used. Checked 8 other CTU-13 scenario READMEs (2026-09-12): none documents HTTPS/TLS as an actual C2 channel, so this ceiling isn't expected to move without a different source. |
| **C2 real botnet evidence** | **1,904 rows, 2 real (src,dst,port) groups** | CTU-13 Scenario 48 (Sogou). A second scenario (52, RBot, 268k connections) was pulled specifically to grow this and contributed 0 usable rows — only 21/268,676 connections matched ground truth, none repeated enough for timing features. Relaxing the match (dropping the ephemeral source port, in case it was an argus/Zeek accounting mismatch) made no difference — the limitation is real data scarcity in that capture, not a join bug. |
| **Exfil low-and-slow** | Synthetic only | Bulk exfil is honestly self-generatable (it's just volume/timing); a genuinely *evasive* low-and-slow pattern (deliberately blended into normal traffic timing to dodge rate-based detection) is harder to synthesize convincingly than badly. The synthetic `exfil_synthetic_*` scenarios approximate the byte/timing shape, not real evasive behavior. |

None of these ceilings are treated as targets to hit with synthetic padding —
padding a 13-row real class to 200,000 with synthetic duplication would make
evaluation *less* trustworthy, not more (see `ML_MODELS.md`'s tier2 discussion).
The honest metric is real-scenario count and what was actually tried, not a
row total.

---

## 4. Known incidents (kept, not scrubbed)

**2026-09-13, conn.log truncation during benign-diversification capture.** Zeek
appends to `conn.log` only within one continuous container run — restarting the
`zeek_ml_capture` container **truncates** it, it does not resume appending. A
benign-diversification capture (`capture_shared_benign_http.py`, meant to add a
second, real, shared benign shape for ddos/recon/c2) was run as a *separate*
container start *after* the main recapture had already torn its container down —
that fresh start wiped the evidence the fresh ddos/recon/c2 rebuild had just
produced. `dataset_recon.csv`/`dataset_c2.csv` were already safely written to disk
before this happened and were unaffected; `dataset_ddos.csv` was rebuilt against
the now-truncated log and came back with 0 ddos-labeled rows. Fixed by redoing
`capture_ddos.py` + `capture_ddos_udp_spoof.py` (~75 min) with the benign-HTTP
capture folded into that *same* continuous session this time, before any teardown.
Recon and C2 deliberately did not get the benign-HTTP addition in this pass —
redoing their own multi-hour captures a second time solely for one benign shape
wasn't judged worth repeating the risk. Lesson applied going forward: any new
capture that reuses an existing container must run inside that container's
existing continuous session, never after a fresh restart.

## 5. Where to look for more detail

- `training/scenarios/README.md` — scenario manifest schema + current inventory
- `ML_MODELS.md` — per-model training/calibration detail, known blind spots
- `docs/metrics/*.json` — current confusion matrices
- `docs/baselines/<date>/` — frozen before/after comparison points
