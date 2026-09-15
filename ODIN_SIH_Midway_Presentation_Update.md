# ODIN — Mid-Way Presentation Update
**SIH PS 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**
Status as of 2026-09-14

---

## 1. Executive Summary

ODIN is a **working prototype, not a simulation of one**. Every component
described in this document is real code that runs today: a real Zeek
instance captures real packets, a real Kafka broker moves real events, six
trained ML classifiers score real traffic, and a live React dashboard shows
exactly what the backend reports — never a hardcoded "online" or a canned
demo number.

**Where we are right now, in one line:** all six PS-mandated threat
detectors are built, trained on real captured attack traffic (not just
synthetic data), cross-validated with rigorous methodology, wired into a
live end-to-end pipeline, and we are now in the middle of a **multi-host
validation push** — moving from single-machine (loopback) validation to a
genuine multi-host Docker lab, with a physical two-laptop demo planned
before the final round.

| Area | Status |
|---|---|
| All 6 PS threat classes detected | ✅ Done — real code, real models, live pipeline |
| Real-traffic training (DDoS, Recon, C2) | ✅ Done — 113,000+ total training rows |
| Real-traffic augmentation (DGA, TLS, Exfil) | ✅ Done — majority-real or real-blended |
| Confidence calibration (all 6 models) | ✅ Done — Platt scaling, honestly reported |
| Cross-threat correlation ("kill chain" detection) | ✅ Done |
| Live dashboard (4 pages, real health checks) | ✅ Done |
| Multi-host (Docker lab) validation | 🔄 In progress — Recon phase complete, DDoS/C2/Exfil next |
| Physical two-laptop demo | ⏳ Planned — pending switch hardware arrival |

---

## 2. The Problem (PS 26145)

Critical-infrastructure operators mirror network traffic — via a hardware
**data diode** or passive tap — into an isolated monitoring enclave. That
enclave can *see* everything crossing the link but has **no protocol-level
way to send anything back** (no ACKs, no active probing, no blocking). The
problem statement requires detecting six attack classes from that
passive-only vantage point:

| # | Threat class | PS-named detection approach | Our detector |
|---|---|---|---|
| a | Volumetric / protocol DDoS (SYN, UDP, spoofed-source) | Flow-rate + source-IP entropy | `ddos.py` |
| b | Botnet C2 beaconing | Periodicity / inter-arrival timing analysis | `c2.py` |
| c | DGA domains / DNS tunnelling | Entropy / n-gram analysis of DNS names | `dga.py` |
| d | Malware in encrypted (TLS/QUIC) sessions | JA3/JA4 fingerprints, no decryption | `tls_malware.py` |
| e | Reconnaissance / port scanning | Fan-out pattern from one source | `recon.py` |
| f | Data exfiltration | Byte-ratio / flow-volume asymmetry | `exfil.py` |

**All six are implemented, trained, and live.** The constraint that shapes
every design decision in ODIN is the **one-way boundary**: nothing in this
system ever assumes it can query back into the monitored network, send a
TCP RST, or otherwise interact with what it's watching. Detection must
work from passive observation alone.

---

## 3. The Innovation — "Hybrid 1" Architecture

### The core idea

Instead of building one monolithic tool, ODIN chains **two component
families that cover each other's weak spot**:

- **Zeek** (network security monitor) — protocol-aware, turns raw packets
  into structured records (`conn.log`, `dns.log`, `ssl.log`, `quic.log`)
  — but has no native ML inference and doesn't scale horizontally as a
  compute layer.
- **Kafka + a stream processor** — scales, and handles stateful windowed
  computation (e.g. "how many ports has this source touched in the last
  60 seconds?") natively — but cannot parse a TLS handshake or a DNS
  query from raw bytes on its own.

Chaining them means **protocol parsing is solved exactly once** (by Zeek),
and **feature computation scales independently** of Zeek's own throughput
ceiling. This is "Hybrid 1" in our own design taxonomy — a prototype-scale
stand-in for what a production deployment would use (Apache Flink instead
of a Python consumer, Suricata alongside Zeek, a real time-series
database) — and the interface between the two halves (a shared `Detector`
base class with one method, `process(event) -> alert | None`) is
deliberately swap-ready, so the lightweight stand-ins can be replaced
without touching detection logic.

### What makes the detections trustworthy, not just accurate

A theme across the whole system: **a confidence number is only useful if
it's honest.** Several pieces exist specifically for this:

- **Platt-scaled probability calibration** on all six models — a raw
  RandomForest's `predict_proba()` tends to be overconfident near its
  decision boundary; calibration corrects this, and every alert carries a
  `calibrated: true/false` flag so the dashboard never claims a
  calibrated number that wasn't actually produced.
- **Range-gating** (C2 detector) — the model is only trusted inside the
  region its training data actually covered; outside it, a
  physically-interpretable fallback rule takes over. This isn't
  theoretical caution: an unrestricted model was empirically measured
  false-positiving 93% of the time just outside its trained range.
- **Real health checks, not hardcoded status** — every dashboard "online"
  indicator (Zeek, Kafka, each detector's model-load state) is derived by
  actually probing the component at request time. The one row that is
  deliberately never shown green is the data diode itself, labeled
  `"simulated"` — because software cannot verify a physical isolation
  guarantee.
- **Cross-threat correlation** — a separate engine watches the alert
  stream itself for four multi-stage attack patterns (e.g. recon → C2 →
  exfil within a 600-second window) and raises a distinct `MULTI_VECTOR`
  alert when a kill-chain completes, without suppressing the individual
  per-threat alerts underneath it.

---

## 4. How the Prototype Works — End-to-End Data Flow

```
Real network traffic (mirrored link — loopback today, multi-host in progress)
        │
        ▼
Zeek  — passive capture, writes JSON conn.log / dns.log / ssl.log / quic.log
        │
        ▼
Kafka producer  — tails all four logs, publishes onto per-log-type Kafka topics
        │
        ▼
Apache Kafka   — single-node broker, decouples capture from processing
        │
        ▼
Stream consumer  — normalizes every raw Zeek event into one stable shape,
                    hands it to every detector in turn (stand-in for Flink)
        │
        ▼
Six detectors (ddos / recon / c2 / dga / tls_malware / exfil)
  — each self-filters by event type, returns a standardized alert or nothing
        │
        ▼
Correlation engine  — watches the alert stream for cross-threat kill-chain
                       patterns, emits an additional MULTI_VECTOR alert
        │
        ▼
alerts.json  — durable append-only alert log
        │
        ▼
Flask API  — serves alerts/stats/metrics, streams new alerts over SSE
        │
        ▼
React dashboard  — polls every 2s (reliable) + SSE (fast path), 4 pages
```

Every arrow above is a real file, socket, or HTTP call that can be
independently inspected live — nothing in this chain is mocked or
pre-recorded during normal operation. (A pcap-replay path exists
specifically for **live demo reliability** — see §7 — but it injects real
log lines into the exact same live pipeline, so the same detectors score
it for real.)

### The dashboard (4 pages)

| Page | Purpose |
|---|---|
| **Overview** | Live stats, throughput, threat distribution, live alert feed, 6-detector health grid |
| **Alerts** | Full searchable/filterable alert feed |
| **Threat Analysis** | Per-threat detail: signals used, real precision/recall/FPR/FNR, confusion matrix, and a "Replay" button for a live demo |
| **Architecture** | Full system design rationale, what's implemented vs. what a full production design would add, live pipeline health, the six-threat coverage matrix |

---

## 5. The ML Models — Detailed Explanation

All six detectors were originally hand-picked fixed thresholds (e.g.
`packet_rate > 200`). **All six now run a trained classifier as the
primary decision-maker**, falling back to the original interpretable rule
only if the model file fails to load — because a demo failing outright is
worse than briefly running a slightly less accurate rule.

### 5.1 Model family used

Five of the six detectors use **RandomForestClassifier** (scikit-learn),
each wrapped in a **Platt-scaling calibration layer**
(`CalibratedClassifierCV(method="sigmoid")`) fit on a held-out calibration
split. RandomForest was chosen for this prototype because it (a) trains
fast on the row counts available, (b) gives directly interpretable
feature importances — useful both for debugging and for explaining a
detection to a human analyst — and (c) handles the mixed numeric feature
sets each detector produces without extensive preprocessing.

The **TLS/QUIC malware detector** additionally has a **second, deep-
learning tier**: a compact 1D Convolutional Neural Network (PyTorch),
described in §5.7. This is the one place in ODIN where a genuinely deep
model is used, and it is used surgically — not everywhere — for reasons
explained there.

### 5.2 DDoS Detector (`ddos.py`) — SYN Flood / UDP Flood / Spoofed-Source

- **Model:** RandomForestClassifier, calibrated.
- **Window:** trailing 10 seconds of TCP+UDP connection events (global).
- **Features:** `packet_rate`, `unique_dst_ports`, `dst_port_entropy`,
  `mean_inter_arrival`, `std_inter_arrival`, `unique_src_ips`,
  `src_ip_entropy`.
- **Training data:** 29,844 real rows from 247 real capture sessions —
  real rate-limited `hping3` SYN floods, real UDP floods against
  reflection-abused ports (53 DNS, 123 NTP), and real
  `hping3 --rand-source` spoofed-source floods (verified to produce
  genuinely varied non-local source addresses).
- **Result:** F1 = **1.000**, vs. 0.912 for the original fixed-rate rule.
- **Extra rule-based path:** a `SlowExhaustionTracker` catches
  Slowloris-style low-and-slow attacks (many long-lived, low-byte
  connections) that a 10-second rate-tuned window structurally cannot
  see — added after directly testing against a real Slowloris run and
  finding the rate path caught 0/120 held-open connections; the added
  path catches 100%.

### 5.3 Reconnaissance / Port Scan Detector (`recon.py`)

- **Model:** RandomForestClassifier, calibrated.
- **Window:** trailing 60 seconds, tracked per source IP.
- **Features:** `unique_ports`, `unique_hosts`, `connection_count`,
  `port_entropy`, `port_range_span`, `mean_inter_arrival`,
  `std_inter_arrival`.
- **Training data:** 17,674 real rows from 175 real `nmap -sT` scan
  sessions (TCP connect scan — needs no root, and Zeek logs an identical
  fan-out signature to a raw SYN scan).
- **Result:** F1 = **1.000**, vs. 0.983 for the original
  `unique_ports > 15 OR unique_hosts > 10` rule.

### 5.4 C2 Beaconing Detector (`c2.py`)

- **Model:** RandomForestClassifier, calibrated, **range-gated**.
- **State:** per `(src_ip, dst_ip, dst_port)` key, last 20 connection
  timestamps.
- **Features:** `observation_count`, `mean_interval`, `std_interval`, `cv`
  (coefficient of variation of beacon timing).
- **Training data:** 31,218 real rows from 144 real sessions generated by
  a self-built beacon emulator (matching the PS's own suggestion of "a
  sandboxed C2 emulator for realistic beaconing timing," not an external
  C2 framework).
- **Result:** F1 = **0.9994**, vs. 0.839 for the original `cv <= 0.35`
  rule — **within a deliberately validated input range**
  (`observation_count <= 20`, `mean_interval <= 45.0s`). Outside that
  range, the detector falls back to the interpretable rule.
- **Why the range gate exists — this is the single best "we did real
  engineering rigor" story in the project:** the model looked clean under
  cross-validation, but wiring it into the live detector surfaced that a
  RandomForest given an input region with **zero training
  counterexamples just predicts the only class it's ever seen there**.
  Concretely: 15 observations of clearly-irregular synthetic benign
  traffic false-positived **93% of the time** on the unrestricted model
  — nowhere near the ~18% cross-validation had reported, because
  cross-validation could only ever score the model on the region its own
  training data happened to cover. The fix was two-fold: (1) gate the
  model to only fire inside its validated range, falling back to the
  rule outside it; (2) run a follow-up capture specifically targeting the
  blind spots with real counterexamples, which closed the gap and let
  the validated range widen from `<=11 obs / <=7.0s` to `<=20 obs /
  <=45.0s`, re-verified at 0/100 false positives even slightly beyond the
  captured boundary.

### 5.5 DGA / DNS Tunnelling Detector (`dga.py`)

- **Model:** RandomForestClassifier, calibrated, plus an always-on
  rule-based DNS-tunnel path (independent of model availability).
- **Features:** Shannon entropy, query/subdomain length, numeric/consonant
  ratios, a character-trigram log-probability score, and a
  **word-boundary score** — the fraction of a domain decomposable into
  real English words, which is what separates dictionary-style DGA
  families (e.g. Suppobox) from purely random-string ones.
- **Training data:** 31,000 rows — 9 synthetic generators reproducing the
  *published algorithmic shape* of real DGA families (Conficker,
  Cryptolocker, Zeus GameOver, Necurs, Tinba, Ramnit, Banjori, Suppobox,
  Matsnu) **plus 6,000 REAL malware-DGA domains** added 2026-09-13 from
  **UMUDGA** (Zago et al. 2020, MIT licensed) — the literal output of 12
  real malware families' own DGA code, not a re-implementation.
- **Result:** held-out F1 = **0.9952**.
- **A real, consequential bug found and fixed:** running the live
  pipeline against this machine's own *ordinary background DNS traffic*
  (not an attack) flagged 498 of 500 alerts as DGA — because the
  original synthetic benign class only ever generated a bare
  `word.tld`, never the realistic `subdomain.domain.tld` shape that
  essentially all real DNS traffic uses. Fixed by adding real, well-known
  domains combined with realistic subdomain prefixes to the benign
  training class; re-verified at zero false positives on nine held-out
  real domains never seen during training.

### 5.6 Data Exfiltration Detector (`exfil.py`)

- **Model:** RandomForestClassifier, rule-gated (a rule-based pre-filter
  lowers the confidence bar required to alert when a human-checkable
  pattern also matches).
- **Training data:** 15,501 rows — **7,001 REAL** (real asymmetric HTTP
  transfers, real ICMP covert-channel pings, real UDP bursts to real
  public DNS resolvers) + 8,500 synthetic top-up for class balance.
- **Result:** F1 = **1.000**.
- **A real production bug found and fixed:** Zeek on a loopback interface
  needs the `-C` (ignore checksums) flag — without it, Linux's deferred
  loopback checksum computation made Zeek silently emit zero-byte
  connection stubs. This was live in production too: the real capture
  log had `orig_bytes: 0` on 99.9% of rows, which had been silently
  disabling this exact detector against live traffic all along.

### 5.7 TLS/QUIC Malware Detector (`tls_malware.py`) — Two-Tier Architecture

This is the most architecturally interesting detector, and the one with
the genuine deep-learning component.

**Tier 1 — always runs:**
- JA3 fingerprint blacklist lookup (97 real entries from sslbl.abuse.ch)
  + a parallel JA4 blacklist path (5 real hashes computed directly from
  real malware pcaps with FoxIO's own reference tool, since no public
  JA4 feed exists).
- A **RandomForestClassifier** on flow statistics — byte counts,
  duration, byte ratio, plus packet-size/timing-sequence summary stats
  (mean/std of the first ~12 packet sizes and inter-arrival gaps) and a
  protocol indicator — 12 features total.
- **Training data:** 18,231 rows — 209 real benign flows (real HTTPS +
  QUIC sessions) + 22 real malicious flows (from a 2024
  Latrodectus/Lumma Stealer infection pcap) + synthetic malicious top-up.
- **Result:** F1 = 0.999.

**Tier 2 — a genuine deep model, invoked selectively:**
- A **compact 1D Convolutional Neural Network** (PyTorch), architecture:
  `Conv1d(2→16, kernel=3) → Conv1d(16→32, kernel=3) → masked max-pool
  over time → Linear(32→16) → Linear(16→1) → sigmoid`.
- **Input:** the raw per-connection sequence of the first ~12 packet
  sizes and inter-packet gaps (2 channels: size, gap), masked to handle
  variable-length real sequences.
- **Why a CNN and not a recurrent net (LSTM/GRU):** 12 timesteps is too
  short for a recurrent model's sequential-dependency modeling to earn
  its keep over a CNN's local-pattern matching, and a small CNN is
  easier to keep well-regularized on a dataset that is still partly
  synthetic.
- **Why it's only invoked selectively (the confidence gate):** Tier 1
  already confidently classifies ~90% of flows correctly on its own. Tier
  2 is only consulted when Tier 1's *calibrated* probability lands in the
  ambiguous band **0.4 ≤ P ≤ 0.7** — i.e., exactly the flows Tier 1
  itself is unsure about. When Tier 2 fires, its own Platt-calibrated
  output **overrides** (not blends with) Tier 1's proba for the final
  decision, and the alert's evidence records `'seq_cnn'` as the deciding
  path instead of `'flow_stats_ml'` — so the dashboard is never dishonest
  about which model actually made a given call.
- **Calibration is load-bearing here, not cosmetic:** Tier 2's raw
  sigmoid output was found to be badly scale-mismatched against the
  thresholds Tier 1's calibrated probabilities use (a fitted Platt slope
  of ~31x on real training runs) — so the code deliberately treats "no
  calibration file available" the same as "no Tier 2 model at all,"
  rather than ever serving an uncalibrated score against calibrated
  thresholds.
- **Held-out F1 = 0.6838** (real recall 0.52) — reported honestly rather
  than hidden: the malicious class for Tier 2 is only 13 real flows (from
  CTU-13 botnet42/Neris) plus a synthetic top-up, and that real-sample
  scarcity is exactly what the lower recall reflects, not a bug.

### 5.8 Validation Methodology — how every number above was earned

- **GroupKFold cross-validation**, grouped by capture session / domain /
  query-length bucket depending on the detector — **never a random row
  split**. Adjacent feature rows from dense time-snapshotting within one
  session are heavily correlated; a random split would leak near-
  duplicate rows across train/test and produce a meaningless accuracy
  number.
- **Pooled confusion matrices** across folds, reported alongside
  precision/recall/F1/false-positive-rate/false-negative-rate for every
  model — every number in this document traces back to a
  `docs/metrics/<detector>.json` file generated the same way, not a
  hand-picked run.
- **A held-out test set, separate from the cross-validation folds**, used
  for the final reported F1 on the exact `.joblib`/`.pt` file that is
  actually deployed — not a temporarily refit model.

### 5.9 Summary Table

| Detector | Model | Training data | F1 |
|---|---|---|---:|
| DDoS | RandomForest (calibrated) | 29,844 rows, 247 real sessions | 1.000 |
| Reconnaissance | RandomForest (calibrated) | 17,674 rows, 175 real sessions | 1.000 |
| C2 Beaconing | RandomForest (calibrated, range-gated) | 31,218 rows, 144 real sessions | 0.9994 |
| DGA / DNS Tunnelling | RandomForest (calibrated) + rule | 31,000 rows (6,000 real) | 0.9952 |
| TLS/QUIC Malware — Tier 1 | RandomForest (calibrated) + JA3/JA4 | 18,231 rows (231 real) | 0.9990 |
| TLS/QUIC Malware — Tier 2 | 1D-CNN (PyTorch, Platt-calibrated) | packet size/gap sequences (13 real malicious) | 0.6838 |
| Data Exfiltration | RandomForest (rule-gated) | 15,501 rows (7,001 real) | 1.000 |

**Combined training dataset: 113,000+ rows** across all persisted CSVs
(frozen baseline, 2026-09-13, commit `96a5409`).

---

## 6. Engineering Rigor — Real Bugs Found, Not Hidden

A deliberate theme of this project is documenting every real defect found
and fixed along the way, rather than presenting a polished-but-untested
surface. A few that best demonstrate genuine engineering (not just ML
tuning):

1. **Zeek's loopback checksum bug** — silently zeroed out byte counts on
   99.9% of real production traffic, disabling the exfil detector
   entirely; found by testing against live traffic, not synthetic data.
2. **`ssl.log` byte-field gap** — Zeek's real SSL log carries no byte/
   duration fields at all (they live only in `conn.log`); the TLS
   detector's flow-stats path was silently dead code against any real
   traffic until a `uid`-based cross-log join was added.
3. **C2's range-gate blind spot** (§5.4) — a clean cross-validation score
   masked a 93% false-positive rate just outside the model's trained
   input range.
4. **A real DNS-tunnel rule direction bug** — the original rule only
   checked answer/query byte ratio in one direction; tested directly
   against a real `iodine` DNS tunnel, it missed 100% of the tunnel's
   upload traffic (which encodes payload into the *query*, not the
   answer). Fixed and re-verified at 184/184.
5. **A Docker Compose project-name collision** silently killed 70 minutes
   of an in-progress capture when an unrelated container teardown was
   run in the same directory — root-caused via `docker inspect`, fixed by
   giving every compose file an explicit project name.
6. **(Current phase) Host-vs-container traffic mislabeling** — during
   this week's multi-host Docker validation work, all captured traffic
   was silently sourced from the Docker host's own bridge-gateway address
   instead of the intended attacker container, because `--attacker-ip`
   was provenance-metadata-only and didn't change where traffic actually
   originated. Caught by the same validate-before-trust discipline used
   throughout the project, root-caused, fixed (mount the capture scripts
   into the attacker container and invoke them via `docker exec`), and
   all affected data was discarded and regenerated — not silently kept.

Every one of these findings and fixes is written up in full in
`ML_MODELS.md` (in-repo) — this section is a summary, not the whole
story.

---

## 7. Live Demo Mechanics

Two ways to generate threat traffic for a demo, both flowing through the
**exact same live pipeline**:

1. **Manual live traffic generators** — real `hping3`/`nmap`/beacon
   scripts run against the live system.
2. **Replay buttons** (one per threat class, on the Threat Analysis page)
   — Zeek re-reads a pre-recorded pcap *offline*, inside the already-
   running container, and injects the resulting log lines into the *live*
   log the real pipeline already tails. This is the reliable option for
   presenting in front of a jury (no dependency on raw-socket privileges
   or passwordless `sudo` that might not be available on demo hardware).

---

## 8. Where We Are Right Now: Multi-Host Validation Push

Every number in §5 above was validated on **loopback traffic** (a single
machine, one generator per attack class) — a real, honestly-disclosed
limitation of the prototype up to this point. We are currently executing
a structured plan (`ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md`)
to close that gap before the final round, moving from single-host to a
genuine multi-container Docker lab, and eventually to physical laptops on
a real switch.

### Completed this week

- **Baseline frozen** — every current model/metric snapshotted so the
  upcoming retraining can be compared against a known-good starting point.
- **Docker multi-host lab built** — a custom bridge network (`10.10.0.0/24`)
  with dedicated attacker / multiple victim / benign containers, Zeek
  passively observing the bridge interface itself (confirmed to never
  appear as a network hop).
- **A scenario-quality gate built** (`validate_scenario.py`) — every
  capture is now automatically checked (correct source IPs, no loopback
  contamination, complete provenance metadata, time-windowed to its own
  capture, not a stale shared log) *before* being trusted for training —
  this is what actually caught the host-vs-container bug in §6.6.
- **Reconnaissance fully re-validated on genuine multi-host traffic** —
  7 distinct scenarios (varying victim count, port ranges, scan rates,
  steady vs. bursty timing patterns), all passing the quality gate, with
  one scenario deliberately held out as an unseen test set rather than
  used for training.

### Next up

- Multi-host DDoS, C2, and (optionally) Exfiltration capture, using the
  same validated pattern.
- Full retraining and before/after evaluation — reporting confusion
  matrices and regression checks, not just a single headline number, so
  any change (better *or* worse) is visible and explained.
- A **physical two-laptop demo** over a real switch, once hardware
  arrives — the genuine "not on the same machine anymore" proof point for
  the jury.

This phase exists specifically to convert "single-host, one generator per
class" from an honest caveat into a closed gap — the same standard of
rigor applied to every other finding in this project.

---

## 9. Honest Limitations (Disclosed, Not Hidden)

Consistent with this project's approach throughout, here is what is *not*
yet true, stated plainly:

- Multi-host validation is **in progress**, not complete — only
  Reconnaissance has been re-validated on genuine multi-host traffic so
  far; DDoS/C2/Exfil retraining is next.
- TLS (flow-stats) and Exfiltration's malicious training class remain
  **majority synthetic** (no ethical source of real malware traffic).
- TLS Tier 2's real malicious sample count is small (13 real flows) —
  its lower recall (0.52) honestly reflects that scarcity.
- C2's ML model is **range-gated by design** — trusted only within its
  validated input range, falling back to an interpretable rule outside
  it.
- The measured throughput (44.8 flows/sec) reflects this Python
  prototype's own scikit-learn inference cost on a laptop CPU, not a
  claim about production-scale throughput.
- The data diode is **simulated in software** (loopback/Docker capture),
  not yet a physical device — explicitly labeled as such in the
  dashboard's own health check, never hidden behind a green status.

---

## 10. Roadmap to the SIH Final (Oct/Nov 2026)

1. Complete multi-host retraining (DDoS, C2, Exfiltration) and the
   before/after evaluation with regression checks.
2. Finalize an explicit unseen-scenario test set per threat class, kept
   isolated from training end-to-end.
3. Physical two-laptop demonstration over a real switch.
4. (Stretch) VM-based validation as an additional intermediate layer,
   time permitting.
5. (Opportunistic, non-blocking) Throughput optimization track.

---

*This document was generated from the current state of the repository
(`README.md`, `ML_MODELS.md`, `ODIN_Multi_Host_Task_List.md`,
`docs/baselines/2026-09-13/`) as of 2026-09-14. For full detail behind
any claim above, see `ML_MODELS.md` in the repository root.*
