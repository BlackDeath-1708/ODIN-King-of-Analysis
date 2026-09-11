# NTRO Unidirectional Threat Monitoring — Hybrid 1 Prototype

A passive, real-time cyberthreat detection pipeline built for **NTRO Problem
26145**: detect attacks in one-way-mirrored IP traffic — inside a monitoring
enclave that has no return path to the network it observes — using an
AI/ML pipeline, and present the results on a live, evidence-backed
dashboard.

This is a working prototype, not a simulation of one. Every piece described
below is real code that runs: a real Zeek instance captures real packets, a
real Kafka broker moves real events, six trained ML classifiers score real
traffic, and the dashboard shows what the backend actually reports — never
a hardcoded "online".

---

## 1. What problem this solves

Critical-infrastructure operators mirror their network traffic — via a
hardware data diode or passive tap — into an isolated monitoring enclave.
That enclave can *see* everything crossing the link but has no protocol-level
way to send anything back. The problem statement names six attack classes
that must be detected from that passive vantage point alone:

| # | Threat class | Named detection approach | Detector | Training data |
|---|---|---|---|---|
| a | Volumetric / protocol DDoS | Flow-level rate + source-IP entropy | `ddos.py` | Real pcaps |
| b | Botnet C2 beaconing | Periodicity / inter-arrival analysis | `c2.py` | Real pcaps |
| c | DGA domains / DNS tunnelling | Entropy / n-gram analysis of DNS names | `dga.py` | Synthetic |
| d | Malware in encrypted sessions | JA3/JA4 TLS fingerprints, no decryption | `tls_malware.py` | Synthetic |
| e | Reconnaissance / port scanning | Fan-out patterns from one source | `recon.py` | Real pcaps |
| f | Data exfiltration | Byte-ratio / flow-volume asymmetry | `exfil.py` | Synthetic |

**All six threat classes named in the problem statement have a real detector
implemented, trained, and wired into the live pipeline.** The distinction
that actually matters at this point isn't "built vs. not built" — it's
training-data provenance: DDoS/C2/recon are trained and cross-validated in
this repo (`training/`) against real captured traffic (16,000+ rows each,
generated with PS-named tooling — real rate-limited `hping3` SYN floods,
real `nmap` scans, a self-built C2 beacon emulator — see `ML_MODELS.md`'s
"Real-traffic retraining"); DGA/TLS/exfil are trained on synthetic data
generated in this repo, because no equivalent real-capture validation set
exists yet for those three classes. Nothing here claims coverage or
validation it doesn't have — see `ML_MODELS.md` for the full, honest
per-model numbers, and the Architecture page's Threat Coverage matrix for
the same breakdown live in the dashboard.

---

## 2. Why "Hybrid 1" — the architecture in one paragraph

The design combines two component families that each cover the other's
weak spot. A network security monitor (**Zeek**) is protocol-aware and
turns raw packets into structured records (`conn.log`, `dns.log`,
`ssl.log`) — but has no native ML inference and doesn't scale horizontally.
A streaming pipeline (**Kafka** + a stream processor) scales and handles
stateful windowed computation natively — but can't parse a TLS handshake
or a DNS query from raw bytes on its own. Chaining them — Zeek's structured
output becomes the streaming layer's input — means protocol parsing is
solved exactly once, and feature computation scales independently of
Zeek's own throughput ceiling. The full reasoning (and what the complete,
non-prototype-scale version of this design would look like — Apache Flink,
a time-series database, Suricata, JA3/JA4) is laid out on the dashboard's
own **Architecture** page, which distinguishes "implemented" from
"designed" at every stage, not just for the detectors.

---

## 3. End-to-end data flow

```
Real network traffic (loopback, standing in for a mirrored production link)
        │
        ▼
Zeek  (docker-compose.yml: zeek/zeek:latest, network_mode: host, -i lo)
  writes JSON-lines conn.log / dns.log / ssl.log to backend/zeek-logs/
        │
        ▼
kafka_producer.py   — tails all three logs, publishes each raw event
                       verbatim onto its own topic: zeek-conn / zeek-dns /
                       zeek-ssl
        │
        ▼
Apache Kafka   (docker-compose.yml: apache/kafka:latest, single-node KRaft)
        │
        ▼
stream_consumer.py  — the prototype's stand-in for Apache Flink: a single
                       Python process consuming all three topics,
                       normalizing each raw Zeek field into a stable event
                       shape tagged with log_type (normalize_event()), then
                       handing it to every detector in turn
        │
        ▼
detectors/{ddos,recon,c2,dga,tls_malware,exfil}.py
  — each self-filters by log_type and returns a standardized alert dict,
    or None, per event
        │
        ▼
correlation/correlator.py  — watches the alert stream itself for four
                              cross-threat patterns (e.g. recon+c2+exfil
                              within 600s of event time); a match emits a
                              second, separate MULTI_VECTOR alert alongside
                              — never instead of — the individual alerts
        │
        ▼
alerts.json   — one JSON object per line, appended by stream_consumer.py
        │
        ▼
app.py (Flask)  — reads alerts.json for /api/alerts and /api/stats,
                   streams new lines over SSE at /api/stream
        │
        ▼
React dashboard  — polls the API every 2s (primary, reliable path) and
                    also listens on the SSE stream (fast path, deduped by
                    flow_id) — see §8 for why both exist
```

Every arrow above is a real file, socket, or HTTP call you can inspect
independently — `docker exec zeek_monitor tail -f
/usr/local/zeek/logs/current/conn.log`, `curl localhost:5000/api/alerts`,
etc.

---

## 4. The six detectors

All six follow the same shape: a shared `Detector` base class
(`backend/detectors/base.py`) with one method, `process(event) -> alert |
None`. This interface is deliberate — it's what would let the processing
layer underneath (currently a plain Kafka consumer) be swapped for a real
Apache Flink job later without changing a single line of detection logic.

| Detector | Method | Model file | F1 | Calibrated? |
|---|---|---|---|---|
| DDoS (SYN/UDP/spoofed) | RandomForest on flow-rate + port/src-IP entropy | `ddos_model_calibrated.joblib` | 1.000 | Yes |
| Reconnaissance | RandomForest on fan-out (unique ports/hosts) features | `recon_model_v3_calibrated.joblib` | 1.000 | Yes |
| C2 Beaconing | RandomForest on inter-arrival timing, range-gated | `c2_model_calibrated.joblib` | 0.9994 | Yes |
| DGA / DNS Tunnelling | RandomForest (entropy/n-gram/word-boundary) + rule-based tunnel path | `dga_model_calibrated.joblib` | 0.99† | Yes |
| TLS Malware (JA3) | JA3 blacklist lookup + RandomForest on flow stats | `tls_flow_model_calibrated.joblib` | 1.00‡ | Yes |
| Data Exfiltration | Rule-based pattern pre-filter + RandomForest on flow-volume | `exfil_model_calibrated.joblib` | 1.00‡ | Yes |

† DGA is synthetic but now reproduces 9 published DGA algorithm families'
real characteristic shapes (Conficker, Cryptolocker, Suppobox, etc.) rather
than one generic generator — see `ML_MODELS.md`.
‡ TLS/exfil now train on majority-REAL captured traffic (real HTTPS
requests, real asymmetric transfers/ICMP/DNS) mixed with a synthetic
top-up for the class with no ethical real-malware source — see
`ML_MODELS.md`'s "Phase 2 detectors" section for the exact real/synthetic
split per model.

Each detector was originally a hand-picked fixed threshold. **All six now
load a trained RandomForest classifier and use it as the primary
decision-maker**, falling back to the original rule if the model file is
missing or fails to load — a demo failing outright is worse than briefly
running the less-accurate rule. Three (DDoS, recon, exfil-adjacent DNS
exfil rule) additionally have rule-based paths documented per-detector
below.

### DDoS: SYN Flood / UDP Flood / Spoofed-Source (`backend/detectors/ddos.py`)
- **Window:** trailing 10 seconds of TCP+UDP connection events (global, not
  per-source).
- **Features fed to the model:** `packet_rate`, `unique_dst_ports`,
  `dst_port_entropy`, `mean_inter_arrival`, `std_inter_arrival`,
  `unique_src_ips`, `src_ip_entropy` (the last two added 2026-09-12 — see
  below).
- **Validated result:** F1 1.000 vs. 0.912 for the old `packet_rate > 200`
  rule, on 29,844 real rows from 247 real capture sessions covering all
  three of PS 26145 (a)'s named DDoS patterns: real `hping3` SYN floods,
  real UDP floods (targeting reflection/amplification-style ports 53/123),
  and real `hping3 --rand-source` spoofed-source floods (verified to
  produce genuinely varied, non-local source addresses that Zeek captures
  correctly even on loopback) — see `ML_MODELS.md`'s "UDP/spoofed-source
  DDoS extension". This also promotes `unique_src_ips`/`src_ip_entropy`
  from evidence-only to real trained features, closing the "single test
  host made source-IP entropy zero-variance" limitation.
- **Fallback rule** (used only if the model can't load) is now an adaptive
  entropy baseline, not a flat rate cutoff — see §5.
- **Slow-exhaustion path (added 2026-09-13, rule-based, separate from the
  ML path above):** `SlowExhaustionTracker` flags many long-duration,
  low-byte connections held open to one destination over a 5-minute
  window — catches Slowloris-style low-and-slow attacks the 10-second
  rate-tuned window structurally cannot see. Added after validating
  directly against a real Slowloris run: 0/120 real held-open connections
  detected via the rate path under a realistic independently-staggered
  close timeline; 100% detected once this path was added. See
  `ML_MODELS.md`.

### Reconnaissance / Port Scan (`backend/detectors/recon.py`)
- **Window:** trailing 60 seconds, tracked per source IP.
- **Features fed to the model:** `unique_ports`, `unique_hosts`,
  `connection_count`, `port_entropy`, `port_range_span`,
  `mean_inter_arrival`, `std_inter_arrival`.
- **Validated result:** F1 1.000 vs. 0.983 for the old
  `unique_ports > 15 OR unique_hosts > 10` rule, on 17,674 real rows from
  175 real nmap-scan capture sessions.

### C2 Beaconing (`backend/detectors/c2.py`)
- **State:** per `(src_ip, dst_ip, dst_port)` key, last 20 connection
  timestamps.
- **Features fed to the model:** `observation_count`, `mean_interval`,
  `std_interval`, `cv` (coefficient of variation).
- **Validated result:** F1 0.9994 (held-out, current model) vs. 0.839 for
  the old `cv <= 0.35` rule, on 31,218 real rows from 144 real
  beacon-emulator capture sessions (114 original + 30 from a 2026-09-11
  range-extension capture — see below) — **within a deliberately gated
  input range** (`observation_count <= 20` and `mean_interval <= 45.0s`,
  widened from the original `<= 11`/`<= 7.0s` — see `ML_MODELS.md`'s "C2's
  range gate" section for the full extension story). Outside that range
  the detector falls back to the rule. This gate isn't cosmetic: the
  unrestricted model was found to false-positive 93% of the time on
  traffic outside its training data's coverage (verified empirically, not
  assumed) before the gate was added, and re-verified against the
  retrained model. Full story in `ML_MODELS.md`.

### DGA / DNS Tunnelling (`backend/detectors/dga.py`)
- **Two independent paths:** a rule-based DNS-tunnel detector (long
  TXT/NULL queries with a high byte ratio in either direction — see
  below) that runs regardless of model availability, and an ML path for
  DGA domain classification.
- **Bidirectional tunnel rule (fixed 2026-09-13):** the original rule only
  checked answer/query byte ratio (a C2 pushing a large encoded command
  down, small query). Validated directly against a real `iodine` DNS
  tunnel, this missed 100% of its upload traffic — iodine encodes payload
  into the long query name itself, with a small answer, the mirror-image
  ratio. Fixed by checking both directions; re-verified at 184/184 (100%)
  detection against a fresh real capture. See `ML_MODELS.md`.
- **Features fed to the model:** Shannon entropy, query/subdomain length,
  numeric/consonant ratios, a character-trigram log-probability score, and
  a **word-boundary score** — the fraction of a domain decomposable into
  known English words, which separates dictionary-style DGA families
  (e.g. Suppobox) from purely random ones. See §5.
- **Trained on synthetic data reproducing 9 published DGA algorithm
  families** (Conficker, Cryptolocker, Zeus GameOver, Necurs, Tinba,
  Ramnit, Banjori, Suppobox, Matsnu) — 19,000 rows, F1 0.99. See
  `ML_MODELS.md` for why this is a meaningfully closer match to PS 26145's
  "DGA samples from published algorithms" methodology than a single
  generic random-string generator.

### TLS/QUIC Malware (`backend/detectors/tls_malware.py`)
- **Path A:** JA3 fingerprint lookup against an offline blacklist (97 real
  entries downloaded from sslbl.abuse.ch — the download itself is a one-off
  script, never called at runtime, keeping the one-way constraint intact).
- **Path A2 (added 2026-09-12):** JA4 blacklist lookup, same shape as Path
  A. Ships empty — no public JA4 threat-intel feed exists yet (checked
  directly against sslbl.abuse.ch); the path is wired up and ready for the
  moment one does. PS 26145 (d)'s "JA3/JA3S or JA4" wording is satisfied by
  the real, working JA3 path regardless.
- **Path B:** RandomForest on flow statistics (byte counts, duration, byte
  ratio, and — added 2026-09-13 — packet-size/timing-sequence summary
  stats plus a protocol indicator, 12 features total) for malware
  families not in the blacklist. **Trained on 23,777 rows: 5,777 REAL
  benign flows (5,405 real HTTPS + 372 real QUIC sessions, 157 distinct
  real domains) + 18,000 synthetic malicious flows**, pooled GroupKFold F1
  0.9998.
- **Packet-size and timing sequences (PS 26145 (d), added 2026-09-13):**
  `zeek/scripts/pkt_seq.zeek` logs the first ~12 packet sizes and
  inter-arrival gaps per SSL/QUIC connection; summarized as mean/std
  features. Feature importances confirm real signal: `pkt_count` and
  `pkt_gap_std` rank 2nd/3rd, ahead of every byte-volume feature except
  `resp_bytes`. Concretely, a synthetic flow with byte_ratio ≈ 1.1 (looks
  benign by volume alone) is now flagged HIGH/0.99 purely from its
  regular packet-timing cadence.
- **QUIC coverage (added 2026-09-12, independently trained 2026-09-13):**
  this detector processes `log_type == "quic"` events — real SNI
  extraction (metadata only, no decryption). Originally reused the
  TLS-only model with an honest "not independently validated" caveat;
  `training/capture/capture_quic.py` now generates real aioquic
  handshakes against ~25 real HTTP/3 hosts (Google, Cloudflare, Discord,
  etc.), giving the retrained model 372 real QUIC training rows and 0
  false positives across 80 held-out real QUIC rows tested directly.
- The JA3/JA4 paths are dormant until `zkg install zeek/salesforce/ja3` /
  `zeek-ja4` are run on a real Zeek deployment — documented, not silently
  broken. QUIC needs no such package (Zeek 8.2.2 has it natively).
- **A real bug was found and fixed here this session**: real Zeek `ssl.log`
  has no byte/duration fields at all (those live only in `conn.log`) — Path
  B's model was silently receiving all-zero feature vectors for every real
  TLS event, and its own guard rejected them before the model even ran.
  Fixed with a `uid`-based join in `backend/stream_consumer.py`
  (`SSLByteEnricher`) — see `ML_MODELS.md`.

### Data Exfiltration (`backend/detectors/exfil.py`)
- **Rule-based pre-filter** labels a human-checkable pattern (ICMP covert
  channel, DNS exfil, high-volume upload, sustained upload) when one
  matches; the ML confidence threshold required to alert is lower when a
  rule also matches (0.60) than when only the model fires (0.80) — raising
  the bar when there's no human-checkable pattern backing the ML call.
- No fixed-threshold fallback if the model can't load — pure byte-ratio
  rules alone were too noisy to run standalone, a deliberate scope choice.
- **Trained on 15,501 rows: 7,001 REAL (real asymmetric local HTTP
  transfers, real ICMP pings, real UDP bursts to real public DNS
  resolvers) + 8,500 synthetic top-up for class balance**, F1 1.000.
- **A second real bug was found and fixed here this session**: Zeek on a
  loopback interface needs the `-C` (ignore checksums) flag — Linux defers
  checksum computation for loopback traffic, and without it Zeek silently
  produced zero-byte connection stubs. This was live in production too:
  the actual `zeek_monitor` container's real capture log had `orig_bytes:0`
  on 99.9% of rows, meaning this detector's `orig_bytes < 1000` guard
  effectively disabled it against real live traffic (masked because pcap
  replay reads pre-recorded files with valid checksums, never hitting this
  path). Fixed in `docker-compose.yml` and verified against fresh live
  traffic post-fix — see `ML_MODELS.md`.

**Every detector's evidence explains which path fired** — every alert's
`evidence` says either `"ML classifier (RandomForest) flagged..."` with a
real confidence percentage, or `"...fixed-threshold rule"` — so nothing in
the dashboard implies a model decision that didn't actually happen.

The three real-traffic models are trained and cross-validated in this repo
(`training/`) directly (GroupKFold by capture session, pooled confusion
matrices, honest reporting of every false-positive trade-off) against real
captured traffic generated with PS-named tooling. See **`ML_MODELS.md`**
for the full per-model numbers, feature importances, and every bug found
and fixed along the way — including two real, verified failure modes in
the C2 model that a clean cross-validation score alone didn't catch, a
real Kafka-port-collision contamination bug found and fixed during the
2026-09-10 retraining, and the honest caveats on the three synthetic-data
models.

---

## 5. Innovations implemented

Beyond "six RandomForest classifiers wired to a Kafka pipeline," a few
pieces exist specifically to make the confidence scores and detections more
trustworthy than raw model output:

- **Platt-scaled confidence calibration.** `calibration/calibrate_models.py`
  fits `CalibratedClassifierCV(method="sigmoid")` on top of each base model
  using a held-out calibration split. All six models are now calibrated —
  DDoS/recon/C2's training moved in-repo (see §1/§4, `ML_MODELS.md`) and
  now persists a real-traffic calibration split the same way DGA/TLS/exfil
  already did. Each detector's `_load_model()` prefers the calibrated file
  when present, and every alert carries a `calibrated: bool` field so the
  dashboard's "(calibrated)" label is never asserted for a raw,
  uncalibrated number.
- **Adaptive entropy baseline for DDoS's fallback rule.** The ML path
  (used whenever the model loads — the normal case, F1 1.000) is
  completely untouched by this. Only the fallback rule — used solely if
  the model fails to load — changed, from a flat `packet_rate > 200`
  cutoff to a rolling 600-second baseline of port-entropy values, flagging
  a new value only when it deviates >2 standard deviations from that
  baseline. Verified directly: resists a synthetic flash-crowd (same
  entropy distribution as the established baseline, just higher volume)
  while still firing correctly on a genuine entropy-shift attack.
- **Word-boundary dictionary-DGA scoring.** Character-entropy alone
  misses dictionary-based DGA families (e.g. Suppobox), which concatenate
  real English words into domains that read as low-entropy. `dga.py`'s
  `word_boundary_score()` greedily decomposes a domain's leftmost label
  against a 73,445-word English wordlist; a high score routes the alert's
  `detection_path` evidence to `DICT_DGA` instead of `RANDOM_DGA`.
- **Cross-threat correlation / kill-chain detection.**
  `correlation/correlator.py` watches the alert stream for four
  multi-stage patterns (KILL_CHAIN, C2_EXFIL, DGA_C2, RECON_DDOS) and
  emits a `MULTI_VECTOR` alert when one completes, without suppressing the
  individual alerts. Windows key off each alert's underlying event
  timestamp, not wall-clock ingest time — this project's own PCAP-replay
  demo mechanism reprocesses a pcap offline and drains it through Kafka
  near-instantly, so wall-clock time would make every pattern's window
  trivially "look" satisfied regardless of how far apart the events
  actually were. Dedup tracks which specific alerts (by `flow_id`)
  contributed to a pattern's last firing, so a second, genuinely
  independent attack chain from the same source isn't silently suppressed
  by a naive time-based cooldown — an issue found and fixed during review.
- **C2 range-gating** — not a new feature so much as the detector's core
  honesty story: the model is trusted only within the input range its
  training data actually covers (`observation_count <= 20`,
  `mean_interval <= 45.0s`, widened 2026-09-11 from the original
  `<= 11`/`<= 7.0s`); outside it, the original CV-threshold rule takes
  over, because a RandomForest predicting in a region with zero training
  counterexamples isn't actually validated there. Full story, including
  the 93% false-positive rate measured before the gate existed and the
  re-verification after widening it, in `ML_MODELS.md`.

---

## 6. The alert schema

Every detector emits the same shape (`Detector.alert()` in `base.py`):

```json
{
  "timestamp": "2026-09-07T08:21:03.952Z",
  "event_ts": 1757232063.11,
  "flow_id": "CfzyiZ11rLp4oPVmFa",
  "src_ip": "203.0.113.7", "src_port": null,
  "dst_ip": "10.0.0.1", "dst_port": 8080,
  "threat_class": "ddos",
  "threat_label": "DDoS / SYN Flood",
  "severity": "CRITICAL",
  "confidence": 0.68,
  "calibrated": false,
  "evidence": ["ML classifier (RandomForest) flagged this window as a flood (model confidence: 68%)", "..."],
  "detector": "ddos",
  "window_seconds": 10
}
```

`timestamp` is wall-clock (when the alert was emitted, for display/sort
order); `event_ts` is the underlying event's own clock (e.g. Zeek's
pcap-relative time) — required so the correlation engine can window
correctly under fast PCAP replay, where wall-clock time desyncs from it.
`evidence` is always a flat array of ready-to-read sentences for the six
per-flow detectors — never a structured object requiring the frontend to
guess at field meanings. The one exception is the correlator's synthetic
`MULTI_VECTOR` alert, whose `evidence` is a small object
(`{pattern, contributing_alerts, correlation_window_seconds}`) describing
which alerts triggered it — `AlertFeed.jsx` renders both shapes without
guessing at values it wasn't given.

---

## 7. Backend API (`backend/app.py`, Flask)

| Route | Method | Purpose |
|---|---|---|
| `/api/alerts?limit=N` | GET | Last N alerts (default 100) |
| `/api/stats` | GET | Counts per threat class (all 6, plus MULTI_VECTOR) over the last 500 alerts |
| `/api/pipeline-status` | GET | Real per-component health — see §8 |
| `/api/throughput` | GET | Live events/sec through the pipeline |
| `/api/detector_status` | GET | Per-detector model load status (ok/model_missing/error), which model file (calibrated vs. base) loaded, and its F1 |
| `/api/model_metrics` | GET | Per-detector precision/recall/F1/false-positive-rate/false-negative-rate/confusion matrix (from each detector's own held-out test set) plus inference latency and pipeline throughput — see §11.5 |
| `/api/replay/<threat>` | POST | Replays a pre-recorded pcap for one threat class — see §9 |
| `/api/clear` | POST | Wipes `alerts.json` (demo reset) |
| `/api/stream` | GET | Server-Sent Events — pushes new alerts as they're appended |

The dev server runs with `threaded=True` — without it, an open SSE
connection blocks every other request on the single-threaded Flask dev
server, which was a real, previously-diagnosed source of "Zeek Offline"
flakiness in the dashboard.

---

## 8. Reliability: real health checks, not hardcoded status

`/api/pipeline-status` never reports a row as "ONLINE" by assumption:

- **Zeek** — is `zeek-logs/conn.log`'s mtime younger than 15 seconds?
- **Kafka** — can the API open a TCP socket to `localhost:9092` right now?
- **Kafka producer / stream detector** — are their heartbeat files
  (`.producer_heartbeat`, `.heartbeat`) fresh?
- **Alert engine** — same process as the stream detector in this
  prototype, so same signal (documented as such, not hidden).
- **Diode** — explicitly labeled `"simulated"` with a note that physical
  isolation is a deployment concern this software cannot verify — the one
  row that is deliberately never shown as a green health check.
- **Per-detector model status** — `/api/detector_status` similarly never
  hardcodes "OK"; it tries to actually `joblib.load()` each detector's
  model file and reports what happened.

The dashboard's live-update path is **polling-first, SSE-second**: every
2 seconds the frontend re-fetches alerts/stats/throughput from the API
regardless of SSE state, and only trusts SSE to push updates *faster* in
between polls (deduped by `flow_id`). This was a deliberate fix for
browser-side `EventSource` flakiness discovered mid-project — polling
never silently stops working, so the dashboard can't get stuck "connected"
while actually stale.

---

## 9. Running the demo

### Prerequisites
Docker + Docker Compose, Python 3, Node.js/npm.

### One-time setup
```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd ../frontend && npm install
```

### Start everything
```bash
./start_demo.sh
```
This is not a thin wrapper — it's a real health-check sequence: it refuses
to run as root (a recurring source of file-permission bugs during
development), waits for the Kafka broker to actually accept connections
(not just for the container to report "up"), creates the `zeek-conn`
topic, confirms Zeek is running, then starts the Kafka producer, the
stream consumer, the Flask API, and the dashboard in order — verifying
each one is actually alive before starting the next.

- Dashboard: `http://localhost:5173`
- API: `http://localhost:5000`

### Generating threat traffic
Two ways, both flow through the exact same live pipeline:

1. **Manual traffic scripts** (`traffic/generate_ddos.sh`,
   `traffic/generate_recon.sh`, `traffic/generate_c2.py`) — real traffic
   generators against loopback. `generate_ddos.sh` is deliberately
   rate-limited (`hping3` capped at ~500pps via `nice`/`timeout`) after an
   earlier unbounded `--flood` run hung the machine entirely — see the
   script's own comments.
2. **Replay buttons** (Threat Analysis page, one per threat class) — the
   more reliable option for a live demo. Pressing one has Zeek re-read a
   pre-recorded pcap (`traffic_pcaps/*.pcap`) **offline**, inside the
   already-running container, and injects the resulting log lines into the
   *live* `conn.log` the real pipeline already tails. Deliberately does
   **not** use `tcpreplay` — that needs raw-socket privileges and
   passwordless `sudo`, which can't be relied on to work unattended in
   front of a jury. Full reasoning in `ML_MODELS.md`.

---

## 10. Frontend (`frontend/`, React + Vite)

| Page | Shows |
|---|---|
| **Overview** | Headline stats, throughput sparkline, threat distribution (all 6 classes), live alert feed, live 6-detector status grid, compact pipeline diagram |
| **Alerts** | Full alert feed with search + threat/severity filters |
| **Threat Analysis** | Per-threat-class detail, detection signals used, and the replay button |
| **Architecture** | Full system design: the Hybrid-1 rationale, detailed pipeline diagram (implemented vs. full-design per stage), live pipeline status, the six-threat coverage matrix, and the one-way security boundary |

The 6-detector status grid (`ActiveDetectors.jsx`) polls
`/api/detector_status` once on mount and shows a green/orange/red dot per
detector — never a static "3 active" claim. The throughput sparkline
(`ThroughputSparkline.jsx`) is a small hand-rolled inline-SVG trend line
(no external charting library — this project didn't have one and one
axis-less 60px sparkline didn't justify adding one), sampling
`/api/throughput` on its own fixed interval so a flat/idle reading still
renders as a flat line rather than an empty chart.

The dev proxy (`vite.config.js`) forwards `/api/*` to the Flask backend
unchanged, so the same relative `fetch()`/`EventSource` calls work whether
the dashboard is opened on `localhost` or from another device on the LAN.

---

## 11. Throughput benchmark

`scripts/benchmark_throughput.py` measures the detection pipeline's own
processing throughput — **not** a full Kafka-broker round-trip. No live
Kafka broker was running in the environment this was measured in (port
9092 unreachable, no container up), so rather than fake or skip the
number, this measures the same `for event: for detector: detector.process
(event)` loop `stream_consumer.py` runs, fed a synthetic 10,000-event
stream, with no broker in between.

**Measured result (12th Gen Intel Core i7-1255U, 12 logical cores):
44.8 sustained flows/sec** (10,000 synthetic events, 223.3s, 1,481 alerts
produced). That number is deliberately unglamorous, and the reason why is
the actual finding, not a caveat to bury: sustained throughput here is
dominated by scikit-learn's per-call inference overhead, not by this
codebase's own Python logic. Isolated measurement: a single RandomForest
`predict()` + `predict_proba()` pair costs ~12ms/call in this environment
(scikit-learn 1.9.0), and `ddos.py`/`recon.py`/`c2.py` each make that pair
of calls per qualifying conn event.

| Detector | Attack sequence | Median latency, verified to actually fire |
|---|---|---|
| DDoS | 200-event flood, single target port | 40.8ms |
| Recon | 60-event scan, 60 unique ports on one host | 81.6ms |
| C2 | 6-observation beacon | 13.7ms |
| DGA | 1 query | 7.5ms |
| TLS | 1 session | 4.1ms |
| Exfil | 1 flow | 4.0ms |

"Verified to actually fire" isn't boilerplate here: an earlier version of
this benchmark used synthetic DDoS/recon sequences that never crossed
either model's real decision boundary (DDoS cycled the destination port,
which reads as scan-like port diversity, not a flood; recon fixed the
destination port, which reads as ordinary single-service traffic, not
port-scanning) — caught by code review, confirmed by loading the actual
`.joblib` models and testing the exact feature vectors those sequences
produced. The script now asserts every detector's sequence fires in every
sample and raises loudly if one doesn't, specifically so this can't
silently regress again. DDoS/recon still cost more than DGA/TLS/exfil
because their windowed features mean multiple model calls accumulate
before the window's feature vector crosses the boundary, not because the
model call itself is slower for them. See `docs/benchmark_results.json`
for the full output and the script's own module docstring for exactly what
was and wasn't measured (e.g. why the sustained-throughput pass's
timestamp spacing isn't flood-dense).

Run it yourself: `python scripts/benchmark_throughput.py`

---

## 11.5. Per-detector evaluation metrics (precision / recall / FPR / FNR / confusion matrix)

F1 alone doesn't answer "how many false positives do you generate" — a
judge's question should get an immediate, sourced number rather than a dig
through this file's prose. Every `training/train_*.py` script now evaluates
its final, deployed model (the exact `.joblib` file loaded at runtime, not
a temporarily-refit model from cross-validation) on a genuinely held-out
test set and writes `docs/metrics/<detector>.json` via the shared
`training/metrics_utils.py` helper: confusion matrix (TP/FP/TN/FN),
precision, recall, F1, false-positive-rate, false-negative-rate, and
accuracy, all derived from the same by-hand confusion-matrix arithmetic so
every rate's definition is visible in one place rather than relying on
`sklearn.classification_report`'s output (which doesn't expose FPR/FNR at
all).

`GET /api/model_metrics` merges these six files with
`docs/benchmark_results.json`'s per-detector inference latency and reports
both at request time — no separate aggregation step to go stale relative
to either source. The Threat Analysis page's per-threat detail panel reads
this endpoint directly (`DetectorMetrics.jsx`), so selecting a threat class
shows its real precision/recall/F1/FPR/FNR, confusion matrix, and latency
alongside the detector's other detail, not just a single F1 number.

Regenerating these numbers after any retrain: re-run the relevant
`training/train_*.py` script (it overwrites both the `.joblib` model and
its `docs/metrics/<name>.json`), then re-run
`calibration/calibrate_models.py` so the calibrated model file stays
consistent with the freshly retrained base model.

---

## 12. Repository layout

```
backend/
  app.py                  Flask API (§7)
  kafka_producer.py       Zeek conn/dns/ssl.log → Kafka (3 topics)
  stream_consumer.py      Kafka → detectors → correlator → alerts.json, plus throughput tracking
  detectors/
    base.py               shared Detector interface + alert schema builder
    features.py            shared entropy/timing-stats math (ddos.py + recon.py)
    ddos.py / recon.py / c2.py / dga.py / tls_malware.py / exfil.py   the six detectors (§4)
  correlation/
    correlator.py          cross-threat correlation engine (§5)
  ml_models/               trained .joblib classifiers (base + calibrated where available)
  data/                    trigram model, English wordlist, JA3 blacklist -- offline data the detectors load
calibration/
  calibrate_models.py      Platt-scaling calibration (§5)
training/                  training scripts for all six models; metrics_utils.py exports each
                           final model's held-out precision/recall/F1/FPR/FNR (§11.5);
                           training/capture/ holds the real-traffic capture tooling for
                           ddos/recon/c2 (hping3/nmap/beacon emulator + isolated Zeek container)
scripts/                   one-off tooling: trigram builder, JA3 blacklist downloader, throughput benchmark (§11)
docs/
  calibration_plots/        reliability diagrams per calibrated model
  benchmark_results.json    output of scripts/benchmark_throughput.py
  metrics/                  per-detector precision/recall/F1/FPR/FNR/confusion matrix (§11.5),
                           one <detector>.json per training/train_*.py run
zeek/local.zeek            Zeek config (JSON logging, conn/dns/ssl analyzers)
traffic/                   live traffic generators for a manual demo
traffic_pcaps/             pre-recorded pcaps for the Replay buttons + generator script
frontend/                  React dashboard (§10)
docker-compose.yml         Kafka + Zeek containers
start_demo.sh               orchestration script (§9)
ML_MODELS.md               full ML integration writeup: features, validation, bugs found & fixed
```

DDoS/Recon/C2 were originally trained in a sibling exploration repo
(`recon-ml-poc/`, not part of this project), kept separate so early
exploratory ML work never risked destabilizing the working prototype while
still unvalidated. As of 2026-09-10 that work has been superseded by a
larger real-traffic retraining run entirely inside `training/` — see
`ML_MODELS.md`.

---

## 13. Honest limitations

- **Only DGA remains fully synthetic.** TLS malware and data exfiltration
  now train on majority-real captured traffic (see §4); DGA has no ethical
  real-malware-DGA source, but its generators now reproduce 9 published DGA
  algorithm families' real characteristic shapes rather than one generic
  generator. Malicious-class data for TLS/exfil is still synthetic (no
  ethical real-malware-traffic source exists for either) — see
  `ML_MODELS.md`.
- **All 6 models are now Platt-calibrated**, but 5 of 6 (all but
  Exfiltration) had a calibration shift exceeding this project's own 0.15
  sanity bound — documented rather than hidden; read as those base models
  being meaningfully overconfident near their decision boundary, corrected
  in the honest direction. See `ML_MODELS.md` for the likely cause
  (RandomForests trained on cleanly-separable data tend to output extreme
  probabilities) and why more rows from the same generators wouldn't fix it
  on their own.
- **Two real production bugs were found and fixed during this session's PS
  26145 compliance audit** (2026-09-11): (1) real Zeek `ssl.log` has no
  byte/duration fields, silently killing TLS malware's flow-stats ML path
  against any real traffic; (2) Zeek on a loopback interface needs `-C`
  (ignore checksums) or it silently produces zero-byte connection stubs —
  verified live in production (`zeek_monitor`'s own capture had
  `orig_bytes:0` on 99.9% of real rows), which had been silently disabling
  the exfiltration detector against real traffic all along. Both fixed at
  the source; see `ML_MODELS.md`'s "Two production bugs found and fixed"
  section for the full detail and verification.
- **Four more real bugs found by testing against real tools (2026-09-13),
  not synthetic proxies:** two in the new packet-sequence Zeek script
  (QUIC's `c$quic` field deleted before it could be checked; QUIC's
  embedded TLS handshake mislabeling every real QUIC connection as "ssl"),
  one in the DNS-tunnel rule (checked only one byte-ratio direction, so a
  real `iodine` tunnel's upload traffic scored 0/138 detected before the
  fix, 184/184 after), and one real detection *gap* rather than a bug: the
  DDoS detector's rate-tuned window structurally could not see a real
  Slowloris run's realistic (independently-staggered) traffic pattern at
  all — 0/120 — until a separate longer-window rule path was added
  specifically for it. All four found and fixed by generating and
  replaying real attack tool traffic, not by code review alone. See
  `ML_MODELS.md`.
- **The throughput benchmark measures Python processing, not Kafka.** No
  live broker was available when it was run — see §11.
- **scikit-learn's per-call inference overhead is the actual bottleneck** —
  measured 44.8 sustained flows/sec on a 12-core laptop CPU (~12ms per
  `predict()`+`predict_proba()` pair). That number reflects this Python
  prototype's own inference cost, not Kafka's or Zeek's — a real
  engineering constraint worth knowing before assuming any throughput
  number here scales to production traffic volumes without further
  optimization (batched inference, a faster serving runtime, etc.).
- **Single-host validation** for the three real-traffic models. All ML
  training/validation traffic ran against loopback (`127.0.0.1`) with one
  generator per class (real rate-limited `hping3` SYN floods for DDoS,
  `nmap` for recon, a self-built beacon emulator for C2). Real multi-host
  attack traffic is unvalidated. Three of PS 26145's own suggested
  dataset tools (`iodine`, Slowloris, `dnscat2`) have now been run
  directly against the live detectors, built from source in throwaway
  containers where needed — `iodine` and Slowloris each found and led to
  fixing a real gap; `dnscat2` (built from `iagox86/dnscat2`) confirmed
  100% real detection across all three record types it auto-negotiates
  (TXT/MX/CNAME), split between the tunnel rule (TXT) and the DGA
  classifier (MX/CNAME, which the tunnel rule deliberately doesn't check
  — see `ML_MODELS.md`). A from-scratch DGArchive pull remains untested
  against this specific build (the in-repo DGA generators reproduce 9
  published algorithm families' characteristic shapes instead).
- **No public JA4 threat-intel feed exists to populate
  `ja4_blacklist.json`** — checked directly against both sslbl.abuse.ch
  and FoxIO's `ja4db.foxio.io` (the latter's real database sits behind a
  signup/auth-gated API, not a public download). The lookup path is real
  and wired up; it just has nothing to match against yet. JA3 (which does
  have a real public feed) already satisfies PS 26145 (d)'s
  "JA3/JA3S or JA4" wording on its own.
- **C2's ML model is range-gated**, not universally trusted — see §4 and
  `ML_MODELS.md` for exactly why.
- **No Apache Flink, no Suricata, no real time-series database.** The
  Architecture page names what each of these would be in the full design;
  this prototype uses lighter stand-ins chosen so the interface (the
  `Detector` class, the alert schema) doesn't have to change if they're
  swapped in later.
- **Flask's development server**, not a production WSGI server — fine for
  a demo, not for production traffic volumes.
- **The data diode is simulated in software** (loopback capture), not a
  physical device — `/api/pipeline-status` labels this row `"simulated"`
  rather than pretending otherwise.

Nothing above is hidden — the dashboard's own Architecture page and
System Notes section state the same limitations live, in front of whoever
is using it.
