# ODIN — Multi-Host Validation & SIH Demonstration Plan

## 0. Objective

Move ODIN from loopback-only/single-host validation to genuine multi-host traffic observed passively by Zeek.

### Goals

1. Validate ODIN with distinct source/destination IPs.
2. Introduce genuine multi-host reconnaissance and fan-out.
3. Validate DDoS, Recon, C2, and Exfil across separate hosts.
4. Preserve the current baseline for comparison.
5. Create an unseen multi-host test set.
6. Build a strong live SIH demonstration.
7. Keep monitoring passive/read-only.
8. Avoid contaminating final evaluation with demonstration traffic.

---

## 1. Overall Architecture

**Scope decision (2026-09-13):** SIH final is Oct/Nov 2026 (~6-10 weeks out). To preserve buffer for report/PPT/video/rehearsal, the VM lab (formerly Phase 13) is **cut from the committed plan** and demoted to an optional stretch goal, only attempted if Docker + physical phases finish early. Scenario diversity (5-7 variants per threat class, §7-10) is kept in full — not trimmed. A physical SPAN-capable switch is being acquired, so Phase 14's mirroring approach proceeds as originally designed rather than falling back to an inline-bridge laptop.

Use two environments incrementally:

```text
                         ODIN
                           │
                    ┌──────┴──────┐
                    │             │
                  Zeek       ML Inference
                    │             │
                    └──────┬──────┘
                           │
                    Network Traffic
                           │
          ┌────────────────┼────────────────┐
          │                                 │
     Docker Lab                      Physical Lab
     systematic                        SIH demo
      testing
```

| Environment | Purpose |
|---|---|
| Docker | Repeatable multi-host dataset generation + primary validation |
| Physical laptops | Final live SIH demonstration |
| ~~VMs~~ | ~~Independent validation~~ — **cut; stretch goal only, see §15** |

Build in this order: **Docker → physical demonstration.** (VMs, if attempted at all, happen only as spare-time work after Phase 13/physical demo is rehearsed and solid.)

---

## 2. Phase 0 — Freeze Current Baseline

Before changing capture infrastructure, create an immutable baseline.

Suggested structure:

```text
docs/baselines/
└── 2026-09-13/
    ├── metrics/
    ├── ml_models/
    ├── dataset_counts.json
    └── README.md
```

Record:

- Current detector metrics
- Confusion matrices
- Precision, recall, F1
- False-positive rate
- Current throughput: **44.8 flows/sec**
- Dataset row counts
- Current GroupKFold configuration
- Model versions

Purpose: establish performance before multi-host validation and preserve a clean before/after comparison.

---

## 3. Phase 1 — Build Docker Multi-Host Lab

Start with Docker because it is cheap and reproducible.

### Proposed topology

```text
                    Docker Bridge
                    10.10.0.0/24
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
   attacker            victim-1            victim-2
   10.10.0.10          10.10.0.20          10.10.0.21
       │
   benign-1            benign-2
   10.10.0.30          10.10.0.31

                           │
                    Bridge interface
                           │
                          Zeek
                           │
                          ODIN
```

Start with:

```text
attacker
victim
benign-client
```

Then expand to:

```text
attacker
victim-1
victim-2
victim-3
benign-1
benign-2
```

**Expansion gate (added 2026-09-13):** build and validate the 3-node topology first — confirm P2/P2.5/P3 pass on it — before provisioning the extra victim/benign containers. Expand only when a specific scenario actually needs the extra hosts (recon_multi_01-03 need 2/3/4 victims respectively; DDoS/C2/exfil can mostly run on the 3-node set).

```text
3-node topology
      │
      ↓
Does the next scenario need more hosts?
      │
   ┌──┴──┐
  YES    NO
   │      │
   ↓      ↓
 expand  keep 3-node
```

Suggested static IPs:

```text
10.10.0.10  attacker
10.10.0.20  victim-1
10.10.0.21  victim-2
10.10.0.22  victim-3
10.10.0.30  benign-1
10.10.0.31  benign-2
```

---

## 4. Phase 2 — Make Zeek Passive

Prefer Zeek observing the host-side Docker bridge rather than acting as an inline intermediary.

```text
attacker ─────┐
victim ───────┼── Docker bridge ──→ Zeek
benign ───────┘                     │
                                    ↓
                                   ODIN
```

Desired property:

> ODIN/Zeek observe traffic but do not participate in generating or forwarding it.

Identify the relevant host-side bridge interface (for example `br-<network-id>`) and capture from that observation interface as appropriate.

---

## 4.5. Phase 2.5 — Feature Extraction Validation (added 2026-09-13)

Before generating a large batch of scenarios, confirm the feature pipeline actually turns multi-host packets into informative features — not just that Zeek sees the right IPs.

- [ ] Run one multi-host capture through the existing feature pipeline
- [ ] Verify `unique_hosts > 1` where expected
- [ ] Verify `host_fanout` reflects the number of contacted hosts
- [ ] Verify `port_fanout` changes with port-range variation
- [ ] Verify inter-arrival features change with scan-rate variation
- [ ] Compare multi-host feature distributions against existing loopback data
- [ ] Confirm no NaN/Inf/schema mismatches are introduced

> The goal isn't merely getting multi-host packets — it's making sure those packets become useful model features.

### Stop condition

Do not proceed to full-scale scenario generation (Phases 5-8) until the feature pipeline demonstrably reflects multi-host structure with a clean schema.

**Operational gotcha confirmed live (2026-09-13):** Zeek buffers a connection record and only writes it to `conn.log` once the connection is considered "done" (an inactivity timeout, up to ~60s for idle UDP/ICMP). Checking `conn.log` immediately after generating test traffic gives false negatives — TCP/UDP/ICMP were all confirmed captured correctly on the Docker bridge (`br-odinlab`) with real multi-host IPs, but only after waiting for the flush. Any capture-validation tooling (P2.5, P4.5) must wait for this, not just check right after a capture script exits.

---

## 5. Phase 3 — Network Sanity Test

Before attacks, generate:

- ICMP
- HTTP
- TCP
- DNS

Verify Zeek `conn.log` contains records such as:

```text
src = 10.10.0.10
dst = 10.10.0.20
```

and:

```text
src != 127.0.0.1
dst != 127.0.0.1
src != dst
```

Verify multiple endpoints:

```text
10.10.0.10 → 10.10.0.20
10.10.0.10 → 10.10.0.21
10.10.0.30 → 10.10.0.20
```

### Stop condition

Do not proceed until Zeek reliably observes distinct container-to-container traffic.

---

## 6. Phase 4 — Parameterize ODIN Capture Scripts

Remove hardcoded loopback assumptions from:

```text
capture_ddos.py
capture_recon.py
capture_c2.py
capture_ddos_udp_spoof.py
capture_exfil.py
```

Replace hardcoded `127.0.0.1` targets with configurable parameters such as:

```text
--attacker-ip
--victim-ip
--victim-ips
--duration
--scenario-id
```

Prefer scenario configuration over scattered hardcoded values.

Example:

```yaml
scenario_id: recon_multi_01

attacker:
  ip: 10.10.0.10

victims:
  - 10.10.0.20
  - 10.10.0.21
  - 10.10.0.22

attack_subtype: port_scan
```

---

## 6.5. Phase 4.5 — Scenario Quality Gate (added 2026-09-13)

Before merging any generated scenario into the training corpus, run it through an acceptance gate. This prevents discovering — after hours of captures — that the data wasn't actually usable.

```text
Scenario generated
       ↓
Schema valid?
       ↓
Correct labels?
       ↓
Expected IP topology?
       ↓
Expected feature variation?
       ↓
No capture corruption?
       ↓
PASS → add to dataset
FAIL → regenerate
```

- [ ] Validate packet/flow counts
- [ ] Validate expected source/destination IPs
- [ ] Validate attack subtype
- [ ] Validate feature distributions
- [ ] Validate timestamps/order
- [ ] Validate no accidental loopback traffic
- [ ] Validate provenance metadata (§11)
- [ ] Only then merge into the training dataset

**Implementation note:** with ~20 scenarios total across Phases 5-8, do this with one small `validate_scenario.py` script that every capture runs through automatically, rather than repeating the checklist by hand each time.

---

## 7. Phase 5 — Multi-Host Recon

Recon should be the first major multi-host experiment.

### Topology

```text
                         ┌── victim-1
                         │
attacker ────────────────┼── victim-2
                         │
                         ├── victim-3
                         │
                         └── victim-4
```

Create behavioral diversity instead of repeating identical scans.

Example scenarios:

```text
recon_multi_01
1 attacker → 2 victims

recon_multi_02
1 attacker → 3 victims

recon_multi_03
1 attacker → 4 victims

recon_multi_04
different port ranges

recon_multi_05
different scan rates

recon_multi_06
slow scan

recon_multi_07
bursty scan  ← reserved as the UNSEEN test scenario (see §12)
```

Pay particular attention to:

```text
unique_hosts
unique_src_ips
unique_dst_ips
port_fanout
host_fanout
```

Do not force any feature to become important; measure what the model actually learns.

---

## 8. Phase 6 — Multi-Host DDoS

Start with:

```text
attacker
10.10.0.10
      │
      ├────────→ victim-1
      │
      └────────→ victim-2
```

Named scenarios (added 2026-09-13, mirrors Recon's explicit naming):

```text
ddos_multi_01
baseline, attacker → victim-1 + victim-2 simultaneously

ddos_multi_02
SYN flood

ddos_multi_03
UDP flood

ddos_multi_04
spoofed-source, varying rate/burstiness  ← reserved as the UNSEEN test scenario (see §12)
```

Vary:

- Target
- Rate
- Duration
- Burstiness
- Source behavior

The goal is to show that DDoS detection is not dependent on localhost traffic, not to create a huge repetitive dataset.

---

## 9. Phase 7 — Multi-Host C2

Use existing C2 behavioral configurations with independent endpoints.

```text
C2/server
10.10.0.10
     │
     │ periodic communication
     ↓
client/victim
10.10.0.20
```

Vary:

- Beacon interval
- Jitter
- Burst/sleep behavior
- Destination
- Port
- Communication duration

Example:

```text
c2_multi_01
30 sec interval

c2_multi_02
60 sec interval

c2_multi_03
30 sec + jitter

c2_multi_04
sleep/burst

c2_multi_05
multiple destinations  ← reserved as the UNSEEN test scenario (see §12)
```

This complements the existing C2 dataset and CTU-13 real-data work.

---

## 10. Phase 8 — Multi-Host Exfiltration

Topology:

```text
victim
10.10.0.20
    │
    │ outbound data
    ↓
external/server
10.10.0.40
```

Use existing asymmetric-flow behavior and supported traffic patterns such as:

```text
HTTP
ICMP
DNS
```

and:

```text
bulk
low-and-slow
```

Named scenarios (added 2026-09-13, mirrors Recon/DDoS/C2's explicit naming — only needed if Phase 8 is attempted, since it's optional):

```text
exfil_multi_01
HTTP bulk

exfil_multi_02
DNS low-and-slow

exfil_multi_03
ICMP covert  ← reserved as the UNSEEN test scenario if this phase runs (see §12)
```

Maintain the existing caveat:

> Low-and-slow synthetic traffic approximates evasive exfiltration behavior; it is not a substitute for a real evasive malware corpus.

---

## 11. Phase 9 — Provenance and Scenario Metadata

Every new capture should be traceable.

**Note on `source` (added 2026-09-13):** 19 existing scenario files across all six threat classes already use `source: real` to mean "genuinely captured via real attack tools + Zeek," distinct from `synthetic` (algorithmically generated feature rows, no real packets) and `real_public_dataset` (external corpora like CTU-13). Docker/physical multi-host captures are captured the same way — real tools, real packets, just a different topology — so they correctly stay `source: real` too; forking a new value (e.g. `lab_generated`) would make them inconsistent with the 19 files already using `real` for the identical kind of capture. The actual ambiguity is *environment* (loopback vs. Docker vs. physical), which `source` was never meant to carry — fixed below with a dedicated field instead.

Recommended fields:

```text
scenario_id
threat_class
attack_subtype
source
environment          ← NEW: loopback | docker_multihost | physical_multihost
label_method
capture_id
attacker_ip
victim_ips
configuration
timestamp
```

Example:

```text
scenario_id: recon_multi_04
threat_class: recon
attack_subtype: port_scan
source: real
environment: docker_multihost
label_method: controlled_generation
attacker_ip: 10.10.0.10
victim_ips: 10.10.0.20,10.10.0.21,10.10.0.22
```

Use the existing production vocabulary:

```text
ddos
recon
c2
dga
tls
exfil
```

`MULTI_VECTOR` remains reserved for the correlator.

---

## 12. Phase 10 — Create an Unseen Multi-Host Test Set

Do not train on every new capture. Held out per threat class (added 2026-09-13, explicit — was previously only spelled out for Recon):

| Threat class | Training | Validation | Unseen final test |
|---|---|---|---|
| Recon | recon_multi_01–05 | recon_multi_06 | **recon_multi_07** (bursty scan) |
| DDoS | ddos_multi_01–03 | — | **ddos_multi_04** (spoofed-source, varying rate/burstiness) |
| C2 | c2_multi_01–04 | — | **c2_multi_05** (multiple destinations) |
| Exfil (if attempted) | exfil_multi_01 | exfil_multi_02 | **exfil_multi_03** (ICMP covert) |

DDoS/C2/Exfil have fewer scenarios than Recon, so they skip a separate validation split and go straight train → unseen test; add a validation scenario for a class only if scenario count grows enough to support the extra split without shrinking training data too far.

The exact number can change. The important principle is:

> The final multi-host scenario remains unseen during training.

**Isolation requirement (added 2026-09-13):**

- [ ] Unseen test data must not influence feature selection, hyperparameter tuning, threshold selection, or retraining

This is what makes the claim "we evaluated generalization on a scenario the model never saw during training or tuning" defensible — a materially stronger claim than simply "we used a test set."

This measures cross-scenario generalization rather than memorization.

---

## 13. Phase 11 — Retrain

After collecting a coherent batch:

```text
Existing dataset
       +
multi-host dataset
       ↓
feature extraction
       ↓
training
       ↓
GroupKFold
       ↓
unseen scenario evaluation
```

Do not retrain after every individual scenario.

---

## 14. Phase 12 — Before/After Evaluation

Compare the frozen baseline with the new multi-host model, split explicitly by which traffic each score comes from — not just an aggregate before/after.

| Metric | Existing baseline | Multi-host retrained |
|---|---:|---:|
| Recon F1 (loopback) | X | X |
| Recon recall (loopback) | X | X |
| Recon FP rate (loopback) | X | X |
| DDoS F1 (loopback) | X | X |
| C2 F1 (loopback) | X | X |
| Exfil F1 (loopback) | X | X |
| Unseen multi-host scenario F1 | — | X |
| Unseen multi-host scenario recall | — | X |
| Cross-scenario F1 | X | X |
| Throughput | 44.8 flows/s | not re-benchmarked here — see §20 opportunistic track |

**Regression check (added 2026-09-13, critical):**

- [ ] Compare performance specifically on original loopback traffic (pre- vs. post-retrain)
- [ ] Compare performance specifically on multi-host traffic
- [ ] Check whether adding multi-host data causes regression on existing data

Acceptable outcome: **multi-host performance ↑, existing performance ≈ or ↑**. Unacceptable: multi-host performance ↑ while existing performance drops sharply. If a real regression shows up, report it honestly rather than hiding it — better to catch it here than at the SIH demo.

**Confusion-matrix comparison (added 2026-09-13, nice-to-have):**

- [ ] Generate confusion matrices per threat class for the existing baseline and the multi-host retrained model, side by side
- [ ] Generate a confusion matrix on each unseen scenario (recon_multi_07, ddos_multi_04, c2_multi_05, exfil_multi_03 if run)
- [ ] Check whether the *error type* shifted (e.g. FN→FP swap) rather than trusting the aggregate F1/recall alone — two models can share the same F1 with very different failure modes, and that difference matters for a security tool

Investigate:

```text
unique_hosts
unique_src_ips
unique_dst_ips
port_fanout
```

Do not assume multi-host features will become important. If `unique_hosts` remains low importance after genuine multi-host variation is introduced, report that honestly.

---

## 15. Phase 13 — Add Two VMs (CUT — stretch goal only)

**Status: cut from the committed plan (2026-09-13).** With the SIH final in Oct/Nov, this phase is skipped to preserve buffer for report/PPT/video/rehearsal. Attempt it only if Phases 0-11 and the Phase 14 physical demo are complete and rehearsed with time still remaining. The rest of this section is kept as reference in case it becomes worth doing later.

Once Docker is stable, add two lightweight VMs for independent validation.

For the 16 GB RAM, i7 12th-gen Ubuntu machine:

| VM | RAM | vCPU | Role |
|---|---:|---:|---|
| VM-1 | 2–3 GB | 2 | Attacker |
| VM-2 | ~2 GB | 2 | Victim |

Leave roughly 8–10 GB for the Ubuntu host, Zeek, ODIN, browser/IDE, and other processes.

Avoid allocating 4 GB+ to each VM; host memory pressure can distort ODIN's 44.8 flows/sec throughput measurement.

### VM topology

```text
VM attacker
     │
     │
Virtual network
     │
     ↓
VM victim
     │
     ↓
Zeek
     ↓
ODIN
```

Use VMs mainly for independent validation rather than regenerating the entire training corpus.

---

## 16. Phase 14 — Physical Laptop SIH Demonstration

If 2–3 additional laptops are available, prioritize them for the final live demonstration.

### Recommended topology

```text
                 Ethernet switch
                       │
          ┌────────────┼────────────┐
          │            │            │
       Laptop A     Laptop B     Laptop C
       ATTACKER      VICTIM       BENIGN
```

The ODIN monitoring machine runs:

```text
Zeek
 ↓
ODIN
 ↓
Dashboard
```

Preferred passive architecture:

```text
Attack laptop ──┐
Victim laptop ──┼── Switch ── SPAN/Mirror ── Monitoring machine
Benign laptop ──┘                              │
                                               ↓
                                              Zeek
                                               ↓
                                              ODIN
```

### Critical networking point

A normal switched network does not automatically send every host's unicast traffic to the monitoring laptop.

For genuine passive observation, use:

- Switch port mirroring/SPAN, or
- an appropriate network tap/observation point.

Ethernet plus a managed switch with port mirroring is preferable to relying on ordinary Wi-Fi capture for the demo.

### Pre-flight capture validation (added 2026-09-13 — run before any attack)

Confirm the passive pipeline end-to-end on benign traffic first:

```text
Physical network → SPAN → Zeek → conn.log → ODIN
```

- [ ] Generate normal traffic between Laptop A ↔ Laptop B
- [ ] Confirm Zeek sees A ↔ B in `conn.log`
- [ ] Generate Laptop C ↔ Laptop B traffic
- [ ] Confirm Zeek sees C ↔ B in `conn.log`
- [ ] Confirm ODIN receives the resulting features (not just that Zeek logs the connection)

Only run the attack scenarios (§18) once every item above is checked.

---

## 17. Physical SIH Demo Roles

### Laptop 1 — Attacker

Use controlled tools/scenarios such as:

```text
nmap
hping3
C2 emulator
```

depending on the selected demonstration.

### Laptop 2 — Victim

Run:

```text
HTTP server
DNS service
normal TCP services
```

### Laptop 3 — Benign client

Generate:

```text
HTTP
DNS
iperf
normal TCP traffic
```

### Monitoring machine

Run:

```text
Network capture
      ↓
Zeek
      ↓
Feature extraction
      ↓
Six detectors
      ↓
Correlation
      ↓
Alert schema
      ↓
Dashboard
```

---

## 18. Recommended SIH Demonstration Sequence

Do not attempt to demonstrate all six threat classes live. Select the strongest 3–4.

### Demo 1 — Recon

```text
Attacker
   ↓
scans multiple hosts
   ↓
Zeek
   ↓
ODIN
   ↓
RECON alert
```

This directly demonstrates the new multi-host capability.

### Demo 2 — DDoS

```text
Attacker
   ↓↓↓↓↓
Victim
   ↓
ODIN
   ↓
DDoS alert
```

### Demo 3 — C2

```text
Victim
   ↕
periodic C2 traffic
   ↓
ODIN
   ↓
C2 beacon alert
```

### Demo 4 — Benign traffic

Run normal traffic simultaneously.

The dashboard should visibly distinguish:

```text
Attack traffic → 🚨
Normal traffic → ✅
```

This demonstrates both detection and benign handling.

---

## 19. What Not to Do

### Do not replace the current dataset

Keep the existing validated loopback data. New multi-host data should be additive.

### Do not chase a large row-count target

Scenario diversity and independent validation are more valuable than hundreds of thousands of repetitive rows.

### Do not train on final live-demo traffic

Where practical, keep final physical demonstration traffic independent of training.

### Do not call Docker containers physical hosts

Use accurate terminology:

> isolated virtual network endpoints

### Do not claim VM validation proves gateway-scale throughput

Multi-host realism and throughput are separate validation dimensions.

### Do not build an unnecessarily large cyber range

The goal is to validate ODIN, not to build a complete enterprise simulator.

---

## 20. Priority Order

Execute the work in this order:

```text
P0    Freeze baseline
 │
 ↓
P1    Docker 3-node topology
 │
 ↓
P2    Zeek passive bridge capture
 │
 ↓
P2.5  Feature extraction validation          ← NEW
 │
 ↓
P3    Network sanity test
 │
 ↓
P4    Parameterize capture scripts
 │
 ↓
P4.5  Scenario quality gate                  ← NEW
 │
 ↓
P5    Multi-host Recon
P6    Multi-host DDoS
P7    Multi-host C2
P8    Multi-host Exfil (optional)
 │
 ↓
P9    Provenance + unseen test scenarios
 │
 ↓
P10   Retrain + GroupKFold
 │
 ↓
P11   Before/after evaluation + regression check
 │
 ↓
P13   Physical laptop SIH demonstration
 │
 ↓
(P12  Two-VM independent validation — STRETCH GOAL ONLY, attempt after
 P13 is rehearsed and solid, and only if time remains before the SIH final)
```

**Opportunistic parallel track (from roughly P4 onward, added 2026-09-13):** throughput (currently 44.8 flows/sec) is a known weakness worth addressing, but calling it "parallel" only makes sense if a second contributor owns it independently. For a single person, treat it as work to pick up during dead time — background captures running, waiting on a retrain — not a track that truly runs alongside the main chain on its own clock. It must never block P0-P13.

```text
throughput profiling → batching/optimization → new benchmark
```

Picked up opportunistically; does not gate any phase above.

---

## 21. Final Recommended Strategy

Do not treat the decision as Docker **vs.** physical laptops.

Use each environment for a different purpose:

```text
Docker
   ↓
SYSTEMATIC TESTING
Repeatable scenarios
Dataset generation
Automation

Physical laptops
   ↓
LIVE SIH DEMONSTRATION
Real machines
Real network
Judge-visible attack → detection

(VMs — stretch goal only, not part of the committed story)
```

### Target outcome

The final ODIN validation story should be:

> ODIN was initially validated using controlled single-host traffic. A reproducible multi-host virtual network was then introduced to generate traffic between distinct network endpoints and evaluate cross-host behavior, with full scenario diversity per threat class. The final system was demonstrated using physically separated laptops connected over a switch-mirrored monitored network. Final multi-host scenarios were held out from training where practical to measure generalization rather than memorization. (Independent VM-based validation was considered but deferred as a stretch goal given the SIH timeline.)

This closes the current **single-host/loopback validation weakness** without discarding the existing dataset or creating an unnecessary infrastructure project.

---

## 22. Success Criteria

- [ ] Current ODIN metrics are frozen as a dated baseline.
- [ ] Docker multi-host network is operational.
- [ ] Zeek captures traffic from the bridge interface.
- [ ] `conn.log` shows distinct non-loopback source/destination IPs.
- [ ] Multi-host feature extraction is validated (§4.5): `unique_hosts`/`host_fanout`/`port_fanout`/inter-arrival features behave as expected, no NaN/Inf/schema issues.
- [ ] Existing capture scripts accept configurable endpoints.
- [ ] Every scenario passes the quality gate (§6.5) — schema, IPs, labels, feature distributions, no accidental loopback, provenance — before merging into the training corpus.
- [ ] Multi-host Recon scenarios are captured.
- [ ] Multi-host DDoS scenarios are captured.
- [ ] Multi-host C2 scenarios are captured.
- [ ] Multi-host Exfil scenarios are captured where practical.
- [ ] New captures have provenance/scenario metadata.
- [ ] At least one multi-host scenario remains unseen for final evaluation.
- [ ] Unseen test data provably did not influence feature selection, hyperparameter tuning, threshold selection, or retraining.
- [ ] Models are retrained and evaluated using the existing grouping methodology.
- [ ] Before/after metrics are recorded, split by loopback vs. multi-host traffic.
- [ ] Regression check confirms multi-host gains did not come at the cost of existing (loopback) performance.
- [ ] Multi-host feature behavior is reported honestly.
- [ ] Pre-flight passive-capture validation (benign A↔B, C↔B traffic reaching ODIN) passed before any live attack scenario was run.
- [ ] 2–3 physical laptops can reproduce a selected live scenario, using the acquired SPAN-capable switch.
- [ ] Passive monitoring architecture is demonstrated.
- [ ] SIH demo clearly shows attack traffic, benign traffic, Zeek observation, ODIN detection, and dashboard alerting.

**Stretch goal (only if time remains after the above are complete and rehearsed):**
- [ ] Two lightweight VMs successfully generate independent validation traffic.
