# ODIN — Dataset Architecture & Data Collection Plan

## Project Context

**Problem Statement:** 26145  
**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization:** National Technical Research Organisation (NTRO)

The problem statement requires a passive, read-only AI/ML pipeline that processes one-directional IP traffic and detects six threat categories:

1. Volumetric / protocol DDoS
2. Botnet C2 beaconing
3. DGA domains and DNS tunnelling
4. Malware inside encrypted sessions
5. Reconnaissance and port scanning
6. Data exfiltration

The solution must support ingest, feature extraction, model inference, and alert output, with streaming/replay processing, a defined throughput target, and a standardized alert schema.

---

# 1. Recommended Dataset Strategy

Because ODIN uses a **separate model for each threat**, the recommended approach is:

> **One unified raw traffic repository → common feature extraction → six threat-specific datasets → six specialized models → one common inference and alert layer.**

Do **not** create six completely isolated data ecosystems.

Instead, maintain:

- A **master raw dataset** containing all traffic sources and attack types.
- Six **derived, threat-specific datasets** used by the individual models.
- Shared benign traffic that can act as negative examples for multiple models.
- A completely separate final test/replay dataset for evaluating the complete ODIN pipeline.

---

# 2. Overall Architecture

```text
                         RAW TRAFFIC
                             │
               ┌─────────────┴─────────────┐
               │                           │
           PCAP files                 Flow records
               │                           │
               └─────────────┬─────────────┘
                             │
                       Feature Engine
                             │
                    ┌────────┴────────┐
                    │                 │
              Common Features    Threat-specific
                                Features
                    │                 │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
            DDoS            C2            DGA/DNS
              │              │              │
              ▼              ▼              ▼
           Dataset 1      Dataset 2      Dataset 3

              │              │              │
              ├──────────────┼──────────────┤
              │              │              │
           TLS/Malware    Recon           Exfil
              │              │              │
              ▼              ▼              ▼
           Dataset 4      Dataset 5      Dataset 6
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                     6 SPECIALIZED MODELS
                             │
                             ▼
                     ODIN INFERENCE ENGINE
                             │
                             ▼
                 Unified Alert / Dashboard
```

---

# 3. Master Dataset

The master repository should preserve the original traffic and its provenance.

Recommended structure:

```text
ODIN_DATASET/
│
├── raw/
│   │
│   ├── benign/
│   │   ├── iperf3/
│   │   ├── ostinato/
│   │   ├── trex/
│   │   └── real_traffic/
│   │
│   ├── ddos/
│   │   ├── syn/
│   │   ├── udp/
│   │   ├── reflection/
│   │   └── spoofed/
│   │
│   ├── c2/
│   │   ├── botnet_capture/
│   │   └── simulated/
│   │
│   ├── dns/
│   │   ├── dga/
│   │   └── tunnelling/
│   │
│   ├── encrypted/
│   │   ├── tls/
│   │   └── quic/
│   │
│   ├── recon/
│   │   ├── port_scan/
│   │   └── host_scan/
│   │
│   └── exfil/
│       ├── bulk/
│       └── low_slow/
│
├── extracted/
│   ├── flows.parquet
│   ├── dns.parquet
│   └── tls.parquet
│
├── datasets/
│   ├── ddos.csv
│   ├── c2.csv
│   ├── dns.csv
│   ├── encrypted.csv
│   ├── recon.csv
│   └── exfil.csv
│
└── splits/
    ├── train/
    ├── validation/
    └── test/
```

### Important

Preserve metadata describing:

- Source dataset
- Original PCAP
- Attack family
- Attack subtype
- Capture/scenario ID
- Timestamp
- Protocol
- Source/destination information where appropriate
- Label generation method

This makes the dataset auditable and easier to defend during evaluation.

---

# 4. Recommended Dataset Size

There is no official dataset-size requirement in the problem statement. The following numbers are recommended targets for a strong prototype.

## Model-level targets

| Model | Positive samples | Negative samples | Total target |
|---|---:|---:|---:|
| DDoS | 300k–400k | 400k–500k | 700k–900k |
| C2 Beaconing | 150k–200k | 250k–300k | 400k–500k |
| DGA/DNS | 150k–200k | 250k–300k | 400k–500k |
| Encrypted Malware | 150k–200k | 250k–300k | 400k–500k |
| Reconnaissance | 150k–200k | 250k–300k | 400k–500k |
| Exfiltration | 150k–200k | 250k–300k | 400k–500k |

This results in approximately **2.7–3.4 million model-training samples across the six models**.

These do not need to be 3.4 million completely unique raw flows. Shared benign traffic can legitimately contribute to multiple threat-specific datasets after appropriate feature extraction.

---

# 5. Recommended Raw PCAP Scale

A practical prototype target is approximately:

- **8–20 GB total PCAP**
- Roughly **1.5–2.5 million useful flows**, depending on traffic composition and protocol
- Multiple scenarios rather than one enormous capture

Raw PCAP size should not be treated as the primary quality metric.

The quality of the temporal patterns, attack diversity, benign diversity, labeling, and train/test separation is more important than simply accumulating gigabytes.

---

# 6. Benign Traffic

Benign traffic should be shared across threat-specific datasets where appropriate.

Recommended target:

**400k–600k flows or more**, covering diverse normal behavior.

Possible sources:

- iperf3
- Ostinato
- TRex
- Normal HTTP/HTTPS
- Normal DNS
- Normal TLS/QUIC
- Normal client-server traffic

Example:

```text
BENIGN
│
├── web_browsing
├── dns
├── https
├── tls
├── quic
├── file_transfer
├── streaming
├── interactive
└── iperf3
```

Avoid making benign traffic consist only of iperf3. A model trained against one narrow type of benign traffic may learn dataset artifacts instead of actual threats.

---

# 7. Dataset 1 — DDoS

The problem statement identifies:

- SYN floods
- UDP reflection/amplification
- Spoofed-source floods

Recommended structure:

```text
ddos/
│
├── benign/
├── syn_flood/
├── udp_flood/
├── udp_reflection/
└── spoofed_source/
```

Recommended features:

```text
timestamp
src_ip
dst_ip
src_port
dst_port
protocol
duration
packets
bytes
pps
bps
syn_count
ack_count
src_ip_entropy
unique_src_ips
unique_dst_ports
flow_rate
label
attack_type
```

Labels:

```text
BENIGN
SYN_FLOOD
UDP_FLOOD
UDP_REFLECTION
SPOOFED_SOURCE
```

### Target

Approximately **300k–500k flows**.

Include multiple attack intensities rather than only one high-rate attack.

---

# 8. Dataset 2 — Botnet C2 Beaconing

The problem statement specifically calls for periodicity and inter-arrival analysis.

Recommended structure:

```text
c2/
│
├── benign/
├── periodic_beacon/
├── jittered_beacon/
├── bursty_c2/
└── irregular_c2/
```

Recommended features:

```text
src_ip
dst_ip
dst_port
protocol

timestamp
flow_duration
packet_count
byte_count

inter_arrival_mean
inter_arrival_std
inter_arrival_min
inter_arrival_max

periodicity_score
jitter
connection_frequency

unique_destinations
destination_repetition

label
```

### Critical requirement

Retain timestamps and ordering.

For example:

```text
10:00:00 → C2 destination
10:00:10 → C2 destination
10:00:20 → C2 destination
10:00:30 → C2 destination
```

contains useful temporal information.

Do not randomly shuffle traffic before extracting temporal/sequence features.

### Target

Approximately **150k–250k flows**, distributed across many beacon behaviors.

Public Botnet-Capture PCAPs can be useful as realistic validation data, while controlled/simulated beaconing can provide known patterns and labels.

---

# 9. Dataset 3 — DGA and DNS Tunnelling

The problem statement groups DGA and DNS tunnelling under one detection category.

Recommended structure:

```text
dns/
│
├── benign_dns/
│
├── dga/
│   ├── algorithm_1/
│   ├── algorithm_2/
│   └── algorithm_3/
│
└── dns_tunnelling/
    ├── dnscat2/
    ├── iodine/
    └── other_patterns/
```

Recommended features:

```text
query_length
domain_length

entropy
digit_ratio
alpha_ratio
special_char_ratio

unique_char_count
vowel_ratio

bigram_score
trigram_score
ngram_score

query_frequency
subdomain_depth

record_type
response_code

label
attack_type
```

Labels:

```text
BENIGN_DNS
DGA
DNS_TUNNELLING
```

### Target

Approximately **150k–250k DNS records/queries**.

Include different domain lengths and different DGA/tunnelling behaviors.

---

# 10. Dataset 4 — Malware Inside Encrypted Sessions

The problem statement requires TLS/QUIC metadata analysis without decrypting payloads.

Recommended structure:

```text
encrypted/
│
├── benign_tls/
├── malicious_tls/
├── benign_quic/
└── malicious_quic/
```

Recommended features:

```text
protocol
tls_version
cipher_suite

ja3
ja3s
ja4

flow_duration
packet_count
byte_count

forward_bytes
backward_bytes

packet_size_mean
packet_size_std
packet_size_sequence

iat_mean
iat_std
iat_sequence

label
```

Do NOT include:

```text
decrypted_payload
HTTP body
application content
credentials
files extracted from encrypted sessions
```

The model should determine whether an encrypted session is suspicious using metadata only.

### Target

Approximately **150k–250k flows**.

---

# 11. Dataset 5 — Reconnaissance / Port Scanning

The problem statement describes reconnaissance through fan-out patterns across destination ports or hosts.

Recommended structure:

```text
recon/
│
├── benign/
│
├── port_scan/
│   ├── horizontal/
│   └── vertical/
│
├── host_scan/
└── mixed_scan/
```

Recommended features:

```text
src_ip

unique_dst_ips
unique_dst_ports

port_fanout
host_fanout

connection_attempts
successful_connections
failed_connections

scan_rate
syn_ratio
rst_ratio

destination_entropy

time_window
label
```

Example of vertical scanning:

```text
Source A
    │
    └── Host 1
        ├── port 21
        ├── port 22
        ├── port 23
        ├── port 80
        └── port 443
```

Example of horizontal scanning:

```text
Source A
    ├── Host 1 : port 22
    ├── Host 2 : port 22
    ├── Host 3 : port 22
    ├── Host 4 : port 22
    └── Host 5 : port 22
```

### Target

Approximately **150k–250k flows/windows**.

---

# 12. Dataset 6 — Data Exfiltration

The problem statement specifically mentions:

- asymmetric flow-volume anomalies
- unusual outbound/inbound byte ratios

Recommended structure:

```text
exfil/
│
├── benign/
├── bulk_exfil/
├── slow_exfil/
├── periodic_exfil/
└── encrypted_exfil/
```

Recommended features:

```text
src_ip
dst_ip

outbound_bytes
inbound_bytes

outbound_packets
inbound_packets

byte_ratio
packet_ratio

flow_duration

bytes_per_second
packets_per_second

destination_frequency

session_count

label
```

Include both:

### High-volume exfiltration

```text
10 MB → 100 MB → 1 GB
```

and:

### Low-and-slow exfiltration

```text
small transfer
small transfer
small transfer
small transfer
...
```

### Target

Approximately **150k–250k flows/windows**.

---

# 13. Dataset Labels

Do not restrict the dataset to only:

```text
0 = benign
1 = malicious
```

Maintain three levels.

## Level 1 — Binary

```text
is_threat

0 = benign
1 = malicious
```

## Level 2 — Threat class

```text
BENIGN
DDOS
C2
DGA
DNS_TUNNEL
ENCRYPTED_MALWARE
RECON
EXFIL
```

## Level 3 — Attack subtype

Examples:

```text
SYN_FLOOD
UDP_REFLECTION
PERIODIC_BEACON
JITTERED_BEACON
DGA
IODINE
DNScat2
TLS_ANOMALY
PORT_SCAN
HOST_SCAN
LOW_SLOW_EXFIL
BULK_EXFIL
```

This allows ODIN to train binary or multiclass models while preserving detailed provenance.

---

# 14. Train / Validation / Test Strategy

Avoid simply doing:

```text
PCAP
 ↓
randomly split rows
 ↓
80% train
20% test
```

This can cause data leakage.

Instead, split at the **capture/scenario/session/host/time level**.

Recommended:

```text
                     RAW CAPTURES
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Capture A    Capture B    Capture C
             │            │            │
           TRAIN          VAL          TEST
```

A reasonable starting split:

```text
TRAIN       70%
VALIDATION  15%
TEST        15%
```

But the split should be performed by scenario/source/capture rather than individual random rows.

---

# 15. Final Unseen Streaming Test Set

Maintain a completely separate test/replay dataset.

```text
FINAL_TEST/
│
├── benign/
├── ddos/
├── c2/
├── dns/
├── encrypted/
├── recon/
└── exfil/
```

This dataset should ideally contain scenarios that were not used to train the models.

Run it through ODIN as:

```text
FINAL_TEST.pcap
       ↓
Streaming PCAP Replay
       ↓
Packet/Flow Extraction
       ↓
Feature Extraction
       ↓
Threat Models
       ↓
Alert Aggregator
       ↓
Dashboard
```

This is important because the problem statement requires streaming rather than only an end-of-run batch report.

---

# 16. Unified Alert Schema

All six models should ultimately produce the same alert structure.

Example:

```json
{
  "timestamp": "...",
  "flow_id": "...",
  "threat_class": "C2_BEACONING",
  "attack_subtype": "PERIODIC_BEACON",
  "confidence": 0.96,
  "severity": "HIGH",
  "evidence": {
    "periodicity_score": 0.94,
    "iat_std": 0.12,
    "destination_repetition": 0.91
  }
}
```

Recommended common fields:

```text
timestamp
flow_id
threat_class
attack_subtype
confidence
severity
supporting_evidence
model_version
```

The threat-specific evidence can differ between models.

---

# 17. Feature Architecture

Do not force every model to use the same feature set.

Use:

## Common features

```text
timestamp
protocol
src/dst identifiers
ports
duration
packet count
byte count
flow rate
```

## DDoS-specific

```text
PPS
BPS
source entropy
SYN/ACK statistics
source fan-in
```

## C2-specific

```text
inter-arrival time
periodicity
jitter
destination repetition
```

## DGA/DNS-specific

```text
domain entropy
n-grams
query length
character statistics
record types
```

## Encrypted-specific

```text
JA3/JA3S/JA4
TLS version
cipher suite
packet size sequences
timing sequences
```

## Recon-specific

```text
host fan-out
port fan-out
scan rate
destination entropy
```

## Exfil-specific

```text
outbound/inbound ratio
byte asymmetry
transfer rate
session frequency
```

---

# 18. Data Reuse Strategy

The same raw benign traffic can be reused across multiple threat-specific datasets.

For example:

```text
                    BENIGN TRAFFIC
                          │
       ┌──────────────────┼──────────────────┐
       ▼                  ▼                  ▼
   DDoS model         C2 model          Recon model
   negative           negative           negative
       │                  │                  │
       └──────────────────┼──────────────────┘
                          │
                   Other models
```

However, threat-specific positive samples should remain appropriate to the features used by that model.

---

# 19. Recommended Model Dataset Balance

Do not make the overall real-world traffic distribution artificially 50/50.

A useful starting point is:

```text
60% benign
40% malicious
```

For the malicious portion:

```text
DDoS                 ~30%
C2                    ~15%
DGA/DNS               ~15%
Encrypted malware     ~15%
Recon                 ~12.5%
Exfiltration          ~12.5%
```

For individual binary models, however, you can use balanced or moderately weighted training sets as appropriate and then evaluate against a more realistic distribution.

---

# 20. Most Important Dataset Quality Rules

### Rule 1 — Diversity > raw size

A 2 GB dataset with diverse behaviors can be more valuable than a 20 GB dataset containing repetitive traffic.

### Rule 2 — Preserve timestamps

Especially for:

- C2
- Recon
- DGA/DNS
- Exfiltration

### Rule 3 — Preserve provenance

Know exactly where every sample came from.

### Rule 4 — Avoid train/test leakage

Do not allow the same attack campaign or nearly identical capture to appear in both training and final testing.

### Rule 5 — Don't decrypt TLS/QUIC

Use metadata only for the encrypted-malware detector.

### Rule 6 — Test streaming separately

Do not only report offline ML metrics.

### Rule 7 — Measure throughput

Record something like:

```text
Test throughput: 25,000 flows/sec
Detection latency: < X ms
```

using the actual values measured by your implementation.

---

# 21. Final Recommended ODIN Data Flow

```text
                         ┌─────────────────────┐
                         │    RAW PCAP SOURCES │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   STREAMING INGEST  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ FEATURE EXTRACTION  │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
        Flow features         DNS features        TLS/QUIC features
              │                     │                     │
      ┌───────┼───────┐             │                     │
      ▼       ▼       ▼             ▼                     ▼
     DDoS    C2      Recon       DGA/DNS          Encrypted Malware
      │       │       │             │                     │
      └───────┴───────┴─────────────┴─────────────────────┘
                              │
                              ▼
                        Exfiltration
                              │
                              ▼
                    ┌──────────────────┐
                    │ ALERT AGGREGATOR │
                    └────────┬─────────┘
                             ▼
                       ODIN DASHBOARD
```

---

# 22. Final Recommendation

For ODIN, use:

> **1 master raw dataset + 6 derived threat-specific datasets + 6 specialized models + 1 completely unseen streaming test dataset.**

Do **not** create six totally independent datasets with six unrelated benign populations.

The ideal target for a strong prototype is approximately:

- **8–20 GB** raw PCAP
- **1.5–2.5 million useful raw flows**
- **~2.7–3.4 million model-training samples across the six models**
- Multiple attack subtypes per threat
- Diverse benign traffic
- Scenario/capture-level train/validation/test separation
- Separate unseen streaming replay set

The goal is not to maximize dataset size. The goal is to demonstrate that **each specialized model learns the behavior it is supposed to detect and that all six models work together inside ODIN's passive, streaming architecture.**
