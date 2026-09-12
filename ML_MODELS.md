# ML Models

All six of the prototype's detectors are now driven by trained classifiers
instead of hand-picked thresholds. **All six are now trained inside this
repo** (`training/train_*.py`, `training/capture/*.py`,
`training/build_dataset_*.py`). DDoS, Recon, and C2 were originally trained
in a sibling exploration repo (`recon-ml-poc/`, not part of this project);
that work has been superseded by a larger, in-repo retraining run so the
full capture → feature → train → validate pipeline is part of this
deliverable, per PS 26145's requirement to document the training/validation
approach. DGA, TLS, and Exfil (added in Phase 2) remain trained on
**synthetic data**, not real captures — see the "Phase 2 detectors" section
below for exactly what that means for how much to trust their numbers.
This page is the short version: what's running in production, on what
data, checked how.

**Dataset sizes (all real captured traffic, comfortably clearing the
>10,000-row target):** DDoS 29,844 rows / 247 sessions (SYN flood + UDP
flood + spoofed-source, see "UDP/spoofed-source DDoS extension"), Recon
17,674 rows / 175 sessions, C2 16,262 rows / 114 sessions. See
"Real-traffic retraining" below for methodology, tooling, and one real
contamination bug found and fixed along the way.

## What's running

| Detector | Model | File | Replaces |
|---|---|---|---|
| `backend/detectors/ddos.py` | RandomForestClassifier | `backend/ml_models/ddos_model.joblib` | fixed `packet_rate > 200` threshold |
| `backend/detectors/recon.py` | RandomForestClassifier | `backend/ml_models/recon_model_v3.joblib` | fixed `unique_ports > 15 OR unique_hosts > 10` threshold |
| `backend/detectors/c2.py` | RandomForestClassifier, range-gated | `backend/ml_models/c2_model.joblib` | fixed `cv <= 0.35` threshold, **within a validated range only** — see below |
| `backend/detectors/dga.py` | RandomForestClassifier + rule-based tunnel path | `backend/ml_models/dga_model.joblib` | new (Phase 2) |
| `backend/detectors/tls_malware.py` | JA3 blacklist + RandomForestClassifier | `backend/ml_models/tls_flow_model.joblib` | new (Phase 2) |
| `backend/detectors/exfil.py` | Rule-gated RandomForestClassifier | `backend/ml_models/exfil_model.joblib` | new (Phase 2) |

All loaded models fall back gracefully if their `.joblib` file is missing or
fails to load (e.g. scikit-learn absent from the venv) — a live demo failing
outright is worse than briefly running degraded. `c2.py` also falls back to
its rule *by design* outside two specific input ranges its training data
never covered — this isn't a missing-file fallback, it's a deliberate,
verified safety gate (see below). `dga.py`'s rule-based tunnel path keeps
working even with no model loaded; `exfil.py` has no rule-only fallback (see
Phase 2 section) so it's simply silent if its model is missing.

## Features (must match training exactly)

**DDoS** (`backend/detectors/features.py` + `ddos.py`), over the same 10s
rolling window the original rule used:
- `packet_rate` — connections in the window (the rule's only signal)
- `unique_dst_ports`, `dst_port_entropy`
- `mean_inter_arrival`, `std_inter_arrival`

**Recon** (`features.py` + `recon.py`), over the same 60s per-source window:
- `unique_ports`, `unique_hosts`, `connection_count` (the rule's signals)
- `port_entropy`, `port_range_span`
- `mean_inter_arrival`, `std_inter_arrival`

Source-IP entropy / unique source-IP count (the DDoS rule's old *supporting*
evidence) are deliberately **not** model inputs — every packet in the
training capture came from the same loopback address, so that signal was a
zero-variance constant during training. They're still shown in the alert's
evidence list as human-readable context, just never fed to the model.

**C2** (`c2.py`), per `(src, dst, dst_port)` key, capped at the same 20
most-recent observations the detector already keeps:
- `observation_count`, `mean_interval`, `std_interval`, `cv` (the rule's
  own statistic)

## Real-traffic retraining (2026-09-10) — moved in-repo, PS-aligned tooling

DDoS, Recon, and C2 were retrained from scratch inside this repo using an
isolated Zeek capture container (`training/capture/docker-compose.yml`,
container `zeek_ml_capture` — deliberately separate from the live demo's
`zeek_monitor`, so bulk training captures never pollute the production
dashboard) and tooling chosen to match PS 26145's own named methodology:

- **DDoS** (`training/capture/capture_ddos.py`): real **hping3** SYN
  packets (`-S`), matching the PS's "attack traffic from hping3 (SYN/UDP
  floods)" line — but rate-bounded (`-i u<micros>`, `-c <count>`, plus an
  independent subprocess timeout) and never `--flood`. An earlier
  exploration attempt found `sudo hping3 --flood` on loopback can hang the
  machine (no rate limit, attacker and "victim" compete for the same CPU);
  this avoids that failure mode by construction while still using the
  PS-named tool for real. 65 session pairs, 10-300 pps floods spanning both
  above and below the fallback rule's 200/10s threshold.
- **Recon** (`training/capture/capture_recon.py`): real `nmap -sT` scans
  (TCP connect scan — no root needed, identical fan-out signature to a raw
  `-sS` scan as far as Zeek's `conn.log` is concerned). 90 session pairs,
  port-range widths 50-800 at 10-100 pkts/sec.
- **C2** (`training/capture/capture_c2.py`): a small self-built beacon
  emulator — literally what the PS suggests ("a sandboxed C2 emulator for
  realistic beaconing timing"), not an external C2 framework. 65 session
  pairs, 3-6s base interval ±15% jitter, 10-15 beacons per session.
- **Benign traffic** for all three uses plain TCP `connect()` bursts, not
  iperf3/Ostinato/TRex (none installed in this environment; the PS lists
  these as "e.g." examples, not a requirement) — Zeek logs an identical
  real `conn.log` entry per attempt either way, which is the only thing
  the feature set below actually reads.

All three were validated with **GroupKFold cross-validation grouped by
capture session** (never a random row split — adjacent feature rows from
dense time-snapshotting are heavily correlated, so a random split would
leak near-duplicate rows across train/test and produce a meaningless
accuracy number), and scored by **pooled confusion matrix** across all
folds.

| Model | Rows | Sessions | Rule F1 | Model F1 |
|---|---|---|---|---|
| DDoS (RandomForest) | 29,844 | 247 | 0.912 | 1.000 |
| Recon (RandomForest) | 17,674 | 175 | 0.983 | 1.000 |
| C2 (RandomForest, gated) | 31,218 | 144 | 0.839 | 0.998 |&nbsp;†

† C2's row/session count and rule F1 reflect the 2026-09-11 range-extension
capture (see "C2's range gate" section below) layered onto the original
16,262-row/114-session capture -- the rule's F1 dropped from 0.875 to
0.839 because the new c2_slow sessions' real-world timing jitter pushes
some genuinely-c2 rows' CV just past the rule's fixed 0.35 cutoff at
longer intervals, not because the rule regressed on the original range.

DDoS and recon are clean, low-cost improvements: the DDoS rule missed 842
of 6,161 flood rows in validation (pooled confusion matrix; mostly "low and
slow" floods below its fixed rate threshold); the model missed 2. Recon's
rule missed 173 of 5,208 recon rows; the model missed 2. Neither model
produced a meaningful false-positive cost (RF: 3 and 2 false positives
respectively, out of 10,148/12,466 benign rows).

**C2 is a real win with a real trade-off, not a free upgrade**: the rule
misses 2,837 of 12,729 c2 rows (it's an all-or-nothing gate that can't fire
before 5 observations exist), and the model recovers almost all of that —
but at a genuine cost of 126 false positives on benign rows (out of 3,533),
something the rule's strict gate can never produce by construction.

### A real contamination bug found and fixed mid-retraining

The first C2 capture attempt used a port pool (`9080-9110`) chosen without
checking what else was actually listening on this machine. It silently
overlapped the live Kafka broker/controller ports (**9092/9093**) running
as part of this project's own demo stack — confirmed with `ss -tanp`. Since
the isolated capture container uses `network_mode: host` (needed so Zeek
can see loopback traffic at all), it captures *all* host loopback traffic,
not just the generator's own connections — so Kafka's periodic controller
heartbeat got folded into the beacon-timing history. Effect: c2 rows'
median coefficient of variation came out ~0.54 instead of the ~0.09
expected from the intended ±15% jitter, and the rule baseline's recall on
the resulting (contaminated) dataset collapsed to 7.8% — a red flag caught
by comparing against the expected theoretical CV before trusting the
numbers, not assumed away. Root-caused by extracting one full session's raw
timestamps directly from `conn.log`: port 9093 traffic was interleaved with
the session's real beacon port on almost every interval.

**Why recon's dataset (which also doesn't filter by destination port) was
unaffected by the same root cause**: recon's signal is *fan-out breadth*
(hundreds of ports scanned), so 1-2 stray Kafka connections landing in a
15-30s benign window are immaterial noise. C2's signal is the *precise
timing statistics of a handful of events* (10-20 per session) — the same
absolute amount of noise that recon shrugs off is enough to dominate a
sample that small. This is why the corruption was severe for C2 and
invisible for recon/DDoS, not evidence those two are also silently broken.

**Fix**: moved `C2_PORT_POOL` (and, pre-emptively, DDoS's
`FLOOD_PORT_POOL`, before it was ever run) to `19080-19140`, verified free
of any listener on this machine via `ss -tanp`. Re-captured C2 from
scratch; re-verified the fix directly (`cv <= 0.35` now holds for 100% of
c2 rows, median CV 0.078 — matching theory) before retraining. **Lesson for
anyone extending this**: when generating synthetic "real" traffic on a
shared/dev machine for training data, verify the chosen port range against
`ss -tanp | grep LISTEN` first — a loopback-wide capture container has no
way to distinguish "traffic my generator made" from "traffic something
else on this machine made to the same port," and small-sample statistical
features (like C2's) are far more fragile to this than large-sample ones
(like DDoS's or recon's).

## PS 26145 compliance audit (2026-09-11, follow-up 2026-09-12) — gaps closed

The 2026-09-11 audit identified four gaps, documented honestly rather than
silently left. All four were then tackled in a 2026-09-12 follow-up:

- **UDP reflection/amplification + spoofed-source floods**: CLOSED. See
  "UDP/spoofed-source DDoS extension" below.
- **JA4/JA4S fingerprinting**: PARTIALLY CLOSED. `tls_malware.py` now has a
  Path A2 JA4 blacklist lookup, parallel to the real JA3 path, and
  `stream_consumer.py`/`kafka_producer.py` pass `ja4`/`ja4s` fields
  through end-to-end. It ships with an EMPTY blacklist (`ja4_blacklist.json`)
  because no equivalent public JA4 threat-intel feed exists yet (checked
  directly: sslbl.abuse.ch, the source for the real JA3 feed, does not
  publish one) — shipping a fake populated list would be worse than an
  honest empty one wired up and ready. PS 26145 (d)'s "JA3/JA3S or JA4"
  wording is satisfied by the real, working JA3 path regardless.
- **QUIC coverage**: CLOSED, with a scoping caveat. Zeek 8.2.2's native
  `base/protocols/quic` analyzer needed no package install (verified
  directly — an earlier `-N Zeek::QUIC` plugin-name check was testing the
  wrong thing). Real QUIC traffic was generated with `aioquic` (curl in
  this environment has no HTTP/3 support) and verified end-to-end: real
  SNI extraction, real conn.log join, real detector alert. Scoped
  pragmatically given cost: QUIC events are routed through the *existing*
  TLS flow-stats model rather than a new dedicated dataset+training cycle
  (byte-ratio/timing anomalies are a protocol-agnostic malware signal) --
  this is real, working coverage, but not independently validated against
  real QUIC malware traffic the way DDoS/Recon/C2/TLS/Exfil's real-traffic
  retraining was. See "QUIC coverage" below for the byte-field-join timing
  finding this surfaced (`PENDING_MAX_AGE` needed raising from 5s to 30s).
- **Spoofed-source-IP detection**: CLOSED as a trained feature. See "UDP/
  spoofed-source DDoS extension" below — `hping3 --rand-source` on
  loopback was verified to produce genuinely varied, non-local source
  addresses that Zeek captures faithfully, lifting the single-test-host
  constraint that previously made this evidence-only.

## QUIC coverage (2026-09-12)

`zeek/local.zeek` and the training capture configs now `@load
base/protocols/quic`. `stream_consumer.py`'s `normalize_event()` recognizes
quic.log rows (discriminated by the `client_initial_dcid` field, unique to
QUIC among conn/dns/ssl/quic) and extracts `server_name` (real SNI,
extracted from the QUIC Initial packet's ClientHello -- metadata only, no
payload decryption, per PS 26145 (b)'s constraint) plus `version`.
`kafka_producer.py` tails `quic.log` onto a new `zeek-quic` topic.
`tls_malware.py` (now documented as the TLS/QUIC malware detector) accepts
`log_type in ("ssl", "quic")`; QUIC events have no JA3/JA4 equivalent
wired up, so they only ever reach the flow-stats ML path, reusing the
model trained on TLS flows.

**The ssl.log byte-field gap (see below) also applies to quic.log** --
same fix, same `FlowByteEnricher` class (renamed from `SSLByteEnricher`
since it now serves both). **A second, QUIC-specific timing finding**: the
5-second `PENDING_MAX_AGE` tuned for TLS was too short for QUIC. Verified
directly -- a batch join check immediately after generating real QUIC
traffic found 0/35 quic.log rows had a matching conn.log entry yet; the
same check ~15-20s later found the (by-then-fewer, since Zeek had rotated
some out) remaining rows matched 5/5. Zeek's UDP inactivity timeout means
conn.log's entry for a QUIC (UDP) flow flushes noticeably later than
quic.log's own entry (written as soon as handshake parsing completes).
Raised to 30s -- still comfortably "bounded latency" for a security alert,
and long enough to reliably catch the real join.

**Verified end-to-end with real traffic**: real `aioquic` connections to
real HTTP/3 servers produced real `quic.log` rows with real extracted SNI
(e.g. `ssl.gstatic.com`, `accounts.google.com` -- ambient QUIC traffic on
the test machine, not only the explicitly-dialed connections, which is
itself confirmation the analyzer works on organic traffic too), joined
correctly to real conn.log byte/duration data, and correctly triggered a
synthetic-bulk-upload-shaped test alert through the live detector code
path (not just a unit-level feature check).

**Honest scope caveat**: unlike DDoS/Recon/C2/TLS/Exfil, QUIC coverage was
NOT given its own dedicated real-traffic dataset + retraining cycle --
given this session's already-substantial cost, it reuses the existing TLS
flow-stats model as-is. This is a defensible design choice (the underlying
signal -- byte-ratio/timing anomalies -- isn't protocol-specific), not a
validated claim that the model's decision boundary is optimal for QUIC's
specific byte/timing distributions. A dedicated QUIC capture+validation
pass (real benign QUIC traffic's byte/duration distribution may differ
meaningfully from TLS's) would be the natural next step if this needs to
be as rigorously validated as the other five detectors.

## Two production bugs found and fixed during the 2026-09-11 PS-compliance audit

Neither of these is a training-data issue — both were live pipeline bugs
that silently degraded real detection, found while building real-traffic
datasets for TLS and Exfil (below) and fixed at the source.

**1. `ssl.log` has no `orig_bytes`/`resp_bytes`/`duration` fields.** Real
Zeek `ssl.log` rows carry only handshake/certificate metadata (version,
cipher, ja3, server_name, ...) — byte counts and duration live exclusively
in `conn.log`. `stream_consumer.py`'s `normalize_event()` read those fields
off ssl rows anyway (`raw.get("orig_bytes", 0)`), which silently defaulted
to 0 for every real TLS event. `tls_malware.py`'s flow-stats ML path (PS
26145's "packet-size and timing sequences" requirement) never actually saw
real byte/duration data — worse, its own `duration < 0.1 or total_bytes <
100` guard rejected every real event before the model was ever called, so
this path was dead code against any real or replayed traffic; only the JA3
blacklist path could ever fire. **Fixed**: `backend/stream_consumer.py`'s
new `SSLByteEnricher` class joins each ssl.log row to its conn.log
counterpart via Zeek's shared `uid` (the standard cross-log correlation
key), handling both arrival orders (a bounded conn-uid cache for ssl-after-
conn, a short-lived pending-ssl buffer with a 5s event-time timeout for
conn-after-ssl, which is the more common real ordering since Zeek typically
flushes ssl.log at handshake completion, well before the connection —and
therefore conn.log— actually closes). Verified with a standalone unit test
covering all three cases (ssl-before-conn, conn-before-ssl, never-matched).

**2. Zeek on a loopback interface needs `-C` (ignore checksums), and
neither `docker-compose.yml` nor the training capture configs had it.**
Linux defers checksum computation for loopback traffic (the kernel trusts
its own traffic and never bothers computing/validating real TCP/UDP
checksums for `lo`), so libpcap-captured loopback packets carry invalid or
absent checksums. Zeek validates checksums by default and silently produces
zero-byte `conn_state: "OTH"` connection stubs (`orig_pkts: 0`,
`orig_bytes` absent) for packets that fail validation, rather than erroring
— easy to miss entirely. Verified directly: **the live production
`zeek_monitor` container's own `backend/zeek-logs/conn.log` had
`orig_bytes:0` on 212,393 of 212,567 real rows (99.9%)** before the fix.
This silently broke `exfil.py`'s detection for real traffic — its own
`orig_bytes < 1000` early-return meant the detector effectively never ran
on live loopback-captured events — and compounded case 1 above for
`tls_malware.py`. It was never noticed because the dashboard's replay demos
(`/api/replay/<threat>`) use an *offline* `zeek -r <pcap>` read of a
pre-recorded file, which has valid checksums baked in from whenever it was
originally captured — completely bypassing this live-capture-only bug.
**Fixed**: added `-C` to the `zeek` command in `docker-compose.yml` (repo
root, the live pipeline) and both training capture configs
(`training/capture/docker-compose.yml`, verified by direct before/after
test: a real local HTTP GET went from `conn_state: "OTH"`/`orig_bytes`
absent to `conn_state: "SF"`/`orig_bytes: 78`/`orig_pkts: 6`). The live
`zeek_monitor` container was recreated with the fix applied and verified
against fresh real traffic post-restart. `docker-compose-tls.yml` (real
NIC interface, not loopback) did not need it — real network interfaces
must compute genuine checksums for packets to be accepted by the remote
host, so this class of bug is specific to loopback/virtual interfaces.

## UDP/spoofed-source DDoS extension (2026-09-12)

PS 26145 (a) names three DDoS patterns: "SYN floods, UDP reflection/
amplification, and spoofed-source floods." The original DDoS retraining
above only covered the first. Closed by adding two new real session types
to `training/capture/capture_ddos_udp_spoof.py` (65 original SYN-flood
pairs + 40 new pairs, 250 sessions total, 29,844 rows):

- **UDP_FLOOD**: real `hping3 -2` (UDP) packets, single real source,
  targeting ports commonly abused for real-world reflection/amplification
  (53 DNS, 123 NTP) -- rate-bounded the same way as the SYN flood (never
  `--flood`).
- **SPOOFED_FLOOD**: real `hping3 -2 --rand-source` -- verified directly
  that this produces genuinely varied, non-local source addresses that
  Zeek captures faithfully even on loopback (e.g. real-looking addresses
  like `15.106.219.46` appear as `id.orig_h` with `local_orig:false`).
  Real amplification attacks are themselves almost always spoofed-source
  UDP, so this session type provides real evidence for both PS-named
  patterns at once.

This also closes the **spoofed-source-IP detection gap**: `unique_src_ips`
and `src_ip_entropy` were previously evidence-only (the single-loopback-
source test rig made them zero-variance, so they couldn't be trained on).
The `--rand-source` sessions give them real, non-constant signal for the
first time, so they're now genuine `FEATURES` entries in `ddos.py` /
`train_ddos.py`, not just display text. `ddos.py`'s protocol filter also
relaxed from TCP-only to `("tcp", "udp")`. Both new features show real
(if modest, next to `packet_rate`'s dominant 0.44) importance in the final
model: `src_ip_entropy` 0.010, `unique_src_ips` 0.008 -- present, genuine
signal, not noise, appropriately smaller than the primary rate/timing
features since a spoofed flood still floods.

**A real incident during this recapture, worth recording**: the first
attempt silently lost ~70 minutes of capture data. `docker-compose.yml`
(loopback) and `docker-compose-tls.yml` (real interface, used for the
QUIC work below) live in the same directory, so Docker Compose inferred
the *same* default project name for both. Tearing down the TLS container
mid-capture (for an unrelated QUIC verification test) silently killed the
"orphan" loopback capture container too -- logged as a warning at the
time, wrongly dismissed as harmless. Diagnosed by comparing the session
markers' timestamp span against the actual captured conn.log's timestamp
span (75 minutes expected, only 5.5 minutes of real data present) and
confirmed via `docker inspect`/`docker logs` showing a clean SIGTERM
partway through. Fixed by giving both compose files an explicit `name:`,
then re-ran the full capture cleanly. **Lesson**: sibling compose files in
one directory need explicit distinct project names, or tearing down one
can silently kill an unrelated "orphaned" container from the other.

## C2's range gate — two real bugs found and fixed after training

Training and cross-validating the C2 model looked clean (table above). Wiring
it into the live detector and re-testing against realistic and actual demo
traffic surfaced two things the offline validation couldn't have caught,
because the validation could only ever score the model on the region its
own training data happened to cover:

1. **`observation_count` blind spot.** The training data's benign sessions
   (short, sparse by design) never accumulated more than 11 real connection
   events, while c2 sessions routinely reached the full 20-observation cap —
   checking `dataset_c2.csv` directly, *every* row with `observation_count >=
   12` is a c2 example, zero exceptions. A RandomForest given a region with
   no counterexamples just predicts the only class it's ever seen there.
   Verified empirically: 15 observations of clearly irregular (CV~0.6–0.7,
   well above the rule's 0.35 cutoff) synthetic benign traffic false-positived
   28/30 times (93%) on the unrestricted model — nowhere near the ~18% FP
   rate cross-validation reported, because CV could only score count<=11.
2. **`mean_interval` blind spot.** Every c2 training session used a 3-6s base
   beacon interval (kept short so the capture finished in a reasonable
   time) — no c2-labeled row has `mean_interval` above 6.01s. This project's
   own bundled demo asset, `traffic_pcaps/attack_c2.pcap`, beacons every
   ~30s. Replaying it still detected the beacon, but only at ~61% confidence
   (vs. 90%+ for in-range beacons) and later than the earliest possible
   observation — the model extrapolating into a region it was never shown a
   positive example for.

**Fix**: `c2.py` only consults the model while `observation_count <= 11`
**and** `mean_interval <= 7.0` (both constants named and explained in the
module's own docstring). Outside that range it falls back to the original
CV rule, which has neither blind spot because it doesn't depend on having
seen every input value during training. Re-verified after the fix: the demo
pcap now fires immediately and confidently (91%, via the rule) instead of
late and shaky (61%, via the model); the false-positive stress test dropped
from 93% back to 10%, in line with the validated rate; genuine in-range
beacons (3-6s interval) still correctly fire via the model at 90%+
confidence. **Takeaway for anyone extending this**: a clean cross-validation
number only certifies the region of input space your training data actually
covered — check what that region is (and what your actual demo assets look
like relative to it) before trusting a deployed model past it.

**Re-verified against the 2026-09-10 retraining** (see "Real-traffic
retraining" above): `training/train_c2.py` now prints this exact blind-spot
check every run rather than requiring a one-off manual query. Against the
new 16,262-row dataset, both blind spots still hold unchanged — every row
with `observation_count >= 12` is still c2-only (1,366/1,366), and every
row with `mean_interval > 7.0` is still benign-only (91/91) — so `c2.py`'s
existing `MODEL_MAX_OBSERVATIONS=11`/`MODEL_MAX_MEAN_INTERVAL=7.0` gate
constants remain correct with no code change needed.

## C2 range-gate extension (2026-09-11) — closing the blind spots rather than just documenting them

The two blind spots above were real findings, not permanent limitations --
`training/capture/capture_c2_extended.py` closes both with two new real
session types, captured against an isolated Zeek instance the same way the
original data was:

- **benign_long** (60-100s duration, 3-6s mean gap): long enough that some
  real benign sessions genuinely accumulate 12-20 connection events --
  targets the `observation_count>=12` blind spot with real, not
  synthetic, counterexamples.
- **c2_slow** (8-45s base interval, +-15% jitter, 6-10 beacons): targets
  the `mean_interval>7.0` blind spot the same way.

This deliberately does NOT attempt the rule's full nominal 3-600s range in
one pass -- a single 600s-interval session with 10+ beacons would take
over an hour of real wall-clock time by itself (this capture needs actual
time to pass between every beacon, same constraint as the original
capture). 15 pairs (30 sessions, 1,708 raw conn.log lines, 408 real
connection events, ~78 minutes real wall-clock time) were captured, kept
in a separate log directory/sessions file
(`training/zeek-logs-c2ext/`, `sessions_c2_extended.json`) and appended
onto the original dataset via `training/build_dataset_c2_extended.py`
rather than rebuilt from a from-scratch merge -- see that script's
docstring for why: an initial attempt to make `build_dataset_c2.py` read
two conn.log sources directly found that `training/zeek-logs/conn.log`
(a single file shared across every ddos/recon/c2/tls/quic capture
campaign this project has run) had its original C2-session raw evidence
silently overwritten by later, unrelated campaigns that reused the same
Zeek container/log path -- a real, previously-undiscovered gap in this
project's own capture hygiene, caught only because rebuilding from
scratch produced zero matching events on the C2 port pool where hundreds
were expected. `training/dataset_c2_original.csv` is now a frozen
snapshot of the already-validated, git-committed 16,262-row dataset
specifically so future extensions never depend on that raw evidence
still being recoverable.

**Re-verified with the same methodology that found the original gap**:
- Both blind spots are closed at the dataset level: `observation_count>=12`
  now has 4,056 rows with **both** labels present (previously c2-only),
  and `mean_interval>7.0` now has 10,683 rows with **both** labels present
  (previously benign-only).
- The retrained model's held-out F1 **within just the newly-covered
  region** is 1.000 (704 test rows for `observation_count` 12-20: 400 TP,
  304 TN, 0 FP, 0 FN; 3,379 test rows for `mean_interval` 7-45s, entirely
  c2-labeled in this particular random test split but still 0 errors) --
  no degradation relative to the original range.
- **The 93%-false-positive stress test was re-run against the new region**
  (clearly-irregular, CV 0.6-0.9 synthetic benign-intent traffic fed
  directly to the retrained model): 0/100 false positives for
  `observation_count` 12-20 combined with `mean_interval` 7-45s, and 0/100
  even when probed at `mean_interval` 45-100s -- **beyond** the captured
  range. Feature importances on the retrained model (`cv`=0.599,
  `std_interval`=0.200, `mean_interval`=0.195, `observation_count`=0.006)
  show `cv` remains overwhelmingly dominant, consistent with the model
  having learned a genuine, largely scale-invariant regularity rule rather
  than memorizing the old training box -- which is the most likely reason
  the stress test came back clean even slightly past the captured 45s
  boundary. That result is reassuring but not itself validation: the gate
  constant is still set to what was actually captured (45.0s), not
  extended further on the strength of one synthetic probe.
- `backend/detectors/c2.py`'s gate constants were updated accordingly:
  `MODEL_MAX_OBSERVATIONS` 11→20 (now equal to the detector's own
  observation-history cap, so no longer a binding constraint in practice --
  kept as a named constant so the range-validation intent stays documented)
  and `MODEL_MAX_MEAN_INTERVAL` 7.0→45.0 (matching exactly what was
  captured and stress-tested, not the rule's own 600s theoretical
  ceiling).

**What this does NOT claim**: the model is not validated for beacons
slower than 45s (up to the rule's 600s design ceiling), which still falls
back to the original CV-threshold rule -- unchanged, and still correct
there since it has no training-coverage dependency. Closing that remaining
gap would need a longer capture budget (hours, not ~80 minutes) run the
same way.

## DGA benign-distribution gap found via live ambient traffic (2026-09-11)

Running the live demo pipeline against this machine's own ordinary background
DNS traffic (not synthetic, not a deliberate attack) surfaced a real,
significant false-positive source: within minutes, the DGA detector flagged
**498 of 500 total alerts** as `DGA / DNS Tunnelling`, all from completely
legitimate queries -- `time.cloudflare.com` (Cloudflare's NTP-over-HTTPS
check), `api.globalping.io` (the `globalping-probe` service also running on
this machine), `main.vscode-cdn.net` (VS Code), and
`http-intake.logs.us5.datadoghq.com` (a Datadog agent) -- at 95-100%
confidence, repeating every few seconds with no dedup.

**Root cause, verified directly**: the bare apex domain alone
(`cloudflare.com`, `globalping.io`) scored correctly low (~0.002), but the
*identical* domain with an ordinary subdomain prefix scored high
(`time.cloudflare.com` 0.950, `api.globalping.io` 0.978). `gen_benign()` in
`training/train_dga.py` only ever produced a bare `word.tld` -- a single
label, always a real dictionary word, directly under the TLD. Real DNS
traffic is overwhelmingly `subdomain.domain.tld` or deeper; the benign
training class had **never once** included that shape, so the model was
extrapolating on nearly every real-world query it saw, not just some
fraction -- the same category of bug as the C2 range-gate blind spot found
earlier this session, just far more consequential here because the gap
covers the common case rather than an edge case.

A second, compounding gap: some apex domains that aren't literal English
dictionary words (`datadoghq`, `vscode-cdn`) scored as DGA-like even in the
exact bare-apex training shape, because `gen_benign()`'s benign class was
built exclusively from real dictionary words, never real-but-uncommon brand
names.

**Fix**: `training/train_dga.py` gained `gen_real_domain_traffic()` -- real,
well-known domains (Google, Cloudflare, GitHub, Anthropic, Vercel, ~75
entries, not synthetic dictionary words) combined with realistic subdomain
prefixes (`www`, `api`, `cdn`, `mail`, `us5`, `http-intake`, ~50 entries) at
varying depths (bare apex / one subdomain / two), added as 6,000 additional
benign rows alongside the original `gen_benign()` output. `backend/detectors/
dga.py`'s `KNOWN_TLDS` also gained five modern legitimate TLDs (`ai`, `dev`,
`app`, `so`, `me`) after a held-out real domain (`api.notion.so`, not in the
curated list) still false-positived at 95.6% post-retrain -- DGA/botnet
operators overwhelmingly favor cheap, bulk-registerable ccTLDs
(`.ru`/`.cn`/`.info`/`.biz`/`.top`/`.xyz`, all still absent from
`KNOWN_TLDS`) over these curated, stricter-registration ones, so this is not
expected to meaningfully help malicious domains evade detection.

**Re-verified, not just re-trained**: held-out F1 unchanged at 0.994 (no
accuracy regression on the original malicious families). Directly tested
against the four real domains that caused the flood plus five additional
real, popular domains **deliberately excluded from the training list**
(`cdn.discordapp.com`, `static.xx.fbcdn.net`, `app.slack.com`,
`api.stripe.com`, `registry.npmjs.org`) as a genuine generalization check,
not a memorization check -- all nine cleared at <0.1% confidence. Three
real malicious-shaped strings (a random DGA-style string, a Suppobox-style
dictionary-DGA domain, and a random string on a suspicious TLD) all still
correctly fired at 100% confidence -- zero false negatives introduced.

**Defense in depth, independent of the accuracy fix**: `dga.py`'s Path B
(the ML classifier, not the tunnel rule) also gained a per-`(src_ip, query)`
300-second cooldown, matching `ddos.py`/`recon.py`'s existing event-time-keyed
cooldown idiom -- even a genuinely-anomalous domain that legitimately
repeats (e.g. a real misconfiguration, not just this bug) shouldn't flood
the alert feed once every few seconds. Path A (the tunnel rule) is
deliberately NOT gated by this, since each tunnel query carries its own
distinct encoded payload by construction -- per-query dedup there would
suppress genuinely new evidence, not repeat noise. Verified directly: a
repeated malicious-shaped query alerts once, is suppressed within the
300s window, and alerts again once the window passes.

**What this does NOT claim**: this is not a claim of zero false positives
against arbitrary real-world traffic -- only that the specific, verified
gap (common subdomain shapes of well-known and popular-but-untrained-on
domains) is closed. A sufficiently obscure or newly-registered legitimate
domain with an unusual shape could still trigger a false positive; this
prototype has no live domain-reputation feed to fall back on, only the
generalization the retrained model has learned from ~150 curated
domain/prefix combinations. Widening coverage further would mean training
against a real top-domains list (e.g. Tranco) rather than a hand-curated one.

## Honest limitations (carried over from validation, not fixed by deploying)

- **Single test host**: all three training captures ran entirely against
  `127.0.0.1` — `unique_hosts` contributed ~0 importance to the recon model
  for exactly this reason. Real multi-host attack traffic is untested.
- **One generator per class**: `nmap -sT` for recon, real rate-bounded
  `hping3` SYN packets for DDoS floods (see "Real-traffic retraining"
  above for why it's never `--flood`), a scripted fixed-interval+jitter
  beacon emulator for C2. A different tool's timing signature is
  unvalidated for any of the three.
- **Row count is not independent-sample count.** Row count comes from
  dense time-snapshotting within each session; the real diversity is the
  session count (130 / 175 / 114). Don't quote a row count as if it were
  sample size.
- **C2's validated range is narrower than the rule's own design range.**
  The rule was always designed to handle beacons anywhere from 3s to 600s
  apart; the model is only trusted from 3-7s. That's not a bug to fix by
  raising the cap — it's a direct consequence of how short the training
  captures were kept, and would need longer/more varied captures to close.

## Replay for demo (`/api/replay/<threat>`)

`traffic_pcaps/*.pcap` are pre-recorded per-threat traffic samples. Pressing
"Replay <Threat> Traffic" (Threat Analysis page) has Zeek re-read that pcap
**offline** (`zeek -C -r`, inside the already-running `zeek_monitor`
container, in its own scratch directory) and appends the resulting log
lines into the *live* logs the real pipeline already tails — so a replayed
event flows through the exact same Kafka → detector → alert path as real
traffic, with the model scoring it for real.

This deliberately does not use `tcpreplay`: that needs raw-socket privileges
and passwordless `sudo` to run unattended from the backend, which can't be
relied on to work in front of a jury. Reading the same pcap offline with
Zeek produces byte-identical log output with no such dependency. Every
injected log file shares one global timestamp shift (from the earliest
timestamp across all of them) so the earliest lands at "now" while
preserving the pcap's original relative spacing — otherwise a years-old
baked-in timestamp would break every detector's rolling-window cutoff math.

**2026-09-12 fixes, found while adding TLS/exfil replay pcaps:**
- The endpoint originally injected only `conn.log`, on the assumption every
  detector reads it. True for ddos/recon/c2/exfil, false for dga (needs
  `dns.log`'s `query`/`qtype_name`/`answers`) and tls (needs `ssl.log`'s
  `ja3`/`ja4` joined to `conn.log`'s byte counts via `FlowByteEnricher`).
  The DGA pcap had been wired into `REPLAY_PCAPS` a session earlier under
  this same conn.log-only assumption — it silently never reached the DGA
  detector's dns branch. Fixed by reading back and injecting whichever of
  `conn.log`/`dns.log`/`ssl.log`/`quic.log` the pcap actually produced.
- The endpoint's own offline `zeek -r` was missing `-C`, so it hit the
  *exact* checksum-offload bug documented below for the live `-i lo`
  process, just never noticed because the pre-existing ddos/recon/c2/dga
  pcaps are header-only (scapy-crafted, no real payload) and don't depend
  on byte counts. It only surfaced once a pcap with real payload bytes
  (attack_tls_malware.pcap) needed `ssl.log` to actually get written.
  Fixed by adding `-C` to the replay's `zeek -r` invocation too.

**`attack_tls_malware.pcap` / `attack_exfil.pcap` (2026-09-12):** unlike the
other four demo pcaps (scapy-crafted, header-only packets — fine for
detectors that key off rate/fan-out/timing/query-name), the tls and exfil
detectors gate on and classify from real byte counts, so a header-only
pcap would report 0 bytes and never reach either model. These two are real
captured traffic instead: a throttled ~800KB HTTPS/HTTP upload from curl to
a local loopback sink, captured via a temporary `zeek -i lo -w` trace
process running alongside the live one. `--limit-rate 300000` (~2.5s
transfer) was chosen after a first attempt at `--limit-rate 20000` (~40s)
reliably produced `truncated_tcp_payload`/`above_hole_data_without_any_acks`
weirds and an incomplete TLS handshake — two Zeek processes sharing
loopback for tens of seconds drop packets under this setup; ~2.5s is short
enough to avoid that while still clearing both detectors' `duration < 0.1s`
reject guard. Verified directly against `TLSMalwareDetector.process()` and
`ExfilDetector.process()` (HIGH severity, 0.99 confidence, both calibrated)
before being committed. See `traffic_pcaps/generate_pcaps.py`'s trailing
comment for the exact repro steps.

## Phase 2 detectors (DGA, TLS, Exfil) — reworked 2026-09-11 with real data where feasible

Originally 100% synthetic (see git history for the earlier version of this
section). Reworked in the same session as the DDoS/Recon/C2 real-traffic
retraining above, closing as much of the "no real-capture cross-check" gap
as ethically/practically possible:

- **DGA**: still fully synthetic (no ethical way to run real malware DGA
  code), but the generators now reproduce the publicly-documented
  *algorithmic shape* of real DGA families (Conficker, Cryptolocker, Zeus
  GameOver, Necurs, Tinba, Ramnit, Banjori, Suppobox, Matsnu) instead of one
  generic random-string generator — see `training/train_dga.py`'s
  docstring. This is what PS 26145's own suggested methodology ("DGA
  samples from published algorithms, e.g. via DGArchive") looks like
  without DGArchive's registration-gated dataset itself.
- **TLS flow-stats**: benign class is now REAL — actual HTTPS requests to
  ~142 diverse real domains, captured and joined via Zeek's `uid` (see the
  SSLByteEnricher bug/fix below). Malicious class stays synthetic (no
  ethical real-malware-traffic source), reshaped with deliberate overlap
  against the real benign distribution instead of the old non-overlapping
  numeric ranges.
- **Exfil**: majority REAL — real local asymmetric HTTP transfers (small
  GET vs multi-MB POST), real ICMP pings with large payloads, and real UDP
  bursts to real public DNS resolvers (8.8.8.8/1.1.1.1/9.9.9.9), topped up
  with a synthetic minority for class balance/volume. See
  `training/build_dataset_exfil.py`'s docstring for the full breakdown and
  the Zeek checksum-offload bug this capture surfaced (below).

| Model | Training data | Rows | GroupKFold F1 | Held-out F1 |
|---|---|---|---|---|
| DGA (`dga_model.joblib`) | 6000 synthetic benign + 13,000 synthetic DGA across 9 published-algorithm families, grouped by length bucket | 19,000 | 0.987 (mean per-fold) | 0.99 |
| TLS flow-stats (`tls_flow_model.joblib`) | 9,530 REAL benign (real HTTPS to 142 domains) + 9,530 synthetic malicious, grouped by domain | 19,060 | 0.9996 | 1.00 |
| Exfil (`exfil_model.joblib`) | 7,001 REAL rows (5,600 benign + 1,401 exfil-shaped: high-upload/ICMP/DNS) + 8,500 synthetic top-up, grouped uniquely per row | 15,501 | 1.000 | 1.00 |

**Why DGA's F1 dropped from a suspicious 1.00 to a more credible 0.987**:
the old single-generator dataset was trivially separable; with 9 distinct
real-algorithm-shaped families (some, like BANJORI's low-mutation pattern,
genuinely closer to benign dictionary words on several features), the
classifier has to do real work — a lower, more honest number here is a
*better* sign than the old perfect one, not a regression.

**TLS/exfil's near-perfect F1 is more legitimate than it looks**: unlike
the old fully-synthetic datasets (whose separability was a generator
artifact), TLS's real benign class is genuinely small/symmetric web traffic
and exfil's real "attack-shaped" class is genuinely multi-MB/asymmetric —
the gap between those is a real property of the traffic, not a synthetic
non-overlapping-range trick. Still worth treating cautiously: the
malicious/attack-shaped classes for both remain generator-shaped (TLS
entirely synthetic; exfil's real portion mimics obvious patterns like bulk
uploads, not a sophisticated attacker actively trying to blend in).

**DGA detector specifics:**
- Rule-based tunnel path (`detection_path: TUNNEL`) needs no model and is
  always active — it's a straightforward length/payload-ratio check, not ML.
- `word_boundary_score` (fraction of a query decomposable into real English
  words from `backend/data/english_wordlist.txt`, built from the system
  `/usr/share/dict/words`, 73,445 words) is what separates `DICT_DGA` from
  `RANDOM_DGA` — verified manually: `sunshinevalleycloud.com` → `DICT_DGA`,
  `xjkqmzpwl.ru` → `RANDOM_DGA`, `google.com` → no alert.
- `trigram_model.json` (6,989 English trigrams, log2 probabilities) is built
  by `scripts/build_trigram_model.py` from the same system dictionary.

**TLS detector specifics:**
- The JA3 blacklist (`backend/data/ja3_blacklist.json`) is real, live data —
  97 entries pulled from `sslbl.abuse.ch`'s public feed via
  `scripts/download_ja3_blacklist.py` — not synthetic. One parsing pitfall
  worth flagging for anyone re-running it: the feed's own CSV header line
  (`ja3_md5,Firstseen,Lastseen,Listingreason`) is itself prefixed with `#`,
  same as the file's purely decorative banner comments — a naive "skip every
  `#` line" filter silently produces zero parsed rows. The script explicitly
  captures that one commented header line before filtering the rest.
- The blacklist path only ever matches once the `ja3`/`ja3s` Zeek fields are
  populated, which requires `zkg install zeek/salesforce/ja3` on the actual
  Zeek deployment (not done as part of this coding session — it needs a real
  Zeek install to run against, not just the Python side). Until then, ssl.log
  rows flow through fine with `ja3=""`, and the flow-stats ML path (which
  doesn't need JA3) still works.

**Exfil detector specifics:**
- No fixed-threshold fallback rule exists (unlike ddos.py/recon.py/c2.py) —
  if `exfil_model.joblib` fails to load, the detector is silently disabled
  rather than running on the byte-ratio rules alone, which the design docs
  judge as too noisy to run standalone. This is a deliberate scope choice,
  not an oversight — flag it if judges ask why exfil has no "ORANGE" degraded
  state the way the others do.

## Cross-cutting change: `log_type` filtering (Phase 2 wiring)

Adding DNS and SSL events to the pipeline (`kafka_producer.py` now tails
`dns.log`/`ssl.log` onto `zeek-dns`/`zeek-ssl`; `stream_consumer.py`
subscribes to all three topics) meant every detector — including the
original three — now receives every event type, not just conn.log rows.
`ddos.py` was accidentally safe already (its `proto != "tcp"` check filters
out DNS/SSL events, which lack a `proto` field). `recon.py` and `c2.py` were
not: before Phase 2, both would have started treating DNS queries and TLS
handshakes as recon fan-out / beacon observations, double-counting
connections `conn.log` already reports and drifting their behavior. Both
now start `process()` with `if event.get("log_type", "conn") != "conn":
return None`, added specifically for this reason and verified with a
regression test feeding synthetic DNS/SSL events to all six detectors.

## Phase 3: Platt calibration — now all 6 models

`calibration/calibrate_models.py` fits a Platt-scaling (sigmoid)
`CalibratedClassifierCV` on top of each base RandomForest, using the
`<name>_cal_data.npz` hold-out split each training script persists.
Originally only DGA/TLS/Exfil had one (DDoS/Recon/C2 were trained outside
this repo and never persisted a split here). Since the 2026-09-10
retraining moved all six models' training in-repo, `train_ddos.py`/
`train_recon.py`/`train_c2.py` now persist a calibration split the same
way `train_dga.py`/`train_exfil.py`/`train_tls_flow.py` already did — so
`calibrate_models.py` picked all six up automatically, with no code change
(it looks for the file, not a hardcoded list).

| Model | Calibrated? | Max confidence shift vs base | File |
|---|---|---|---|
| DDoS | Yes | 0.250 (see caveat below) | `ddos_model_calibrated.joblib` |
| Recon | Yes | 0.266 (see caveat below) | `recon_model_v3_calibrated.joblib` |
| C2 | Yes | 0.172 (see caveat below) | `c2_model_calibrated.joblib` |
| DGA | Yes | 0.396 (see caveat below) | `dga_model_calibrated.joblib` |
| TLS flow-stats | Yes | 0.239 (see caveat below) | `tls_flow_model_calibrated.joblib` |
| Exfiltration | Yes | 0.052 | `exfil_model_calibrated.joblib` |

**Five of six exceed the 0.15 sanity bound** the calibration script warns
on (all but Exfiltration). Read plainly, not hidden: each base model's raw
`predict_proba` was overconfident by up to ~25-40 percentage points
relative to its own held-out set, and Platt scaling corrected that — in the
direction of being *more* honest, not less. For DDoS/Recon/C2 this is a
real finding from the 2026-09-10 retraining (their calibration sets are the
real-traffic hold-outs described in "Real-traffic retraining" above —
genuine sessions, not synthetic stand-ins — so the shift reflects an actual
property of these RandomForests being overconfident near their decision
boundary, not a data-quality artifact). DGA's shift grew substantially
(0.091 → 0.396) after the 2026-09-11 rework replaced one trivially-
separable generator with 9 published-algorithm-shaped families (see "Phase
2 detectors" above) — a harder, more realistic dataset genuinely has more
decision-boundary uncertainty for Platt scaling to correct, consistent with
DGA's held-out F1 also dropping from a suspicious 1.00 to a more credible
0.99. TLS's shift is similarly a real finding now that its benign class is
genuine real traffic, not a synthetic stand-in. Exfiltration's small shift
(0.052) is consistent with that detector's exceptionally clean real
separation (see above). The likely cause across the five larger-shift
models is the same: `RandomForestClassifier`s trained on cleanly-separable
data tend to output extreme probabilities (near 0 or 1) even where genuine
uncertainty exists — Platt scaling pulls those back toward the model's
actual observed accuracy. A larger, more behaviorally diverse capture (more
distinct attack tools/timings per class, not just more sessions/rows of the
same few generators) would be the way to shrink this further.

Each of the six detectors' `_load_model()` checks for
`<name>_model_calibrated.joblib` first and falls back to the base
`.joblib` if it's absent — now all six use their calibrated file.
`Detector.alert()` carries a `calibrated: bool` field so the dashboard
(and anyone inspecting `/api/alerts`) can tell which happened per-alert;
the fixed-threshold/CV fallback rules (used only when a model fails to
load) always report `calibrated: false`, since there's no model backing
that decision to calibrate in the first place. Reliability diagrams (base
vs. calibrated, 10-bin) for all six calibrated models are in
`docs/calibration_plots/`.

## Phase 4: adaptive entropy baseline for DDoS's fallback rule

The ML path (used whenever `ddos_model.joblib`/`ddos_model_calibrated.joblib`
loads successfully — the normal case, F1=1.000) is untouched by this: its
trigger condition is exactly what it was before. What changed is the
**fallback rule**, used only if the model fails to load. It used to be a flat
`packet_rate > 200` cutoff — vulnerable to the same flash-crowd false-positive
problem any fixed-rate threshold has. `AdaptiveEntropyBaseline`
(`backend/detectors/ddos.py`) replaces it: a rolling 600-second (event-time,
not wall-clock — same reasoning as the Phase 1 cooldown fix) window of
observed dst-port-entropy values, flagging a new value anomalous only when it
deviates more than 2 standard deviations from that rolling mean. Below 10
observed samples it falls back to a fixed `entropy < 1.5` sanity check rather
than dividing by an unstable stdev.

Verified directly (model forced unavailable to exercise the fallback path):
a synthetic "flash crowd" — high-volume traffic sharing the *same*
port-entropy distribution as the established baseline — produced zero
false alerts once the baseline had warmed up (20 samples), while a
genuine entropy-shift attack (same volume, materially different port
distribution) fired correctly at 3.4 sigma deviation. The `sigma_deviation`
value is also surfaced as an evidence line (`"Entropy deviation from rolling
baseline: {sigma}sigma"`) on every DDoS alert regardless of which path
(ML or fallback) triggered it — genuine demo value, without claiming it
gates a decision it doesn't gate on the ML path.

## Phase 5: cross-threat correlation engine, and a new cross-cutting `event_ts` field

`backend/correlation/correlator.py`'s `CorrelationEngine` watches the alert
stream (not raw events) for four hardcoded multi-vector patterns per
source IP: `KILL_CHAIN` (recon+c2+exfil, 600s, confidence 0.97),
`C2_EXFIL` (c2+exfil, 600s, 0.92), `DGA_C2` (dga+c2, 120s, 0.88),
`RECON_DDOS` (recon+ddos, 300s, 0.85). A match emits a second, separate
`MULTI_VECTOR` alert alongside — never instead of — the individual alerts
that triggered it. `stream_consumer.py` feeds every detector-produced alert
through `correlator.ingest()` right after writing it.

**First version keyed correlation windows on wall-clock ingest time; a code
review caught that this was wrong for this project's own primary demo
mechanism.** `/api/replay/<threat>` (see below) makes Zeek reprocess a pcap
*offline* and drains the resulting log lines through Kafka back-to-back —
so wall-clock time for an entire multi-stage attack pcap collapses into a
few real seconds, regardless of how far apart the events actually were on
the pcap's own timeline. Keying correlation on wall-clock time would have
made every pattern's window trivially "look" satisfied during any replay,
which defeats the actual point of having per-pattern windows at all — and
is the exact same category of bug `ddos.py`'s cooldown and
`AdaptiveEntropyBaseline` already hit and fixed (Phase 1, Phase 4) by
switching from wall-clock to the event's own `ts`.

Fixed by adding a new field to `Detector.alert()`'s contract: `event_ts`,
the originating event's own clock value (distinct from the existing
`timestamp` field, which stays wall-clock — "when this alert was emitted,"
used for display/sort order). All six detectors' `alert()` call sites now
pass it (`dga.py`/`exfil.py`/`tls_malware.py` didn't previously extract
`event["ts"]` at all, since they didn't need it before this). The
correlator windows and prunes on `event_ts`, not `time.time()`.

**Second review finding, also fixed (and then fixed again — see below):**
the first version re-evaluated all four patterns from scratch on every
`ingest()` call with no memory of having already fired — a still-active
kill chain (its contributing alerts still inside the window) would
re-emit a fresh `MULTI_VECTOR` alert on *every* subsequent qualifying
alert from that source, flooding `alerts.json` with duplicates of the
same correlated finding.

The first fix attempt used a flat `{(src_ip, pattern_name):
last_fired_event_ts}` cooldown — same idiom as `ddos.py`/`recon.py`/`c2.py`'s
per-source cooldowns, just keyed on (source, pattern). **A second review
round caught that this was itself wrong**: a purely time-based cooldown
can reuse a stale, already-used alert to "re-earn" a *different* pattern,
which then burns that pattern's own cooldown and can silently suppress a
second, genuinely independent, fully-formed attack chain from the same
source arriving shortly after the first — a false negative in an engine
whose entire job is catching multi-stage attacks, which is worse than the
duplicate-flooding it was meant to fix. Fixed properly: dedup now tracks
*which specific alerts* (`flow_id`) contributed to a pattern's last
firing, and only suppresses a new match when every contributing alert
this time was already used last time — any new alert instance (even one
new one) is enough to re-fire. Verified against the reviewer's own
reproduction: two back-to-back independent kill chains from the same
source, sharing one stale contributing alert, both alert; a literal
re-ingestion of the same alert does not.

**Third finding, also fixed twice:** `_history`'s per-source list was
pruned to empty but the dict key never removed — a slow memory leak for a
source that alerts once and goes idle. The first fix (delete-on-empty
inside the single-source `_prune`) turned out to be dead code: `_prune`
only ever ran on the source that had just appended a brand-new record, which by
construction always survives its own cutoff, so the empty-list branch
could never actually trigger for the case that matters (an *idle* source
whose alerts age out while nothing new arrives from it). Fixed by sweeping
*every* tracked source's history (and `_fired` entries) on each `ingest()`
call, not just the ingesting alert's own source — so idle sources are
actually reclaimed as event time advances via any traffic, not only via
their own future alerts.

Verified with a direct unit test suite (not integration-tested against a
live Kafka/Zeek stack in this session): all four patterns fire correctly
using event time; a pattern spanning more event-time than its window does
not fire even when ingested back-to-back in wall time (the pcap-replay
scenario this exists to handle); a second, independent attack chain from
the same source is not silently suppressed even when it shares one stale
alert with the first; a literal duplicate alert is still correctly
suppressed; an idle source's history and cooldown state are both actually
reclaimed once other traffic advances event time past its window.

## Phase 6/7: dashboard honesty fixes, and the real throughput number

Phase 6 (dashboard completion) surfaced a cluster of stale claims left over
from before Phase 2 built the DGA/TLS/exfil detectors: `AlertFeed.jsx`'s
`THREAT_META`, `ActiveDetectors.jsx`'s hardcoded 3-detector list,
`ThreatChart.jsx`'s distribution categories, and — most significantly —
`ThreatCoverageMatrix.jsx`/`threatMatrix.js` and two prose strings in
`ArchitecturePage.jsx`/`pipelineStages.js` still said three of six threat
classes were "designed, not built." All fixed to reflect that all six now
run for real, with the honest real-pcap-vs-synthetic-data distinction kept
front and center instead of the stale built-vs-not framing. A new
`GET /api/detector_status` endpoint (`app.py`) backs a live green/orange/red
status grid in `ActiveDetectors.jsx` — checks calibrated-then-base model
path per detector (matching each detector's own `_load_model()`), never
hardcodes "ok". A new `ThroughputSparkline.jsx` (hand-rolled inline SVG, no
new charting dependency — this project had none and one 60px axis-less
sparkline didn't justify adding one) samples `/api/throughput` on its own
timer so a flat/idle reading still shows as a flat line, not an empty chart
forever waiting for its first change (an earlier version only recorded a
sample when the value differed from the last one, verified by live-testing
in a browser with no pipeline running — confirmed the bug, then fixed it).

Phase 7 (throughput benchmark) could not measure a real Kafka-broker
round-trip — no broker was running in this environment (port 9092
unreachable, no container up), and this repo's `docker-compose.yml` isn't
set up for a headless CI-style benchmark run. `scripts/benchmark_throughput.py`
measures the Python detection pipeline's own processing throughput instead
(the same per-event `for detector in detectors: detector.process(event)`
loop `stream_consumer.py` runs), documented explicitly as not a Kafka
number. Two real things were found while building it, both worth keeping
in mind for anyone touching `ddos.py`/`recon.py`/`c2.py` again:

1. **A first version of the synthetic benchmark stream used unrealistically
   dense timestamps** (~0.01s apart), which made `ddos.py`'s and `recon.py`'s
   rolling windows (both unbounded until events age out past `WINDOW_SECONDS`)
   grow to thousands of entries, and the per-event entropy/interval
   recomputation over that window dominated cost — an artifact of the
   generator, not a real finding about the pipeline. Fixed by spacing
   synthetic timestamps at 0.5-3.0s, matching realistic background-traffic
   density.
2. **With that fixed, the real bottleneck turned out to be scikit-learn's
   per-call inference overhead, not this codebase's Python logic at all.**
   Isolated measurement: a single `RandomForestClassifier.predict()` +
   `.predict_proba()` pair on one sample costs ~12ms in this environment
   (scikit-learn 1.9.0) — and `ddos.py`/`recon.py`/`c2.py` each make that
   exact pair of calls per qualifying conn event. Measured sustained
   throughput: **44.8 flows/sec** (10,000 synthetic events, 223.3s
   elapsed, 1,481 alerts produced, 12-core Intel i7-1255U laptop). Full
   numbers, including per-detector latency for one complete triggering
   sequence per detector, in `docs/benchmark_results.json`.
3. **A code review then caught that the per-detector latency numbers for
   DDoS and recon didn't measure what they claimed to.** The synthetic
   "attack" sequences never actually crossed either model's real decision
   boundary: `_ddos_attack_events` cycled the destination port across 500
   values (high port diversity reads as scan-like traffic, not a flood, to
   a model trained on `dst_port_entropy` as a feature), and
   `_recon_attack_events` fixed `dst_port=22` for every connection
   (`unique_ports=1` reads as ordinary single-service traffic, not a
   scan). Confirmed directly by loading the real `.joblib` models and
   feeding them the exact feature vectors those sequences produced —
   both predicted benign. Fixed by rebuilding both sequences against the
   actual models (verified `predict_proba` crosses >99% confidence): DDoS
   now floods a single port; recon now scans many ports on one host.
   `benchmark_per_detector_latency()` also now asserts every detector's
   sequence fires at least once across all samples and raises loudly if
   one doesn't, so this specific failure mode can't silently regress
   again. Corrected numbers: DDoS 40.8ms, recon 81.6ms (both dropped
   sharply from the wrong numbers, since a firing sequence short-circuits
   via `any()` the moment the model's decision boundary is crossed,
   rather than running every event in the sequence to no effect).

## Packet-size/timing sequences, independent QUIC training, and real-tool validation (2026-09-13)

Three PS 26145 gaps closed in one pass, each validated against real generated traffic, not just implemented and assumed correct.

### 1. Packet-size and timing sequences (PS 26145 (d), literal wording)

`zeek/scripts/pkt_seq.zeek` (new) tracks the first 12 packet sizes and
inter-arrival gaps per SSL/QUIC connection, logged to a new `pkt_seq.log`
stream, tailed onto a new `zeek-pktseq` Kafka topic
(`kafka_producer.py`), and joined into the TLS/QUIC detector's event by
`uid` (`FlowByteEnricher` in `stream_consumer.py`, extended alongside its
existing byte-count join — opportunistic, not a dispatch gate: a flow
dispatched before its pkt_seq row lands just gets empty sizes/gaps).
`TLSMalwareDetector._flow_features()` now summarizes these as
mean/std of packet size and inter-arrival gap, plus a packet count and an
`is_quic` indicator -- 6 new features alongside the original 6 byte-volume
ones.

Two real bugs found writing and validating this script against real
traffic (not caught by design review, only by testing against real Zeek
output):
- Zeek's QUIC analyzer calls `delete c$quic` immediately after logging
  quic.log's own row -- well before `connection_state_remove` fires for a
  UDP flow -- so checking `c?$quic` at removal time is always false.
  Every real QUIC connection silently produced zero pkt_seq.log rows
  until this was caught. Fixed by tagging protocol opportunistically
  during `new_packet` instead (while the field still exists), cached on
  the connection record.
- QUIC's handshake embeds a genuine TLS 1.3 handshake in its CRYPTO
  frames, and Zeek's QUIC analyzer runs its own embedded SSL analyzer to
  parse it -- confirmed directly via a real QUIC connection's conn.log
  showing `"service":"quic,ssl"`, both analyzers engaged. Checking
  `c?$ssl` before `c?$quic` therefore mislabeled every real QUIC
  connection as "ssl". Fixed using the packet's own transport header as
  the disambiguator: real plain TLS is always TCP, so an SSL-analyzer
  match on a UDP packet can only be QUIC's embedded handshake.

Retrained `tls_flow_model` on the resulting 12-feature vector (dataset
rebuilt by `training/build_dataset_tls.py`, real benign rows unchanged in
source, synthetic malicious rows now also carry matching synthetic
packet-sequence shapes -- tight/regular for beacon-style, near-MTU/low-
variance for bulk-upload-style, generated for both protocols so `is_quic`
can't become a label shortcut). Pooled GroupKFold F1 0.9998. Feature
importances confirm the new features are doing real work, not just
present: `pkt_count` (0.198) and `pkt_gap_std` (0.170) rank 2nd and 3rd,
ahead of every original byte-volume feature except `resp_bytes`.
Concretely verified: a synthetic malicious flow with byte_ratio ≈ 1.1 (a
shape the pre-2026-09-13 model would have scored as benign on volume
alone) is now flagged HIGH/0.99 confidence purely from its regular
packet-size/timing cadence -- real, new detection capability, not just a
compliance checkbox.

### 2. Independent QUIC training data (closes a documented gap)

`training/capture/capture_quic.py` (new) fires real aioquic handshakes
(`quic_client.py`) at ~25 real HTTP/3 hosts (Google, Cloudflare, Discord,
etc.) via the external-capture container (`docker-compose-tls.yml`) --
375 attempts, 268-270 real successful QUIC sessions per run. Previously
the TLS/QUIC model had **zero** real QUIC training rows; QUIC events at
inference time were scored by a model trained purely on TLS ssl.log rows
and hoped to generalize (an explicit, honest caveat that shipped in
`tls_malware.py`'s docstring). The rebuilt dataset now includes 372 real
benign QUIC rows (5777 real rows total across both protocols, 157
distinct real domains) alongside the real TLS rows. Verified directly: 0
false positives across 80 real benign QUIC rows run through the full
retrained detector.

### 3. Real-tool validation surfaced two more genuine detection gaps (PS 26145's suggested dataset tooling)

Following through on PS 26145's own suggested dataset section --
"dnscat2/iodine (DNS tunnelling)" and "Slowloris (slow HTTP exhaustion)"
-- by actually running both tools (not just synthetic proxies) against
the live detectors found two real gaps neither synthetic training data
nor design review had surfaced:

**iodine (real DNS tunnel, installed via a throwaway Docker container to
avoid needing host root):** `dga.py`'s tunnel rule
(`payload_ratio = answer_bytes / query_bytes > 3.0`) only ever checked
one direction -- a C2 pushing a large encoded command down in the DNS
answer, small query. Real iodine's upload/exfil direction is the mirror
image: the payload is encoded into the long query name itself, with a
tiny ack-sized answer. Real captured queries up to 678 characters scored
~0.03 under the original one-directional formula, never crossing 3.0 --
**0/138 real iodine tunnel queries detected**. Fixed by checking both
`answer/query` and `query/answer` ratios, recording which direction fired
as `evidence.tunnel_direction`. Re-verified against a fresh real capture:
**184/184 (100%) detected** (118 via the new UPSTREAM path, 66 caught by
the DGA randomness classifier as a bonus -- encoded tunnel data also
looks similar to algorithmically-generated random strings).

**Slowloris (real implementation, raw sockets -- no dependency needed):**
120 sockets held open ~50s each against a local target. Tested two
timelines: as literally captured (all closed within a script's own
teardown window) fired once via the existing flood ML path; a realistic
timeline (closes staggered over 5 minutes, matching how a real target's
own independent per-connection timeout actually behaves, not an attacker
script's synchronized tail) scored **0/120** -- the existing 10-second,
rate-tuned window structurally cannot see a pattern deliberately
engineered to stay under any rate threshold. This is a genuinely
different signal (duration and byte count over a much longer window, not
rate), so it's a new rule-based path (`SlowExhaustionTracker` in
`ddos.py`) alongside the flood ML path -- the same hybrid rule+ML pattern
`dga.py`'s tunnel path and `exfil.py`'s pattern pre-filter already use --
rather than retraining the flood model around a second window it was
never designed for. Re-verified against the realistic timeline: fires
correctly (8 alerts over the 300s window, rate-limited by the existing
30s per-destination cooldown).

Both fixes are a direct result of testing against the real tools PS 26145
names, not assuming synthetic proxies generalize -- consistent with this
project's approach throughout (see the checksum-offload and ssl.log
byte-field bugs found the same way in earlier passes).

## Closing the last two gaps: JA4 feed re-check, and dnscat2 (2026-09-13)

**JA4 threat-intel feed -- re-checked, genuinely still doesn't exist.**
Went beyond the original "sslbl.abuse.ch doesn't publish one" check:
FoxIO (JA4's creator) runs `ja4db.foxio.io`, but its own JS bundle shows
the real database sits behind `/api/auth/signup-requests` and
`/api/auth/token` -- a gated community database, not a public download.
`foxio.io/intel-list` (referenced from the same bundle) redirects to
`/404`. No public, freely-downloadable JA4 malicious-fingerprint feed
exists as of this check -- the empty `ja4_blacklist.json` stays an
honest placeholder, not a shortcut that was never actually attempted.

**dnscat2 (real tool, built from source in a throwaway container --
iodine's approach, no host root needed):** cloned `iagox86/dnscat2`,
built the Ruby server and C client, ran a real handshake + session
locally. Found one more genuine, specific gap: dnscat2's client
auto-negotiates between TXT, MX, and CNAME record types (visible directly
in its own startup log, `type = TXT,CNAME,MX`) -- and `dga.py`'s tunnel
rule only ever checks `qtype_name in ('TXT', 'NULL')`. A captured real
session split 11 TXT / 10 MX / 8 CNAME queries.

Tested end-to-end against the live detector anyway rather than assuming
the qtype gap meant a miss: **29/29 (100%) detected**, but via two
different paths --
- the 11 TXT queries hit the intended TUNNEL rule (validating the
  2026-09-13 bidirectional-ratio fix generalizes beyond iodine's own
  NULL-record traffic to a second real tool's TXT traffic too)
- the 18 MX/CNAME queries, which the TUNNEL rule structurally cannot
  reach, were instead caught by the DGA randomness classifier (Path B) --
  dnscat2's base32/hex-encoded subdomains score as highly random
  regardless of which record type carries them, so the general-purpose
  DGA path picks up what the tunnel-specific rule's qtype allowlist
  misses.

**Deliberately not widening the tunnel rule's qtype check to include
MX/CNAME**, even though it would close the theoretical gap: TXT/NULL are
essentially never used for legitimate application traffic (which is why
the rule targets them specifically, to stay a low-false-positive
rule-based path), while MX and CNAME are extremely common for completely
legitimate mail routing and CDN aliasing -- adding them to a *rule* would
trade a small recall gain (already covered by the ML path) for a real
precision cost on ordinary traffic. The two-path coverage already
verified above is the better trade: a tight rule for the record types
that are almost always evidence of something, and a general classifier
picking up the rest.

## Tier-2 confidence-gated seq-CNN for TLS malware (2026-09-12)

Path B's RandomForest (tls_flow_model.joblib) only ever sees scalar
aggregates of the packet-size/gap sequence (mean/std) -- see
`_flow_features()`'s comment on why (RandomForest has no native
variable-length input support). A second model that looks at the *raw*
sequence can catch subtler shapes the aggregates wash out, but running it
on every flow would cost real per-event latency for no benefit on the
~90% of flows Tier 1 already calls confidently.

Added a **confidence gate**: Tier 1's proba is already Platt-calibrated
(`calibration/calibrate_models.py`), so `0.4 <= proba <= 0.7` is a
genuinely ambiguous probability band, not an arbitrary cut on a raw score.
Only flows landing in that band get a second opinion from a compact 1D-CNN
(`backend/detectors/tier2_model.py`) over the first 12 packets'
sizes/gaps (`backend/detectors/tier2_features.py`), which then *replaces*
(not supplements) Tier 1's proba for the final `> 0.72` decision.
`evidence.detection_method` becomes `'flow_stats_ml+tier2_seq_cnn'` when
Tier 2 fired, `'flow_stats_ml'` otherwise -- verified end-to-end with a
mocked Tier-1/Tier-2 pair: Tier 2 is invoked exactly when proba is
in-band and never otherwise, and its output alone determines whether an
in-band flow ends up alerting.

CNN chosen over a GRU: 12 timesteps is too short for recurrence to earn
its keep over local pattern-matching, and a CNN is easier to keep small
(~3k params: two Conv1d layers, global max-pool over the packet axis so
padding is naturally inert, two FC layers) and well-regularized on a
dataset that's still partly synthetic (see below). `torch==2.14.0+cpu`
added to `backend/requirements.txt` -- confirmed a real `cp314` wheel
exists for this repo's Python 3.14.4 venv before committing to it.

**Training data, honestly**: same real-malware-TLS-traffic gap
`build_dataset_tls.py` already documents for Tier 1's malicious class
(no ethical real-world source existed at the time) -- except this time
addressed rather than left as a caveat. Pulled a real CTU-13 botnet
capture (Stratosphere Lab, scenario `CTU-Malware-Capture-Botnet-42`
/Neris, CC-BY licensed, ground-truth-labeled) via
`training/build_malicious_pcap_logs.py` (a disposable `docker run` against
`zeek/zeek:latest`, not the live demo container) +
`training/build_dataset_tls_seq.py` (joins Zeek's conn.log 5-tuple against
the scenario's own argus `Botnet`-labeled flows). That scenario's capture
contains 63 total SSL/QUIC sessions with a packet sequence, of which
**13** matched a ground-truth Botnet 5-tuple riding port 443 -- small
(most of that scenario's 71 raw Botnet/443 flows are `S_RA`/`S_`-state
TCP-Attempt rows with no completed handshake, so no ssl.log entry at all;
13 is what's left after that), but genuinely real, not synthetic-
generator-fingerprinting. Tagged with a `provenance` column (alongside
5,402 synthetic-malicious rows kept as a comparison arm, not deleted) so
train_tier2.py can report real vs. synthetic held-out recall separately
as a standing sanity check against a model that only fits the generator
-- with only one real-malicious group so far, that split's held-out slot
came up empty this run (the single group landed entirely in train), which
is itself an honest artifact of n=13 rather than a bug. `SCENARIO_LABELS`
in build_dataset_tls_seq.py is a one-line-per-scenario dict specifically
so trying more CTU-13/Stratosphere scenarios is additive, not a rewrite.

Trained on real-benign + 13 real-malicious + synthetic-malicious:
`docs/metrics/tls_tier2.json` -- precision=1.0, recall=0.520,
F1=0.684 on held-out synthetic malicious rows (real-malicious held-out
count was 0 this run, see above). The recall ceiling here is expected
and not a regression to chase yet: 40 epochs on a deliberately tiny net
against a still mostly-synthetic dataset -- the point of this pass was
proving the gate/schema/graceful-degrade/calibration plumbing, not tuning
accuracy against data that's still mostly not real. Retraining (once more
real-malicious rows land) is `training/build_dataset_tls_seq.py` +
`training/train_tier2.py`, no other code changes -- `tls_tier2_model.pt`
gets overwritten in place.

**Calibration**: a code-review pass on this feature caught a real issue
here worth recording -- the first version reused Tier 1's `calibrated`
flag (and its 0.72/0.85 severity thresholds) for Tier-2-driven alerts too,
mislabeling a raw CNN sigmoid as a Platt-calibrated probability, and
comparing it against thresholds tuned for a differently-distributed
calibrated score. Fixed the same way `calibration/calibrate_models.py`
calibrates the other 6 (sklearn) models -- `train_tier2.py` now fits a
1-D Platt scaling (`calibrated_logit = a*raw_logit + b`, via
`sklearn.linear_model.LogisticRegression` on a held-out group split) on
top of the frozen trained net, saved to
`backend/ml_models/tls_tier2_calibration.npz`. `tier2_model.py`'s
`Tier2Model.calibrated` reflects whether that file loaded, and
`tls_malware.py` now reports `calibrated=self.tier2_model.calibrated`
(not `self.calibrated`, Tier 1's flag) whenever Tier 2 actually decided
the alert -- verified directly: the `calibrated` field on a Tier-2-driven
alert now reads `True` only because the calibration file loaded, not
because Tier 1 happened to be calibrated.

## Real E2E throughput benchmark, and a real correlator bug it found (2026-09-12)

A PS-26145 compliance review flagged the existing benchmark
(`scripts/benchmark_throughput.py`) as too weak a throughput claim: it's a
pure in-process Python loop calling `detector.process()` directly, with no
Kafka, no Zeek, no network I/O -- its own `measurement_scope` field
already says so. Added `scripts/benchmark_e2e.py`, a sibling (not a
replacement) that generates real traffic against the *live* pipeline
(Zeek `-i lo` capture -> Kafka -> `stream_consumer.py` -> detectors ->
`alerts.json`) and measures what the pipeline itself sustained, via a
self-contained `asyncio` TCP swarm (no `iperf3`/`tcpreplay` -- neither is
installed and there's no passwordless sudo to install them unattended;
`app.py`'s own `/api/replay` endpoint already made the same call for the
same reason). Short connect->send->close cycles per worker (not held-open
connections), matching `traffic/generate_c2.py`'s existing convention --
Zeek only logs a connection on close, so held-open connections would
produce a batchy, misleading throughput series instead of a real one.

**First run found a real, serious bug, not a benchmark artifact.** The
sink server initially never replied, making every generated flow
maximally byte-asymmetric -- exactly `exfil.py`'s own detection signature.
900 exfil alerts fired in ~25s, and `correlator.py`'s `C2_EXFIL` pattern
fired a *new* `MULTI_VECTOR` alert on every single one of them (its dedup
only suppresses when nothing new contributed, and every flow has a unique
`flow_id`, so under a sustained burst nothing ever gets suppressed by
design) -- each firing embedding an ever-growing `contributing_alerts`
list (~1+2+...+900, roughly 405,000 embedded entries total across all
firings). That bloated `alerts.json` enough that reading it back via
`/api/alerts` **OOM-killed the live Flask process** (confirmed via
`dmesg`: `Out of memory: Killed process ... (python3) ... anon-rss:
6010412kB`). Fixed at the source, not by making the test gentler:
`correlator.py`'s `_make_correlated` now caps `contributing_alerts` to the
most recent `MAX_CONTRIBUTING_ALERTS = 20` entries -- bounds every
correlated alert's size regardless of burst length, without changing
which alerts count for the re-fire dedup (still correctly avoids missing
a second, genuinely distinct attack chain). Also fixed the benchmark's
own sink to echo the payload back (byte_ratio ~= 1.0, a real
request/response shape) so it's a clean capacity test rather than an
inadvertent (if correctly detected) exfil stress test.

**Real numbers** (`docs/benchmark_e2e_results.json`, rerun after both
fixes): generator offered 297.6 flows/sec / 4.88 Mbps (30 workers, 2KB
payloads, 25s, rate-capped); the *pipeline* sustained ~21-22 events/sec at
steady state -- a real, measured gap between offered and sustained load,
consistent with the existing isolated-loop benchmark's ~44.8 flows/sec
ceiling (scikit-learn `predict()` call overhead dominates either way).
Explicitly scoped, same honesty convention as the original benchmark: a
single 12-core mobile laptop running the capture, broker, and detectors
on the same cores as the load generator -- not dedicated hardware, not a
real NIC.

## STIX 2.1 + CEF alert export (2026-09-12)

A second compliance gap: the internal alert schema (`base.py`) already
has every field PS 26145 literally lists (timestamp, flow_id,
threat_class, confidence, evidence), but nothing exported it in a format
an air-gapped SOC's SIEM/TIP would actually ingest. Added
`backend/alert_export.py` -- `to_stix_indicator`/`to_stix_bundle` (STIX
2.1, hand-rolled with stdlib `uuid`/`datetime` rather than the `stix2`
library, since STIX 2.1 Indicator objects are simple enough to get right
without an unverified-for-this-repo's-Python-3.14.4-venv new dependency)
and `to_cef_line`/`to_cef_lines` (CEF syslog format, no widely-used
library exists for it either way). Purely additive: takes the existing
alert dict unchanged, zero changes to `base.py`, any detector, or the
correlator.

The real constraint this had to handle: `evidence` is not uniform across
detectors -- a `list[str]` for ddos/recon/c2, a flat `dict` for
dga/exfil/tls, and a `dict` with a nested `list` for the correlator's
`MULTI_VECTOR` alerts. Both exporters just JSON-serialize `evidence`
as-is rather than type-branching, which is correct for all three shapes.
CEF escaping needed to be precise, not approximate: header fields escape
`|`/`\`; extension *values* escape `=`/`\`/newlines -- and the JSON-encoded
evidence blob needs CEF-escaping applied on top of, not instead of, JSON's
own `"`-escaping, since JSON doesn't cover CEF's `=`/`|` delimiters.

Two integration points, both live and verified against real alerts:
**on-demand** (`GET /api/alerts/stix`, `GET /api/alerts/cef`, reusing the
existing `read_alerts()`), and **continuous** (`write_alert()` in
`stream_consumer.py` now also appends to `backend/alerts.cef.log` and
`backend/alerts.stix.jsonl` on every alert -- the realistic air-gapped-SOC
integration point, since CEF's whole purpose is syslog-style tailing).
The continuous appends are best-effort (`try/except Exception`, logged
and swallowed) and strictly *after* the existing `alerts.json` write, so
a future malformed-evidence shape in some new detector can never crash
the consumer loop or leave the canonical, dashboard-relied-on
`alerts.json` inconsistent -- `write_alert()` had no error handling at
all before this change.
