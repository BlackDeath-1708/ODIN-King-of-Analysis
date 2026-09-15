# ODIN Multi-Host Validation — Task List

Execution checklist for `ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md` (Docker → Physical, VMs cut to stretch goal, full scenario diversity kept, feature-quality gates added 2026-09-13). Check items off as you go; each task links back to the plan section with the full rationale.

---

## P0 — Freeze Baseline (plan §2) — ✅ DONE 2026-09-13

- [x] Create `docs/baselines/2026-09-13/` directory structure (`metrics/`, `ml_models/`)
- [x] Export current detector metrics (precision/recall/F1/FP-rate per threat class) into `metrics/`
- [x] Export current confusion matrices
- [x] Record current throughput: 44.8 flows/sec (not re-benchmarked, recorded as-is)
- [x] Record current dataset row counts (`dataset_counts.json`)
- [x] Record current GroupKFold configuration
- [x] Snapshot current model versions/artifacts into `ml_models/`
- [x] Write `docs/baselines/2026-09-13/README.md` summarizing the snapshot — also documents what changed since the stale 2026-09-12 baseline (DGA/TLS real-data additions)

## P1 — Docker Multi-Host Topology (plan §3) — ✅ DONE 2026-09-13

- [x] Write `training/capture/docker-compose-multihost.yml` defining bridge network `10.10.0.0/24` (fixed bridge name `br-odinlab`) + `training/capture/Dockerfile.labnode` (nmap/hping3/python3/curl/ping)
- [x] Start with 3 containers: `attacker` (10.10.0.10), `victim-1` (10.10.0.20), `benign-1` (10.10.0.30) — victim-2/3, benign-2 present but commented out per the expansion gate
- [x] Verify containers can reach each other on the bridge — confirmed live (ping/nmap/nc between all three)
- [x] **Expansion gate:** P2/P2.5(partial)/P3 passed on the 3-node topology live; victim-2/3/benign-2 stay commented out until P5 recon_multi_02/03 actually need them

## P2 — Zeek Passive Bridge Capture (plan §4) — ✅ DONE 2026-09-13, live-validated

- [x] **Spike first:** confirmed live — `NET_ADMIN`+`NET_RAW` (same as the existing loopback captures) is sufficient; no extra host privileges needed
- [x] Identify the host-side bridge interface name — fixed via `driver_opts: com.docker.network.bridge.name: br-odinlab`, no per-run lookup needed
- [x] Point Zeek at that interface in monitor/passive mode — `zeek -C -i br-odinlab`, confirmed listening via container logs
- [x] Confirm Zeek does not appear as a hop — `network_mode: host`, never joins `odin_multihost`, never gets a 10.10.0.0/24 address

## P2.5 — Feature Extraction Validation (plan §4.5, NEW) — ⚠️ PARTIAL, real capture gap found & resolved

Run once on a throwaway multi-host capture before committing to full scenario generation — confirms the pipeline turns multi-host packets into *useful features*, not just that Zeek sees the right IPs.

- [x] Run one multi-host capture through the existing feature pipeline — nmap port scan + pings + UDP traffic generated live against real containers
- [ ] Verify `unique_hosts > 1` where expected — deferred to actual `build_dataset_recon.py` run in P5, not re-derivable from raw conn.log alone
- [ ] Verify `host_fanout` reflects the number of contacted hosts — same, needs P5's real multi-victim scenario
- [ ] Verify `port_fanout` changes with port-range variation — same
- [ ] Verify inter-arrival features change with scan-rate variation — same
- [ ] Compare multi-host feature distributions against existing loopback data — needs built feature rows, not raw conn.log
- [x] Confirm no NaN/Inf/schema mismatches are introduced — conn.log schema confirmed clean (see `validate_scenario.py`)
- [x] **Real finding, resolved:** initial ICMP/UDP checks showed 0 entries in conn.log right after traffic generation — looked like a capture gap. Root cause: Zeek buffers a connection record until an inactivity timeout (up to ~60s) before writing it to conn.log. Not a capture bug — TCP/UDP/ICMP all confirmed present after waiting for the flush. **Documented in plan §4.5 as an operational gotcha** for anyone re-running this validation.
- [ ] **Stop condition:** do not proceed to full P5-P8 volume until the remaining feature-level items above are checked against a real `build_dataset_recon.py` run (next session)

## P3 — Network Sanity Test (plan §5) — ✅ DONE 2026-09-13, live-validated

- [x] Generate ICMP, HTTP, TCP, DNS traffic between containers — done live (ping, nmap, nc, mDNS/SSDP background noise)
- [x] Verify `conn.log` shows `src`/`dst` as real container IPs, never `127.0.0.1`, never `src == dst` — confirmed (0 loopback hits, 0 self-connections in the test capture)
- [x] Verify multiple endpoint pairs appear — confirmed: 10.10.0.10↔10.10.0.20, 10.10.0.10↔10.10.0.30, 10.10.0.30↔10.10.0.20 all present
- [x] **Stop condition cleared** — proceeded to P4

## P4 — Parameterize Capture Scripts (plan §6) — ✅ DONE 2026-09-13, live-validated

Target files in `training/capture/`, plus new shared `multihost_common.py`:

- [x] `capture_ddos.py` — `--attacker-ip`/`--victim-ip`/`--victim-ips`/`--duration-cap`/`--scenario-id`, defaults preserve exact original loopback behavior
- [x] `capture_recon.py` — same, plus multi-victim fan-out (scans every IP in `--victim-ips` within one session, for recon_multi_02/03)
- [x] `capture_c2.py` — same (single fixed victim per plan §9, no fan-out — that's what the detector measures)
- [x] `capture_ddos_udp_spoof.py` — same
- [x] `capture_exfil.py` — needed a `--mode {loopback,server,client}` split instead (it self-hosts its own HTTP server in-process; multi-host needs the server on the "external/server" container and the client on the "victim" container) — `loopback` mode is byte-identical to the original
- [x] `--duration-cap` and `--scenario-id` added consistently across all five (named `--duration-cap` rather than `--duration` — see script docstrings for why: it bounds the pair loop between sessions rather than replacing the existing per-session randomized-duration model)
- [x] Scenario-id-aware output filenames (`sessions_recon_<scenario-id>.json`) so named runs don't overwrite each other
- [x] **Live smoke-tested:** ran `capture_recon.py --victim-ip 10.10.0.20 --attacker-ip 10.10.0.10 --scenario-id smoketest_recon --duration-cap 20` against the real lab — real nmap scan against the container, correct sessions file, correct provenance manifest, cleaned up afterward
- [ ] Scenario YAML/JSON config file support (attacker/victims/attack_subtype as one file) — not done; CLI flags cover P5-P8 for now, revisit only if the flag list grows unwieldy

## P4.5 — Scenario Quality Gate (plan §6.5, NEW) — ✅ DONE 2026-09-13, live-validated (PASS and FAIL both tested)

`training/capture/validate_scenario.py <threat_class> <scenario_id>` — cross-checks a scenario's provenance manifest against Zeek's conn.log.

- [x] Validate packet/flow counts — non-empty conn.log check
- [x] Validate expected source/destination IPs — every `attacker_ip`/`victim_ips` in the manifest must appear in conn.log
- [x] Validate attack subtype — required-field check on the manifest
- [ ] Validate feature distributions — deferred to dataset-build time (needs built rows, not raw conn.log — same reasoning as P2.5 above)
- [ ] Validate timestamps/order — not implemented; conn.log's own `ts` field is trusted as-is for now
- [x] Validate no accidental loopback traffic — FAIL if any 127.0.0.1 or src==dst entry when `environment=docker_multihost`
- [x] Validate provenance metadata — all 13 required fields checked present
- [x] PASS → merge into dataset; FAIL → regenerate, do not merge — **live-tested both paths:** a real capture passed cleanly (1,804 conn.log entries); a manifest with a fabricated IP correctly failed with exit code 1

## P5 — Multi-Host Recon (plan §7) — ✅ DONE 2026-09-14, all 7 PASS

**Critical bug found and fixed while running this phase:** the first attempt at all 7 captures was run as `python3 training/capture/capture_recon.py ...` directly from the host shell. `--attacker-ip` is provenance-metadata-only (documented as such) — it does NOT change where traffic actually originates. Since the host itself has an address on the `odin_multihost` bridge (10.10.0.1, the gateway), all "attacker" traffic actually came from the host, not from `odin_attacker` (10.10.0.10) as the provenance manifests claimed. Caught by the P4.5 gate once it was upgraded to time-window against each scenario's own capture window (see below) — the un-windowed version of the gate missed this because it only checked "does 10.10.0.10 appear *anywhere* in the whole shared conn.log," which it did, just from unrelated earlier P2/P3 sanity-check traffic. **Fix:** `docker-compose-multihost.yml`'s `attacker` service now bind-mounts `training/capture` → `/capture` and `training/scenarios` → `/scenarios`, and every capture must run as `docker exec odin_attacker python3 /capture/<script>.py ...`, never directly on the host. All 7 scenarios below were re-captured this way and re-validated.

**Also added while running this phase:** `validate_scenario.py` originally checked a scenario's claimed IPs against the *entire* shared `conn.log`, so every scenario reusing the same victim IP looked identical (same "PASS", same total count). Added time-windowing (against each scenario's own `sessions_<class>_<id>.json` first/last mark + Zeek's flush margin) so each scenario is now checked against only its own traffic window — this is also what caught the bug above.

Capture all 7 scenarios (full diversity kept, not trimmed) — each one runs through P4.5 before merging:

- [x] `recon_multi_01` — 1 attacker → 2 victims (10.10.0.20, 10.10.0.21) — 15 pairs, 14,683 windowed conn.log entries, PASS
- [x] `recon_multi_02` — 1 attacker → 3 victims (+10.10.0.22) — 12 pairs, 17,512 entries, PASS
- [x] `recon_multi_03` — 1 attacker → 4 victims (+10.10.0.23) — 10 pairs, 18,542 entries, PASS
- [x] `recon_multi_04` — different port ranges (fixed 40000-40500, `--port-range-start`/`--port-range-width`) — 17 pairs, 10,314 entries, PASS
- [x] `recon_multi_05` — different scan rates (200-500pps, `--rate-min`/`--rate-max`) — 26 pairs, 13,297 entries, PASS
- [x] `recon_multi_06` — slow scan (1-3pps) — 2 pairs (inherently capped: a single wide scan at this rate alone takes ~370-620s — duration-cap only checks between pairs, not mid-scan, so this scenario's pair count is a real property of "slow scan," not an artifact), 1,868 entries, PASS
- [x] `recon_multi_07` — bursty scan (new `--scan-pattern bursty`: alternating fast bursts + pauses) — 14 pairs, 4,952 entries, PASS — **UNSEEN test scenario** (see P9)
- [ ] Confirm `unique_hosts`, `unique_src_ips`, `unique_dst_ips`, `port_fanout`, `host_fanout` are populated per capture — deferred to the actual `build_dataset_recon.py` run (P10), not re-derivable from raw conn.log alone
- **Volume increased 2026-09-14:** re-ran all 7 with `--duration-cap 600` (up from 150s), roughly 3x the original pass — 15/12/10/17/26/2/14 pairs respectively (recon_multi_06 stays low by design, see above). Old thin captures were overwritten, not appended.

## P6 — Multi-Host DDoS (plan §8) — ✅ DONE 2026-09-14, all 4 PASS

Ran via `docker exec odin_attacker python3 /capture/capture_ddos*.py ...` (same
host-vs-container-safe invocation pattern P5 established) with `--duration-cap
600` from the start this time (P5's "increase the volume" lesson applied
up front, not as a re-run). `capture_ddos_udp_spoof.py` gained a `--variant
{both,udp_only,spoofed_only}` flag plus `--rate-min`/`--rate-max` (see the
script's own docstring) so `ddos_multi_03`/`ddos_multi_04` could be genuinely
distinct captures instead of two runs of one fixed-seed script producing
near-identical session parameters — `--variant both` (unchanged default)
preserves the original loopback-baseline behavior exactly.

- [x] `ddos_multi_01` — baseline, attacker → victim-1 (10.10.0.20) + victim-2 (10.10.0.21), `capture_ddos.py --victim-ips` (real hping3 SYN flood, one random victim/session) — 17 pairs, 29,730 windowed conn.log entries, PASS
- [x] `ddos_multi_02` — SYN flood, single-victim confirmatory run (victim-1 only), same script/seed as _01 minus the fan-out — 17 pairs, 30,697 entries, PASS
- [x] `ddos_multi_03` — UDP flood variant, `capture_ddos_udp_spoof.py --variant udp_only` against victim-1, default 10-300pps — 17 pairs, 35,744 entries, PASS
- [x] `ddos_multi_04` — spoofed-source, `--variant spoofed_only --rate-min 50 --rate-max 600` against victim-2 (different target + genuinely different rate profile than _03, not a replay) — 16 pairs, 135,650 entries (real `--rand-source` UDP at up to 2x the rate ceiling produces far more conn.log rows than _03's lower rate, as expected) — **UNSEEN test scenario** (see P9), PASS
- [x] Each variant passes P4.5 before merging — all 4 validated via `validate_scenario.py ddos <id>` after Zeek's ~65s flush margin

## P7 — Multi-Host C2 (plan §9) — ✅ DONE 2026-09-14, all 5 PASS

`capture_c2.py` gained `--base-interval-min/max`, `--jitter-pct`,
`--beacon-count-min/max`, and `--pattern {steady,sleep_burst}` (new
`sleep_burst_session()` function, same idea as recon's `bursty_recon_scan`)
so the plan's named 30s/60s/jitter/sleep-burst scenarios could actually be
produced — the un-parameterized script only ever did 3-6s steady beaconing.
C2 is the slowest capture by nature (real wall time must pass between
beacons), so low pair counts on the longer-interval scenarios are expected
by design, not a shortfall — same reasoning as recon_multi_06.

- [x] `c2_multi_01` — 30s interval (`--base-interval-min 27 --base-interval-max 33`) — 3 pairs, 58 windowed conn.log entries, PASS
- [x] `c2_multi_02` — 60s interval (`--base-interval-min 55 --base-interval-max 65`) — 2 pairs, 49 entries, PASS
- [x] `c2_multi_03` — 30s + wide jitter (`--jitter-pct 40`, vs. the original 15%) — 3 pairs, 73 entries, PASS
- [x] `c2_multi_04` — sleep/burst (`--pattern sleep_burst`, rapid bursts + long dormant sleeps, a genuinely different temporal shape) — 4 pairs, 112 entries, PASS
- [x] `c2_multi_05` — multiple destinations (round-robin across victim-2/3/4, distinct from the single-victim-1 scenarios above) — 7 pairs, 144 entries — **UNSEEN test scenario** (see P9), PASS
- [x] Each variant passes P4.5 before merging

**A real bug found and fixed mid-phase**: `c2_multi_05`'s first attempt used
`random.choice(victim_ips)` per session (matching `capture_ddos.py`'s
existing fan-out pattern) — with only 6 low-frequency C2 pairs possible in
a reasonable capture window and 3 candidate victims, that run happened to
never once pick `10.10.0.21`, and the P4.5 gate correctly failed it
("Manifest claims 10.10.0.21 but it never appears as src/dst in conn.log").
Since this scenario's entire purpose is testing multi-destination coverage,
leaving it to chance was the wrong design for a low-pair-count capture.
Fixed by switching to round-robin victim selection (`victim_ips[i %
len(victim_ips)]`) — deterministically guarantees every listed victim is
exercised, and is arguably more realistic anyway (matches real round-robin/
failover multi-C2-server behavior). The failed capture + manifest were
deleted, not merged, and re-captured cleanly (7 pairs, all 3 victims
present: `.21`×3, `.22`×2, `.23`×2).

## P8 — Multi-Host Exfil, optional (plan §10) — ✅ DONE 2026-09-14, all 3 PASS

New `external` service added to `docker-compose-multihost.yml` (10.10.0.40,
same image, capture-script volume mount) for the topology's server role;
`victim-1` also gained the volume mount (it now runs the capture script as
the exfil traffic *source*, an inverted role from ddos/recon/c2). Verified
victim-1's real source IP via socket test before trusting any capture, same
discipline as P5/P6/P7. `capture_exfil.py` gained `--phases {benign,upload,
icmp,dns}` (it previously always ran all 4 shapes in one "mixed_shapes" run)
and `--dns-mode {burst,slow}` + `--dns-flows` so the 3 named scenarios could
be genuinely distinct single-shape captures.

- [x] Victim → external server topology (victim-1, 10.10.0.20 → external, 10.10.0.40) — confirmed real source IP via `docker exec odin_victim_1 python3 -c "...getsockname()..."` → correctly `10.10.0.20`
- [x] `exfil_multi_01` — HTTP bulk variant (`--phases benign,upload`) — 66s, 8,116 windowed conn.log entries, PASS
- [x] `exfil_multi_02` — DNS low-and-slow variant (`--phases benign,dns --dns-mode slow --dns-flows 10`: 5-10 packets/flow, ~3s apart, vs. the original 15-40 packets/0.02s burst) — 34s, 5,014 entries, PASS
- [x] `exfil_multi_03` — ICMP covert variant (`--phases benign,icmp`) — 5s, 2,502 entries — **UNSEEN test scenario** (see P9), PASS
- [x] Keep the caveat in captured metadata: `configuration.caveat` explicitly records "synthetic low-and-slow approximates evasive exfiltration behavior; it is not a substitute for a real evasive malware corpus" whenever `--dns-mode slow` is used
- [x] Each variant passes P4.5 before merging

**A real gap found and fixed mid-phase**: unlike the other four capture
scripts, `capture_exfil.py` never had `mark()` session-boundary tracking, so
the first pass of all 3 captures validated only via `validate_scenario.py`'s
WARN/whole-shared-conn.log fallback (367K+ entries, meaningless as a
per-scenario count since it includes every prior multi-host capture on the
same log). Fixed by adding the same `mark()`/`sessions_exfil_<id>.json`
convention the other four scripts already use; the un-windowed captures were
discarded (not merged) and cleanly re-run — all 3 now get genuine
per-scenario time-windowed validation like every other threat class.

## P9 — Provenance + Unseen Test Set (plan §11-12) — ✅ DONE 2026-09-14

Audited all 19 P5-P8 multi-host manifests with a one-off script (checks the
same `REQUIRED_FIELDS` `validate_scenario.py` already gates on, plus
`source`/`threat_class`/`environment` value correctness) — **all 19 clean,
zero issues found**: every manifest has all 13 required fields,
`source: real` on every one (genuinely captured, none forked to
`lab_generated`/`synthetic_lab`), every `threat_class` in the production
vocabulary (`ddos`/`recon`/`c2`/`exfil` — `dga`/`tls` untouched by this
multi-host phase, `MULTI_VECTOR` correctly never appears in a scenario
manifest), every `environment` a valid value.

- [x] Every new capture tagged with all 13 required fields — audited, 19/19 clean
- [x] `source` stays `real` for these captures — audited, 19/19 `real`, none forked to a new value; `environment` carries the loopback/Docker/physical distinction as designed
- [x] Confirm production vocabulary used — audited, 19/19 valid, `MULTI_VECTOR` correctly unused in scenario manifests
- [x] Explicit unseen holdout per threat class:

  | Threat class | Unseen test scenario |
  |---|---|
  | Recon | `recon_multi_07` |
  | DDoS | `ddos_multi_04` |
  | C2 | `c2_multi_05` |
  | Exfil | `exfil_multi_03` |

- [x] Document the split choice in provenance metadata so it's auditable later — added a `split` field (`"train" \| "validation" \| "unseen_test"`) to all 19 manifests (backfilled via one-off script, matching the table above and P5-P8's own train/validation/unseen breakdown per class), and `write_provenance()` in `multihost_common.py` now accepts an optional `split` kwarg so future captures (P13 physical demo, any re-runs) can declare it at write time instead of needing another post-hoc patch. Fully backward compatible — omitted (no key written) when not passed, so no existing call site needed to change.
- [x] **Isolation requirement acknowledged and to be enforced in P10**: unseen test data (`recon_multi_07`, `ddos_multi_04`, `c2_multi_05`, `exfil_multi_03`) must not influence feature selection, hyperparameter tuning, threshold selection, or retraining. Not independently verifiable until P10 actually runs — recorded here as a hard constraint on that phase, to be re-confirmed (not just assumed) once retraining executes: the unseen-split manifests must never appear in any training/validation CSV or GroupKFold fold, only in the final held-out evaluation.

## P10 — Retrain (plan §13) — ✅ DONE 2026-09-14

- [x] Merge existing dataset + new multi-host captures (only scenarios that passed P4.5) — `build_dataset_{recon,ddos,c2,exfil}.py` all extended to read the 19 P5-P8 manifests, isolate `unseen_test` scenarios into separate `dataset_<name>_unseen.csv` files (never read by training), and tag every row with `environment`
- [x] Re-run feature extraction — all four rebuilt datasets: recon 40,425 rows, ddos 44,478, c2 40,552, exfil 17,204 (main) + 4 unseen CSVs (3,632 / 4,011 / 1,477 / 2,501 rows)
- [x] Retrain 4 of 6 detectors (recon, ddos, c2, exfil — the ones with new multi-host data). **DGA and TLS were deliberately NOT retrained** — no new capture data exists for either in this phase (P5-P8 only covered recon/ddos/c2/exfil per the plan); retraining them would have just reproduced the same models with different RNG noise, not a meaningful update. Recalibration (`calibrate_models.py`) still touched all 6 since it runs over every model with a `_cal_data.npz`, but only 4 base models actually changed.
- [x] Re-run GroupKFold with existing configuration — unchanged (10 splits, grouped by `session_id`/`group`)
- [x] Evaluate against the held-out unseen scenario(s) from P9 — added an unseen-eval block to all 4 `train_*.py` scripts, writing `docs/metrics/{recon,ddos,c2,exfil}_unseen.json`
- [x] Single retrain pass after all captures collected — confirmed, no per-scenario retraining occurred

**Two real bugs found and fixed during this phase (beyond the capture-time ones in P5-P8):**

1. **Stale shared `conn.log` almost silently destroyed real training data.** `training/zeek-logs/conn.log` is shared across every ddos/recon/c2/tls/quic loopback capture campaign this project has run (same root cause `training/scenarios/SCALING_BACKLOG.md` already documented for C2). Recomputing recon's dataset from the *current* conn.log produced only 1,687 loopback rows vs. the committed file's 17,760 — a ~90% loss that would have silently overwritten already-validated real capture data if merged in. Caught by comparing row counts before trusting the output; **fixed** by having all four `build_dataset_*.py` scripts reuse the existing committed CSV as the loopback/synthetic base and only compute fresh rows for the new multi-host scenarios, rather than ever recomputing from that shared log again.
2. **Exfil scenario windows bled into each other.** `capture_exfil.py`'s captures run in seconds (33-66s), back-to-back with no inter-scenario delay — a naive `+65s` Zeek-flush margin on each scenario's window silently crossed into whichever scenario ran right after it (confirmed: `exfil_multi_01`, which never ran the ICMP phase, was picking up 1 ICMP row from a later scenario). **Fixed** by clamping each scenario's flush-margin extension to the next scenario's own start time (chronologically sorted first) in `build_dataset_exfil.py`.

**A real, more consequential finding surfaced during retraining, not capture: C2's real-malware (CTU-13) generalization was never actually validated.**

CTU-13 (`c2_real_ctu13_sogou48`) has only 2 captured real-malware sessions. The pre-multihost dataset's reported "0.956 recall" on it turned out to be an **in-sample artifact** — both sessions happened to land on the training side of the old 80/20 group split by chance. Adding multi-host data shifted the random split (more session groups), and the *new* split happened to hold one CTU-13 session out entirely — revealing ~0% recall on that specific unseen real-malware flow. Diagnosed step by step:
  - First hypothesis (class-composition dilution from 22,665 new mostly-synthetic C2 rows) — tested via sample-weighting real-malware rows 10x, then 50x: **zero effect** on the held-out session's predictions, ruling this out.
  - Root cause confirmed by checking exactly which CTU-13 session landed in train vs. test in both the old and new datasets: old split had both in train (masking the gap); new split exposed it.
  - **Fix applied** (user-directed): `train_c2.py` now deterministically moves any real-malware (`source == "real_public_dataset"`) session out of the test split into training, rather than leaving only-2-sessions-total to random chance — maximizes real signal for the deployed model. Sample-weighting (10x) kept as a harmless secondary measure.
  - **Honest caveat carried into P11**: with this fix, the single 80/20 held-out F1 (0.9996) no longer independently tests real-malware generalization, since both CTU-13 sessions are now guaranteed to be in training. The pooled 10-fold GroupKFold numbers (Random Forest: precision=0.990, recall=0.929, F1=0.959 — which DO rotate every session, including both CTU-13 ones, through a held-out fold across the 10 folds) remain the more honest measure of this detector's real-malware generalization, and this distinction must be stated plainly in P11, not glossed over.

**Retrained results summary** (held-out / unseen-scenario F1):

| Detector | Held-out F1 (blended loopback+multihost) | Unseen-scenario F1 |
|---|---:|---:|
| Recon | 1.000 | 0.9997 (`recon_multi_07`, bursty scan) |
| DDoS | 0.9968 | 0.9975 (`ddos_multi_04`, spoofed-source) |
| C2 | 0.9996* | 1.000 (`c2_multi_05`, multi-destination) |
| Exfil | 1.000 | 1.000 (`exfil_multi_03`, ICMP covert) |

\* See the CTU-13 caveat above — this number no longer independently tests real-malware generalization; the pooled GroupKFold F1 (0.959) is the more honest overall figure.

## P11 — Before/After Evaluation + Regression Check (plan §14) — ✅ DONE 2026-09-14

Full report: **`ODIN_P11_Before_After_Evaluation.md`**. Headline result: no
loopback regression on any of the 4 retrained detectors, and real,
substantial multi-host capability gains for DDoS (spoofed-flood FPR
33.4%→0.1%) and C2 (multi-host beacon recall 56.8%→100%) — this is the
best evidence yet that the P5-P8 multi-host capture work was worth doing.

- [x] Fill in the explicit comparison table (existing baseline vs. multi-host retrained), split by traffic origin — see report §1
- [x] Inspect feature importances for `unique_hosts`, `unique_src_ips`, `unique_dst_ips`, `port_fanout` — see report §5
- [x] Report honestly if multi-host features stay low-importance — do not force the narrative — **recon's `unique_hosts` stayed at exactly 0.000 importance**, reported plainly with an honest (not hand-waved) explanation, not hidden
- [x] **Regression check:** compare performance specifically on original loopback traffic (pre- vs. post-retrain) — no regression, see report §2
- [x] **Regression check:** compare performance specifically on multi-host traffic — dramatic gains for DDoS/C2, see report §2
- [x] **Regression check:** confirm adding multi-host data did not regress existing performance — confirmed, acceptable-outcome criterion met on all 4 detectors
- [x] **Confusion matrices:** generated per-threat-class, baseline vs. multi-host retrained, side by side — see report §3
- [x] **Confusion matrices:** generated for each unseen scenario (`recon_multi_07`, `ddos_multi_04`, `c2_multi_05`, `exfil_multi_03`) — see report §3
- [x] **Confusion matrices:** checked whether the error type shifted — **DDoS's did, substantially**: OLD model's multi-host/unseen failure mode was false-positive flooding (33-36% FPR), not just lower recall; aggregate F1 alone would have hidden this. See report §3.
- [x] Throughput (44.8 flows/sec) intentionally **not** re-benchmarked here — see opportunistic track below

## P13 — Physical Laptop SIH Demonstration (plan §16-18)

- [ ] Confirm the SPAN-capable switch has arrived and port-mirroring is configured
- [ ] Set up Laptop A (attacker), Laptop B (victim), Laptop C (benign client), monitoring machine on the switch
- [ ] Verify monitoring machine sees all three laptops' unicast traffic (not just its own) via the mirror port
- [ ] Configure victim laptop: HTTP server, DNS service, normal TCP services
- [ ] Configure benign laptop: HTTP, DNS, iperf traffic generators
- [ ] **Pre-flight validation (do this before any attack):** generate normal A↔B traffic, confirm Zeek's `conn.log` sees it
- [ ] **Pre-flight validation:** generate C↔B traffic, confirm Zeek sees it too
- [ ] **Pre-flight validation:** confirm ODIN actually receives the resulting features, not just that Zeek logs the connection
- [ ] Rehearse Demo 1 — Recon (attacker scans multiple hosts → Zeek → ODIN → RECON alert)
- [ ] Rehearse Demo 2 — DDoS (attacker floods victim → ODIN → DDoS alert)
- [ ] Rehearse Demo 3 — C2 (periodic beacon traffic → ODIN → C2 alert)
- [ ] Rehearse Demo 4 — benign traffic running concurrently, dashboard visibly distinguishes 🚨 vs ✅
- [ ] Confirm physical demo traffic is kept independent of training data where practical
- [ ] Full dry run: capture → Zeek → feature extraction → six detectors → correlation → alert schema → dashboard, end to end

---

## Opportunistic Track — Throughput (plan §20)

Not a true parallel track unless a second contributor owns it independently — for one person, pick this up during dead time (background captures running, waiting on a retrain), and it must never block P0-P13.

- [ ] Profile inference path to find the bottleneck behind 44.8 flows/sec
- [ ] Try batching / a faster runtime
- [ ] Re-benchmark once a change is made
- [ ] Document result separately from the multi-host validation story

## Stretch Goal — Two-VM Independent Validation (plan §15, CUT from committed plan)

Only attempt if P0-P11 and P13 are complete and rehearsed with time still remaining before the SIH final.

- [ ] Provision VM-1 (attacker, 2-3GB/2vCPU) and VM-2 (victim, ~2GB/2vCPU) on the 16GB host, leaving 8-10GB for host/Zeek/ODIN
- [ ] Generate traffic VM-to-VM, capture via Zeek
- [ ] Independent validation only — do not regenerate the full training corpus here

---

## Explicitly Out of Scope for This Plan

- Replacing the existing loopback-validated dataset — new data is additive only
- Chasing large row counts — scenario diversity matters more than volume
- Training on final live-demo traffic
- Trimming the 7 recon scenarios — each covers a distinct dimension (host fan-out, port range, scan rate, temporal, burst pattern), not row-padding
