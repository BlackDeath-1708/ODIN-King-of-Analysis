"""
Bulk real-traffic capture for the C2 beaconing classifier, run against the
isolated zeek_ml_capture container (see docker-compose.yml in this
directory) -- never the live demo's zeek_monitor container.

Per PS 26145's own suggested methodology ("a sandboxed C2 emulator for
realistic beaconing timing"), this IS that emulator -- a small, safe,
local script that produces real periodic TCP connections with controlled
timing statistics. No external C2 framework is used or needed; the
detector's only signal is inter-arrival timing regularity, which this
reproduces directly and safely.

The real C2Detector (backend/detectors/c2.py) groups connections by
(src, dst, dst_port) and looks for a low coefficient of variation (CV =
std/mean of inter-arrival intervals) -- the signature of programmatic,
regularly-timed beaconing versus human/app-driven traffic. Both session
types below target a single fixed (host, port) for their whole duration,
isolating exactly the one variable this detector measures (timing
regularity) rather than mixing in port/host-count signal that belongs to
the recon detector.

Benign sessions use `random.expovariate` for inter-arrival gaps -- a
Poisson-process-like pattern (what uncoordinated human/app traffic looks
like), with high CV (~1.0) by construction. A *uniform* random interval
would still read as low-CV/beacon-like on this detector's one feature, so
exponential gaps are required to make "benign" genuinely distinguishable.

C2 sessions use a fixed base interval plus +-15% jitter -- low, realistic
CV, mimicking real beaconing malware.

Randomized per session:
  Benign: mean inter-arrival gap (3-8s), duration (15-30s).
  C2:     base beacon interval (3-6s, kept short so an unattended bulk
          capture finishes in a reasonable time -- same "compressed demo
          timing" reasoning as c2.py itself) and beacon count (10-15).

This is a genuinely low-frequency signal (real wall time must pass
between beacons), so this capture takes noticeably longer per row than
ddos/recon -- see the printed ETA.

Ground truth label is generator intent, not whether the fixed CV<=0.35
rule happens to fire.

Run: python3 training/capture/capture_c2.py
     python3 training/capture/capture_c2.py --victim-ip 10.10.0.20 \
         --attacker-ip 10.10.0.10 --scenario-id c2_multi_01
Writes: training/capture/sessions_c2.json (or sessions_c2_<scenario-id>.json)
"""
import argparse
import json
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from multihost_common import add_multihost_args, resolve_victim_ips, sessions_filename, write_provenance  # noqa: E402

OUT_DIR = Path(__file__).parent
N_PAIRS = 65   # previous 30 pairs -> 7,265 rows (~242/pair); 65 pairs targets ~15,700 rows
random.seed(13)

sessions = []


def mark(label):
    sessions.append({"label": label, "ts": time.time()})


def _connect_once(port, victim_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect((victim_ip, port))
        s.close()
    except Exception:
        pass


def benign_session(duration, port, mean_gap, victim_ip):
    end = time.time() + duration
    while time.time() < end:
        _connect_once(port, victim_ip)
        time.sleep(random.expovariate(1.0 / mean_gap))


def c2_session(base_interval, beacon_count, port, victim_ip, jitter_pct=15.0):
    for _ in range(beacon_count):
        _connect_once(port, victim_ip)
        jitter = base_interval * random.uniform(-jitter_pct / 100.0, jitter_pct / 100.0)
        time.sleep(max(0.1, base_interval + jitter))


def sleep_burst_session(base_interval, port, victim_ip, n_bursts=3, burst_size=4, dormant_range=(20, 40)):
    """c2_multi_04: a genuinely different temporal shape from steady beaconing
    (same idea as capture_recon.py's bursty_recon_scan) -- rapid-fire bursts
    of beacons close together, separated by long dormant sleeps, rather than
    one steady interval throughout. Still low-CV *within* a burst; the
    dormant gaps are what c2.py's detector has never been shown before."""
    for _ in range(n_bursts):
        for _ in range(burst_size):
            _connect_once(port, victim_ip)
            time.sleep(max(0.1, base_interval * random.uniform(0.85, 1.15)))
        time.sleep(random.uniform(*dormant_range))


BENIGN_PORT_POOL = list(range(8080, 8130))
# NOTE: was originally range(9080, 9110), which silently overlapped the
# live Kafka broker/controller ports (9092/9093 -- confirmed via `ss -tanp`)
# running in this environment. Zeek's isolated capture container still
# sees ALL loopback traffic host-wide (network_mode: host), so Kafka's own
# periodic controller heartbeat got folded into the beacon-timing history
# and badly corrupted the dataset (median CV ~0.54 instead of the
# expected ~0.09 for the intended +-15% jitter). Moved to a range with no
# other listener on this machine (verified via `ss -tanp | grep LISTEN`).
C2_PORT_POOL = list(range(19110, 19140))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_multihost_args(parser)
    parser.add_argument("--base-interval-min", type=float, default=3.0,
                         help="Min C2 base beacon interval, seconds (default 3, the original range).")
    parser.add_argument("--base-interval-max", type=float, default=6.0,
                         help="Max C2 base beacon interval, seconds -- override for e.g. "
                              "c2_multi_01's ~30s or c2_multi_02's ~60s interval scenarios.")
    parser.add_argument("--jitter-pct", type=float, default=15.0,
                         help="Beacon timing jitter, +-percent of base_interval (default 15, "
                              "the original amount) -- e.g. c2_multi_03's wider-jitter scenario.")
    parser.add_argument("--beacon-count-min", type=int, default=10,
                         help="Min beacons per c2 session (default 10). Lower this for longer "
                              "base intervals so a bulk capture still finishes in reasonable "
                              "wall-clock time (see this file's docstring on real-time cost).")
    parser.add_argument("--beacon-count-max", type=int, default=15, help="Max beacons per c2 session (default 15).")
    parser.add_argument("--pattern", choices=["steady", "sleep_burst"], default="steady",
                         help="steady (default): original fixed-interval+jitter beaconing, "
                              "unchanged. sleep_burst (c2_multi_04): rapid bursts of beacons "
                              "separated by long dormant sleeps -- a genuinely different "
                              "temporal shape, not just a different interval.")
    args = parser.parse_args()
    victim_ips = resolve_victim_ips(args)
    sessions_file = OUT_DIR / sessions_filename("sessions_c2.json", args.scenario_id)

    t_start = time.time()
    for i in range(N_PAIRS):
        if args.duration_cap and (time.time() - t_start) >= args.duration_cap:
            print(f"  [duration-cap] stopping after {i} pairs ({time.time() - t_start:.0f}s)")
            break

        # Round-robin, not random.choice: each session still targets one
        # fixed (host, port) for its whole duration (plan §9), but with a
        # low pair count (C2 is the slowest capture -- real wall time must
        # pass between beacons) random selection can easily skip a listed
        # destination entirely by chance -- confirmed live 2026-09-14, a
        # random 6-pair c2_multi_05 run never once picked one of 3 listed
        # victims and failed the P4.5 quality gate as a result. Round-robin
        # guarantees every victim_ips entry is actually exercised, and
        # matches real round-robin/failover multi-C2-server behavior more
        # faithfully than uniform random selection would anyway.
        victim_ip = victim_ips[i % len(victim_ips)]

        # --- benign session ---
        duration = random.uniform(15, 30)
        mean_gap = random.uniform(3, 8)
        port = random.choice(BENIGN_PORT_POOL)
        mark(f"benign_{i}_start")
        benign_session(duration, port, mean_gap, victim_ip)
        mark(f"benign_{i}_end")

        # --- c2 session ---
        base_interval = random.uniform(args.base_interval_min, args.base_interval_max)
        beacon_count = random.randint(args.beacon_count_min, args.beacon_count_max)
        port = random.choice(C2_PORT_POOL)
        mark(f"c2_{i}_start")
        if args.pattern == "sleep_burst":
            sleep_burst_session(base_interval, port, victim_ip)
        else:
            c2_session(base_interval, beacon_count, port, victim_ip, jitter_pct=args.jitter_pct)
        mark(f"c2_{i}_end")

        elapsed = time.time() - t_start
        print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
              f"(benign: {duration:.0f}s/gap~{mean_gap:.1f}s, c2: {beacon_count} beacons @ "
              f"{base_interval:.1f}s [{args.pattern}] -> {victim_ip})")

    with open(sessions_file, "w") as f:
        json.dump(sessions, f, indent=2)

    print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} session pairs saved to {sessions_file}")

    if args.scenario_id:
        write_provenance(
            scenario_id=args.scenario_id,
            threat_class="c2",
            attack_subtype="periodic_beacon" if args.pattern == "steady" else "sleep_burst_beacon",
            source="real",
            environment="loopback" if victim_ips == ["127.0.0.1"] else "docker_multihost",
            label_method="controlled_generation",
            generator="training/capture/capture_c2.py",
            attacker_ip=args.attacker_ip,
            victim_ips=victim_ips,
            configuration={
                "n_pairs": N_PAIRS,
                "base_interval_range_s": [args.base_interval_min, args.base_interval_max],
                "jitter_pct": args.jitter_pct,
                "beacon_count_range": [args.beacon_count_min, args.beacon_count_max],
                "pattern": args.pattern,
                "duration_cap": args.duration_cap,
            },
        )


if __name__ == "__main__":
    main()
