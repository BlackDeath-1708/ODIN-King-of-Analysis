"""
Supplementary real-traffic capture for the DDoS classifier, adding the two
PS 26145 (a) attack patterns the original capture_ddos.py didn't cover:
UDP reflection/amplification floods, and spoofed-source floods. Appends to
the SAME sessions_ddos.json / conn.log as capture_ddos.py (Zeek's
container is left running across both scripts) -- session labels still
start with "ddos" so build_dataset_ddos.py's existing label logic needs no
change.

UDP_FLOOD sessions: real hping3 UDP packets (`-2`), single real source,
targeting ports commonly abused for reflection/amplification in the real
world (53 DNS, 123 NTP) -- rate-bounded the same way as the original SYN
flood (never --flood, always -c <count> + a subprocess timeout).

SPOOFED_FLOOD sessions: real hping3 UDP packets with `--rand-source` --
genuinely varied non-local source addresses (verified: Zeek captures these
correctly on loopback, e.g. real-looking addresses like 15.106.219.46 show
up as id.orig_h with local_orig:false). This is what makes unique_src_ips /
src_ip_entropy a real trained signal instead of a zero-variance constant --
see backend/detectors/ddos.py and training/build_dataset_ddos.py's
2026-09-12 update notes. Real amplification attacks are themselves almost
always spoofed-source UDP, so this session type doubles as evidence for
both PS-named patterns at once.

Run: python3 training/capture/capture_ddos_udp_spoof.py
     python3 training/capture/capture_ddos_udp_spoof.py --victim-ip 10.10.0.20 \
         --attacker-ip 10.10.0.10 --scenario-id ddos_multi_04
Appends to: training/capture/sessions_ddos.json (or sessions_ddos_<scenario-id>.json)
"""
import argparse
import json
import random
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from multihost_common import add_multihost_args, resolve_victim_ips, sessions_filename, write_provenance  # noqa: E402

OUT_DIR = Path(__file__).parent
N_PAIRS = 40
random.seed(53)

PORT_POOL = list(range(8080, 8130))
REFLECTION_PORTS = [53, 123]
SPOOFED_PORTS = list(range(19140, 19170))  # distinct from the original 19080-19109 flood pool


def mark(sessions, label):
    sessions.append({"label": label, "ts": time.time()})


def _connect_once(port, victim_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect((victim_ip, port))
        s.close()
    except Exception:
        pass


def benign_traffic(duration, ports, victim_ip):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        port = ports[i % len(ports)]
        i += 1
        _connect_once(port, victim_ip)
        time.sleep(random.uniform(0.5, 1.5))


def udp_flood(duration, port, target_rate, victim_ip):
    interval_us = max(int(1_000_000 / target_rate), 200)
    count = int(duration * target_rate)
    cmd = ["hping3", "-2", "-p", str(port), "-i", f"u{interval_us}", "-c", str(count), victim_ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration + 5)
    except subprocess.TimeoutExpired:
        print(f"  [warn] udp_flood exceeded {duration + 5:.0f}s bound, killed")


def spoofed_flood(duration, port, target_rate, victim_ip):
    interval_us = max(int(1_000_000 / target_rate), 200)
    count = int(duration * target_rate)
    cmd = ["hping3", "-2", "--rand-source", "-p", str(port),
           "-i", f"u{interval_us}", "-c", str(count), victim_ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration + 5)
    except subprocess.TimeoutExpired:
        print(f"  [warn] spoofed_flood exceeded {duration + 5:.0f}s bound, killed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_multihost_args(parser)
    parser.add_argument("--variant", choices=["both", "udp_only", "spoofed_only"], default="both",
                         help="both (default): original behavior, every pair gets a real UDP "
                              "reflection-style flood AND a real spoofed-source flood, one "
                              "combined 'spoofed_udp_flood' provenance label -- unchanged from "
                              "before this flag existed. udp_only/spoofed_only: emit just one "
                              "attack subtype per pair, with its own accurate provenance label "
                              "-- lets ddos_multi_03 (UDP) and ddos_multi_04 (spoofed, UNSEEN) "
                              "be genuinely distinct captures instead of two runs of this "
                              "same-seeded script producing near-identical session parameters.")
    parser.add_argument("--rate-min", type=int, default=10, help="Min flood rate, pkts/sec.")
    parser.add_argument("--rate-max", type=int, default=300,
                         help="Max flood rate, pkts/sec -- override for a genuinely different "
                              "rate/burstiness profile (e.g. ddos_multi_04's 'varying rate/"
                              "burstiness' UNSEEN scenario, distinct from ddos_multi_03's).")
    args = parser.parse_args()
    victim_ips = resolve_victim_ips(args)
    victim_ip = victim_ips[0]
    sessions_file = OUT_DIR / sessions_filename("sessions_ddos.json", args.scenario_id)

    sessions = []
    t_start = time.time()
    for i in range(N_PAIRS):
        if args.duration_cap and (time.time() - t_start) >= args.duration_cap:
            print(f"  [duration-cap] stopping after {i} pairs ({time.time() - t_start:.0f}s)")
            break

        duration = random.uniform(15, 30)
        ports = random.sample(PORT_POOL, random.choice([1, 2, 3]))
        mark(sessions, f"benign_udpspoof_{i}_start")
        benign_traffic(duration, ports, victim_ip)
        mark(sessions, f"benign_udpspoof_{i}_end")

        if args.variant in ("both", "udp_only"):
            flood_duration = random.uniform(8, 20)
            target_rate = random.uniform(args.rate_min, args.rate_max)
            port = random.choice(REFLECTION_PORTS)
            mark(sessions, f"ddos_udpflood_{i}_start")
            udp_flood(flood_duration, port, target_rate, victim_ip)
            mark(sessions, f"ddos_udpflood_{i}_end")

        if args.variant in ("both", "spoofed_only"):
            flood_duration = random.uniform(8, 20)
            target_rate = random.uniform(args.rate_min, args.rate_max)
            port = random.choice(SPOOFED_PORTS)
            mark(sessions, f"ddos_spoofed_{i}_start")
            spoofed_flood(flood_duration, port, target_rate, victim_ip)
            mark(sessions, f"ddos_spoofed_{i}_end")

        elapsed = time.time() - t_start
        print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done [{args.variant}]")

    # Append to the existing sessions file rather than overwrite -- Zeek's
    # container/conn.log was left running across both capture scripts.
    existing = []
    if sessions_file.exists():
        with open(sessions_file) as f:
            existing = json.load(f)
    with open(sessions_file, "w") as f:
        json.dump(existing + sessions, f, indent=2)

    print(f"\nDone in {time.time() - t_start:.0f}s. Appended {len(sessions)//2} sessions "
          f"({len(existing)//2} existing + {len(sessions)//2} new) to {sessions_file}")

    if args.scenario_id:
        subtype_by_variant = {
            "both": "spoofed_udp_flood",
            "udp_only": "udp_flood",
            "spoofed_only": "spoofed_flood",
        }
        write_provenance(
            scenario_id=args.scenario_id,
            threat_class="ddos",
            attack_subtype=subtype_by_variant[args.variant],
            source="real",
            environment="loopback" if victim_ip == "127.0.0.1" else "docker_multihost",
            label_method="controlled_generation",
            generator="training/capture/capture_ddos_udp_spoof.py",
            attacker_ip=args.attacker_ip,
            victim_ips=[victim_ip],
            configuration={
                "n_pairs": N_PAIRS,
                "variant": args.variant,
                "rate_range_pps": [args.rate_min, args.rate_max],
                "reflection_ports": REFLECTION_PORTS if args.variant in ("both", "udp_only") else None,
                "spoofed_ports": SPOOFED_PORTS if args.variant in ("both", "spoofed_only") else None,
                "duration_cap": args.duration_cap,
            },
        )


if __name__ == "__main__":
    main()
