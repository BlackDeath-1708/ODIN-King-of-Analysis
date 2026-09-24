"""
Bulk real-traffic capture for the reconnaissance / port-scan classifier,
run against the isolated zeek_ml_capture container (see docker-compose.yml
in this directory) -- never the live demo's zeek_monitor container.

Uses real `nmap -sT` scans (TCP connect scan -- needs no root, and Zeek
logs the identical fan-out signature it would for a raw SYN scan `-sS`).
This directly matches PS 26145's "port scanning" threat category; nmap
itself isn't a PS-named tool (the PS doesn't name one for this category),
but it's the de facto real-world tool for this exact behavior.

Randomized per session (same scheme as recon-ml-poc/capture_data_bulk.py):
  Benign: duration (15-30s), 1-3 fixed ports from a pool, human-paced
          connections (0.5-1.0s apart).
  Recon:  port range width (50-800) + random start offset, scan rate
          (10-100 pkts/sec) -- spans fast/wide and slow/narrow scan
          profiles.

Ground truth label is generator intent, not whether any fixed rule fires.

Run: python3 training/capture/capture_recon.py
     python3 training/capture/capture_recon.py --victim-ips 10.10.0.20,10.10.0.21 \
         --attacker-ip 10.10.0.10 --scenario-id recon_multi_02
Writes: training/capture/sessions_recon.json (or sessions_recon_<scenario-id>.json)
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
N_PAIRS = 90   # previous 50 pairs -> 9,990 rows (~200/pair); 90 pairs targets ~18,000 rows
random.seed(42)

sessions = []


def mark(label):
    sessions.append({"label": label, "ts": time.time()})


def benign_traffic(duration, ports, victim_ip):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        port = ports[i % len(ports)]
        i += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            s.connect((victim_ip, port))
            s.close()
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 1.0))


def recon_scan(start_port, width, max_rate, victim_ips):
    # Scans every victim in the list within the same session -- this is what
    # actually produces host_fanout/unique_dst_ips signal for the
    # recon_multi_02/03 (2/3/4-victim) scenarios, not just a single target
    # scanned repeatedly.
    end_port = start_port + width
    for victim_ip in victim_ips:
        subprocess.run(
            ["nmap", "-sT", "-p", f"{start_port}-{end_port}", "--max-rate", str(max_rate), victim_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def bursty_recon_scan(start_port, width, max_rate, victim_ips, n_bursts=4, pause_range=(3, 8)):
    """recon_multi_07: alternating fast bursts + pauses instead of one
    continuous scan -- a genuinely different temporal shape from steady/slow,
    not just a rate-parameter change."""
    end_port = start_port + width
    per_burst_width = max(5, width // n_bursts)
    for burst_i in range(n_bursts):
        burst_start = start_port + burst_i * per_burst_width
        burst_end = min(burst_start + per_burst_width, end_port)
        for victim_ip in victim_ips:
            subprocess.run(
                ["nmap", "-sT", "-p", f"{burst_start}-{burst_end}", "--max-rate", str(max_rate), victim_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        if burst_i < n_bursts - 1:
            time.sleep(random.uniform(*pause_range))


PORT_POOL = list(range(8080, 8130))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_multihost_args(parser)
    parser.add_argument("--port-range-start", type=int, default=None,
                         help="Fixed scan start port (recon_multi_04 'different port ranges'). "
                              "Default: random per session, same as original behavior.")
    parser.add_argument("--port-range-width", type=int, default=None,
                         help="Fixed scan width in ports, paired with --port-range-start.")
    parser.add_argument("--rate-min", type=int, default=10, help="Min scan rate, pkts/sec.")
    parser.add_argument("--rate-max", type=int, default=100,
                         help="Max scan rate, pkts/sec (recon_multi_05 'different scan rates' -- "
                              "e.g. --rate-min 1 --rate-max 5 for a slow/stealthy profile).")
    parser.add_argument("--scan-pattern", choices=["steady", "bursty"], default="steady",
                         help="steady (default): one continuous scan per session, same as "
                              "original behavior. bursty (recon_multi_07): alternating fast "
                              "bursts and pauses -- a different temporal shape, not just a "
                              "different rate.")
    args = parser.parse_args()
    victim_ips = resolve_victim_ips(args)
    sessions_file = OUT_DIR / sessions_filename("sessions_recon.json", args.scenario_id)

    t_start = time.time()
    for i in range(N_PAIRS):
        if args.duration_cap and (time.time() - t_start) >= args.duration_cap:
            print(f"  [duration-cap] stopping after {i} pairs ({time.time() - t_start:.0f}s)")
            break

        # --- benign session ---
        duration = random.uniform(15, 30)
        n_ports = random.choice([1, 2, 3])
        ports = random.sample(PORT_POOL, n_ports)
        mark(f"benign_{i}_start")
        benign_traffic(duration, ports, victim_ips[0])
        mark(f"benign_{i}_end")

        # --- recon session ---
        width = args.port_range_width if args.port_range_width else random.randint(50, 800)
        start_port = args.port_range_start if args.port_range_start else random.randint(1, max(1, 2000 - width))
        max_rate = random.randint(args.rate_min, args.rate_max)
        mark(f"recon_{i}_start")
        if args.scan_pattern == "bursty":
            bursty_recon_scan(start_port, width, max_rate, victim_ips)
        else:
            recon_scan(start_port, width, max_rate, victim_ips)
        mark(f"recon_{i}_end")

        elapsed = time.time() - t_start
        print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
              f"(benign: {duration:.0f}s/{n_ports}ports, recon: {width}wide@{max_rate}pps "
              f"[{args.scan_pattern}], victims: {victim_ips})")

    with open(sessions_file, "w") as f:
        json.dump(sessions, f, indent=2)

    print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} session pairs saved to {sessions_file}")

    if args.scenario_id:
        write_provenance(
            scenario_id=args.scenario_id,
            threat_class="recon",
            attack_subtype="port_scan",
            source="real",
            environment="loopback" if victim_ips == ["127.0.0.1"] else "docker_multihost",
            label_method="controlled_generation",
            generator="training/capture/capture_recon.py",
            attacker_ip=args.attacker_ip,
            victim_ips=victim_ips,
            configuration={
                "n_pairs": N_PAIRS,
                "port_width_range": [50, 800] if not args.port_range_width else [args.port_range_width],
                "port_range_start": args.port_range_start,
                "rate_range": [args.rate_min, args.rate_max],
                "scan_pattern": args.scan_pattern,
                "duration_cap": args.duration_cap,
            },
        )


if __name__ == "__main__":
    main()
