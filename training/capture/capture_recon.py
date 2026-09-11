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
Writes: training/capture/sessions_recon.json
"""
import json
import random
import socket
import subprocess
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent
SESSIONS_FILE = OUT_DIR / "sessions_recon.json"
N_PAIRS = 90   # previous 50 pairs -> 9,990 rows (~200/pair); 90 pairs targets ~18,000 rows
random.seed(42)

sessions = []


def mark(label):
    sessions.append({"label": label, "ts": time.time()})


def benign_traffic(duration, ports):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        port = ports[i % len(ports)]
        i += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            s.connect(("127.0.0.1", port))
            s.close()
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 1.0))


def recon_scan(start_port, width, max_rate):
    end_port = start_port + width
    subprocess.run(
        ["nmap", "-sT", "-p", f"{start_port}-{end_port}", "--max-rate", str(max_rate), "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


PORT_POOL = list(range(8080, 8130))

t_start = time.time()
for i in range(N_PAIRS):
    # --- benign session ---
    duration = random.uniform(15, 30)
    n_ports = random.choice([1, 2, 3])
    ports = random.sample(PORT_POOL, n_ports)
    mark(f"benign_{i}_start")
    benign_traffic(duration, ports)
    mark(f"benign_{i}_end")

    # --- recon session ---
    width = random.randint(50, 800)
    start_port = random.randint(1, max(1, 2000 - width))
    max_rate = random.randint(10, 100)
    mark(f"recon_{i}_start")
    recon_scan(start_port, width, max_rate)
    mark(f"recon_{i}_end")

    elapsed = time.time() - t_start
    print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
          f"(benign: {duration:.0f}s/{n_ports}ports, recon: {width}wide@{max_rate}pps)")

with open(SESSIONS_FILE, "w") as f:
    json.dump(sessions, f, indent=2)

print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} session pairs saved to {SESSIONS_FILE}")
