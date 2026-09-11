"""
Bulk real-traffic capture for the DDoS / SYN-flood classifier, run against
the isolated zeek_ml_capture container (docker-compose.yml in this
directory) -- never the live demo's zeek_monitor container.

Per PS 26145's named methodology ("attack traffic from hping3 (SYN/UDP
floods)"), this uses REAL hping3 SYN packets, not a connect()-based
simulation. Earlier exploration work (recon-ml-poc/capture_data_ddos.py)
deliberately avoided hping3 because `sudo hping3 --flood` on loopback once
hung the machine -- flood mode has NO rate limit and both attacker and
"victim" compete for the same CPU. This script avoids that failure mode
two ways instead of avoiding hping3 altogether:
  1. Never uses --flood. Every invocation is `-i u<micros>` (a fixed,
     computed inter-packet delay) capped at the same 10-300 conn/sec range
     used before, plus an explicit `-c <count>` so hping3 stops on its own.
  2. A subprocess timeout (session duration + 5s margin) as a second,
     independent bound in case -c is ever miscounted.
Needs `sudo setcap cap_net_raw+ep $(which hping3)` run once beforehand so
this can run without sudo (see repo setup notes).

Benign traffic: this environment has no iperf3/Ostinato/TRex installed
(the PS's own examples are given as "e.g."). Falls back to the same plain
TCP connect() traffic used throughout this project's other capture
scripts -- Zeek logs a real conn.log entry per attempt either way, which
is the only thing the feature set below actually reads.

Feature parity: see build_dataset_ddos.py / backend/detectors/ddos.py --
this script only needs to produce real conn.log rows with accurate
session boundaries; feature computation happens at dataset-build time.

Randomized per session (same scheme as recon-ml-poc/capture_data_ddos.py):
  Benign: duration (15-30s), 1-3 fixed ports from a pool, human-paced
          connections (0.5-1.5s apart).
  DDoS:   target rate (10-300 conn/sec, deliberately spans both above and
          below the original 200/10s fixed-rule threshold) and burst
          duration (8-20s), single fixed dst port per session.

Ground truth label is generator intent, not whether any fixed rule fires.

Run: sudo setcap cap_net_raw+ep $(which hping3)   # once
     python3 training/capture/capture_ddos.py
Writes: training/capture/sessions_ddos.json
"""
import json
import random
import socket
import subprocess
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent
SESSIONS_FILE = OUT_DIR / "sessions_ddos.json"
N_PAIRS = 65   # ~253 rows/pair observed previously -> targets ~16,400 rows total
random.seed(7)

sessions = []


def mark(label):
    sessions.append({"label": label, "ts": time.time()})


def _connect_once(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(("127.0.0.1", port))
        s.close()
    except Exception:
        pass


def benign_traffic(duration, ports):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        port = ports[i % len(ports)]
        i += 1
        _connect_once(port)
        time.sleep(random.uniform(0.5, 1.5))


def hping3_flood(duration, port, target_rate):
    """Real hping3 SYN packets at a bounded rate -- never --flood."""
    interval_us = max(int(1_000_000 / target_rate), 200)   # floor: 5000 pps hard cap
    count = int(duration * target_rate)
    cmd = [
        "hping3", "-S", "-p", str(port),
        "-i", f"u{interval_us}",
        "-c", str(count),
        "127.0.0.1",
    ]
    try:
        subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=duration + 5,
        )
    except subprocess.TimeoutExpired:
        print(f"  [warn] hping3 exceeded {duration + 5:.0f}s bound, killed")


PORT_POOL = list(range(8080, 8130))
# NOTE: was originally range(9080, 9110), which overlaps the live Kafka
# broker/controller ports (9092/9093) running in this environment --
# confirmed via `ss -tanp` to badly corrupt the c2 dataset the same pool
# was originally used for (see capture_c2.py's note). Moved before this
# script's first run to avoid the same contamination here.
FLOOD_PORT_POOL = list(range(19080, 19109))

t_start = time.time()
for i in range(N_PAIRS):
    # --- benign session ---
    duration = random.uniform(15, 30)
    n_ports = random.choice([1, 2, 3])
    ports = random.sample(PORT_POOL, n_ports)
    mark(f"benign_{i}_start")
    benign_traffic(duration, ports)
    mark(f"benign_{i}_end")

    # --- ddos session (real hping3 SYN flood, rate-bounded) ---
    flood_duration = random.uniform(8, 20)
    target_rate = random.uniform(10, 300)
    port = random.choice(FLOOD_PORT_POOL)
    mark(f"ddos_{i}_start")
    hping3_flood(flood_duration, port, target_rate)
    mark(f"ddos_{i}_end")

    elapsed = time.time() - t_start
    print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
          f"(benign: {duration:.0f}s/{n_ports}ports, ddos: {flood_duration:.0f}s@{target_rate:.0f}pps)")

with open(SESSIONS_FILE, "w") as f:
    json.dump(sessions, f, indent=2)

print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} session pairs saved to {SESSIONS_FILE}")
