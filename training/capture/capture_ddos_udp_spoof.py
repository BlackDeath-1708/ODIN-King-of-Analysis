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
Appends to: training/capture/sessions_ddos.json
"""
import json
import random
import socket
import subprocess
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent
SESSIONS_FILE = OUT_DIR / "sessions_ddos.json"
N_PAIRS = 40
random.seed(53)

PORT_POOL = list(range(8080, 8130))
REFLECTION_PORTS = [53, 123]
SPOOFED_PORTS = list(range(19140, 19170))  # distinct from the original 19080-19109 flood pool


def mark(sessions, label):
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


def udp_flood(duration, port, target_rate):
    interval_us = max(int(1_000_000 / target_rate), 200)
    count = int(duration * target_rate)
    cmd = ["hping3", "-2", "-p", str(port), "-i", f"u{interval_us}", "-c", str(count), "127.0.0.1"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration + 5)
    except subprocess.TimeoutExpired:
        print(f"  [warn] udp_flood exceeded {duration + 5:.0f}s bound, killed")


def spoofed_flood(duration, port, target_rate):
    interval_us = max(int(1_000_000 / target_rate), 200)
    count = int(duration * target_rate)
    cmd = ["hping3", "-2", "--rand-source", "-p", str(port),
           "-i", f"u{interval_us}", "-c", str(count), "127.0.0.1"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration + 5)
    except subprocess.TimeoutExpired:
        print(f"  [warn] spoofed_flood exceeded {duration + 5:.0f}s bound, killed")


def main():
    sessions = []
    t_start = time.time()
    for i in range(N_PAIRS):
        duration = random.uniform(15, 30)
        ports = random.sample(PORT_POOL, random.choice([1, 2, 3]))
        mark(sessions, f"benign_udpspoof_{i}_start")
        benign_traffic(duration, ports)
        mark(sessions, f"benign_udpspoof_{i}_end")

        flood_duration = random.uniform(8, 20)
        target_rate = random.uniform(10, 300)
        port = random.choice(REFLECTION_PORTS)
        mark(sessions, f"ddos_udpflood_{i}_start")
        udp_flood(flood_duration, port, target_rate)
        mark(sessions, f"ddos_udpflood_{i}_end")

        flood_duration = random.uniform(8, 20)
        target_rate = random.uniform(10, 300)
        port = random.choice(SPOOFED_PORTS)
        mark(sessions, f"ddos_spoofed_{i}_start")
        spoofed_flood(flood_duration, port, target_rate)
        mark(sessions, f"ddos_spoofed_{i}_end")

        elapsed = time.time() - t_start
        print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done")

    # Append to the existing sessions file rather than overwrite -- Zeek's
    # container/conn.log was left running across both capture scripts.
    existing = []
    if SESSIONS_FILE.exists():
        with open(SESSIONS_FILE) as f:
            existing = json.load(f)
    with open(SESSIONS_FILE, "w") as f:
        json.dump(existing + sessions, f, indent=2)

    print(f"\nDone in {time.time() - t_start:.0f}s. Appended {len(sessions)//2} sessions "
          f"({len(existing)//2} existing + {len(sessions)//2} new) to {SESSIONS_FILE}")


if __name__ == "__main__":
    main()
