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
Writes: training/capture/sessions_c2.json
"""
import json
import random
import socket
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent
SESSIONS_FILE = OUT_DIR / "sessions_c2.json"
N_PAIRS = 65   # previous 30 pairs -> 7,265 rows (~242/pair); 65 pairs targets ~15,700 rows
random.seed(13)

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


def benign_session(duration, port, mean_gap):
    end = time.time() + duration
    while time.time() < end:
        _connect_once(port)
        time.sleep(random.expovariate(1.0 / mean_gap))


def c2_session(base_interval, beacon_count, port):
    for _ in range(beacon_count):
        _connect_once(port)
        jitter = base_interval * random.uniform(-0.15, 0.15)
        time.sleep(max(0.1, base_interval + jitter))


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

t_start = time.time()
for i in range(N_PAIRS):
    # --- benign session ---
    duration = random.uniform(15, 30)
    mean_gap = random.uniform(3, 8)
    port = random.choice(BENIGN_PORT_POOL)
    mark(f"benign_{i}_start")
    benign_session(duration, port, mean_gap)
    mark(f"benign_{i}_end")

    # --- c2 session ---
    base_interval = random.uniform(3, 6)
    beacon_count = random.randint(10, 15)
    port = random.choice(C2_PORT_POOL)
    mark(f"c2_{i}_start")
    c2_session(base_interval, beacon_count, port)
    mark(f"c2_{i}_end")

    elapsed = time.time() - t_start
    print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
          f"(benign: {duration:.0f}s/gap~{mean_gap:.1f}s, c2: {beacon_count} beacons @ {base_interval:.1f}s)")

with open(SESSIONS_FILE, "w") as f:
    json.dump(sessions, f, indent=2)

print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} session pairs saved to {SESSIONS_FILE}")
