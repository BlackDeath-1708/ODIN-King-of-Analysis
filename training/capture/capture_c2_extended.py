"""
Extends the C2 beaconing capture (capture_c2.py) into the two input
regions its own training data never covered -- see ML_MODELS.md's "C2's
range gate" section and backend/detectors/c2.py's docstring for why the
deployed model is only trusted within observation_count<=11 and
mean_interval<=7.0s: the original capture used a 3-6s base interval and
10-15 beacons/session, so the RandomForest never saw a single
counterexample outside that box and was found to false-positive 93% of
the time when forced to extrapolate past it.

This does NOT attempt to cover the rule's full theoretical 3-600s range in
one pass -- a single c2 session at a 600s interval with 10+ beacons would
take over an hour of real wall-clock time by itself, and this capture
needs real time to pass between every beacon by construction (see
capture_c2.py's own honesty note). Instead it meaningfully widens the
covered range (up to 45s intervals, up to 20 observations) while staying
within a background-runnable time budget, and the fix should be judged as
"closes the specific blind spots that were empirically found," not "closes
the rule's entire nominal range." Revisit with a longer capture budget if
a future stress test finds a new blind spot inside 45-600s.

Two new session types, both still targeting a single fixed (host, port)
for their whole duration (same reasoning as capture_c2.py):

  benign_long: duration 60-100s, mean_gap 3-6s (Poisson/expovariate gaps,
    same as capture_c2.py's benign sessions) -- long and frequent enough
    that some real sessions should genuinely accumulate 12+ connection
    events, giving the model real benign counterexamples in the
    observation_count>=12 region it previously only ever saw as c2.

  c2_slow: base_interval 8-45s (+-15% jitter, same low-CV construction as
    capture_c2.py's c2 sessions), beacon_count 6-10 -- gives the model
    real c2-labeled examples with mean_interval>7.0s, the region it
    previously only ever saw as benign (by construction of the range gate,
    not because it was actually tested there).

Writes to a fresh, separate log directory (see docker-compose-c2-
extended.yml) and a separate sessions file -- training/build_dataset_c2.py
merges both the original and extended sessions/conn.log rather than this
script touching either.

Run: python3 training/capture/capture_c2_extended.py
Prerequisite: docker compose -f training/capture/docker-compose-c2-extended.yml up -d
Writes: training/capture/sessions_c2_extended.json
"""
import json
import random
import socket
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent
SESSIONS_FILE = OUT_DIR / "sessions_c2_extended.json"
N_PAIRS = 15
random.seed(2026)

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


# Same pools as capture_c2.py -- verified free of any listener on this
# machine again before this run (see this session's port-check), and safe
# to reuse since this capture writes to its own separate log directory
# entirely (no risk of re-triggering the original Kafka-port contamination
# bug, which was specifically about a shared, overlapping conn.log).
BENIGN_PORT_POOL = list(range(8080, 8130))
C2_PORT_POOL = list(range(19110, 19140))

t_start = time.time()
est_seconds = N_PAIRS * ((60 + 100) / 2 + 26.5 * 8)
print(f"Estimated duration: ~{est_seconds / 60:.0f} minutes for {N_PAIRS} pairs")

for i in range(N_PAIRS):
    # --- long benign session: targets observation_count>=12 with label=0 ---
    duration = random.uniform(60, 100)
    mean_gap = random.uniform(3, 6)
    port = random.choice(BENIGN_PORT_POOL)
    mark(f"benign_long_{i}_start")
    benign_session(duration, port, mean_gap)
    mark(f"benign_long_{i}_end")

    # --- slow c2 session: targets mean_interval>7.0 with label=1 ---
    # NOTE: label name must start with "c2" -- build_dataset_c2.py's
    # load_sessions() classifies purely by that prefix.
    base_interval = random.uniform(8, 45)
    beacon_count = random.randint(6, 10)
    port = random.choice(C2_PORT_POOL)
    mark(f"c2_slow_{i}_start")
    c2_session(base_interval, beacon_count, port)
    mark(f"c2_slow_{i}_end")

    elapsed = time.time() - t_start
    print(f"[{elapsed:6.0f}s] pair {i + 1}/{N_PAIRS} done "
          f"(benign_long: {duration:.0f}s/gap~{mean_gap:.1f}s, "
          f"c2_slow: {beacon_count} beacons @ {base_interval:.1f}s)", flush=True)

with open(SESSIONS_FILE, "w") as f:
    json.dump(sessions, f, indent=2)

print(f"\nDone in {time.time() - t_start:.0f}s. {len(sessions)//2} extended session pairs saved to {SESSIONS_FILE}")
