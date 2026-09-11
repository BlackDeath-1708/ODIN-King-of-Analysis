#!/usr/bin/env python3
"""
Synthetic traffic generator for prototype validation -- a controlled demo
input, not a production attack-simulation tool. Simulates C2 beaconing:
connects to a local listener at a fixed interval (+/- jitter).

Demo timing is compressed (5s interval, 6 beacons) so the detector's
MIN_OBSERVATIONS=5 threshold is reached in ~25-30s for a live demo.
A production deployment would observe much longer, less obvious
intervals -- these are demo-timing knobs, not detection-logic changes.
Override via environment variables:

    C2_INTERVAL=5 C2_JITTER=0.5 C2_BEACONS=6 python3 generate_c2.py
"""
import os
import socket
import time
import random

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9999
INTERVAL    = float(os.environ.get("C2_INTERVAL", 5))
JITTER      = float(os.environ.get("C2_JITTER", 0.5))
BEACONS     = int(os.environ.get("C2_BEACONS", 6))

print(f"[C2 Generator] Sending {BEACONS} beacons to {TARGET_HOST}:{TARGET_PORT}")
print(f"[C2 Generator] Interval: {INTERVAL}s +/- {JITTER}s jitter")

for i in range(BEACONS):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_HOST, TARGET_PORT))
        s.send(b"beacon\n")
        s.close()
        print(f"[C2 Generator] Beacon {i + 1}/{BEACONS} sent")
    except Exception as e:
        print(f"[C2 Generator] Connection failed (expected if no listener): {e}")

    wait = INTERVAL + random.uniform(-JITTER, JITTER)
    if i < BEACONS - 1:
        print(f"[C2 Generator] Sleeping {wait:.1f}s...")
        time.sleep(wait)

print("[C2 Generator] Done.")
