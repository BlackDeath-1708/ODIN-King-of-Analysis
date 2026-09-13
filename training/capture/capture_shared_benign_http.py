"""
Dataset-plan Step 4 (diversify benign traffic sources): ddos, recon and c2
all captured benign traffic the SAME way until now -- plain TCP
connect() bursts (see capture_ddos.py/capture_recon.py/capture_c2.py's own
benign_traffic()/benign_session() functions). A model trained against
only one benign shape risks learning "not a bare connect() burst = benign"
rather than the actual per-threat signal. This adds a second, real,
shared benign shape (lightweight local HTTP GET/POST, matching the same
approach capture_exfil.py already uses for ITS benign class) and appends
session marks to all three sessions_*.json files at once, so one capture
run serves all three detectors' datasets -- matching the original dataset
plan's own "Data Reuse Strategy" (shared benign traffic across models).

Uses port 8300 -- distinct from exfil's 8199, ddos/c2's 8080-8130 pool,
and recon's 1-1000 scan range, so this traffic is never mistaken for any
existing scenario's signal.

Run: python3 training/capture/capture_shared_benign_http.py
Reads/writes: training/capture/sessions_ddos.json,
              training/capture/sessions_recon.json,
              training/capture/sessions_c2.json
"""
import http.server
import json
import random
import subprocess
import threading
import time
from pathlib import Path

PORT = 8300
N_REPS = 15
CAPTURE_DIR = Path(__file__).parent
SESSIONS_FILES = [
    CAPTURE_DIR / "sessions_ddos.json",
    CAPTURE_DIR / "sessions_recon.json",
    CAPTURE_DIR / "sessions_c2.json",
]

random.seed(4004)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"x" * random.randint(200, 2000)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def http_burst(duration):
    end = time.time() + duration
    while time.time() < end:
        if random.random() < 0.7:
            subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:{PORT}/"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        else:
            subprocess.run(["curl", "-s", "-o", "/dev/null", "-X", "POST",
                             "-d", "x" * random.randint(100, 2000), f"http://127.0.0.1:{PORT}/"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        time.sleep(random.uniform(0.3, 1.0))


def main():
    server = start_server()
    time.sleep(0.5)
    marks = []
    t_start = time.time()
    for i in range(N_REPS):
        duration = random.uniform(15, 25)
        marks.append({"label": f"benign_http_{i}_start", "ts": time.time()})
        http_burst(duration)
        marks.append({"label": f"benign_http_{i}_end", "ts": time.time()})
        print(f"[{time.time()-t_start:.0f}s] rep {i+1}/{N_REPS} done ({duration:.0f}s)")
    server.shutdown()

    for path in SESSIONS_FILES:
        existing = []
        if path.exists():
            with open(path) as f:
                existing = json.load(f)
        with open(path, "w") as f:
            json.dump(existing + marks, f, indent=2)
        print(f"Appended {len(marks)//2} benign_http sessions to {path}")

    print(f"\nDone in {time.time()-t_start:.0f}s.")


if __name__ == "__main__":
    main()
