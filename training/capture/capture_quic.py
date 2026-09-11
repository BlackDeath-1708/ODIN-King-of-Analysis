"""
Real QUIC traffic capture -- independent training data for the TLS/QUIC
malware detector's QUIC path (PS 26145 (d): "Malware inside encrypted
sessions... TLS/QUIC metadata alone"). Until this script, the flow-stats
model had ZERO real QUIC training rows; QUIC events at inference time were
scored by a model trained purely on TLS ssl.log rows and hoped to
generalize (documented as an explicit, honest caveat in tls_malware.py).
This closes that gap with real aioquic handshakes to real HTTP/3 hosts.

Run against the isolated zeek_ml_capture_tls container
(docker-compose-tls.yml in this directory) -- same external-capture setup
capture_tls.py uses, since QUIC is UDP over the real egress interface too,
not loopback.

Delegates each handshake to quic_client.py via subprocess (one aioquic
event loop per process) rather than running many aioquic connections
concurrently in one event loop -- simpler and more robust than sharing
aioquic's per-connection internals across concurrent asyncio tasks, at the
cost of some process-spawn overhead (acceptable: I/O-bound handshakes,
not CPU-bound).

Run: backend/.venv/bin/python3 training/capture/capture_quic.py
"""
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

QUIC_CLIENT = Path(__file__).parent / "quic_client.py"
PYTHON = sys.executable  # must be a venv with aioquic installed (backend/.venv)

# Real domains that serve HTTP/3 over QUIC on port 443. Google and
# Cloudflare-fronted sites are the most reliably QUIC-enabled; a handshake
# quic_client.py can't complete (site doesn't speak QUIC, UDP/443 blocked,
# transient failure) just yields one fewer real sample -- same
# fail-quietly design as capture_tls.py's curl calls.
QUIC_DOMAINS = [
    "www.google.com", "www.youtube.com", "drive.google.com", "mail.google.com",
    "www.gstatic.com", "fonts.gstatic.com", "www.googleapis.com",
    "www.cloudflare.com", "developers.cloudflare.com", "blog.cloudflare.com",
    "discord.com", "www.discord.com", "medium.com", "www.medium.com",
    "www.facebook.com", "www.instagram.com", "www.whatsapp.com",
    "www.reddit.com", "www.speedtest.net", "www.fastly.com",
    "http3check.net", "www.litespeedtech.com", "caddyserver.com",
    "www.bing.com", "www.linkedin.com",
]
N_PER_DOMAIN = 15
MAX_WORKERS = 10
HANDSHAKE_TIMEOUT = 12  # generous vs quic_client.py's internal 8s asyncio.wait_for

random.seed(31)


def fetch(domain: str) -> None:
    try:
        subprocess.run(
            [PYTHON, str(QUIC_CLIENT), domain],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=HANDSHAKE_TIMEOUT,
        )
    except Exception:
        pass


def main():
    tasks = QUIC_DOMAINS * N_PER_DOMAIN
    random.shuffle(tasks)
    print(f"Firing {len(tasks)} real QUIC handshake attempts across {len(QUIC_DOMAINS)} "
          f"domains ({MAX_WORKERS} concurrent workers)...")

    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for _ in pool.map(fetch, tasks):
            done += 1
            if done % 25 == 0:
                print(f"[{time.time() - t0:6.0f}s] {done}/{len(tasks)} attempts done")

    print(f"\nDone in {time.time() - t0:.0f}s. {len(tasks)} real QUIC handshake attempts fired "
          f"(not all will have succeeded -- see quic.log for the real count).")


if __name__ == "__main__":
    main()
