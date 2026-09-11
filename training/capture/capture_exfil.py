"""
Real-traffic capture for the data-exfiltration classifier, run against
BOTH isolated capture containers already set up in this project:
  - zeek_ml_capture (docker-compose.yml, loopback) for the local HTTP
    asymmetric-transfer traffic below.
  - zeek_ml_capture_tls (docker-compose-tls.yml, real egress interface)
    for the real ICMP/DNS-shaped traffic below, since it targets real
    external hosts, not loopback.
Both can run concurrently -- different interfaces, different log dirs, no
contamination risk (unlike the earlier ddos/recon/c2 Kafka-port lesson,
this doesn't share a narrow port range with anything else running).

exfil.py's features (orig_bytes, resp_bytes, byte_ratio, duration,
orig_pkts, resp_pkts, bytes_per_sec, is_icmp, to_dns, dst_port-in-common)
are ALL native conn.log fields -- no join bug like tls_malware.py's, real
capture is straightforward here.

Four real traffic shapes generated, matching exfil.py's own rule patterns
so the dataset's real vs malicious-shaped classes line up with what the
detector actually looks for:
  BENIGN: small symmetric-ish local HTTP GET requests (small orig_bytes,
    comparable resp_bytes) -- ordinary request/response traffic.
  HIGH_UPLOAD-shaped: local HTTP POST of large bodies (1-5MB) to a small
    response -- byte_ratio > 5, orig_bytes > 500k (exfil.py's own
    HIGH_UPLOAD rule thresholds).
  ICMP_COVERT-shaped: real ICMP echo requests with large payloads (ping -s)
    to a real external host -- orig_bytes > 1000 on proto=icmp.
  DNS_EXFIL-shaped: real UDP packets (raw socket, one persistent 5-tuple so
    Zeek aggregates them into one flow) to dst_port 53 on a real external
    host, with padded payload data accumulating past 5000 bytes.

Run: python3 training/capture/capture_exfil.py
"""
import http.server
import random
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

LOCAL_PORT = 8199
EXTERNAL_HOSTS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # real, well-known public resolvers

random.seed(31)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep stdout clean

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


def start_local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def benign_get(_):
    subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:{LOCAL_PORT}/"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)


def high_upload_post(_):
    # curl reading the POST body from stdin (piped `input=`) can't know the
    # size in advance and falls back to chunked transfer-encoding -- the
    # handler's Content-Length-based read then sees 0 and never reads the
    # body, so almost nothing actually crosses the wire before the server's
    # early response tears the connection down (verified: real captured
    # orig_bytes topped out at 148 bytes with the stdin-pipe approach).
    # A real temp file lets curl determine size up front and set a real
    # Content-Length header, which is what actually gets the full payload
    # transmitted and captured.
    size = random.randint(1_000_000, 5_000_000)
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"x" * size)
        f.flush()
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-X", "POST",
             "--data-binary", f"@{f.name}",
             f"http://127.0.0.1:{LOCAL_PORT}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )


def icmp_covert(_):
    size = random.randint(1200, 8000)
    host = random.choice(EXTERNAL_HOSTS)
    try:
        subprocess.run(["ping", "-c", "1", "-s", str(size), "-W", "3", host],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass


def dns_exfil_shaped(_):
    """One persistent UDP socket, multiple sends to the same (src port,
    dst host, dst port=53) 5-tuple so Zeek aggregates them into a single
    conn.log flow whose orig_bytes accumulates past exfil.py's 5000-byte
    DNS_EXFIL threshold. Payload doesn't need to be valid DNS -- Zeek's
    conn.log records raw flow volume regardless of whether the dns
    analyzer can parse it."""
    host = random.choice(EXTERNAL_HOSTS)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        n_packets = random.randint(15, 40)
        for _ in range(n_packets):
            payload = bytes(random.randint(0, 255) for _ in range(random.randint(200, 400)))
            s.sendto(payload, (host, 53))
            time.sleep(0.02)
    except Exception:
        pass
    finally:
        s.close()


def main():
    server = start_local_server()
    time.sleep(0.5)
    t0 = time.time()

    print("Phase 1: benign local HTTP GETs (2500)...")
    with ThreadPoolExecutor(max_workers=30) as pool:
        list(pool.map(benign_get, range(2500)))
    print(f"  done at {time.time()-t0:.0f}s")

    print("Phase 2: HIGH_UPLOAD-shaped local HTTP POSTs (600)...")
    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(high_upload_post, range(600)))
    print(f"  done at {time.time()-t0:.0f}s")

    print("Phase 3: real ICMP_COVERT-shaped pings (1200)...")
    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(icmp_covert, range(1200)))
    print(f"  done at {time.time()-t0:.0f}s")

    print("Phase 4: real DNS_EXFIL-shaped UDP bursts (400 flows)...")
    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(dns_exfil_shaped, range(400)))
    print(f"  done at {time.time()-t0:.0f}s")

    server.shutdown()
    print(f"\nDone in {time.time()-t0:.0f}s.")


if __name__ == "__main__":
    main()
