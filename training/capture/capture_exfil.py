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

Run: python3 training/capture/capture_exfil.py                                  # loopback, unchanged
     # multi-host (plan Phase 8): run the server on the "external/server"
     # container, then the client on the "victim" (exfiltrating) container --
     # see plan.md's Phase 8 topology, where roles are inverted from the
     # other four scripts (the traffic SOURCE is called "victim" here, the
     # DESTINATION is the external/server; --victim-ip still means "the
     # non-attacker IP this script's traffic is directed at", for
     # consistency with the other four scripts' CLI).
     python3 training/capture/capture_exfil.py --mode server                    # on 10.10.0.40
     python3 training/capture/capture_exfil.py --mode client --victim-ip 10.10.0.40 \
         --attacker-ip 10.10.0.20 --scenario-id exfil_multi_01
"""
import argparse
import http.server
import json
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from multihost_common import add_multihost_args, resolve_victim_ips, sessions_filename, write_provenance  # noqa: E402

OUT_DIR = Path(__file__).parent
LOCAL_PORT = 8199
EXTERNAL_HOSTS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # real, well-known public resolvers -- loopback mode only

random.seed(31)

sessions = []


def mark(label):
    sessions.append({"label": label, "ts": time.time()})


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


def start_local_server(bind_host="127.0.0.1"):
    # bind_host="0.0.0.0" for --mode server, so other containers can reach
    # this from across the multi-host bridge; loopback mode is unchanged.
    server = http.server.ThreadingHTTPServer((bind_host, LOCAL_PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def benign_get(_, target_host):
    subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://{target_host}:{LOCAL_PORT}/"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)


def high_upload_post(_, target_host):
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
             f"http://{target_host}:{LOCAL_PORT}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )


def icmp_covert(_, targets):
    size = random.randint(1200, 8000)
    host = random.choice(targets)
    try:
        subprocess.run(["ping", "-c", "1", "-s", str(size), "-W", "3", host],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass


def dns_exfil_shaped(_, targets, packet_count_range=(15, 40), delay=0.02):
    """One persistent UDP socket, multiple sends to the same (src port,
    dst host, dst port=53) 5-tuple so Zeek aggregates them into a single
    conn.log flow whose orig_bytes accumulates past exfil.py's 5000-byte
    DNS_EXFIL threshold. Payload doesn't need to be valid DNS -- Zeek's
    conn.log records raw flow volume regardless of whether the dns
    analyzer can parse it.

    packet_count_range/delay default to the original burst shape (15-40
    packets, 0.02s apart). exfil_multi_02's --dns-mode slow passes a lower
    packet_count_range and a multi-second delay instead -- fewer packets,
    spread over real wall-clock minutes, for a genuinely low-and-slow shape
    rather than just a relabeled burst. Caveat (kept in provenance too):
    this is still synthetic-shaped and approximates evasive exfiltration
    behavior, not a substitute for a real evasive-malware traffic corpus."""
    host = random.choice(targets)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        n_packets = random.randint(*packet_count_range)
        for _ in range(n_packets):
            payload = bytes(random.randint(0, 255) for _ in range(random.randint(200, 400)))
            s.sendto(payload, (host, 53))
            time.sleep(delay)
    except Exception:
        pass
    finally:
        s.close()


DNS_SLOW_PACKET_RANGE = (5, 10)
DNS_SLOW_DELAY_S = 3.0


def run_server_mode():
    print(f"Serving on 0.0.0.0:{LOCAL_PORT} (Ctrl+C to stop) -- run the client "
          f"phases from the 'victim' container against this container's IP.")
    server = start_local_server(bind_host="0.0.0.0")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_multihost_args(parser)
    parser.add_argument("--mode", choices=["loopback", "server", "client"], default="loopback",
                         help="loopback (default): exact original single-process behavior "
                              "(starts its own local server + runs all 4 phases against it). "
                              "server: just runs the HTTP listener, for the 'external/server' "
                              "multi-host container. client: runs all 4 phases against "
                              "--victim-ip (the external/server's IP), for the 'victim' "
                              "(exfiltrating) container -- does not start a local server.")
    parser.add_argument("--phases", default="benign,upload,icmp,dns",
                         help="Comma-separated subset of {benign,upload,icmp,dns} to run "
                              "(default: all four, exact original behavior). e.g. "
                              "'benign,upload' for exfil_multi_01 (HTTP bulk), 'benign,dns' "
                              "for exfil_multi_02 (DNS low-and-slow), 'benign,icmp' for "
                              "exfil_multi_03 (ICMP covert) -- see plan.md Phase 8.")
    parser.add_argument("--dns-mode", choices=["burst", "slow"], default="burst",
                         help="burst (default): original rapid packet burst (15-40 packets, "
                              "0.02s apart). slow: exfil_multi_02's low-and-slow shape (5-10 "
                              "packets, ~3s apart) -- still synthetic-shaped, approximates "
                              "evasive exfil rather than substituting for a real evasive "
                              "malware corpus (kept as an explicit caveat in provenance).")
    parser.add_argument("--dns-flows", type=int, default=400,
                         help="Number of DNS-shaped flows (default 400, the original count) -- "
                              "lower this for --dns-mode slow so the real per-packet delay "
                              "doesn't make the capture take unreasonably long.")
    args = parser.parse_args()
    phases = {p.strip() for p in args.phases.split(",") if p.strip()}

    if args.mode == "server":
        run_server_mode()
        return

    is_multihost = args.mode == "client"
    if is_multihost:
        targets = resolve_victim_ips(args)
        target_host = targets[0]
        server = None
    else:
        targets = EXTERNAL_HOSTS
        target_host = "127.0.0.1"
        server = start_local_server(bind_host="127.0.0.1")
        time.sleep(0.5)

    t0 = time.time()

    if "benign" in phases:
        mark("benign_start")
        print("Phase 1: benign HTTP GETs (2500)...")
        with ThreadPoolExecutor(max_workers=30) as pool:
            list(pool.map(lambda i: benign_get(i, target_host), range(2500)))
        mark("benign_end")
        print(f"  done at {time.time()-t0:.0f}s")

    if "upload" in phases:
        mark("upload_start")
        print("Phase 2: HIGH_UPLOAD-shaped HTTP POSTs (600)...")
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda i: high_upload_post(i, target_host), range(600)))
        mark("upload_end")
        print(f"  done at {time.time()-t0:.0f}s")

    if "icmp" in phases:
        mark("icmp_start")
        print("Phase 3: real ICMP_COVERT-shaped pings (1200)...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda i: icmp_covert(i, targets), range(1200)))
        mark("icmp_end")
        print(f"  done at {time.time()-t0:.0f}s")

    if "dns" in phases:
        if args.dns_mode == "slow":
            packet_range, delay = DNS_SLOW_PACKET_RANGE, DNS_SLOW_DELAY_S
        else:
            packet_range, delay = (15, 40), 0.02
        mark("dns_start")
        print(f"Phase 4: real DNS_EXFIL-shaped UDP bursts ({args.dns_flows} flows, {args.dns_mode})...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda i: dns_exfil_shaped(i, targets, packet_range, delay), range(args.dns_flows)))
        mark("dns_end")
        print(f"  done at {time.time()-t0:.0f}s")

    if server is not None:
        server.shutdown()
    print(f"\nDone in {time.time()-t0:.0f}s.")

    if args.scenario_id and sessions:
        sessions_file = OUT_DIR / sessions_filename("sessions_exfil.json", args.scenario_id)
        with open(sessions_file, "w") as f:
            json.dump(sessions, f, indent=2)
        print(f"  sessions: {sessions_file}")

    if args.scenario_id:
        malicious_phases = phases - {"benign"}
        if malicious_phases == {"upload"}:
            subtype = "high_upload"
        elif malicious_phases == {"dns"}:
            subtype = "dns_low_and_slow" if args.dns_mode == "slow" else "dns_exfil"
        elif malicious_phases == {"icmp"}:
            subtype = "icmp_covert"
        else:
            subtype = "mixed_shapes"  # original all-four (or other combination) behavior
        configuration = {"phases": sorted(phases), "counts": {"benign": 2500, "upload": 600,
                          "icmp": 1200, "dns": args.dns_flows if "dns" in phases else None},
                          "dns_mode": args.dns_mode if "dns" in phases else None}
        if "dns" in phases and args.dns_mode == "slow":
            configuration["caveat"] = ("synthetic low-and-slow approximates evasive exfiltration "
                                        "behavior; it is not a substitute for a real evasive "
                                        "malware corpus")
        write_provenance(
            scenario_id=args.scenario_id,
            threat_class="exfil",
            attack_subtype=subtype,
            source="real",
            environment="loopback" if not is_multihost else "docker_multihost",
            label_method="controlled_generation",
            generator="training/capture/capture_exfil.py",
            attacker_ip=args.attacker_ip,
            victim_ips=targets if is_multihost else None,
            configuration=configuration,
        )


if __name__ == "__main__":
    main()
