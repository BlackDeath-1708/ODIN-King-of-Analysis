"""
Real end-to-end throughput benchmark -- generates actual network traffic,
lets the LIVE pipeline (Zeek -i lo capture -> kafka_producer.py -> Kafka ->
stream_consumer.py -> detectors -> alerts.json) observe and process it for
real, and measures what the pipeline itself sustained. Sibling to, not a
replacement for, scripts/benchmark_throughput.py, which answers a
different, still-useful question ("is the Python detector logic itself
fast enough in isolation, with no Kafka/Zeek/network I/O at all").

WHY A CUSTOM ASYNCIO GENERATOR INSTEAD OF iperf3/tcpreplay: neither is
installed in this environment, and there's no passwordless sudo configured
(confirmed: `sudo -n true` fails) -- installing either would need an
interactive password prompt this script can't rely on running unattended.
backend/app.py's own /api/replay endpoint already made the same call for
the same reason ("tcpreplay needs raw-socket privileges... can't rely on
unattended sudo in front of a jury"). A stdlib-only asyncio TCP swarm needs
no root and no install step -- always runnable with one command.

WHY SHORT connect->send->close CYCLES, NOT HELD-OPEN CONNECTIONS: Zeek only
writes a conn.log row when a connection *closes*, and kafka_producer.py's
tailer only sees rows that exist in the file. Held-open connections for
the whole run would produce a batchy, misleading throughput series (near
zero the whole time, then a spike at the end) instead of a real continuous
one. traffic/generate_c2.py and generate_ddos.sh already use short cycles
for the same reason -- this script follows that established convention.

WHY CONSERVATIVE DEFAULTS: this machine is a single 12-core mobile laptop
already running Zeek + Kafka + the detector pipeline + this generator all
on the same cores, and was observed with only ~2.6GiB free RAM and
3.7/4GiB swap already in use. traffic/generate_ddos.sh self-limits to
~500pps specifically because unrestrained loopback flooding "can hang the
whole machine" (its own comment) -- this script applies the same
philosophy via an explicit, overridable rate cap.

Run: backend/.venv/bin/python3 scripts/benchmark_e2e.py
Override via environment variables:
    E2E_WORKERS=30 E2E_PAYLOAD_BYTES=2048 E2E_DURATION=25 E2E_RATE_CAP=300 \
        backend/.venv/bin/python3 scripts/benchmark_e2e.py
Reads (over HTTP, from the live backend/app.py on :5000):
    /api/pipeline-status, /api/throughput, /api/alerts
Writes: docs/benchmark_e2e_results.json
"""
import asyncio
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
API_BASE = "http://127.0.0.1:5000"
OUT_JSON = REPO_ROOT / "docs" / "benchmark_e2e_results.json"

WORKERS = int(os.environ.get("E2E_WORKERS", 30))
PAYLOAD_BYTES = int(os.environ.get("E2E_PAYLOAD_BYTES", 2048))
DURATION_SECONDS = float(os.environ.get("E2E_DURATION", 25))
RATE_CAP_PER_SEC = float(os.environ.get("E2E_RATE_CAP", 300))  # total connections/sec across all workers
DRAIN_SECONDS = 13  # covers kafka_producer.py's 0.5s tail-poll + stream_consumer.py's 10s rolling window
SINK_PORT_CANDIDATES = (18080, 28765, 39217, 8890)
PAYLOAD = b"x" * PAYLOAD_BYTES


def _api_get(path: str) -> dict:
    with urllib.request.urlopen(f"{API_BASE}{path}", timeout=5) as resp:
        return json.loads(resp.read())


def _preflight_check() -> None:
    status = _api_get("/api/pipeline-status")
    required = ("zeek", "kafka", "kafka_producer", "stream_detector")
    dead = [k for k in required if not status.get(k)]
    if dead:
        raise RuntimeError(
            f"Pipeline not fully live ({dead} reported down via /api/pipeline-status) -- "
            f"refusing to benchmark a half-dead pipeline. Status: {status}"
        )
    print(f"[preflight] pipeline live: {status}")


async def _sink_server_handler(reader, writer):
    # A one-way send-only load (no reply) produces exactly the byte-ratio
    # asymmetry exfil.py is designed to flag -- confirmed directly on the
    # first run of this script (900/900 exfil+correlated alerts on
    # otherwise-benign load traffic). Echoing the payload back keeps
    # byte_ratio ~= 1.0, a genuine request/response shape, so this stays a
    # clean capacity test rather than an inadvertent (if correctly
    # detected) exfil stress test.
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def _start_sink_server():
    for port in SINK_PORT_CANDIDATES:
        try:
            server = await asyncio.start_server(_sink_server_handler, "127.0.0.1", port,
                                                 reuse_address=True)
            print(f"[sink] listening on 127.0.0.1:{port}")
            return server, port
        except OSError as e:
            print(f"[sink] port {port} unavailable ({e}), trying next candidate")
    raise RuntimeError(f"No free sink port among candidates {SINK_PORT_CANDIDATES}")


class GeneratorStats:
    def __init__(self):
        self.connections = 0
        self.bytes_sent = 0


async def _worker(port: int, stop_at: float, stats: GeneratorStats, per_worker_interval: float):
    while time.monotonic() < stop_at:
        cycle_start = time.monotonic()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(PAYLOAD)
            await writer.drain()
            writer.write_eof()  # signal done-sending so the sink's echo loop terminates
            await reader.read(len(PAYLOAD))  # drain the echoed reply -- keeps byte_ratio ~1.0, avoids RSTs
            writer.close()
            await writer.wait_closed()
            stats.connections += 1
            stats.bytes_sent += len(PAYLOAD)
        except OSError:
            pass  # transient refused/reset under load -- keep going, don't crash the run
        elapsed = time.monotonic() - cycle_start
        await asyncio.sleep(max(0.0, per_worker_interval - elapsed))


async def _poll_throughput(stop_at: float, samples: list):
    while time.monotonic() < stop_at:
        try:
            samples.append({"t": time.monotonic(), **_api_get("/api/throughput")})
        except Exception as e:
            samples.append({"t": time.monotonic(), "error": str(e)})
        await asyncio.sleep(1.0)


def _fetch_alerts_since(start_iso: str) -> list:
    alerts = _api_get("/api/alerts?limit=5000")
    return [a for a in alerts if a.get("timestamp", "") >= start_iso]


def _alert_latency_stats(alerts: list) -> dict:
    latencies = []
    for a in alerts:
        try:
            ts = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
            event_ts = a.get("event_ts")
            if event_ts:
                latencies.append(ts.timestamp() - float(event_ts))
        except (KeyError, ValueError, TypeError):
            continue
    if not latencies:
        return {"count": 0, "note": "No alerts fired during the benchmark window (benign load, expected)."}
    latencies.sort()
    return {
        "count": len(latencies),
        "min_seconds": round(latencies[0], 3),
        "median_seconds": round(latencies[len(latencies) // 2], 3),
        "max_seconds": round(latencies[-1], 3),
        "note": (
            "This bundles Zeek's own flow-close/log-flush delay with real pipeline transit "
            "time (Kafka + consumer dispatch + detector compute) -- it is NOT a pure "
            "pipeline-overhead number, especially for long-lived flows."
        ),
    }


async def run_benchmark() -> dict:
    _preflight_check()
    baseline_throughput = _api_get("/api/throughput")
    run_start_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(f"[benchmark] baseline total_events={baseline_throughput.get('total_events')}")

    server, port = await _start_sink_server()
    throughput_samples = []
    stats = GeneratorStats()

    per_worker_interval = WORKERS / RATE_CAP_PER_SEC  # spreads the total rate cap across all workers
    run_start = time.monotonic()
    stop_at = run_start + DURATION_SECONDS

    print(f"[benchmark] generating load: {WORKERS} workers, {PAYLOAD_BYTES}B/send, "
          f"{DURATION_SECONDS}s duration, rate cap {RATE_CAP_PER_SEC}/s")
    await asyncio.gather(
        *(_worker(port, stop_at, stats, per_worker_interval) for _ in range(WORKERS)),
        _poll_throughput(stop_at, throughput_samples),
    )
    elapsed = time.monotonic() - run_start
    server.close()
    await server.wait_closed()

    print(f"[benchmark] load generation done, draining {DRAIN_SECONDS}s for the pipeline to catch up...")
    await asyncio.sleep(DRAIN_SECONDS)

    final_throughput = _api_get("/api/throughput")
    alerts_in_window = _fetch_alerts_since(run_start_iso)

    events_per_sec_samples = [s["events_per_sec"] for s in throughput_samples if "events_per_sec" in s]

    return {
        "measurement_scope": (
            "Real end-to-end pipeline throughput (Zeek -i lo live capture -> Kafka -> "
            "stream_consumer.py -> detectors -> alerts.json), NOT an isolated Python-loop "
            "micro-benchmark (see scripts/benchmark_throughput.py for that). Single "
            "self-contained 12-core mobile laptop (i7-1255U) running the capture, broker, "
            "and detector pipeline on the same cores as this load generator -- not "
            "dedicated hardware, not a real NIC (loopback only). Numbers here reflect "
            "single-laptop self-contained capacity, not a production appliance. "
            "Measured with a real Kafka broker running (docker compose kafka+zeek services) "
            "and stream_consumer.py's micro-batched detector dispatch (ODIN throughput plan "
            "Phase A1 -- see docs/benchmark_results.json's 'batching_speedup_x'). A prior run "
            "on the pre-batching code, same generator config, peaked at 22.2 events/sec "
            "avg 21.47 -- this run's peak_events_per_sec/avg_events_per_sec below is the "
            "batched-code result on the same hardware and load shape."
        ),
        "generator_config": {
            "workers": WORKERS, "payload_bytes": PAYLOAD_BYTES,
            "duration_seconds": DURATION_SECONDS, "rate_cap_per_sec": RATE_CAP_PER_SEC,
        },
        "generator_offered": {
            "connections": stats.connections,
            "bytes_sent": stats.bytes_sent,
            "elapsed_seconds": round(elapsed, 3),
            "flows_per_sec": round(stats.connections / elapsed, 2) if elapsed else 0,
            "mbps": round((stats.bytes_sent * 8 / 1_000_000) / elapsed, 3) if elapsed else 0,
        },
        "pipeline_observed": {
            "baseline_total_events": baseline_throughput.get("total_events", 0),
            "final_total_events": final_throughput.get("total_events", 0),
            "events_per_sec_samples": events_per_sec_samples,
            "peak_events_per_sec": max(events_per_sec_samples, default=0),
            "avg_events_per_sec": (
                round(sum(events_per_sec_samples) / len(events_per_sec_samples), 2)
                if events_per_sec_samples else 0
            ),
        },
        "alert_latency": _alert_latency_stats(alerts_in_window),
        "hardware": f"{os.cpu_count()} logical cores (see docs/benchmark_results.json for the exact CPU model)",
        "generated_at": run_start_iso,
    }


def main():
    result = asyncio.run(run_benchmark())
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2))
    print(f"\nSaved results to {OUT_JSON}")
    print(f"Generator offered: {result['generator_offered']['flows_per_sec']} flows/sec, "
          f"{result['generator_offered']['mbps']} Mbps")
    print(f"Pipeline observed: peak {result['pipeline_observed']['peak_events_per_sec']} events/sec, "
          f"avg {result['pipeline_observed']['avg_events_per_sec']} events/sec")
    print(f"Alert latency: {result['alert_latency']}")


if __name__ == "__main__":
    main()
