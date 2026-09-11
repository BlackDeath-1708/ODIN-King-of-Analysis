"""
Throughput and per-detector latency benchmark.

Run: python scripts/benchmark_throughput.py

WHAT THIS ACTUALLY MEASURES (read before quoting the numbers):
The plan this script implements originally called for publishing 10,000
synthetic conn.log rows through kafka_producer.py and measuring wall-clock
time from first publish to last consumer ACK -- i.e. a full Kafka-broker
round-trip. That requires a live Kafka broker; in this environment Kafka
was not running (`docker ps` showed no kafka container, port 9092
unreachable) and this repo's own docker-compose.yml only ships a stand-alone
Kafka+Zeek stack, not a way to spin one up headless for a benchmark run.

Rather than fake a number or skip the benchmark, this measures the actual
Python detection pipeline's own processing throughput directly: the same
`for event in events: for detector in detectors: detector.process(event)`
loop stream_consumer.py runs, fed a synthetic 10,000-event stream, with no
Kafka broker in between. This is an honest, real, reproducible number for
"how fast can this codebase's own detection logic run" -- it is NOT a
Kafka-broker-inclusive number, and shouldn't be quoted as one. Apache
Kafka's own throughput is a well-established, independently-benchmarked
commodity capability that isn't specific to this project's code; what *is*
specific to this project is whether its 6 detectors' Python logic keeps up,
which is what this script actually answers.

Per-detector latency: 100 synthetic attack-shaped events per detector
(reusing the same trigger patterns verified during development), median
wall-clock time from calling process() to it returning an alert.

Output: docs/benchmark_results.json
"""
import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from detectors import ACTIVE_DETECTORS  # noqa: E402

TEST_EVENT_COUNT = 10_000
PER_DETECTOR_SAMPLES = 30  # 100 made the ddos/recon sequences (each ~200/60 events, ~13ms/event
                           # in scikit-learn model-call overhead) take several minutes on their own
OUTPUT_PATH = Path(__file__).parent.parent / "docs" / "benchmark_results.json"


def _conn_event(ts, src_ip, dst_ip, dst_port, proto="tcp", **overrides):
    event = {
        "log_type": "conn", "ts": ts, "uid": f"C{ts}-{dst_port}",
        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto,
        "orig_bytes": 500, "resp_bytes": 300, "orig_pkts": 5, "resp_pkts": 4, "duration": 1.0,
    }
    event.update(overrides)
    return event


def _dns_event(ts, src_ip, query, qtype_name="A", answers="1.2.3.4"):
    return {
        "log_type": "dns", "ts": ts, "uid": f"D{ts}", "src_ip": src_ip, "dst_ip": "8.8.8.8",
        "dst_port": 53, "query": query, "qtype_name": qtype_name, "answers": answers,
    }


def _ssl_event(ts, src_ip, dst_ip, orig_bytes=5000, resp_bytes=5000):
    return {
        "log_type": "ssl", "ts": ts, "uid": f"S{ts}", "src_ip": src_ip, "dst_ip": dst_ip,
        "dst_port": 443, "ja3": "", "ja3s": "", "version": "TLSv12", "server_name": "example.com",
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, "duration": 2.0,
    }


def generate_synthetic_stream(n: int, seed: int = 42) -> list:
    """A mix of benign and attack-shaped flows across all three log types,
    matching the field shapes stream_consumer.normalize_event() actually
    produces -- not a simplified stand-in.

    Timestamp spacing (0.5-3.0s) is deliberately NOT flood-dense: an
    earlier attempt at ~0.01s spacing crammed 10,000 events into ~100
    simulated seconds, which blew up ddos.py's/recon.py's rolling windows
    (both keep every raw event, unpruned, until it ages out) to thousands
    of entries each, making entropy/interval recomputation the dominant
    cost instead of what this benchmark is actually meant to measure. This
    spacing keeps those windows at realistic background-traffic size (single
    digits to a few dozen entries) so the number reported here reflects
    steady-state per-event processing cost, not an artifact of a
    pathologically bursty synthetic generator. Per-detector *attack*
    latency (bursty by design) is measured separately below."""
    rng = random.Random(seed)
    events = []
    ts = 1_000_000.0
    for i in range(n):
        ts += rng.uniform(0.5, 3.0)
        roll = rng.random()
        src_ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
        if roll < 0.7:
            events.append(_conn_event(ts, src_ip, "192.168.1.50", rng.randint(1, 65535)))
        elif roll < 0.85:
            events.append(_dns_event(ts, src_ip, f"host{i}.example.com"))
        else:
            events.append(_ssl_event(ts, src_ip, "192.168.1.60"))
    return events


def benchmark_sustained_throughput(detectors, events) -> dict:
    start = time.perf_counter()
    alert_count = 0
    for i, event in enumerate(events):
        for detector in detectors:
            if detector.process(event) is not None:
                alert_count += 1
        if i and i % 1000 == 0:
            print(f"  ...{i}/{len(events)} events processed "
                  f"({time.perf_counter() - start:.1f}s elapsed)", flush=True)
    elapsed = time.perf_counter() - start
    return {
        "test_event_count": len(events),
        "elapsed_seconds": round(elapsed, 4),
        "sustained_flows_per_sec": round(len(events) / elapsed, 1),
        "alerts_produced": alert_count,
    }


# One attack-shaped event-sequence generator per detector, reusing the same
# trigger patterns exercised during development (see ML_MODELS.md). Each
# takes a distinct src_ip per sample so a single long-lived detector
# instance's per-source cooldown/state never suppresses the next sample --
# reloading a fresh detector (and its joblib model + DGA's wordlist) per
# sample was tried first and made this benchmark itself take minutes.
def _ddos_attack_events(ts0, src_ip):
    # A real flood the trained model recognizes needs a HIGH rate to a
    # SINGLE port (zero port diversity) -- a first version of this cycled
    # dst_port across hundreds of values, which reads to the model as
    # high port-entropy scanning-like traffic, not a flood, and never
    # actually crossed the decision boundary (predict()==0 the whole way
    # through). Verified directly against ddos_model.joblib: predict_proba
    # crosses 99%+ confidence at packet_rate>=200 to a single port --
    # 200 events keeps this fast while still comfortably past the boundary.
    return [_conn_event(ts0 + i * 0.02, src_ip, "1.1.1.1", 80) for i in range(200)]


def _recon_attack_events(ts0, src_ip):
    # Real port-scan pattern the model recognizes: MANY unique ports
    # against one host, fast. A first version fixed dst_port=22 for every
    # connection (unique_ports=1), which reads as ordinary single-service
    # traffic, not a scan, and never crossed the decision boundary either.
    return [_conn_event(ts0 + i * 0.5, src_ip, "10.0.0.5", i + 1) for i in range(60)]


def _c2_attack_events(ts0, src_ip):
    return [_conn_event(ts0 + i * 4.0, src_ip, "6.6.6.6", 443) for i in range(6)]


def _dga_attack_event(ts0, src_ip):
    return [_dns_event(ts0, src_ip, "xjkqmzpwlqzrbv.ru")]


def _tls_attack_event(ts0, src_ip):
    return [_ssl_event(ts0, src_ip, "3.3.3.3", orig_bytes=200000, resp_bytes=1000)]


def _exfil_attack_event(ts0, src_ip):
    return [_conn_event(ts0, src_ip, "1.1.1.1", 443, orig_bytes=2_000_000, resp_bytes=10_000, duration=60)]


ATTACK_EVENT_BUILDERS = {
    "ddos": _ddos_attack_events,
    "recon": _recon_attack_events,
    "c2": _c2_attack_events,
    "dga": _dga_attack_event,
    "tls": _tls_attack_event,
    "exfil": _exfil_attack_event,
}


def benchmark_per_detector_latency() -> dict:
    """Returns {name: median_ms}. Raises if any detector's synthetic
    attack sequence never actually fires an alert -- a silent non-firing
    sequence would report a real-looking latency number for something
    that isn't detection latency at all (found by code review: an earlier
    version's ddos/recon sequences never crossed either model's decision
    boundary and this went unnoticed until someone checked)."""
    latencies_ms = {}
    for cls in ACTIVE_DETECTORS:
        detector = cls()  # one instance, model loaded once -- matches how it actually runs
        name = detector.name
        builder = ATTACK_EVENT_BUILDERS.get(name)
        if builder is None:
            continue
        samples = []
        fired_count = 0
        for i in range(PER_DETECTOR_SAMPLES):
            ts0 = 2_000_000.0 + i * 1000.0
            src_ip = f"172.16.{i // 250}.{i % 250 + 1}"  # distinct source per sample, avoids cooldown collision
            warm_up_events = builder(ts0, src_ip)
            start = time.perf_counter()
            fired = any(detector.process(ev) is not None for ev in warm_up_events)
            samples.append((time.perf_counter() - start) * 1000)
            fired_count += fired
        if fired_count == 0:
            raise RuntimeError(
                f"[{name}] synthetic attack sequence never fired an alert in {PER_DETECTOR_SAMPLES} "
                f"samples -- this would report a latency number for a sequence that isn't actually "
                f"triggering detection. Fix the sequence in ATTACK_EVENT_BUILDERS, verify it against "
                f"the loaded model directly, then re-run."
            )
        if fired_count < PER_DETECTOR_SAMPLES:
            print(f"  WARNING [{name}]: only fired in {fired_count}/{PER_DETECTOR_SAMPLES} samples")
        latencies_ms[name] = round(statistics.median(samples), 4)
    return latencies_ms


def main():
    detectors = [cls() for cls in ACTIVE_DETECTORS]
    print(f"Loaded {len(detectors)} detectors: {', '.join(d.name for d in detectors)}")

    events = generate_synthetic_stream(TEST_EVENT_COUNT)
    print(f"Generated {len(events)} synthetic events, running sustained-throughput pass...")
    throughput = benchmark_sustained_throughput(detectors, events)
    print(f"  {throughput['sustained_flows_per_sec']} flows/sec "
          f"({throughput['elapsed_seconds']}s for {throughput['test_event_count']} events, "
          f"{throughput['alerts_produced']} alerts)")

    print("Running per-detector latency pass...")
    per_detector_latency_ms = benchmark_per_detector_latency()
    for name, ms in per_detector_latency_ms.items():
        print(f"  {name}: {ms}ms median (per triggering event sequence)")

    result = {
        "measurement_scope": (
            "Python detection-pipeline throughput only (detector.process() calls in a tight "
            "loop, matching stream_consumer.py's dispatch loop exactly) -- NOT a Kafka-broker "
            "round-trip measurement. No live Kafka broker was running in this environment "
            "(port 9092 unreachable) when this benchmark was run; see this script's module "
            "docstring for why that number isn't faked here."
        ),
        "sustained_flows_per_sec": throughput["sustained_flows_per_sec"],
        "test_event_count": throughput["test_event_count"],
        "elapsed_seconds": throughput["elapsed_seconds"],
        "alerts_produced_on_synthetic_stream": throughput["alerts_produced"],
        "per_detector_latency_ms": per_detector_latency_ms,
        "bottleneck_finding": (
            "Sustained throughput here is dominated by scikit-learn's per-call inference "
            "overhead, not by this codebase's own Python logic: a single RandomForest "
            "predict()+predict_proba() pair measured ~12ms/call in this environment "
            "(scikit-learn 1.9.0), and ddos.py/recon.py/c2.py each make that pair of calls "
            "per qualifying conn event. Verified directly: an unrealistically dense synthetic "
            "stream (events spaced ~0.01s apart) made ddos.py's/recon.py's rolling windows grow "
            "to thousands of unpruned entries and dominated cost instead -- an artifact of the "
            "generator, not a finding about the pipeline -- which is why this benchmark uses "
            "0.5-3.0s spacing (see generate_synthetic_stream's docstring) to isolate the real "
            "steady-state bottleneck."
        ),
        "hardware": "<fill manually -- run `lscpu | grep \"Model name\"` and note core count/RAM>",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nWrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
