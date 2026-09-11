import json
import os
import socket
import subprocess
import time
from pathlib import Path
import joblib
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ALERTS_FILE     = Path("alerts.json")
CONN_LOG        = Path("zeek-logs/conn.log")
HEARTBEAT_FILE  = Path(".heartbeat")
PRODUCER_HEARTBEAT_FILE = Path(".producer_heartbeat")
THROUGHPUT_FILE = Path(".throughput")
STALE_AFTER_SECONDS = 15   # a heartbeat/log older than this counts as offline
ALERTS_FILE.touch()

ZEEK_CONTAINER = "zeek_monitor"
REPLAY_PCAPS = {
    "ddos":  "attack_syn_flood.pcap",
    "recon": "attack_recon.pcap",
    "c2":    "attack_c2.pcap",
    "dga":   "attack_dns_tunnel.pcap",
    # Real (not scapy-synthesized) captures: a throttled ~800KB HTTPS/HTTP
    # upload to a local loopback sink, shaped to land in the same
    # bulk-upload feature region the tls/exfil models were trained on --
    # see traffic_pcaps/generate_pcaps.py for exactly how these were built.
    "tls":   "attack_tls_malware.pcap",
    "exfil": "attack_exfil.pcap",
}

def read_alerts(limit: int = 100) -> list:
    try:
        lines = ALERTS_FILE.read_text().strip().splitlines()
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed[-limit:]
    except Exception:
        return []

@app.route("/api/alerts")
def get_alerts():
    limit = int(request.args.get("limit", 100))
    alerts = read_alerts(limit)
    return jsonify(alerts)

@app.route("/api/stats")
def get_stats():
    alerts = read_alerts(500)
    stats = {"ddos": 0, "recon": 0, "c2": 0, "dga": 0, "tls": 0, "exfil": 0, "MULTI_VECTOR": 0, "total": len(alerts)}
    for a in alerts:
        tc = a.get("threat_class", "")
        if tc in stats:
            stats[tc] += 1
    return jsonify(stats)


# name -> (base model filename, calibrated model filename, F1, validated_on)
# F1/validated_on are pulled straight from ML_MODELS.md, not recomputed here --
# this endpoint reports load status, not model quality.
DETECTOR_MODELS = {
    "ddos":  ("ddos_model.joblib",       "ddos_model_calibrated.joblib",       1.000, "real traffic, in-repo (SYN+UDP+spoofed floods) + rule-based slow-exhaustion path"),
    "recon": ("recon_model_v3.joblib",   "recon_model_v3_calibrated.joblib",   1.000, "real traffic, in-repo (nmap scans)"),
    "c2":    ("c2_model.joblib",         "c2_model_calibrated.joblib",         0.994, "real traffic, in-repo (beacon emulator)"),
    "dga":   ("dga_model.joblib",        "dga_model_calibrated.joblib",        0.99,  "synthetic (9 published DGA algorithm families) + bidirectional tunnel rule"),
    "tls":   ("tls_flow_model.joblib",   "tls_flow_model_calibrated.joblib",   1.00,  "real TLS+QUIC traffic (incl. packet-sequence features) + synthetic malicious"),
    "exfil": ("exfil_model.joblib",      "exfil_model_calibrated.joblib",      1.000, "real traffic + synthetic top-up"),
}
ML_MODELS_DIR = Path("ml_models")


@app.route("/api/detector_status")
def detector_status():
    """Real per-detector load status -- tries the calibrated model first
    (matching each detector's own _load_model()), falls back to the base
    model, and only reports model_missing if neither file exists. F1/
    validated_on are static context from ML_MODELS.md, not live-computed."""
    result = {}
    for name, (base_file, cal_file, f1, validated_on) in DETECTOR_MODELS.items():
        cal_path = ML_MODELS_DIR / cal_file
        base_path = ML_MODELS_DIR / base_file
        path = cal_path if cal_path.exists() else base_path
        if not path.exists():
            result[name] = {"status": "model_missing", "f1": f1, "validated_on": validated_on}
            continue
        try:
            joblib.load(path)
            result[name] = {
                "status": "ok",
                "calibrated": path == cal_path,
                "f1": f1,
                "validated_on": validated_on,
            }
        except Exception as e:
            result[name] = {"status": "error", "detail": str(e), "f1": f1, "validated_on": validated_on}
    return jsonify(result)

def _recent_mtime(path: Path) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) < STALE_AFTER_SECONDS
    except OSError:
        return False


def _kafka_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 9092), timeout=1):
            return True
    except OSError:
        return False


@app.route("/api/pipeline-status")
def pipeline_status():
    """Real liveness signals, not hardcoded ONLINE labels -- each row is
    backed by an actual file mtime or socket check."""
    zeek_alive     = _recent_mtime(CONN_LOG)
    kafka_alive    = _kafka_reachable()
    producer_alive = _recent_mtime(PRODUCER_HEARTBEAT_FILE)
    stream_alive   = _recent_mtime(HEARTBEAT_FILE)
    return jsonify({
        "diode":            {"status": "simulated", "detail": "Physical isolation is a deployment concern, not software in this prototype"},
        "zeek":              zeek_alive,
        "kafka":             kafka_alive,
        "kafka_producer":    producer_alive,
        "stream_detector":   stream_alive,
        "alert_engine":      stream_alive,   # same process in this prototype -- see stream_consumer.py
        "api":               True,           # trivially true: this response means the API answered
        "read_only_ingest":  True,
        "return_path":       "NONE",
    })


@app.route("/api/throughput")
def throughput():
    """Live events/sec through the detection pipeline, written by
    stream_consumer.py's own rolling window -- not derived here, just
    relayed, and only while fresh (see STALE_AFTER_SECONDS)."""
    try:
        data = json.loads(THROUGHPUT_FILE.read_text())
        if (time.time() - data.get("updated", 0)) < STALE_AFTER_SECONDS:
            return jsonify({"events_per_sec": data["events_per_sec"], "total_events": data["total_events"]})
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return jsonify({"events_per_sec": 0, "total_events": 0})


# The Kafka-forwarded logs (see kafka_producer.py's LOG_TOPICS) -- a replay
# pcap only ever produces a subset of these (a DNS-tunnel pcap makes
# dns.log+conn.log but never ssl.log; a TLS pcap makes ssl.log+conn.log but
# never dns.log), so /api/replay below reads back whichever exist rather
# than assuming conn.log is the only one that matters.
REPLAY_LOG_FILES = ["conn.log", "dns.log", "ssl.log", "quic.log"]


@app.route("/api/replay/<threat>", methods=["POST"])
def replay(threat):
    """Replays a pre-recorded pcap for one threat class through the same
    live pipeline real traffic uses, for a reliable, on-demand demo
    trigger -- see traffic_pcaps/generate_pcaps.py for how the pcaps were
    built, and ML_MODELS.md / docker-compose.yml for why this uses Zeek's
    own offline `-r` reader (inside the already-running zeek_monitor
    container) rather than tcpreplay: tcpreplay needs raw-socket
    privileges and a passwordless sudo setup that can't be relied on to
    work unattended in front of a jury, while Zeek reading the same pcap
    offline produces byte-identical log output with no such dependency.
    The offline read runs in its own scratch directory inside the
    container -- it never touches the live `-i lo` process or its logs.

    Injects into every Kafka-forwarded log the pcap actually produced, not
    just conn.log -- the DGA detector needs dns.log's query/qtype/answers
    fields and the TLS detector needs ssl.log's ja3/ja4 fields joined to
    conn.log's byte counts (see stream_consumer.py's FlowByteEnricher); a
    conn.log-only injection would silently never reach either detector's
    real code path even though the endpoint reports success.

    Every log file shares one global timestamp shift (computed from the
    earliest ts across all of them) so a session's conn.log and ssl.log
    rows land within FlowByteEnricher's PENDING_MAX_AGE of each other, the
    same as they would arriving live off the wire.
    """
    pcap = REPLAY_PCAPS.get(threat)
    if pcap is None:
        return jsonify({"status": "error", "message": f"unknown threat '{threat}'"}), 400

    try:
        subprocess.run(
            ["docker", "exec", ZEEK_CONTAINER, "sh", "-c",
             "rm -rf /tmp/replay && mkdir -p /tmp/replay && cd /tmp/replay && "
             # -C: without it Zeek discards every packet with a
             # (loopback-typical, checksum-offloaded) invalid checksum --
             # harmless for the header-only ddos/recon/c2/dga pcaps, but it
             # silently dropped all payload on the byte-heavy tls/exfil
             # pcaps and meant ssl.log was never even written (same
             # checksum-offload bug documented in ML_MODELS.md for the
             # live -i lo process, missed here until the tls/exfil pcaps
             # surfaced it).
             f"zeek -C -r /pcaps/{pcap} /usr/local/zeek/share/zeek/site/local.zeek"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        raw_by_file = {}
        for log_name in REPLAY_LOG_FILES:
            result = subprocess.run(
                ["docker", "exec", ZEEK_CONTAINER, "sh", "-c",
                 f"cat /tmp/replay/{log_name} 2>/dev/null || true"],
                capture_output=True, text=True, timeout=10, check=True,
            )
            lines = [l for l in result.stdout.strip().splitlines() if l]
            if lines:
                raw_by_file[log_name] = lines
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"zeek replay failed: {e.stderr.strip()}"}), 502
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "zeek replay timed out"}), 504
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "docker CLI not found on host"}), 500

    if not raw_by_file:
        return jsonify({"status": "error", "message": "replay produced no forwarded-log events"}), 502

    events_by_file = {}
    all_ts = []
    for log_name, lines in raw_by_file.items():
        events = []
        for line in lines:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(e)
            all_ts.append(float(e.get("ts", 0)))
        if events:
            events_by_file[log_name] = events
    if not all_ts:
        return jsonify({"status": "error", "message": "replay produced no parseable events"}), 502

    shift = time.time() - min(all_ts)
    total_injected = 0
    for log_name, events in events_by_file.items():
        events.sort(key=lambda e: float(e.get("ts", 0)))
        for e in events:
            e["ts"] = float(e.get("ts", 0)) + shift
        payload = "".join(json.dumps(e) + "\n" for e in events)

        # Appended via `docker exec` (root inside the container), not a direct
        # host-side file write: Zeek's live -i lo process runs as root and owns
        # these bind-mounted files, so the Flask process (a normal user) can
        # read them but not append to them directly.
        try:
            subprocess.run(
                ["docker", "exec", "-i", ZEEK_CONTAINER, "sh", "-c",
                 f"cat >> /usr/local/zeek/logs/current/{log_name}"],
                input=payload, capture_output=True, text=True, timeout=10, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return jsonify({"status": "error", "message": f"failed to inject {log_name}: {e}"}), 502
        total_injected += len(events)

    return jsonify({"status": "replayed", "threat": threat, "events_injected": total_injected})


@app.route("/api/clear", methods=["POST"])
def clear_alerts():
    ALERTS_FILE.write_text("")
    return jsonify({"status": "cleared"})

@app.route("/api/stream")
def stream():
    def event_generator():
        last_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
        yield "data: {\"type\": \"connected\"}\n\n"
        while True:
            time.sleep(0.5)
            try:
                current_size = ALERTS_FILE.stat().st_size
            except FileNotFoundError:
                continue
            if current_size > last_size:
                with open(ALERTS_FILE, "r") as f:
                    f.seek(last_size)
                    new_content = f.read()
                last_size = current_size
                for raw_line in new_content.strip().splitlines():
                    if raw_line:
                        yield f"data: {raw_line}\n\n"

    return Response(event_generator(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
