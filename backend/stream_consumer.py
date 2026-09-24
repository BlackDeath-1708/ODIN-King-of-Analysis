"""
Kafka -> stateful stream processing -> detectors -> alerts.

This is the prototype stand-in for the Flink/Spark layer in the full
Hybrid 1 architecture. It deliberately does exactly one job on top of
consuming from Kafka: normalize the raw Zeek event into a stable schema,
then hand it to each detector plugin unchanged. Swapping this file for a
Flink job later means reimplementing this loop in Flink's API -- the
normalized event shape and the detector classes in detectors/ do not
change.

    Kafka Consumer -> normalize_event() -> Detector.process(event) -> alert

Consumes five topics (zeek-conn/zeek-dns/zeek-ssl/zeek-quic/zeek-pktseq --
see kafka_producer.py) in one consumer loop. Every event is still handed to
every detector unchanged; each detector is responsible for ignoring log
types it doesn't handle via the log_type field normalize_event() adds
below. zeek-pktseq is the one exception -- it's pure enrichment data (see
FlowByteEnricher), never dispatched to detectors directly.
"""

import json
import time
from collections import deque
from pathlib import Path

from kafka import KafkaConsumer

import alert_export
import forensic_chain
from detectors import ACTIVE_DETECTORS
from correlation.correlator import CorrelationEngine

KAFKA_BOOTSTRAP = "localhost:9092"
TOPICS          = ["zeek-conn", "zeek-dns", "zeek-ssl", "zeek-quic", "zeek-pktseq"]
GROUP_ID        = "ntro-stream-consumer"
ALERTS_FILE     = Path("alerts.json")
CEF_FILE        = Path("alerts.cef.log")
STIX_FILE       = Path("alerts.stix.jsonl")
HEARTBEAT_FILE  = Path(".heartbeat")
THROUGHPUT_FILE = Path(".throughput")
THROUGHPUT_WINDOW_SECONDS = 10
POLL_TIMEOUT_MS  = 100  # micro-batch flush deadline -- see run()'s docstring comment
POLL_MAX_RECORDS = 64   # micro-batch size cap, whichever bound hits first


def _extract_common(raw: dict) -> dict:
    """Fields every Zeek log (conn/dns/ssl) shares -- id.orig_h/id.resp_h
    style connection 4-tuple plus ts/uid. Every detector can rely on these
    keys existing regardless of which log an event came from."""
    return {
        "ts":       float(raw.get("ts", 0)),
        "uid":      raw.get("uid"),
        "src_ip":   raw.get("id.orig_h", ""),
        "src_port": int(raw.get("id.orig_p", 0)) or None,
        "dst_ip":   raw.get("id.resp_h", ""),
        "dst_port": int(raw.get("id.resp_p", 0)) or None,
    }


def normalize_event(raw: dict) -> dict | None:
    """Zeek's dotted log keys -> a stable, Zeek-independent event shape.
    Every detector depends on this shape, not on Zeek's field names -- this
    is the seam that would let a Suricata EVE JSON source feed the same
    detectors with only this function changing.

    conn.log, dns.log, and ssl.log rows all land here (see TOPICS above)
    deserialized generically, so this branches on which fields are present
    to tell them apart and tags every event with log_type accordingly.
    """
    try:
        common = _extract_common(raw)

        if "sizes" in raw and "gaps" in raw:
            # pkt_seq.log (zeek/scripts/pkt_seq.zeek) -- PS 26145 (d)'s
            # "packet-size and timing sequences" signal, joined into the
            # matching ssl/quic event by uid (see FlowByteEnricher below)
            # rather than dispatched to detectors directly.
            common.update({
                "log_type": "pktseq",
                "sizes":    raw.get("sizes", []),
                "gaps":     raw.get("gaps", []),
            })
            return common

        if "query" in raw or "qtype_name" in raw:
            common.update({
                "log_type":   "dns",
                "query":      raw.get("query", ""),
                "qtype_name": raw.get("qtype_name", "A"),
                "answers":    raw.get("answers", ""),
            })
            return common

        if "version" in raw and "cipher" in raw:
            common.update({
                "log_type":    "ssl",
                "ja3":         raw.get("ja3", ""),
                "ja3s":        raw.get("ja3s", ""),
                "ja4":         raw.get("ja4", ""),
                "ja4s":        raw.get("ja4s", ""),
                "version":     raw.get("version", ""),
                "server_name": raw.get("server_name", ""),
                "orig_bytes":  raw.get("orig_bytes", 0),
                "resp_bytes":  raw.get("resp_bytes", 0),
                "duration":    raw.get("duration", 0.0),
            })
            return common

        if "client_initial_dcid" in raw:
            # QUIC (PS 26145 (d): "TLS/QUIC metadata alone"). quic.log has no
            # byte/duration fields either (same gap as ssl.log -- see
            # FlowByteEnricher), so these get joined in from conn.log the
            # same way, then reused by the same flow-stats model tls_malware.py
            # already runs for TLS (byte-ratio/timing anomalies are a
            # protocol-agnostic malware signal, not TLS-specific).
            common.update({
                "log_type":    "quic",
                "version":     raw.get("version", ""),
                "server_name": raw.get("server_name", ""),
                "orig_bytes":  raw.get("orig_bytes", 0),
                "resp_bytes":  raw.get("resp_bytes", 0),
                "duration":    raw.get("duration", 0.0),
            })
            return common

        common.update({
            "log_type":   "conn",
            "proto":      raw.get("proto", ""),
            "conn_state": raw.get("conn_state", ""),
            "orig_bytes": raw.get("orig_bytes", 0),
            "resp_bytes": raw.get("resp_bytes", 0),
            "orig_pkts":  raw.get("orig_pkts", 0),
            "resp_pkts":  raw.get("resp_pkts", 0),
            "duration":   raw.get("duration", 0.0),
        })
        return common
    except (ValueError, TypeError):
        return None


class FlowByteEnricher:
    """
    Real Zeek ssl.log AND quic.log carry NO orig_bytes/resp_bytes/duration
    fields -- those live only in conn.log. normalize_event() previously read
    them off ssl rows anyway (raw.get("orig_bytes", 0)), which silently
    defaulted to 0 for every real TLS event: tls_malware.py's flow-stats ML
    path always saw a degenerate all-zero feature vector, and its own
    `duration < 0.1 or total_bytes < 100` guard rejected every real event
    before the model was ever called -- the ML path (PS 26145's "packet-size
    and timing sequences" requirement) was dead code against any real or
    replayed traffic, only the JA3 blacklist path could ever fire. QUIC
    coverage (added 2026-09-12, PS 26145 (d)'s "TLS/QUIC metadata alone")
    reuses this exact same enricher, since quic.log has the identical gap.

    Fixed by joining ssl.log rows to their conn.log counterpart via Zeek's
    shared `uid` (the same connection identifier Zeek writes across
    conn.log/ssl.log/dns.log for one connection -- the standard mechanism
    for cross-log correlation). Bounded both directions, since Zeek doesn't
    guarantee which log for a connection gets flushed first:
      - conn.log arriving after ssl.log (the common case -- Zeek typically
        flushes ssl.log at handshake completion, well before the connection
        -- and therefore conn.log -- actually closes): the ssl event is held
        in `_pending_ssl` until a matching conn event resolves it.
      - ssl.log arriving after conn.log: `_conn_cache` (bounded, oldest-uid
        eviction) still has the byte data ready to enrich immediately.
    An unmatched ssl event older than PENDING_MAX_AGE (event time, not
    wall-clock) is dispatched anyway with zero-byte fields -- no worse than
    the pre-fix behavior for that one event, and keeps latency bounded per
    PS 26145's streaming requirement rather than holding forever.

    pkt_seq.log rows (2026-09-12, PS 26145 (d)'s "packet-size and timing
    sequences") are joined the same way, via a second bounded uid cache --
    but opportunistically, not as a dispatch gate: pkt_seq.log is written
    at connection_state_remove, empirically arriving at close to the same
    time as conn.log for the same uid (not guaranteed to be before it), so
    holding dispatch open an extra round waiting for it isn't worth the
    added latency for what's a secondary ML feature, not a detector
    trigger condition on its own. An event dispatched before its pkt_seq
    row arrives simply gets empty sizes/gaps (see
    TLSMalwareDetector._flow_features(), which treats that as "no sequence
    data available" rather than a zero-value signal).
    """
    CONN_CACHE_MAX = 5000
    PENDING_MAX_AGE = 30.0  # QUIC's UDP conn.log entries flush noticeably
    # slower than TLS's TCP ones (Zeek's UDP inactivity timeout vs TCP FIN/RST) --
    # verified directly: a 5s window (tuned for TLS) missed QUIC joins that
    # succeeded once given ~15-20s. 30s is still comfortably "bounded
    # latency" for a security alert.

    def __init__(self):
        self._conn_cache = {}       # uid -> {orig_bytes, resp_bytes, duration}
        self._conn_order = deque()  # uid insertion order, for bounded eviction
        self._pending_ssl = {}      # uid -> (first_seen_ts, ssl event dict)
        self._pktseq_cache = {}     # uid -> {sizes, gaps}
        self._pktseq_order = deque()

    def _enrich(self, ssl_event: dict, conn_data: dict) -> dict:
        ssl_event["orig_bytes"] = conn_data["orig_bytes"]
        ssl_event["resp_bytes"] = conn_data["resp_bytes"]
        ssl_event["duration"] = conn_data["duration"]
        pktseq = self._pktseq_cache.get(ssl_event.get("uid"))
        ssl_event["pkt_sizes"] = pktseq["sizes"] if pktseq else []
        ssl_event["pkt_gaps"] = pktseq["gaps"] if pktseq else []
        return ssl_event

    def handle_conn(self, event: dict) -> list[dict]:
        """Cache this conn event's byte data; resolve a pending ssl event
        waiting on the same uid, if any. Returns 0-1 newly-ready events."""
        uid = event.get("uid")
        if not uid:
            return []
        self._conn_cache[uid] = {
            "orig_bytes": event.get("orig_bytes", 0),
            "resp_bytes": event.get("resp_bytes", 0),
            "duration": event.get("duration", 0.0),
        }
        self._conn_order.append(uid)
        while len(self._conn_order) > self.CONN_CACHE_MAX:
            self._conn_cache.pop(self._conn_order.popleft(), None)

        pending = self._pending_ssl.pop(uid, None)
        if pending is None:
            return []
        return [self._enrich(pending[1], self._conn_cache[uid])]

    def handle_ssl(self, event: dict) -> dict | None:
        """Returns the event ready to dispatch now, or None if deferred
        pending a conn.log match (see handle_conn/expire_stale)."""
        uid = event.get("uid")
        if not uid:
            return event
        conn_data = self._conn_cache.get(uid)
        if conn_data is not None:
            return self._enrich(event, conn_data)
        self._pending_ssl[uid] = (event.get("ts", 0.0), event)
        return None

    def handle_pktseq(self, event: dict) -> None:
        """Cache this pkt_seq event's sizes/gaps for a later handle_ssl or
        handle_conn call on the same uid to pick up -- see the class
        docstring for why this is opportunistic, not a dispatch gate."""
        uid = event.get("uid")
        if not uid:
            return
        self._pktseq_cache[uid] = {"sizes": event.get("sizes", []), "gaps": event.get("gaps", [])}
        self._pktseq_order.append(uid)
        while len(self._pktseq_order) > self.CONN_CACHE_MAX:
            self._pktseq_cache.pop(self._pktseq_order.popleft(), None)

    def expire_stale(self, now_ts: float) -> list[dict]:
        """Give up on ssl events whose conn match hasn't shown up within
        PENDING_MAX_AGE of event time -- dispatch with best-effort (zero)
        byte fields rather than holding indefinitely."""
        expired = []
        for uid, (first_seen, ssl_event) in list(self._pending_ssl.items()):
            if now_ts - first_seen > self.PENDING_MAX_AGE:
                popped = self._pending_ssl.pop(uid)[1]
                pktseq = self._pktseq_cache.get(uid)
                popped["pkt_sizes"] = pktseq["sizes"] if pktseq else []
                popped["pkt_gaps"] = pktseq["gaps"] if pktseq else []
                expired.append(popped)
        return expired


def connect_consumer(retries=30, delay=2):
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                *TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=GROUP_ID,
                auto_offset_reset="latest",
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            print(f"[STREAM] Connected to Kafka topics {TOPICS}")
            return consumer
        except Exception as e:
            print(f"[STREAM] Kafka not ready yet ({attempt}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Kafka at {KAFKA_BOOTSTRAP} after {retries} attempts")


def write_alert(alert: dict):
    # Forensic chain-of-custody (PS 26145: "preserves a clean chain of
    # custody for forensic use") -- see forensic_chain.py. Must happen
    # BEFORE the write below so seq/prev_hash/record_hash land in the same
    # line as everything else, not as a separate record.
    forensic_chain.append_chain_fields(alert, ALERTS_FILE)

    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {alert['threat_label']} detected | confidence={alert['confidence']} | src={alert['src_ip']}")

    # Continuous STIX 2.1 / CEF export for air-gapped SOC/SIEM/TIP tailing
    # (see backend/alert_export.py). Best-effort and strictly AFTER the
    # alerts.json write above -- alerts.json is the canonical record the
    # dashboard/API already rely on, so a crash mid-export must never leave
    # it inconsistent, and a future malformed/unexpected evidence shape in
    # a new detector must never crash this consumer loop over a cosmetic
    # export failure (write_alert() itself has no other error handling,
    # unlike write_throughput()/touch_heartbeat() below).
    try:
        with open(CEF_FILE, "a") as f:
            f.write(alert_export.to_cef_line(alert) + "\n")
    except Exception as e:
        print(f"[ALERT_EXPORT] CEF export failed ({e}) -- alerts.json write above is unaffected")
    try:
        with open(STIX_FILE, "a") as f:
            f.write(json.dumps(alert_export.to_stix_bundle([alert])) + "\n")
    except Exception as e:
        print(f"[ALERT_EXPORT] STIX export failed ({e}) -- alerts.json write above is unaffected")


def touch_heartbeat():
    try:
        HEARTBEAT_FILE.write_text(str(time.time()))
    except OSError:
        pass


def write_throughput(rate: float, total: int):
    try:
        THROUGHPUT_FILE.write_text(json.dumps({
            "events_per_sec": round(rate, 1),
            "total_events": total,
            "updated": time.time(),
        }))
    except OSError:
        pass


def run():
    ALERTS_FILE.touch()
    consumer = connect_consumer()
    detectors = [cls() for cls in ACTIVE_DETECTORS]
    correlator = CorrelationEngine()
    ssl_enricher = FlowByteEnricher()
    print(f"[STREAM] Detection engine active with {len(detectors)} detectors: "
          + ", ".join(d.name for d in detectors))

    consumed = 0
    recent_arrivals = deque()   # wall-clock times of recently consumed events

    # Micro-batching (ODIN throughput plan, Phase A1): scikit-learn's
    # per-call predict_proba() overhead (~12ms, see docs/benchmark_results.json's
    # bottleneck_finding) dominated sustained throughput when each event was
    # dispatched to every detector's process() individually. consumer.poll()
    # (vs. the old blocking `for message in consumer:` iterator) bounds how
    # long a batch can wait to fill -- POLL_TIMEOUT_MS keeps per-alert
    # latency far inside the PS's "bounded latency, not an end-of-run
    # report" requirement, while POLL_MAX_RECORDS caps memory/CNN-cost for
    # a burst. Every detector still sees every event exactly once, in
    # arrival order -- only the model call itself is batched.
    while True:
        polled = consumer.poll(timeout_ms=POLL_TIMEOUT_MS, max_records=POLL_MAX_RECORDS)
        if not polled:
            continue

        buffer = []  # normalized, enriched events ready for detector dispatch
        for messages in polled.values():
            for message in messages:
                touch_heartbeat()
                event = normalize_event(message.value)
                if event is None:
                    continue
                consumed += 1

                now = time.time()
                recent_arrivals.append(now)
                cutoff = now - THROUGHPUT_WINDOW_SECONDS
                while recent_arrivals and recent_arrivals[0] < cutoff:
                    recent_arrivals.popleft()
                write_throughput(len(recent_arrivals) / THROUGHPUT_WINDOW_SECONDS, consumed)

                if consumed % 25 == 0:
                    print(f"[STREAM] {consumed} events consumed from Kafka")

                # ssl.log/quic.log rows need their byte/duration fields joined in
                # from the matching conn.log row (see FlowByteEnricher) before any
                # detector sees them -- conn/dns events pass through untouched.
                to_dispatch = [event]
                if event["log_type"] == "conn":
                    to_dispatch += ssl_enricher.handle_conn(event)
                elif event["log_type"] in ("ssl", "quic"):
                    resolved = ssl_enricher.handle_ssl(event)
                    to_dispatch = [resolved] if resolved is not None else []
                elif event["log_type"] == "pktseq":
                    ssl_enricher.handle_pktseq(event)
                    to_dispatch = []  # enrichment-only, never dispatched to detectors itself
                to_dispatch += ssl_enricher.expire_stale(event.get("ts", 0.0))
                buffer.extend(to_dispatch)

        if not buffer:
            continue

        # One process_batch() call per detector for the whole buffer (the
        # actual batching -- see each detector's process_batch() for how
        # the model call is deferred/batched internally), THEN replay
        # results in the original event-outer/detector-inner order so
        # alert emission and correlator.ingest() see events in exactly the
        # same sequence a per-event dispatch loop would have produced.
        results_by_detector = [detector.process_batch(buffer) for detector in detectors]
        for event_idx in range(len(buffer)):
            for detector_idx in range(len(detectors)):
                alert = results_by_detector[detector_idx][event_idx]
                if alert:
                    write_alert(alert)
                    correlated = correlator.ingest(alert)
                    if correlated:
                        write_alert(correlated)


if __name__ == "__main__":
    run()
