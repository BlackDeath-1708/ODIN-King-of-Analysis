"""
Zeek -> Kafka producer.

Tails Zeek's conn.log, dns.log, ssl.log, quic.log, and pkt_seq.log (JSON
lines) and publishes each raw event onto its own Kafka topic
("zeek-conn"/"zeek-dns"/"zeek-ssl"/"zeek-quic"/"zeek-pktseq"). This is the
boundary between the NSM layer and the streaming layer in the Hybrid 1
architecture: everything downstream of Kafka (the stream consumer, the
detectors) only ever sees events that came off the bus, never the log files
directly -- which is exactly what makes it possible to swap this producer
for a real Filebeat/Kafka Connect pipeline, or the consumer for Flink,
without touching anything else.

Each log gets its own tailing thread sharing one KafkaProducer (thread-safe
for concurrent .send() calls) -- the logs grow independently, so one being
briefly quiet or slow to appear doesn't block the others. pkt_seq.log (see
zeek/scripts/pkt_seq.zeek) only ever has rows for ssl/quic connections, so
its tailing thread is simply idle for non-TLS/QUIC traffic -- not an error.
"""

import json
import time
import threading
from pathlib import Path

from kafka import KafkaProducer

KAFKA_BOOTSTRAP = "localhost:9092"
LOG_TOPICS = [
    (Path("zeek-logs/conn.log"),    "zeek-conn"),
    (Path("zeek-logs/dns.log"),     "zeek-dns"),
    (Path("zeek-logs/ssl.log"),     "zeek-ssl"),
    (Path("zeek-logs/quic.log"),    "zeek-quic"),
    (Path("zeek-logs/pkt_seq.log"), "zeek-pktseq"),
]
HEARTBEAT_FILE  = Path(".producer_heartbeat")
POLL_INTERVAL   = 0.5


def touch_heartbeat():
    try:
        HEARTBEAT_FILE.write_text(str(time.time()))
    except OSError:
        pass


def connect_producer(retries=30, delay=2):
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                retries=5,
            )
            print(f"[PRODUCER] Connected to Kafka at {KAFKA_BOOTSTRAP}")
            return producer
        except Exception as e:
            print(f"[PRODUCER] Kafka not ready yet ({attempt}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Kafka at {KAFKA_BOOTSTRAP} after {retries} attempts")


def tail_file(filepath: Path):
    while not filepath.exists():
        print(f"[PRODUCER] Waiting for {filepath}...")
        time.sleep(2)
    print(f"[PRODUCER] Tailing {filepath}")
    with open(filepath, "r") as f:
        f.seek(0, 2)   # only new lines from here on
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_INTERVAL)


def publish_log(producer: KafkaProducer, filepath: Path, topic: str):
    """Tail one Zeek log file and publish each JSON line to its topic.
    Runs in its own thread -- one per log file -- so conn/dns/ssl tailing
    proceeds independently of each other."""
    sent = 0
    for raw_line in tail_file(filepath):
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        # Partition key (ODIN throughput plan, Phase A3 -- horizontal
        # scaling design): keying by source IP means every event for a
        # given src_ip always lands on the same partition, which is what
        # lets multiple stream_consumer.py processes share one Kafka
        # consumer group (same GROUP_ID) safely -- every detector's
        # per-source state (ddos.py's AdaptiveEntropyBaseline, correlator.py's
        # per-src_ip history, etc.) stays correct because a given source's
        # events are never split across two consumer processes. Zeek's
        # dotted key names vary per log type (id.orig_h for conn/dns/ssl,
        # same field for quic/pkt_seq) -- all share this one source-address
        # field, so one key expression covers every topic this producer
        # publishes to.
        producer.send(topic, event, key=event.get("id.orig_h"))
        touch_heartbeat()
        sent += 1
        if sent % 25 == 0:
            print(f"[ZEEK] Event received | [KAFKA] {sent} events published to '{topic}'")


def run():
    producer = connect_producer()
    threads = [
        threading.Thread(target=publish_log, args=(producer, path, topic), daemon=True)
        for path, topic in LOG_TOPICS
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    run()
