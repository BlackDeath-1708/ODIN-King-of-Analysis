#!/bin/bash
set -e

if [ "$EUID" -eq 0 ]; then
  echo "ERROR: do not run this as root / with sudo." >&2
  echo "Docker and the Python venv are set up for your normal user; running as" >&2
  echo "root creates a separate set of root-owned files/processes that" >&2
  echo "conflict with them. Just run: ./start_demo.sh" >&2
  exit 1
fi

echo "=================================================="
echo "  HYBRID 1 -- Passive Cyber Threat Detection PoC   "
echo "=================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/backend/.venv/bin/python3"

if [ ! -x "$PYTHON" ]; then
  echo "[x] $PYTHON not found." >&2
  echo "    Run this once: cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

PIDS=()
cleanup() {
  echo ""
  echo "Stopping services..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  (cd "$SCRIPT_DIR" && docker compose down) 2>/dev/null || true
}
trap cleanup EXIT

# ---- 1. Docker infrastructure (Kafka + Zeek) ------------------------------
echo "[1/7] Starting Docker infrastructure (Kafka, Zeek)..."
(cd "$SCRIPT_DIR" && docker compose up -d)

# ---- 2. Wait for Kafka to actually be ready -------------------------------
# Docker reporting the container "up" is not the same as the broker being
# ready to accept connections -- Kafka can take 10-30s after container start.
# A publisher/consumer that connects before then fails or crashes, so this
# is a real health-check loop, not a sleep timer.
echo "[2/7] Waiting for Kafka broker..."
KAFKA_READY=0
for i in $(seq 1 60); do
  if docker exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list &>/dev/null; then
    KAFKA_READY=1
    break
  fi
  sleep 2
done
if [ "$KAFKA_READY" -ne 1 ]; then
  echo "[x] Kafka did not become ready after 120s. Check: docker logs kafka" >&2
  exit 1
fi
docker exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic zeek-conn --partitions 1 --replication-factor 1 &>/dev/null
echo "[✓] Kafka ready"

# ---- 3. Confirm Zeek is actually running -----------------------------------
echo "[3/7] Checking Zeek..."
ZEEK_READY=0
for i in $(seq 1 15); do
  if [ "$(docker inspect -f '{{.State.Running}}' zeek_monitor 2>/dev/null)" = "true" ]; then
    ZEEK_READY=1
    break
  fi
  sleep 1
done
if [ "$ZEEK_READY" -ne 1 ]; then
  echo "[x] Zeek container is not running. Check: docker logs zeek_monitor" >&2
  exit 1
fi
echo "[✓] Zeek started"

cd "$SCRIPT_DIR/backend"
rm -f .heartbeat .producer_heartbeat
touch alerts.json

# ---- 4. Kafka publisher (Zeek log -> Kafka) --------------------------------
echo "[4/7] Starting Kafka publisher..."
"$PYTHON" kafka_producer.py &
PRODUCER_PID=$!
PIDS+=("$PRODUCER_PID")
sleep 2
if ! kill -0 "$PRODUCER_PID" 2>/dev/null; then
  echo "[x] Kafka publisher failed to start. Check backend/kafka_producer.py" >&2
  exit 1
fi
echo "[✓] Event pipeline started (PID $PRODUCER_PID)"

# ---- 5. Streaming detector (Kafka -> detectors -> alerts.json) ------------
echo "[5/7] Starting streaming detection engine..."
"$PYTHON" stream_consumer.py &
CONSUMER_PID=$!
PIDS+=("$CONSUMER_PID")
sleep 2
if ! kill -0 "$CONSUMER_PID" 2>/dev/null; then
  echo "[x] Streaming detector failed to start. Check backend/stream_consumer.py" >&2
  exit 1
fi
echo "[✓] Detection engine started (PID $CONSUMER_PID)"

# ---- 6. Flask API/SSE -------------------------------------------------------
echo "[6/7] Starting API server..."
"$PYTHON" app.py &
API_PID=$!
PIDS+=("$API_PID")
API_READY=0
for i in $(seq 1 15); do
  if curl -s -o /dev/null http://localhost:5000/api/pipeline-status; then
    API_READY=1
    break
  fi
  sleep 1
done
if [ "$API_READY" -ne 1 ]; then
  echo "[x] API server did not come up. Check backend/app.py" >&2
  exit 1
fi
echo "[✓] API started (PID $API_PID)"

# ---- 7. React dashboard -----------------------------------------------------
echo "[7/7] Starting dashboard..."
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!
PIDS+=("$FRONTEND_PID")
echo "[✓] Dashboard started (PID $FRONTEND_PID)"

echo ""
echo "=================================================="
echo "  Dashboard: http://localhost:5173                "
echo "  API:       http://localhost:5000                "
echo "=================================================="
echo ""
echo "Press Ctrl+C to stop all services."

wait
