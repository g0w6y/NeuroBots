#!/bin/bash
# Brings up the demo upstream API, the gateway, and the ML worker in the
# correct order, with real health checks between each step - not just
# fire-and-hope. Frontend is deliberately NOT started here: run it yourself
# in its own terminal (npm run dev) so it's visible and interactive during
# a live demo rather than backgrounded.
#
# Usage: ./start_all.sh
# Stop everything:  ./stop_all.sh

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT_DIR/.demo-logs"
PID_FILE="$ROOT_DIR/.demo-pids"
mkdir -p "$LOG_DIR"
rm -f "$PID_FILE"

GATEWAY_URL="http://127.0.0.1:8080"
UPSTREAM_URL="http://127.0.0.1:9000"
ADMIN_KEY="${ADMIN_API_KEY:-changeme-admin-key}"

wait_for() {
    local url="$1"
    local name="$2"
    local tries=20
    while [ $tries -gt 0 ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -qE "^(200|401|404)$"; then
            echo "  $name is up ($url)"
            return 0
        fi
        tries=$((tries - 1))
        sleep 0.5
    done
    echo "  WARNING: $name did not respond at $url within 10s - check $LOG_DIR for its log"
    return 1
}

echo "=== 1/3 starting demo upstream API ==="
(cd "$ROOT_DIR/backend" && python3 demo_upstream.py > "$LOG_DIR/upstream.log" 2>&1 &)
sleep 1
# pgrep -f "python3 <script>" is unreliable on macOS: the interpreter's real
# argv0 on disk (Python.app/.../Python) doesn't literally contain "python3",
# so that pattern silently matches nothing. Match on the script name alone
# instead - this bit stop_all.sh completely the first time this was tested.
UPSTREAM_PID=$(pgrep -nf "demo_upstream\.py" || true)
echo "upstream:$UPSTREAM_PID" >> "$PID_FILE"
wait_for "$UPSTREAM_URL/api/accounts/1001" "demo upstream"

echo "=== 2/3 starting gateway ==="
(cd "$ROOT_DIR/backend" && python3 main.py > "$LOG_DIR/gateway.log" 2>&1 &)
sleep 1
GATEWAY_PID=$(pgrep -nf "main\.py" || true)
echo "gateway:$GATEWAY_PID" >> "$PID_FILE"
wait_for "$GATEWAY_URL/health" "gateway"

echo "=== 3/3 starting ML worker (best-effort - needs real Redis) ==="
REDIS_REACHABLE=$(curl -s "$GATEWAY_URL/health" | grep -o '"shared_store_redis":"connected"' || true)
if [ -n "$REDIS_REACHABLE" ]; then
    (cd "$ROOT_DIR/ml" && REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}" GATEWAY_URL="$GATEWAY_URL" \
        ADMIN_API_KEY="$ADMIN_KEY" python3 -u worker.py > "$LOG_DIR/ml_worker.log" 2>&1 &)
    sleep 1
    ML_PID=$(pgrep -nf "worker\.py" || true)
    echo "ml_worker:$ML_PID" >> "$PID_FILE"
    echo "  ML worker started (pid $ML_PID) - it only adds a signal, nothing depends on it"
else
    echo "  Redis not reachable from the gateway - skipping ML worker."
    echo "  Detection still works fully without it (rule-engine anomaly + everything else is unaffected)."
    echo "  To include it: start Redis, restart the gateway, then run ./start_all.sh again."
fi

echo ""
echo "=== up ==="
echo "  gateway:        $GATEWAY_URL"
echo "  demo upstream:  $UPSTREAM_URL"
echo "  health:         curl $GATEWAY_URL/health"
echo "  ml status:      curl -H 'X-Admin-Key: $ADMIN_KEY' $GATEWAY_URL/admin/ml-status"
echo "  logs:           $LOG_DIR/"
echo ""
echo "Now start the dashboard yourself: cd frontend && npm run dev"
echo "Stop everything from this script with: ./stop_all.sh"
