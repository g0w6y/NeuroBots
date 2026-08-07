#!/bin/bash
# NeuroBots end-to-end demo (DEVOPS.md Part 8).
#
# Brings the whole stack up with Docker Compose, waits for it to actually be
# healthy, proves detection with the attack suite, measures performance, and
# opens the dashboard.
#
#   ./scripts/demo.sh
#   SKIP_BENCH=1 ./scripts/demo.sh     # faster, for a live audience
#
# This drives the containerised stack. For the no-Docker path use start_all.sh
# (or start_all.ps1 on Windows) and run the two scripts below by hand.

set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GATEWAY="http://127.0.0.1:8080"
DASHBOARD="http://127.0.0.1:3000"
ADMIN_KEY="${ADMIN_API_KEY:-changeme-admin-key}"

echo "=== 1/5 building and starting the stack ==="
docker compose up -d --build

echo ""
echo "=== 2/5 waiting for services to be healthy ==="
# Poll the gateway's own health endpoint rather than sleeping a fixed number of
# seconds. `docker compose up -d` returns as soon as containers are *created*,
# which on a cold build is well before uvicorn is accepting connections.
for i in $(seq 1 60); do
    if curl -sf "$GATEWAY/health" > /dev/null 2>&1; then
        echo "  gateway healthy after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "  gateway did not become healthy within 60s"
        docker compose ps
        docker compose logs --tail=40 gateway
        exit 1
    fi
    sleep 1
done

curl -s "$GATEWAY/health" | python3 -m json.tool 2>/dev/null || curl -s "$GATEWAY/health"

echo ""
echo "=== 3/5 attack simulation ==="
# Run inside the gateway container so no local venv is needed, and so the
# simulator reads exactly the config the gateway is running with.
docker compose exec -T gateway python attack_sim/simulate.py --gateway http://127.0.0.1:8080

if [ -z "${SKIP_BENCH:-}" ]; then
    echo ""
    echo "=== 4/5 performance benchmark ==="
    if [ -x "backend/venv/bin/python" ]; then
        backend/venv/bin/python scripts/benchmark.py --gateway "$GATEWAY" --out BENCHMARK.md
    else
        python3 scripts/benchmark.py --gateway "$GATEWAY" --out BENCHMARK.md
    fi
else
    echo ""
    echo "=== 4/5 benchmark skipped (SKIP_BENCH set) ==="
fi

echo ""
echo "=== 5/5 opening the dashboard ==="
if command -v xdg-open > /dev/null; then xdg-open "$DASHBOARD"
elif command -v open > /dev/null; then open "$DASHBOARD"
elif command -v powershell.exe > /dev/null; then powershell.exe -NoProfile -Command "Start-Process '$DASHBOARD'"
else echo "  open $DASHBOARD yourself"
fi

echo ""
echo "Dashboard : $DASHBOARD"
echo "Gateway   : $GATEWAY"
echo "Live feed : docker compose logs -f gateway"
echo "Stop      : docker compose down        (add -v to wipe Redis/Postgres volumes)"
