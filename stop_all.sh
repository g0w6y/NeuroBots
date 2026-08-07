#!/bin/bash
# Stops everything start_all.sh started, by PID. Safe to run even if nothing
# is running (each kill is best-effort).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.demo-pids"

if [ ! -f "$PID_FILE" ]; then
    echo "No .demo-pids file - nothing to stop (or start_all.sh was never run)."
    exit 0
fi

while IFS=: read -r name pid; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null && echo "stopped $name (pid $pid)"
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "done."
