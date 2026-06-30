#!/usr/bin/env bash
# Stop the adapter started by start.sh, using its PID file.
#
# Env overrides:
#   PIDFILE  pid file location  (default: <app>.pid)
set -euo pipefail
cd "$(dirname "$0")"

APP="harbor-dooray-webhook-adapter"
PIDFILE="${PIDFILE:-${APP}.pid}"

if [ ! -f "$PIDFILE" ]; then
  echo "not running (no $PIDFILE)"
  exit 0
fi

PID="$(cat "$PIDFILE")"
if ! kill -0 "$PID" 2>/dev/null; then
  echo "process $PID not running, removing stale $PIDFILE"
  rm -f "$PIDFILE"
  exit 0
fi

echo "stopping pid $PID ..."
kill "$PID"
for _ in $(seq 1 20); do
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.5
done
if kill -0 "$PID" 2>/dev/null; then
  echo "did not exit gracefully, sending SIGKILL"
  kill -9 "$PID" 2>/dev/null || true
fi
rm -f "$PIDFILE"
echo "stopped"
