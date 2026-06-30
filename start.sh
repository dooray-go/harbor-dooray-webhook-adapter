#!/usr/bin/env bash
# Build and start the adapter in the background, recording its PID.
#
# Env overrides:
#   CONFIG   path to config file   (default: config.yaml)
#   PIDFILE  pid file location     (default: <app>.pid)
#   LOGFILE  log file location     (default: <app>.log)
set -euo pipefail
cd "$(dirname "$0")"

APP="harbor-dooray-webhook-adapter"
BIN="dist/${APP}"
CONFIG="${CONFIG:-config.yaml}"
PIDFILE="${PIDFILE:-${APP}.pid}"
LOGFILE="${LOGFILE:-${APP}.log}"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "already running (pid $(cat "$PIDFILE"))"
  exit 0
fi

if [ ! -f "$CONFIG" ]; then
  echo "config not found: $CONFIG (copy config.example.yaml and edit it)" >&2
  exit 1
fi

echo "building ${BIN} ..."
make build

echo "starting ..."
nohup "./${BIN}" -config "$CONFIG" >>"$LOGFILE" 2>&1 &
echo $! >"$PIDFILE"
echo "started (pid $(cat "$PIDFILE")), logs -> $LOGFILE"
