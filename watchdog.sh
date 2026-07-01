#!/usr/bin/env bash
# Restart the adapter if it is not running. Intended to be run periodically
# from cron (see install-cron.sh). Safe to run concurrently — a flock guards
# against overlapping restarts.
#
# "Not running" means: no PID file, a stale PID file (process gone), or — when
# HEALTH_URL is set — the health endpoint not returning HTTP 200.
#
# Env overrides (shared with start.sh/stop.sh):
#   CONFIG     config file        (default: config.yaml)
#   PIDFILE    pid file           (default: <app>.pid)
#   LOGFILE    app log file       (default: <app>.log)
#   WATCHLOG   watchdog log file  (default: watchdog.log)
#   HEALTH_URL health check URL   (default: empty = PID check only)
set -euo pipefail
cd "$(dirname "$0")"

APP="harbor-dooray-webhook-adapter"
PIDFILE="${PIDFILE:-${APP}.pid}"
WATCHLOG="${WATCHLOG:-watchdog.log}"
HEALTH_URL="${HEALTH_URL:-}"
LOCKDIR="${LOCKDIR:-/tmp/${APP}.watchdog.lock.d}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$WATCHLOG"; }

# Serialize runs so two overlapping cron ticks never double-start. mkdir is
# atomic on POSIX filesystems, so it works without flock (absent on macOS).
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  # Lock is held. If it is older than 10 minutes, assume a previous run was
  # killed and steal it; otherwise another watchdog is active, so bail.
  if [ -n "$(find "$LOCKDIR" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then
    rmdir "$LOCKDIR" 2>/dev/null || true
    mkdir "$LOCKDIR" 2>/dev/null || exit 0
  else
    exit 0
  fi
fi
trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT

running=true
reason=""

if [ ! -f "$PIDFILE" ]; then
  running=false
  reason="no pid file"
elif ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  running=false
  reason="process $(cat "$PIDFILE") not alive"
elif [ -n "$HEALTH_URL" ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$HEALTH_URL" || echo 000)"
  if [ "$code" != "200" ]; then
    running=false
    reason="health check ${HEALTH_URL} returned ${code}"
    # Stop the unhealthy-but-alive process before restarting.
    ./stop.sh >>"$WATCHLOG" 2>&1 || true
  fi
fi

if [ "$running" = true ]; then
  exit 0
fi

log "adapter down (${reason}); restarting"
if ./start.sh >>"$WATCHLOG" 2>&1; then
  log "restart ok (pid $(cat "$PIDFILE" 2>/dev/null || echo '?'))"
else
  log "restart FAILED (exit $?)"
  exit 1
fi
