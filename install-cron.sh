#!/usr/bin/env bash
# Install (or remove) a crontab entry that runs watchdog.sh periodically, so the
# adapter is restarted automatically if it dies.
#
# Usage:
#   ./install-cron.sh [install]   # add/refresh the cron entry (default)
#   ./install-cron.sh remove      # remove the cron entry
#   ./install-cron.sh status      # show the current entry
#
# Env overrides:
#   INTERVAL    cron schedule (default: "* * * * *" = every minute)
#   HEALTH_URL  passed through to watchdog.sh (default: empty = PID check only)
#   CONFIG / PIDFILE / LOGFILE / WATCHLOG  passed through to watchdog.sh
set -euo pipefail
cd "$(dirname "$0")"

APP="harbor-dooray-webhook-adapter"
DIR="$(pwd -P)"
WATCHDOG="${DIR}/watchdog.sh"
MARKER="# ${APP}-watchdog"
INTERVAL="${INTERVAL:-* * * * *}"
ACTION="${1:-install}"

# Build the env prefix from any overrides the caller set, so cron (which has a
# minimal environment) runs the watchdog with the same settings.
env_prefix=""
for v in CONFIG PIDFILE LOGFILE WATCHLOG HEALTH_URL LOCKFILE; do
  if [ -n "${!v:-}" ]; then
    env_prefix+="${v}=$(printf '%q' "${!v}") "
  fi
done

current_crontab() { crontab -l 2>/dev/null || true; }
without_entry() { current_crontab | grep -vF "$MARKER" || true; }

case "$ACTION" in
  install)
    if [ ! -x "$WATCHDOG" ]; then
      echo "watchdog.sh not found or not executable: $WATCHDOG" >&2
      exit 1
    fi
    line="${INTERVAL} ${env_prefix}${WATCHDOG} >/dev/null 2>&1 ${MARKER}"
    { without_entry; echo "$line"; } | crontab -
    echo "installed cron entry:"
    echo "  $line"
    ;;
  remove)
    without_entry | crontab -
    echo "removed cron entry (${MARKER})"
    ;;
  status)
    if current_crontab | grep -F "$MARKER"; then :; else echo "no watchdog cron entry installed"; fi
    ;;
  *)
    echo "usage: $0 [install|remove|status]" >&2
    exit 2
    ;;
esac
