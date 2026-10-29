#!/usr/bin/env bash
#
# service.sh — install and run Vajranet.
#
# Usage:
#   scripts/service.sh setup [step]                          install everything (see scripts/setup/)
#   scripts/service.sh <start|stop|restart|status> [service|all]
#   scripts/service.sh dev <start|stop|status> [backend|frontend|all]   (local development)
#
# Services (all are systemd units; edit the table in unit_of() to add one):
#   postgres, redis, grafana, backend, nginx
#   The frontend is static files served by nginx, so it has no service of its own.
#
# setup runs the numbered scripts in scripts/setup/ in order and stops at the first
# failure. It reads its settings from environment variables, for example:
#   DB_PASSWORD=... FULL_DOMAIN=vajra.example.com IP_ADDRESS=10.0.0.5 \
#   USER_NAME=Admin USER_EMAIL=admin@example.com USER_MOBILE=9999999999 \
#   USER_COMPANY=Acme USER_ADDRESS=Mumbai  scripts/service.sh setup
# Run a single step with its number, e.g.: scripts/service.sh setup 04
# The steps also set up the C++ server (vajra_server) and build the agent downloads, so
# vajra_server, linux_agent and windows_agent must sit next to this folder (or set
# VAJRA_SERVER_DIR, LINUX_AGENT_DIR, WINDOWS_AGENT_DIR). Everything runs on this machine.
#
# dev runs `npm run dev` for the backend and/or frontend as background processes (pid and
# log in run/). Stop the backend service first (`service.sh stop backend`) so port 4000 is free.

set -uo pipefail

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/setup"
SERVICES="postgres redis grafana backend nginx"   # start order; stop runs in reverse

unit_of() {   # systemd unit of a service
  case "$1" in
    postgres) echo postgresql ;;
    redis)    echo redis-server ;;
    grafana)  echo grafana-server ;;
    backend)  echo vajra-backend ;;
    nginx)    echo nginx ;;
  esac
}

usage() { sed -n '3,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 1; }

[ "$#" -ge 1 ] || usage
ACTION="$1"; TARGET="${2:-}"

# ---- dev: run backend/frontend from the source tree -------------------------
if [ "$ACTION" = dev ]; then
  CMD="${2:-}"; WHAT="${3:-all}"; RUN_DIR="$SETUP_DIR/../../run"; mkdir -p "$RUN_DIR"
  [ "$WHAT" = all ] && WHAT="backend frontend"
  for app in $WHAT; do
    [ "$app" = backend ] || [ "$app" = frontend ] || usage
    pidf="$RUN_DIR/$app.pid"
    up() { [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; }
    case "$CMD" in
      start) up && { echo "$app: already running"; continue; }
             # setsid gives it its own process group so stop also ends npm's children.
             (cd "$SETUP_DIR/../../$app" && exec setsid npm run dev >"$RUN_DIR/$app.log" 2>&1) &
             echo $! > "$pidf"; echo "$app: started (log: run/$app.log)" ;;
      stop)  if up; then kill -TERM -- "-$(cat "$pidf")" 2>/dev/null; echo "$app: stopped"; else echo "$app: not running"; fi
             rm -f "$pidf" ;;
      status) up && echo "$app: running" || echo "$app: stopped" ;;
      *) usage ;;
    esac
  done
  exit 0
fi

# ---- setup: run the install steps ------------------------------------------
if [ "$ACTION" = setup ]; then
  # With a step number only that step runs, otherwise every [0-9]*.sh in order.
  for script in "$SETUP_DIR"/${TARGET:-[0-9]}*.sh; do
    [ -f "$script" ] || { echo "No setup step matches '${TARGET}'" >&2; exit 1; }
    echo ">>> $(basename "$script")"
    bash "$script" || { echo "Setup stopped: $(basename "$script") failed" >&2; exit 1; }
  done
  exit 0
fi

# ---- start / stop / restart / status ---------------------------------------
case "$ACTION" in start|stop|restart|status) ;; *) usage ;; esac
TARGET="${TARGET:-all}"
if [ "$TARGET" = all ]; then LIST="$SERVICES"; else
  [[ " $SERVICES " == *" $TARGET "* ]] || { echo "Unknown service '$TARGET' (use: $SERVICES, all)" >&2; exit 1; }
  LIST="$TARGET"
fi
[ "$ACTION" = stop ] && LIST="$(echo "$LIST" | tr ' ' '\n' | tac | tr '\n' ' ')"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
rc=0
for s in $LIST; do
  unit="$(unit_of "$s")"
  if [ "$ACTION" = status ]; then
    if systemctl is-active --quiet "$unit" 2>/dev/null; then echo "$s: running"; else echo "$s: stopped"; fi
  elif $SUDO systemctl "$ACTION" "$unit"; then
    echo "$s: $ACTION ok"
  else
    echo "$s: $ACTION FAILED" >&2; rc=1
  fi
done
exit "$rc"
