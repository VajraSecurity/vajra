#!/usr/bin/env bash
#
# install.sh — install and run the whole Vajra platform on this machine, without Docker.
# (For Docker use docker-compose.yml instead; see README.md.)
#
#   ./install.sh [--host ADDRESS] [--admin-email EMAIL]    install everything (Ubuntu/Debian)
#   ./install.sh <start|stop|restart|status>               manage the services afterwards
#   ./uninstall.sh                                         remove everything this installed
#
# ADDRESS is the name or IP that browsers and agents use to reach this machine. It defaults to
# this machine's first IP address. It is saved in .install.env, so a re-run keeps the same
# passwords. What it sets up (all on this machine, plain HTTP):
#   - PostgreSQL, Redis, Kafka, the C++ server (agents enroll on port 1234) and detection engine
#   - the Node.js backend (port 4000) and the web console (nginx, port 8080)
#   - linux_agent.zip and windows_agent.zip with the address, certificate and secret filled in,
#     downloadable from the web console
# The steps are in vajranet_server/scripts/setup/; service.sh runs them. A step can be repeated
# with: vajranet_server/scripts/service.sh setup <number>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="$ROOT/vajranet_server/scripts/service.sh"
STATE="$ROOT/.install.env"            # settings and generated passwords (git-ignored)
CREDS="$ROOT/admin-credentials.txt"   # first admin login (git-ignored)

case "${1:-install}" in
  start|stop|restart|status)
    C_UNITS="vajra_kafka vajra_server vajra_engine_v2"   # C++ side: broker, ingest server, detection engine
    case "$1" in
      start)   "$SERVICE" start all; sudo systemctl start $C_UNITS ;;
      stop)    sudo systemctl stop vajra_engine_v2 vajra_server vajra_kafka; "$SERVICE" stop all ;;
      restart) "$0" stop; "$0" start ;;
      status)  "$SERVICE" status all
               for u in $C_UNITS; do
                 systemctl is-active --quiet "$u" && echo "$u: running" || echo "$u: stopped"
               done ;;
    esac
    exit 0 ;;
esac

HOST_ARG=""; ADMIN_EMAIL_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    install) ;;
    --host) HOST_ARG="${2:?--host needs a value}"; shift ;;
    --admin-email) ADMIN_EMAIL_ARG="${2:?--admin-email needs a value}"; shift ;;
    *) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1 ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user with sudo rights, not as root." >&2; exit 1; }
command -v sudo >/dev/null || { echo "sudo is required." >&2; exit 1; }
for d in vajranet_server vajra_server linux_agent windows_agent; do
  [ -d "$ROOT/$d" ] || { echo "Missing folder $d next to install.sh." >&2; exit 1; }
done

# ---- the Docker stack and this install use the same ports (console, 4000, 1234): not both ----
if command -v docker >/dev/null 2>&1 && \
   [ -n "$(docker ps -q --filter label=com.docker.compose.project=vajra 2>/dev/null)" ]; then
  echo "The Docker setup of Vajra is running on this machine. It uses the same ports as this install" >&2
  echo "(8080, 4000, 1234), so the two would collide. Stop it first:  docker compose down   (or ./docker/cleanup.sh)" >&2
  exit 1
fi

# ---- settings: reuse the saved ones, otherwise create them ------------------
if [ -f "$STATE" ]; then source "$STATE"; fi
if [ -n "$HOST_ARG" ]; then PUBLIC_HOST="$HOST_ARG"; fi
if [ -z "${PUBLIC_HOST:-}" ]; then
  PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$PUBLIC_HOST" ] || { echo "Could not detect this machine's IP. Pass --host ADDRESS." >&2; exit 1; }
fi
IP_ADDRESS="$PUBLIC_HOST"
[[ "$IP_ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  IP_ADDRESS="$(getent hosts "$PUBLIC_HOST" | awk '{print $1; exit}')"
[ -n "$IP_ADDRESS" ] || { echo "Cannot resolve $PUBLIC_HOST to an IP address." >&2; exit 1; }
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -hex 16)}"
ADMIN_EMAIL="${ADMIN_EMAIL_ARG:-${ADMIN_EMAIL:-admin@vajra.local}}"
ADMIN_CREATED="${ADMIN_CREATED:-0}"

save_state() {
  ( umask 077; cat > "$STATE" <<S
PUBLIC_HOST=$PUBLIC_HOST
DB_PASSWORD=$DB_PASSWORD
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_CREATED=$ADMIN_CREATED
S
  )
}
save_state

# What the setup steps read (see vajranet_server/scripts/setup/00-init.sh).
export WEB_PORT="${WEB_PORT:-8080}"
export DB_PASSWORD FULL_DOMAIN="$PUBLIC_HOST" IP_ADDRESS
export USER_NAME="${USER_NAME:-Vajra Admin}" USER_EMAIL="$ADMIN_EMAIL" USER_MOBILE="${USER_MOBILE:-9999999999}"
export USER_COMPANY="${USER_COMPANY:-Vajra}" USER_ADDRESS="${USER_ADDRESS:-Local}"

# ---- remember what was on this machine before, so uninstall.sh removes only what we add ----
SNAP="$ROOT/.install-snapshot"
if [ ! -d "$SNAP" ]; then
  mkdir -p "$SNAP"
  dpkg-query -W -f='${Package}\n' 2>/dev/null | sort -u > "$SNAP/packages.txt"
  {
    [ -e /etc/apt/sources.list.d/nodesource.list ] || [ -e /etc/apt/sources.list.d/nodesource.sources ] && echo "HAD_NODESOURCE=1" || echo "HAD_NODESOURCE=0"
    ls -d "$HOME"/kafka_* >/dev/null 2>&1 && echo "HAD_KAFKA_DIR=1" || echo "HAD_KAFKA_DIR=0"
    [ -d "$HOME/kafka-data" ] && echo "HAD_KAFKA_DATA=1" || echo "HAD_KAFKA_DATA=0"
    [ -e /var/lib/postgresql ] && echo "HAD_PG_DIR=1" || echo "HAD_PG_DIR=0"
    # Did the databases/role we will create already exist? If we cannot tell (PostgreSQL installed but
    # not answering), say yes: uninstall then leaves them alone.
    pg_had() {
      local out
      if ! command -v psql >/dev/null 2>&1 || ! dpkg-query -W -f='${Status}' postgresql 2>/dev/null | grep -q "install ok"; then echo 0; return; fi
      out=$(sudo -u postgres psql -tAc "$1" 2>/dev/null) || { echo 1; return; }
      [ "$out" = 1 ] && echo 1 || echo 0
    }
    echo "HAD_DB_FLEET=$(pg_had "SELECT 1 FROM pg_database WHERE datname='fleet'")"
    echo "HAD_DB_VAJRA_DB=$(pg_had "SELECT 1 FROM pg_database WHERE datname='vajra_db'")"
    echo "HAD_ROLE_VAJRA=$(pg_had "SELECT 1 FROM pg_roles WHERE rolname='vajra'")"
    [ -e /etc/nginx/sites-enabled/default ] && echo "HAD_NGINX_DEFAULT=1" || echo "HAD_NGINX_DEFAULT=0"
  } > "$SNAP/state.env"
fi

echo "Installing Vajra for address: $PUBLIC_HOST ($IP_ADDRESS)"
echo "This installs system packages and takes a while (the C++ server is compiled)."

# ---- run the steps; the admin account is only created once -----------------
for step in 00 01 02 03 04 05 06 07 08 09 10 11 12; do
  if [ "$step" = 09 ] && [ "$ADMIN_CREATED" = 1 ]; then echo ">>> 09 skipped (admin already created)"; continue; fi
  if [ "$step" = 09 ]; then
    ( umask 077; "$SERVICE" setup 09 2>&1 | tee "$CREDS" ) || { rm -f "$CREDS"; exit 1; }
    ADMIN_CREATED=1; save_state
  else
    "$SERVICE" setup "$step"
  fi
done

cat <<DONE

====================================================================
Vajra is running.
  Web console:       http://$PUBLIC_HOST:$WEB_PORT
  Agent downloads:   http://$PUBLIC_HOST:$WEB_PORT/linux_agent.zip
                     http://$PUBLIC_HOST:$WEB_PORT/windows_agent.zip
  Agents report to:  $PUBLIC_HOST:1234 (osquery) and $PUBLIC_HOST:4000 (extension)
  First login:       see $CREDS (change the password at first login)
  Manage services:   ./install.sh status | stop | start | restart
Open ports $WEB_PORT, 1234 and 4000 in this machine's firewall for agents on other machines.
====================================================================
DONE
