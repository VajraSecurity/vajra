#!/usr/bin/env bash
#
# uninstall.sh — remove everything ./install.sh set up on this machine.
#
#   ./uninstall.sh [--yes] [--keep-packages]
#
# It removes: the Vajra services, the databases and role, nginx site, web files, build output,
# generated certificates, passwords and settings. System packages (PostgreSQL, Redis, nginx,
# Node.js, build tools, ...) are removed only if they were NOT on this machine before
# ./install.sh ran (it saved a list in .install-snapshot/). Packages that were already there
# stay installed; only Vajra's data in them is dropped. --keep-packages skips package removal
# altogether. --yes does not ask for confirmation.
#
# This script does not remove agents. To remove an agent from a machine see README.md.
# For the Docker setup use docker/cleanup.sh instead.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAP="$ROOT/.install-snapshot"
YES=0; KEEP_PKGS=0
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;;
    --keep-packages) KEEP_PKGS=1 ;;
    *) sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1 ;;
  esac
done
[ "$(id -u)" -ne 0 ] || { echo "Run as a normal user with sudo rights, not as root." >&2; exit 1; }

# Only for installs made with ./install.sh. A Docker install is removed with docker/cleanup.sh.
if [ ! -f "$ROOT/.install.env" ] && [ ! -d "$SNAP" ]; then
  if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -aq --filter label=com.docker.compose.project=vajra 2>/dev/null)" ]; then
    echo "This machine runs Vajra with Docker, not with ./install.sh." >&2
    echo "To remove it run:  ./docker/cleanup.sh" >&2
  else
    echo "Nothing to remove: ./install.sh has not been run from this folder (no .install.env)." >&2
  fi
  exit 1
fi

[ -f "$ROOT/.install.env" ] && source "$ROOT/.install.env"
HOST="${PUBLIC_HOST:-}"
# Defaults are the safe ones: when we do not know what was there before, keep it.
HAD_NODESOURCE=1; HAD_KAFKA_DIR=1; HAD_KAFKA_DATA=1; HAD_NGINX_DEFAULT=0
HAD_PG_DIR=1; HAD_DB_FLEET=1; HAD_DB_VAJRA_DB=1; HAD_ROLE_VAJRA=1
[ -f "$SNAP/state.env" ] && source "$SNAP/state.env"

# HOST ends up in rm -rf paths: accept only a plain IP address or host name.
if [ -n "$HOST" ] && ! [[ "$HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
  echo "Refusing to continue: the saved address '$HOST' in .install.env is not a plain IP or host name." >&2
  exit 1
fi

say() { echo; echo "==> $*"; }
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "$1 [y/N] " r; [[ "$r" =~ ^[Yy]$ ]]; }

echo "This will remove Vajra and what ./install.sh added to this machine."
confirm "Continue?" || { echo "Cancelled."; exit 0; }

# ---- services ---------------------------------------------------------------
say "Stopping and removing services"
for u in vajra-backend vajra_engine_v2 vajra_rule_builder vajra_event_processor vajra_server vajra_kafka; do
  sudo systemctl stop "$u" 2>/dev/null
  sudo systemctl disable "$u" 2>/dev/null
  sudo rm -f "/etc/systemd/system/$u.service"
done
sudo systemctl daemon-reload
sudo rm -f /var/log/vajra-backend.log
# Only stop a Kafka that this install created (its folder was not there before); never a broker of your own.
if [ "$HAD_KAFKA_DIR" = 0 ]; then pkill -f "$HOME/kafka_[0-9.]*-" 2>/dev/null || true; fi
for app in backend frontend; do   # processes started with service.sh dev
  [ -f "$ROOT/vajranet_server/run/$app.pid" ] && kill -TERM -- "-$(cat "$ROOT/vajranet_server/run/$app.pid")" 2>/dev/null
done

# ---- databases ---------------------------------------------------------------
if command -v psql >/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
  say "Dropping the Vajra databases and role (only those this install created)"
  drop() {   # drop KIND NAME HAD_BEFORE
    if [ "$3" != 0 ]; then echo "Keeping $1 $2 (it existed before, or could not be checked)."; return; fi
    if [ "$1" = role ]; then sudo -u postgres psql -qc "DROP ROLE IF EXISTS $2;" 2>/dev/null
    else sudo -u postgres psql -qc "DROP DATABASE IF EXISTS $2 WITH (FORCE);" 2>/dev/null; fi
  }
  drop database vajra_db "$HAD_DB_VAJRA_DB"
  drop database fleet    "$HAD_DB_FLEET"
  drop role     vajra    "$HAD_ROLE_VAJRA"
fi

# ---- nginx site and web files --------------------------------------------------
if [ -n "$HOST" ]; then
  say "Removing the nginx site and web files for $HOST"
  sudo rm -f "/etc/nginx/sites-enabled/$HOST" "/etc/nginx/sites-available/$HOST"
  sudo rm -rf "/var/www/$HOST"
fi
if [ "$HAD_NGINX_DEFAULT" = 1 ] && [ -e /etc/nginx/sites-available/default ]; then
  sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default   # install removed it
fi
command -v nginx >/dev/null && sudo nginx -t >/dev/null 2>&1 && sudo systemctl reload nginx 2>/dev/null

# ---- files created inside the repository, Kafka, logs ------------------------------
say "Removing build output, generated keys, certificates and settings"
rm -rf "$ROOT/vajranet_server/backend/"{node_modules,dist,keys,storage,.env} \
       "$ROOT/vajranet_server/frontend/"{node_modules,dist,.env} \
       "$ROOT/vajranet_server/run" \
       "$ROOT/vajra_server/"{cmake-build-debug,ssl,logs,enrollment_secret.txt,config.json} \
       "$ROOT/vajra_server/engine_v2/build" "$ROOT/vajra_server/rule_builder/build" \
       /tmp/vajra /tmp/vajra_register.json /tmp/kafka-server.log
[ "${HAD_KAFKA_DIR:-1}" = 0 ] && rm -rf "$HOME"/kafka_2.13-*
[ "${HAD_KAFKA_DATA:-1}" = 0 ] && rm -rf "$HOME/kafka-data"
[ "${HAD_NODESOURCE:-1}" = 0 ] && sudo rm -f /etc/apt/sources.list.d/nodesource.* /etc/apt/keyrings/nodesource.gpg

# ---- packages that install.sh added ----------------------------------------------------
# Only packages from this fixed list can ever be removed, and only if they were NOT installed before
# ./install.sh ran. Nothing else on the machine is touched: no desktop, login or system packages, and
# never "everything added since". Common tools (python3, curl, git, openssl, tar, ca-certificates, make)
# are left installed on purpose: other software depends on them and they are harmless.
VAJRA_PACKAGES="nodejs nginx postgresql postgresql-contrib redis-server redis-tools jq zip cmake g++ wget
  netcat-openbsd libpq-dev libpqxx-dev libboost-all-dev librdkafka-dev libjsoncpp-dev libsqlite3-dev
  libcrypto++-dev libprocps-dev libproc2-dev openjdk-17-jdk python3-pip build-essential grafana"
if [ "$KEEP_PKGS" = 1 ]; then
  say "Keeping all packages (--keep-packages)"
elif [ ! -f "$SNAP/packages.txt" ]; then
  say "No package list from before the install (.install-snapshot/ missing): leaving packages alone"
else
  say "Packages this install added"
  : > /tmp/vajra_new_packages.txt
  for pkg in $VAJRA_PACKAGES; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok" && ! grep -qx "$pkg" "$SNAP/packages.txt"; then
      echo "$pkg" >> /tmp/vajra_new_packages.txt
    fi
  done
  if [ -s /tmp/vajra_new_packages.txt ]; then
    echo "Candidates: $(tr '\n' ' ' < /tmp/vajra_new_packages.txt)"
    # Dry run: removing a package also removes everything that depends on it. If that would take away
    # anything that is not in the list above, stop. Desktop and login packages must never be affected.
    mapfile -t wanted < /tmp/vajra_new_packages.txt
    sudo apt-get -s purge "${wanted[@]}" 2>/dev/null | sed -n 's/^Purg \([^ ]*\).*/\1/p' | sort -u > /tmp/vajra_would_purge.txt
    extra="$(comm -13 <(sort -u /tmp/vajra_new_packages.txt) /tmp/vajra_would_purge.txt)"
    if [ -n "$extra" ]; then
      echo "Not purging anything: that would also remove packages that are not part of Vajra:"
      echo "$extra" | tr '\n' ' '; echo
      echo "Nothing was removed. Remove packages by hand if you want, or use --keep-packages."
    elif confirm "Purge these packages?"; then
      sudo apt-get purge "${wanted[@]}" -y || echo "apt could not remove everything; leaving the rest."
      # Remove PostgreSQL's data folders only when none of PostgreSQL existed before this install.
      if [ "$HAD_PG_DIR" = 0 ] && ! grep -qE '^postgresql(-[0-9]+)?$' "$SNAP/packages.txt"; then
        sudo rm -rf /var/lib/postgresql /etc/postgresql
      fi
    fi
    rm -f /tmp/vajra_would_purge.txt
  else
    echo "None: everything Vajra needed was already installed, so nothing was removed."
  fi
  rm -f /tmp/vajra_new_packages.txt
fi

rm -rf "$SNAP" "$ROOT/.install.env" "$ROOT/admin-credentials.txt"

echo
echo "Done. Vajra has been removed from this machine."
echo "Agents installed on machines are not removed by this script (see README.md)."
