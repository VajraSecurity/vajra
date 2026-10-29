#!/usr/bin/env bash
# Builds linux_agent.zip and windows_agent.zip with this platform's address, CA certificate
# and enrollment secret filled in, so an unzipped agent installs on a real machine and
# reports to this server. The agent folders in the repository are not modified.
#
# Used by docker-compose.yml (service "agents") and by vajranet_server/scripts/setup/10-agents.sh.
#
# Settings (environment):
#   PUBLIC_HOST         address agents use to reach this machine (required, not localhost)
#   ENROLLMENT_SECRET   shared enrollment secret (or ENROLLMENT_SECRET_FILE)
#   CERT                CA certificate the C++ server's certificate was signed with
#   OUT_DIR             where the zips are written
#   FLEET_PORT=1234     C++ server (osquery enroll and logging)
#   API_PORT=4000       Node.js backend (agent WebSocket)
#   LINUX_AGENT_DIR, WINDOWS_AGENT_DIR   default: ../linux_agent and ../windows_agent
#   WAIT_SECONDS=600    how long to wait for CERT to appear (first start generates it)
#   OSQUERY_VERSION=5.12.1   Linux osqueryd to download when linux_agent/common/osqueryd is missing
#   EXTENSION_URL, EXTENSION_SHA256   where to download the Linux Vajra extension (extension.ext)
#                       from, and its SHA-256, when linux_agent/common/extension.ext is missing.
#                       The checksum is required: a file that does not match is not used.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${PUBLIC_HOST:?PUBLIC_HOST is required (the address agents use to reach this machine)}"
: "${CERT:?CERT is required (path to the CA certificate, myCA.pem)}"
: "${OUT_DIR:?OUT_DIR is required}"
FLEET_PORT="${FLEET_PORT:-1234}"
API_PORT="${API_PORT:-4000}"
LINUX_AGENT_DIR="${LINUX_AGENT_DIR:-$HERE/linux_agent}"
WINDOWS_AGENT_DIR="${WINDOWS_AGENT_DIR:-$HERE/windows_agent}"
WAIT_SECONDS="${WAIT_SECONDS:-600}"
OSQUERY_VERSION="${OSQUERY_VERSION:-5.12.1}"

log() { echo "package-agents: $*"; }
die() { echo "package-agents: ERROR: $*" >&2; exit 1; }

case "$PUBLIC_HOST" in
  localhost|127.*|::1) log "WARNING: PUBLIC_HOST=$PUBLIC_HOST only works for an agent on this same machine." ;;
esac
command -v zip >/dev/null || die "zip is not installed (sudo apt-get install zip)"
[ -d "$LINUX_AGENT_DIR" ] && [ -d "$WINDOWS_AGENT_DIR" ] || die "agent folders not found ($LINUX_AGENT_DIR, $WINDOWS_AGENT_DIR)"

# The enrollment secret, from the variable or from a file.
if [ -z "${ENROLLMENT_SECRET:-}" ] && [ -n "${ENROLLMENT_SECRET_FILE:-}" ]; then
  ENROLLMENT_SECRET="$(tr -d '\r\n' < "$ENROLLMENT_SECRET_FILE")"
fi
[ -n "${ENROLLMENT_SECRET:-}" ] || die "ENROLLMENT_SECRET (or ENROLLMENT_SECRET_FILE) is required"

# The C++ server creates its CA on first start; wait for it.
waited=0
until [ -s "$CERT" ]; do
  [ "$waited" -lt "$WAIT_SECONDS" ] || die "$CERT did not appear after ${WAIT_SECONDS}s (is vajra_server running?)"
  [ $((waited % 30)) -ne 0 ] || log "waiting for $CERT ..."
  sleep 5; waited=$((waited + 5))
done

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# package NAME SOURCE_DIR SECRET_FILE_NAME EXTENSION_CONF
package() {
  local name="$1" src="$2" secret_name="$3" ext_conf="$4"
  cp -r "$src" "$WORK/$name"
  printf '%s\n' "$ext_conf" > "$WORK/$name/common/extension.conf"
  sed -i "s|^--tls_hostname=.*|--tls_hostname=${PUBLIC_HOST}:${FLEET_PORT}|" "$WORK/$name"/*/osquery.flags
  cp "$CERT" "$WORK/$name/common/cert.pem"
  printf '%s' "$ENROLLMENT_SECRET" > "$WORK/$name/common/$secret_name"
}

# ---- Windows ---------------------------------------------------------------
package windows_agent "$WINDOWS_AGENT_DIR" enrollment_secret.txt \
"{
  \"tls_hostname\": \"${PUBLIC_HOST}:${API_PORT}\",
  \"websocket_secure\": false
}"

# ---- Linux -----------------------------------------------------------------
package linux_agent "$LINUX_AGENT_DIR" enrollment_secret \
"{
  \"tls_hostname\": \"${PUBLIC_HOST}:${API_PORT}\",
  \"logger_path\" : \"/tmp/vajra_extension\",
  \"websocket_secure\": false
}"

# osqueryd is an upstream binary, so it is downloaded here instead of being stored in git.
if [ ! -f "$WORK/linux_agent/common/osqueryd" ]; then
  arch="$(uname -m)"; [ "$arch" = x86_64 ] || [ "$arch" = aarch64 ] || arch=x86_64
  url="https://pkg.osquery.io/linux/osquery-${OSQUERY_VERSION}_1.linux_${arch}.tar.gz"
  log "downloading osqueryd ${OSQUERY_VERSION} from $url"
  if curl -fsSL "$url" -o "$WORK/osquery.tar.gz" \
     && tar -xzf "$WORK/osquery.tar.gz" -C "$WORK" --wildcards '*/bin/osqueryd' \
     && install -m 755 "$(find "$WORK" -path '*/bin/osqueryd' -type f | head -1)" "$WORK/linux_agent/common/osqueryd"; then
    log "osqueryd added to linux_agent.zip"
  else
    log "WARNING: could not download osqueryd. Put a binary at linux_agent/common/osqueryd and run this again."
  fi
fi
# The Vajra extension is not stored in git either. Use linux_agent/common/extension.ext if it is
# there, otherwise download EXTENSION_URL and check it against EXTENSION_SHA256.
if [ ! -f "$WORK/linux_agent/common/extension.ext" ]; then
  if [ -z "${EXTENSION_URL:-}" ]; then
    log "WARNING: linux_agent/common/extension.ext is missing and EXTENSION_URL is not set; linux_agent.zip will not install."
  elif [ -z "${EXTENSION_SHA256:-}" ]; then
    log "WARNING: EXTENSION_URL is set but EXTENSION_SHA256 is not; refusing to use an unchecked download."
  else
    log "downloading the Vajra extension from $EXTENSION_URL"
    if curl -fsSL "$EXTENSION_URL" -o "$WORK/extension.ext" \
       && [ "$(sha256sum "$WORK/extension.ext" | cut -d' ' -f1)" = "$(echo "$EXTENSION_SHA256" | tr 'A-F' 'a-f')" ]; then
      install -m 755 "$WORK/extension.ext" "$WORK/linux_agent/common/extension.ext"
      log "extension.ext added to linux_agent.zip (checksum verified)"
    else
      log "WARNING: the extension download failed or its SHA-256 does not match; it was not added."
    fi
  fi
fi

for name in windows_agent linux_agent; do
  rm -f "$OUT_DIR/$name.zip"
  ( cd "$WORK" && zip -rq "$OUT_DIR/$name.zip" "$name" ) || die "zipping $name failed"
  log "built $OUT_DIR/$name.zip"
done
chmod a+r "$OUT_DIR"/*.zip
