#!/usr/bin/env bash
# Step 10: build the Linux and Windows agent download zips with this machine's address,
# certificate and enrollment secret filled in, and put them in the web root so the UI
# can offer them for download. The packaging itself is scripts/package-agents.sh at the
# repository root, shared with docker-compose.yml. The agent folders are not modified.
# Expects linux_agent and windows_agent next to this repo, or set LINUX_AGENT_DIR /
# WINDOWS_AGENT_DIR (and optionally *_REPO_URL).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars FULL_DOMAIN
VAJRA_SERVER_DIR="${VAJRA_SERVER_DIR:-$REPO_ROOT/../vajra_server}"
export LINUX_AGENT_DIR="${LINUX_AGENT_DIR:-$REPO_ROOT/../linux_agent}"
export WINDOWS_AGENT_DIR="${WINDOWS_AGENT_DIR:-$REPO_ROOT/../windows_agent}"
PACKAGER="${PACKAGER:-$REPO_ROOT/../scripts/package-agents.sh}"
command -v zip >/dev/null || handle_error "zip is not installed (sudo apt-get install zip)"
[ -f "$PACKAGER" ] || handle_error "Packager not found at $PACKAGER (set PACKAGER)"

ensure_repo "$LINUX_AGENT_DIR" "${LINUX_AGENT_REPO_URL:-}" "linux_agent"
ensure_repo "$WINDOWS_AGENT_DIR" "${WINDOWS_AGENT_REPO_URL:-}" "windows_agent"

CERT="$VAJRA_SERVER_DIR/ssl/myCA.pem"                 # CA that signed the C++ server certificate
SECRET="$VAJRA_SERVER_DIR/enrollment_secret.txt"      # shared enrollment secret
[ -f "$CERT" ] && [ -f "$SECRET" ] || handle_error "Run step 03 first: missing $CERT or $SECRET"

WEBROOT="${WEBROOT:-/var/www/${FULL_DOMAIN}}"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

PUBLIC_HOST="$FULL_DOMAIN" CERT="$CERT" ENROLLMENT_SECRET_FILE="$SECRET" OUT_DIR="$OUT" \
FLEET_PORT="${FLEET_PORT:-1234}" API_PORT="${API_PORT:-4000}" \
  bash "$PACKAGER" || handle_error "Packaging the agents failed"

sudo mkdir -p "$WEBROOT"
sudo cp "$OUT"/*.zip "$WEBROOT/"
sudo chmod a+r "$WEBROOT"/*.zip

log_step "Agent zips available at http://${FULL_DOMAIN}:${WEB_PORT}/windows_agent.zip and /linux_agent.zip"
