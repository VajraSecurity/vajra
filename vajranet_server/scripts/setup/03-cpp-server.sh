#!/usr/bin/env bash
# Step 3: build and start the Vajra C++ server (agent ingest on port 1234) together with
# its Kafka broker, fleet database and detection engine, using vajra_server's own vajra.sh.
# Expects the vajra_server repo next to this one, or set VAJRA_SERVER_DIR / VAJRA_SERVER_REPO_URL.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars DB_PASSWORD FULL_DOMAIN IP_ADDRESS
VAJRA_SERVER_DIR="${VAJRA_SERVER_DIR:-$REPO_ROOT/../vajra_server}"
ensure_repo "$VAJRA_SERVER_DIR" "${VAJRA_SERVER_REPO_URL:-}" "vajra_server"
VAJRA_SERVER_DIR="$(cd "$VAJRA_SERVER_DIR" && pwd)"

# Passphrase of the server's own certificate authority. Generated once and kept next
# to the certificates; it is only needed to issue new certificates later.
mkdir -p "$VAJRA_SERVER_DIR/ssl"
PASS_FILE="$VAJRA_SERVER_DIR/ssl/ca_passphrase.txt"
[ -f "$PASS_FILE" ] || { umask 077; openssl rand -hex 16 > "$PASS_FILE"; }

# A plain IP address is passed as the certificate host by vajra.sh itself, so only a name needs -d.
domain_args=(-d "$FULL_DOMAIN")
[[ "$FULL_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && domain_args=()

( cd "$VAJRA_SERVER_DIR" \
  && DB_PASS="$DB_PASSWORD" SSL_PASSWORD="$(cat "$PASS_FILE")" IP_ADDRESS="$IP_ADDRESS" \
     ./vajra.sh deploy "${domain_args[@]}" -y --with-rule-engine ) \
  || handle_error "vajra_server deploy failed"

[ -f "$VAJRA_SERVER_DIR/ssl/myCA.pem" ] || handle_error "Certificate authority file ssl/myCA.pem was not created"
[ -f "$VAJRA_SERVER_DIR/enrollment_secret.txt" ] || handle_error "enrollment_secret.txt was not created"

log_step "Vajra C++ server running (agents enroll on port 1234)"
