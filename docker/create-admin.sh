#!/usr/bin/env bash
# Creates the first admin account for the Docker setup and prints its one-time password.
#   ./docker/create-admin.sh [email]
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
EMAIL="${1:-admin@vajra.local}"
PASSWORD="$(openssl rand -hex 8)Aa1!"
payload="$(printf '{"name":"Vajra Admin","email":"%s","mobile":"9999999999","company":"Vajra","address":"Local","password":"%s","passwordConfirm":"%s","role":"Super Administrator","forcePasswordChange":true}' "$EMAIL" "$PASSWORD" "$PASSWORD")"
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
code="$(curl -s -o "$out" -w '%{http_code}' -X POST "http://${PUBLIC_HOST}:${API_PORT:-4000}/api/auth/user_register" \
  -H 'Content-Type: application/json' -d "$payload")"
if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
  echo "Admin created: $EMAIL"
  echo "One-time password: $PASSWORD   (change it at first login)"
  echo "Web console: http://${PUBLIC_HOST}:${WEB_PORT:-8080}"
else
  cat "$out"; echo; echo "Registration failed (HTTP $code). If an admin already exists, sign in instead." >&2; exit 1
fi
