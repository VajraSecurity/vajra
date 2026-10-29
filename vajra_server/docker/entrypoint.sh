#!/usr/bin/env bash
# Container entrypoint for the vajra/app image (docker/Dockerfile).
# Selects vajra_server or vajra_engine_v2 via VAJRA_SERVICE, renders
# config.json from config.template.json using the environment (mirrors
# vajra.sh's patch_config()), generates SSL material on first boot for the
# server (mirrors vajra.sh's gen_ssl()), then execs the chosen binary.
set -euo pipefail

: "${VAJRA_SERVICE:?set VAJRA_SERVICE=server|engine}"
: "${SERVER_HOSTNAME:=vajra-server}"
: "${DB_HOST:=postgres}"
: "${DB_PORT:=5432}"
: "${DB_USER:=vajra}"
: "${DB_PASS:?DB_PASS is required (postgres role password)}"
: "${DB_NAME:=fleet}"
: "${KAFKA_BOOTSTRAP:=kafka:9092}"
: "${ENROLLMENT_SECRET:=}"

case "$VAJRA_SERVICE" in
    server)
        : "${SSL_PASSWORD:?SSL_PASSWORD is required (CA key passphrase used to mint the server cert)}"
        /app/gen-ssl.sh
        ;;
    engine)
        # vajra_engine_v2 only opens fleet_server.db_configuration (see
        # engine_v2/src/main.cpp) -- it never touches server_configuration's
        # cert paths, so it doesn't need SSL material of its own.
        ;;
    *)
        echo "entrypoint.sh: unknown VAJRA_SERVICE '${VAJRA_SERVICE}' (expected 'server' or 'engine')" >&2
        exit 1
        ;;
esac

SERVER_HOSTNAME="$SERVER_HOSTNAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" \
DB_USER="$DB_USER" DB_PASS="$DB_PASS" DB_NAME="$DB_NAME" \
KAFKA_BOOTSTRAP="$KAFKA_BOOTSTRAP" ENROLLMENT_SECRET="$ENROLLMENT_SECRET" \
    python3 /app/render-config.py /app/config.template.json /app/bin/config.json

# Both binaries default to "config.json" relative to their cwd (WORKDIR
# /app/bin, set in the Dockerfile) -- vajra_server doesn't even accept an
# argv override, so this relies on that cwd rather than passing a path.
case "$VAJRA_SERVICE" in
    server) exec /app/bin/vajra_server ;;
    engine) exec /app/bin/vajra_engine_v2 /app/bin/config.json ;;
esac
