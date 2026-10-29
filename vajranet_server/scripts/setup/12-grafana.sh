#!/usr/bin/env bash
# Step 12 (optional): install Grafana with the Vajra dashboards. Skipped unless INSTALL_GRAFANA=1.
# Grafana is served by nginx under /grafana/ and signs users in through the Vajra login.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "${INSTALL_GRAFANA:-0}" != 1 ]; then
  echo "INSTALL_GRAFANA is not 1, skipping Grafana."
  exit 0
fi
require_vars DB_PASSWORD FULL_DOMAIN

# grafana/setup.sh needs a superuser database account (it creates roles and changes
# PostgreSQL settings). 'vajra' gets that right only while this step runs.
sudo -u postgres psql -qc "ALTER ROLE vajra SUPERUSER;"
trap 'sudo -u postgres psql -qc "ALTER ROLE vajra NOSUPERUSER;"' EXIT

"$REPO_ROOT/grafana/setup.sh" --domain "$FULL_DOMAIN" --scheme http \
  --db-host localhost --db-port 5432 --db-user vajra --db-password "$DB_PASSWORD" \
  --app-db-name vajra_db --fleet-db-name fleet || handle_error "Grafana setup failed"

sudo systemctl restart vajra-backend   # the Grafana setup may restart PostgreSQL

log_step "Grafana installed"
