#!/bin/bash
# Local/dev Grafana setup: installs Grafana, copies provisioning as-is (no
# templating — matches the default 'fleet' / 'vajra_db' / 'grafana_local_password'
# placeholders already in grafana/provisioning/datasources/vajra.yml), and
# actually provisions the grafana_reader role + materialized views against a
# local Postgres. For a real deployment use grafana/setup.sh instead, which
# generates a real password and points at your actual DB names.
set -e

echo "Starting local Grafana setup..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# 1. Install Grafana (skipped if already installed — see the matching comment
# in grafana/setup.sh about the upstream postinst plugins-bundled bug)
if dpkg-query -W -f='${Status}' grafana 2>/dev/null | grep -q "install ok installed"; then
    echo "Grafana is already installed — skipping package install."
else
    sudo apt-get install -y apt-transport-https software-properties-common
    sudo mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt-get update
    sudo apt-get install -y grafana
fi

# 2. Copy configuration as-is (local dev only — matches the checked-in
# placeholder database/password values, no sed substitution)
echo "Copying Grafana configuration and provisioning files..."
sudo cp grafana/grafana.ini /etc/grafana/grafana.ini
sudo mkdir -p /etc/grafana/provisioning/datasources
sudo mkdir -p /etc/grafana/provisioning/dashboards/json
sudo mkdir -p /etc/grafana/provisioning/alerting
sudo cp grafana/provisioning/datasources/vajra.yml /etc/grafana/provisioning/datasources/
sudo cp grafana/provisioning/dashboards/dashboard.yml /etc/grafana/provisioning/dashboards/
# Clear first, matching deploy_dashboards() in grafana/setup.sh: a plain `cp`
# only overlays files still present in the source, so a dashboard deleted from
# the repo — or one added straight onto the box — is left behind and keeps
# loading. That is how a deployment ends up serving panels nobody can find in
# version control.
sudo find /etc/grafana/provisioning/dashboards/json -mindepth 1 -name '*.json' -delete
sudo cp grafana/provisioning/dashboards/json/*.json /etc/grafana/provisioning/dashboards/json/
sudo cp grafana/provisioning/alerting/alerting.yml /etc/grafana/provisioning/alerting/ 2>/dev/null || true

# Fix permissions (all four provisioning subdirectories need the group execute
# bit or grafana-server, running as group 'grafana', can't traverse into them
# — alerting/ was previously missing from this list, so the shipped alert
# rule silently failed to load)
sudo chown -R root:grafana /etc/grafana
sudo chmod -R 640 /etc/grafana/grafana.ini /etc/grafana/provisioning/*
sudo chmod 750 /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards \
    /etc/grafana/provisioning/dashboards/json /etc/grafana/provisioning/alerting

# 3. Create database user and views — actually run, not left commented out.
# Assumes a local Postgres reachable via 'sudo -u postgres psql' with 'fleet'
# already created; adjust connection params here if your local setup differs.
echo "Running SQL migrations for Grafana user and views..."
sudo -u postgres psql -f backend/src/migrations/create_grafana_views.sql -d fleet \
    || echo "Warning: could not run create_grafana_views.sql — ensure the 'fleet' database exists and is reachable as the postgres superuser."

GRAFANA_ROLE_SQL="
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'grafana_reader') THEN
    CREATE USER grafana_reader WITH PASSWORD 'grafana_local_password';
  END IF;
END \$\$;
ALTER ROLE grafana_reader BYPASSRLS;
GRANT CONNECT ON DATABASE fleet TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
"
sudo -u postgres psql -d fleet -c "$GRAFANA_ROLE_SQL" \
    || echo "Warning: could not provision grafana_reader on 'fleet' — dashboards will fail to load data until this is run manually."

# grafana_reader only needs CONNECT on the app DB — the postgres_fdw bridge
# (setupGrafanaGroupScoping in ormconfig-setup.ts) exposes just the narrow
# grafana_user_scoping view, never the raw vajra_users table.
sudo -u postgres psql -d vajra_db -c "GRANT CONNECT ON DATABASE vajra_db TO grafana_reader;" \
    || echo "Warning: could not grant CONNECT on vajra_db to grafana_reader — run backend's db:setup and db:setup:fleet npm scripts, then re-run this."

# 4. Enable and start Grafana
echo "Starting Grafana service..."
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl restart grafana-server

echo "Grafana setup complete!"
