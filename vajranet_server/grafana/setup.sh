#!/bin/bash
# One-shot Grafana install and provisioning for a production/on-prem host.
#
# This is the single entry point for the whole flow: package install, Postgres
# role/view provisioning, config and dashboard deployment. Dashboards are always
# read from this repo's grafana/provisioning/dashboards/json/, never by bare
# filename relative to the current directory, so a stale or unscoped dashboard
# elsewhere on the box can never be deployed by accident.
set -e

usage() {
    cat <<'USAGE'
Usage: grafana/setup.sh [-d|--domain DOMAIN] [--scheme http|https] [--dashboards-only]
                         [--db-host HOST] [--db-port PORT] [--db-user USER]
                         [--db-password PASSWORD]
                         [--app-db-name NAME] [--fleet-db-name NAME]

  -d, --domain DOMAIN     Public domain for Grafana's root_url (default: localhost)
  --scheme http|https     Scheme for Grafana's root_url (default: https). Set to
                          http for a plain-HTTP/on-prem deployment with no TLS
                          anywhere in the chain — leaving this at https when
                          nothing serves 443 makes nginx's /grafana/ link
                          301-redirect to a URL the deployment can never answer.
  --dashboards-only       Only (re)deploy dashboard JSON + restart Grafana; skips
                          package install, DB role/view provisioning, and config copy.
                          Use this after editing a dashboard JSON file.
  --db-host HOST          Postgres host for both the app and fleet databases
  --db-port PORT          Postgres port for both databases
  --db-user USER          Postgres user for both databases (default: vajra;
                          must already be a superuser — role creation,
                          ALTER SYSTEM, etc. need it)
  --db-password PASSWORD  Password for --db-user
  --app-db-name NAME      App database name (default: vajra_db)
  --fleet-db-name NAME    Fleet database name (default: fleet_prod)

Without these flags, connection details are read from backend/.env as before
(PG_HOST, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, and the _1-suffixed
fleet equivalents). Flags take precedence when given, and are written back
into backend/.env so the backend app itself picks up the same values —
passing them once is enough to configure both Grafana and the app from a
freshly-copied backend/.env.example with no manual editing.
USAGE
}

DOMAIN="localhost"
SCHEME="https"
DASHBOARDS_ONLY=false
FLAG_DB_HOST=""
FLAG_DB_PORT=""
FLAG_DB_USER=""
FLAG_DB_PASSWORD=""
FLAG_APP_DB_NAME=""
FLAG_FLEET_DB_NAME=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift ;;
        --scheme)
            SCHEME="$2"
            if [[ "$SCHEME" != "http" && "$SCHEME" != "https" ]]; then
                echo "Invalid --scheme '$SCHEME' (must be http or https)"; exit 1
            fi
            shift ;;
        --dashboards-only) DASHBOARDS_ONLY=true ;;
        --db-host) FLAG_DB_HOST="$2"; shift ;;
        --db-port) FLAG_DB_PORT="$2"; shift ;;
        --db-user) FLAG_DB_USER="$2"; shift ;;
        --db-password) FLAG_DB_PASSWORD="$2"; shift ;;
        --app-db-name) FLAG_APP_DB_NAME="$2"; shift ;;
        --fleet-db-name) FLAG_FLEET_DB_NAME="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown parameter passed: $1"; usage; exit 1 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Single source of truth for what gets deployed: whatever JSON files live in
# grafana/provisioning/dashboards/json/. No separate copy list to drift out of
# sync, and no ambiguity about which directory a dashboard is read from.
deploy_dashboards() {
    echo "Deploying dashboards from grafana/provisioning/dashboards/json/..."
    sudo mkdir -p /etc/grafana/provisioning/dashboards/json
    # Clear the deployed directory first. A plain `cp` only overlays files that
    # still exist in the source, so a dashboard removed from
    # grafana/provisioning/dashboards/json/ would be left behind and keep
    # loading in Grafana indefinitely.
    sudo find /etc/grafana/provisioning/dashboards/json -mindepth 1 -name '*.json' -delete
    sudo cp grafana/provisioning/dashboards/json/*.json /etc/grafana/provisioning/dashboards/json/
    sudo chown -R root:grafana /etc/grafana/provisioning/dashboards
    # `find -exec`, not a `*.json` glob. The invoking user is not in the
    # `grafana` group, so after the chown above they can no longer list this
    # directory to expand a glob, and the shell expands `*.json` before sudo
    # runs — it becomes the literal string "*.json" and chmod fails with "No
    # such file or directory". find's traversal happens inside the sudo'd
    # process, which can list the directory.
    sudo find /etc/grafana/provisioning/dashboards/json -maxdepth 1 -name '*.json' -exec chmod 640 {} +
    sudo chmod 750 /etc/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards/json
    # daemon-reload before restart: if the unit is in a "failed to load" state
    # after a prior crash, systemd refuses a bare `restart` with "Device or
    # resource busy" until reloaded. Needed here as well as later in the script,
    # because --dashboards-only calls this function standalone.
    sudo systemctl daemon-reload
    sudo systemctl restart grafana-server
    echo "Dashboards deployed."
}

if [ "$DASHBOARDS_ONLY" = true ]; then
    deploy_dashboards
    exit 0
fi

echo "Starting Grafana setup..."

if [ "$DOMAIN" != "localhost" ]; then
    echo "Configuring for domain: $DOMAIN"
fi

# 1. Load environment variables
ENV_FILE="backend/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found! Copy backend/.env.example to backend/.env and fill it in first."
    exit 1
fi

export $(grep -v '^#' "$ENV_FILE" | xargs)

# Upsert KEY=VALUE into backend/.env: replaces an existing line for KEY in
# place, appends it otherwise. Used for both flag-provided DB connection details
# and the auto-generated GRAFANA_DB_PASSWORD below, so the backend app reads the
# same values this script used rather than drifting from them.
set_env_var() {
    local key="$1" value="$2" esc
    # Escape '&' (and '\\', '|') in the replacement: '&' would otherwise expand
    # to the whole matched line and silently corrupt a password containing one.
    esc=$(printf '%s' "$value" | sed -e 's/[\\&|]/\\&/g')
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${esc}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

# Flags both override and persist into .env, so passing them once against a
# freshly copied backend/.env.example is enough to configure Grafana and the app
# with no manual editing. They are applied to both the app and fleet connection
# profiles, because in every deployment this script targets both databases live
# on the same Postgres instance behind the same user (see the PG_SUPERUSER_CLI
# comment below). Where that is not the case, pre-populate the _1-suffixed fleet
# variables in .env directly instead of using these flags.
if [ -n "$FLAG_DB_HOST" ]; then
    set_env_var PG_HOST "$FLAG_DB_HOST"; set_env_var PG_HOST1 "$FLAG_DB_HOST"
fi
if [ -n "$FLAG_DB_PORT" ]; then
    set_env_var PG_PORT "$FLAG_DB_PORT"; set_env_var PG_PORT1 "$FLAG_DB_PORT"
fi
if [ -n "$FLAG_DB_USER" ]; then
    set_env_var POSTGRES_USER "$FLAG_DB_USER"; set_env_var POSTGRES_USER1 "$FLAG_DB_USER"
fi
if [ -n "$FLAG_DB_PASSWORD" ]; then
    set_env_var POSTGRES_PASSWORD "$FLAG_DB_PASSWORD"; set_env_var POSTGRES_PASSWORD1 "$FLAG_DB_PASSWORD"
fi
if [ -n "$FLAG_APP_DB_NAME" ]; then
    set_env_var POSTGRES_DB "$FLAG_APP_DB_NAME"
fi
if [ -n "$FLAG_FLEET_DB_NAME" ]; then
    set_env_var POSTGRES_DB1 "$FLAG_FLEET_DB_NAME"
fi
if [ -n "$FLAG_DB_HOST$FLAG_DB_PORT$FLAG_DB_USER$FLAG_DB_PASSWORD$FLAG_APP_DB_NAME$FLAG_FLEET_DB_NAME" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# backend/.env.example ships a non-empty placeholder line
# (GRAFANA_DB_PASSWORD=your_grafana_password_here), so a bare "key present?"
# check always matches it and never generates a real password — every deployment
# made from a freshly-copied .env.example would end up with the same
# publicly-known password on grafana_reader. The placeholder value has to be
# checked too, not just the presence of the key.
if ! grep -q "^GRAFANA_DB_PASSWORD=" "$ENV_FILE" || grep -q "^GRAFANA_DB_PASSWORD=your_grafana_password_here" "$ENV_FILE"; then
    echo "GRAFANA_DB_PASSWORD not set (or still the placeholder) in .env. Generating a secure random password..."
    NEW_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 20)
    set_env_var GRAFANA_DB_PASSWORD "$NEW_PASS"
    export GRAFANA_DB_PASSWORD=$NEW_PASS
    echo "Generated and stored new GRAFANA_DB_PASSWORD in $ENV_FILE"
fi

PG_HOST=${PG_HOST:-localhost}
PG_PORT=${PG_PORT:-5432}
POSTGRES_USER=${POSTGRES_USER:-vajra}
POSTGRES_DB=${POSTGRES_DB:-vajra_db}

PG_HOST1=${PG_HOST1:-localhost}
PG_PORT1=${PG_PORT1:-5432}
POSTGRES_USER1=${POSTGRES_USER1:-vajra}
POSTGRES_DB1=${POSTGRES_DB1:-fleet_prod}

if [ -z "$POSTGRES_PASSWORD" ] || [ -z "$POSTGRES_PASSWORD1" ]; then
    echo "Error: no Postgres password available (POSTGRES_PASSWORD/POSTGRES_PASSWORD1 not in $ENV_FILE and --db-password not given)."
    echo "Pass --db-password, or set POSTGRES_PASSWORD/POSTGRES_PASSWORD1 in $ENV_FILE, and re-run."
    exit 1
fi

# Persist the values resolved above (flag > .env > default) back into .env. A
# bash `${VAR:-default}` fallback exists only for the rest of this process and
# never reaches disk, and a freshly-copied backend/.env.example holds
# POSTGRES_USER=your_db_user — a real but wrong string, not an empty one — so it
# would be used as written and fail rather than falling back. Writing the
# resolved value back means that after one successful run .env holds working
# values.
set_env_var PG_HOST "$PG_HOST"; set_env_var PG_HOST1 "$PG_HOST1"
set_env_var PG_PORT "$PG_PORT"; set_env_var PG_PORT1 "$PG_PORT1"
set_env_var POSTGRES_USER "$POSTGRES_USER"; set_env_var POSTGRES_USER1 "$POSTGRES_USER1"
set_env_var POSTGRES_DB "$POSTGRES_DB"; set_env_var POSTGRES_DB1 "$POSTGRES_DB1"

# Every Postgres-level operation below — role creation, grants, ALTER SYSTEM,
# CREATE EXTENSION — runs as $POSTGRES_USER1 over a normal TCP connection rather
# than via `sudo -u postgres` peer auth. Not every environment this script runs
# in has a local 'postgres' OS user at all (a managed or remote Postgres has
# none), whereas the app's own configured DB user always exists and, in every
# deployment this app runs in, is a superuser. ALTER SYSTEM and role creation
# require superuser regardless of which identity performs them, and a Postgres
# superuser is a superuser over any connection — OS access to the 'postgres'
# account is a differently authenticated path, not a more privileged one.
# `systemctl restart postgresql` further down is the only genuinely OS-level
# action here, and this script already runs under sudo.
PG_SUPERUSER_CLI=(psql -h "$PG_HOST1" -p "$PG_PORT1" -U "$POSTGRES_USER1")
export PGPASSWORD=$POSTGRES_PASSWORD1

# 2. Install Grafana, skipped entirely if dpkg already reports
# "install ok installed". Grafana's Debian postinst does an unconditional
# `mv $GRAFANA_HOME/data/plugins-bundled $DATA_DIR` on every configure pass
# (https://github.com/grafana/grafana/issues/123110), and once
# /var/lib/grafana/plugins-bundled exists from a prior install that mv fails
# with "Directory not empty". So apt-get install runs only when the package is
# actually missing or broken, not on every re-run of this script.
if dpkg-query -W -f='${Status}' grafana 2>/dev/null | grep -q "install ok installed"; then
    echo "Grafana is already installed — skipping package install."
else
    echo "Installing Grafana..."
    sudo apt-get update
    sudo apt-get install -y apt-transport-https software-properties-common wget curl gpg openssl

    sudo mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt-get update
    sudo apt-get install -y grafana
fi

# 3. Install and enable pg_cron so the materialized views the dashboards read
# from refresh on a schedule. All three parts are needed: the apt package, the
# extension itself, and pg_cron in shared_preload_libraries. With any one
# missing, scheduling is skipped silently rather than erroring.
# `systemctl restart postgresql` needs this script's own sudo. If Postgres is
# not running on this same host (a managed or remote instance) the restart below
# simply fails and this whole step is not applicable — have a DBA configure it
# out of band instead.
PG_CRON_READY=false
# Tracked in a variable rather than re-running `dpkg -l | grep` below to check
# the same thing: that dumps and greps the entire installed-package list, and
# whichever branch runs already knows the answer.
CRON_PKG_PRESENT=true
if ! dpkg -l | grep -q "postgresql-.*-cron"; then
    CRON_PKG_PRESENT=false
    PG_MAJOR=$("${PG_SUPERUSER_CLI[@]}" -d postgres -tAc "SHOW server_version_num;" | cut -c1-2)
    PG_CRON_PKG="postgresql-${PG_MAJOR}-cron"
    echo "$PG_CRON_PKG is missing. Installing..."
    if sudo apt-get install -y "$PG_CRON_PKG"; then
        CRON_PKG_PRESENT=true
    else
        echo "Warning: could not install $PG_CRON_PKG automatically. Install it manually and re-run this script to enable materialized-view auto-refresh."
    fi
fi

if [ "$CRON_PKG_PRESENT" = true ]; then
    CURRENT_PRELOAD=$("${PG_SUPERUSER_CLI[@]}" -d postgres -tAc "SHOW shared_preload_libraries;")
    if echo "$CURRENT_PRELOAD" | grep -q "pg_cron"; then
        PG_CRON_READY=true
    else
        echo "Adding pg_cron to shared_preload_libraries (this requires restarting PostgreSQL)..."
        if [ -n "$CURRENT_PRELOAD" ]; then
            NEW_PRELOAD="${CURRENT_PRELOAD},pg_cron"
        else
            NEW_PRELOAD="pg_cron"
        fi
        "${PG_SUPERUSER_CLI[@]}" -d postgres -c "ALTER SYSTEM SET shared_preload_libraries = '$NEW_PRELOAD';"
        echo "Restarting PostgreSQL to apply shared_preload_libraries..."
        if sudo systemctl restart postgresql; then
            PG_CRON_READY=true
        else
            echo "Warning: could not restart PostgreSQL (it may not be running on this host) — pg_cron will not be enabled this run."
        fi
    fi
fi

# 4. Configure PostgreSQL databases, roles, and views
echo "Configuring PostgreSQL databases and views..."

if ! PGPASSWORD=$POSTGRES_PASSWORD psql -h "$PG_HOST" -p "$PG_PORT" -U "$POSTGRES_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'" | grep -q 1; then
    echo "Database $POSTGRES_DB does not exist. Creating..."
    PGPASSWORD=$POSTGRES_PASSWORD createdb -h "$PG_HOST" -p "$PG_PORT" -U "$POSTGRES_USER" "$POSTGRES_DB"
fi

if ! PGPASSWORD=$POSTGRES_PASSWORD1 psql -h "$PG_HOST1" -p "$PG_PORT1" -U "$POSTGRES_USER1" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB1'" | grep -q 1; then
    echo "Database $POSTGRES_DB1 does not exist. Creating..."
    PGPASSWORD=$POSTGRES_PASSWORD1 createdb -h "$PG_HOST1" -p "$PG_PORT1" -U "$POSTGRES_USER1" "$POSTGRES_DB1"
fi

echo "Creating grafana_reader user..."
# grafana_reader is a read-only reporting role. BYPASSRLS is re-granted on every
# run rather than assumed to have been set once, so a role recreated by hand
# still ends up correct. ormconfig-setup.ts's setupGrafanaGroupScoping() grants
# it too on every fleet DB deploy, so the result is the same whichever path runs
# last.
GRAFANA_ROLE_SQL="
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'grafana_reader') THEN
    CREATE USER grafana_reader WITH PASSWORD '$GRAFANA_DB_PASSWORD';
  ELSE
    ALTER USER grafana_reader WITH PASSWORD '$GRAFANA_DB_PASSWORD';
  END IF;
END \$\$;
ALTER ROLE grafana_reader BYPASSRLS;
"
GRANT_FLEET_SQL="
GRANT CONNECT ON DATABASE $POSTGRES_DB1 TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
"
GRANT_APP_SQL="
GRANT CONNECT ON DATABASE $POSTGRES_DB TO grafana_reader;
"

# Role creation is cluster-wide, so this connects to the fleet DB's 'postgres'
# maintenance database via $PG_SUPERUSER_CLI rather than introducing a third
# connection profile for one statement.
"${PG_SUPERUSER_CLI[@]}" -d postgres -c "$GRAFANA_ROLE_SQL"
echo "Granting permissions on $POSTGRES_DB1 (Fleet)..."
"${PG_SUPERUSER_CLI[@]}" -d "$POSTGRES_DB1" -c "$GRANT_FLEET_SQL"
echo "Granting CONNECT on $POSTGRES_DB (App, for the postgres_fdw bridge only)..."
PGPASSWORD=$POSTGRES_PASSWORD psql -h "$PG_HOST" -p "$PG_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$GRANT_APP_SQL"

# The two privileged prerequisites for Grafana group-scoping. Everything else
# setupGrafanaGroupScoping() does (foreign server, user mapping, IMPORT FOREIGN
# SCHEMA, the two predicate functions) the app user can do for itself — but
# CREATE EXTENSION and USAGE on a foreign-data wrapper are superuser-only, and
# that is where it has been failing.
#
# The failure is quiet: setupFleetDatabase() catches it, logs one warning, and
# carries on. The dashboards then load without the predicates resolving, so
# unless someone reads that line the deployment looks fine. Doing this here,
# where a superuser connection already exists, is what makes the app-side
# provisioning able to complete.
#
# This matters beyond reporting: controllers/auth/validateGrafana.ts admits
# Group Admins to /grafana/ on the understanding that every panel filters on
# grafana_group_visible(). Without these two statements that function does not
# exist.
echo "Enabling postgres_fdw on $POSTGRES_DB1 for Grafana group-scoping..."
FDW_PREREQ_SQL="
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
GRANT USAGE ON FOREIGN DATA WRAPPER postgres_fdw TO $POSTGRES_USER1;
"
"${PG_SUPERUSER_CLI[@]}" -d "$POSTGRES_DB1" -c "$FDW_PREREQ_SQL" \
    || echo "Warning: could not enable postgres_fdw on $POSTGRES_DB1. Grafana group-scoping will not provision, and Group Admins must stay out of /grafana/ until it does."

if [ "$PG_CRON_READY" = true ]; then
    # pg_cron enforces a single database for the extension itself: whichever
    # one cron.database_name names, default 'postgres'. That default is left
    # alone here, since other tools on the same instance may depend on it.
    # CREATE EXTENSION pg_cron on $POSTGRES_DB1 fails with "can only create
    # extension in database postgres", so the extension lives in
    # cron.database_name and cron.schedule_in_database() (pg_cron >= 1.4) points
    # a job from that connection at a different database, here $POSTGRES_DB1.
    CRON_DB=$("${PG_SUPERUSER_CLI[@]}" -d postgres -tAc "SHOW cron.database_name;")
    echo "Ensuring pg_cron extension exists on '$CRON_DB' (cron.database_name)..."
    "${PG_SUPERUSER_CLI[@]}" -d "$CRON_DB" -c "CREATE EXTENSION IF NOT EXISTS pg_cron;" \
        && "${PG_SUPERUSER_CLI[@]}" -d "$CRON_DB" -c "
            DO \$\$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'refresh_grafana_views') THEN
                PERFORM cron.schedule_in_database(
                  'refresh_grafana_views',
                  '0 * * * *',
                  'REFRESH MATERIALIZED VIEW CONCURRENTLY mv_host_cve_summary; ' ||
                  'REFRESH MATERIALIZED VIEW mv_software_cve_flat; ' ||
                  'REFRESH MATERIALIZED VIEW mv_cve_detection_trend; ' ||
                  'REFRESH MATERIALIZED VIEW mv_compliance_trend; ' ||
                  'REFRESH MATERIALIZED VIEW mv_alert_mitre_summary; ' ||
                  'REFRESH MATERIALIZED VIEW mv_patch_gap; ' ||
                  'REFRESH MATERIALIZED VIEW mv_linux_package_cves;',
                  '$POSTGRES_DB1',
                  '$POSTGRES_USER1'
                );
              END IF;
            END
            \$\$;" \
        || echo "Warning: could not create pg_cron extension/schedule; materialized views will need manual refresh."
fi

# grafana_reader intentionally gets no grant on vajra_db's own tables, only the
# CONNECT above. The FDW bridge (setupGrafanaGroupScoping) exposes just the
# narrow grafana_user_scoping view and the user_group_memberships table, never
# the raw vajra_users table with its password_hash, mfa_secret and
# recovery_codes columns. Do not add `GRANT SELECT ON ALL TABLES` on
# $POSTGRES_DB here.

echo "Running create_grafana_views.sql on $POSTGRES_DB1..."
PGPASSWORD=$POSTGRES_PASSWORD1 psql -h "$PG_HOST1" -p "$PG_PORT1" -U "$POSTGRES_USER1" -d "$POSTGRES_DB1" -f backend/src/migrations/create_grafana_views.sql

# 5. Copy configuration & provisioning
echo "Copying Grafana configuration and provisioning files..."
if [ "$DOMAIN" != "localhost" ] || [ "$SCHEME" != "https" ]; then
    # Rewrite domain and scheme together in one pass. The checked-in file
    # defaults to "https://localhost/grafana/", so substituting only the domain
    # would leave an http-mode deployment advertising an https:// link that
    # 301-redirects to a port nothing is listening on.
    sed "s|root_url = https://localhost/grafana/|root_url = $SCHEME://$DOMAIN/grafana/|" grafana/grafana.ini | sudo tee /etc/grafana/grafana.ini > /dev/null
else
    sudo cp grafana/grafana.ini /etc/grafana/grafana.ini
fi
sudo mkdir -p /etc/grafana/provisioning/datasources
sudo mkdir -p /etc/grafana/provisioning/dashboards/json
sudo mkdir -p /etc/grafana/provisioning/alerting

sed -e "s/database: fleet/database: $POSTGRES_DB1/" \
    -e "s/password: grafana_local_password/password: $GRAFANA_DB_PASSWORD/" \
    -e "s/url: localhost:5432/url: $PG_HOST:$PG_PORT/" \
    grafana/provisioning/datasources/vajra.yml | sudo tee /etc/grafana/provisioning/datasources/vajra.yml > /dev/null

sudo cp grafana/provisioning/dashboards/dashboard.yml /etc/grafana/provisioning/dashboards/
sudo cp grafana/provisioning/alerting/alerting.yml /etc/grafana/provisioning/alerting/ 2>/dev/null || true

# 6. Lock down permissions: owner and group only, never world-readable. The
# datasource YAML embeds GRAFANA_DB_PASSWORD in plaintext, so a blanket 755 here
# would let any local user on the box read a live cross-database credential.
# Directories get 750, since they need the execute bit to be traversable at all,
# and files get 640.
#
# Applied with `find` rather than a fixed list of subdirectories, because
# /etc/grafana/provisioning ships default subdirectories of its own (e.g.
# "plugins", with its sample.yaml) beyond the datasources/dashboards/alerting
# this script manages. A fixed list leaves those at 640 with no execute bit,
# which makes Grafana fail to start on "permission denied" reading its own
# default provisioning files.
#
# Runs before deploy_dashboards, which restarts Grafana — restarting with the
# rest of the tree still misconfigured just fails the same way again.
echo "Setting permissions..."
sudo chown -R root:grafana /etc/grafana
sudo find /etc/grafana -type d -exec chmod 750 {} +
sudo find /etc/grafana -type f -exec chmod 640 {} +

# 7. Deploy dashboards (also restarts Grafana)
deploy_dashboards

# 8. Remove the systemd env override that forces anonymous Editor access
# (GF_AUTH_ANONYMOUS_ENABLED=true / GF_AUTH_ANONYMOUS_ORG_ROLE=Editor), left
# behind on hosts provisioned by an earlier setup script. Environment variables
# win over grafana.ini, so leaving the file in place keeps anonymous Editor
# access live despite [auth.anonymous] enabled = false in grafana.ini. Anonymous
# access and embedding are controlled entirely by grafana/grafana.ini now, so
# the override has no replacement and is simply deleted.
if [ -f /etc/systemd/system/grafana-server.service.d/override.conf ]; then
    echo "Removing stale anonymous-access systemd override..."
    sudo rm -f /etc/systemd/system/grafana-server.service.d/override.conf
    sudo rmdir /etc/systemd/system/grafana-server.service.d 2>/dev/null || true
fi

# 9. Restart Grafana
echo "Restarting Grafana..."
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl restart grafana-server

echo "Grafana setup complete!"
