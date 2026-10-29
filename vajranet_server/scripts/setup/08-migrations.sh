#!/usr/bin/env bash
# Step 8: apply the extra SQL (columns, indexes, triggers) to the fleet database.
#
# The tables themselves already exist by now: the C++ server created the telemetry tables
# (step 3) and the backend created its own on first start (in development mode TypeORM
# synchronize does that). The files below add what those do not, such as the trigger behind
# live alert updates and query-speed indexes. They are safe to re-run. Order matters: the
# alerts trigger needs the alerts columns from 002, so keep the order in
# backend/migrations/fleet-extras.list.
# The app database (vajra_db) needs nothing here.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars DB_PASSWORD

# The backend's own fleet-database setup (nodes group columns and the tables the device pages need).
# In development mode the backend does not run it by itself, and without it /api/nodes/list fails.
( cd "$REPO_ROOT/backend" && set -a && . ./.env && set +a && node dist/orm/config/ormconfig-setup.js --fleet ) \
  || handle_error "Fleet database setup failed (see above)"

export PGHOST=localhost PGUSER=vajra PGDATABASE=fleet PGPASSWORD="$DB_PASSWORD"
bash "$REPO_ROOT/backend/migrations/apply-fleet-extras.sh" "$REPO_ROOT/backend" \
  || handle_error "Some fleet SQL files failed (fix the cause, then re-run: scripts/service.sh setup 08)"

# The C++ server prepares its SQL statements at start-up and this step (and the backend's first
# start) changed the tables they use, so restart it and the engine to avoid enrollment errors
# ("cached plan must not change result type").
sudo systemctl try-restart vajra_server.service vajra_engine_v2.service 2>/dev/null || true

log_step "Fleet database migrations applied"
