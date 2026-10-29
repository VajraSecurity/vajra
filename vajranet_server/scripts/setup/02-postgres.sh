#!/usr/bin/env bash
# Step 2: start PostgreSQL and create the 'vajra' role and the 'vajra_db' database.
# (The fleet database is created by the Vajra C++ server, not here.)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars DB_PASSWORD
case "$DB_PASSWORD" in *"'"*) handle_error "DB_PASSWORD must not contain a single quote" ;; esac

sudo systemctl enable --now postgresql || handle_error "PostgreSQL start failed"
psql_admin() { sudo -u postgres psql -tAc "$1"; }

if ! psql_admin "SELECT 1 FROM pg_roles WHERE rolname='vajra'" | grep -q 1; then
  psql_admin "CREATE USER vajra WITH ENCRYPTED PASSWORD '${DB_PASSWORD}';" >/dev/null || handle_error "Failed to create role"
fi
if ! psql_admin "SELECT 1 FROM pg_database WHERE datname='vajra_db'" | grep -q 1; then
  psql_admin "CREATE DATABASE vajra_db OWNER vajra;" >/dev/null || handle_error "Failed to create database"
fi
psql_admin "GRANT ALL PRIVILEGES ON DATABASE vajra_db TO vajra;" >/dev/null || handle_error "Failed to grant privileges"

log_step "PostgreSQL configured"
