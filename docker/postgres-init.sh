#!/bin/bash
# Runs once, the first time the postgres container starts with an empty data directory.
# The container's default database (fleet) is created by the image; this adds the web
# console's own database next to it.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -c "CREATE DATABASE vajra_db OWNER $POSTGRES_USER"
