#!/usr/bin/env bash
# Applies the files listed in fleet-extras.list to the fleet database, in order.
# Used by scripts/setup/08-migrations.sh and by the db-extras service in docker-compose.yml.
#
# Connection settings come from the standard psql variables (PGHOST, PGUSER, PGPASSWORD,
# PGDATABASE). Usage: apply-fleet-extras.sh [backend-dir]   (default: the folder above this one)
#
# Each file runs on its own, not in one transaction, because some use CREATE INDEX CONCURRENTLY.
# A file that refers to a table or column that does not exist is skipped, not treated as an
# error: some tables only exist when optional components are installed (for example the
# vulnerability tables), and some files only migrate data from older versions.
set -uo pipefail

BACKEND_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LIST="$BACKEND_DIR/migrations/fleet-extras.list"

failed=0
while IFS= read -r f; do
  echo "Applying $f"
  if out="$(psql -v ON_ERROR_STOP=1 -q -f "$BACKEND_DIR/$f" 2>&1 >/dev/null)"; then
    continue
  elif grep -q "does not exist" <<<"$out"; then
    echo "  skipped (needs something that is not installed): $(grep -m1 'does not exist' <<<"$out" | sed 's/^.*ERROR:  //')"
  else
    echo "  FAILED: $f"; echo "$out" | sed 's/^/    /'; failed=1
  fi
done < <(grep -vE '^\s*(#|$)' "$LIST")

if [ "$failed" -ne 0 ]; then echo "Some fleet SQL files failed."; exit 1; fi
echo "Fleet SQL applied."
