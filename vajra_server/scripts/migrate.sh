#!/bin/bash
#
# Vajra migration runner
#
# Applies sql/migrations/*.sql in filename order, exactly once each.
# Tracks applied versions in a schema_migrations table; re-running is a no-op.
# Each migration runs inside a single transaction and the runner stops on the
# first error (already-applied migrations stay applied).
#
# Non-transactional migrations: statements like CREATE INDEX CONCURRENTLY
# cannot run inside a BEGIN/COMMIT block at all (PostgreSQL rejects it). A
# migration file whose FIRST line is exactly:
#   -- migrate:no-transaction
# is run through psql directly in its normal autocommit mode instead (each
# statement in the file commits independently), and the schema_migrations
# bookkeeping row is inserted as a separate statement afterward. Because the
# statements commit one at a time, such files MUST be written so a partial
# failure is safe to re-run (CREATE INDEX CONCURRENTLY IF NOT EXISTS, guarded
# INSERTs, etc.) — a re-run picks up wherever it stopped.
#
# Connection comes from the standard libpq environment variables. The
# non-secret parameters carry sensible defaults matching deploy.sh; the
# password is NEVER defaulted and must be supplied explicitly (env var, or an
# interactive prompt when a human is at the terminal):
#   PGHOST      (default: localhost)
#   PGPORT      (default: 5432)
#   PGUSER      (default: vajra)
#   PGDATABASE  (default: fleet)
#   PGPASSWORD  (REQUIRED — no default; set it in the environment)
#
# Usage:
#   PGPASSWORD=... ./scripts/migrate.sh            # apply pending migrations
#   PGPASSWORD=... ./scripts/migrate.sh --status   # list applied/pending
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATIONS_DIR="${SCRIPT_DIR}/../sql/migrations"

export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-vajra}"
export PGDATABASE="${PGDATABASE:-fleet}"

# No hardcoded password default — shipping one bakes a credential into the
# release tarball and becomes a wrong-credential trap after rotation. Require
# PGPASSWORD explicitly; prompt only when a human is at the terminal.
if [[ -z "${PGPASSWORD:-}" ]]; then
    if [[ -t 0 ]]; then
        read -r -s -p "PGPASSWORD for ${PGUSER}@${PGHOST}:${PGPORT}/${PGDATABASE}: " PGPASSWORD
        echo >&2
        if [[ -z "$PGPASSWORD" ]]; then
            echo "ERROR: PGPASSWORD is required (no password entered)" >&2
            exit 1
        fi
    else
        echo "ERROR: PGPASSWORD is not set — set PGPASSWORD before running $0" >&2
        exit 1
    fi
fi
export PGPASSWORD

STATUS_ONLY=0
if [[ "${1:-}" == "--status" ]]; then
    STATUS_ONLY=1
elif [[ -n "${1:-}" ]]; then
    echo "Usage: $0 [--status]" >&2
    exit 2
fi

command -v psql >/dev/null 2>&1 || { echo "ERROR: psql not found in PATH" >&2; exit 1; }

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    echo "ERROR: migrations directory not found: $MIGRATIONS_DIR" >&2
    exit 1
fi

PSQL=(psql --no-psqlrc --quiet -v ON_ERROR_STOP=1)

# Ensure the tracking table exists (safe to run repeatedly).
"${PSQL[@]}" -c "CREATE TABLE IF NOT EXISTS schema_migrations (
    version    text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);" >/dev/null

applied=0
pending=0
shopt -s nullglob
files=("$MIGRATIONS_DIR"/*.sql)
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No migration files in $MIGRATIONS_DIR — nothing to do."
    exit 0
fi

# Filenames sort lexicographically == application order (0001_, 0002_, ...).
IFS=$'\n' files=($(printf '%s\n' "${files[@]}" | sort)); unset IFS

for file in "${files[@]}"; do
    version="$(basename "$file" .sql)"

    already="$("${PSQL[@]}" -tA -c \
        "SELECT 1 FROM schema_migrations WHERE version = '$version';")"

    if [[ "$already" == "1" ]]; then
        echo "  [applied] $version"
        continue
    fi

    if [[ $STATUS_ONLY -eq 1 ]]; then
        echo "  [pending] $version"
        pending=$((pending + 1))
        continue
    fi

    echo "  [running] $version"
    if head -n 1 "$file" | grep -qx -- '-- migrate:no-transaction'; then
        # Autocommit mode: required for CREATE INDEX CONCURRENTLY and similar
        # statements that PostgreSQL refuses to run inside a transaction
        # block. Each statement in the file commits on its own.
        "${PSQL[@]}" -f "$file" >/dev/null || {
            echo "ERROR: migration $version failed (no-transaction mode) — statements before the failure may already be committed; the file must be safe to re-run (IF NOT EXISTS / guarded), fix and re-run" >&2
            exit 1
        }
        "${PSQL[@]}" -c "INSERT INTO schema_migrations (version) VALUES ('$version');" >/dev/null || {
            echo "ERROR: migration $version ran but recording it in schema_migrations failed — it will be re-attempted on the next run" >&2
            exit 1
        }
    else
        # Single transaction: the migration body and the schema_migrations
        # insert commit together, or not at all.
        {
            echo "BEGIN;"
            cat "$file"
            echo ";"
            echo "INSERT INTO schema_migrations (version) VALUES ('$version');"
            echo "COMMIT;"
        } | "${PSQL[@]}" -f - >/dev/null || {
            echo "ERROR: migration $version failed — aborting (nothing from it was committed)" >&2
            exit 1
        }
    fi
    echo "  [done]    $version"
    applied=$((applied + 1))
done

if [[ $STATUS_ONLY -eq 1 ]]; then
    echo "Status: $pending pending migration(s)."
else
    echo "Migrations complete: $applied newly applied."
fi
