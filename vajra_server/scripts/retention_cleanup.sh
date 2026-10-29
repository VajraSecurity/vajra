#!/bin/bash
#
# Vajra event retention cleanup
#
# Deletes rows older than a configured retention window from the
# high-volume event/log/state tables, in small batches, so a run never
# holds a lock that blocks live osquery ingestion for long. Intended to be
# run periodically (cron / systemd timer) — see docs/RETENTION.md.
#
# Prerequisite: sql/migrations/0002_event_retention.sql must be applied
# first (./scripts/migrate.sh). It adds the unixtime/created_at indexes
# this script's batched deletes rely on — without them, every batch does a
# sequential scan of the whole table instead of an index range scan.
#
# This script is independent of the pre-existing GET /settings/data_retention
# mechanism in server/api/settings.cpp — see docs/RETENTION.md for why (that
# endpoint is unauthenticated-GET-triggered, generates a script embedding the
# DB password in plaintext, and its default seed value of "0 days" was found
# to be a delete-everything landmine, now repaired by migration 0002). Do not
# run both mechanisms against the same tables at once; pick one. This script
# is the recommended one.
#
# Connection: standard libpq env vars, same defaults as scripts/migrate.sh.
#   PGHOST      (default: localhost)
#   PGPORT      (default: 5432)
#   PGUSER      (default: vajra)
#   PGDATABASE  (default: fleet)
#   PGPASSWORD  (REQUIRED — no default; set it in the environment)
#
# Retention windows, all overridable via environment variable:
#   RETENTION_DAYS_DEFAULT  (default 90)  raw process/socket/file/dns/ssl/
#                                          http/registry events, query and
#                                          snapshot results, inventory
#                                          differential/state tables
#   RETENTION_DAYS_ALERTS   (default 180) alerts, sw_alerts, clamav_alerts
#                                          (security-relevant — kept longer)
#   RETENTION_DAYS_DLQ      (default 30)  dead_letter_queue (operational
#                                          error backlog, not investigative
#                                          data — short retention is fine)
#
# Batching (tune down further on a very hot production system if needed):
#   RETENTION_BATCH_SIZE       (default 5000)  rows deleted per statement
#   RETENTION_BATCH_SLEEP_SECS (default 0.2)   pause between batches, to
#                                               leave headroom for live
#                                               ingestion on the same table
#
# Usage:
#   PGPASSWORD=... ./scripts/retention_cleanup.sh              # run cleanup
#   PGPASSWORD=... ./scripts/retention_cleanup.sh --dry-run     # report row
#                                                                 counts only,
#                                                                 delete nothing
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-vajra}"
export PGDATABASE="${PGDATABASE:-fleet}"

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

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
elif [[ -n "${1:-}" ]]; then
    echo "Usage: $0 [--dry-run]" >&2
    exit 2
fi

RETENTION_DAYS_DEFAULT="${RETENTION_DAYS_DEFAULT:-90}"
RETENTION_DAYS_ALERTS="${RETENTION_DAYS_ALERTS:-180}"
RETENTION_DAYS_DLQ="${RETENTION_DAYS_DLQ:-30}"
RETENTION_BATCH_SIZE="${RETENTION_BATCH_SIZE:-5000}"
RETENTION_BATCH_SLEEP_SECS="${RETENTION_BATCH_SLEEP_SECS:-0.2}"

validate_positive_int() {
    local name="$1" value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]]; then
        echo "ERROR: $name must be a positive integer (got '$value')" >&2
        exit 1
    fi
}
validate_positive_int RETENTION_DAYS_DEFAULT "$RETENTION_DAYS_DEFAULT"
validate_positive_int RETENTION_DAYS_ALERTS "$RETENTION_DAYS_ALERTS"
validate_positive_int RETENTION_DAYS_DLQ "$RETENTION_DAYS_DLQ"
validate_positive_int RETENTION_BATCH_SIZE "$RETENTION_BATCH_SIZE"
if ! [[ "$RETENTION_BATCH_SLEEP_SECS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "ERROR: RETENTION_BATCH_SLEEP_SECS must be a non-negative number (got '$RETENTION_BATCH_SLEEP_SECS')" >&2
    exit 1
fi

command -v psql >/dev/null 2>&1 || { echo "ERROR: psql not found in PATH" >&2; exit 1; }

PSQL=(psql --no-psqlrc -v ON_ERROR_STOP=1)

NOW_EPOCH=$(date +%s)
CUTOFF_DEFAULT_EPOCH=$((NOW_EPOCH - RETENTION_DAYS_DEFAULT * 86400))
CUTOFF_ALERTS_EPOCH=$((NOW_EPOCH - RETENTION_DAYS_ALERTS * 86400))

# Epoch-seconds tables (column: unixtime bigint). Tier 1 + Tier 2 + Tier 3
# from sql/migrations/0002_event_retention.sql, at RETENTION_DAYS_DEFAULT.
DEFAULT_EPOCH_TABLES=(
    process_events socket_events user_events file_events
    bpf_process_events bpf_socket_events bpf_file_events
    win_process_events win_socket_events win_file_events
    win_dns_events win_dns_response_events win_ssl_events win_http_events
    win_registry_events windows_eventlog win_event_log_data
    query_result snapshot_result
    process_open_pipes process_open_files logged_in_users suid_bin
    process_open_sockets cpu_time memory_info interface_addresses
    chrome_extensions file wmi_cli_event_consumers
)

# Epoch-seconds tables kept longer (security-relevant alerts).
ALERTS_EPOCH_TABLES=(alerts sw_alerts)

# Real timestamp columns (column: created_at timestamptz/timestamp).
ALERTS_TS_TABLES=(clamav_alerts)
DLQ_TS_TABLES=(dead_letter_queue)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Reports (dry-run) or deletes (real run) rows older than $3 from
# "$1"."$2" in batches of RETENTION_BATCH_SIZE, using ctid so each batch
# hits the index on $2 instead of re-scanning already-checked rows.
process_table() {
    local table="$1" column="$2" cutoff_expr="$3"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        local count
        count=$("${PSQL[@]}" -tA -c \
            "SELECT count(*) FROM \"${table}\" WHERE ${column} < ${cutoff_expr};") || {
            echo "ERROR: dry-run count failed on ${table}" >&2
            return 1
        }
        log "  ${table}: ${count} row(s) would be deleted"
        return 0
    fi

    local total=0
    while true; do
        local n
        n=$("${PSQL[@]}" -tA -c \
            "WITH batch AS (DELETE FROM \"${table}\" WHERE ctid IN (SELECT ctid FROM \"${table}\" WHERE ${column} < ${cutoff_expr} LIMIT ${RETENTION_BATCH_SIZE}) RETURNING 1) SELECT count(*) FROM batch;") || {
            echo "ERROR: batch delete failed on ${table} (partial deletes from earlier batches, if any, are already committed — safe to re-run)" >&2
            return 1
        }
        total=$((total + n))
        if [[ "$n" -eq 0 ]]; then
            break
        fi
        sleep "$RETENTION_BATCH_SLEEP_SECS"
    done
    log "  ${table}: deleted ${total} row(s)"
}

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Dry run — no rows will be deleted."
fi
log "Retention windows: default=${RETENTION_DAYS_DEFAULT}d, alerts=${RETENTION_DAYS_ALERTS}d, dlq=${RETENTION_DAYS_DLQ}d"

log "Default-window tables (unixtime < ${CUTOFF_DEFAULT_EPOCH}):"
for t in "${DEFAULT_EPOCH_TABLES[@]}"; do
    process_table "$t" "unixtime" "$CUTOFF_DEFAULT_EPOCH"
done

log "Alert tables, epoch column (unixtime < ${CUTOFF_ALERTS_EPOCH}):"
for t in "${ALERTS_EPOCH_TABLES[@]}"; do
    process_table "$t" "unixtime" "$CUTOFF_ALERTS_EPOCH"
done

log "Alert tables, timestamp column (created_at older than ${RETENTION_DAYS_ALERTS}d):"
for t in "${ALERTS_TS_TABLES[@]}"; do
    process_table "$t" "created_at" "(now() - interval '${RETENTION_DAYS_ALERTS} days')"
done

log "Dead-letter queue (created_at older than ${RETENTION_DAYS_DLQ}d):"
for t in "${DLQ_TS_TABLES[@]}"; do
    process_table "$t" "created_at" "(now() - interval '${RETENTION_DAYS_DLQ} days')"
done

log "Retention cleanup complete."
