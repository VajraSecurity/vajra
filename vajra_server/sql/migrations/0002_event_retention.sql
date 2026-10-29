-- migrate:no-transaction
-- 0002_event_retention
--
-- R2-8: retention/partitioning groundwork for the high-volume event tables.
-- See docs/RETENTION.md for the full design write-up and the reasoning
-- behind the table list and the CONCURRENTLY choice below.
--
-- This migration does two things, both required before
-- scripts/retention_cleanup.sh can delete old rows without doing a
-- sequential scan of a multi-hundred-million-row table on every run:
--
--   1. Adds a plain btree index on the time column of every high-volume
--      event/log/state table that does not already have one usable as a
--      leading column for a "WHERE time_col < cutoff" predicate. (A few
--      tables — win_process_events, alerts, snapshot_result — already have
--      a composite (host_identifier, unixtime) index; that index cannot be
--      used for a host-agnostic range delete, so they get a dedicated
--      single-column index too.)
--   2. Seeds a default row in data_retention_settings if the table is
--      empty, so the pre-existing /settings/data_retention_days endpoint
--      (server/api/settings.cpp) stops reporting "No data available" on a
--      fresh install. This does NOT change any retention behavior by
--      itself — scripts/retention_cleanup.sh has its own independent
--      RETENTION_DAYS_* configuration (see docs/RETENTION.md for why).
--
-- Every statement below uses CREATE INDEX CONCURRENTLY, which builds the
-- index without holding a lock that blocks concurrent INSERT/UPDATE/DELETE
-- — required so this migration does not stall live osquery ingestion on
-- tables that may already hold a large number of rows. CONCURRENTLY cannot
-- run inside a transaction block, which is why this file opens with the
-- "-- migrate:no-transaction" marker (see scripts/migrate.sh): each
-- statement here commits independently.
--
-- Idempotency / re-run safety: every CREATE INDEX uses IF NOT EXISTS, so if
-- this file is interrupted partway (or a CONCURRENTLY build is left marked
-- INVALID by a cancelled run — check with the query in docs/RETENTION.md),
-- re-running scripts/migrate.sh picks up from wherever it stopped. An
-- INVALID index left behind by an aborted CONCURRENTLY build must be
-- dropped manually before re-running (IF NOT EXISTS considers it present
-- and will not rebuild it) — see docs/RETENTION.md "Troubleshooting".
--
-- Runtime note: building these indexes on tables that already hold a large
-- backlog can take a while (CONCURRENTLY trades speed for not locking). Run
-- during a quiet period if possible; ingestion keeps working throughout
-- either way.

-- ---------------------------------------------------------------------
-- Tier 1: primary EDR event streams (win_*, bpf_*, legacy process/socket/
-- file/user events, DNS/SSL/HTTP/registry telemetry, Windows event log).
-- ---------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_events_unixtime ON process_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_socket_events_unixtime ON socket_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_events_unixtime ON user_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_events_unixtime ON file_events (unixtime);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_unixtime ON bpf_process_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_socket_events_unixtime ON bpf_socket_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_file_events_unixtime ON bpf_file_events (unixtime);

-- win_process_events already has idx_win_process_events_host_time
-- (host_identifier, unixtime DESC) from sql/02_production_indexes.sql —
-- not usable for a host-agnostic range delete, so add a plain one too.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_unixtime ON win_process_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_socket_events_unixtime ON win_socket_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_file_events_unixtime ON win_file_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_dns_events_unixtime ON win_dns_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_dns_response_events_unixtime ON win_dns_response_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_ssl_events_unixtime ON win_ssl_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_http_events_unixtime ON win_http_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_registry_events_unixtime ON win_registry_events (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_eventlog_unixtime ON windows_eventlog (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_event_log_data_unixtime ON win_event_log_data (unixtime);

-- ---------------------------------------------------------------------
-- Tier 2: generic result tables fed by every /log and /write call
-- (snapshot queries and distributed query results, across all agents).
-- ---------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_query_result_unixtime ON query_result (unixtime);
-- snapshot_result already has idx_snapshot_result_lookup
-- (host_identifier, query_name, unixtime DESC) — same reasoning as above.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_result_unixtime ON snapshot_result (unixtime);

-- ---------------------------------------------------------------------
-- Tier 3: differential/inventory state tables. Lower per-row volume than
-- tier 1, but osquery re-sends the full differential on every scheduled
-- interval across every agent, so these still accumulate without bound.
-- (This is the same table set server/api/settings.cpp's manual_purge/
-- data_retention hardcode, minus tables that turned out not to exist —
-- see docs/RETENTION.md for the reconciliation.)
-- ---------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_open_pipes_unixtime ON process_open_pipes (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_open_files_unixtime ON process_open_files (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_logged_in_users_unixtime ON logged_in_users (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_suid_bin_unixtime ON suid_bin (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_open_sockets_unixtime ON process_open_sockets (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cpu_time_unixtime ON cpu_time (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memory_info_unixtime ON memory_info (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_interface_addresses_unixtime ON interface_addresses (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_chrome_extensions_unixtime ON chrome_extensions (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_unixtime ON file (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_wmi_cli_event_consumers_unixtime ON wmi_cli_event_consumers (unixtime);

-- ---------------------------------------------------------------------
-- Tier 4: security-relevant alert tables (kept longer, see
-- RETENTION_DAYS_ALERTS in scripts/retention_cleanup.sh) and the
-- operational dead-letter table (kept shorter, RETENTION_DAYS_DLQ).
-- ---------------------------------------------------------------------
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_unixtime ON alerts (unixtime);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sw_alerts_unixtime ON sw_alerts (unixtime);
-- clamav_alerts and dead_letter_queue use real timestamptz/timestamp
-- columns (created_at), not the epoch-seconds unixtime convention.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_clamav_alerts_created_at ON clamav_alerts (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dead_letter_queue_created_at ON dead_letter_queue (created_at);

-- ---------------------------------------------------------------------
-- Seed / repair the default retention window so the existing
-- /settings/data_retention_days endpoint has something sane to report.
-- Stored in SECONDS to match the existing column's established convention
-- (server/api/settings.cpp writes days*86400). 90 days: see
-- docs/RETENTION.md "Chosen default" for the reasoning.
--
-- IMPORTANT FINDING (see docs/RETENTION.md): sql/schema.sql:1924 seeds this
-- table with `insert into data_retention_settings (days) values (0);` on
-- every fresh install. days=0 is not "no retention configured" to the
-- rest of the code — it is a live landmine: if an operator ever calls
-- GET /settings/data_retention (server/api/settings.cpp) without first
-- setting a real value via /settings/data_retention_days, the generated
-- cron script computes `timestamp=$((ts-0))` and runs
-- `DELETE FROM <table> WHERE unixtime < $timestamp` — i.e. deletes
-- everything, every night, via crontab. The UPDATE below repairs any
-- existing 0/NULL row to the sane default; it leaves alone any row an
-- operator has already set to a real positive value.
-- ---------------------------------------------------------------------
UPDATE data_retention_settings
SET days = 90 * 86400
WHERE days IS NULL OR days <= 0;

INSERT INTO data_retention_settings (days)
SELECT 90 * 86400
WHERE NOT EXISTS (SELECT 1 FROM data_retention_settings);
