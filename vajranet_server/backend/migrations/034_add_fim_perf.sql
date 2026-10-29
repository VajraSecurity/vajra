-- Documentation mirror of FIM_PERF_DDL (src/utils/fim/fimRegistryDdl.ts), run on boot by the
-- 'fim-registry-tables' startup step. Canonical source: vajra_server/sql/migrations/0008_fim_perf.sql.

SELECT pg_advisory_xact_lock(727299);  -- shared FIM DDL lock; apply this file in ONE transaction (psql -1)
-- FIM schema contract v8 (vajra_fim). Additive and idempotent. Requires 0004, 0005, 0006, 0007.
--
-- CONCURRENCY: the first statement takes the shared FIM DDL advisory lock (727299), held until
-- the end of the transaction, so the file must be applied in ONE transaction (psql -1 -v
-- ON_ERROR_STOP=1 -f, or scripts/migrate.sh). The worker migration path and the backend boot DDL
-- then serialize instead of colliding on pg_class / pg_type / pg_proc.
--
-- WHAT IT ADDS
--   1. fim_schema_version() = 8 (never downgrades). The worker requires >= 8; on an older schema it
--      fails closed exactly like v7 (one 'FIM worker schema mismatch' alert, nothing processed,
--      nothing lost).
--   2. CHECK constraints fim_baseline_kind_check / fim_drift_kind_check (kind IN ('file',
--      'directory','item'), the only kinds the worker writes), added NOT VALID then validated, so
--      a database whose kind column predates the inline CHECK of 0004 gets it too.
--   3. Drops the stale column fim_policies.auto_init (no code reads or writes it any more).
--   4. fim_cursor_gaps: the worker's open id holes per feed (ids allocated but not yet committed
--      when the cursor passed them). Persisted so a row that commits late is still processed after a
--      worker restart (previously the hole list lived only in memory).
--   6. Partial indexes idx_fim_init_requests_pending_qid / idx_fim_verify_requests_pending_qid
--      ((queue_id::text), host_identifier) WHERE status = 'pending': the worker finds ANSWERED pending
--      requests from the answer side (new query_result / dead_letter_queue rows), however many
--      unanswered requests there are.
--   7. fim_schema_applied (name, sha256, applied_at): created here by the owner so the backend app
--      role needs no CREATE privilege on the schema.
--   All ALTERs and CREATE INDEXes are conditional (catalog checks), so a no-op re-apply takes no
--   exclusive lock on the FIM tables.
--   5. fim_drift.last_realtime_at: time of the newest real-time event on a drift. A check-scan or
--      scheduled-scan answer confirms a drift (or replaces its observation) only when it was captured
--      at or after that time; a stale answer never confirms over a newer real-time change.
--   The two request-probe PERF indexes are NOT here: they are in 0008a_fim_perf_indexes.sql, built
--   CONCURRENTLY outside a transaction (a CREATE INDEX here would block inserts into
--   dead_letter_queue / query_result for the whole build). The worker only WARNS while they are
--   missing or INVALID (one 'FIM perf indexes missing: ...' fim_health alert) and keeps working.
--
-- UPGRADE NOTE (redaction marker format): baselines taken before redaction spec v2 hold length-only
-- markers 'REDACTED(len=N)'. The new marker is 'REDACTED(len=N,sha256=H)', so each redacted value
-- drifts ONCE ('modified') after the upgrade. engine_v2/fim/tools/accept_marker_format.sql (one shot,
-- psql -1) re-keys those baseline rows to the v2 marker and closes the one-off drifts as 'ignored'
-- ('redaction marker format upgrade') -- only when the new v2 marker has the SAME length; a v1 marker
-- has no hash, so the equal length is the only guarantee (documented in the script).
--
-- DEPLOY ORDER: apply 0006, 0007, 0008 (in order, each with psql -1), THEN 0008a (plain psql -f, no
-- -1: CREATE INDEX CONCURRENTLY), THEN restart / upgrade the worker. The backend also builds the
-- 0008a indexes CONCURRENTLY in a background step after boot when they are missing. A v8 worker on a
-- v7 database fails closed until 0008 is applied; a v7 worker on a v8 database keeps working (it
-- requires >= 7 and the v7 index, both unchanged here). After the first scans of the upgraded worker,
-- optionally run engine_v2/fim/tools/accept_marker_format.sql (see the UPGRADE NOTE).
--
-- This file is embedded verbatim by the backend (TypeScript template literal): keep it free of
-- backslashes, backticks and dollar-brace sequences.

-- Every change below is CONDITIONAL (catalog checks first): a no-op re-apply takes no ACCESS
-- EXCLUSIVE (or SHARE) lock on fim_drift / fim_baseline / fim_policies / the request tables, so it
-- never waits for -- or blocks -- readers and the worker.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_baseline_kind_check' AND conrelid = 'fim_baseline'::regclass) THEN
        ALTER TABLE fim_baseline ADD CONSTRAINT fim_baseline_kind_check CHECK (kind IN ('file','directory','item')) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_baseline_kind_check' AND conrelid = 'fim_baseline'::regclass AND NOT convalidated) THEN
        ALTER TABLE fim_baseline VALIDATE CONSTRAINT fim_baseline_kind_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_drift_kind_check' AND conrelid = 'fim_drift'::regclass) THEN
        ALTER TABLE fim_drift ADD CONSTRAINT fim_drift_kind_check CHECK (kind IN ('file','directory','item')) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_drift_kind_check' AND conrelid = 'fim_drift'::regclass AND NOT convalidated) THEN
        ALTER TABLE fim_drift VALIDATE CONSTRAINT fim_drift_kind_check;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
               AND table_name = 'fim_policies' AND column_name = 'auto_init') THEN
        ALTER TABLE fim_policies DROP COLUMN auto_init;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                   AND table_name = 'fim_drift' AND column_name = 'last_realtime_at') THEN
        ALTER TABLE fim_drift ADD COLUMN last_realtime_at bigint;
    END IF;
    -- F4: answers are matched to PENDING requests from the answer side (new query_result /
    -- dead_letter_queue rows joined by queue id + host); small partial indexes on the request tables.
    IF to_regclass('idx_fim_init_requests_pending_qid') IS NULL THEN
        CREATE INDEX idx_fim_init_requests_pending_qid ON fim_init_requests ((queue_id::text), host_identifier) WHERE status = 'pending';
    END IF;
    IF to_regclass('idx_fim_verify_requests_pending_qid') IS NULL THEN
        CREATE INDEX idx_fim_verify_requests_pending_qid ON fim_verify_requests ((queue_id::text), host_identifier) WHERE status = 'pending';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS fim_cursor_gaps (
    source      text NOT NULL,
    id          bigint NOT NULL,
    first_seen  bigint NOT NULL,
    PRIMARY KEY (source, id)
);

-- Owned by the migrating (owner) role, so the backend's app role does not need CREATE on the schema.
CREATE TABLE IF NOT EXISTS fim_schema_applied (
    name        text PRIMARY KEY,
    sha256      text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- Never downgrades: re-running 0008 after a later migration keeps the later version.
DO $$
DECLARE v integer := 0;
BEGIN
    IF to_regprocedure('fim_schema_version()') IS NOT NULL THEN
        EXECUTE 'SELECT fim_schema_version()' INTO v;
    END IF;
    IF v < 8 THEN
        EXECUTE 'CREATE OR REPLACE FUNCTION fim_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS ''SELECT 8''';
    END IF;
END $$;
