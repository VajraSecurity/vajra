-- Documentation mirror of FIM_VERIFY_DDL (src/utils/fim/fimRegistryDdl.ts), run on boot by the
-- 'fim-registry-tables' startup step. Canonical source: vajra_server/sql/migrations/0006_fim_verify.sql.

-- Real-time registry drift -> targeted check scan (docs/FIM_REGISTRY_DESIGN.md §3.9, plan step 14).
-- Additive and idempotent. Requires 0004_fim.sql.
-- DEPLOY ORDER: apply 0006 and then 0007_fim_worker_schema.sql, THEN restart/upgrade the vajra_fim
-- worker. Do not run a worker binary older than schema v7 against these indexes (see 0007 header
-- for the four worker x index combinations). The backend applies 0005-0007 on boot.
--
-- A win_registry_events change raises drift at once (with the actor) and queues ONE distributed
-- query with that entry's own scan SQL (at most one per host+entry per 30 s). The answer is diffed
-- like a scheduled scan (never replacing the baseline): it confirms the drift in osquery's format
-- (new_sha256 / new_attrs from the scan, confirmed_at), or, when the value is back to the
-- baseline, keeps the drift OPEN and sets reverted = true (tamper-then-revert stays visible).

-- Concurrency: every FIM DDL block takes the shared advisory lock 727299 (worker migrations and the
-- backend boot DDL alike). Apply this file in ONE transaction (psql -1 -v ON_ERROR_STOP=1 -f ...)
-- so the lock is held for the whole file.
SELECT pg_advisory_xact_lock(727299);

CREATE TABLE IF NOT EXISTS fim_verify_requests (
    id               bigserial PRIMARY KEY,
    policy_id        bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier  varchar(40) NOT NULL,
    entry_idx        integer NOT NULL,
    rev              integer NOT NULL,
    drift_id         bigint,
    queue_id         bigint,
    after_result_id  bigint NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','failed','expired')),
    created_at       bigint NOT NULL,
    completed_at     bigint,
    error            text
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_verify_status') IS NULL THEN
        CREATE INDEX idx_fim_verify_status ON fim_verify_requests (status, created_at);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_verify_slot') IS NULL THEN
        CREATE INDEX idx_fim_verify_slot ON fim_verify_requests (policy_id, host_identifier, entry_idx, created_at DESC);
    END IF;
END $fimddl$;

DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_drift' AND column_name = 'reverted') THEN
        ALTER TABLE fim_drift ADD COLUMN reverted boolean NOT NULL DEFAULT false;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_drift' AND column_name = 'confirmed_at') THEN
        ALTER TABLE fim_drift ADD COLUMN confirmed_at bigint;
    END IF;
END $fimddl$;

-- Registry item identity is case-insensitive (Windows registry names are): real-time events carry
-- the stored case, scans the pattern's literal case. One OPEN drift per (policy, host, item) with
-- registry item keys compared by ONE folding rule shared by the worker (ascii_lower), this index,
-- the worker's lookups and the approve path adoption: lower(path COLLATE "C"), which folds ASCII
-- letters only (a database-collation lower() would also fold non-ASCII letters the worker keeps
-- distinct). File paths stay case-sensitive.
--
-- Existing open duplicates that differ only in ASCII letter case are merged before the index is
-- built. The SURVIVOR is the row with the most recent last_seen_at (ties: highest id), because it
-- holds the latest evidence (actor, new hash, new attributes). It receives the summed occurrences,
-- the earliest detected_at and the highest severity of the group. The other rows are closed as
-- 'ignored' with a note naming the survivor, and their still-open linked console alerts are closed
-- with the same remark (an open alert must not point at a closed drift).
DO $$
BEGIN
    CREATE TEMP TABLE fim_ci_dup ON COMMIT DROP AS
    SELECT id, keep_id FROM (
        SELECT id, first_value(id) OVER (PARTITION BY policy_id, host_identifier, lower(path COLLATE "C")
                                          ORDER BY last_seen_at DESC NULLS LAST, id DESC) AS keep_id
        FROM fim_drift WHERE status = 'open' AND kind = 'item' AND path LIKE 'registry|%') g
    WHERE id <> keep_id;
    IF EXISTS (SELECT 1 FROM fim_ci_dup) THEN
        UPDATE fim_drift s SET occurrences = s.occurrences + a.occ,
               detected_at = LEAST(s.detected_at, a.det),
               severity = CASE WHEN a.rnk > (CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                               THEN a.sev ELSE s.severity END,
               note = left(COALESCE(s.note || ' | ', '') || 'Merged ' || a.n || ' open duplicate(s) differing only in letter case', 2000)
        FROM (SELECT c.keep_id, sum(d.occurrences) AS occ, min(d.detected_at) AS det, count(*) AS n,
                     max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS rnk,
                     (array_agg(d.severity ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC))[1] AS sev
              FROM fim_ci_dup c JOIN fim_drift d ON d.id = c.id GROUP BY c.keep_id) a
        WHERE s.id = a.keep_id;
        UPDATE alerts a SET is_open = false,
               remarks = left(COALESCE(a.remarks || ' | ', '') || 'Closed by migration: its drift was merged into drift #' || c.keep_id || ' (same registry item, different letter case)', 2000)
        FROM fim_ci_dup c JOIN fim_drift d ON d.id = c.id
        WHERE a.is_open AND a.alert_type = 'fim' AND a.host_identifier = d.host_identifier
          AND (a.id = d.alert_id OR substring(a.metadata from '"drift_id"[[:space:]]*:[[:space:]]*"?([0-9]{1,15})') = d.id::text);
        UPDATE fim_drift d SET status = 'ignored', resolved_by = 'migration', resolved_at = extract(epoch FROM now())::bigint,
               note = left(COALESCE(d.note || ' | ', '') || 'Merged into drift #' || c.keep_id || ' (same registry item, differs only in letter case; the survivor has the latest evidence)', 2000)
        FROM fim_ci_dup c WHERE d.id = c.id;
    END IF;
    DROP TABLE fim_ci_dup;
    -- An index built by an earlier revision of this migration used the database collation: replace it.
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_ci' AND indexdef NOT LIKE '%COLLATE%') THEN
        DROP INDEX uq_fim_drift_open_ci;
    END IF;
END $$;
-- Case-insensitive baseline lookups (worker + approve path adoption) use the same expression.
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_baseline_lowerpath_c') IS NULL THEN
        CREATE INDEX idx_fim_baseline_lowerpath_c ON fim_baseline (policy_id, host_identifier, lower(path COLLATE "C"));
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_drift_open_ci') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_drift_open_ci ON fim_drift
    (policy_id, host_identifier, (CASE WHEN kind = 'item' AND path LIKE 'registry|%' THEN lower(path COLLATE "C") ELSE path END))
    WHERE status = 'open';
    END IF;
END $fimddl$;

-- Backend query performance (drift / alert listings, linked-drift joins, alert updates).
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_alert') IS NULL THEN
        CREATE INDEX idx_fim_drift_alert ON fim_drift (alert_id) WHERE alert_id IS NOT NULL;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_time') IS NULL THEN
        CREATE INDEX idx_fim_drift_time ON fim_drift (detected_at DESC, id DESC);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_hostname_lower') IS NULL THEN
        CREATE INDEX idx_fim_drift_hostname_lower ON fim_drift (lower(COALESCE(hostname, '')));
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_alerts_fim_host') IS NULL THEN
        CREATE INDEX idx_alerts_fim_host ON alerts (host_identifier) WHERE alert_type IN ('fim','fim_health','fim_config');
    END IF;
END $fimddl$;

-- Cheap change marker for the worker's policy cache (no md5 over every policy on every tick).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_policies' AND column_name = 'paths_hash') THEN
        ALTER TABLE fim_policies ADD COLUMN paths_hash text;
    END IF;
END $fimddl$;
CREATE OR REPLACE FUNCTION fim_policies_paths_hash() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.paths_hash := md5(NEW.paths::text);
    RETURN NEW;
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_policies_paths_hash' AND tgrelid = 'fim_policies'::regclass) THEN
        CREATE TRIGGER trg_fim_policies_paths_hash BEFORE INSERT OR UPDATE OF paths ON fim_policies
    FOR EACH ROW EXECUTE FUNCTION fim_policies_paths_hash();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_policies_paths_hash' AND tgrelid = 'fim_policies'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_policies ENABLE TRIGGER trg_fim_policies_paths_hash;
    END IF;
END $fimddl$;
UPDATE fim_policies SET paths_hash = md5(paths::text) WHERE paths_hash IS DISTINCT FROM md5(paths::text);

-- Audit outbox in the SAME database and transaction as every FIM registry mutation (the primary
-- audit_trail write is best-effort, after commit). Denied privileged attempts are recorded too.
CREATE TABLE IF NOT EXISTS fim_audit (
    id          bigserial PRIMARY KEY,
    at          bigint NOT NULL,
    actor       text NOT NULL,
    user_id     bigint,
    action      text NOT NULL,
    outcome     text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success','denied','error')),
    request_id  text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_audit_at') IS NULL THEN
        CREATE INDEX idx_fim_audit_at ON fim_audit (at DESC);
    END IF;
END $fimddl$;

-- Measurements are kept per node + OS build (and used conservatively: the largest recent one).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_measure' AND column_name = 'os_build') THEN
        ALTER TABLE fim_reg_measure ADD COLUMN os_build text;
    END IF;
END $fimddl$;
