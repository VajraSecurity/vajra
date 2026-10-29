-- Documentation mirror of FIM_WORKER_DDL (src/utils/fim/fimRegistryDdl.ts), run on boot by the
-- 'fim-registry-tables' startup step. Canonical source: vajra_server/sql/migrations/0007_fim_worker_schema.sql.

SELECT pg_advisory_xact_lock(727299);  -- shared FIM DDL lock; apply this file in ONE transaction (psql -1)
-- FIM worker schema contract v7 (vajra_fim). Additive and idempotent. Requires 0004, 0005, 0006.
--
-- CONCURRENCY: the first statement takes the shared FIM DDL advisory lock (727299), held until
-- the end of the transaction, so the file must be applied in ONE transaction (psql -1 -v
-- ON_ERROR_STOP=1 -f, or scripts/migrate.sh). The worker migration path and the backend boot DDL
-- then serialize instead of colliding on pg_class / pg_type / pg_proc.
--
-- WHAT IT ADDS
--   1. fim_schema_version(): the schema revision the worker runs against (7). The worker checks it,
--      and the definition of the drift identity index below, at start and every 5 minutes.
--   2. uq_fim_drift_open_v7: ONE open drift per (policy, host, item identity), where identity folds
--      ASCII letter case (lower(path COLLATE "C"), the worker's ascii_lower) for
--        - registry items (kind = 'item' AND path LIKE 'registry|%'), as 0006 already did, and
--        - Windows FILE paths (kind <> 'item' AND path starting with a drive letter and a colon),
--          so a real-time event spelling C:/Windows/Tasks/EVIL.job (with Windows separators) and a
--          scan spelling c:/windows/tasks/evil.job of the same new file raise ONE drift, not two;
--      everything else (Linux paths, other item kinds) stays exact. The worker's
--      ON CONFLICT target is exactly this expression.
--      uq_fim_drift_open (0004) and uq_fim_drift_open_ci (0006) are kept: both are implied by this
--      index (rows unique here are unique there), so they never reject a row this one accepts,
--      and re-running 0006 stays a no-op.
--   3. Open drifts that already collide under the new identity are merged first, like 0006: the
--      survivor is the row with the most recent last_seen_at (ties: highest id); it receives the
--      summed occurrences, the earliest detected_at and the highest severity of its group; the
--      other rows are closed as 'ignored' with a note naming the survivor, and their still-open
--      linked console alerts are closed with the same remark.
--
-- DEPLOY ORDER (precise)
--   1. Apply the migrations in order: 0006_fim_verify.sql, THEN this file (0007). Both are
--      idempotent; re-running them is safe.
--   2. THEN restart / upgrade the vajra_fim worker to the build that expects schema v7.
--   An OLD worker binary (built before v7) must NOT run on a database that has this index: stop
--   (or upgrade) it before or together with applying 0007.
--
-- THE FOUR COMBINATIONS (worker x index)
--   old worker + old index (0006 only): previous behaviour. Works, but a Windows file can carry
--      two open drifts that differ only in letter case (event spelling vs scan spelling).
--   old worker + new index (0007): UNSAFE. The old worker's ON CONFLICT names the 0006 expression,
--      so a case variant of an open Windows file drift violates uq_fim_drift_open_v7 instead of
--      bumping the drift: the statement fails and its transaction rolls back. A scan row is retried
--      three times and then skipped (that scan's drift is lost); a real-time batch is retried
--      forever (the real-time cursor stalls). Do not run this combination.
--   new worker + old index (no fim_schema_version(), no uq_fim_drift_open_v7, a v7 index with a
--      different definition, or an extra unique index on fim_drift such as a uq_fim_drift_open_ci
--      built with the database collation): the worker FAILS CLOSED. It logs an error, opens ONE
--      fim_health alert ('FIM worker schema mismatch', kept open, never duplicated) and processes
--      no scans, real-time events or check scans until the schema is fixed; its cursors do not
--      move, so nothing is lost: after the migrations are applied it resumes (within 30 s) where it
--      stopped and closes the alert. This also holds on a FRESH install: the worker creates its
--      cursors at start, before the schema check, so events that arrive while it waits are kept.
--      (Since 0008 the worker requires fim_schema_version() >= 8; see 0008_fim_perf.sql.)
--   CURRENT DEPLOY ORDER: 0006, 0007, 0008 (each with psql -1), then 0008a_fim_perf_indexes.sql
--   (plain psql, CREATE INDEX CONCURRENTLY; the backend also builds these in the background), then
--   restart the worker. Missing 0008a indexes only raise a 'FIM perf indexes missing' warning.
--   new worker + new index: normal operation.
--
-- This file is embedded verbatim by the backend (TypeScript template literal): keep it free of
-- backslashes, backticks and dollar-brace sequences.

-- Never downgrades: re-running 0007 after a later migration keeps the later version.
DO $$
DECLARE v integer := 0;
BEGIN
    IF to_regprocedure('fim_schema_version()') IS NOT NULL THEN
        EXECUTE 'SELECT fim_schema_version()' INTO v;
    END IF;
    IF v < 7 THEN
        EXECUTE 'CREATE OR REPLACE FUNCTION fim_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS ''SELECT 7''';
    END IF;
END $$;

DO $$
BEGIN
    CREATE TEMP TABLE fim_v7_dup ON COMMIT DROP AS
    SELECT id, keep_id FROM (
        SELECT id, first_value(id) OVER (
                   PARTITION BY policy_id, host_identifier,
                       (CASE WHEN (kind = 'item' AND path LIKE 'registry|%') OR (kind <> 'item' AND path ~ '^[A-Za-z]:')
                             THEN lower(path COLLATE "C") ELSE path END)
                   ORDER BY last_seen_at DESC NULLS LAST, id DESC) AS keep_id
        FROM fim_drift WHERE status = 'open') g
    WHERE id <> keep_id;
    IF EXISTS (SELECT 1 FROM fim_v7_dup) THEN
        UPDATE fim_drift s SET occurrences = s.occurrences + a.occ,
               detected_at = LEAST(s.detected_at, a.det),
               severity = CASE WHEN a.rnk > (CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                               THEN a.sev ELSE s.severity END,
               note = left(COALESCE(s.note || ' | ', '') || 'Merged ' || a.n || ' open duplicate(s) differing only in letter case', 2000)
        FROM (SELECT c.keep_id, sum(d.occurrences) AS occ, min(d.detected_at) AS det, count(*) AS n,
                     max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS rnk,
                     (array_agg(d.severity ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC))[1] AS sev
              FROM fim_v7_dup c JOIN fim_drift d ON d.id = c.id GROUP BY c.keep_id) a
        WHERE s.id = a.keep_id;
        UPDATE alerts a SET is_open = false,
               remarks = left(COALESCE(a.remarks || ' | ', '') || 'Closed by migration: its drift was merged into drift #' || c.keep_id || ' (same item, different letter case)', 2000)
        FROM fim_v7_dup c JOIN fim_drift d ON d.id = c.id
        WHERE a.is_open AND a.alert_type = 'fim' AND a.host_identifier = d.host_identifier
          AND (a.id = d.alert_id OR substring(a.metadata from '"drift_id"[[:space:]]*:[[:space:]]*"?([0-9]{1,15})') = d.id::text);
        UPDATE fim_drift d SET status = 'ignored', resolved_by = 'migration', resolved_at = extract(epoch FROM now())::bigint,
               note = left(COALESCE(d.note || ' | ', '') || 'Merged into drift #' || c.keep_id || ' (same item, differs only in letter case; the survivor has the latest evidence)', 2000)
        FROM fim_v7_dup c WHERE d.id = c.id;
    END IF;
    DROP TABLE fim_v7_dup;
    -- An index of this name with another definition (hand-made or an earlier draft) is replaced.
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_v7'
               AND (indexdef NOT LIKE '%COLLATE "C"%' OR indexdef NOT LIKE '%^[A-Za-z]:%' OR indexdef NOT LIKE '%registry|%')) THEN
        DROP INDEX uq_fim_drift_open_v7;
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_fim_drift_open_v7 ON fim_drift
    (policy_id, host_identifier,
     (CASE WHEN (kind = 'item' AND path LIKE 'registry|%') OR (kind <> 'item' AND path ~ '^[A-Za-z]:')
           THEN lower(path COLLATE "C") ELSE path END))
    WHERE status = 'open';
