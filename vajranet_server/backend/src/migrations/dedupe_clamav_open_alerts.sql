-- DESTRUCTIVE. Step 1 of this file UPDATEs `metadata` on surviving alert rows
-- and then DELETEs the alert rows it folded away. It rewrites and removes live
-- alert data, there is no undo, and deduplicating alerts is an operator
-- decision — never run this unattended or as part of an automated deploy.
-- Run the verification query at the bottom against the target database first,
-- so you know exactly which rows will be merged.
--
-- Database: fleet (the secondary / PG_*1 database, the one that owns
-- public.alerts). Not the primary auth database.
--
-- What this fixes. The clamav_push ingest in websocket/node.ts writes each
-- detection with a bump-or-insert CTE: if an open alert already exists for the
-- same (host_identifier, alert_type='ClamAV Alert', event_code=<signature>,
-- metadata->>'path'), bump its occurrences counter, otherwise insert. The
-- statement is atomic, but nothing stops two of them running concurrently, and
-- when they do, both observe "no open alert to bump" and both insert. That has
-- happened in production. websocket/node.ts serialises each host's clamav_push
-- batch, which closes the race for every write this Node process makes, but not
-- against a second Node process, the C++ fleet server or any other writer that
-- learns to insert 'ClamAV Alert' rows, or a manual backfill. Only a unique
-- index makes the invariant true regardless of who is writing.
--
-- A plain CREATE UNIQUE INDEX is not enough on its own: rows that already
-- violate the constraint would make the build fail. Step 1 merges them into
-- their oldest row first, preserving the occurrences arithmetic the bump path
-- would have produced.
--
-- COALESCE on the path is load-bearing, do not simplify it away. Every
-- reference to the detection path below is COALESCE(...,'') rather than a bare
-- ->>'path', mirroring websocket/node.ts's bump predicate, which compares
-- COALESCE(metadata::jsonb->>'path','') = $10 so a detection with no path
-- deduplicates instead of inserting a fresh open alert every time. With the
-- bare expression the two would disagree exactly on pathless detections: SQL
-- NULL never equals NULL, so a plain unique index treats every pathless row as
-- distinct and would not enforce what the application relies on, and the merge
-- steps would skip those rows and leave the duplicates they exist to remove.
-- Postgres accepts COALESCE in a unique index expression, since it is immutable
-- here.
--
-- Notes on the index expression. `metadata` is a TEXT column holding JSON, so
-- the path component has to be extracted as (metadata::jsonb->>'path'). That is
-- legal in an index because the text->jsonb conversion cast resolves to
-- jsonb_in (provolatile='i') and jsonb_object_field_text is likewise immutable.
--
-- The index is partial on (is_open AND alert_type = 'ClamAV Alert'):
--   * is_open — a closed alert must not block a new one. A file reappearing
--     after triage is deliberately a fresh alert, which is why the bump path
--     filters on is_open = true. A total unique index would break that.
--   * alert_type — every other alert family (Defender, USB, ClamAV Scan, the
--     scanner-sourced alerts) is untouched. Several of them legitimately
--     produce repeated rows and must not be constrained.
--
-- Rows whose metadata carries no 'path' key yield NULL, and NULLs do not
-- conflict in a btree unique index, so pathless detections keep the current
-- insert-always behaviour rather than collapsing into one another. That matches
-- today's bump predicate, which cannot match a NULL path either.
--
-- Cost. public.alerts on production is 8,940 rows / 10 MB, of which 24 are
-- 'ClamAV Alert'. Step 1 seq-scans the table once and step 2 builds a partial
-- index over those 24 rows, so both are milliseconds at this size. Re-check
-- before running against a materially larger deployment.
--
-- Once this is applied, the CTE in websocket/node.ts can be simplified to a
-- single
--   INSERT ... ON CONFLICT (host_identifier, event_code, (metadata::jsonb->>'path'))
--   WHERE is_open AND alert_type = 'ClamAV Alert'
--   DO UPDATE SET unixtime = GREATEST(...), metadata = jsonb_set(...)
-- which is race-free by construction and needs no serialisation. Do not make
-- that code change before this migration is applied everywhere: ON CONFLICT
-- against a missing index is a hard error at execution time, which on this path
-- would mean every ClamAV detection failing to persist.

BEGIN;

-- Step 1: merge pre-existing duplicates. This is the destructive half.
--
-- For each (host, signature, path) group of OPEN 'ClamAV Alert' rows, keep the
-- lowest id and fold the others into it:
--   * unixtime           -> the greatest across the group (same as the bump's
--                           GREATEST(unixtime, $2))
--   * metadata.occurrences -> the sum across the group, so the surviving row
--                           reports the true detection count rather than
--                           silently losing the merged rows' counts
--   * metadata.last_detected_at -> from the row with the greatest unixtime
--
-- Anything already closed is left completely alone.

WITH grouped AS (
  SELECT
    id,
    host_identifier,
    event_code,
    metadata::jsonb->>'path'                                   AS path,
    unixtime,
    COALESCE((metadata::jsonb->>'occurrences')::int, 1)        AS occurrences,
    metadata::jsonb->>'last_detected_at'                       AS last_detected_at,
    MIN(id)  OVER w                                            AS keep_id,
    COUNT(*) OVER w                                            AS group_size
  FROM alerts
  WHERE alert_type = 'ClamAV Alert'
    AND is_open = true
  WINDOW w AS (PARTITION BY host_identifier, event_code, COALESCE(metadata::jsonb->>'path', ''))
),
dupes AS (
  SELECT * FROM grouped WHERE group_size > 1
),
merged AS (
  SELECT
    keep_id,
    SUM(occurrences)::int AS total_occurrences,
    MAX(unixtime)         AS max_unixtime,
    (ARRAY_AGG(last_detected_at ORDER BY unixtime DESC NULLS LAST))[1] AS newest_last_detected_at
  FROM dupes
  GROUP BY keep_id
)
UPDATE alerts a
SET unixtime = m.max_unixtime,
    metadata = jsonb_set(
                 jsonb_set(
                   a.metadata::jsonb,
                   '{occurrences}',
                   to_jsonb(m.total_occurrences)
                 ),
                 '{last_detected_at}',
                 to_jsonb(COALESCE(m.newest_last_detected_at, ''))
               )::text
FROM merged m
WHERE a.id = m.keep_id;

-- Delete the folded-away rows (everything in a duplicate group that is not the
-- surviving keep_id).
WITH grouped AS (
  SELECT
    id,
    MIN(id)  OVER w AS keep_id,
    COUNT(*) OVER w AS group_size
  FROM alerts
  WHERE alert_type = 'ClamAV Alert'
    AND is_open = true
  WINDOW w AS (PARTITION BY host_identifier, event_code, COALESCE(metadata::jsonb->>'path', ''))
)
DELETE FROM alerts
WHERE id IN (SELECT id FROM grouped WHERE group_size > 1 AND id <> keep_id);

COMMIT;

-- Step 2: the constraint itself.
--
-- CONCURRENTLY so the build never takes an ACCESS EXCLUSIVE lock on `alerts` --
-- that table is on the agent ingest path and a blocking build would stall every
-- agent push for the duration. CONCURRENTLY cannot run inside a transaction
-- block, hence the COMMIT above.
--
-- If this reports "could not create unique index", step 1 did not catch every
-- duplicate (a new one raced in during the build). Re-run step 1, DROP INDEX
-- the resulting INVALID index, and try again.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_alerts_clamav_open_detection
  ON alerts (host_identifier, event_code, (COALESCE(metadata::jsonb->>'path', '')))
  WHERE is_open = true AND alert_type = 'ClamAV Alert';

-- Verification (should return zero rows):
--   SELECT host_identifier, event_code, metadata::jsonb->>'path', count(*)
--   FROM alerts WHERE alert_type = 'ClamAV Alert' AND is_open
--   GROUP BY 1,2,3 HAVING count(*) > 1;
