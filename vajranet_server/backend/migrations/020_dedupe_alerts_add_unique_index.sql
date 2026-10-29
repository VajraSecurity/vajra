-- Fleet DB: remove duplicate alert rows, then add the unique index preventing them.
--
-- DESTRUCTIVE. Deletes rows from `alerts`.
--
-- Scope of the delete: rows byte-identical to another on every column except `id`.
-- The lowest id in each group is kept, so no alert is lost, only redundant copies.
-- Measured before this ran: 433 excess rows of 9,035 across 172 groups (Defender
-- 383/133, USB 34/23, Process 15/15, ClamAV 1/1); one group held 13 copies.
--
-- Cause: defender_push and usb_device_push each build two independent insert
-- thunks. The detail insert carries ON CONFLICT DO NOTHING; the paired `alerts`
-- insert is bare and never learns the detail insert was a no-op. An agent's
-- store-and-forward buffer clears only after a successful WS write, so a crash in
-- that window redelivers the batch. clamav_push in the same file guards against
-- this; these two paths do not.
--
-- ORDER IS LOAD-BEARING. The DELETE must precede the CREATE UNIQUE INDEX — building
-- first fails with 23505 and applies nothing. Do not reorder.
--
-- COALESCE on nullable columns is required: NULLs are distinct in a unique index,
-- so a null-metadata duplicate would pass the check meant to stop it. md5() keeps
-- the index small, since metadata is TEXT holding multi-KB JSON.
--
-- Companion code change: add ON CONFLICT DO NOTHING to the two `alerts` INSERTs in
-- websocket/node.ts. Without it, redelivery raises 23505 instead of duplicating —
-- correct, but noisy. The index is safe to apply alone.
--
-- CONCURRENTLY: cannot run inside a transaction. Apply with psql -f, never wrapped
-- in BEGIN/COMMIT.
--
-- Rollback: DROP INDEX CONCURRENTLY uq_alerts_dedupe. Deleted rows are not
-- recoverable, which is why the delete is restricted to exact duplicates.
--
-- Verify before and after — the count must go from 172 to 0, and the index valid:
--   SELECT count(*) FROM (SELECT 1 FROM alerts GROUP BY host_identifier, alert_type,
--     event_code, unixtime, severity, md5(COALESCE(metadata,''))
--     HAVING count(*) > 1) g;
--   SELECT indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
--    WHERE c.relname = 'uq_alerts_dedupe';

DELETE FROM alerts a
USING (
  SELECT
    min(id) AS keep_id,
    host_identifier,
    alert_type,
    event_code,
    unixtime,
    severity,
    md5(COALESCE(metadata, '')) AS meta_hash
  FROM alerts
  GROUP BY host_identifier, alert_type, event_code, unixtime, severity, md5(COALESCE(metadata, ''))
  HAVING count(*) > 1
) dup
WHERE a.host_identifier         IS NOT DISTINCT FROM dup.host_identifier
  AND a.alert_type              IS NOT DISTINCT FROM dup.alert_type
  AND a.event_code              IS NOT DISTINCT FROM dup.event_code
  AND a.unixtime                IS NOT DISTINCT FROM dup.unixtime
  AND a.severity                IS NOT DISTINCT FROM dup.severity
  AND md5(COALESCE(a.metadata, '')) = dup.meta_hash
  AND a.id <> dup.keep_id;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_alerts_dedupe
  ON alerts (
    COALESCE(host_identifier, ''),
    COALESCE(alert_type, ''),
    COALESCE(event_code, ''),
    COALESCE(unixtime, 0),
    COALESCE(severity, ''),
    md5(COALESCE(metadata, ''))
  );
