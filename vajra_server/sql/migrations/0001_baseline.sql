-- 0001_baseline
-- Baseline marker: the schema at this point is defined by sql/schema.sql
-- (plus the historical hand-applied patches sql/01..08_*.sql, which stay
-- where they are and are NOT re-run by the migration runner).
-- This migration intentionally makes no schema changes; it only records
-- that a database has been baselined. New changes start at 0002_*.sql.
SELECT 1;
