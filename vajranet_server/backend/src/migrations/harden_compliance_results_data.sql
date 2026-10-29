-- DESTRUCTIVE. This DELETEs rows from all four per-node compliance_results
-- tables — every row whose compliance_data is not a JSON array — before adding
-- a CHECK constraint that keeps new ones out. There is no undo; the deleted
-- rows exist only in a prior backup. Review what the DELETEs would match
-- before running this anywhere.
--
-- Why. Rows written directly against the database bypass the app's
-- `Array.isArray(complianceData)` validation. One such row was found in
-- production (certin_compliance_results, host_identifier='1',
-- compliance_data=1 — a bare JSON number). It makes reports.ts's
-- `jsonb_array_elements(compliance_data::jsonb)` derivation query throw for
-- that host, and that error is swallowed by a `.catch(() => [])`, so the page
-- silently reads as "no non-compliant nodes" instead of surfacing the failure.
-- The CHECK constraint closes the hole for every write path, not just the app's.
--
-- Safe to re-run: the DELETEs are conditional and the constraints are added
-- inside a DO block that checks pg_constraint first, since Postgres has no
-- `ADD CONSTRAINT IF NOT EXISTS`.

DELETE FROM compliance_results        WHERE jsonb_typeof(compliance_data) != 'array';
DELETE FROM certin_compliance_results WHERE jsonb_typeof(compliance_data) != 'array';
DELETE FROM irdai_compliance_results  WHERE jsonb_typeof(compliance_data) != 'array';
DELETE FROM sebi_compliance_results   WHERE jsonb_typeof(compliance_data) != 'array';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'compliance_data_is_array') THEN
    ALTER TABLE compliance_results ADD CONSTRAINT compliance_data_is_array CHECK (jsonb_typeof(compliance_data) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'certin_compliance_data_is_array') THEN
    ALTER TABLE certin_compliance_results ADD CONSTRAINT certin_compliance_data_is_array CHECK (jsonb_typeof(compliance_data) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'irdai_compliance_data_is_array') THEN
    ALTER TABLE irdai_compliance_results ADD CONSTRAINT irdai_compliance_data_is_array CHECK (jsonb_typeof(compliance_data) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sebi_compliance_data_is_array') THEN
    ALTER TABLE sebi_compliance_results ADD CONSTRAINT sebi_compliance_data_is_array CHECK (jsonb_typeof(compliance_data) = 'array');
  END IF;
END
$$;
