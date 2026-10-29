-- Fleet DB: group scoping for the org-level compliance snapshot tables.
--
-- Without a column attributing a saved snapshot to the node group(s) it was
-- swept from, the Compliance page serves the same fleet-wide history to every
-- user regardless of their assigned node group. NULL owner_group_ids means a
-- fleet-wide snapshot — a row predating this column, or one saved by an
-- unrestricted/Super Admin caller — and the app shows those only to
-- unrestricted viewers, never to a scoped Group Admin or Viewer.
--
-- Run this against the `fleet` database (POSTGRES_DB1) before deploying the
-- backend build that references owner_group_ids: the app runs with
-- synchronize: false in production and will not create the column itself.
--
-- Safe to re-run: IF NOT EXISTS guards every statement.

ALTER TABLE historical_compliance       ADD COLUMN IF NOT EXISTS owner_group_ids text[];
ALTER TABLE sebi_historical_compliance  ADD COLUMN IF NOT EXISTS owner_group_ids text[];
ALTER TABLE irdai_historical_compliance ADD COLUMN IF NOT EXISTS owner_group_ids text[];
ALTER TABLE certin_historical_compliance ADD COLUMN IF NOT EXISTS owner_group_ids text[];

-- Scoped (non-super-admin) callers filter these history tables on
-- `owner_group_ids && $1::text[]`; without a GIN index that filter can't be
-- satisfied via an index scan and degrades toward a growing backward scan as
-- history accumulates.
--
-- CONCURRENTLY cannot run inside a transaction block, so apply these with
-- autocommit on (e.g. `psql -f add_compliance_owner_group_ids.sql`) and
-- separately from the ALTER TABLE statements above, which need a transaction
-- and must be applied first regardless.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_historical_compliance_owner_group_ids
  ON historical_compliance USING GIN (owner_group_ids);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sebi_historical_compliance_owner_group_ids
  ON sebi_historical_compliance USING GIN (owner_group_ids);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_irdai_historical_compliance_owner_group_ids
  ON irdai_historical_compliance USING GIN (owner_group_ids);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_certin_historical_compliance_owner_group_ids
  ON certin_historical_compliance USING GIN (owner_group_ids);
