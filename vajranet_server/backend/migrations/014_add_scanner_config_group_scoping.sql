-- Documentation-only mirror: nothing in this codebase executes
-- migrations/*.sql automatically. The schema below is applied for real on every
-- server boot by the idempotent bootstrap block in backend/src/index.ts (search for "nessus_configs table ready",
-- "openvas_configs table ready", "burpsuite_configs table ready",
-- "burpsuite_scan_history table ready"). Keep the two in sync if either changes.
--
-- Makes Nessus/OpenVAS/Burp Suite integration config (and Burp's local scan
-- history) per-group instead of one config shared by every admin. See
-- backend/src/utils/scannerScope.ts for the resolution logic and
-- backend/src/utils/nodeScope.ts for the underlying group-scoping primitives.
--
-- group_id is a soft reference to the fleet DB's nodes_groups.group_id, same
-- pattern used everywhere else in this codebase (no FK possible — groups live
-- in a separate PostgreSQL DataSource). NULL means "the Super Administrator's
-- own config/scan", not tied to any group. Any config row predating this column
-- keeps group_id = NULL and so becomes the Super Admin's own config rather than
-- disappearing; that is the intended upgrade behaviour, not an accident of the
-- ALTER.

ALTER TABLE nessus_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_nessus_config_group ON nessus_configs(group_id);
-- At most one active config per group (including the NULL/Super-Admin bucket,
-- via COALESCE — a plain UNIQUE(group_id) can't express this because Postgres
-- treats every NULL as distinct).
CREATE UNIQUE INDEX IF NOT EXISTS idx_nessus_config_active_group_unique
  ON nessus_configs (COALESCE(group_id, ''))
  WHERE is_active;

ALTER TABLE openvas_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_openvas_config_group ON openvas_configs(group_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_openvas_config_active_group_unique
  ON openvas_configs (COALESCE(group_id, ''))
  WHERE is_active;

ALTER TABLE burpsuite_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_burpsuite_config_group ON burpsuite_configs(group_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_burpsuite_config_active_group_unique
  ON burpsuite_configs (COALESCE(group_id, ''))
  WHERE is_active;

-- Burp Suite is the only one of the three scanners with local scan-result
-- storage (Nessus/OpenVAS proxy live to a remote server and store nothing
-- here) — group_id records which scope launched each cached scan.
ALTER TABLE burpsuite_scan_history ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_burpsuite_history_group ON burpsuite_scan_history(group_id);
