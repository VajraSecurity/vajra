-- Documentation-only mirror: nothing in this codebase executes
-- migrations/*.sql automatically. The schema below is applied for real on every
-- server boot (including production, where TypeORM synchronize is disabled) by
-- the idempotent bootstrap block in backend/src/index.ts (search for
-- "scan_schedules schema up to date"). Keep the two in sync if either changes.

CREATE TABLE IF NOT EXISTS scan_schedules (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  target VARCHAR(20) NOT NULL,
  frequency_preset VARCHAR(20) NOT NULL,
  cron_expression VARCHAR(100) NOT NULL,
  reason VARCHAR(500) NOT NULL DEFAULT '',
  known_ips JSONB NOT NULL DEFAULT '[]',
  created_by_user_id INTEGER,
  created_by_name VARCHAR(255),
  last_run_at TIMESTAMPTZ,
  last_run_status VARCHAR(20),
  last_run_history_id BIGINT,
  last_new_ip_count INTEGER,
  last_pending_ip_count INTEGER,
  last_reused_ip_count INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS last_pending_ip_count INTEGER;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS last_reused_ip_count INTEGER;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS known_ips JSONB NOT NULL DEFAULT '[]';
-- group_id: soft reference to nodes_groups.group_id (see backend/src/utils/nodeScope.ts).
-- NULL means a Super Administrator created this schedule outside any group
-- ("fleet-wide"), visible only to Super Admins. Group Admin access to the Scan
-- Scheduler sub-tab is scoped to the caller's own group through this column
-- rather than exposing every schedule fleet-wide; see
-- backend/src/utils/scannerScope.ts.
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_group ON scan_schedules(group_id);

ALTER TABLE network_scan_history ADD COLUMN IF NOT EXISTS schedule_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_nsh_schedule_id ON network_scan_history(schedule_id);

-- Supports ScanSchedulerService's per-tick "already notified" dedup lookup.
CREATE INDEX IF NOT EXISTS idx_alerts_schedule_id
  ON alerts ((metadata::jsonb->>'schedule_id'));
