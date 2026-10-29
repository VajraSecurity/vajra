-- Documentation-only mirror: nothing in this codebase executes
-- migrations/*.sql automatically. The schema below is applied for real on every
-- server boot by the idempotent bootstrap block in backend/src/index.ts (search for "alerts schema up to date"). Keep
-- the two in sync if either changes.
--
-- Adds group scoping to the `alerts` table for alert types whose triggering
-- entity carries a group but whose host_identifier does not correspond to a
-- real `nodes` row (so the usual host_identifier -> nodes.owner_group_id join
-- used to scope every other alert type — see alert_list.ts / alert_list_my.ts
-- / alert_by_id.ts — can't apply). Today that's only the Scan Scheduler's
-- consolidated "Unmanaged Hosts Detected" alert: it covers many IPs in one
-- row keyed by a synthetic `schedule-<id>-run-<scanId>` identifier, so it has
-- no single node to inherit a group from. createRunAlert (scanSchedulerService.ts)
-- stamps the triggering ScanSchedule's group_id here directly.
--
-- group_id is a soft reference to the fleet DB's nodes_groups.group_id, same
-- pattern used everywhere else in this codebase (no FK possible — groups live
-- in a separate PostgreSQL DataSource). NULL means either "not a group-scoped
-- alert type" (every alert type except the one above) or "triggered by a
-- Super Administrator's own fleet-wide schedule" — both cases keep the
-- pre-existing behavior (Super Admin sees it, no Group Admin does, via the
-- read paths' `n.owner_group_id = ANY(...) OR a.group_id = ANY(...)` check).

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_alerts_group_id ON alerts(group_id);
