-- Fleet DB: Patch Management tables. Tracked the same way as agent_releases /
-- agent_cert_provisioning_tokens / node_agent_versions: a reviewed, additive
-- migration plus TypeORM entities under orm/entities/fleet/ so
-- findMissingEntityTables() can detect drift.
--
-- One patch_jobs row per admin-triggered check/upgrade(/fallback) action
-- across a set of nodes; patch_job_nodes holds the per-node outcome,
-- correlated to the agent's async osupdate_result push primarily by
-- task_id (recorded when the agent's immediate ack for the dispatch
-- arrives — see websocket/node.ts's "osupdate_ack:" rid handling), falling
-- back to "the newest dispatched/acked/running row for this host" only
-- when task_id is absent (older agent, or a lost ack). pending_patch_commands
-- queues a command for a node that's offline at dispatch time, replayed
-- (one at a time — osupdate is single-flight per host) when it reconnects
-- (websocket/patchDispatch.ts). patch_available_updates is a per-host/
-- per-manager snapshot-replace table (same shape as packages_snapshot)
-- populated from a completed "check" operation.
--
-- All host_identifier comparisons against these tables are wrapped in
-- LOWER() at query time (see controllers/nodes/patch_management.ts,
-- websocket/patchDispatch.ts, websocket/node.ts) — matching the convention
-- already used in src/migrations/create_grafana_views.sql. The column
-- itself is left case-as-stored deliberately; this migration does not
-- rewrite existing rows.
CREATE TABLE IF NOT EXISTS patch_jobs (
  id                BIGSERIAL    PRIMARY KEY,
  operation         TEXT         NOT NULL,
  created_by_id     INTEGER,
  created_by_email  TEXT,
  reason            TEXT,
  -- 'native': dispatched straight to the agent's osupdate engine (apt/dnf/
  -- yum/zypper/pacman, whatever the host actually has).
  -- 'bundle': a Vajra-signed offline package bundle, dispatched as an
  -- apply_bundle action to the agent (see createPatchJob in
  -- controllers/nodes/patch_management.ts) — created either as a fallback
  -- for hosts whose native attempt failed (POST /api/patch/apply/fallback)
  -- or pinned to one exact bundle version (POST /api/patch/bundles/:id/apply).
  source            TEXT         NOT NULL DEFAULT 'native',
  fallback_of_job_id INTEGER     REFERENCES patch_jobs(id),
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
-- For installs where patch_jobs predates these columns, the CREATE TABLE above
-- is a no-op, so add them explicitly.
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS source             TEXT    NOT NULL DEFAULT 'native';
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS fallback_of_job_id INTEGER REFERENCES patch_jobs(id);

CREATE TABLE IF NOT EXISTS patch_job_nodes (
  id                BIGSERIAL    PRIMARY KEY,
  patch_job_id      BIGINT       NOT NULL REFERENCES patch_jobs(id) ON DELETE CASCADE,
  host_identifier   TEXT         NOT NULL,
  package_names     JSONB,
  -- Status machine: queued -> dispatched -> acked -> running -> success|failed|timed_out
  --   queued:     row created, not yet sent (host offline at dispatch time,
  --               or awaiting a scheduled_at firing).
  --   dispatched: WS send to the agent succeeded; no confirmation from the
  --               agent yet that it actually started the job.
  --   acked:      the agent's immediate response to the "osupdate" command
  --               arrived and carried a task_id — it has genuinely started.
  --   running:    reserved for a future explicit "in progress" signal; not
  --               currently set by anything (kept for forward compatibility
  --               with the status-filter queries that already reference it).
  --   success/failed/timed_out: terminal.
  status            TEXT         NOT NULL DEFAULT 'queued',
  manager           TEXT,
  result            JSONB,
  -- Set from the agent's immediate ack (task_id) once dispatched -> acked;
  -- used to correlate the later async osupdate_result push to this exact row.
  task_id           TEXT,
  reboot_required   BOOLEAN,
  failure_reason    TEXT,
  dispatched_at     TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
ALTER TABLE patch_job_nodes ADD COLUMN IF NOT EXISTS task_id         TEXT;
ALTER TABLE patch_job_nodes ADD COLUMN IF NOT EXISTS reboot_required BOOLEAN;
ALTER TABLE patch_job_nodes ADD COLUMN IF NOT EXISTS failure_reason  TEXT;

CREATE INDEX IF NOT EXISTS idx_patch_job_nodes_job ON patch_job_nodes (patch_job_id);
CREATE INDEX IF NOT EXISTS idx_patch_job_nodes_host_status ON patch_job_nodes (host_identifier, status);
CREATE INDEX IF NOT EXISTS idx_patch_job_nodes_task_id ON patch_job_nodes (task_id);

CREATE TABLE IF NOT EXISTS pending_patch_commands (
  id                BIGSERIAL    PRIMARY KEY,
  patch_job_node_id BIGINT       NOT NULL REFERENCES patch_job_nodes(id) ON DELETE CASCADE,
  host_identifier   TEXT         NOT NULL,
  payload           JSONB        NOT NULL,
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pending_patch_commands_host ON pending_patch_commands (host_identifier);

CREATE TABLE IF NOT EXISTS patch_available_updates (
  id                BIGSERIAL    PRIMARY KEY,
  host_identifier   TEXT         NOT NULL,
  manager           TEXT         NOT NULL,
  name              TEXT         NOT NULL,
  installed_version TEXT,
  available_version TEXT         NOT NULL,
  updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE (host_identifier, manager, name)
);
CREATE INDEX IF NOT EXISTS idx_patch_available_updates_host ON patch_available_updates (host_identifier);
