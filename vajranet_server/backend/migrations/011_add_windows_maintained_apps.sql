-- Fleet DB: Windows "maintained apps" software install/uninstall management
-- (third-party software via vendor installers — Brave, 7-Zip, etc. — NOT
-- Windows Update/OS patching, which stays entirely separate). Backs
-- orm/entities/fleet/MaintainedApp.ts, MaintainedAppVersion.ts,
-- WindowsPatchJob.ts. See WINDOWS_AGENT_PATCH_MANAGEMENT.md for the full
-- agent-side wire contract these tables serve.
--
-- Deliberately named windows_patch_jobs, not patch_jobs — that name is
-- already taken by the pre-existing Linux osupdate feature
-- (005_add_patch_management_tables.sql). The two features are unrelated and
-- must never share a table.

-- Catalog root: one row per maintained app (platform is always 'windows'
-- today; the column exists for future-proofing only, per the agent doc).
CREATE TABLE IF NOT EXISTS maintained_apps (
  id                  BIGSERIAL     PRIMARY KEY,
  slug                VARCHAR(150)  NOT NULL,
  name                VARCHAR(200)  NOT NULL,
  publisher           VARCHAR(200),
  platform            VARCHAR(20)   NOT NULL DEFAULT 'windows',
  package_identifier  VARCHAR(200),
  display_name_match  VARCHAR(200)  NOT NULL,
  fuzzy_match_name    BOOLEAN       NOT NULL DEFAULT FALSE,
  category            VARCHAR(100),
  is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_maintained_apps_slug ON maintained_apps (slug);
CREATE INDEX IF NOT EXISTS idx_maintained_apps_active ON maintained_apps (is_active);

-- One row per known version of a maintained app; exactly one is_current=true
-- row per maintained_app_id at a time. install_script/uninstall_script are
-- the literal PowerShell text sent verbatim to the agent as arg2's
-- install_script/uninstall_script fields (never templated server-side).
CREATE TABLE IF NOT EXISTS maintained_app_versions (
  id                  BIGSERIAL     PRIMARY KEY,
  maintained_app_id   BIGINT        NOT NULL REFERENCES maintained_apps(id) ON DELETE CASCADE,
  version             VARCHAR(50)   NOT NULL,
  installer_url       TEXT,
  sha256              VARCHAR(64),
  install_script      TEXT          NOT NULL,
  uninstall_script    TEXT          NOT NULL,
  is_current          BOOLEAN       NOT NULL DEFAULT FALSE,
  source_ref          VARCHAR(300),
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mav_app_version ON maintained_app_versions (maintained_app_id, version);
CREATE INDEX IF NOT EXISTS idx_mav_current ON maintained_app_versions (maintained_app_id, is_current);

-- Per-host job tracking for an install/uninstall dispatch. id IS the job_id
-- sent to the agent as arg1 (a UUID already satisfies the agent's
-- ^[A-Za-z0-9_-]{1,64}$ charset, no transform needed).
-- status: pending -> acknowledged -> success|failure, or rejected (agent
-- refused synchronously) | timed_out (no completion push arrived in time —
-- not currently swept automatically, left for a future sweeper if needed).
CREATE TABLE IF NOT EXISTS windows_patch_jobs (
  id                          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  host_identifier             VARCHAR(128)  NOT NULL,
  maintained_app_id           BIGINT        NOT NULL REFERENCES maintained_apps(id),
  maintained_app_version_id   BIGINT        NOT NULL REFERENCES maintained_app_versions(id),
  action                      VARCHAR(20)   NOT NULL,
  status                      VARCHAR(20)   NOT NULL DEFAULT 'pending',
  requested_by_user_id        INTEGER,
  requested_by_email          VARCHAR(255),
  request_reason              TEXT,
  requested_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  acknowledged_at             TIMESTAMPTZ,
  completed_at                TIMESTAMPTZ,
  exit_code                   INTEGER,
  outcome_reason              TEXT,
  installed_version           VARCHAR(50),
  duration_ms                 INTEGER
);
CREATE INDEX IF NOT EXISTS idx_wpj_host ON windows_patch_jobs (host_identifier);
CREATE INDEX IF NOT EXISTS idx_wpj_status ON windows_patch_jobs (status);
-- listJobs() (controllers/nodes/windows_patch_management.ts) always does
-- ORDER BY requested_at DESC LIMIT 200, including the unrestricted/group-scoped
-- branches hit whenever the caller omits host_identifier (the frontend's
-- default Job History view) — without this, every such load requires a full
-- sort of the table, which only grows over the feature's lifetime.
CREATE INDEX IF NOT EXISTS idx_wpj_requested_at ON windows_patch_jobs (requested_at DESC);
