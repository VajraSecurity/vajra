-- Documentation mirror of the FIM bootstrap block in src/index.ts
-- ('fim-tables' startup step), which is the DDL that actually runs on boot.
-- Canonical source: vajra_server/sql/migrations/0004_fim.sql (plus the published_rev
-- column, which the API owns). Keep all in sync. Idempotent; safe to re-run.

CREATE TABLE IF NOT EXISTS fim_policies (
    id                bigserial PRIMARY KEY,
    name              text NOT NULL UNIQUE,
    description       text NOT NULL DEFAULT '',
    os_platform       text NOT NULL DEFAULT 'linux'
                      CHECK (os_platform IN ('linux','windows')),
    -- [{ "path": "/etc/%%", "severity": "high", "category": "config",
    --    "ignore": ["/etc/mtab"], "hash": true }, ...]
    paths             jsonb NOT NULL DEFAULT '[]'::jsonb,
    scan_interval_secs integer NOT NULL DEFAULT 3600 CHECK (scan_interval_secs >= 60),
    realtime          boolean NOT NULL DEFAULT true,
    -- enforce: raise drift + alerts. learn: report-only (drift rows, no alerts). Baselines
    -- NEVER change automatically in either mode: only Initialize / approve change them.
    mode              text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('learn','enforce')),
    -- Unused since baselines became button-only (kept for compatibility).
    learn_scans       integer NOT NULL DEFAULT 2 CHECK (learn_scans >= 1),
    enabled           boolean NOT NULL DEFAULT true,
    -- Bumped by the API whenever paths/ignores or os_platform change. Scans produced under an
    -- older rev are ignored (their coverage is unknown). Baselines are NOT touched by a bump:
    -- files under newly added paths show as drift until you Initialize the baseline again.
    rev               integer NOT NULL DEFAULT 1,
    -- rev as of the last publish (NULL = not published); rev <> published_rev => unpublished edits.
    published_rev     integer,
    template          text,
    -- config_queries.id this policy is published as (managed by the API).
    config_query_id   bigint,
    created_by        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Who the policy applies to. target_type: all | group (nodes.device_group) | node (host_identifier)
CREATE TABLE IF NOT EXISTS fim_policy_targets (
    policy_id    bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    target_type  text NOT NULL CHECK (target_type IN ('all','group','node')),
    target_value text NOT NULL DEFAULT '',
    PRIMARY KEY (policy_id, target_type, target_value)
);

-- Per (policy, host) lifecycle.
CREATE TABLE IF NOT EXISTS fim_host_state (
    policy_id     bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier varchar(40) NOT NULL,
    state         text NOT NULL DEFAULT 'learning' CHECK (state IN ('learning','locked')),
    rev           integer NOT NULL DEFAULT 0,
    scan_count    integer NOT NULL DEFAULT 0,
    last_scan_at  bigint,
    locked_at     bigint,
    PRIMARY KEY (policy_id, host_identifier)
);

CREATE TABLE IF NOT EXISTS fim_baseline (
    id            bigserial PRIMARY KEY,
    policy_id     bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier varchar(40) NOT NULL,
    path          text NOT NULL,
    sha256        text,
    md5           text,
    size          bigint,
    mode          text,
    uid           bigint,
    gid           bigint,
    mtime         bigint,
    first_seen    bigint NOT NULL,
    last_seen     bigint NOT NULL,
    approved_by   text,
    -- file: regular file (hashed). directory: directories and other non-regular objects
    -- (mode/uid/gid only). item: a non-file object (registry value, ACL entry, xattr, table row);
    -- for items 'path' is the item key and 'data' holds the observed columns.
    kind          text NOT NULL DEFAULT 'file' CHECK (kind IN ('file','directory','item')),
    entry_idx     integer,
    data          jsonb,
    UNIQUE (policy_id, host_identifier, path)
);
CREATE INDEX IF NOT EXISTS idx_fim_baseline_host ON fim_baseline (host_identifier, policy_id);
-- Case-insensitive lookups for Windows real-time events.
CREATE INDEX IF NOT EXISTS idx_fim_baseline_lowerpath ON fim_baseline (policy_id, host_identifier, lower(path));

-- Drift is audit evidence: deliberately NO foreign key to fim_policies so that
-- deleting a policy never deletes its drift history (policy_name is snapshotted).
CREATE TABLE IF NOT EXISTS fim_drift (
    id            bigserial PRIMARY KEY,
    policy_id     bigint NOT NULL,
    policy_name   text,
    host_identifier varchar(40) NOT NULL,
    hostname      text,
    path          text NOT NULL,
    change_type   text NOT NULL CHECK (change_type IN ('added','removed','modified','attributes')),
    source        text NOT NULL CHECK (source IN ('scan','realtime')),
    severity      text NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
    old_sha256    text,
    new_sha256    text,
    old_attrs     jsonb,
    new_attrs     jsonb,
    actor_process text,
    actor_user    text,
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open','approved','rejected','ignored')),
    occurrences   integer NOT NULL DEFAULT 1,
    detected_at   bigint NOT NULL,
    last_seen_at  bigint NOT NULL,
    resolved_by   text,
    resolved_at   bigint,
    note          text,
    alert_id      bigint,
    kind          text NOT NULL DEFAULT 'file' CHECK (kind IN ('file','directory','item')),
    entry_idx     integer
);
-- One open drift per (policy, host, path): repeats bump occurrences.
CREATE UNIQUE INDEX IF NOT EXISTS uq_fim_drift_open
    ON fim_drift (policy_id, host_identifier, path) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_fim_drift_status_time ON fim_drift (status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_fim_drift_host ON fim_drift (host_identifier, detected_at DESC);

-- Per (policy, host, scan entry) bookkeeping: each path entry is scanned by its own
-- osquery query, so each has its own "first scan with current paths" moment.
CREATE TABLE IF NOT EXISTS fim_host_entry (
    policy_id       bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier varchar(40) NOT NULL,
    entry_idx       integer NOT NULL,
    rev             integer NOT NULL,
    last_scan_at    bigint,
    PRIMARY KEY (policy_id, host_identifier, entry_idx)
);

-- "Initialize baseline" (tripwire --init): one distributed query per (host, path entry),
-- delivered through query_queue; results come back in query_result keyed by queue_id.
CREATE TABLE IF NOT EXISTS fim_init_requests (
    id               bigserial PRIMARY KEY,
    batch_id         text NOT NULL,
    policy_id        bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier  varchar(40) NOT NULL,
    entry_idx        integer NOT NULL,
    rev              integer NOT NULL,
    queue_id         bigint,
    after_result_id  bigint NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','done','failed','expired')),
    requested_by     text,
    note             text,
    created_at       bigint NOT NULL,
    completed_at     bigint,
    file_count       integer,
    error            text
);
CREATE INDEX IF NOT EXISTS idx_fim_init_status ON fim_init_requests (status, created_at);
CREATE INDEX IF NOT EXISTS idx_fim_init_host ON fim_init_requests (policy_id, host_identifier, created_at DESC);

-- One row per baseline (re)initialisation of a (policy, host). digest = sha256 over the
-- sorted "path, sha256, mode, uid, gid" lines of the baseline as initialised.
CREATE TABLE IF NOT EXISTS fim_baseline_version (
    id               bigserial PRIMARY KEY,
    policy_id        bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier  varchar(40) NOT NULL,
    version          integer NOT NULL,
    reason           text NOT NULL DEFAULT 'init',
    created_by       text,
    note             text,
    created_at       bigint NOT NULL,
    file_count       integer NOT NULL,
    digest           text NOT NULL,
    UNIQUE (policy_id, host_identifier, version)
);

-- Worker read watermarks per source table.
CREATE TABLE IF NOT EXISTS fim_cursors (
    source   text PRIMARY KEY,
    last_id  bigint NOT NULL DEFAULT 0
);

-- Upgrade path for databases created by earlier revisions of this schema.
ALTER TABLE fim_policies   ADD COLUMN IF NOT EXISTS rev integer NOT NULL DEFAULT 1;
ALTER TABLE fim_host_state ADD COLUMN IF NOT EXISTS rev integer NOT NULL DEFAULT 0;
-- rev the currently published config was generated from (NULL = not published).
ALTER TABLE fim_policies   ADD COLUMN IF NOT EXISTS published_rev integer;
-- Drift is audit evidence: no FK to fim_policies; policy_name is snapshotted.
ALTER TABLE fim_drift      DROP CONSTRAINT IF EXISTS fim_drift_policy_id_fkey;
ALTER TABLE fim_drift      ADD COLUMN IF NOT EXISTS policy_name text;
ALTER TABLE fim_baseline   ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'file';
ALTER TABLE fim_baseline   ADD COLUMN IF NOT EXISTS entry_idx integer;
ALTER TABLE fim_baseline   ADD COLUMN IF NOT EXISTS data jsonb;
ALTER TABLE fim_drift      ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'file';
ALTER TABLE fim_drift      ADD COLUMN IF NOT EXISTS entry_idx integer;
