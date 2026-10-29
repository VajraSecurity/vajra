-- Documentation mirror of the FIM registry bootstrap block in src/index.ts
-- ('fim-registry-tables' startup step), which is the DDL that actually runs on boot.
-- Canonical source: vajra_server/sql/migrations/0005_fim_registry.sql. Keep all three in sync.
-- Idempotent; safe to re-run.

-- Per-node, configurable Windows registry integrity monitoring.
-- Design: docs/FIM_REGISTRY_DESIGN.md (§3.11 DDL, §4 security). Builds on 0004_fim.sql.
-- Additive and idempotent; safe to re-run. Down migration: see the bottom of this file.
--
-- Model: one MANAGED fim_policies row per Windows node (managed_kind = 'registry_node'),
-- materialised at publish time from the layers catalog -> profile -> group -> node. The
-- vajra_fim worker treats it like any other policy (node target = that host only).

-- Concurrency: every FIM DDL block takes the shared advisory lock 727299 (worker migrations and the
-- backend boot DDL alike). Apply this file in ONE transaction (psql -1 -v ON_ERROR_STOP=1 -f ...)
-- so the lock is held for the whole file.
SELECT pg_advisory_xact_lock(727299);

-- ---------------------------------------------------------------------------------------------
-- Managed per-node policies
-- ---------------------------------------------------------------------------------------------
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_policies' AND column_name = 'managed_kind') THEN
        ALTER TABLE fim_policies ADD COLUMN managed_kind text;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_policies' AND column_name = 'managed_host') THEN
        ALTER TABLE fim_policies ADD COLUMN managed_host varchar(40);
    END IF;
END $fimddl$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_policies_managed_kind_check') THEN
        ALTER TABLE fim_policies ADD CONSTRAINT fim_policies_managed_kind_check
            CHECK (managed_kind IS NULL OR managed_kind IN ('registry_node'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_policies_managed_host_check') THEN
        ALTER TABLE fim_policies ADD CONSTRAINT fim_policies_managed_host_check
            CHECK ((managed_kind IS NULL) = (managed_host IS NULL));
    END IF;
END $$;
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_policies_managed_host') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_policies_managed_host
    ON fim_policies (managed_host) WHERE managed_kind = 'registry_node';
    END IF;
END $fimddl$;

-- Per-entry scan bookkeeping used by the worker (FIM_REGISTRY_DESIGN §3.8 W3, §4.7):
--   hive_seen     {"<sid lower-case>": <unix ts>} last scan in which each user hive was loaded
--   last_empty_at last empty scan of the entry; empty_streak = consecutive empty scans
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_host_entry' AND column_name = 'hive_seen') THEN
        ALTER TABLE fim_host_entry ADD COLUMN hive_seen jsonb;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_host_entry' AND column_name = 'last_empty_at') THEN
        ALTER TABLE fim_host_entry ADD COLUMN last_empty_at bigint;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_host_entry' AND column_name = 'empty_streak') THEN
        ALTER TABLE fim_host_entry ADD COLUMN empty_streak integer NOT NULL DEFAULT 0;
    END IF;
END $fimddl$;

-- ---------------------------------------------------------------------------------------------
-- Feature switch (FIM_REGISTRY_MANAGED). Single row. Off by default: nothing is created or
-- published for any node until a Super Admin turns it on (audited).
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_reg_settings (
    id               boolean PRIMARY KEY DEFAULT true CHECK (id),
    managed_enabled  boolean NOT NULL DEFAULT false,
    -- Designated waiver approvers [{userId, email}] besides Super Admins (set by a Super Admin):
    -- keeps the two-person rule usable when there is a single Super Admin.
    approvers        jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_by       text,
    updated_at       bigint
);
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_settings' AND column_name = 'approvers') THEN
        ALTER TABLE fim_reg_settings ADD COLUMN approvers jsonb NOT NULL DEFAULT '[]'::jsonb;
    END IF;
END $fimddl$;
-- Resume point of a time-boxed reconcile sweep (shared by all backend instances, survives restarts).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_settings' AND column_name = 'sweep_cursor') THEN
        ALTER TABLE fim_reg_settings ADD COLUMN sweep_cursor text NOT NULL DEFAULT '';
    END IF;
END $fimddl$;
INSERT INTO fim_reg_settings (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------------------------
-- Layers: profiles (L1), group/node assignments (L2/L3), rules, waivers
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_reg_profiles (
    id                 bigserial PRIMARY KEY,
    name               text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 120),
    description        text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    tier               text NOT NULL DEFAULT 'essential'
                       CHECK (tier IN ('essential','recommended','comprehensive')),
    is_default         boolean NOT NULL DEFAULT false,
    scan_interval_secs integer NOT NULL DEFAULT 3600 CHECK (scan_interval_secs BETWEEN 300 AND 86400),
    mode               text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('learn','enforce')),
    version            integer NOT NULL DEFAULT 1,          -- optimistic concurrency
    created_by text, updated_by text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_reg_profiles_default') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_reg_profiles_default ON fim_reg_profiles (is_default) WHERE is_default;
    END IF;
END $fimddl$;

CREATE TABLE IF NOT EXISTS fim_reg_assignments (
    scope_type   text NOT NULL CHECK (scope_type IN ('group','node')),
    scope_value  text NOT NULL CHECK (length(scope_value) BETWEEN 1 AND 255), -- owner_group_id | host_identifier
    profile_id   bigint REFERENCES fim_reg_profiles(id) ON DELETE RESTRICT,   -- NULL = inherit
    tier         text CHECK (tier IS NULL OR tier IN ('essential','recommended','comprehensive')),
    version      integer NOT NULL DEFAULT 1,
    updated_by text, updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_type, scope_value)
);

-- Protected-entry exceptions: two people (requester <> approver, enforced here), at most 30 days.
CREATE TABLE IF NOT EXISTS fim_reg_waivers (
    id            bigserial PRIMARY KEY,
    entry_key     text NOT NULL CHECK (length(entry_key) BETWEEN 1 AND 200),
    scope_type    text NOT NULL CHECK (scope_type IN ('profile','group','node')),
    scope_value   text NOT NULL CHECK (length(scope_value) BETWEEN 1 AND 255),
    action        text NOT NULL CHECK (action IN ('disable','narrow','lower_severity','opt_out')),
    reason        text NOT NULL CHECK (length(reason) BETWEEN 10 AND 2000),
    requested_by  text NOT NULL, requested_at bigint NOT NULL,
    approved_by   text, approved_at bigint,
    decision_note text,
    expires_at    bigint NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','approved','rejected','revoked','expired')),
    revoked_by    text, revoked_at bigint,
    -- A waiver is bound to ONE exact rule (layer = scope_type, scope_value, op, target, spec) and is
    -- single-use: rule_hash = sha256(canonical JSON of that rule); rule_id = the rule created from it.
    rule_op       text, rule_target text, rule_spec jsonb, rule_hash text, rule_id bigint,
    -- Two-person rule on USER IDS (an e-mail can be changed): requester id <> approver id.
    requested_by_user_id bigint, approved_by_user_id bigint,
    CHECK (approved_by IS NULL OR lower(approved_by) <> lower(requested_by)),
    CHECK (expires_at > requested_at AND expires_at <= requested_at + 30 * 86400),
    CHECK (status <> 'approved' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'rule_op') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN rule_op text;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'rule_target') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN rule_target text;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'rule_spec') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN rule_spec jsonb;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'rule_hash') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN rule_hash text;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'rule_id') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN rule_id bigint;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'requested_by_user_id') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN requested_by_user_id bigint;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'approved_by_user_id') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN approved_by_user_id bigint;
    END IF;
END $fimddl$;
-- 'super_admin' | 'approver': an approval by a designated approver stays valid only while that
-- user is still designated (re-checked by the resolver).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_waivers' AND column_name = 'approved_by_role') THEN
        ALTER TABLE fim_reg_waivers ADD COLUMN approved_by_role text;
    END IF;
END $fimddl$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_reg_waivers_distinct_user_ids') THEN
        ALTER TABLE fim_reg_waivers ADD CONSTRAINT fim_reg_waivers_distinct_user_ids
            CHECK (approved_by_user_id IS NULL OR (requested_by_user_id IS NOT NULL AND approved_by_user_id <> requested_by_user_id));
    END IF;
END $$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_waivers_scope') IS NULL THEN
        CREATE INDEX idx_fim_reg_waivers_scope ON fim_reg_waivers (scope_type, scope_value, entry_key);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_waivers_status') IS NULL THEN
        CREATE INDEX idx_fim_reg_waivers_status ON fim_reg_waivers (status, expires_at);
    END IF;
END $fimddl$;

CREATE TABLE IF NOT EXISTS fim_reg_rules (
    id           bigserial PRIMARY KEY,
    layer        text NOT NULL CHECK (layer IN ('profile','group','node')),
    scope_value  text NOT NULL CHECK (length(scope_value) BETWEEN 1 AND 255), -- profile id | owner_group_id | host_identifier
    op           text NOT NULL CHECK (op IN ('add','disable','exclude','filter','severity')),
    target       text NOT NULL CHECK (length(target) BETWEEN 1 AND 200),       -- catalog id | custom:<hex16> | '*'
    spec         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (length(spec::text) <= 32768),
    reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    waiver_id    bigint REFERENCES fim_reg_waivers(id),
    status       text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_by text NOT NULL, created_at bigint NOT NULL,
    revoked_by text, revoked_at bigint
);
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_reg_rules_active') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_reg_rules_active
    ON fim_reg_rules (layer, scope_value, op, target) WHERE status = 'active';
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_rules_scope') IS NULL THEN
        CREATE INDEX idx_fim_reg_rules_scope ON fim_reg_rules (layer, scope_value) WHERE status = 'active';
    END IF;
END $fimddl$;
-- Single use: a waiver backs at most one rule, ever (revoked rules keep it consumed).
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_reg_rules_waiver') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_reg_rules_waiver ON fim_reg_rules (waiver_id) WHERE waiver_id IS NOT NULL;
    END IF;
END $fimddl$;

-- ---------------------------------------------------------------------------------------------
-- Stable entry slots per host (indices are never reused) and the resolved/published state
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_reg_slots (
    host_identifier varchar(40) NOT NULL,
    slot_idx        integer NOT NULL CHECK (slot_idx >= 0),
    entry_key       text NOT NULL,
    fingerprint     text NOT NULL,
    created_at      bigint NOT NULL,
    retired_at      bigint,
    purge_after     bigint,                           -- soft-retire window end (baseline rows kept until then)
    purged_at       bigint,
    PRIMARY KEY (host_identifier, slot_idx)
);
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_reg_slots_live') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_reg_slots_live
    ON fim_reg_slots (host_identifier, entry_key) WHERE retired_at IS NULL;
    END IF;
END $fimddl$;

CREATE TABLE IF NOT EXISTS fim_reg_effective (
    host_identifier varchar(40) PRIMARY KEY,
    policy_id       bigint,                           -- managed fim_policies.id
    catalog_version integer NOT NULL,
    owner_group_id  text,                             -- group at last resolution (group-move detection)
    resolved        jsonb NOT NULL,                   -- entries + sources (for the UI)
    resolved_hash   text NOT NULL,
    resolved_at     bigint NOT NULL,
    published_hash  text,
    published_at    bigint, published_by text,
    status          text NOT NULL CHECK (status IN ('in_sync','pending','needs_init','invalid')),
    error           text,
    invalid_since   bigint,
    needs_init_since bigint,
    inputs_key      text,                             -- digest of the resolution inputs (reconcile cache)
    auto_attempt_hash text                            -- resolution hash of the last automatic publish attempt (invalid back-off)
);
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_effective' AND column_name = 'inputs_key') THEN
        ALTER TABLE fim_reg_effective ADD COLUMN inputs_key text;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_effective' AND column_name = 'auto_attempt_hash') THEN
        ALTER TABLE fim_reg_effective ADD COLUMN auto_attempt_hash text;
    END IF;
END $fimddl$;
-- Waiver ids the PUBLISHED config relies on: when one stops being valid (expired, revoked) the node
-- is republished on the next sweep regardless of the auto-publish budget.
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_effective' AND column_name = 'published_waivers') THEN
        ALTER TABLE fim_reg_effective ADD COLUMN published_waivers jsonb NOT NULL DEFAULT '[]'::jsonb;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_effective_status') IS NULL THEN
        CREATE INDEX idx_fim_reg_effective_status ON fim_reg_effective (status);
    END IF;
END $fimddl$;

-- ---------------------------------------------------------------------------------------------
-- Rollback source + tamper evidence: append-only, hash-chained snapshot of a scope's
-- assignment + active rules after every change.
--   row_hash = sha256(prev_hash || canonical JSON of {at, actor, reason, scope_type, scope_value, snapshot})
-- UPDATE/DELETE/TRUNCATE are refused by trigger unless the CURRENT ROLE is a member of
-- fim_history_admin AND the session flag vajra.fim_history_maintenance = 'on' is set.
-- Recommended deployment (least privilege): the tables are owned by a separate owner role; the
-- application role gets SELECT/INSERT on fim_reg_history (no UPDATE/DELETE/TRUNCATE) and is NOT a
-- member of fim_history_admin. Single-role deployments where the application connects as the
-- owner or a superuser are WEAKER (a superuser is a member of every role): there the hash chain
-- (HMAC keyed outside the database) plus the head anchored in the audit trail is the tamper
-- evidence. row_hash = HMAC-SHA256(key, prev_hash || canonical row) when a key is configured.
-- Least-privilege setup (run once by a DBA; role names are examples):
--   CREATE ROLE vajra_fim_owner NOLOGIN;
--   ALTER TABLE fim_reg_history OWNER TO vajra_fim_owner;
--   REVOKE ALL ON fim_reg_history FROM vajra_app;
--   GRANT SELECT, INSERT ON fim_reg_history TO vajra_app;
--   GRANT USAGE ON SEQUENCE fim_reg_history_id_seq TO vajra_app;
--   -- maintenance only through a separate login that is a member of fim_history_admin:
--   GRANT fim_history_admin TO vajra_fim_maint;
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_reg_history (
    id          bigserial PRIMARY KEY,
    scope_type  text NOT NULL CHECK (scope_type IN ('profile','group','node','settings')),
    scope_value text NOT NULL,
    snapshot    jsonb NOT NULL,
    actor       text NOT NULL, at bigint NOT NULL, reason text,
    prev_hash   text, row_hash text NOT NULL
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_history_scope') IS NULL THEN
        CREATE INDEX idx_fim_reg_history_scope ON fim_reg_history (scope_type, scope_value, id DESC);
    END IF;
END $fimddl$;
-- Key id of the HMAC key a row was hashed with (key ring: rotation keeps old rows verifiable).
-- NULL = written without a key (weaker; reported by verification).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_history' AND column_name = 'key_id') THEN
        ALTER TABLE fim_reg_history ADD COLUMN key_id text;
    END IF;
END $fimddl$;
-- Fingerprint of the key behind each key id (HMAC of a fixed string; reveals nothing about the key):
-- an id reused with a different key is reported as a key mismatch instead of tampering.
CREATE TABLE IF NOT EXISTS fim_reg_history_keys (
    key_id        text PRIMARY KEY,
    fingerprint   text NOT NULL,
    first_used_at bigint NOT NULL
);
-- Append-only (key rows are evidence: deleting or rewriting them must not turn 'broken' into ok).
CREATE OR REPLACE FUNCTION fim_reg_history_keys_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('vajra.fim_history_maintenance', true) = 'on'
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin')
       AND pg_has_role(current_user, 'fim_history_admin', 'MEMBER') THEN
        IF TG_LEVEL = 'STATEMENT' THEN RETURN NULL; END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'fim_reg_history_keys is append-only';
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_keys_guard' AND tgrelid = 'fim_reg_history_keys'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_keys_guard BEFORE UPDATE OR DELETE ON fim_reg_history_keys
    FOR EACH ROW EXECUTE FUNCTION fim_reg_history_keys_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_keys_guard' AND tgrelid = 'fim_reg_history_keys'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history_keys ENABLE TRIGGER trg_fim_reg_history_keys_guard;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_keys_no_truncate' AND tgrelid = 'fim_reg_history_keys'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_keys_no_truncate BEFORE TRUNCATE ON fim_reg_history_keys
    FOR EACH STATEMENT EXECUTE FUNCTION fim_reg_history_keys_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_keys_no_truncate' AND tgrelid = 'fim_reg_history_keys'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history_keys ENABLE TRIGGER trg_fim_reg_history_keys_no_truncate;
    END IF;
END $fimddl$;
-- Anchor outbox, written in the SAME transaction as every history append. A flusher copies the
-- newest head into the audit trail (another database) and stamps anchored_at; verification
-- reports 'unverifiable' while an anchor write is overdue and checks that every outbox head
-- still exists in the chain (deleting the newest rows is detected even before anchoring).
CREATE TABLE IF NOT EXISTS fim_reg_anchor_outbox (
    history_id  bigint PRIMARY KEY,
    row_hash    text NOT NULL,
    row_count   bigint NOT NULL,
    key_id      text,
    created_at  bigint NOT NULL,
    anchored_at bigint
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_anchor_pending') IS NULL THEN
        CREATE INDEX idx_fim_reg_anchor_pending ON fim_reg_anchor_outbox (created_at) WHERE anchored_at IS NULL;
    END IF;
END $fimddl$;
-- The outbox is append-only like the history: only anchored_at may be stamped (NULL -> value);
-- other updates and deletes need fim_history_admin membership AND the maintenance flag.
CREATE OR REPLACE FUNCTION fim_reg_anchor_outbox_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('vajra.fim_history_maintenance', true) = 'on'
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin')
       AND pg_has_role(current_user, 'fim_history_admin', 'MEMBER') THEN
        IF TG_LEVEL = 'STATEMENT' THEN RETURN NULL; END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.anchored_at IS NULL AND NEW.anchored_at IS NOT NULL
       AND NEW.history_id = OLD.history_id AND NEW.row_hash = OLD.row_hash AND NEW.row_count = OLD.row_count
       AND NEW.key_id IS NOT DISTINCT FROM OLD.key_id AND NEW.created_at = OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'fim_reg_anchor_outbox is append-only';
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_anchor_outbox_guard' AND tgrelid = 'fim_reg_anchor_outbox'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_anchor_outbox_guard BEFORE UPDATE OR DELETE ON fim_reg_anchor_outbox
    FOR EACH ROW EXECUTE FUNCTION fim_reg_anchor_outbox_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_anchor_outbox_guard' AND tgrelid = 'fim_reg_anchor_outbox'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_anchor_outbox ENABLE TRIGGER trg_fim_reg_anchor_outbox_guard;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_anchor_outbox_no_truncate' AND tgrelid = 'fim_reg_anchor_outbox'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_anchor_outbox_no_truncate BEFORE TRUNCATE ON fim_reg_anchor_outbox
    FOR EACH STATEMENT EXECUTE FUNCTION fim_reg_anchor_outbox_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_anchor_outbox_no_truncate' AND tgrelid = 'fim_reg_anchor_outbox'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_anchor_outbox ENABLE TRIGGER trg_fim_reg_anchor_outbox_no_truncate;
    END IF;
END $fimddl$;

-- Monotonic high-water mark of the chain head (single row; a trigger forbids decreasing it outside
-- maintenance): deleting the newest history row AND its outbox row is still detected locally.
-- Created ONCE (with the current head, for databases that already have history); never re-seeded
-- afterwards, so truncating or deleting it later is detected instead of silently re-created.
DO $$
BEGIN
    IF to_regclass('fim_reg_history_hwm') IS NULL THEN
        CREATE TABLE fim_reg_history_hwm (
            id         boolean PRIMARY KEY DEFAULT true CHECK (id),
            head_id    bigint NOT NULL DEFAULT 0,
            row_hash   text,
            row_count  bigint NOT NULL DEFAULT 0,
            updated_at bigint
        );
        INSERT INTO fim_reg_history_hwm (id, head_id, row_hash, row_count)
        SELECT true, COALESCE((SELECT max(id) FROM fim_reg_history), 0),
               (SELECT row_hash FROM fim_reg_history ORDER BY id DESC LIMIT 1), (SELECT count(*) FROM fim_reg_history);
    END IF;
END $$;
CREATE OR REPLACE FUNCTION fim_reg_history_hwm_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('vajra.fim_history_maintenance', true) = 'on'
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin')
       AND pg_has_role(current_user, 'fim_history_admin', 'MEMBER') THEN
        IF TG_LEVEL = 'STATEMENT' THEN RETURN NULL; END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.head_id >= OLD.head_id AND NEW.row_count >= OLD.row_count THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'fim_reg_history_hwm can only increase';
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_hwm_guard' AND tgrelid = 'fim_reg_history_hwm'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_hwm_guard BEFORE UPDATE OR DELETE ON fim_reg_history_hwm
    FOR EACH ROW EXECUTE FUNCTION fim_reg_history_hwm_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_hwm_guard' AND tgrelid = 'fim_reg_history_hwm'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history_hwm ENABLE TRIGGER trg_fim_reg_history_hwm_guard;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_hwm_no_truncate' AND tgrelid = 'fim_reg_history_hwm'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_hwm_no_truncate BEFORE TRUNCATE ON fim_reg_history_hwm
    FOR EACH STATEMENT EXECUTE FUNCTION fim_reg_history_hwm_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_hwm_no_truncate' AND tgrelid = 'fim_reg_history_hwm'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history_hwm ENABLE TRIGGER trg_fim_reg_history_hwm_no_truncate;
    END IF;
END $fimddl$;
-- Second, independent monotonic marker of the chain head (another table, its own trigger): losing
-- or resetting ONE of the two markers is detected by comparing them.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_reg_settings' AND column_name = 'history_head_id') THEN
        ALTER TABLE fim_reg_settings ADD COLUMN history_head_id bigint NOT NULL DEFAULT 0;
        UPDATE fim_reg_settings SET history_head_id = COALESCE((SELECT max(id) FROM fim_reg_history), 0) WHERE id;
    END IF;
END $$;
CREATE OR REPLACE FUNCTION fim_reg_settings_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.history_head_id < OLD.history_head_id
       AND NOT (current_setting('vajra.fim_history_maintenance', true) = 'on'
                AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin')
                AND pg_has_role(current_user, 'fim_history_admin', 'MEMBER')) THEN
        RAISE EXCEPTION 'fim_reg_settings.history_head_id can only increase';
    END IF;
    RETURN NEW;
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_settings_head_guard' AND tgrelid = 'fim_reg_settings'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_settings_head_guard BEFORE UPDATE ON fim_reg_settings
    FOR EACH ROW EXECUTE FUNCTION fim_reg_settings_head_guard();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_settings_head_guard' AND tgrelid = 'fim_reg_settings'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_settings ENABLE TRIGGER trg_fim_reg_settings_head_guard;
    END IF;
END $fimddl$;

-- Background jobs (profile-wide publish): one running job per kind, resumable via cursor.
CREATE TABLE IF NOT EXISTS fim_reg_jobs (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('publish_profile')),
    params      jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','failed','cancelled','aborted')),
    total       integer NOT NULL DEFAULT 0,
    done        integer NOT NULL DEFAULT 0,
    failed      integer NOT NULL DEFAULT 0,
    cursor      text NOT NULL DEFAULT '',
    results     jsonb NOT NULL DEFAULT '[]'::jsonb,
    error       text,
    created_by  text,
    created_by_user_id bigint,
    created_at  bigint NOT NULL,
    heartbeat_at bigint,
    finished_at bigint
);
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_reg_jobs_active') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_reg_jobs_active ON fim_reg_jobs (kind) WHERE status IN ('queued','running');
    END IF;
END $fimddl$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_reg_jobs' AND column_name = 'lease_token') THEN
        ALTER TABLE fim_reg_jobs ADD COLUMN lease_token text;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_reg_jobs_status_check' AND pg_get_constraintdef(oid) NOT LIKE '%aborted%') THEN
        ALTER TABLE fim_reg_jobs DROP CONSTRAINT fim_reg_jobs_status_check;
        ALTER TABLE fim_reg_jobs ADD CONSTRAINT fim_reg_jobs_status_check CHECK (status IN ('queued','running','done','failed','cancelled','aborted'));
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin') THEN
        BEGIN
            CREATE ROLE fim_history_admin NOLOGIN;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'fim_history_admin role not created (no CREATEROLE); history maintenance stays disabled';
        END;
    END IF;
END $$;
CREATE OR REPLACE FUNCTION fim_reg_history_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('vajra.fim_history_maintenance', true) = 'on'
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fim_history_admin')
       AND pg_has_role(current_user, 'fim_history_admin', 'MEMBER') THEN
        IF TG_LEVEL = 'STATEMENT' THEN RETURN NULL; END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'fim_reg_history is append-only';
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_no_update' AND tgrelid = 'fim_reg_history'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_no_update BEFORE UPDATE OR DELETE ON fim_reg_history
    FOR EACH ROW EXECUTE FUNCTION fim_reg_history_append_only();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_no_update' AND tgrelid = 'fim_reg_history'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history ENABLE TRIGGER trg_fim_reg_history_no_update;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_no_truncate' AND tgrelid = 'fim_reg_history'::regclass) THEN
        CREATE TRIGGER trg_fim_reg_history_no_truncate BEFORE TRUNCATE ON fim_reg_history
    FOR EACH STATEMENT EXECUTE FUNCTION fim_reg_history_append_only();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_reg_history_no_truncate' AND tgrelid = 'fim_reg_history'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_reg_history ENABLE TRIGGER trg_fim_reg_history_no_truncate;
    END IF;
END $fimddl$;

-- ---------------------------------------------------------------------------------------------
-- Measure: count-only distributed query (two numbers, no registry data) per entry/node.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_reg_measure (
    id              bigserial PRIMARY KEY,
    host_identifier varchar(40) NOT NULL,
    entry_key       text NOT NULL,
    fingerprint     text NOT NULL,                    -- entry fingerprint the measurement applies to
    spec            jsonb NOT NULL,
    queue_id        bigint,
    after_result_id bigint NOT NULL DEFAULT 0,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','failed')),
    rows_count      bigint,
    bytes_count     bigint,
    error           text,
    requested_by    text,
    created_at      bigint NOT NULL,
    completed_at    bigint
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_measure_host') IS NULL THEN
        CREATE INDEX idx_fim_reg_measure_host ON fim_reg_measure (host_identifier, created_at DESC);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_reg_measure_fp') IS NULL THEN
        CREATE INDEX idx_fim_reg_measure_fp ON fim_reg_measure (fingerprint, status);
    END IF;
END $fimddl$;

-- Baseline hygiene findings acknowledged by an analyst (§4.5): one row per (host, item, value hash).
CREATE TABLE IF NOT EXISTS fim_reg_hygiene_ack (
    host_identifier varchar(40) NOT NULL,
    item_path       text NOT NULL,
    sha256          text NOT NULL DEFAULT '',
    acked_by        text NOT NULL,
    acked_at        bigint NOT NULL,
    note            text NOT NULL CHECK (length(note) BETWEEN 1 AND 2000),
    PRIMARY KEY (host_identifier, item_path, sha256)
);

-- ---------------------------------------------------------------------------------------------
-- Seed profiles (§3.15 step 2). The default profile is Essential.
-- ---------------------------------------------------------------------------------------------
INSERT INTO fim_reg_profiles (name, description, tier, is_default, created_by, updated_by)
SELECT 'Workstation default', 'Essential registry coverage for every Windows node (protected entries).',
       'essential', NOT EXISTS (SELECT 1 FROM fim_reg_profiles WHERE is_default), 'migration', 'migration'
WHERE NOT EXISTS (SELECT 1 FROM fim_reg_profiles WHERE name = 'Workstation default');
INSERT INTO fim_reg_profiles (name, description, tier, is_default, created_by, updated_by)
SELECT 'Server', 'Recommended registry coverage (suggested for servers).', 'recommended', false, 'migration', 'migration'
WHERE NOT EXISTS (SELECT 1 FROM fim_reg_profiles WHERE name = 'Server');

-- ---------------------------------------------------------------------------------------------
-- Down migration (manual; run only after every managed policy was disabled and deleted
-- through the API so nodes.config_id is clean):
--   SET vajra.fim_history_maintenance = 'on';
--   DROP TABLE IF EXISTS fim_reg_hygiene_ack, fim_reg_measure, fim_reg_history, fim_reg_effective,
--       fim_reg_slots, fim_reg_rules, fim_reg_waivers, fim_reg_assignments, fim_reg_profiles,
--       fim_reg_settings;
--   DROP FUNCTION IF EXISTS fim_reg_history_append_only();
--   DROP INDEX IF EXISTS uq_fim_policies_managed_host;
--   ALTER TABLE fim_policies DROP CONSTRAINT IF EXISTS fim_policies_managed_host_check,
--       DROP CONSTRAINT IF EXISTS fim_policies_managed_kind_check,
--       DROP COLUMN IF EXISTS managed_host, DROP COLUMN IF EXISTS managed_kind;
--   ALTER TABLE fim_host_entry DROP COLUMN IF EXISTS hive_seen, DROP COLUMN IF EXISTS last_empty_at,
--       DROP COLUMN IF EXISTS empty_streak;
-- ---------------------------------------------------------------------------------------------
