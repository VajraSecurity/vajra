/**
 * DDL of the per-node registry coverage tables (FIM_REGISTRY_DESIGN §3.11), run on boot by the
 * 'fim-registry-tables' startup step in src/index.ts. Byte-for-byte the canonical
 * vajra_server/sql/migrations/0005_fim_registry.sql; backend/migrations/031_add_fim_registry.sql is
 * the documentation mirror. src/test/utils/fimRegistry.selftest.ts fails when they drift apart.
 */
export const FIM_REGISTRY_DDL = `-- Per-node, configurable Windows registry integrity monitoring.
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
`;

/** Canonical vajra_server/sql/migrations/0006_fim_verify.sql (mirror backend/migrations/032_add_fim_verify.sql). */
export const FIM_VERIFY_DDL = `-- Real-time registry drift -> targeted check scan (docs/FIM_REGISTRY_DESIGN.md §3.9, plan step 14).
-- Additive and idempotent. Requires 0004_fim.sql.
-- DEPLOY ORDER: apply 0006 and then 0007_fim_worker_schema.sql, THEN restart/upgrade the vajra_fim
-- worker. Do not run a worker binary older than schema v7 against these indexes (see 0007 header
-- for the four worker x index combinations). The backend applies 0005-0007 on boot.
--
-- A win_registry_events change raises drift at once (with the actor) and queues ONE distributed
-- query with that entry's own scan SQL (at most one per host+entry per 30 s). The answer is diffed
-- like a scheduled scan (never replacing the baseline): it confirms the drift in osquery's format
-- (new_sha256 / new_attrs from the scan, confirmed_at), or, when the value is back to the
-- baseline, keeps the drift OPEN and sets reverted = true (tamper-then-revert stays visible).

-- Concurrency: every FIM DDL block takes the shared advisory lock 727299 (worker migrations and the
-- backend boot DDL alike). Apply this file in ONE transaction (psql -1 -v ON_ERROR_STOP=1 -f ...)
-- so the lock is held for the whole file.
SELECT pg_advisory_xact_lock(727299);

CREATE TABLE IF NOT EXISTS fim_verify_requests (
    id               bigserial PRIMARY KEY,
    policy_id        bigint NOT NULL REFERENCES fim_policies(id) ON DELETE CASCADE,
    host_identifier  varchar(40) NOT NULL,
    entry_idx        integer NOT NULL,
    rev              integer NOT NULL,
    drift_id         bigint,
    queue_id         bigint,
    after_result_id  bigint NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','failed','expired')),
    created_at       bigint NOT NULL,
    completed_at     bigint,
    error            text
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_verify_status') IS NULL THEN
        CREATE INDEX idx_fim_verify_status ON fim_verify_requests (status, created_at);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_verify_slot') IS NULL THEN
        CREATE INDEX idx_fim_verify_slot ON fim_verify_requests (policy_id, host_identifier, entry_idx, created_at DESC);
    END IF;
END $fimddl$;

DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_drift' AND column_name = 'reverted') THEN
        ALTER TABLE fim_drift ADD COLUMN reverted boolean NOT NULL DEFAULT false;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_drift' AND column_name = 'confirmed_at') THEN
        ALTER TABLE fim_drift ADD COLUMN confirmed_at bigint;
    END IF;
END $fimddl$;

-- Registry item identity is case-insensitive (Windows registry names are): real-time events carry
-- the stored case, scans the pattern's literal case. One OPEN drift per (policy, host, item) with
-- registry item keys compared by ONE folding rule shared by the worker (ascii_lower), this index,
-- the worker's lookups and the approve path adoption: lower(path COLLATE "C"), which folds ASCII
-- letters only (a database-collation lower() would also fold non-ASCII letters the worker keeps
-- distinct). File paths stay case-sensitive.
--
-- Existing open duplicates that differ only in ASCII letter case are merged before the index is
-- built. The SURVIVOR is the row with the most recent last_seen_at (ties: highest id), because it
-- holds the latest evidence (actor, new hash, new attributes). It receives the summed occurrences,
-- the earliest detected_at and the highest severity of the group. The other rows are closed as
-- 'ignored' with a note naming the survivor, and their still-open linked console alerts are closed
-- with the same remark (an open alert must not point at a closed drift).
DO $$
BEGIN
    CREATE TEMP TABLE fim_ci_dup ON COMMIT DROP AS
    SELECT id, keep_id FROM (
        SELECT id, first_value(id) OVER (PARTITION BY policy_id, host_identifier, lower(path COLLATE "C")
                                          ORDER BY last_seen_at DESC NULLS LAST, id DESC) AS keep_id
        FROM fim_drift WHERE status = 'open' AND kind = 'item' AND path LIKE 'registry|%') g
    WHERE id <> keep_id;
    IF EXISTS (SELECT 1 FROM fim_ci_dup) THEN
        UPDATE fim_drift s SET occurrences = s.occurrences + a.occ,
               detected_at = LEAST(s.detected_at, a.det),
               severity = CASE WHEN a.rnk > (CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                               THEN a.sev ELSE s.severity END,
               note = left(COALESCE(s.note || ' | ', '') || 'Merged ' || a.n || ' open duplicate(s) differing only in letter case', 2000)
        FROM (SELECT c.keep_id, sum(d.occurrences) AS occ, min(d.detected_at) AS det, count(*) AS n,
                     max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS rnk,
                     (array_agg(d.severity ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC))[1] AS sev
              FROM fim_ci_dup c JOIN fim_drift d ON d.id = c.id GROUP BY c.keep_id) a
        WHERE s.id = a.keep_id;
        UPDATE alerts a SET is_open = false,
               remarks = left(COALESCE(a.remarks || ' | ', '') || 'Closed by migration: its drift was merged into drift #' || c.keep_id || ' (same registry item, different letter case)', 2000)
        FROM fim_ci_dup c JOIN fim_drift d ON d.id = c.id
        WHERE a.is_open AND a.alert_type = 'fim' AND a.host_identifier = d.host_identifier
          AND (a.id = d.alert_id OR substring(a.metadata from '"drift_id"[[:space:]]*:[[:space:]]*"?([0-9]{1,15})') = d.id::text);
        UPDATE fim_drift d SET status = 'ignored', resolved_by = 'migration', resolved_at = extract(epoch FROM now())::bigint,
               note = left(COALESCE(d.note || ' | ', '') || 'Merged into drift #' || c.keep_id || ' (same registry item, differs only in letter case; the survivor has the latest evidence)', 2000)
        FROM fim_ci_dup c WHERE d.id = c.id;
    END IF;
    DROP TABLE fim_ci_dup;
    -- An index built by an earlier revision of this migration used the database collation: replace it.
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_ci' AND indexdef NOT LIKE '%COLLATE%') THEN
        DROP INDEX uq_fim_drift_open_ci;
    END IF;
END $$;
-- Case-insensitive baseline lookups (worker + approve path adoption) use the same expression.
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_baseline_lowerpath_c') IS NULL THEN
        CREATE INDEX idx_fim_baseline_lowerpath_c ON fim_baseline (policy_id, host_identifier, lower(path COLLATE "C"));
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('uq_fim_drift_open_ci') IS NULL THEN
        CREATE UNIQUE INDEX uq_fim_drift_open_ci ON fim_drift
    (policy_id, host_identifier, (CASE WHEN kind = 'item' AND path LIKE 'registry|%' THEN lower(path COLLATE "C") ELSE path END))
    WHERE status = 'open';
    END IF;
END $fimddl$;

-- Backend query performance (drift / alert listings, linked-drift joins, alert updates).
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_alert') IS NULL THEN
        CREATE INDEX idx_fim_drift_alert ON fim_drift (alert_id) WHERE alert_id IS NOT NULL;
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_time') IS NULL THEN
        CREATE INDEX idx_fim_drift_time ON fim_drift (detected_at DESC, id DESC);
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_drift_hostname_lower') IS NULL THEN
        CREATE INDEX idx_fim_drift_hostname_lower ON fim_drift (lower(COALESCE(hostname, '')));
    END IF;
END $fimddl$;
DO $fimddl$ BEGIN
    IF to_regclass('idx_alerts_fim_host') IS NULL THEN
        CREATE INDEX idx_alerts_fim_host ON alerts (host_identifier) WHERE alert_type IN ('fim','fim_health','fim_config');
    END IF;
END $fimddl$;

-- Cheap change marker for the worker's policy cache (no md5 over every policy on every tick).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_policies' AND column_name = 'paths_hash') THEN
        ALTER TABLE fim_policies ADD COLUMN paths_hash text;
    END IF;
END $fimddl$;
CREATE OR REPLACE FUNCTION fim_policies_paths_hash() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.paths_hash := md5(NEW.paths::text);
    RETURN NEW;
END $$;
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_policies_paths_hash' AND tgrelid = 'fim_policies'::regclass) THEN
        CREATE TRIGGER trg_fim_policies_paths_hash BEFORE INSERT OR UPDATE OF paths ON fim_policies
    FOR EACH ROW EXECUTE FUNCTION fim_policies_paths_hash();
    ELSIF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fim_policies_paths_hash' AND tgrelid = 'fim_policies'::regclass AND tgenabled = 'D') THEN
        ALTER TABLE fim_policies ENABLE TRIGGER trg_fim_policies_paths_hash;
    END IF;
END $fimddl$;
UPDATE fim_policies SET paths_hash = md5(paths::text) WHERE paths_hash IS DISTINCT FROM md5(paths::text);

-- Audit outbox in the SAME database and transaction as every FIM registry mutation (the primary
-- audit_trail write is best-effort, after commit). Denied privileged attempts are recorded too.
CREATE TABLE IF NOT EXISTS fim_audit (
    id          bigserial PRIMARY KEY,
    at          bigint NOT NULL,
    actor       text NOT NULL,
    user_id     bigint,
    action      text NOT NULL,
    outcome     text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success','denied','error')),
    request_id  text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
DO $fimddl$ BEGIN
    IF to_regclass('idx_fim_audit_at') IS NULL THEN
        CREATE INDEX idx_fim_audit_at ON fim_audit (at DESC);
    END IF;
END $fimddl$;

-- Measurements are kept per node + OS build (and used conservatively: the largest recent one).
DO $fimddl$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'fim_reg_measure' AND column_name = 'os_build') THEN
        ALTER TABLE fim_reg_measure ADD COLUMN os_build text;
    END IF;
END $fimddl$;
`;

/** Worker schema contract v7 (= vajra_server sql/migrations/0007_fim_worker_schema.sql). */
export const FIM_WORKER_DDL = `SELECT pg_advisory_xact_lock(727299);  -- shared FIM DDL lock; apply this file in ONE transaction (psql -1)
-- FIM worker schema contract v7 (vajra_fim). Additive and idempotent. Requires 0004, 0005, 0006.
--
-- CONCURRENCY: the first statement takes the shared FIM DDL advisory lock (727299), held until
-- the end of the transaction, so the file must be applied in ONE transaction (psql -1 -v
-- ON_ERROR_STOP=1 -f, or scripts/migrate.sh). The worker migration path and the backend boot DDL
-- then serialize instead of colliding on pg_class / pg_type / pg_proc.
--
-- WHAT IT ADDS
--   1. fim_schema_version(): the schema revision the worker runs against (7). The worker checks it,
--      and the definition of the drift identity index below, at start and every 5 minutes.
--   2. uq_fim_drift_open_v7: ONE open drift per (policy, host, item identity), where identity folds
--      ASCII letter case (lower(path COLLATE "C"), the worker's ascii_lower) for
--        - registry items (kind = 'item' AND path LIKE 'registry|%'), as 0006 already did, and
--        - Windows FILE paths (kind <> 'item' AND path starting with a drive letter and a colon),
--          so a real-time event spelling C:/Windows/Tasks/EVIL.job (with Windows separators) and a
--          scan spelling c:/windows/tasks/evil.job of the same new file raise ONE drift, not two;
--      everything else (Linux paths, other item kinds) stays exact. The worker's
--      ON CONFLICT target is exactly this expression.
--      uq_fim_drift_open (0004) and uq_fim_drift_open_ci (0006) are kept: both are implied by this
--      index (rows unique here are unique there), so they never reject a row this one accepts,
--      and re-running 0006 stays a no-op.
--   3. Open drifts that already collide under the new identity are merged first, like 0006: the
--      survivor is the row with the most recent last_seen_at (ties: highest id); it receives the
--      summed occurrences, the earliest detected_at and the highest severity of its group; the
--      other rows are closed as 'ignored' with a note naming the survivor, and their still-open
--      linked console alerts are closed with the same remark.
--
-- DEPLOY ORDER (precise)
--   1. Apply the migrations in order: 0006_fim_verify.sql, THEN this file (0007). Both are
--      idempotent; re-running them is safe.
--   2. THEN restart / upgrade the vajra_fim worker to the build that expects schema v7.
--   An OLD worker binary (built before v7) must NOT run on a database that has this index: stop
--   (or upgrade) it before or together with applying 0007.
--
-- THE FOUR COMBINATIONS (worker x index)
--   old worker + old index (0006 only): previous behaviour. Works, but a Windows file can carry
--      two open drifts that differ only in letter case (event spelling vs scan spelling).
--   old worker + new index (0007): UNSAFE. The old worker's ON CONFLICT names the 0006 expression,
--      so a case variant of an open Windows file drift violates uq_fim_drift_open_v7 instead of
--      bumping the drift: the statement fails and its transaction rolls back. A scan row is retried
--      three times and then skipped (that scan's drift is lost); a real-time batch is retried
--      forever (the real-time cursor stalls). Do not run this combination.
--   new worker + old index (no fim_schema_version(), no uq_fim_drift_open_v7, a v7 index with a
--      different definition, or an extra unique index on fim_drift such as a uq_fim_drift_open_ci
--      built with the database collation): the worker FAILS CLOSED. It logs an error, opens ONE
--      fim_health alert ('FIM worker schema mismatch', kept open, never duplicated) and processes
--      no scans, real-time events or check scans until the schema is fixed; its cursors do not
--      move, so nothing is lost: after the migrations are applied it resumes (within 30 s) where it
--      stopped and closes the alert. This also holds on a FRESH install: the worker creates its
--      cursors at start, before the schema check, so events that arrive while it waits are kept.
--      (Since 0008 the worker requires fim_schema_version() >= 8; see 0008_fim_perf.sql.)
--   CURRENT DEPLOY ORDER: 0006, 0007, 0008 (each with psql -1), then 0008a_fim_perf_indexes.sql
--   (plain psql, CREATE INDEX CONCURRENTLY; the backend also builds these in the background), then
--   restart the worker. Missing 0008a indexes only raise a 'FIM perf indexes missing' warning.
--   new worker + new index: normal operation.
--
-- This file is embedded verbatim by the backend (TypeScript template literal): keep it free of
-- backslashes, backticks and dollar-brace sequences.

-- Never downgrades: re-running 0007 after a later migration keeps the later version.
DO $$
DECLARE v integer := 0;
BEGIN
    IF to_regprocedure('fim_schema_version()') IS NOT NULL THEN
        EXECUTE 'SELECT fim_schema_version()' INTO v;
    END IF;
    IF v < 7 THEN
        EXECUTE 'CREATE OR REPLACE FUNCTION fim_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS ''SELECT 7''';
    END IF;
END $$;

DO $$
BEGIN
    CREATE TEMP TABLE fim_v7_dup ON COMMIT DROP AS
    SELECT id, keep_id FROM (
        SELECT id, first_value(id) OVER (
                   PARTITION BY policy_id, host_identifier,
                       (CASE WHEN (kind = 'item' AND path LIKE 'registry|%') OR (kind <> 'item' AND path ~ '^[A-Za-z]:')
                             THEN lower(path COLLATE "C") ELSE path END)
                   ORDER BY last_seen_at DESC NULLS LAST, id DESC) AS keep_id
        FROM fim_drift WHERE status = 'open') g
    WHERE id <> keep_id;
    IF EXISTS (SELECT 1 FROM fim_v7_dup) THEN
        UPDATE fim_drift s SET occurrences = s.occurrences + a.occ,
               detected_at = LEAST(s.detected_at, a.det),
               severity = CASE WHEN a.rnk > (CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                               THEN a.sev ELSE s.severity END,
               note = left(COALESCE(s.note || ' | ', '') || 'Merged ' || a.n || ' open duplicate(s) differing only in letter case', 2000)
        FROM (SELECT c.keep_id, sum(d.occurrences) AS occ, min(d.detected_at) AS det, count(*) AS n,
                     max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS rnk,
                     (array_agg(d.severity ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC))[1] AS sev
              FROM fim_v7_dup c JOIN fim_drift d ON d.id = c.id GROUP BY c.keep_id) a
        WHERE s.id = a.keep_id;
        UPDATE alerts a SET is_open = false,
               remarks = left(COALESCE(a.remarks || ' | ', '') || 'Closed by migration: its drift was merged into drift #' || c.keep_id || ' (same item, different letter case)', 2000)
        FROM fim_v7_dup c JOIN fim_drift d ON d.id = c.id
        WHERE a.is_open AND a.alert_type = 'fim' AND a.host_identifier = d.host_identifier
          AND (a.id = d.alert_id OR substring(a.metadata from '"drift_id"[[:space:]]*:[[:space:]]*"?([0-9]{1,15})') = d.id::text);
        UPDATE fim_drift d SET status = 'ignored', resolved_by = 'migration', resolved_at = extract(epoch FROM now())::bigint,
               note = left(COALESCE(d.note || ' | ', '') || 'Merged into drift #' || c.keep_id || ' (same item, differs only in letter case; the survivor has the latest evidence)', 2000)
        FROM fim_v7_dup c WHERE d.id = c.id;
    END IF;
    DROP TABLE fim_v7_dup;
    -- An index of this name with another definition (hand-made or an earlier draft) is replaced.
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_v7'
               AND (indexdef NOT LIKE '%COLLATE "C"%' OR indexdef NOT LIKE '%^[A-Za-z]:%' OR indexdef NOT LIKE '%registry|%')) THEN
        DROP INDEX uq_fim_drift_open_v7;
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_fim_drift_open_v7 ON fim_drift
    (policy_id, host_identifier,
     (CASE WHEN (kind = 'item' AND path LIKE 'registry|%') OR (kind <> 'item' AND path ~ '^[A-Za-z]:')
           THEN lower(path COLLATE "C") ELSE path END))
    WHERE status = 'open';
`;

/** Worker perf/indexes contract v8 (= vajra_server sql/migrations/0008_fim_perf.sql); set by the DDL sync. */
export const FIM_PERF_DDL = `SELECT pg_advisory_xact_lock(727299);  -- shared FIM DDL lock; apply this file in ONE transaction (psql -1)
-- FIM schema contract v8 (vajra_fim). Additive and idempotent. Requires 0004, 0005, 0006, 0007.
--
-- CONCURRENCY: the first statement takes the shared FIM DDL advisory lock (727299), held until
-- the end of the transaction, so the file must be applied in ONE transaction (psql -1 -v
-- ON_ERROR_STOP=1 -f, or scripts/migrate.sh). The worker migration path and the backend boot DDL
-- then serialize instead of colliding on pg_class / pg_type / pg_proc.
--
-- WHAT IT ADDS
--   1. fim_schema_version() = 8 (never downgrades). The worker requires >= 8; on an older schema it
--      fails closed exactly like v7 (one 'FIM worker schema mismatch' alert, nothing processed,
--      nothing lost).
--   2. CHECK constraints fim_baseline_kind_check / fim_drift_kind_check (kind IN ('file',
--      'directory','item'), the only kinds the worker writes), added NOT VALID then validated, so
--      a database whose kind column predates the inline CHECK of 0004 gets it too.
--   3. Drops the stale column fim_policies.auto_init (no code reads or writes it any more).
--   4. fim_cursor_gaps: the worker's open id holes per feed (ids allocated but not yet committed
--      when the cursor passed them). Persisted so a row that commits late is still processed after a
--      worker restart (previously the hole list lived only in memory).
--   6. Partial indexes idx_fim_init_requests_pending_qid / idx_fim_verify_requests_pending_qid
--      ((queue_id::text), host_identifier) WHERE status = 'pending': the worker finds ANSWERED pending
--      requests from the answer side (new query_result / dead_letter_queue rows), however many
--      unanswered requests there are.
--   7. fim_schema_applied (name, sha256, applied_at): created here by the owner so the backend app
--      role needs no CREATE privilege on the schema.
--   All ALTERs and CREATE INDEXes are conditional (catalog checks), so a no-op re-apply takes no
--   exclusive lock on the FIM tables.
--   5. fim_drift.last_realtime_at: time of the newest real-time event on a drift. A check-scan or
--      scheduled-scan answer confirms a drift (or replaces its observation) only when it was captured
--      at or after that time; a stale answer never confirms over a newer real-time change.
--   The two request-probe PERF indexes are NOT here: they are in 0008a_fim_perf_indexes.sql, built
--   CONCURRENTLY outside a transaction (a CREATE INDEX here would block inserts into
--   dead_letter_queue / query_result for the whole build). The worker only WARNS while they are
--   missing or INVALID (one 'FIM perf indexes missing: ...' fim_health alert) and keeps working.
--
-- UPGRADE NOTE (redaction marker format): baselines taken before redaction spec v2 hold length-only
-- markers 'REDACTED(len=N)'. The new marker is 'REDACTED(len=N,sha256=H)', so each redacted value
-- drifts ONCE ('modified') after the upgrade. engine_v2/fim/tools/accept_marker_format.sql (one shot,
-- psql -1) re-keys those baseline rows to the v2 marker and closes the one-off drifts as 'ignored'
-- ('redaction marker format upgrade') -- only when the new v2 marker has the SAME length; a v1 marker
-- has no hash, so the equal length is the only guarantee (documented in the script).
--
-- DEPLOY ORDER: apply 0006, 0007, 0008 (in order, each with psql -1), THEN 0008a (plain psql -f, no
-- -1: CREATE INDEX CONCURRENTLY), THEN restart / upgrade the worker. The backend also builds the
-- 0008a indexes CONCURRENTLY in a background step after boot when they are missing. A v8 worker on a
-- v7 database fails closed until 0008 is applied; a v7 worker on a v8 database keeps working (it
-- requires >= 7 and the v7 index, both unchanged here). After the first scans of the upgraded worker,
-- optionally run engine_v2/fim/tools/accept_marker_format.sql (see the UPGRADE NOTE).
--
-- This file is embedded verbatim by the backend (TypeScript template literal): keep it free of
-- backslashes, backticks and dollar-brace sequences.

-- Every change below is CONDITIONAL (catalog checks first): a no-op re-apply takes no ACCESS
-- EXCLUSIVE (or SHARE) lock on fim_drift / fim_baseline / fim_policies / the request tables, so it
-- never waits for -- or blocks -- readers and the worker.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_baseline_kind_check' AND conrelid = 'fim_baseline'::regclass) THEN
        ALTER TABLE fim_baseline ADD CONSTRAINT fim_baseline_kind_check CHECK (kind IN ('file','directory','item')) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_baseline_kind_check' AND conrelid = 'fim_baseline'::regclass AND NOT convalidated) THEN
        ALTER TABLE fim_baseline VALIDATE CONSTRAINT fim_baseline_kind_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_drift_kind_check' AND conrelid = 'fim_drift'::regclass) THEN
        ALTER TABLE fim_drift ADD CONSTRAINT fim_drift_kind_check CHECK (kind IN ('file','directory','item')) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_drift_kind_check' AND conrelid = 'fim_drift'::regclass AND NOT convalidated) THEN
        ALTER TABLE fim_drift VALIDATE CONSTRAINT fim_drift_kind_check;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
               AND table_name = 'fim_policies' AND column_name = 'auto_init') THEN
        ALTER TABLE fim_policies DROP COLUMN auto_init;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                   AND table_name = 'fim_drift' AND column_name = 'last_realtime_at') THEN
        ALTER TABLE fim_drift ADD COLUMN last_realtime_at bigint;
    END IF;
    -- F4: answers are matched to PENDING requests from the answer side (new query_result /
    -- dead_letter_queue rows joined by queue id + host); small partial indexes on the request tables.
    IF to_regclass('idx_fim_init_requests_pending_qid') IS NULL THEN
        CREATE INDEX idx_fim_init_requests_pending_qid ON fim_init_requests ((queue_id::text), host_identifier) WHERE status = 'pending';
    END IF;
    IF to_regclass('idx_fim_verify_requests_pending_qid') IS NULL THEN
        CREATE INDEX idx_fim_verify_requests_pending_qid ON fim_verify_requests ((queue_id::text), host_identifier) WHERE status = 'pending';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS fim_cursor_gaps (
    source      text NOT NULL,
    id          bigint NOT NULL,
    first_seen  bigint NOT NULL,
    PRIMARY KEY (source, id)
);

-- Owned by the migrating (owner) role, so the backend's app role does not need CREATE on the schema.
CREATE TABLE IF NOT EXISTS fim_schema_applied (
    name        text PRIMARY KEY,
    sha256      text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- Never downgrades: re-running 0008 after a later migration keeps the later version.
DO $$
DECLARE v integer := 0;
BEGIN
    IF to_regprocedure('fim_schema_version()') IS NOT NULL THEN
        EXECUTE 'SELECT fim_schema_version()' INTO v;
    END IF;
    IF v < 8 THEN
        EXECUTE 'CREATE OR REPLACE FUNCTION fim_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS ''SELECT 8''';
    END IF;
END $$;
`;

/** 0004 base FIM tables (documentation mirror: migrations/030_add_fim_tables.sql). */
export const FIM_BASE_DDL = `
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
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_policies' AND column_name = 'rev') THEN
        ALTER TABLE fim_policies ADD COLUMN rev integer NOT NULL DEFAULT 1;
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_host_state' AND column_name = 'rev') THEN
        ALTER TABLE fim_host_state ADD COLUMN rev integer NOT NULL DEFAULT 0;
    END IF;
END $fimc$;
-- rev the currently published config was generated from (NULL = not published).
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_policies' AND column_name = 'published_rev') THEN
        ALTER TABLE fim_policies ADD COLUMN published_rev integer;
    END IF;
END $fimc$;
-- Drift is audit evidence: no FK to fim_policies; policy_name is snapshotted.
DO $fimc$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fim_drift_policy_id_fkey') THEN
        ALTER TABLE fim_drift DROP CONSTRAINT fim_drift_policy_id_fkey;
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_drift' AND column_name = 'policy_name') THEN
        ALTER TABLE fim_drift ADD COLUMN policy_name text;
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_baseline' AND column_name = 'kind') THEN
        ALTER TABLE fim_baseline ADD COLUMN kind text NOT NULL DEFAULT 'file';
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_baseline' AND column_name = 'entry_idx') THEN
        ALTER TABLE fim_baseline ADD COLUMN entry_idx integer;
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_baseline' AND column_name = 'data') THEN
        ALTER TABLE fim_baseline ADD COLUMN data jsonb;
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_drift' AND column_name = 'kind') THEN
        ALTER TABLE fim_drift ADD COLUMN kind text NOT NULL DEFAULT 'file';
    END IF;
END $fimc$;
DO $fimc$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fim_drift' AND column_name = 'entry_idx') THEN
        ALTER TABLE fim_drift ADD COLUMN entry_idx integer;
    END IF;
END $fimc$;
      `;
