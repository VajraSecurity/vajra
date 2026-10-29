/**
 * Database Setup and Migrations
 * Handles creation of indexes, audit tables, and other database setup
 * This can be run as a separate script during deployment
 */

import 'dotenv/config';
import { DataSource } from 'typeorm';
import databaseConfig, { databaseConfig2 } from './ormconfig';
import { getLogger } from '../../utils/logger';
import { SUPER_ADMIN_ROLE, DEFAULT_USER_ROLE } from '../entities/users/Users';
import { GROUP_MEMBERSHIP_ROLE_ADMIN } from '../entities/users/UserGroupMembership';
import { RLS_GROUP_SESSION_VAR } from '../../consts/database';

const logger = getLogger('orm.setup');

/**
 * SQL statements for database setup
 * Includes indexes and optional audit/session tables
 */
export const DATABASE_SETUP_QUERIES = {

  // ==============================================================
  // 1. PERFORMANCE INDEXES
  // ==============================================================

  // Email unique index (UNIQUE constraint exists from TypeORM, but explicit index helps)
  createEmailIndex: `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_vajra_users_email 
    ON vajra_users(LOWER(email));
  `,

  // Created at index for sorting and filtering
  createCreatedAtIndex: `
    CREATE INDEX IF NOT EXISTS idx_vajra_users_created_at 
    ON vajra_users(created_at DESC);
  `,

  // Session version index for session invalidation queries
  createSessionVersionIndex: `
    CREATE INDEX IF NOT EXISTS idx_vajra_users_session_version 
    ON vajra_users(session_version);
  `,

  // Role column for RBAC
  addUserRoleColumn: `
    ALTER TABLE vajra_users
    ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT '${DEFAULT_USER_ROLE}';
  `,

  addUserSuspendedColumn: `
    ALTER TABLE vajra_users
    ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT false;
  `,

  // Group-based node access control: user <-> group_id membership.
  // group_id is a soft reference to the fleet DB's nodes_groups.group_id /
  // nodes.group_ids elements — no FK possible cross-DataSource.
  createUserGroupMembershipsTable: `
    CREATE TABLE IF NOT EXISTS user_group_memberships (
      id          BIGSERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES vajra_users(id) ON DELETE CASCADE,
      group_id    VARCHAR(255) NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, group_id)
    );
  `,
  createUserGroupMembershipsIndexes: `
    CREATE INDEX IF NOT EXISTS idx_ugm_user_id  ON user_group_memberships (user_id);
    CREATE INDEX IF NOT EXISTS idx_ugm_group_id ON user_group_memberships (group_id);
  `,

  // Per-membership role: lets one person be a full Group Admin (read + act) on
  // one group and a read-only Group Viewer on another, instead of every
  // membership granting identical access. Existing rows default to 'Group
  // Admin', matching the access they already had before this column existed.
  addUserGroupMembershipsRoleColumn: `
    ALTER TABLE user_group_memberships
    ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT '${GROUP_MEMBERSHIP_ROLE_ADMIN}';
  `,

  // One-time migration: the 'Administrator' role is removed in favor of the
  // group-scoped 'Group Admin' role. Existing Administrators are migrated with
  // zero groups assigned — they regain node access once a Super Admin assigns
  // them a group.
  migrateAdministratorRoleToGroupAdmin: `
    UPDATE vajra_users SET role = '${GROUP_MEMBERSHIP_ROLE_ADMIN}' WHERE role = 'Administrator';
  `,

  // Narrow, credential-free view of vajra_users for the Grafana FDW bridge
  // (see setupGrafanaGroupScoping in this file). Only id/email/role are ever
  // needed to resolve grafana_group_visible()/grafana_scan_visible() — the
  // view exists so that bridge can never expose password_hash/mfa_secret/
  // recovery_codes/security_answer_*_hash, even if someone widens the FDW
  // import later.
  createGrafanaUserScopingView: `
    CREATE OR REPLACE VIEW grafana_user_scoping AS
    SELECT id, email, role FROM vajra_users;
  `,

  // ==============================================================
  // 2. AUDIT LOGGING TABLE (OPTIONAL)
  // ==============================================================

  createAuditLogsTable: `
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      
      -- Event details
      action VARCHAR(100) NOT NULL,
      status VARCHAR(20) NOT NULL CHECK(status IN ('success', 'failure')),
      severity VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
      
      -- User information
      user_id INTEGER REFERENCES vajra_users(id) ON DELETE SET NULL,
      email VARCHAR(255),
      
      -- Request information
      ip_address INET,
      user_agent TEXT,
      
      -- Custom details stored as JSON
      details JSONB,
      
      -- Timestamps
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      
      -- Constraints
      CONSTRAINT audit_logs_user_or_email CHECK (user_id IS NOT NULL OR email IS NOT NULL)
    );
  `,

  createAuditLogsIndexes: `
    CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_email ON audit_logs(email);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity);
  `,

  // ==============================================================
  // 3. USER SESSION HISTORY TABLE (OPTIONAL)
  // ==============================================================

  createUserSessionsTable: `
    CREATE TABLE IF NOT EXISTS user_sessions (
      id SERIAL PRIMARY KEY,
      
      -- User reference
      user_id INTEGER NOT NULL REFERENCES vajra_users(id) ON DELETE CASCADE,
      
      -- Session details
      ip_address INET,
      user_agent TEXT,
      
      -- Session timestamps
      login_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      logout_time TIMESTAMPTZ,
      is_active BOOLEAN DEFAULT true,
      
      -- Session duration (calculated on logout)
      duration_seconds INTEGER,

      -- Additional state
      logout_reason VARCHAR(255),
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `,

  createUserSessionsIndexes: `
    CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_sessions_is_active ON user_sessions(is_active);
    CREATE INDEX IF NOT EXISTS idx_user_sessions_login_time ON user_sessions(login_time DESC);
  `,

  // ==============================================================
  // 4. AUDIT TRAIL TABLE (login, register, password, rename node, alert status)
  // ==============================================================

  createAuditTrailTable: `
    CREATE TABLE IF NOT EXISTS audit_trail (
      id SERIAL PRIMARY KEY,
      action VARCHAR(50) NOT NULL,
      status VARCHAR(20) NOT NULL CHECK(status IN ('success', 'failure')),
      user_id INTEGER REFERENCES vajra_users(id) ON DELETE SET NULL,
      email VARCHAR(255),
      ip_address INET,
      user_agent TEXT,
      details JSONB,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `,

  createAuditTrailIndexes: `
    CREATE INDEX IF NOT EXISTS idx_audit_trail_user_id ON audit_trail(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_trail_email ON audit_trail(email);
    CREATE INDEX IF NOT EXISTS idx_audit_trail_action ON audit_trail(action);
    CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON audit_trail(created_at DESC);
  `,

  // ==============================================================
  // 6. RULE ENGINE RESOURCE OWNERSHIP TABLE
  // ==============================================================
  // Vajranet-side ownership for a rule-engine resource that has no local
  // entity of its own — see orm/entities/rule_engine/RuleEngineResourceOwner.ts
  // and utils/ruleEngineScope.ts for why this exists (the sibling engine
  // console has no group/tenant concept at all).
  createRuleEngineResourceOwnersTable: `
    CREATE TABLE IF NOT EXISTS rule_engine_resource_owners (
      id              BIGSERIAL PRIMARY KEY,
      resource_type   VARCHAR(32) NOT NULL,
      resource_key    VARCHAR(255) NOT NULL,
      owner_group_id  VARCHAR(255) NOT NULL,
      created_by      VARCHAR(255),
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (resource_type, resource_key)
    );
  `,
  createRuleEngineResourceOwnersIndexes: `
    CREATE INDEX IF NOT EXISTS idx_rule_engine_resource_owners_owner_group_id ON rule_engine_resource_owners (owner_group_id);
  `,
};

/**
 * Execute all database setup queries
 * Used during application initialization or deployment
 */
export const setupDatabase = async (): Promise<void> => {
  const dataSource = new DataSource(databaseConfig as any);

  try {
    await dataSource.initialize();
    logger.info('Initializing database setup');

    // Create performance indexes
    logger.info('Creating database indexes');
    await dataSource.query(DATABASE_SETUP_QUERIES.addUserRoleColumn);
    await dataSource.query(DATABASE_SETUP_QUERIES.addUserSuspendedColumn);
    await dataSource.query(DATABASE_SETUP_QUERIES.createEmailIndex);
    await dataSource.query(DATABASE_SETUP_QUERIES.createCreatedAtIndex);
    await dataSource.query(DATABASE_SETUP_QUERIES.createSessionVersionIndex);
    logger.info('Database indexes created');

    logger.info('Creating user_group_memberships table');
    await dataSource.query(DATABASE_SETUP_QUERIES.createUserGroupMembershipsTable);
    await dataSource.query(DATABASE_SETUP_QUERIES.createUserGroupMembershipsIndexes);
    await dataSource.query(DATABASE_SETUP_QUERIES.addUserGroupMembershipsRoleColumn);
    logger.info('user_group_memberships table created');

    logger.info('Migrating Administrator role to Group Admin');
    // This UPDATE strips group access from every affected user (see the
    // comment on migrateAdministratorRoleToGroupAdmin) — the row count is the
    // only way to tell, after the fact, whether this run actually migrated
    // (and de-scoped) any accounts or was a no-op on an already-migrated DB.
    const [, migratedAdminCount] = await dataSource.query(DATABASE_SETUP_QUERIES.migrateAdministratorRoleToGroupAdmin);
    logger.info({ migratedAdminCount }, 'Administrator to Group Admin role migration complete');

    logger.info('Creating grafana_user_scoping view');
    await dataSource.query(DATABASE_SETUP_QUERIES.createGrafanaUserScopingView);
    logger.info('grafana_user_scoping view ready');

    // Create audit logs table (optional)
    if (process.env.ENABLE_AUDIT_LOGS === 'true') {
      logger.info('Creating audit logs table');
      await dataSource.query(DATABASE_SETUP_QUERIES.createAuditLogsTable);
      await dataSource.query(DATABASE_SETUP_QUERIES.createAuditLogsIndexes);
      logger.info('Audit logs table created');
    } else {
      logger.info('Skipping audit logs table: ENABLE_AUDIT_LOGS is not set to true');
    }

    // Create user sessions table (optional)
    if (process.env.ENABLE_SESSION_TRACKING === 'true') {
      logger.info('Creating user sessions table');
      await dataSource.query(DATABASE_SETUP_QUERIES.createUserSessionsTable);
      await dataSource.query(DATABASE_SETUP_QUERIES.createUserSessionsIndexes);
      logger.info('User sessions table created');
    } else {
      logger.info('Skipping user sessions table: ENABLE_SESSION_TRACKING is not set to true');
    }

    // Create audit trail table (login, register, password, rename node, alert status)
    logger.info('Creating audit_trail table');
    await dataSource.query(DATABASE_SETUP_QUERIES.createAuditTrailTable);
    await dataSource.query(DATABASE_SETUP_QUERIES.createAuditTrailIndexes);
    logger.info('Audit trail table created');

    logger.info('Creating rule_engine_resource_owners table');
    await dataSource.query(DATABASE_SETUP_QUERIES.createRuleEngineResourceOwnersTable);
    await dataSource.query(DATABASE_SETUP_QUERIES.createRuleEngineResourceOwnersIndexes);
    logger.info('rule_engine_resource_owners table created');

    logger.info('Database setup completed successfully');
    await dataSource.destroy();
  } catch (error) {
    logger.error({ err: error }, 'Database setup failed');
    process.exit(1);
  }
};

// ==============================================================
// FLEET (SECONDARY) DATABASE SETUP
// ==============================================================

export const FLEET_SETUP_QUERIES = {
  createComplianceResultsTable: `
    CREATE TABLE IF NOT EXISTS compliance_results (
      id              BIGSERIAL PRIMARY KEY,
      host_identifier VARCHAR   NOT NULL,
      unixtime        BIGINT    NOT NULL,
      compliance_data JSONB     NOT NULL
    );
  `,
  createComplianceResultsIndexes: `
    CREATE INDEX IF NOT EXISTS idx_cr_host          ON compliance_results (host_identifier);
    CREATE INDEX IF NOT EXISTS idx_cr_host_unixtime ON compliance_results (host_identifier, unixtime DESC);
  `,

  addNodesGroupIdsColumn: `
    ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS group_ids JSONB DEFAULT '[]'::jsonb;
  `,
  createNodesGroupIdsIndex: `
    CREATE INDEX IF NOT EXISTS idx_nodes_group_ids ON nodes USING GIN (group_ids);
  `,

  // Single-owner group column — the authoritative source for all access-scoping
  // decisions (REST scoping, RLS policies, the live host->group map). NULL means
  // "unassigned" (visible only to global/Super Admin users). group_ids (above)
  // is kept only for the frontend's existing display code and is never read by
  // any enforcement path from this point on.
  addNodesOwnerGroupIdColumn: `
    ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS owner_group_id VARCHAR(255);
  `,
  createNodesOwnerGroupIdIndex: `
    CREATE INDEX IF NOT EXISTS idx_nodes_owner_group_id ON nodes (owner_group_id);
  `,

  // One-time backfill for any deployment that already assigned nodes to groups
  // under the old multi-group (group_ids array) model. Picks the FIRST group in
  // the array as the sole owner — if a node was deliberately placed in more than
  // one group, this migration silently drops the others. On a fresh install (or
  // one where no node has ever been assigned) this is a no-op. Guarded by
  // `owner_group_id IS NULL` so it is safe to run on every startup.
  backfillNodesOwnerGroupIdFromGroupIds: `
    UPDATE nodes
    SET owner_group_id = group_ids->>0
    WHERE owner_group_id IS NULL
      AND jsonb_array_length(COALESCE(group_ids, '[]'::jsonb)) > 0;
  `,

  // One-time backfill for scan_schedules-driven network_scan_history rows
  // created before scanSchedulerService.ts started passing createdByUserId —
  // every scheduled scan landed with created_by_user_id NULL, which
  // grafana_scan_visible() treats as visible only to a Super Administrator,
  // hiding scheduler-discovered "unknown devices" from the group that owns
  // the schedule. Guarded by `created_by_user_id IS NULL` so it only ever
  // touches rows this bug actually affected, and is a no-op on every run
  // after the first.
  backfillNetworkScanHistoryCreatedBy: `
    UPDATE network_scan_history nsh
    SET created_by_user_id = ss.created_by_user_id,
        created_by_name = ss.created_by_name
    FROM scan_schedules ss
    WHERE nsh.schedule_id = ss.id
      AND nsh.created_by_user_id IS NULL
      AND ss.created_by_user_id IS NOT NULL;
  `,

  createSebiComplianceResultsTable: `
    CREATE TABLE IF NOT EXISTS sebi_compliance_results (
      id              BIGSERIAL PRIMARY KEY,
      host_identifier VARCHAR   NOT NULL,
      unixtime        BIGINT    NOT NULL,
      compliance_data JSONB     NOT NULL
    );
  `,
  createSebiComplianceResultsIndexes: `
    CREATE INDEX IF NOT EXISTS sebi_idx_scr_host          ON sebi_compliance_results (host_identifier);
    CREATE INDEX IF NOT EXISTS sebi_idx_scr_host_unixtime ON sebi_compliance_results (host_identifier, unixtime DESC);
  `,

  createIrdaiComplianceResultsTable: `
    CREATE TABLE IF NOT EXISTS irdai_compliance_results (
      id              BIGSERIAL PRIMARY KEY,
      host_identifier VARCHAR   NOT NULL,
      unixtime        BIGINT    NOT NULL,
      compliance_data JSONB     NOT NULL
    );
  `,
  createIrdaiComplianceResultsIndexes: `
    CREATE INDEX IF NOT EXISTS irdai_idx_icr_host          ON irdai_compliance_results (host_identifier);
    CREATE INDEX IF NOT EXISTS irdai_idx_icr_host_unixtime ON irdai_compliance_results (host_identifier, unixtime DESC);
  `,

  // CREATE TABLE IF NOT EXISTS is a no-op on a deployment where the table
  // already existed before owner_group_ids was added to its CREATE statement
  // below — these four ADD COLUMN IF NOT EXISTS calls are what actually
  // backfill it on those installs. Found live: all four *_historical_compliance
  // tables predated this column, so every org-level history/snapshot endpoint
  // (Vajra baseline, SEBI, IRDAI, CERT-In) was throwing "column owner_group_ids
  // does not exist" until this ran.
  addHistoricalComplianceOwnerGroupIdsColumn: `
    ALTER TABLE historical_compliance
    ADD COLUMN IF NOT EXISTS owner_group_ids TEXT[];
  `,
  addSebiHistoricalComplianceOwnerGroupIdsColumn: `
    ALTER TABLE sebi_historical_compliance
    ADD COLUMN IF NOT EXISTS owner_group_ids TEXT[];
  `,
  addIrdaiHistoricalComplianceOwnerGroupIdsColumn: `
    ALTER TABLE irdai_historical_compliance
    ADD COLUMN IF NOT EXISTS owner_group_ids TEXT[];
  `,
  addCertinHistoricalComplianceOwnerGroupIdsColumn: `
    ALTER TABLE certin_historical_compliance
    ADD COLUMN IF NOT EXISTS owner_group_ids TEXT[];
  `,

  createSebiHistoricalComplianceTable: `
    CREATE TABLE IF NOT EXISTS sebi_historical_compliance (
      id BIGSERIAL PRIMARY KEY,
      snapshot_at BIGINT NOT NULL,
      total_nodes INTEGER,
      windows_hosts INTEGER,
      windows_with_results INTEGER,
      fully_compliant_nodes INTEGER,
      avg_compliance_percent FLOAT,
      strong_count INTEGER,
      moderate_count INTEGER,
      needs_attention_count INTEGER,
      control_pass_rates JSONB NOT NULL,
      source VARCHAR(20) NOT NULL DEFAULT 'live',
      fully_compliant_nodes_list JSONB,
      non_compliant_nodes_list JSONB,
      owner_group_ids TEXT[]
    );
  `,
  createSebiHistoricalComplianceIndexes: `
    CREATE INDEX IF NOT EXISTS sebi_idx_hc_snapshot_at
    ON sebi_historical_compliance (snapshot_at);
  `,

  createIrdaiHistoricalComplianceTable: `
    CREATE TABLE IF NOT EXISTS irdai_historical_compliance (
      id BIGSERIAL PRIMARY KEY,
      snapshot_at BIGINT NOT NULL,
      total_nodes INTEGER,
      windows_hosts INTEGER,
      windows_with_results INTEGER,
      fully_compliant_nodes INTEGER,
      avg_compliance_percent FLOAT,
      strong_count INTEGER,
      moderate_count INTEGER,
      needs_attention_count INTEGER,
      control_pass_rates JSONB NOT NULL,
      source VARCHAR(20) NOT NULL DEFAULT 'live',
      fully_compliant_nodes_list JSONB,
      non_compliant_nodes_list JSONB,
      owner_group_ids TEXT[]
    );
  `,
  createIrdaiHistoricalComplianceIndexes: `
    CREATE INDEX IF NOT EXISTS irdai_idx_hc_snapshot_at
    ON irdai_historical_compliance (snapshot_at);
  `,

  createCertinComplianceResultsTable: `
    CREATE TABLE IF NOT EXISTS certin_compliance_results (
      id              BIGSERIAL PRIMARY KEY,
      host_identifier VARCHAR   NOT NULL,
      unixtime        BIGINT    NOT NULL,
      compliance_data JSONB     NOT NULL
    );
  `,
  createCertinComplianceResultsIndexes: `
    CREATE INDEX IF NOT EXISTS certin_idx_cr_host          ON certin_compliance_results (host_identifier);
    CREATE INDEX IF NOT EXISTS certin_idx_cr_host_unixtime ON certin_compliance_results (host_identifier, unixtime DESC);
  `,

  createCertinHistoricalComplianceTable: `
    CREATE TABLE IF NOT EXISTS certin_historical_compliance (
      id BIGSERIAL PRIMARY KEY,
      snapshot_at BIGINT NOT NULL,
      total_nodes INTEGER,
      windows_hosts INTEGER,
      windows_with_results INTEGER,
      fully_compliant_nodes INTEGER,
      avg_compliance_percent FLOAT,
      strong_count INTEGER,
      moderate_count INTEGER,
      needs_attention_count INTEGER,
      control_pass_rates JSONB NOT NULL,
      source VARCHAR(20) NOT NULL DEFAULT 'live',
      fully_compliant_nodes_list JSONB,
      non_compliant_nodes_list JSONB,
      owner_group_ids TEXT[]
    );
  `,
  createCertinHistoricalComplianceIndexes: `
    CREATE INDEX IF NOT EXISTS certin_idx_hc_snapshot_at
    ON certin_historical_compliance (snapshot_at);
  `,

  createHistoricalComplianceTable: `
    CREATE TABLE IF NOT EXISTS historical_compliance (
      id BIGSERIAL PRIMARY KEY,
      snapshot_at BIGINT NOT NULL,
      total_nodes INTEGER,
      windows_hosts INTEGER,
      windows_with_results INTEGER,
      avg_compliance_percent INTEGER,
      strong_count INTEGER,
      moderate_count INTEGER,
      needs_attention_count INTEGER,
      control_pass_rates JSONB NOT NULL,
      source VARCHAR(20) NOT NULL DEFAULT 'live',
      fully_compliant_nodes_list JSONB,
      non_compliant_nodes_list JSONB,
      owner_group_ids TEXT[]
    );
  `,
  createHistoricalComplianceIndexes: `
    CREATE INDEX IF NOT EXISTS idx_hc_snapshot_at
    ON historical_compliance (snapshot_at);
  `,

  createPackagesSnapshotTable: `
    CREATE TABLE IF NOT EXISTS packages_snapshot (
      id               BIGSERIAL    PRIMARY KEY,
      host_identifier  TEXT         NOT NULL,
      source           TEXT         NOT NULL,
      name             TEXT         NOT NULL,
      version          TEXT,
      revision         TEXT,
      channel          TEXT,
      publisher        TEXT,
      confinement      TEXT,
      snap_type        TEXT,
      app_id           TEXT,
      branch           TEXT,
      origin           TEXT,
      arch             TEXT,
      install_dir      TEXT,
      size             TEXT,
      updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );
  `,
  createPackagesSnapshotIndexes: `
    CREATE INDEX IF NOT EXISTS idx_packages_snapshot_host
      ON packages_snapshot (host_identifier);
    CREATE INDEX IF NOT EXISTS idx_packages_snapshot_host_source
      ON packages_snapshot (host_identifier, source);
  `,

  createAgentCertProvisioningTokensTable: `
    CREATE TABLE IF NOT EXISTS agent_cert_provisioning_tokens (
      id              BIGSERIAL PRIMARY KEY,
      token_hash      VARCHAR(64) NOT NULL UNIQUE,
      host_identifier VARCHAR(255) NOT NULL,
      issued_by_id    INTEGER NOT NULL,
      issued_by_email VARCHAR(255) NOT NULL,
      status          VARCHAR(20) NOT NULL DEFAULT 'active',
      issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at      TIMESTAMPTZ NOT NULL,
      used_at         TIMESTAMPTZ,
      revoked_at      TIMESTAMPTZ,
      revoked_by_id   INTEGER
    );
  `,
  createAgentCertProvisioningTokensIndexes: `
    CREATE INDEX IF NOT EXISTS idx_acpt_host_identifier ON agent_cert_provisioning_tokens (host_identifier);
    CREATE INDEX IF NOT EXISTS idx_acpt_status ON agent_cert_provisioning_tokens (status);
  `,
};

// ==============================================================
// GROUP-SCOPED HISTORICAL HUNTING: vajra_hunt ROLE + ROW-LEVEL SECURITY
// ==============================================================
//
// Free-form SQL (the Threat Hunting box, and the AI's execute_db_query tool)
// runs whatever SELECT statement the caller writes, so scoping it by
// rewriting or post-filtering the query is not reliable — a query can always
// be phrased to defeat a filter that inspects its output (e.g. aliasing a
// column so it appears to belong to an allowed host). The only enforcement
// point that holds regardless of how the query is phrased is the database
// itself: a row-level policy attached to the table, evaluated by Postgres
// after the caller's SQL has already been parsed and planned.
//
// This requires a role that ISN'T the table owner — Postgres exempts the
// owner (and superusers) from Row-Level Security entirely, which is also
// what keeps ingest, the dashboard, and every other existing connection
// completely unaffected: they authenticate as the owning role and never see
// any of this.

/**
 * Tables a group-scoped hunt is allowed to read, each keyed by host_identifier.
 * Roughly the telemetry surface documented to the model in
 * mcp/schema/definitions.ts, less the org-wide aggregates (e.g.
 * historical_compliance) that have no host_identifier column and so stay global
 * and Super-Admin-only rather than being row-filtered.
 *
 * The two lists are not kept mechanically in sync and do diverge:
 * listening_ports is documented there but absent here, so a group-scoped caller
 * gets a permission error on it rather than filtered rows. Anything documented
 * to the model and expected to be readable under group scope must be added here
 * explicitly.
 */
const HUNT_HOST_KEYED_TABLES = [
  'alerts',
  'compliance_results',
  'certin_compliance_results',
  'sebi_compliance_results',
  'irdai_compliance_results',
  'windows_security_products',
  'windows_security_center',
  'windows_firewall_rules',
  'windows_update_history',
  'memory_info',
  'wmi_bios_info',
  'tpm_info',
  'wifi_events',
  'programs',
  'deb_packages',
  'rpm_packages',
  'npm_packages',
  'chocolatey_packages',
  'chrome_extensions',
  'ie_extensions',
  'firefox_addons',
  'system_info',
  'win_registry_events',
  'win_process_events',
  'win_socket_events',
  'win_file_events',
  'win_dns_events',
  'win_dns_response_events',
  'win_ssl_events',
  'win_http_events',
  'packages_snapshot',
];

/**
 * Idempotent: creates the role if missing, and always re-applies the password
 * so rotating POSTGRES_HUNT_PASSWORD takes effect on the next restart. Postgres
 * has no `CREATE ROLE IF NOT EXISTS`, hence the pg_roles existence check.
 * NOBYPASSRLS is the default for a non-superuser role already — stated
 * explicitly so a future `ALTER ROLE ... BYPASSRLS` doesn't silently disable
 * enforcement without someone noticing the deviation from this file.
 */
function buildHuntRoleSql(password: string): string {
  const escapedPassword = password.replace(/'/g, "''");
  return `
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vajra_hunt') THEN
        CREATE ROLE vajra_hunt LOGIN NOBYPASSRLS;
      END IF;
    END
    $$;
    ALTER ROLE vajra_hunt WITH PASSWORD '${escapedPassword}';
  `;
}

/** The row-level policy shape shared by every host-keyed table except nodes itself. */
function hostKeyedPolicySql(table: string): string {
  return `
    GRANT SELECT ON ${table} TO vajra_hunt;
    ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS group_scope ON ${table};
    CREATE POLICY group_scope ON ${table} FOR SELECT USING (
      host_identifier IN (
        SELECT host_identifier FROM nodes
        WHERE owner_group_id = ANY (string_to_array(current_setting('${RLS_GROUP_SESSION_VAR}', true), ','))
      )
    );
  `;
}

/** nodes carries owner_group_id directly, so its policy filters on that column, not a subquery. */
const NODES_POLICY_SQL = `
  GRANT SELECT ON nodes TO vajra_hunt;
  ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS group_scope ON nodes;
  CREATE POLICY group_scope ON nodes FOR SELECT USING (
    owner_group_id = ANY (string_to_array(current_setting('${RLS_GROUP_SESSION_VAR}', true), ','))
  );
`;

/**
 * The asset identity tables need their OWN policy shapes and must NOT reuse
 * hostKeyedPolicySql: none of them has a `host_identifier` column, so the
 * policy body would fail to parse at CREATE POLICY time — and setupHuntRole's
 * per-table catch would SWALLOW that failure. The table would then be left with
 * ROW LEVEL SECURITY enabled but no policy at all in the best case, or (if the
 * ALTER succeeded and only the CREATE POLICY failed) readable-by-nobody, with a
 * warning that looks identical to the routine "table not provisioned yet" one.
 * A silent RLS hole is exactly the failure mode this comment exists to prevent.
 *
 * `assets` carries owner_group_id directly, like nodes.
 */
const ASSETS_POLICY_SQL = `
  GRANT SELECT ON assets TO vajra_hunt;
  ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS group_scope ON assets;
  CREATE POLICY group_scope ON assets FOR SELECT USING (
    owner_group_id = ANY (string_to_array(current_setting('${RLS_GROUP_SESSION_VAR}', true), ','))
  );
`;

/**
 * asset_identities and asset_observations are keyed on asset_uuid, not
 * host_identifier, so they inherit their scope from `assets` the same way the
 * host-keyed tables inherit theirs from `nodes`.
 *
 * Note the consequence, which is deliberate and matches the REST API: an asset
 * only agentless scanners have ever seen has owner_group_id NULL, `NULL = ANY
 * (...)` is never true, and so a scoped caller sees none of its identities or
 * observations either. Such an asset becomes visible to a group the moment it
 * merges with an agent-backed one.
 */
function assetKeyedPolicySql(table: string): string {
  return `
    GRANT SELECT ON ${table} TO vajra_hunt;
    ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS group_scope ON ${table};
    CREATE POLICY group_scope ON ${table} FOR SELECT USING (
      asset_uuid IN (
        SELECT asset_uuid FROM assets
        WHERE owner_group_id = ANY (string_to_array(current_setting('${RLS_GROUP_SESSION_VAR}', true), ','))
      )
    );
  `;
}

/** Asset identity tables keyed on asset_uuid; see assetKeyedPolicySql. */
const HUNT_ASSET_KEYED_TABLES = ['asset_identities', 'asset_observations'];

/**
 * Provisions the vajra_hunt role, table grants, and RLS policies on the fleet
 * DB. Requires the connecting user (databaseConfig2 / POSTGRES_USER1) to hold
 * CREATEROLE or be a superuser — many managed Postgres setups deliberately
 * don't grant that to the application user, so this is allowed to fail: the
 * caller (setupFleetDatabase) catches the error, logs an actionable one-time
 * warning, and continues without aborting the rest of setup. Until this
 * succeeds (run once, by a DBA, with elevated privilege if needed), scoped
 * historical hunting reports "not available" rather than the app refusing to
 * start — see the optional third DataSource in index.ts.
 */
async function setupHuntRole(dataSource: DataSource): Promise<void> {
  const password = process.env.POSTGRES_HUNT_PASSWORD;
  if (!password) {
    logger.info('POSTGRES_HUNT_PASSWORD not set, skipping vajra_hunt role setup');
    return;
  }

  await dataSource.query(buildHuntRoleSql(password));

  // Each table is provisioned independently. Some (e.g. the Windows
  // network-telemetry tables) only exist once a deployment has ingested that
  // event type, and one missing table must not abort provisioning for every
  // table after it — including `nodes`, without whose policy scoped hunting
  // reports "unavailable" outright.
  let policiedCount = 0;
  let skippedCount = 0;
  for (const table of HUNT_HOST_KEYED_TABLES) {
    try {
      await dataSource.query(hostKeyedPolicySql(table));
      policiedCount += 1;
    } catch (tableErr) {
      skippedCount += 1;
      logger.warn({ err: tableErr, table }, 'Skipping vajra_hunt policy: table missing or not yet provisioned');
    }
  }
  logger.info(
    { policiedCount, skippedCount, total: HUNT_HOST_KEYED_TABLES.length },
    'vajra_hunt table policy provisioning complete',
  );
  await dataSource.query(NODES_POLICY_SQL);

  // The asset identity tables are provisioned in the same tolerant style: they
  // do not exist on an install whose bootstrap DDL has not run yet, and one
  // missing table must not cost the others their policy. Each gets its OWN
  // policy shape — see ASSETS_POLICY_SQL / assetKeyedPolicySql for why reusing
  // hostKeyedPolicySql here would open a silent RLS hole.
  try {
    await dataSource.query(ASSETS_POLICY_SQL);
  } catch (assetsErr) {
    logger.warn({ err: assetsErr, table: 'assets' }, 'Skipping vajra_hunt policy: table missing or not yet provisioned');
  }
  for (const table of HUNT_ASSET_KEYED_TABLES) {
    try {
      await dataSource.query(assetKeyedPolicySql(table));
    } catch (tableErr) {
      logger.warn({ err: tableErr, table }, 'Skipping vajra_hunt policy: table missing or not yet provisioned');
    }
  }
}

/**
 * Lets the embedded Grafana "CVE Analysis" and "Network Analysis" dashboards
 * scope every panel to the viewing user's group(s), so a Group Admin/Viewer
 * only sees their own group's nodes/CVEs/scans instead of the whole fleet.
 *
 * Why this can't reuse the vajra_hunt/RLS approach above: the Grafana
 * datasource connects as `grafana_reader`, which this function grants
 * BYPASSRLS (grafana_reader is a read-only reporting role with no write
 * access, so bypassing RLS here doesn't grant it anything beyond broader
 * read visibility, and every panel that needs scoping calls
 * grafana_group_visible()/grafana_scan_visible() explicitly instead of
 * relying on RLS) — RLS can't be turned back on selectively per dashboard,
 * so scoping is a literal filter in each panel's SQL, driven by Grafana's
 * built-in `${__user.email}` (populated from the auth-proxy-verified
 * session; NOT a client-editable `var-` query param, so it can't be spoofed
 * by editing the dashboard URL — but see the panel SQL itself, which must
 * use `${var:sqlstring}` for any *user-editable* template variable to avoid
 * reopening this as a SQL-injection hole).
 *
 * Why postgres_fdw instead of a synced/mirrored table: `user_group_memberships`
 * lives in the primary app DB, not this fleet DB, and Postgres has no
 * cross-database queries. A foreign table avoids maintaining a second,
 * sync-prone copy of membership data — every lookup reads the primary DB
 * live, through the FDW connection, so it's always current.
 *
 * Why a view (grafana_user_scoping), not the raw vajra_users table: vajra_users
 * carries password_hash/mfa_secret/recovery_codes/security_answer_*_hash.
 * IMPORT FOREIGN SCHEMA has no column-level filter — it can only limit which
 * *tables* are imported — so importing the raw table would hand grafana_reader
 * (and anyone who can run an ad-hoc query against the Fleet datasource) direct
 * read access to every credential column via the FDW bridge. The view is
 * created in the primary DB itself (see DATABASE_SETUP_QUERIES.createGrafanaUserScopingView
 * in setupDatabase()) and exposes only id/email/role.
 */
async function setupGrafanaGroupScoping(dataSource: DataSource): Promise<void> {
  // Step-by-step logging below: this function is a single ~13-statement chain
  // wrapped by the caller in one generic try/catch (see setupFleetDatabase),
  // so without a marker before each step, a failure only ever surfaces as
  // "Could not provision Grafana group-scoping" with no indication of which
  // of the 13 statements actually failed.
  logger.info('Grafana group-scoping: granting BYPASSRLS to grafana_reader');
  // grafana_reader is provisioned by the setup script before this runs; BYPASSRLS
  // lives here (not in a shell script) so there is exactly one place that grants
  // it, regardless of which script created the role.
  await dataSource.query(`ALTER ROLE grafana_reader BYPASSRLS;`);

  logger.info('Grafana group-scoping: creating postgres_fdw extension');
  await dataSource.query(`CREATE EXTENSION IF NOT EXISTS postgres_fdw;`);

  logger.info('Grafana group-scoping: creating/updating vajra_app_db foreign server');
  // Escaped the same way as buildHuntRoleSql's password above: these are
  // deployer-controlled env values, not attacker input, but an embedded `'`
  // (plausible in an auto-generated POSTGRES_PASSWORD) would otherwise break
  // the DDL with a syntax error.
  const escapedPgHost = (process.env.PG_HOST ?? '').replace(/'/g, "''");
  const escapedPgPort = (process.env.PG_PORT ?? '').replace(/'/g, "''");
  const escapedPostgresDb = (process.env.POSTGRES_DB ?? '').replace(/'/g, "''");
  const escapedPostgresUser = (process.env.POSTGRES_USER ?? '').replace(/'/g, "''");
  const escapedPostgresPassword = (process.env.POSTGRES_PASSWORD ?? '').replace(/'/g, "''");
  await dataSource.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_foreign_server WHERE srvname = 'vajra_app_db') THEN
        CREATE SERVER vajra_app_db FOREIGN DATA WRAPPER postgres_fdw
          OPTIONS (host '${escapedPgHost}', port '${escapedPgPort}', dbname '${escapedPostgresDb}');
      END IF;
    END
    $$;
  `);
  // Kept in sync on every deploy (unlike a one-time IF NOT EXISTS) so rotating
  // PG_HOST/PG_PORT/POSTGRES_DB doesn't leave this bridge silently pointed at
  // a stale host forever.
  await dataSource.query(`
    ALTER SERVER vajra_app_db OPTIONS (
      SET host '${escapedPgHost}',
      SET port '${escapedPgPort}',
      SET dbname '${escapedPostgresDb}'
    );
  `);

  logger.info('Grafana group-scoping: creating/updating PUBLIC user mapping for vajra_app_db');
  // FOR PUBLIC so it covers every local role that queries through this
  // server without its own mapping: both grafana_reader at panel-query time
  // AND whichever role runs this setup script itself (needed for the
  // IMPORT FOREIGN SCHEMA introspection below, which authenticates as the
  // current connection, not as grafana_reader).
  await dataSource.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_user_mappings um
        JOIN pg_foreign_server fs ON um.srvid = fs.oid
        WHERE fs.srvname = 'vajra_app_db' AND um.usename = 'public'
      ) THEN
        CREATE USER MAPPING FOR PUBLIC SERVER vajra_app_db
          OPTIONS (user '${escapedPostgresUser}', password '${escapedPostgresPassword}');
      END IF;
    END
    $$;
  `);
  // Same rationale as ALTER SERVER above: rotating POSTGRES_PASSWORD must not
  // silently break this bridge until someone notices scoped dashboards are
  // returning zero rows.
  await dataSource.query(`
    ALTER USER MAPPING FOR PUBLIC SERVER vajra_app_db
    OPTIONS (SET user '${escapedPostgresUser}', SET password '${escapedPostgresPassword}');
  `);

  logger.info('Grafana group-scoping: importing foreign schema into grafana_fdw');
  // Imported into their own schema, not public — this fleet DB's own
  // `entities/users/**` glob (shared with the primary DB config; see
  // ormconfig.ts) means a REAL local `vajra_users` table already exists here
  // in dev (synchronize: true creates it), so importing into public would
  // collide with it. Dropped and re-imported every run so schema changes on
  // the primary DB (e.g. a new column) are picked up rather than going stale.
  await dataSource.query(`CREATE SCHEMA IF NOT EXISTS grafana_fdw;`);
  await dataSource.query(`DROP FOREIGN TABLE IF EXISTS grafana_fdw.vajra_users;`);
  await dataSource.query(`DROP FOREIGN TABLE IF EXISTS grafana_fdw.grafana_user_scoping;`);
  await dataSource.query(`DROP FOREIGN TABLE IF EXISTS grafana_fdw.user_group_memberships;`);
  await dataSource.query(`
    IMPORT FOREIGN SCHEMA public LIMIT TO (grafana_user_scoping, user_group_memberships)
    FROM SERVER vajra_app_db INTO grafana_fdw;
  `);
  await dataSource.query(`GRANT USAGE ON SCHEMA grafana_fdw TO grafana_reader;`);
  await dataSource.query(`GRANT SELECT ON grafana_fdw.grafana_user_scoping, grafana_fdw.user_group_memberships TO grafana_reader;`);

  logger.info('Grafana group-scoping: creating grafana_group_visible/grafana_scan_visible functions');

  // Single predicate every node-scoped panel calls: true for a Super
  // Administrator, or for any node owned by a group the given email has
  // membership in. NULL/unknown email (e.g. an anonymous Grafana session, or
  // anonymous access being disabled entirely) matches nothing — default-deny,
  // not default-allow.
  await dataSource.query(`
    CREATE OR REPLACE FUNCTION grafana_group_visible(p_email text, p_owner_group_id text)
    RETURNS boolean
    LANGUAGE sql STABLE AS $$
      SELECT
        EXISTS (
          SELECT 1 FROM grafana_fdw.grafana_user_scoping WHERE LOWER(email) = LOWER(p_email) AND role = '${SUPER_ADMIN_ROLE}'
        )
        OR (
          p_owner_group_id IS NOT NULL
          AND p_owner_group_id IN (
            SELECT ugm.group_id
            FROM grafana_fdw.user_group_memberships ugm
            JOIN grafana_fdw.grafana_user_scoping u ON u.id = ugm.user_id
            WHERE LOWER(u.email) = LOWER(p_email)
          )
        );
    $$;
  `);
  await dataSource.query(`GRANT EXECUTE ON FUNCTION grafana_group_visible(text, text) TO grafana_reader;`);

  // Companion predicate for data that isn't node-owned (e.g. network scan
  // history, keyed by who ran the scan rather than by owner_group_id): true
  // for a Super Administrator, or if the viewing email shares at least one
  // group with the scan's creator. NULL/unknown creator or email matches
  // nothing — same default-deny stance as grafana_group_visible.
  await dataSource.query(`
    CREATE OR REPLACE FUNCTION grafana_scan_visible(p_email text, p_created_by_user_id bigint)
    RETURNS boolean
    LANGUAGE sql STABLE AS $$
      SELECT
        EXISTS (
          SELECT 1 FROM grafana_fdw.grafana_user_scoping WHERE LOWER(email) = LOWER(p_email) AND role = '${SUPER_ADMIN_ROLE}'
        )
        OR (
          p_created_by_user_id IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM grafana_fdw.user_group_memberships viewer_ugm
            JOIN grafana_fdw.grafana_user_scoping viewer_u ON viewer_u.id = viewer_ugm.user_id
            JOIN grafana_fdw.user_group_memberships creator_ugm ON creator_ugm.group_id = viewer_ugm.group_id
            WHERE LOWER(viewer_u.email) = LOWER(p_email) AND creator_ugm.user_id = p_created_by_user_id
          )
        );
    $$;
  `);
  await dataSource.query(`GRANT EXECUTE ON FUNCTION grafana_scan_visible(text, bigint) TO grafana_reader;`);
}

/**
 * Execute fleet (secondary DB) setup queries.
 * Run during deployment when NODE_ENV=production (synchronize is disabled).
 * Usage: npx ts-node src/orm/config/ormconfig-setup.ts --fleet
 */
export const setupFleetDatabase = async (): Promise<void> => {
  const dataSource = new DataSource(databaseConfig2 as any);
  try {
    await dataSource.initialize();
    logger.info('Initializing fleet database setup');

    // Logged per-table (not one line for all four): the original single
    // "Creating compliance_results table" line covered all four of these
    // statement pairs, so a failure partway through (e.g. the CERT-In table)
    // was indistinguishable in the logs from a failure on the very first one.
    logger.info('Creating compliance_results table');
    await dataSource.query(FLEET_SETUP_QUERIES.createComplianceResultsTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createComplianceResultsIndexes);
    logger.info('Creating SEBI compliance_results table');
    await dataSource.query(FLEET_SETUP_QUERIES.createSebiComplianceResultsTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createSebiComplianceResultsIndexes);
    logger.info('Creating IRDAI compliance_results table');
    await dataSource.query(FLEET_SETUP_QUERIES.createIrdaiComplianceResultsTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createIrdaiComplianceResultsIndexes);
    logger.info('Creating CERT-In compliance_results table');
    await dataSource.query(FLEET_SETUP_QUERIES.createCertinComplianceResultsTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createCertinComplianceResultsIndexes);

    logger.info('Creating Vajra baseline org-level historical compliance table');
    await dataSource.query(FLEET_SETUP_QUERIES.createHistoricalComplianceTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createHistoricalComplianceIndexes);
    await dataSource.query(FLEET_SETUP_QUERIES.addHistoricalComplianceOwnerGroupIdsColumn);

    logger.info('Creating SEBI historical compliance table');
    await dataSource.query(FLEET_SETUP_QUERIES.createSebiHistoricalComplianceTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createSebiHistoricalComplianceIndexes);
    await dataSource.query(FLEET_SETUP_QUERIES.addSebiHistoricalComplianceOwnerGroupIdsColumn);

    logger.info('Creating IRDAI historical compliance table');
    await dataSource.query(FLEET_SETUP_QUERIES.createIrdaiHistoricalComplianceTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createIrdaiHistoricalComplianceIndexes);
    await dataSource.query(FLEET_SETUP_QUERIES.addIrdaiHistoricalComplianceOwnerGroupIdsColumn);

    logger.info('Creating CERT-In historical compliance table');
    await dataSource.query(FLEET_SETUP_QUERIES.createCertinHistoricalComplianceTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createCertinHistoricalComplianceIndexes);
    await dataSource.query(FLEET_SETUP_QUERIES.addCertinHistoricalComplianceOwnerGroupIdsColumn);

    logger.info('Creating packages_snapshot table');
    await dataSource.query(FLEET_SETUP_QUERIES.createPackagesSnapshotTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createPackagesSnapshotIndexes);

    logger.info('Adding group_ids column to nodes table');
    await dataSource.query(FLEET_SETUP_QUERIES.addNodesGroupIdsColumn);
    await dataSource.query(FLEET_SETUP_QUERIES.createNodesGroupIdsIndex);

    logger.info('Adding owner_group_id column to nodes table for single-owner access scoping');
    await dataSource.query(FLEET_SETUP_QUERIES.addNodesOwnerGroupIdColumn);
    await dataSource.query(FLEET_SETUP_QUERIES.createNodesOwnerGroupIdIndex);
    // Row count matters here: per the query's own comment, a node with more
    // than one prior group silently loses all but the first — without this,
    // there is no way from logs to know whether this run backfilled (and
    // potentially narrowed) any nodes, or found none left to migrate.
    const [, backfilledOwnerGroupIdCount] = await dataSource.query(FLEET_SETUP_QUERIES.backfillNodesOwnerGroupIdFromGroupIds);
    logger.info({ backfilledOwnerGroupIdCount }, 'owner_group_id backfill from group_ids complete');

    logger.info('Creating agent_cert_provisioning_tokens table');
    await dataSource.query(FLEET_SETUP_QUERIES.createAgentCertProvisioningTokensTable);
    await dataSource.query(FLEET_SETUP_QUERIES.createAgentCertProvisioningTokensIndexes);
    // network_scan_history/scan_schedules are lazily self-created by the
    // backend's own first boot (see index.ts), not by anything above in this
    // function — on a genuinely fresh fleet DB that hasn't been booted
    // against yet (the realistic day-one state when this runs as part of an
    // automated deploy script, before the backend service has ever started),
    // neither table exists yet. Isolated in its own try/catch, same reasoning
    // as the vajra_hunt block below: this backfill is a one-time data-quality
    // fixup, not something the rest of fleet DB setup depends on, so a
    // missing table here must not abort every step after it.
    try {
      logger.info('Backfilling network_scan_history creator from owning schedule');
      // Row count distinguishes "nothing left to backfill" from "backfilled N
      // rows" — without it, this line reads identically whether the historical
      // visibility bug this fixes affected zero rows or thousands.
      const [, backfilledScanHistoryCount] = await dataSource.query(FLEET_SETUP_QUERIES.backfillNetworkScanHistoryCreatedBy);
      logger.info({ backfilledScanHistoryCount }, 'network_scan_history creator backfill complete');
    } catch (backfillError) {
      logger.warn(
        { err: backfillError },
        'Skipping network_scan_history creator backfill — table(s) not present yet (created on the backend\'s first boot); safe to ignore on a fresh deployment, re-run db:setup:fleet later if this persists after the backend has started at least once',
      );
    }

    // Deliberately isolated from the try/catch that guards the rest of setup:
    // provisioning vajra_hunt needs CREATEROLE, which the application's DB
    // user may not have in every environment. A failure here must not block
    // the fleet DB features every deployment depends on — it only means
    // scoped historical hunting stays unavailable until a DBA runs this step
    // with sufficient privilege.
    try {
      logger.info('Provisioning vajra_hunt role for group-scoped historical hunting');
      await setupHuntRole(dataSource);
      logger.info('vajra_hunt role and RLS policies ready');
    } catch (huntSetupError) {
      logger.warn(
        { err: huntSetupError },
        'Could not provision vajra_hunt role, likely missing CREATEROLE privilege on the connecting DB user; group-scoped historical hunting will be unavailable until run manually with elevated privilege',
      );
    }

    // Isolated for the same reason as vajra_hunt above: CREATE EXTENSION/SERVER
    // needs elevated privilege in some environments, and its absence must not
    // block the rest of setup — the CVE Analysis dashboard just stays
    // fleet-wide (unscoped) until this is run with sufficient privilege.
    try {
      logger.info('Provisioning Grafana group-scoping via postgres_fdw bridge to primary DB');
      await setupGrafanaGroupScoping(dataSource);
      logger.info('Grafana group-scoping ready');
    } catch (grafanaScopingError) {
      logger.warn(
        { err: grafanaScopingError },
        'Could not provision Grafana group-scoping. The usual cause is that the connecting DB user lacks CREATE EXTENSION postgres_fdw and USAGE on the wrapper; grafana/setup.sh grants both as superuser, so re-running it is the normal fix. Until it succeeds grafana_group_visible() does not exist, every scoped dashboard panel errors, and Group Admins must not be admitted to /grafana/ (see controllers/auth/validateGrafana.ts)',
      );
    }

    logger.info('Fleet database setup completed successfully');
    await dataSource.destroy();
  } catch (error) {
    logger.error({ err: error }, 'Fleet database setup failed');
    process.exit(1);
  }
};

/**
 * CLI script to run database setup
 * Usage: npx ts-node src/orm/config/ormconfig-setup.ts
 *        npx ts-node src/orm/config/ormconfig-setup.ts --fleet
 */
if (require.main === module) {
  if (process.argv.includes('--fleet')) {
    setupFleetDatabase();
  } else {
    setupDatabase();
  }
}

export default DATABASE_SETUP_QUERIES;
