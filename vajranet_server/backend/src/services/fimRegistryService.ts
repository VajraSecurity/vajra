/**
 * Per-node Windows registry coverage (docs/FIM_REGISTRY_DESIGN.md, vajra_server repo):
 * profiles, group/node assignments, rules, waivers, per-node publish into ONE managed
 * fim_policies row per Windows node (stable slots, soft-retire), hash-chained history,
 * rollback, measure (count-only distributed query), reconcile job, baseline hygiene and the
 * legacy-policy migration assistant.
 *
 * Invariants kept here:
 *  - Baselines stay strict and button-only. Nothing here creates or changes a baseline row
 *    except compaction (explicit, audited) which REMOVES the node's baseline so monitoring
 *    pauses until Initialize; the soft-retire purge deletes rows of slots that left coverage
 *    more than 7 days ago.
 *  - Fail closed: a resolution or validation error never publishes and never disables the
 *    managed policy; the last good published config keeps running and the node is 'invalid'.
 *  - Every mutation is authorised against the caller's scope AT REQUEST TIME (RegActor),
 *    audited by the controller, and rule/assignment/profile changes append a hash-chained
 *    fim_reg_history snapshot (append-only table).
 *  - All SQL is parameterized. Registry SQL comes only from fimRegistrySql (validated).
 */
import { randomUUID, createHmac, createHash } from 'crypto';
import {
  FimDb, FimQ, rowsOf, publishPolicyTx, fetchPolicy, resolveDriftTx, templateUpgradeAvailable,
  FimNotFoundError, FimConflictError, FimBadRequestError,
} from './fimService';
import {
  FimValidationError, FIM_MANAGED_NAME_PREFIX, pathsChanged, buildScanSql, normalizePaths, type FimPathEntry,
} from '../utils/fim/fimLogic';
import {
  REG_CATALOG, REG_CATALOG_VERSION, REG_TIERS, REG_TIER_RANK, getRegCatalogEntry, anchorBytes, regTierEntries,
  type RegTier, type RegCatalogEntry,
} from '../utils/fim/fimRegistryCatalog';
import {
  normalizeRegistryEntryV2, validateRegistryKeyV2, validateValueName, entryFingerprint, customEntryKey, canonicalRegistryKey,
  exclusionInside, asciiLower, buildRegistryScanSqlV2, isEntryKey, REG_LIMITS, isCleanText, likeMatch, patternMatchesKey,
} from '../utils/fim/fimRegistrySql';
import {
  resolveRegistry, allocateSlots, compactSlots, diffCoverage, canonicalJson, sha256Hex, fromCatalog, customEntry, regRuleHash, namesIntersect, isExact,
  FIM_REG_CAPS, REG_OPS, type RegRule, type RegWaiver, type RegProfile, type RegAssignment, type ResolveResult, type SlotRow,
  type EffectiveEntry, type RegLayer, type RegOp, type RegWaiverAction, type PublishedEntry,
} from '../utils/fim/fimRegistryResolver';

export class FimForbiddenError extends Error {}
/** The FIM registry feature is unavailable (e.g. history key missing): HTTP 503, `code` in the details. */
export class FimUnavailableError extends Error {
  constructor(message: string, public code: string) { super(message); }
}

// Feature-level kill state set at boot (never a process exit): registry writes are refused.
let registryDisabled: { reason: string; code: string } | null = null;
export function setRegistryDisabled(reason: string | null, code = 'unavailable'): void { registryDisabled = reason ? { reason, code } : null; }
export function registryDisabledReason(): string | null { return registryDisabled?.reason ?? null; }
function assertRegistryAvailable(): void {
  if (registryDisabled) throw new FimUnavailableError(`FIM registry is disabled: ${registryDisabled.reason}`, registryDisabled.code);
}

// Non-fatal health findings shown in the registry settings view (UI amber list).
const healthWarnings = new Map<string, string>();
export function setHealthWarning(key: string, text: string | null): void { if (text) healthWarnings.set(key, text); else healthWarnings.delete(key); }
export function listHealthWarnings(): string[] { return [...healthWarnings.values()]; }

/** Triggers that make the history tamper-evident: they must exist and be enabled. */
export const FIM_REQUIRED_TRIGGERS: [string, string][] = [
  ['fim_reg_history', 'trg_fim_reg_history_no_update'], ['fim_reg_history', 'trg_fim_reg_history_no_truncate'],
  ['fim_reg_anchor_outbox', 'trg_fim_reg_anchor_outbox_guard'], ['fim_reg_anchor_outbox', 'trg_fim_reg_anchor_outbox_no_truncate'],
  ['fim_reg_history_hwm', 'trg_fim_reg_history_hwm_guard'], ['fim_reg_history_hwm', 'trg_fim_reg_history_hwm_no_truncate'],
  ['fim_reg_settings', 'trg_fim_reg_settings_head_guard'],
  ['fim_reg_history_keys', 'trg_fim_reg_history_keys_guard'], ['fim_reg_history_keys', 'trg_fim_reg_history_keys_no_truncate'],
];
export const FIM_EXPECTED_SCHEMA_VERSION = 8;
/** Performance indexes the backend builds CONCURRENTLY in the background (0008a). */
export const FIM_PERF_INDEXES: { name: string; ddl: string }[] = [
  { name: 'idx_dead_letter_queue_table_id', ddl: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dead_letter_queue_table_id ON dead_letter_queue (table_name, id)' },
  { name: 'idx_query_result_qname_host_id', ddl: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_query_result_qname_host_id ON query_result (query_name, host_identifier, id)' },
];

/**
 * Cheap schema invariants checked on every boot and daily (the DDL hash skip alone cannot see a
 * dropped/disabled trigger or a downgraded schema version): returns the problems found.
 */
export async function fimSchemaInvariants(q: FimQ): Promise<string[]> {
  const problems: string[] = [];
  const trg = rowsOf(await q.query(`SELECT c.relname, t.tgname, t.tgenabled FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal`));
  for (const [tbl, name] of FIM_REQUIRED_TRIGGERS) {
    const r = trg.find((x) => x.relname === tbl && x.tgname === name);
    if (!r) problems.push(`trigger ${name} on ${tbl} is missing`);
    else if (r.tgenabled === 'D') problems.push(`trigger ${name} on ${tbl} is disabled`);
  }
  try {
    const v = num(rowsOf(await q.query('SELECT fim_schema_version() AS v'))[0]?.v);
    if (v < FIM_EXPECTED_SCHEMA_VERSION) problems.push(`fim_schema_version() is ${v}, expected ${FIM_EXPECTED_SCHEMA_VERSION}`);
  } catch { problems.push('fim_schema_version() is missing'); }
  return problems;
}

/** Latest object of each FIM DDL block: all present (+ invariants) = the schema is current. */
export const FIM_SCHEMA_MARKERS: { block: string; kind: 'column' | 'table' | 'index'; table?: string; name: string }[] = [
  { block: '0004_fim_base', kind: 'column', table: 'fim_policies', name: 'published_rev' },
  { block: '0004_fim_base', kind: 'column', table: 'fim_drift', name: 'entry_idx' },
  { block: '0005_fim_registry', kind: 'column', table: 'fim_reg_jobs', name: 'lease_token' },
  { block: '0005_fim_registry', kind: 'column', table: 'fim_reg_settings', name: 'history_head_id' },
  { block: '0005_fim_registry', kind: 'table', name: 'fim_reg_history_keys' },
  { block: '0005_fim_registry', kind: 'table', name: 'fim_reg_history_hwm' },
  { block: '0006_fim_verify', kind: 'column', table: 'fim_drift', name: 'confirmed_at' },
  { block: '0006_fim_verify', kind: 'index', name: 'idx_fim_drift_alert' },
  { block: '0006_fim_verify', kind: 'table', name: 'fim_audit' },
  { block: '0007_fim_worker_schema', kind: 'index', name: 'uq_fim_drift_open_v7' },
  { block: '0008_fim_perf', kind: 'column', table: 'fim_drift', name: 'last_realtime_at' },
  { block: '0008_fim_perf', kind: 'table', name: 'fim_cursor_gaps' },
  { block: '0008_fim_perf', kind: 'index', name: 'idx_fim_init_requests_pending_qid' },
  { block: '0008_fim_perf', kind: 'index', name: 'idx_fim_verify_requests_pending_qid' },
  { block: '0008_fim_perf', kind: 'table', name: 'fim_schema_applied' },
];
/**
 * Read-only check (no DDL privileges needed): is the FIM schema already at the expected state?
 * Every block's latest marker object exists and the invariants hold.
 */
export async function fimSchemaCurrent(q: FimQ): Promise<{ current: boolean; missing: string[] }> {
  const missing: string[] = [];
  const cols = new Set(rowsOf(await q.query(`SELECT table_name || '.' || column_name AS k FROM information_schema.columns WHERE table_schema = current_schema()`)).map((r) => r.k));
  const rels = new Set(rowsOf(await q.query(`SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema()`)).map((r) => r.relname));
  for (const m of FIM_SCHEMA_MARKERS) {
    const ok = m.kind === 'column' ? cols.has(`${m.table}.${m.name}`) : rels.has(m.name);
    if (!ok) missing.push(`${m.block}: ${m.kind} ${m.table ? `${m.table}.` : ''}${m.name}`);
  }
  if (!missing.length) missing.push(...await fimSchemaInvariants(q));
  return { current: missing.length === 0, missing };
}
const isPrivilegeError = (err: unknown): boolean => {
  const code = (err as any)?.code ?? (err as any)?.driverError?.code;
  return code === '42501' || /must be owner|permission denied/i.test(String((err as Error)?.message ?? ''));
};

/**
 * Builds the 0008a performance indexes CONCURRENTLY, outside any transaction, one at a time (never
 * inline in the boot DDL: an in-transaction build holds a SHARE lock and blocks inserts). An
 * INVALID leftover from an interrupted build is dropped CONCURRENTLY and rebuilt.
 */
export async function ensurePerfIndexes(db: FimQ, log?: (msg: string, extra?: Record<string, unknown>) => void): Promise<{ built: string[]; missing: string[] }> {
  const built: string[] = [];
  const missing: string[] = [];
  // Session lock 727300 (shared with 0008a; NOT the transactional DDL lock 727299, so a long
  // build never blocks schema changes). Another builder holding it -> skip this round.
  const got = rowsOf(await db.query('SELECT pg_try_advisory_lock(727300) AS ok'))[0]?.ok;
  if (!got) return { built, missing: FIM_PERF_INDEXES.map((x) => x.name) };
  try {
  for (const ix of FIM_PERF_INDEXES) {
    const cur = rowsOf(await db.query(`SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = $1`, [ix.name]))[0];
    if (cur && cur.indisvalid) continue;
    setHealthWarning(`perf:${ix.name}`, `FIM perf index ${ix.name} is being built in the background`);
    try {
      if (cur && !cur.indisvalid) await db.query(`DROP INDEX CONCURRENTLY IF EXISTS ${ix.name}`);
      await db.query(`SET statement_timeout = 0`);
      await db.query(ix.ddl);
      built.push(ix.name);
      setHealthWarning(`perf:${ix.name}`, null);
    } catch (err) {
      missing.push(ix.name);
      setHealthWarning(`perf:${ix.name}`, `FIM perf index ${ix.name} missing (build failed: ${(err as Error).message.slice(0, 200)}; retried later)`);
      log?.('FIM perf index build failed (will retry)', { err, index: ix.name });
    } finally {
      await db.query(`RESET statement_timeout`).catch(() => undefined);
    }
  }
  } finally { await db.query('SELECT pg_advisory_unlock(727300)').catch(() => undefined); }
  return { built, missing };
}

/**
 * Boot-time FIM schema step (never fatal for the process): applies the DDL blocks (hash skip,
 * shared lock, lock timeout, retries), checks the schema invariants and repairs them by forcing a
 * re-apply, checks the history key ring, and sets the registry state (disabled + reason, health
 * warnings) and alerts accordingly. Returns ok=false when the caller should retry later.
 */
export async function bootFimSchema(db: FimDb, blocks: [string, string][], log?: (msg: string, extra?: Record<string, unknown>) => void): Promise<{ ok: boolean; repaired: string[]; problems: string[] }> {
  try {
    // State first (read-only): an up-to-date schema needs NO DDL privileges at all - the block
    // hashes are only recorded (best effort). DDL runs only when something is really missing.
    const state = await fimSchemaCurrent(db);
    if (state.current) {
      const canRecord = rowsOf(await db.query(`SELECT to_regclass('fim_schema_applied') IS NOT NULL AS t`))[0]?.t
        && rowsOf(await db.query(`SELECT has_table_privilege('fim_schema_applied', 'INSERT,UPDATE') AS ok`))[0]?.ok;
      if (canRecord) {
        for (const [name, ddl] of blocks) if (ddl) {
          await db.query(`INSERT INTO fim_schema_applied (name, sha256) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET sha256 = EXCLUDED.sha256 WHERE fim_schema_applied.sha256 <> EXCLUDED.sha256`, [name, sha256Hex(ddl)]);
        }
      }
    } else {
      try {
        // The stored hashes cannot be trusted for the blocks whose objects are missing: re-apply them.
        const stale = [...new Set(state.missing.map((x) => x.split(':')[0]).filter((b) => blocks.some(([name]) => name === b)))];
        if (stale.length && rowsOf(await db.query(`SELECT to_regclass('fim_schema_applied') IS NOT NULL AS t`))[0]?.t) {
          await db.query(`DELETE FROM fim_schema_applied WHERE name = ANY($1::text[])`, [stale]);
        }
        for (const [name, ddl] of blocks) if (ddl) await applyFimDdl(db, name, ddl, log);
        const after = await fimSchemaCurrent(db);
        if (!after.current && after.missing.some((x) => blocks.some(([name]) => x.startsWith(`${name}:`)))) {
          throw Object.assign(new Error(`schema still incomplete after applying the blocks: ${after.missing.slice(0, 5).join('; ')}`), { code: 'FIMSTATE' });
        }
      } catch (err) {
        if (!isPrivilegeError(err)) throw err;
        // Least-privilege app role: the owner must run the migrations. Precise, no retry loop.
        const msg = `FIM migration required: run sql/migrations 0004-0008 (each with psql -1) and 0008a as the schema owner; missing: ${state.missing.slice(0, 5).join('; ')}`;
        setRegistryDisabled(msg.slice(0, 500), 'migration_required');
        log?.('FIM registry DISABLED: migration required (insufficient privileges for DDL)', { err, missing: state.missing });
        await raiseRegistryHealthAlert(db, msg.slice(0, 480)).catch(() => undefined);
        return { ok: true, repaired: [], problems: state.missing };
      }
    }
    let problems = await fimSchemaInvariants(db);
    const repaired: string[] = [];
    if (problems.length) {
      // Re-apply every block regardless of the stored hash, then re-check.
      try {
        await db.query(`DELETE FROM fim_schema_applied WHERE name = ANY($1::text[])`, [blocks.map((b) => b[0])]);
        for (const [name, ddl] of blocks) if (ddl) await applyFimDdl(db, name, ddl, log);
      } catch (err) {
        if (!isPrivilegeError(err)) throw err;
        log?.('FIM schema invariants broken and the app role cannot repair them (owner must re-run the migrations)', { err, problems });
      }
      const after = await fimSchemaInvariants(db);
      repaired.push(...problems.filter((x) => !after.includes(x)));
      problems = after;
      if (repaired.length) {
        setHealthWarning('schema:repaired', `FIM schema invariant broken and re-applied: ${repaired.join('; ')}`.slice(0, 500));
        await configAlert(db, null, `FIM schema invariants were broken and have been re-applied: ${repaired.join('; ')}`.slice(0, 480), 'critical', { repaired }, true).catch(() => undefined);
      }
    }
    if (problems.length) {
      setHealthWarning('schema:invariants', `FIM schema invariants broken: ${problems.join('; ')}`.slice(0, 500));
      await configAlert(db, null, `FIM schema invariants broken: ${problems.join('; ')}`.slice(0, 480), 'critical', { problems }, true).catch(() => undefined);
    } else setHealthWarning('schema:invariants', null);
    const managed = rowsOf(await db.query('SELECT managed_enabled FROM fim_reg_settings WHERE id'))[0]?.managed_enabled === true;
    try {
      assertHistoryKeyForProduction(process.env, managed);
      assertHistoryKeyRingCovers(await storedHistoryKeys(db));
      if (registryDisabled?.code === 'history_key_missing' || registryDisabled?.code === 'schema_unavailable') setRegistryDisabled(null);
    } catch (err) {
      setRegistryDisabled((err as Error).message, 'history_key_missing');
      log?.('FIM registry DISABLED: history key missing or not covering stored rows', { err });
      await raiseRegistryHealthAlert(db, `FIM registry disabled: ${(err as Error).message}`.slice(0, 480)).catch(() => undefined);
    }
    return { ok: true, repaired, problems };
  } catch (err) {
    setRegistryDisabled(`FIM registry schema could not be applied: ${(err as Error).message}`.slice(0, 500), 'schema_unavailable');
    log?.('FIM registry DISABLED: schema could not be applied (retried in the background)', { err });
    await raiseRegistryHealthAlert(db, `FIM registry disabled: schema could not be applied (${(err as Error).message.slice(0, 300)}); retried automatically`).catch(() => undefined);
    return { ok: false, repaired: [], problems: [] };
  }
}

/** Shared advisory lock key of every FIM DDL block / migration (worker migrations use the same). */
export const FIM_DDL_LOCK = 727299;
/**
 * Applies one FIM DDL block at boot without disturbing running workers: skipped entirely when the
 * same text was already applied (no ACCESS EXCLUSIVE locks on a no-op boot); otherwise run in ONE
 * transaction under the shared DDL advisory lock with a lock timeout, retried on lock timeout or
 * deadlock (never fatal for the process; the caller disables the registry on final failure).
 */
export async function applyFimDdl(db: FimDb, name: string, ddl: string, log?: (msg: string, extra?: Record<string, unknown>) => void): Promise<'skipped' | 'applied'> {
  // Normally created by migration 0008 (owner); created here only when the role may.
  if (!rowsOf(await db.query(`SELECT to_regclass('fim_schema_applied') IS NOT NULL AS t`))[0]?.t) {
    await db.query(`CREATE TABLE IF NOT EXISTS fim_schema_applied (name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
  }
  const sha = sha256Hex(ddl);
  if (rowsOf(await db.query('SELECT 1 AS x FROM fim_schema_applied WHERE name = $1 AND sha256 = $2', [name, sha])).length) return 'skipped';
  for (let attempt = 1; ; attempt++) {
    try {
      await db.transaction(async (q) => {
        await q.query(`SET LOCAL lock_timeout = '5s'`);
        await q.query('SELECT pg_advisory_xact_lock($1)', [FIM_DDL_LOCK]);
        await q.query(ddl);
        await q.query(`INSERT INTO fim_schema_applied (name, sha256) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET sha256 = EXCLUDED.sha256, applied_at = now()`, [name, sha]);
      });
      return 'applied';
    } catch (err) {
      const code = (err as any)?.code ?? (err as any)?.driverError?.code;
      if ((code === '55P03' || code === '40P01') && attempt < 6) {
        log?.(`FIM DDL ${name}: ${code === '40P01' ? 'deadlock' : 'lock timeout'}, retrying (${attempt}/5)`, { name });
        await new Promise((r) => setTimeout(r, 1000 * attempt));
        continue;
      }
      throw err;
    }
  }
}

export class FimRateLimitError extends Error {}

const ADVISORY_PUBLISH = 727201;
const ADVISORY_HISTORY = 727202;
const ADVISORY_RECONCILE = 727203;
const ADVISORY_ANCHOR = 727205;
const ADVISORY_RULES = 727206;
const SEV_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
/** Auto-publishes per reconcile sweep (new nodes / group moves / waiver expiry); the rest waits. */
export const FIM_REG_AUTO_PUBLISH_PER_SWEEP = Math.min(5000, Math.max(1, Number(process.env.FIM_REG_AUTO_PUBLISH_PER_SWEEP) || 200));
/** Time box of one reconcile sweep's status pass (resumes where it stopped on the next sweep). */
export const FIM_REG_SWEEP_BUDGET_MS = Math.min(55_000, Math.max(1_000, Number(process.env.FIM_REG_SWEEP_BUDGET_MS) || 40_000));
/** A managed policy of a node that disappeared is disabled at once and deleted after this. */
export const FIM_REG_DELETED_NODE_RETENTION_DAYS = 30;
/** Alert when a node stays 'invalid' this long (§4.3). */
export const FIM_REG_INVALID_ALERT_SECS = 3600;
/** Daily digest when a node still needs Initialize after this (§3.10). */
export const FIM_REG_NEEDS_INIT_DIGEST_SECS = 24 * 3600;
/** A profile tier downgrade affecting more nodes than this raises an alert (§4.3). */
export const FIM_REG_DOWNGRADE_ALERT_NODES = 10;

const now = (): number => Math.floor(Date.now() / 1000);
const num = (v: any): number => (v === null || v === undefined ? 0 : Number(v));
const numOrNull = (v: any): number | null => (v === null || v === undefined ? null : Number(v));
const tsec = (v: any): number => (v ? Math.floor(new Date(v).getTime() / 1000) : 0);

function isUniqueViolation(err: any): boolean {
  return err?.code === '23505' || err?.driverError?.code === '23505';
}
function isFkViolation(err: any): boolean {
  return err?.code === '23503' || err?.driverError?.code === '23503';
}
function isCheckViolation(err: any): boolean {
  return err?.code === '23514' || err?.driverError?.code === '23514';
}

// ---------------------------------------------------------------------------------------------
// Caller context (RBAC, §4.1). Built by the controller from the request; evaluated at request time.
// ---------------------------------------------------------------------------------------------

export interface RegActor {
  email: string | null;
  /** vajra_users.id (two-person rule compares ids, never e-mails). null = system. */
  userId: number | null;
  /** Designated waiver approver (settings.approvers). */
  isApprover?: boolean;
  superAdmin: boolean;
  /** Groups the caller is Group Admin of (act). */
  actGroups: Set<string>;
  /** Hosts the caller may act on; null = all (Super Admin). */
  actHosts: Set<string> | null;
  /** Hosts / groups the caller may view; null = all. */
  viewHosts: Set<string> | null;
  viewGroups: Set<string>;
  requestId: string;
}

export const systemActor = (requestId: string = randomUUID()): RegActor => ({
  email: 'system', userId: null, superAdmin: true, actGroups: new Set(), actHosts: null, viewHosts: null, viewGroups: new Set(), requestId,
});

const actorName = (a: RegActor): string => a.email ?? 'unknown';

export function canWriteScope(a: RegActor, layer: RegLayer, scopeValue: string): boolean {
  if (a.superAdmin) return true;
  if (layer === 'profile') return false;
  if (layer === 'group') return a.actGroups.has(scopeValue);
  return a.actHosts !== null && a.actHosts.has(scopeValue);
}
export function canViewHost(a: RegActor, host: string): boolean {
  return a.viewHosts === null || a.viewHosts.has(host);
}
export function canViewGroup(a: RegActor, gid: string): boolean {
  return a.superAdmin || a.viewGroups.has(gid) || a.actGroups.has(gid);
}
function assertWrite(a: RegActor, layer: RegLayer, scopeValue: string): void {
  if (!canWriteScope(a, layer, scopeValue)) {
    throw new FimForbiddenError(layer === 'profile' ? 'Only a Super Administrator can change profiles' : `You do not have Group Admin access to this ${layer}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Settings (feature switch FIM_REGISTRY_MANAGED)
// ---------------------------------------------------------------------------------------------

export async function getSettings(q: FimQ) {
  const r = rowsOf(await q.query('SELECT managed_enabled, approvers, updated_by, updated_at FROM fim_reg_settings WHERE id'));
  const approvers = ((Array.isArray(r[0]?.approvers) ? r[0].approvers : []) as any[]).filter((a: any) => Number.isSafeInteger(a?.userId))
    .map((a: any) => ({ userId: Number(a.userId), email: String(a.email ?? '') }));
  return { managedEnabled: !!r[0]?.managed_enabled, approvers, updatedBy: r[0]?.updated_by ?? null, updatedAt: numOrNull(r[0]?.updated_at),
    /** Health: the history chain is keyed (false = weaker chain accepted via FIM_HISTORY_ALLOW_UNKEYED). */
    historyKeyed: historyKeyed(),
    /** Non-null while the registry is disabled (registry writes answer 503). */
    registryDisabledReason: registryDisabledReason(),
    /** Non-fatal health findings (perf indexes, repaired schema invariants, ...). */
    healthWarnings: listHealthWarnings() };
}

/** Roles that may be designated waiver approvers. */
export const FIM_APPROVER_ROLES = ['Super Administrator', 'Group Admin'];
/**
 * Approver status at request time: designated in settings AND the account is active (not
 * suspended) AND still holds an admin role. A demoted, suspended or never-designated user is not.
 */
export function isActiveApprover(userId: number | null, approvers: { userId: number }[], user: { role?: string | null; suspended?: boolean | null } | null | undefined): boolean {
  return userId !== null && approvers.some((a) => a.userId === userId) && !!user && user.suspended !== true && FIM_APPROVER_ROLES.includes(String(user.role ?? ''));
}

/**
 * Who may approve a waiver (never their own: compared by user id):
 *  - a Super Administrator: any waiver;
 *  - a designated approver (settings.approvers; the controller also requires the account to be
 *    active - not suspended - and still an admin, re-checked on every request): only node- and
 *    group-scope waivers inside the approver's own act scope. Profile-scope (fleet-wide) waivers
 *    always need a Super Administrator.
 */
export async function canApproveWaivers(q: FimQ, actor: RegActor, w?: { scope_type: string; scope_value: string }): Promise<boolean> {
  if (actor.userId === null) return false;
  if (actor.superAdmin) return true;
  if (actor.isApprover === false) return false;
  if (!(await getSettings(q)).approvers.some((a) => a.userId === actor.userId)) return false;
  if (!w) return true;
  if (w.scope_type === 'profile') return false;
  return canWriteScope(actor, w.scope_type as RegLayer, w.scope_value);
}

/** Designated approvers (Super Admin only). `users` were validated against vajra_users by the caller. */
export async function setApprovers(db: FimDb, users: { userId: number; email: string }[], actor: RegActor, note: string) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can designate waiver approvers');
  if (users.length > 50) throw new FimValidationError('at most 50 approvers');
  return db.transaction(async (q) => {
    const before = await getSettings(q);
    await q.query('UPDATE fim_reg_settings SET approvers = $1::jsonb, updated_by = $2, updated_at = $3 WHERE id',
      [JSON.stringify(users.map((u) => ({ userId: u.userId, email: u.email }))), actorName(actor), now()]);
    const head = await appendHistory(q, 'settings', 'approvers', { approvers: users }, actorName(actor), note);
    await auditTx(q, actor, 'FIM_REG_SETTINGS', { approvers: users, note });
    return { before: before.approvers, after: users, rowHash: head.rowHash, historyHead: head };
  });
}

/**
 * Turning coverage OFF disables every managed policy in ONE transaction through the normal
 * publish path (config ids leave nodes.config_id; drift and baselines are kept, §4.8).
 * Turning it ON only sets the flag: the reconcile job then (re)publishes every Windows node.
 */
export async function setManagedEnabled(db: FimDb, enabled: boolean, actor: RegActor, note: string) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can change registry coverage settings');
  if (enabled) {
    try { assertHistoryKeyForProduction(process.env, true); } catch (e) { throw new FimBadRequestError((e as Error).message); }
  }
  return db.transaction(async (q) => {
    await q.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_RECONCILE]);
    // Exclusive row lock: every publishing path holds FOR SHARE on this row while it publishes,
    // so a publish either completes before the switch (and is then disabled below) or sees it off.
    const before = await getSettings(q);
    await q.query('UPDATE fim_reg_settings SET managed_enabled = $1, updated_by = $2, updated_at = $3 WHERE id', [enabled, actorName(actor), now()]);
    let disabled = 0;
    if (!enabled) {
      // Set-based backout (one statement per table, not one publish per node).
      const pols = rowsOf(await q.query(
        `UPDATE fim_policies SET enabled = false, updated_at = now() WHERE managed_kind = 'registry_node' AND enabled RETURNING id, config_query_id`));
      disabled = pols.length;
      const cqs = pols.map((p) => p.config_query_id).filter((x) => x !== null && x !== undefined).map(String);
      if (cqs.length) {
        await q.query(
          `UPDATE nodes SET config_id = array_to_string(ARRAY(SELECT x FROM unnest(${SQL_IDS}) AS x WHERE NOT (x = ANY($1::text[]))), ',')
           WHERE ${SQL_IDS} && $1::text[]`, [cqs]);
        await q.query('DELETE FROM config_queries WHERE id = ANY($1::bigint[])', [cqs]);
        await q.query(`UPDATE fim_policies SET config_query_id = NULL, published_rev = NULL WHERE managed_kind = 'registry_node' AND config_query_id = ANY($1::bigint[])`, [cqs]);
      }
    }
    const head = await appendHistory(q, 'settings', 'registry', { managedEnabled: enabled }, actorName(actor), note);
    await auditTx(q, actor, 'FIM_REG_SETTINGS', { managedEnabled: enabled, disabledPolicies: disabled, note });
    return { before, after: await getSettings(q), disabledPolicies: disabled, rowHash: head.rowHash, historyHead: head };
  });
}

const SQL_IDS = `ARRAY(SELECT btrim(y) FROM unnest(string_to_array(COALESCE(config_id, ''), ',')) AS y WHERE btrim(y) <> '')`;

/** Shared lock on the switch row + check; held until the publishing transaction ends (kill-switch race). */
async function assertEnabled(q: FimQ): Promise<void> {
  assertRegistryAvailable();
  const r = rowsOf(await q.query('SELECT managed_enabled FROM fim_reg_settings WHERE id FOR SHARE'));
  if (!r[0]?.managed_enabled) throw new FimBadRequestError('Registry coverage is turned off (FIM_REGISTRY_MANAGED); a Super Administrator can turn it on');
}

// ---------------------------------------------------------------------------------------------
// Alerts (alert_type 'fim_config', §4.3)
// ---------------------------------------------------------------------------------------------

async function configAlert(q: FimQ, host: string | null, code: string, severity: 'high' | 'medium' | 'critical', meta: Record<string, unknown>, dedupe = false): Promise<void> {
  if (dedupe) {
    const d = rowsOf(await q.query(
      `SELECT 1 AS x FROM alerts WHERE alert_type = 'fim_config' AND is_open AND event_code = $1 AND host_identifier IS NOT DISTINCT FROM $2::text LIMIT 1`, [code, host]));
    if (d.length) return;
  }
  await q.query(
    `INSERT INTO alerts (host_identifier, hostname, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, os_name, detection_time)
     VALUES ($1::text, (SELECT hostname FROM nodes WHERE host_identifier = $1::text), $2, $3, $4, true, true, $5, 'fim_config', 'File Integrity', '', '',
             (SELECT os_platform FROM nodes WHERE host_identifier = $1::text), $2)`,
    [host, now(), code.slice(0, 500), JSON.stringify({ fim_config: true, ...meta }), severity],
  );
}

/**
 * Audit outbox row in the SAME transaction as the mutation (fim_audit, fleet DB). The primary
 * audit_trail entry written by the controller after commit stays as the external record/anchor.
 */
export async function auditTx(q: FimQ, actor: RegActor, action: string, details: Record<string, unknown>, outcome: 'success' | 'denied' | 'error' = 'success'): Promise<void> {
  await q.query(
    `INSERT INTO fim_audit (at, actor, user_id, action, outcome, request_id, details) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
    [now(), actorName(actor), actor.userId, action, outcome, actor.requestId, JSON.stringify(details ?? {})]);
}

// ---------------------------------------------------------------------------------------------
// Hash-chained history (§4.4). Append-only; one global chain; serialized by an advisory lock.
// ---------------------------------------------------------------------------------------------

/**
 * Key ring for the history chain (keys live outside the database):
 *   FIM_HISTORY_HMAC_KEY          active key (>= 32 characters)
 *   FIM_HISTORY_HMAC_KEY_ID       its id (default 'k1'), stored per row in fim_reg_history.key_id
 *   FIM_HISTORY_HMAC_PREVIOUS_KEYS  older keys still needed to verify old rows, as a JSON object
 *                                  {"<id>": "<key>", ...} (keys may contain any character)
 * Rotation: generate a new key, set FIM_HISTORY_HMAC_KEY_ID to a new id, add the old id and key to
 * FIM_HISTORY_HMAC_PREVIOUS_KEYS, restart. A fingerprint of each key is stored per key id
 * (fim_reg_history_keys): reusing an id with a DIFFERENT key is reported as a key mismatch
 * (configuration error), not as tampering; startup checks every stored key id is configured. New rows use the new key; verification picks each
 * row's key by its key_id. Never drop a previous key while rows hashed with it exist.
 * Rows written without any key (key_id NULL) are accepted only BEFORE the first keyed row.
 */
function keyRing(env: NodeJS.ProcessEnv = process.env): { activeId: string | null; keys: Map<string, Buffer> } {
  const keys = new Map<string, Buffer>();
  const derive = (k: string) => createHash('sha256').update(`vajra-fim-history|${k}`).digest();
  const prevRaw = String(env.FIM_HISTORY_HMAC_PREVIOUS_KEYS ?? '').trim();
  if (prevRaw) {
    let prev: unknown;
    try { prev = JSON.parse(prevRaw); } catch { throw new Error('FIM_HISTORY_HMAC_PREVIOUS_KEYS must be a JSON object {"<key id>": "<key>"}'); }
    if (!prev || typeof prev !== 'object' || Array.isArray(prev)) throw new Error('FIM_HISTORY_HMAC_PREVIOUS_KEYS must be a JSON object {"<key id>": "<key>"}');
    for (const [id, key] of Object.entries(prev as Record<string, unknown>)) if (typeof key === 'string' && key) keys.set(id, derive(key));
  }
  const k = env.FIM_HISTORY_HMAC_KEY || '';
  const activeId = k ? (env.FIM_HISTORY_HMAC_KEY_ID || 'k1') : null;
  if (activeId) keys.set(activeId, derive(k));
  return { activeId, keys };
}

/**
 * Startup check: the history chain must be keyed whenever registry coverage can be used (in any
 * environment, not only NODE_ENV=production). FIM_HISTORY_ALLOW_UNKEYED=1 accepts a weaker,
 * unkeyed chain explicitly (the settings view then shows a warning).
 */
export function assertHistoryKeyForProduction(env: NodeJS.ProcessEnv = process.env, managedEnabled = true): void {
  if (env.FIM_HISTORY_ALLOW_UNKEYED === '1' || !managedEnabled) return;
  if (!env.FIM_HISTORY_HMAC_KEY || env.FIM_HISTORY_HMAC_KEY.length < 32) {
    throw new Error('FIM_HISTORY_HMAC_KEY (>= 32 characters) is required to key the registry history hash chain; set FIM_HISTORY_ALLOW_UNKEYED=1 only to accept a weaker, unkeyed chain');
  }
}
export const historyKeyed = (): boolean => keyRing().activeId !== null;

/** Startup: every key id stored in the chain must be in the key ring (else verification fails). */
export function assertHistoryKeyRingCovers(rows: { key_id: string; fingerprint?: string | null }[], env: NodeJS.ProcessEnv = process.env): void {
  const ring = keyRing(env);
  const missing = rows.map((r) => r.key_id).filter((k) => !ring.keys.has(k));
  if (missing.length) throw new Error(`history key id(s) ${missing.join(', ')} are stored in the chain but not configured (FIM_HISTORY_HMAC_KEY_ID / FIM_HISTORY_HMAC_PREVIOUS_KEYS)`);
  const wrong = rows.filter((r) => r.fingerprint && keyFingerprint(ring.keys.get(r.key_id)!) !== r.fingerprint).map((r) => r.key_id);
  if (wrong.length) throw new Error(`history key mismatch: key id(s) ${wrong.join(', ')} are configured with a different key than the one the chain was written with`);
}
/** Non-secret fingerprint of a key (detects an id reused with a different key). */
function keyFingerprint(key: Buffer): string { return createHmac('sha256', key).update('vajra-fim-history-key-check').digest('hex').slice(0, 32); }
/** Key ids used by the chain with their stored fingerprints (for the startup coverage check). */
export async function storedHistoryKeys(q: FimQ): Promise<{ key_id: string; fingerprint: string | null }[]> {
  return rowsOf(await q.query(
    `SELECT DISTINCT h.key_id, k.fingerprint FROM fim_reg_history h LEFT JOIN fim_reg_history_keys k ON k.key_id = h.key_id WHERE h.key_id IS NOT NULL`));
}
/** Critical oversight alert about the registry feature itself (deduplicated while open). */
export async function raiseRegistryHealthAlert(q: FimQ, code: string): Promise<void> {
  await configAlert(q, null, code, 'critical', { health: true }, true);
}

export function historyRowHash(prev: string | null, row: { at: number; actor: string; reason: string | null; scope_type: string; scope_value: string; snapshot: unknown },
  keyId: string | null | undefined = keyRing().activeId): string {
  const msg = (prev ?? '') + canonicalJson({ at: row.at, actor: row.actor, reason: row.reason ?? null, scope_type: row.scope_type, scope_value: row.scope_value, snapshot: row.snapshot });
  if (keyId === null || keyId === undefined) return sha256Hex(msg);
  const key = keyRing().keys.get(keyId);
  if (!key) throw new Error(`unknown history key id ${keyId}`);
  return createHmac('sha256', key).update(msg, 'utf8').digest('hex');
}

/** Chain head after an append; anchored in the audit trail (another database) via the outbox. */
export interface HistoryHead { id: number; rowHash: string; count: number }

async function appendHistory(q: FimQ, scopeType: string, scopeValue: string, snapshot: unknown, actor: string, reason: string | null): Promise<HistoryHead> {
  // No history (and so no registry change) while the feature is disabled (e.g. history key missing).
  assertRegistryAvailable();
  // Serialised: one global chain, appends never interleave (the anchor is monotonic in id/count).
  await q.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_HISTORY]);
  const last = rowsOf(await q.query('SELECT row_hash FROM fim_reg_history ORDER BY id DESC LIMIT 1'))[0];
  const prev = last?.row_hash ?? null;
  const at = now();
  const snap = JSON.parse(JSON.stringify(snapshot ?? {}));
  const ring = keyRing();
  const keyId = ring.activeId;
  if (keyId) {
    const fp = keyFingerprint(ring.keys.get(keyId)!);
    const stored = rowsOf(await q.query(
      `INSERT INTO fim_reg_history_keys (key_id, fingerprint, first_used_at) VALUES ($1,$2,$3) ON CONFLICT (key_id) DO UPDATE SET key_id = EXCLUDED.key_id RETURNING fingerprint`, [keyId, fp, now()]))[0];
    if (stored && stored.fingerprint !== fp) throw new FimUnavailableError(`history key mismatch: key id ${keyId} was used with a different key; use a new key id when rotating`, 'history_key_mismatch');
  }
  const rowHash = historyRowHash(prev, { at, actor, reason, scope_type: scopeType, scope_value: scopeValue, snapshot: snap }, keyId);
  const ins = rowsOf(await q.query(
    `INSERT INTO fim_reg_history (scope_type, scope_value, snapshot, actor, at, reason, prev_hash, row_hash, key_id) VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8,$9) RETURNING id`,
    [scopeType, scopeValue, JSON.stringify(snap), actor, at, reason, prev, rowHash, keyId],
  ))[0];
  const count = num(rowsOf(await q.query('SELECT count(*) AS n FROM fim_reg_history'))[0]?.n);
  // Anchor outbox in the SAME transaction: the head can never be lost between commit and anchoring.
  await q.query(`INSERT INTO fim_reg_anchor_outbox (history_id, row_hash, row_count, key_id, created_at) VALUES ($1,$2,$3,$4,$5)`, [num(ins.id), rowHash, count, keyId, at]);
  // Monotonic high-water mark (a trigger forbids decreasing it): deleting the newest history row
  // AND its outbox row is still detected locally.
  await q.query(
    `INSERT INTO fim_reg_history_hwm (id, head_id, row_hash, row_count, updated_at) VALUES (true, $1, $2, $3, $4)
     ON CONFLICT (id) DO UPDATE SET head_id = EXCLUDED.head_id, row_hash = EXCLUDED.row_hash, row_count = EXCLUDED.row_count, updated_at = EXCLUDED.updated_at`,
    [num(ins.id), rowHash, count, at]);
  // Second, independent marker (another table and trigger): one marker's loss is detected.
  await q.query('UPDATE fim_reg_settings SET history_head_id = GREATEST(history_head_id, $1) WHERE id', [num(ins.id)]);
  return { id: num(ins.id), rowHash, count };
}

/** Writes a head into the external anchor store (audit trail). Throws on failure. */
export type AnchorWriter = (head: HistoryHead) => Promise<void>;
/** Seconds an anchor write may be pending before verification reports the chain unverifiable. */
export const FIM_HISTORY_ANCHOR_OVERDUE_SECS = 600;

/**
 * Copies the newest pending outbox head into the anchor store and stamps every pending row up to
 * it. Called after each mutation and by the reconcile job (retries after a failed write).
 */
export async function flushHistoryAnchors(db: FimDb, write: AnchorWriter): Promise<{ anchored: number | null }> {
  // Single writer (advisory lock): anchors reach the store in increasing history order.
  return db.transaction(async (q) => {
    await q.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_ANCHOR]);
    const head = rowsOf(await q.query('SELECT history_id, row_hash, row_count FROM fim_reg_anchor_outbox WHERE anchored_at IS NULL ORDER BY history_id DESC LIMIT 1'))[0];
    if (!head) return { anchored: null };
    const h: HistoryHead = { id: num(head.history_id), rowHash: head.row_hash, count: num(head.row_count) };
    await write(h);
    await q.query('UPDATE fim_reg_anchor_outbox SET anchored_at = $2 WHERE anchored_at IS NULL AND history_id <= $1', [h.id, now()]);
    return { anchored: h.id };
  });
}

/** Snapshot of a scope's assignment + active rules (+ profile settings) after a change. */
async function scopeSnapshot(q: FimQ, layer: RegLayer, scopeValue: string): Promise<Record<string, unknown>> {
  const rules = rowsOf(await q.query(
    `SELECT id, op, target, spec, waiver_id, reason, created_by, created_at FROM fim_reg_rules
     WHERE layer = $1 AND scope_value = $2 AND status = 'active' ORDER BY op, target, id`, [layer, scopeValue],
  )).map((r) => ({ id: num(r.id), op: r.op, target: r.target, spec: r.spec ?? {}, waiverId: numOrNull(r.waiver_id), reason: r.reason ?? '', createdBy: r.created_by, createdAt: num(r.created_at) }));
  const snap: Record<string, unknown> = { rules };
  if (layer === 'profile') {
    const p = rowsOf(await q.query('SELECT name, description, tier, is_default, scan_interval_secs, mode FROM fim_reg_profiles WHERE id = $1', [Number(scopeValue)]))[0];
    snap.profile = p ? { name: p.name, description: p.description, tier: p.tier, isDefault: !!p.is_default, scanIntervalSecs: num(p.scan_interval_secs), mode: p.mode } : null;
  } else {
    const a = rowsOf(await q.query('SELECT profile_id, tier FROM fim_reg_assignments WHERE scope_type = $1 AND scope_value = $2', [layer, scopeValue]))[0];
    snap.assignment = a ? { profileId: numOrNull(a.profile_id), tier: a.tier ?? null } : null;
  }
  return snap;
}

async function recordScopeChange(q: FimQ, layer: RegLayer, scopeValue: string, actor: RegActor, reason: string | null): Promise<HistoryHead> {
  return appendHistory(q, layer, scopeValue, await scopeSnapshot(q, layer, scopeValue), actorName(actor), reason);
}

/** Latest chain head anchored outside this database (audit trail), or null if none is known. */
export type HistoryAnchorFn = () => Promise<HistoryHead | null>;
export interface ChainVerification {
  ok: boolean; brokenAt: number | null; rows: number; keyed: boolean; anchored: boolean; reason: string | null;
  /** Integrity could not be established (anchor store unreachable / anchor overdue / missing): not ok. */
  unverifiable: boolean; unkeyedRows: number;
}

/**
 * Verifies the chain. Full by default; `fromCache` reuses the last verified prefix (only rows
 * after it are re-hashed; the nightly job always runs a full check). Each row is checked with the
 * key of its key_id. With an anchor: the anchored head row must exist unchanged and the chain must
 * have at least the anchored number of rows; every outbox head must still exist in the chain; an
 * anchor store that cannot be read, an overdue anchor write, or a missing anchor while heads were
 * anchored make the result UNVERIFIABLE (ok=false) - never silently ok.
 */
/** Rows re-hashed on every incremental verification (the nightly check re-hashes everything). */
export const FIM_HISTORY_VERIFY_WINDOW = 500;
const verifiedPrefix = { id: 0, hash: null as string | null, rows: 0, keyedSeen: false, unkeyed: 0 };
export async function verifyHistoryChain(q: FimQ, opts: { anchor?: HistoryAnchorFn; fromCache?: boolean } = {}): Promise<ChainVerification> {
  const cached = !!opts.fromCache && verifiedPrefix.id > 0;
  let prev: string | null = cached ? verifiedPrefix.hash : null;
  let last = cached ? verifiedPrefix.id : 0;
  let rows = cached ? verifiedPrefix.rows : 0;
  let keyedSeen = cached ? verifiedPrefix.keyedSeen : false;
  let unkeyed = cached ? verifiedPrefix.unkeyed : 0;
  if (cached && last) {
    const chk = rowsOf(await q.query('SELECT row_hash FROM fim_reg_history WHERE id = $1', [last]))[0];
    if (!chk || chk.row_hash !== prev) { prev = null; last = 0; rows = 0; keyedSeen = false; unkeyed = 0; }
  }
  const keyed = historyKeyed();
  const keyRows = rowsOf(await q.query('SELECT key_id, fingerprint, first_used_at FROM fim_reg_history_keys'));
  const keyFps = new Map(keyRows.map((k) => [k.key_id, k.fingerprint]));
  // Once any key was used, rows written after its first use must carry a key id (an attacker
  // re-writing rows unkeyed - key_id NULL - is broken, not merely "unkeyed rows").
  const keyedSince = keyRows.length ? Math.min(...keyRows.map((k) => num(k.first_used_at))) : null;
  const res = (o: Partial<ChainVerification>): ChainVerification => ({ ok: false, brokenAt: null, rows, keyed, anchored: false, reason: null, unverifiable: false, unkeyedRows: unkeyed, ...o });
  for (;;) {
    const batch = rowsOf(await q.query(
      'SELECT id, scope_type, scope_value, snapshot, actor, at, reason, prev_hash, row_hash, key_id FROM fim_reg_history WHERE id > $1 ORDER BY id LIMIT 1000', [last]));
    if (!batch.length) break;
    for (const r of batch) {
      rows++;
      const kid = r.key_id ?? null;
      if (kid === null) {
        unkeyed++;
        if (keyedSeen) return res({ brokenAt: num(r.id), reason: 'row without a key after keyed rows' });
        if (keyedSince !== null && num(r.at) >= keyedSince) return res({ brokenAt: num(r.id), reason: 'row without a key written after a history key was in use' });
      } else keyedSeen = true;
      if (kid !== null && !keyFps.has(kid)) return res({ brokenAt: num(r.id), reason: `the fingerprint row of key id ${kid} is missing (deleted key evidence)` });
      if (kid !== null && keyFps.has(kid) && keyRing().keys.has(kid) && keyFingerprint(keyRing().keys.get(kid)!) !== keyFps.get(kid)) {
        return res({ brokenAt: num(r.id), reason: `key mismatch: key id ${kid} is configured with a different key than the chain was written with (or the key fingerprint was altered)` });
      }
      let expect: string;
      try { expect = historyRowHash(prev, { at: num(r.at), actor: r.actor, reason: r.reason ?? null, scope_type: r.scope_type, scope_value: r.scope_value, snapshot: r.snapshot }, kid); } catch (e) {
        return res({ brokenAt: num(r.id), reason: (e as Error).message, unverifiable: true });
      }
      if ((r.prev_hash ?? null) !== prev || r.row_hash !== expect) return res({ brokenAt: num(r.id), reason: 'hash mismatch' });
      prev = r.row_hash;
      last = num(r.id);
    }
  }
  Object.assign(verifiedPrefix, { id: last, hash: prev, rows, keyedSeen, unkeyed });
  // Rows deleted anywhere (also inside an already-verified prefix): the total must match.
  const total = num(rowsOf(await q.query('SELECT count(*) AS n FROM fim_reg_history'))[0]?.n);
  if (total !== rows) { verifiedPrefix.id = 0; return res({ reason: `row count mismatch (${total} stored, ${rows} verified): rows were deleted or inserted out of order` }); }
  if (opts.fromCache) {
    // Sliding window: re-hash the last FIM_HISTORY_VERIFY_WINDOW rows of the cached prefix each time
    // (a rewrite inside the prefix is caught without waiting for the nightly full check).
    const win = rowsOf(await q.query(
      `SELECT id, scope_type, scope_value, snapshot, actor, at, reason, prev_hash, row_hash, key_id FROM
         (SELECT * FROM fim_reg_history ORDER BY id DESC LIMIT $1) w ORDER BY id`, [FIM_HISTORY_VERIFY_WINDOW]));
    for (const r of win) {
      try {
        if (historyRowHash(r.prev_hash ?? null, { at: num(r.at), actor: r.actor, reason: r.reason ?? null, scope_type: r.scope_type, scope_value: r.scope_value, snapshot: r.snapshot }, r.key_id ?? null) !== r.row_hash) {
          verifiedPrefix.id = 0; return res({ brokenAt: num(r.id), reason: 'hash mismatch (recent window)' });
        }
      } catch (e) { return res({ brokenAt: num(r.id), reason: (e as Error).message, unverifiable: true }); }
    }
  }
  // Local high-water mark: the newest head ever written must still be there, with its hash.
  // (Redundant with the outbox-head check above for most deletions; it alone catches deletion of
  // the newest row TOGETHER with its outbox row.)
  const hwm = rowsOf(await q.query('SELECT head_id, row_hash, row_count FROM fim_reg_history_hwm WHERE id'))[0];
  const head2 = num(rowsOf(await q.query('SELECT history_head_id FROM fim_reg_settings WHERE id'))[0]?.history_head_id);
  if (rows > 0 && (!hwm || num(hwm.head_id) === 0)) return res({ brokenAt: last, reason: 'the high-water mark is missing or reset while history rows exist (truncated or deleted)' });
  if (hwm && head2 !== num(hwm.head_id)) return res({ brokenAt: Math.max(head2, num(hwm.head_id)), reason: `the two head markers disagree (high-water mark ${num(hwm.head_id)}, settings ${head2})` });
  if (hwm && num(hwm.head_id) > 0) {
    const hr = rowsOf(await q.query('SELECT row_hash FROM fim_reg_history WHERE id = $1', [num(hwm.head_id)]))[0];
    if (!hr || hr.row_hash !== hwm.row_hash) return res({ brokenAt: num(hwm.head_id), reason: 'the newest recorded head (high-water mark) is missing or rewritten (deleted or altered history)' });
    if (rows < num(hwm.row_count)) return res({ brokenAt: num(hwm.head_id), reason: `fewer rows (${rows}) than the high-water mark (${num(hwm.row_count)})` });
  }
  // Outbox heads (anchored or not) must still exist: deleting the newest rows is detected at once.
  const lost = rowsOf(await q.query(
    `SELECT o.history_id FROM fim_reg_anchor_outbox o LEFT JOIN fim_reg_history h ON h.id = o.history_id
     WHERE h.id IS NULL OR h.row_hash <> o.row_hash ORDER BY o.history_id DESC LIMIT 1`))[0];
  if (lost) return res({ brokenAt: num(lost.history_id), reason: 'a recorded chain head is missing or rewritten (deleted or altered history)' });
  let anchored = false;
  if (opts.anchor) {
    let head: HistoryHead | null;
    try { head = await opts.anchor(); } catch (e) {
      return res({ unverifiable: true, reason: `anchor store unavailable: ${(e as Error).message}`.slice(0, 300) });
    }
    const overdue = rowsOf(await q.query('SELECT min(created_at) AS t FROM fim_reg_anchor_outbox WHERE anchored_at IS NULL'))[0]?.t;
    if (overdue !== null && overdue !== undefined && num(overdue) < now() - FIM_HISTORY_ANCHOR_OVERDUE_SECS) {
      return res({ unverifiable: true, reason: 'anchor writes are overdue (the newest history rows are not anchored outside the database)' });
    }
    const wasAnchored = rowsOf(await q.query('SELECT max(history_id) AS id FROM fim_reg_anchor_outbox WHERE anchored_at IS NOT NULL'))[0]?.id;
    if (!head) {
      if (wasAnchored !== null && wasAnchored !== undefined) return res({ unverifiable: true, reason: 'the anchor store has no head although heads were anchored' });
      if (rows > 0 && keyed) return res({ unverifiable: true, reason: 'no anchor is available outside the database (anchor store unreachable or empty)' });
    } else {
      anchored = true;
      const row = rowsOf(await q.query('SELECT row_hash FROM fim_reg_history WHERE id = $1', [head.id]))[0];
      if (!row || row.row_hash !== head.rowHash) return res({ brokenAt: head.id, anchored, reason: 'anchored head row missing or rewritten (deleted or altered history)' });
      if (rows < head.count) return res({ brokenAt: head.id, anchored, reason: `fewer rows (${rows}) than anchored (${head.count})` });
      // Monotonic: the anchored head can never be older than what the outbox recorded as anchored.
      if (wasAnchored !== null && wasAnchored !== undefined && head.id < num(wasAnchored)) {
        return res({ brokenAt: head.id, anchored, reason: `anchor regressed (store head ${head.id} < anchored ${num(wasAnchored)}): anchored history was removed` });
      }
    }
  }
  return res({ ok: true, anchored });
}

export async function listHistory(q: FimQ, scopeType: string, scopeValue: string, page: number, pageSize: number, opts: { full?: boolean; anchor?: HistoryAnchorFn } = {}) {
  const total = num(rowsOf(await q.query('SELECT count(*) AS n FROM fim_reg_history WHERE scope_type = $1 AND scope_value = $2', [scopeType, scopeValue]))[0]?.n);
  const rows = rowsOf(await q.query(
    `SELECT * FROM fim_reg_history WHERE scope_type = $1 AND scope_value = $2 ORDER BY id DESC LIMIT $3 OFFSET $4`,
    [scopeType, scopeValue, pageSize, (page - 1) * pageSize]));
  // Incremental by default (only rows after the last verified prefix); full on request / nightly.
  const chain = await verifyHistoryChain(q, { fromCache: !opts.full, anchor: opts.anchor });
  return {
    items: rows.map((r) => ({ id: num(r.id), scopeType: r.scope_type, scopeValue: r.scope_value, actor: r.actor, at: num(r.at), reason: r.reason ?? null, snapshot: r.snapshot ?? {}, rowHash: r.row_hash, prevHash: r.prev_hash ?? null })),
    total, page, pageSize, chainOk: chain.ok, chainBrokenAt: chain.brokenAt, chainReason: chain.reason, chainKeyed: chain.keyed, chainAnchored: chain.anchored,
    /** ok | unverifiable (integrity cannot be established right now - NOT evidence of tampering) | broken. */
    chainStatus: chain.ok ? 'ok' : chain.unverifiable ? 'unverifiable' : 'broken', chainUnkeyedRows: chain.unkeyedRows,
  };
}

// ---------------------------------------------------------------------------------------------
// Layer data
// ---------------------------------------------------------------------------------------------

export interface LayerData {
  profiles: (RegProfile & { description: string; version: number; createdBy: string | null; updatedBy: string | null; createdAt: number; updatedAt: number })[];
  assignments: Map<string, RegAssignment & { version: number; updatedBy: string | null; updatedAt: number }>;
  rules: (RegRule & { reason: string; createdBy: string; createdAt: number })[];
  waivers: RegWaiver[];
  measured: Map<string, { rows: number; bytes: number }>;
}

export async function loadLayerData(q: FimQ, filter?: { host?: string; group?: string | null }): Promise<LayerData> {
  const profiles = rowsOf(await q.query('SELECT * FROM fim_reg_profiles ORDER BY id')).map((p) => ({
    id: num(p.id), name: p.name, description: p.description ?? '', tier: p.tier as RegTier, isDefault: !!p.is_default,
    scanIntervalSecs: num(p.scan_interval_secs), mode: p.mode, version: num(p.version), createdBy: p.created_by ?? null,
    updatedBy: p.updated_by ?? null, createdAt: tsec(p.created_at), updatedAt: tsec(p.updated_at),
  }));
  const f = filter ?? null;
  const asg = rowsOf(await q.query(
    `SELECT * FROM fim_reg_assignments WHERE $1::boolean OR (scope_type = 'node' AND scope_value = $2) OR (scope_type = 'group' AND scope_value = $3)`,
    [f === null, f?.host ?? '', f?.group ?? '']));
  const assignments = new Map<string, RegAssignment & { version: number; updatedBy: string | null; updatedAt: number }>();
  for (const a of asg) assignments.set(`${a.scope_type}:${a.scope_value}`, { scopeType: a.scope_type, scopeValue: a.scope_value, profileId: numOrNull(a.profile_id), tier: a.tier ?? null, version: num(a.version), updatedBy: a.updated_by ?? null, updatedAt: tsec(a.updated_at) });
  const rules = rowsOf(await q.query(
    `SELECT * FROM fim_reg_rules WHERE status = 'active' AND ($1::boolean OR layer = 'profile' OR (layer = 'node' AND scope_value = $2) OR (layer = 'group' AND scope_value = $3)) ORDER BY id`,
    [f === null, f?.host ?? '', f?.group ?? ''])).map((r) => ({
    id: num(r.id), layer: r.layer, scopeValue: r.scope_value, op: r.op, target: r.target, spec: r.spec ?? {}, waiverId: numOrNull(r.waiver_id),
    reason: r.reason ?? '', createdBy: r.created_by, createdAt: num(r.created_at),
  }));
  // An approval by a designated approver stays valid only while that user is still designated.
  const designated = new Set((await getSettings(q)).approvers.map((a) => a.userId));
  const waivers = rowsOf(await q.query(`SELECT * FROM fim_reg_waivers WHERE status IN ('approved','pending')`)).map((w) => ({
    id: num(w.id), entryKey: w.entry_key, scopeType: w.scope_type, scopeValue: w.scope_value, action: w.action,
    requestedBy: w.requested_by, approvedBy: w.approved_by ?? null,
    status: w.status === 'approved' && w.approved_by_role === 'approver' && !designated.has(num(w.approved_by_user_id)) ? 'revoked' : w.status,
    expiresAt: num(w.expires_at), ruleHash: w.rule_hash ?? null,
  }));
  const measured = new Map<string, { rows: number; bytes: number }>();
  for (const m of rowsOf(await q.query(
    `SELECT DISTINCT ON (fingerprint) fingerprint, rows_count, bytes_count FROM fim_reg_measure WHERE status = 'done' ORDER BY fingerprint, completed_at DESC`))) {
    measured.set(m.fingerprint, { rows: num(m.rows_count), bytes: num(m.bytes_count) });
  }
  return { profiles, assignments, rules, waivers, measured };
}

export interface WinNode { host: string; hostname: string | null; ownerGroupId: string | null }

async function getWindowsNode(q: FimQ, host: string): Promise<WinNode> {
  const r = rowsOf(await q.query('SELECT host_identifier, hostname, os_platform, owner_group_id FROM nodes WHERE host_identifier = $1', [host]))[0];
  if (!r) throw new FimNotFoundError('Node not found');
  if (String(r.os_platform ?? '').toLowerCase() !== 'windows') throw new FimBadRequestError('Registry coverage is only available for Windows nodes');
  return { host: r.host_identifier, hostname: r.hostname ?? null, ownerGroupId: r.owner_group_id ?? null };
}

export function resolveFor(node: WinNode, data: LayerData, opts: {
  extraRules?: RegRule[]; dropRuleIds?: Set<number>; nodeAssignment?: RegAssignment | null; tierOverride?: RegTier; skipNodeLayer?: boolean; now?: number;
} = {}): ResolveResult {
  const rules: RegRule[] = [...data.rules.filter((r) => !opts.dropRuleIds?.has(r.id)), ...(opts.extraRules ?? [])];
  return resolveRegistry({
    host: node.host, ownerGroupId: node.ownerGroupId, profiles: data.profiles,
    nodeAssignment: opts.nodeAssignment !== undefined ? opts.nodeAssignment : data.assignments.get(`node:${node.host}`) ?? null,
    groupAssignment: node.ownerGroupId ? data.assignments.get(`group:${node.ownerGroupId}`) ?? null : null,
    rules, waivers: data.waivers, measured: data.measured, tierOverride: opts.tierOverride, skipNodeLayer: opts.skipNodeLayer, now: opts.now ?? now(),
  });
}

// ---------------------------------------------------------------------------------------------
// Managed policy + slots
// ---------------------------------------------------------------------------------------------

interface ManagedPolicyRow { id: number; rev: number; publishedRev: number | null; enabled: boolean; paths: FimPathEntry[]; configQueryId: number | null }

async function getManagedPolicy(q: FimQ, host: string, forUpdate = false): Promise<ManagedPolicyRow | null> {
  const r = rowsOf(await q.query(
    `SELECT id, rev, published_rev, enabled, paths, config_query_id FROM fim_policies WHERE managed_kind = 'registry_node' AND managed_host = $1${forUpdate ? ' FOR UPDATE' : ''}`, [host]))[0];
  return r ? { id: num(r.id), rev: num(r.rev), publishedRev: numOrNull(r.published_rev), enabled: !!r.enabled, paths: r.paths ?? [], configQueryId: numOrNull(r.config_query_id) } : null;
}

async function loadSlots(q: FimQ, host: string, forUpdate = false): Promise<SlotRow[]> {
  return rowsOf(await q.query(`SELECT * FROM fim_reg_slots WHERE host_identifier = $1 ORDER BY slot_idx${forUpdate ? ' FOR UPDATE' : ''}`, [host])).map((s) => ({
    slotIdx: num(s.slot_idx), entryKey: s.entry_key, fingerprint: s.fingerprint, createdAt: num(s.created_at),
    retiredAt: numOrNull(s.retired_at), purgeAfter: numOrNull(s.purge_after), purgedAt: numOrNull(s.purged_at),
  }));
}

function publishedEntries(paths: FimPathEntry[]): PublishedEntry[] {
  const out: PublishedEntry[] = [];
  paths.forEach((p, i) => {
    if (p.retired || p.kind !== 'registry' || !p.entryKey) return;
    out.push({ entryKey: p.entryKey, fingerprint: p.fingerprint ?? '', path: p.path ?? '', severity: p.severity, category: p.category, label: p.label ?? '', slot: i });
  });
  return out;
}

/** Live slots of a host that have never been initialised since the slot was created. */
async function needsInitSlots(q: FimQ, policyId: number | null, host: string): Promise<number[]> {
  if (!policyId) return [];
  const locked = rowsOf(await q.query(`SELECT 1 AS x FROM fim_host_state WHERE policy_id = $1 AND host_identifier = $2 AND state = 'locked'`, [policyId, host])).length > 0;
  const rows = rowsOf(await q.query(
    `SELECT s.slot_idx FROM fim_reg_slots s WHERE s.host_identifier = $2 AND s.retired_at IS NULL
       AND (NOT $3::boolean OR NOT EXISTS (SELECT 1 FROM fim_init_requests r WHERE r.policy_id = $1 AND r.host_identifier = $2
             AND r.entry_idx = s.slot_idx AND r.status = 'done' AND r.completed_at >= s.created_at))
     ORDER BY s.slot_idx`, [policyId, host, locked]));
  return rows.map((r) => num(r.slot_idx));
}

async function writeSlots(q: FimQ, host: string, changed: SlotRow[]): Promise<void> {
  // Retirements first so the partial unique index (one live slot per entry key) holds at every statement.
  const ordered = [...changed.filter((s) => s.retiredAt !== null), ...changed.filter((s) => s.retiredAt === null)];
  for (const s of ordered) {
    await q.query(
      `INSERT INTO fim_reg_slots (host_identifier, slot_idx, entry_key, fingerprint, created_at, retired_at, purge_after, purged_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (host_identifier, slot_idx) DO UPDATE SET entry_key = EXCLUDED.entry_key, fingerprint = EXCLUDED.fingerprint, created_at = EXCLUDED.created_at,
         retired_at = EXCLUDED.retired_at, purge_after = EXCLUDED.purge_after, purged_at = EXCLUDED.purged_at`,
      [host, s.slotIdx, s.entryKey, s.fingerprint, s.createdAt, s.retiredAt, s.purgeAfter, s.purgedAt],
    );
  }
}

/** Compact stored form (the full entry list is recomputed on demand; ~1 KB per node, not ~10 KB). */
function resolvedJson(res: ResolveResult, slots: Map<string, number>, needsInit: number[]): Record<string, unknown> {
  void slots;
  return {
    profile: res.profile, tier: res.tier, mode: res.mode, scanIntervalSecs: res.scanIntervalSecs, totals: res.totals,
    blocked: res.blocked.length, blockedSample: res.blocked.slice(0, 10), warnings: res.warnings.slice(0, 20), errors: res.errors.slice(0, 20),
    needsInitSlots: needsInit, usedWaivers: res.usedWaivers,
  };
}

async function upsertEffective(q: FimQ, host: string, f: {
  policyId: number | null; ownerGroupId: string | null; resolved: Record<string, unknown>; resolvedHash: string; status: string; error: string | null;
  published?: { hash: string; by: string; waivers: number[] } | null; inputsKey?: string | null;
}): Promise<void> {
  const t = now();
  await q.query(
    `INSERT INTO fim_reg_effective (host_identifier, policy_id, catalog_version, owner_group_id, resolved, resolved_hash, resolved_at,
        published_hash, published_at, published_by, status, error, invalid_since, needs_init_since, inputs_key, published_waivers)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,CASE WHEN $8::text IS NULL THEN NULL ELSE $7::bigint END,$9,$10,$11,
             CASE WHEN $10 = 'invalid' THEN $7::bigint END, CASE WHEN $10 = 'needs_init' THEN $7::bigint END, $12, COALESCE($13::jsonb, '[]'::jsonb))
     ON CONFLICT (host_identifier) DO UPDATE SET
       policy_id = COALESCE(EXCLUDED.policy_id, fim_reg_effective.policy_id), catalog_version = EXCLUDED.catalog_version,
       owner_group_id = CASE WHEN $8::text IS NULL THEN fim_reg_effective.owner_group_id ELSE EXCLUDED.owner_group_id END,
       resolved = EXCLUDED.resolved, resolved_hash = EXCLUDED.resolved_hash, resolved_at = EXCLUDED.resolved_at,
       published_hash = COALESCE(EXCLUDED.published_hash, fim_reg_effective.published_hash),
       published_at = COALESCE(EXCLUDED.published_at, fim_reg_effective.published_at),
       published_by = COALESCE(EXCLUDED.published_by, fim_reg_effective.published_by),
       published_waivers = CASE WHEN $8::text IS NULL THEN fim_reg_effective.published_waivers ELSE EXCLUDED.published_waivers END,
       status = EXCLUDED.status, error = EXCLUDED.error, inputs_key = COALESCE(EXCLUDED.inputs_key, fim_reg_effective.inputs_key),
       auto_attempt_hash = CASE WHEN $8::text IS NULL THEN fim_reg_effective.auto_attempt_hash END,
       invalid_since = CASE WHEN EXCLUDED.status = 'invalid' THEN COALESCE(fim_reg_effective.invalid_since, EXCLUDED.resolved_at) END,
       needs_init_since = CASE WHEN EXCLUDED.status = 'needs_init' THEN COALESCE(fim_reg_effective.needs_init_since, EXCLUDED.resolved_at) END`,
    [host, f.policyId, REG_CATALOG_VERSION, f.ownerGroupId, JSON.stringify(f.resolved), f.resolvedHash, t,
      f.published?.hash ?? null, f.published?.by ?? null, f.status, f.error, f.inputsKey ?? null,
      f.published ? JSON.stringify(f.published.waivers) : null],
  );
}

/**
 * Digest of everything a node's resolution depends on (reconcile cache, §3.10): catalog version,
 * all profiles, the node's group, assignment + rules of its group / node, profile rules, the set
 * of currently VALID waivers (bound hashes; depends on `now`) and the measurements.
 */
export function inputsKeyFor(node: WinNode, data: LayerData, t: number): string {
  const rulesOf = (layer: string, scope: string | null) => data.rules.filter((r) => r.layer === layer && (scope === null || r.scopeValue === scope))
    .map((r) => [r.id, r.scopeValue, r.op, r.target, r.spec, r.waiverId]).sort((x, y) => Number(x[0]) - Number(y[0]));
  const valid = data.waivers.filter((w) => w.status === 'approved' && w.expiresAt > t).map((w) => [w.id, w.ruleHash, w.approvedBy, w.requestedBy]).sort((x, y) => Number(x[0]) - Number(y[0]));
  return sha256Hex(canonicalJson({
    v: REG_CATALOG_VERSION, profiles: data.profiles.map((p) => [p.id, p.tier, p.isDefault, p.scanIntervalSecs, p.mode, p.version]),
    group: node.ownerGroupId, ag: node.ownerGroupId ? data.assignments.get(`group:${node.ownerGroupId}`) ?? null : null, an: data.assignments.get(`node:${node.host}`) ?? null,
    rp: rulesOf('profile', null), rg: node.ownerGroupId ? rulesOf('group', node.ownerGroupId) : [], rn: rulesOf('node', node.host),
    w: valid, m: [...data.measured.entries()].sort(),
  }));
}

export interface PublishNodeResult {
  host: string;
  status: 'in_sync' | 'pending' | 'needs_init' | 'invalid' | 'unmanaged';
  policyId: number | null;
  rev: number | null;
  revChanged: boolean;
  needsInit: number[];
  newSlots: number[];
  retired: number[];
  revived: number[];
  error: string | null;
  blocked: number;
  usedWaivers: number[];
}

/**
 * Publish ONE node (one transaction, serialized per host by an advisory lock):
 * resolve -> (stale expected hash: 409) -> invalid: keep the last published config ->
 * allocate/retire slots -> upsert the managed policy (+ rev bump iff the slot fingerprints
 * changed) -> publishPolicy -> soft-retire (open drift on retired slots closed as ignored,
 * baseline rows kept 7 days) -> fim_reg_effective.
 */
/** A resolution computed earlier (reconcile pre-check), reused when its inputs are unchanged. */
export interface PreResolved { res: ResolveResult; inputsKey: string }
export async function publishNodeTx(q: FimQ, host: string, opts: { actor: RegActor; expectedHash?: string | null; note: string | null; auto?: string | null; data?: LayerData; pre?: PreResolved }): Promise<PublishNodeResult> {
  await q.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [ADVISORY_PUBLISH, host]);
  await assertEnabled(q);
  const node = await getWindowsNode(q, host);
  const data = opts.data ?? await loadLayerData(q, { host, group: node.ownerGroupId });
  const t = now();
  // Reuse the caller's resolution when its input digest still matches (no second resolution).
  let res = opts.pre && opts.pre.inputsKey === inputsKeyFor(node, data, t) ? opts.pre.res : resolveFor(node, data, { now: t });
  // Any stated review hash is checked, an empty one included (an empty string never matches).
  if (opts.expectedHash !== undefined && opts.expectedHash !== null && opts.expectedHash !== res.hash) {
    throw new FimConflictError('The coverage of this node changed since it was reviewed; reload, review the changes and apply again');
  }
  // Fail-safe: an INVALID resolution normally keeps the last published config - but never while
  // that config still relies on a waiver that is no longer valid (expired / revoked / approver
  // removed). Then the catalog-only coverage of the node's profile tier (no custom or override
  // rules, so protected coverage is complete) is published instead, the node stays 'invalid'
  // and a critical alert says so.
  // Fail-safe (never a stale config): when the node's resolution is INVALID, the catalog-only
  // coverage of its profile tier is published instead (no custom, override or waiver-backed rules:
  // protected coverage is complete and no expired/revoked waiver or revoked reduction stays in
  // force). The node stays 'invalid' (alerted per cause after an hour; immediately and critically
  // when a dead waiver was involved) until its rules are fixed.
  let failSafe: { error: string; deadWaivers: number[] } | null = null;
  if (!res.ok) {
    const effPrev = rowsOf(await q.query('SELECT published_waivers FROM fim_reg_effective WHERE host_identifier = $1', [host]))[0];
    const published: number[] = Array.isArray(effPrev?.published_waivers) ? effPrev.published_waivers.map(Number) : [];
    const valid = new Set(data.waivers.filter((w) => w.status === 'approved' && w.expiresAt > t).map((w) => w.id));
    const dead = published.filter((id) => !valid.has(id));
    const safe = resolveFor(node, { ...data, rules: [], waivers: [] }, { now: t });
    if (safe.ok) { failSafe = { error: res.errors.join('; ').slice(0, 4000), deadWaivers: dead }; res = safe; }
  }
  const pol = await getManagedPolicy(q, host, true);
  const base: PublishNodeResult = { host, status: 'invalid', policyId: pol?.id ?? null, rev: pol?.rev ?? null, revChanged: false, needsInit: [], newSlots: [], retired: [], revived: [], error: null, blocked: res.blocked.length, usedWaivers: res.usedWaivers };
  if (!res.ok) {
    // Fail closed: keep whatever is published; record why.
    const error = res.errors.join('; ').slice(0, 4000);
    await upsertEffective(q, host, { policyId: pol?.id ?? null, ownerGroupId: node.ownerGroupId, resolved: resolvedJson(res, new Map(), []), resolvedHash: res.hash || 'invalid', status: 'invalid', error, inputsKey: inputsKeyFor(node, data, t) });
    if (opts.auto) await q.query('UPDATE fim_reg_effective SET auto_attempt_hash = $2 WHERE host_identifier = $1', [host, res.hash || 'invalid']);
    return { ...base, error };
  }
  const slots = await loadSlots(q, host, true);
  const plan = allocateSlots(slots, res.entries, t);
  if (plan.paths.length > FIM_REG_CAPS.pathsMax) {
    const error = `${plan.paths.length} slots (incl. retired) exceed ${FIM_REG_CAPS.pathsMax}; compact the coverage of this node first`;
    await upsertEffective(q, host, { policyId: pol?.id ?? null, ownerGroupId: node.ownerGroupId, resolved: resolvedJson(res, new Map(), []), resolvedHash: res.hash, status: 'invalid', error, inputsKey: inputsKeyFor(node, data, t) });
    if (opts.auto) await q.query('UPDATE fim_reg_effective SET auto_attempt_hash = $2 WHERE host_identifier = $1', [host, res.hash]);
    return { ...base, error };
  }
  if (plan.paths.length > FIM_REG_CAPS.pathsMax * 0.9) {
    await configAlert(q, host, `FIM registry: ${host} uses ${plan.paths.length} of ${FIM_REG_CAPS.pathsMax} slots (incl. retired); compact its coverage soon`, 'medium',
      { host, slots: plan.paths.length, cap: FIM_REG_CAPS.pathsMax }, true);
  }
  // Defence in depth: every live entry must produce valid SQL before anything is written.
  for (const p of plan.paths) if (!p.retired) buildScanSql(p as never, 'windows');

  let policyId: number;
  let rev: number;
  let revChanged: boolean;
  if (!pol) {
    const ins = rowsOf(await q.query(
      `INSERT INTO fim_policies (name, description, os_platform, paths, scan_interval_secs, realtime, mode, learn_scans, enabled, template, created_by, managed_kind, managed_host)
       VALUES ($1, $2, 'windows', $3::jsonb, $4, true, $5, 1, true, 'registry-managed', $6, 'registry_node', $7) RETURNING id, rev`,
      [`${FIM_MANAGED_NAME_PREFIX}${host}`, 'Per-node registry coverage (managed by /api/fim/registry; do not edit by hand).', JSON.stringify(plan.paths),
        res.scanIntervalSecs, res.mode, actorName(opts.actor), host],
    ));
    policyId = num(ins[0].id);
    rev = num(ins[0].rev);
    revChanged = true;
  } else {
    policyId = pol.id;
    revChanged = pathsChanged(pol.paths, plan.paths as unknown as FimPathEntry[]);
    const upd = rowsOf(await q.query(
      `UPDATE fim_policies SET paths = $2::jsonb, scan_interval_secs = $3, mode = $4, realtime = true, enabled = true,
         rev = CASE WHEN $5::boolean THEN rev + 1 ELSE rev END, updated_at = now() WHERE id = $1 RETURNING rev`,
      [policyId, JSON.stringify(plan.paths), res.scanIntervalSecs, res.mode, revChanged]));
    rev = num(upd[0].rev);
  }
  await q.query('DELETE FROM fim_policy_targets WHERE policy_id = $1', [policyId]);
  await q.query(`INSERT INTO fim_policy_targets (policy_id, target_type, target_value) VALUES ($1, 'node', $2)`, [policyId, host]);
  await writeSlots(q, host, plan.changed);
  await publishPolicyTx(q, policyId);

  // Retired slots: an entry whose definition CHANGED keeps its evidence (open drift moves to the
  // new slot, so 'Initialize needs force for open critical drift' still applies); only drift of an
  // entry that left coverage ENTIRELY is closed, and closing critical/high drift is alerted.
  const oldKey = new Map(slots.map((sl) => [sl.slotIdx, sl.entryKey]));
  const closed: { id: number; severity: string; slot: number }[] = [];
  const carried: { from: number; to: number; n: number }[] = [];
  const reslotted: string[] = [];
  const suspended: { entryKey: string; slot: number; openDrift: number; serious: number }[] = [];
  for (const slot of plan.retired) {
    const key = oldKey.get(slot);
    const to = key !== undefined ? plan.entrySlot.get(key) : undefined;
    if (to !== undefined && key && getRegCatalogEntry(key)?.protected) reslotted.push(`${key} (slot ${slot} -> ${to})`);
    if (to !== undefined) {
      const u = rowsOf(await q.query(
        `UPDATE fim_drift SET entry_idx = $4, note = left(COALESCE(note || ' | ', '') || $5, 2000)
         WHERE policy_id = $1 AND host_identifier = $2 AND status = 'open' AND entry_idx = $3 RETURNING id`,
        [policyId, host, slot, to, `coverage of this entry changed: carried from slot ${slot} to slot ${to} (Initialize slot ${to} to compare again)`]));
      if (u.length) carried.push({ from: slot, to, n: u.length });
    } else if (failSafe) {
      // Fail-safe publish: coverage is only SUSPENDED (the rules are still there, the resolution
      // is broken) - open drift is never closed; it keeps its slot (revived when coverage returns).
      const u = rowsOf(await q.query(
        `UPDATE fim_drift SET note = left(COALESCE(note || ' | ', '') || $4, 2000)
         WHERE policy_id = $1 AND host_identifier = $2 AND status = 'open' AND entry_idx = $3 RETURNING id, severity`,
        [policyId, host, slot, 'coverage suspended: the node coverage is invalid and the fail-safe catalog-only coverage is published']));
      if (key) suspended.push({ entryKey: key, slot, openDrift: u.length, serious: u.filter((x) => x.severity === 'critical' || x.severity === 'high').length });
    } else {
      for (const r of rowsOf(await q.query(
        `SELECT id, severity FROM fim_drift WHERE policy_id = $1 AND host_identifier = $2 AND status = 'open' AND entry_idx = $3`, [policyId, host, slot]))) {
        closed.push({ id: num(r.id), severity: r.severity, slot });
      }
    }
  }
  if (suspended.length) {
    await configAlert(q, host, `FIM registry: coverage SUSPENDED on ${host} (invalid resolution, fail-safe catalog-only coverage): ${suspended.map((x) => x.entryKey).join(', ')}`.slice(0, 480), 'critical',
      { host, suspended, cause: failSafe?.error.slice(0, 500) ?? null, by: actorName(opts.actor), byUserId: opts.actor.userId, requestId: opts.actor.requestId }, true);
  }
  if (reslotted.length) {
    await configAlert(q, host, `FIM registry: protected entr${reslotted.length === 1 ? 'y' : 'ies'} re-slotted on ${host} - needs Initialize: ${reslotted.join(', ')}`.slice(0, 480), 'high',
      { host, reslotted, by: actorName(opts.actor), byUserId: opts.actor.userId, requestId: opts.actor.requestId });
  }
  if (closed.length) {
    await resolveDriftTx(q, closed.map((r) => r.id), 'ignore', actorName(opts.actor), `Registry coverage removed by ${actorName(opts.actor)}${opts.note ? `: ${opts.note}` : ''}`.slice(0, 2000), null, null);
    const serious = closed.filter((r) => r.severity === 'critical' || r.severity === 'high');
    if (serious.length) {
      await configAlert(q, host, `FIM registry: ${serious.length} open critical/high drift closed on ${host} because their coverage was removed`, 'high',
        { host, driftIds: serious.map((r) => r.id), slots: [...new Set(serious.map((r) => r.slot))], by: actorName(opts.actor), byUserId: opts.actor.userId, requestId: opts.actor.requestId });
    }
  }
  await auditTx(q, opts.actor, 'FIM_REG_PUBLISH', { host, rev, revChanged, newSlots: plan.needsInit, retired: plan.retired, revived: plan.revived, closedDrift: closed.map((r) => r.id), carriedDrift: carried, auto: opts.auto ?? null, note: opts.note });
  const ni = await needsInitSlots(q, policyId, host);
  const status = failSafe ? 'invalid' : ni.length ? 'needs_init' : 'in_sync';
  await upsertEffective(q, host, {
    policyId, ownerGroupId: node.ownerGroupId, resolved: resolvedJson(res, plan.entrySlot, ni), resolvedHash: failSafe ? 'invalid' : res.hash, status,
    error: failSafe ? `fail-safe catalog-only coverage published${failSafe.deadWaivers.length ? ` (waivers ${failSafe.deadWaivers.join(', ')} no longer valid)` : ''}; resolution error: ${failSafe.error}`.slice(0, 4000) : null,
    published: { hash: res.hash, by: actorName(opts.actor), waivers: res.usedWaivers }, inputsKey: inputsKeyFor(node, data, t),
  });
  // A waiver-backed rule now in effect reduces protected coverage: alert (§4.3).
  if (res.usedWaivers.length) {
    await configAlert(q, host, `FIM registry: protected coverage reduced on ${host} (waivers ${res.usedWaivers.join(', ')})`, 'high',
      { host, waivers: res.usedWaivers, by: actorName(opts.actor), byUserId: opts.actor.userId, requestId: opts.actor.requestId }, true);
  }
  if (failSafe) await q.query('UPDATE fim_reg_effective SET auto_attempt_hash = $2 WHERE host_identifier = $1', [host, 'failsafe']);
  if (failSafe && failSafe.deadWaivers.length) {
    await configAlert(q, host, `FIM registry: ${host} had coverage reduced by waiver(s) ${failSafe.deadWaivers.join(', ')} that are no longer valid while its coverage is invalid - fail-safe catalog-only coverage published`, 'critical',
      { host, deadWaivers: failSafe.deadWaivers, error: failSafe.error.slice(0, 500), by: actorName(opts.actor), byUserId: opts.actor.userId, requestId: opts.actor.requestId });
  }
  return { host, status, policyId, rev, revChanged, needsInit: ni, newSlots: plan.needsInit, retired: plan.retired, revived: plan.revived,
    error: failSafe ? `fail-safe coverage published: ${failSafe.error}`.slice(0, 4000) : null, blocked: res.blocked.length, usedWaivers: res.usedWaivers };
}

export async function publishNode(db: FimDb, host: string, opts: { actor: RegActor; expectedHash?: string | null; note: string | null; auto?: string | null; pre?: PreResolved }): Promise<PublishNodeResult> {
  return db.transaction((q) => publishNodeTx(q, host, opts));
}

/** Hosts a publish request covers (scope-checked; ≤ publishBatchMax). */
export async function publishTargets(q: FimQ, body: { hosts?: string[]; group?: string; profile?: number }, actor: RegActor): Promise<string[]> {
  const set = new Set<string>();
  if (body.hosts) for (const h of body.hosts) set.add(h);
  if (body.group) {
    if (!canWriteScope(actor, 'group', body.group)) throw new FimForbiddenError('You do not have Group Admin access to this group');
    for (const r of rowsOf(await q.query(`SELECT host_identifier FROM nodes WHERE owner_group_id = $1 AND lower(COALESCE(os_platform,'')) = 'windows'`, [body.group]))) set.add(r.host_identifier);
  }
  if (body.profile !== undefined) {
    if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can publish every node of a profile');
    for (const h of await profileTargets(q, body.profile)) set.add(h);
  }
  const hosts = [...set].sort();
  for (const h of hosts) if (!canWriteScope(actor, 'node', h)) throw new FimForbiddenError(`You do not have access to node ${h}`);
  return hosts;
}

async function allWindowsNodes(q: FimQ): Promise<WinNode[]> {
  return rowsOf(await q.query(`SELECT host_identifier, hostname, owner_group_id FROM nodes WHERE lower(COALESCE(os_platform,'')) = 'windows' ORDER BY host_identifier`))
    .map((r) => ({ host: r.host_identifier, hostname: r.hostname ?? null, ownerGroupId: r.owner_group_id ?? null }));
}

// ---------------------------------------------------------------------------------------------
// Compaction (§3.5): renumber slots, needs a full re-init; monitoring of the node pauses
// ---------------------------------------------------------------------------------------------

export async function compactNode(db: FimDb, host: string, actor: RegActor, note: string): Promise<PublishNodeResult> {
  assertWrite(actor, 'node', host);
  return db.transaction(async (q) => {
    await q.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [ADVISORY_PUBLISH, host]);
    await assertEnabled(q);
    const node = await getWindowsNode(q, host);
    const pol = await getManagedPolicy(q, host, true);
    if (!pol) throw new FimBadRequestError('This node has no published registry coverage to compact');
    const data = await loadLayerData(q, { host, group: node.ownerGroupId });
    const t = now();
    const res = resolveFor(node, data, { now: t });
    if (!res.ok) throw new FimBadRequestError(`Coverage is invalid: ${res.errors.join('; ')}`);
    const plan = compactSlots(res.entries, t);
    await q.query('DELETE FROM fim_reg_slots WHERE host_identifier = $1', [host]);
    await writeSlots(q, host, plan.changed);
    await q.query(`UPDATE fim_policies SET paths = $2::jsonb, rev = rev + 1, scan_interval_secs = $3, mode = $4, enabled = true, updated_at = now() WHERE id = $1`,
      [pol.id, JSON.stringify(plan.paths), res.scanIntervalSecs, res.mode]);
    // Old baseline rows are keyed by the old slot numbers: remove them and stop comparing until
    // the node is initialised again (scans of a non-locked host are ignored by the worker).
    await q.query('DELETE FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2', [pol.id, host]);
    await q.query('DELETE FROM fim_host_entry WHERE policy_id = $1 AND host_identifier = $2', [pol.id, host]);
    await q.query(`UPDATE fim_host_state SET state = 'learning', scan_count = 0 WHERE policy_id = $1 AND host_identifier = $2`, [pol.id, host]);
    await publishPolicyTx(q, pol.id);
    const ni = await needsInitSlots(q, pol.id, host);
    await upsertEffective(q, host, { policyId: pol.id, ownerGroupId: node.ownerGroupId, resolved: resolvedJson(res, plan.entrySlot, ni), resolvedHash: res.hash, status: 'needs_init', error: null, published: { hash: res.hash, by: actorName(actor), waivers: res.usedWaivers }, inputsKey: inputsKeyFor(node, data, t) });
    await configAlert(q, host, `FIM registry coverage compacted on ${host}: baseline removed, Initialize required`, 'medium', { host, by: actorName(actor), byUserId: actor.userId, note, requestId: actor.requestId });
    await auditTx(q, actor, 'FIM_REG_COMPACT', { host, note });
    const rev = num(rowsOf(await q.query('SELECT rev FROM fim_policies WHERE id = $1', [pol.id]))[0]?.rev);
    return { host, status: 'needs_init', policyId: pol.id, rev, revChanged: true, needsInit: ni, newSlots: plan.needsInit, retired: [], revived: [], error: null, blocked: res.blocked.length, usedWaivers: res.usedWaivers };
  });
}

// ---------------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------------

export interface RuleInput { layer: RegLayer; scopeValue: string; op: RegOp; target: string; spec: Record<string, any>; reason: string; waiverId: number | null }

const LAYERS: RegLayer[] = ['profile', 'group', 'node'];
const WAIVER_ACTIONS: Record<RegOp, RegWaiverAction[]> = { disable: ['disable', 'opt_out'], filter: ['narrow'], exclude: ['narrow'], severity: ['lower_severity'], add: ['narrow'] };

/** Free text (reasons, notes, labels): newlines/tabs allowed, no other control/format/bidi/invisible characters. */
function cleanText(v: unknown, what: string, max: number, required = false): string {
  if (v === undefined || v === null) { if (required) throw new FimValidationError(`${what} is required`); return ''; }
  if (typeof v !== 'string' || v.length > max) throw new FimValidationError(`${what} must be a string of at most ${max} characters`);
  if (!isCleanText(v.replace(/[\n\t]/g, ''))) throw new FimValidationError(`${what} must not contain control, format, bidi, invisible or unpaired surrogate characters`);
  if (required && !v.trim()) throw new FimValidationError(`${what} is required`);
  return v.trim();
}

function validNames(list: unknown, max: number, what: string, allowEmpty = true): string[] {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list) || list.length > max) throw new FimValidationError(`${what} must be an array of at most ${max} value names`);
  for (const n of list) { const e = validateValueName(n); if (e) throw new FimValidationError(`${what}: ${e}`); }
  const out = [...new Map((list as string[]).map((n) => [asciiLower(n), n])).values()];
  if (!allowEmpty && out.length === 0) throw new FimValidationError(`${what} must not be empty`);
  return out;
}

/** Validates a rule body (server side; the client mirrors it for UX only). */
export function validateRuleInput(body: any, actor: RegActor): RuleInput {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new FimValidationError('request body must be an object');
  const layer = body.layer;
  if (!LAYERS.includes(layer)) throw new FimValidationError('layer must be profile, group or node');
  const scopeValue = cleanText(body.scopeValue, 'scopeValue', layer === 'node' ? 40 : 255, true);
  if (layer === 'profile' && !/^[0-9]{1,15}$/.test(scopeValue)) throw new FimValidationError('profile scopeValue must be a profile id');
  const op = body.op;
  if (!REG_OPS.includes(op)) throw new FimValidationError(`op must be one of ${REG_OPS.join(', ')}`);
  let target = body.target;
  if (typeof target !== 'string' || target.length < 1 || target.length > 200) throw new FimValidationError('target is required');
  const specIn = body.spec === undefined || body.spec === null ? {} : body.spec;
  if (typeof specIn !== 'object' || Array.isArray(specIn)) throw new FimValidationError('spec must be an object');
  let spec: Record<string, any> = {};
  if (target === '*') {
    if (op !== 'exclude') throw new FimValidationError("target '*' is only valid for exclude");
  } else if (op === 'add' && (target === 'custom' || target.startsWith('custom:'))) {
    const v2 = normalizeRegistryEntryV2({ ...specIn, entryKey: undefined }, { allowRecursive: actor.superAdmin });
    target = customEntryKey(v2.path);
    const severity = specIn.severity ?? 'high';
    if (!SEVERITIES.includes(severity)) throw new FimValidationError('severity must be low, medium, high or critical');
    spec = {
      path: v2.path, values: v2.values, ignoreValues: v2.ignoreValues, excludeKeys: v2.excludeKeys, redactValues: v2.redactValues,
      includeSubkeys: v2.includeSubkeys, anchor: v2.anchor, hiveScoped: v2.hiveScoped, realtimeRequired: v2.realtimeRequired,
      severity, category: cleanText(specIn.category, 'category', 64) || 'custom', label: cleanText(specIn.label, 'label', 120) || 'Custom registry key',
    };
    if (/[\n\t]/.test(spec.label + spec.category)) throw new FimValidationError('label/category must be one line');
    if (specIn.measureOverride !== undefined) {
      if (typeof specIn.measureOverride !== 'boolean') throw new FimValidationError('measureOverride must be a boolean');
      if (specIn.measureOverride) {
        if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can add a custom key without measuring it');
        spec.measureOverride = true;
      }
    }
  } else {
    if (!isEntryKey(target)) throw new FimValidationError('target must be a catalog id (reg.*), custom:<16 hex> or *');
    if (target.startsWith('reg.') && !getRegCatalogEntry(target)) throw new FimValidationError(`unknown catalog id '${target}' (catalog version ${REG_CATALOG_VERSION})`);
    if (op === 'add' && target.startsWith('custom:')) throw new FimValidationError('custom keys are added with target "custom" and a spec');
  }
  if (op === 'filter') {
    spec = { values: validNames(specIn.values, REG_LIMITS.valuesMax, 'values') };
    // A narrowing that keeps NONE of a protected entry's monitored names effectively disables it:
    // that must be said explicitly (and is part of what the waiver approves).
    const cat = getRegCatalogEntry(target);
    // A narrowing that keeps NONE of a protected entry's monitored names - or ANY named filter on a
    // protected all-values entry (e.g. Run) - effectively disables what it watches: it must be said
    // explicitly, only a Super Administrator may ask for it, and it is alerted when applied.
    if (cat?.protected && spec.values.length && (cat.values.length === 0 || !cat.values.some((v) => spec.values.some((x: string) => asciiLower(x) === asciiLower(v))))) {
      if (specIn.dropsAllMonitored !== true) throw new FimValidationError(`this filter keeps none of ${cat.id}'s monitored values; set spec.dropsAllMonitored=true to request that explicitly`);
      if (!actor.superAdmin) throw new FimForbiddenError(`only a Super Administrator can request a filter that drops all monitored values of ${cat.id}`);
      spec.dropsAllMonitored = true;
    }
  }
  if (op === 'severity') {
    if (!SEVERITIES.includes(specIn.severity)) throw new FimValidationError('severity must be low, medium, high or critical');
    spec = { severity: specIn.severity };
  }
  if (op === 'exclude') {
    const ignoreValues = validNames(specIn.ignoreValues, REG_LIMITS.ignoreValuesMax, 'ignoreValues');
    if (target === '*' && ignoreValues.length) throw new FimValidationError("a '*' exclusion can only exclude keys (excludeKeys)");
    const raw = specIn.excludeKeys ?? [];
    if (!Array.isArray(raw) || raw.length > REG_LIMITS.excludeKeysMax) throw new FimValidationError(`excludeKeys must be an array of at most ${REG_LIMITS.excludeKeysMax} key patterns`);
    const excludeKeys: string[] = [];
    for (const x of raw) {
      const e = validateRegistryKeyV2(x, { exclusion: true });
      if (e) throw new FimValidationError(`excludeKeys: ${e}`);
      excludeKeys.push(canonicalRegistryKey(x));
    }
    const cat = target.startsWith('reg.') ? getRegCatalogEntry(target) : undefined;
    if (cat) for (const x of excludeKeys) {
      if (!exclusionInside(cat.path, x)) throw new FimValidationError(`excludeKeys: '${x}' matches no key of ${cat.id} (${cat.path})`);
      if (likeMatch(x, cat.path)) throw new FimValidationError(`excludeKeys: '${x}' would exclude ${cat.id}'s own key pattern`);
    }
    if (!ignoreValues.length && !excludeKeys.length) throw new FimValidationError('an exclusion needs ignoreValues or excludeKeys');
    spec = { ignoreValues, excludeKeys };
  }
  const reason = cleanText(body.reason, 'reason', 2000);
  let waiverId: number | null = null;
  if (body.waiverId !== undefined && body.waiverId !== null) {
    if (!Number.isSafeInteger(body.waiverId) || body.waiverId <= 0) throw new FimValidationError('waiverId must be a positive integer');
    waiverId = body.waiverId;
  }
  return { layer, scopeValue, op, target, spec, reason, waiverId };
}

/**
 * Protected catalog entries whose coverage this rule reduces (relative to the catalog definition).
 * A custom EXACT key inside a protected wildcard entry counts: the resolver would carve that key
 * out of the protected entry, so it needs a waiver bound to exactly that add.
 */
export function touchesProtected(r: Pick<RuleInput, 'op' | 'target' | 'spec'>): RegCatalogEntry[] {
  if (r.op === 'add') {
    if (!r.target.startsWith('custom:') || typeof r.spec?.path !== 'string') return [];
    let c: ReturnType<typeof customEntry>;
    try { c = customEntry(r.target, r.spec); } catch { return []; }
    if (!isExact(c.path)) return [];
    return REG_CATALOG.filter((p) => p.protected && !isExact(p.path) && patternMatchesKey(p.path, c.path) && namesIntersect(fromCatalog(p), c));
  }
  if (r.target === '*') {
    const keys: string[] = r.spec.excludeKeys ?? [];
    return REG_CATALOG.filter((c) => c.protected && keys.some((x) => exclusionInside(c.path, x)));
  }
  const c = getRegCatalogEntry(r.target);
  if (!c || !c.protected) return [];
  if (r.op === 'severity') return SEV_RANK[r.spec.severity] < SEV_RANK[c.severity] ? [c] : [];
  if (r.op === 'filter') {
    // ANY filter that changes a protected entry's value set changes its fingerprint (re-slot, new
    // baseline needed) - widening included: it needs the same waiver as narrowing.
    const next = new Set((r.spec.values as string[]).map(asciiLower));
    const cur = new Set(c.values.map(asciiLower));
    return next.size === cur.size && [...next].every((v) => cur.has(v)) ? [] : [c];
  }
  return [c]; // disable, exclude
}

async function assertScopeExists(q: FimQ, layer: RegLayer, scopeValue: string): Promise<void> {
  if (layer === 'profile') {
    if (!rowsOf(await q.query('SELECT 1 AS x FROM fim_reg_profiles WHERE id = $1', [Number(scopeValue)])).length) throw new FimNotFoundError('Profile not found');
  } else if (layer === 'node') {
    await getWindowsNode(q, scopeValue);
  } else {
    const hasTable = rowsOf(await q.query(`SELECT to_regclass('nodes_groups') IS NOT NULL AS t`))[0]?.t;
    const inTable = hasTable ? rowsOf(await q.query('SELECT 1 AS x FROM nodes_groups WHERE group_id = $1', [scopeValue])).length > 0 : false;
    const inNodes = rowsOf(await q.query('SELECT 1 AS x FROM nodes WHERE owner_group_id = $1 LIMIT 1', [scopeValue])).length > 0;
    if (!inTable && !inNodes) throw new FimNotFoundError('Group not found');
  }
}

/**
 * A rule that reduces protected coverage needs an APPROVED (never pending), unexpired, unused
 * waiver that was approved for exactly this rule (spec hash). Returns the waiver id to consume.
 */
async function assertWaiverFor(q: FimQ, r: RuleInput, entries: RegCatalogEntry[]): Promise<number | null> {
  if (!entries.length) return null;
  if (r.target === '*') throw new FimValidationError(`this '*' exclusion intersects protected entries (${entries.map((c) => c.id).join(', ')}); exclude per entry with an approved waiver instead`);
  if (entries.length > 1) throw new FimValidationError(`protected coverage: ${entries[0].id} and ${entries.length - 1} other protected entr(ies) would be narrowed; make the change specific to one protected entry`);
  const id = entries[0].id;
  if (r.reason.length < 10) throw new FimValidationError(`protected coverage: ${id} needs a reason of at least 10 characters`);
  if (!r.waiverId) throw new FimValidationError(`protected coverage: ${id} would be narrowed by this change; request a waiver for exactly this rule (two people, at most ${FIM_REG_CAPS.waiverMaxDays} days)`);
  const w = rowsOf(await q.query('SELECT * FROM fim_reg_waivers WHERE id = $1 FOR UPDATE', [r.waiverId]))[0];
  if (!w || w.entry_key !== id || w.scope_type !== r.layer || w.scope_value !== r.scopeValue || !WAIVER_ACTIONS[r.op].includes(w.action)) {
    throw new FimValidationError('the waiver does not cover this entry, scope and action');
  }
  if (w.status !== 'approved') throw new FimValidationError(`the waiver is ${w.status}; only an approved waiver can be used`);
  if (num(w.expires_at) <= now()) throw new FimValidationError('the waiver has expired');
  // Single use, layer 1 of 3 (also: the conditional UPDATE ... rule_id IS NULL in insertRuleTx and the
  // DB unique index uq_fim_reg_rules_waiver): removing any one layer alone is covered by the others.
  if (w.rule_id !== null && w.rule_id !== undefined) throw new FimConflictError('the waiver was already used (waivers are single-use)');
  if (!w.rule_hash || w.rule_hash !== regRuleHash(r)) throw new FimValidationError('the waiver was approved for a different change (rule spec differs)');
  return num(w.id);
}

async function assertMeasured(q: FimQ, r: RuleInput): Promise<void> {
  if (r.op !== 'add' || !r.target.startsWith('custom:') || r.spec.measureOverride) return;
  const fp = entryFingerprint({ ...r.spec, entryKey: r.target } as never);
  // Conservative: the LARGEST measurement of this exact entry in the last 30 days (any node / OS build).
  const m = rowsOf(await q.query(
    `SELECT max(rows_count) AS rows_count, max(bytes_count) AS bytes_count, count(*) AS n FROM fim_reg_measure
     WHERE fingerprint = $1 AND status = 'done' AND completed_at >= $2 HAVING count(*) > 0`, [fp, now() - 30 * 86400]))[0];
  if (!m) throw new FimValidationError('measure this custom key on a Windows node first (Measure); a Super Administrator may override with a reason');
  if (num(m.rows_count) > FIM_REG_CAPS.entryRowsBlock || num(m.bytes_count) > FIM_REG_CAPS.entryBytesBlock) {
    throw new FimValidationError(`measured ${num(m.rows_count)} rows / ${Math.round(num(m.bytes_count) / 1024)} KiB exceeds the per-entry limit (${FIM_REG_CAPS.entryRowsBlock} rows / ${FIM_REG_CAPS.entryBytesBlock / 1024} KiB); narrow the key`);
  }
}

export function mapRule(r: any, actor?: RegActor) {
  return {
    id: num(r.id), layer: r.layer as RegLayer, scopeValue: r.scope_value, op: r.op as RegOp, target: r.target, spec: r.spec ?? {}, reason: r.reason ?? '',
    waiverId: numOrNull(r.waiver_id), status: r.status, createdBy: r.created_by, createdAt: num(r.created_at), revokedBy: r.revoked_by ?? null, revokedAt: numOrNull(r.revoked_at),
    ...(actor ? { canManage: r.status === 'active' && canWriteScope(actor, r.layer, r.scope_value) } : {}),
  };
}

export async function listRules(q: FimQ, f: { layer?: RegLayer; scopeValue?: string }, actor: RegActor) {
  const rows = rowsOf(await q.query(
    `SELECT * FROM fim_reg_rules WHERE status = 'active' AND ($1::text IS NULL OR layer = $1) AND ($2::text IS NULL OR scope_value = $2) ORDER BY layer, scope_value, op, target, id LIMIT 2000`,
    [f.layer ?? null, f.scopeValue ?? null]));
  return rows.filter((r) => ruleVisible(actor, r.layer, r.scope_value)).map((r) => mapRule(r, actor));
}

function ruleVisible(a: RegActor, layer: RegLayer, scope: string): boolean {
  if (a.superAdmin || layer === 'profile') return true;
  return layer === 'group' ? canViewGroup(a, scope) : canViewHost(a, scope);
}

/** Insert one validated rule (all checks) inside a transaction. */
async function insertRuleTx(q: FimQ, r: RuleInput, actor: RegActor, opts: { skipMeasure?: boolean } = {}) {
  assertRegistryAvailable();
  await assertScopeExists(q, r.layer, r.scopeValue);
  const count = num(rowsOf(await q.query(`SELECT count(*) AS n FROM fim_reg_rules WHERE layer = $1 AND scope_value = $2 AND status = 'active'`, [r.layer, r.scopeValue]))[0]?.n);
  if (count >= FIM_REG_CAPS.rulesPerScope) throw new FimValidationError(`at most ${FIM_REG_CAPS.rulesPerScope} active rules per scope`);
  const waiverId = await assertWaiverFor(q, r, touchesProtected(r));
  if (!opts.skipMeasure) await assertMeasured(q, r);
  let row: any;
  try {
    row = rowsOf(await q.query(
      `INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, waiver_id, created_by, created_at)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9) RETURNING *`,
      [r.layer, r.scopeValue, r.op, r.target, JSON.stringify(r.spec), r.reason, waiverId, actorName(actor), now()]))[0];
  } catch (err) {
    if (isUniqueViolation(err)) throw new FimConflictError('An active rule with this operation and target already exists in this scope (or the waiver was already used); revoke it first');
    throw err;
  }
  if (waiverId !== null) {
    // Single use, layer 2 of 3 (see assertWaiverFor and uq_fim_reg_rules_waiver).
    const u = rowsOf(await q.query('UPDATE fim_reg_waivers SET rule_id = $2 WHERE id = $1 AND rule_id IS NULL RETURNING id', [waiverId, num(row.id)]));
    if (!u.length) throw new FimConflictError('the waiver was already used (waivers are single-use)');
  }
  return row;
}

/**
 * A new rule must not make the coverage of its scope unresolvable (e.g. an overlapping custom
 * wildcard): checked by resolving the scope with the rule included (node: that node; group: the
 * group's coverage; profile: a node on that profile). Refused with the resolver's errors.
 */
/** Time budget for validating a group/profile rule against every affected node (yielding). */
export const FIM_REG_RULE_VALIDATE_BUDGET_MS = 30_000;
/**
 * A new rule must not make the coverage of ANY affected node unresolvable, and a broader-scope
 * (group / profile) rule must not collide with a node's own rules (the node rule would win and
 * the new rule would silently not apply there). Checked against every affected node's FULL layer
 * stack (node: that node; group: every member; profile: every node on it, time-boxed - beyond the
 * budget the runtime precedence still protects node coverage). Refused naming the first conflict.
 */
async function assertRuleResolves(q: FimQ, r: RuleInput, waiverId: number | null): Promise<void> {
  const data = await loadLayerData(q);
  const nextId = data.rules.reduce((m, x) => Math.max(m, x.id), 0) + 1;
  const cand = { id: nextId, layer: r.layer, scopeValue: r.scopeValue, op: r.op, target: r.target, spec: r.spec, waiverId, reason: r.reason, createdBy: '', createdAt: now() } as never;
  const withRule: LayerData = { ...data, rules: [...data.rules, cand] };
  let nodes: WinNode[];
  if (r.layer === 'node') nodes = [await getWindowsNode(q, r.scopeValue)];
  else if (r.layer === 'group') nodes = (await allWindowsNodes(q)).filter((n) => n.ownerGroupId === r.scopeValue);
  else { const hs = new Set(await profileTargets(q, Number(r.scopeValue), data)); nodes = (await allWindowsNodes(q)).filter((n) => hs.has(n.host)); }
  // With no member node yet, still check the scope's own coverage.
  if (!nodes.length && r.layer === 'group') nodes = [{ host: '\u0000group', hostname: null, ownerGroupId: r.scopeValue }];
  if (!nodes.length && r.layer === 'profile') {
    const n0: WinNode = { host: '\u0000profile', hostname: null, ownerGroupId: null };
    withRule.assignments = new Map(withRule.assignments);
    withRule.assignments.set(`node:${n0.host}`, { scopeType: 'node', scopeValue: n0.host, profileId: Number(r.scopeValue), tier: null, version: 0, updatedBy: null, updatedAt: 0 } as never);
    nodes = [n0];
  }
  const t = now();
  const deadline = Date.now() + FIM_REG_RULE_VALIDATE_BUDGET_MS;
  let last = Date.now();
  for (const n of nodes) {
    if (Date.now() > deadline) break;
    if (Date.now() - last > 20) { await new Promise<void>((res) => setImmediate(res)); last = Date.now(); }
    const res = resolveFor(n, withRule, { now: t, skipNodeLayer: n.host === '\u0000group' });
    const where = n.host.startsWith('\u0000') ? `${r.layer} ${r.scopeValue}` : `node ${n.host}`;
    if (!res.ok) throw new FimValidationError(`this rule would make the registry coverage of ${where} invalid: ${res.errors.join('; ').slice(0, 1000)}`);
    if (r.layer !== 'node') {
      const dropped = res.blocked.find((b) => b.target === r.target && b.reason.startsWith('overlap:'));
      if (dropped) throw new FimValidationError(`this ${r.layer} rule conflicts with the coverage of ${where}: ${dropped.reason}`);
    }
  }
}

export async function createRule(db: FimDb, body: any, actor: RegActor) {
  assertRegistryAvailable();
  const r = validateRuleInput(body, actor);
  assertWrite(actor, r.layer, r.scopeValue);
  return db.transaction(async (q) => {
    // Serialise rule creation: two concurrent overlapping rules must not both pass the resolve check.
    await q.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_RULES]);
    await assertRuleResolves(q, r, r.waiverId);
    const row = await insertRuleTx(q, r, actor);
    const head = await recordScopeChange(q, r.layer, r.scopeValue, actor, r.reason || null);
    await auditTx(q, actor, 'FIM_REG_RULE_ADD', { rule: mapRule(row) });
    return { rule: mapRule(row, actor), rowHash: head.rowHash, historyHead: head };
  });
}

export async function revokeRule(db: FimDb, id: number, actor: RegActor, reason: string) {
  return db.transaction(async (q) => {
    const row = rowsOf(await q.query('SELECT * FROM fim_reg_rules WHERE id = $1 FOR UPDATE', [id]))[0];
    if (!row || !ruleVisible(actor, row.layer, row.scope_value)) throw new FimNotFoundError('Rule not found');
    if (row.status !== 'active') throw new FimConflictError('The rule is already revoked');
    assertWrite(actor, row.layer, row.scope_value);
    await q.query(`UPDATE fim_reg_rules SET status = 'revoked', revoked_by = $2, revoked_at = $3 WHERE id = $1`, [id, actorName(actor), now()]);
    const head = await recordScopeChange(q, row.layer, row.scope_value, actor, reason || null);
    await auditTx(q, actor, 'FIM_REG_RULE_REVOKE', { ruleId: id, layer: row.layer, scopeValue: row.scope_value, op: row.op, target: row.target, reason });
    return { rule: mapRule({ ...row, status: 'revoked', revoked_by: actorName(actor), byUserId: actor.userId, revoked_at: now() }), rowHash: head.rowHash, historyHead: head };
  });
}

// ---------------------------------------------------------------------------------------------
// Profiles (Super Admin)
// ---------------------------------------------------------------------------------------------

export interface ProfileInput { name: string; description: string; tier: RegTier; isDefault: boolean; scanIntervalSecs: number; mode: 'learn' | 'enforce'; reason: string; version?: number }

export function validateProfileInput(b: any): ProfileInput {
  if (!b || typeof b !== 'object') throw new FimValidationError('request body must be an object');
  const name = cleanText(b.name, 'name', 120, true);
  if (!isCleanText(name)) throw new FimValidationError('name must not contain control characters');
  if (!REG_TIERS.includes(b.tier)) throw new FimValidationError('tier must be essential, recommended or comprehensive');
  if (typeof b.isDefault !== 'boolean') throw new FimValidationError('isDefault must be a boolean');
  if (!Number.isInteger(b.scanIntervalSecs) || b.scanIntervalSecs < 300 || b.scanIntervalSecs > 86400) throw new FimValidationError('scanIntervalSecs must be an integer between 300 and 86400');
  if (b.mode !== 'learn' && b.mode !== 'enforce') throw new FimValidationError("mode must be 'learn' or 'enforce'");
  if (b.version !== undefined && (!Number.isSafeInteger(b.version) || b.version < 0)) throw new FimValidationError('version must be a non-negative integer');
  return { name, description: cleanText(b.description, 'description', 2000), tier: b.tier, isDefault: b.isDefault, scanIntervalSecs: b.scanIntervalSecs, mode: b.mode, reason: cleanText(b.reason, 'reason', 2000), version: b.version };
}

/** The profile a node resolves to (same precedence as the resolver: node, group, default) - no resolution. */
export function effectiveProfileId(n: WinNode, d: LayerData): number | null {
  const ids = new Set(d.profiles.map((p) => p.id));
  const na = d.assignments.get(`node:${n.host}`);
  if (na?.profileId != null && ids.has(na.profileId)) return na.profileId;
  const ga = n.ownerGroupId ? d.assignments.get(`group:${n.ownerGroupId}`) : undefined;
  if (ga?.profileId != null && ids.has(ga.profileId)) return ga.profileId;
  return d.profiles.find((p) => p.isDefault)?.id ?? null;
}
/** Windows nodes whose effective profile is `profileId` (cheap: assignments only; yields regularly). */
export async function profileTargets(q: FimQ, profileId: number, data?: LayerData): Promise<string[]> {
  const d = data ?? await loadLayerData(q);
  const out: string[] = [];
  let i = 0;
  for (const n of await allWindowsNodes(q)) {
    if (++i % 2000 === 0) await new Promise<void>((r) => setImmediate(r));
    if (effectiveProfileId(n, d) === profileId) out.push(n.host);
  }
  return out;
}
async function profileAffected(q: FimQ, data?: LayerData): Promise<Map<number, number>> {
  const d = data ?? await loadLayerData(q);
  const out = new Map<number, number>();
  for (const n of await allWindowsNodes(q)) {
    const pid = effectiveProfileId(n, d);
    if (pid != null) out.set(pid, (out.get(pid) ?? 0) + 1);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Background jobs: a profile-wide publish can touch thousands of nodes. It runs in small chunks
// (one transaction per node, yielding to the event loop between chunks), reports progress, is
// resumable after a restart (cursor + heartbeat) and only one runs at a time (unique index).
// ---------------------------------------------------------------------------------------------

export const FIM_REG_JOB_CHUNK = 20;
export const FIM_REG_JOB_STALE_SECS = 120;
const mapJob = (j: any) => ({
  id: num(j.id), kind: j.kind, params: j.params ?? {}, status: j.status, total: num(j.total), done: num(j.done), failed: num(j.failed),
  results: j.results ?? [], error: j.error ?? null, createdBy: j.created_by ?? null, createdAt: num(j.created_at),
  heartbeatAt: numOrNull(j.heartbeat_at), finishedAt: numOrNull(j.finished_at),
});
/** Maximum age of a job before it is failed and alerted (a stuck job never blocks the next one forever). */
export const FIM_REG_JOB_MAX_AGE_SECS = 6 * 3600;
export async function startProfilePublishJob(db: FimDb, profileId: number, actor: RegActor, note: string | null, expectedDigest: string) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can publish every node of a profile');
  if (typeof expectedDigest !== 'string' || !expectedDigest) throw new FimValidationError('expectedProfileDigest (digest of the reviewed profile) is required for a profile publish');
  return db.transaction(async (q) => {
    await assertEnabled(q);
    if (!rowsOf(await q.query('SELECT 1 AS x FROM fim_reg_profiles WHERE id = $1', [profileId])).length) throw new FimNotFoundError('Profile not found');
    if (await currentProfileDigest(q, profileId) !== expectedDigest) throw new FimConflictError('This profile changed since it was reviewed; reload and review it again');
    let row: any;
    try {
      row = rowsOf(await q.query(
        `INSERT INTO fim_reg_jobs (kind, params, created_by, created_by_user_id, created_at) VALUES ('publish_profile', $1::jsonb, $2, $3, $4) RETURNING *`,
        // The reviewed digest is stored: every chunk (and a resume) re-checks it.
        [JSON.stringify({ profileId, note, requestId: actor.requestId, expectedDigest }), actorName(actor), actor.userId, now()]))[0];
    } catch (err) {
      if (isUniqueViolation(err)) throw new FimConflictError('A profile publish is already running; wait for it to finish');
      throw err;
    }
    await auditTx(q, actor, 'FIM_REG_JOB', { op: 'start', jobId: num(row.id), kind: 'publish_profile', profileId, note, expectedDigest });
    return mapJob(row);
  });
}
export async function getJob(q: FimQ, id: number, actor: RegActor) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can view registry jobs');
  const j = rowsOf(await q.query('SELECT * FROM fim_reg_jobs WHERE id = $1', [id]))[0];
  if (!j) throw new FimNotFoundError('Job not found');
  return mapJob(j);
}
export async function cancelJob(db: FimDb, id: number, actor: RegActor, note: string | null) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can cancel registry jobs');
  return db.transaction(async (q) => {
    const row = rowsOf(await q.query(
      `UPDATE fim_reg_jobs SET status = 'cancelled', finished_at = $2, error = COALESCE(error, $3), lease_token = NULL
       WHERE id = $1 AND status IN ('queued','running') RETURNING *`, [id, now(), `cancelled by ${actorName(actor)}${note ? `: ${note}` : ''}`.slice(0, 1000)]))[0];
    if (!row) throw new FimConflictError('The job is not running');
    await auditTx(q, actor, 'FIM_REG_JOB', { op: 'cancel', jobId: id, note });
    return mapJob(row);
  });
}
/**
 * Runs (or resumes) a job until done. Ownership is a LEASE token: only the runner holding it may
 * write progress; a runner that loses it (stale heartbeat taken over, cancel) stops at once.
 */
export async function runRegistryJob(db: FimDb, id: number, log?: (msg: string, extra?: Record<string, unknown>) => void): Promise<void> {
  const lease = randomUUID();
  const claimed = rowsOf(await db.query(
    `UPDATE fim_reg_jobs SET status = 'running', heartbeat_at = $2, lease_token = $4
     WHERE id = $1 AND (status = 'queued' OR (status = 'running' AND COALESCE(heartbeat_at, 0) < $3)) RETURNING *`,
    [id, now(), now() - FIM_REG_JOB_STALE_SECS, lease]))[0];
  if (!claimed) return;
  const job = mapJob(claimed);
  const actor: RegActor = { ...systemActor(String(job.params.requestId ?? randomUUID())), email: job.createdBy ?? 'system', userId: numOrNull(claimed.created_by_user_id) };
  const owned = `id = $1 AND lease_token = '${lease}'`; // lease is a server-generated UUID (no user input)
  try {
    const profileId = Number(job.params.profileId);
    // Order AND resume-compare with the SAME comparator (code-unit order, not the DB collation):
    // a cursor compared in another order than the list was built in silently skips nodes.
    const hosts = (await profileTargets(db, profileId)).sort(cmpStr).filter((h) => cmpStr(h, String(claimed.cursor ?? '')) > 0);
    const total = job.done + job.failed + hosts.length;
    if (!rowsOf(await db.query(`UPDATE fim_reg_jobs SET total = $2 WHERE ${owned} RETURNING id`, [id, total])).length) return;
    // Per-node guard (one cheap query before EVERY node): lease still ours, not cancelled, and the
    // profile unchanged since the digest check (epoch over the profile row version and its rules).
    const epochSql = `SELECT j.status, j.lease_token,
        md5(COALESCE((SELECT p.version::text || '|' || p.tier || '|' || p.mode || '|' || p.scan_interval_secs FROM fim_reg_profiles p WHERE p.id = $2), 'gone') || '|' ||
            COALESCE((SELECT string_agg(r.id::text || ':' || r.status, ',' ORDER BY r.id) FROM fim_reg_rules r WHERE r.layer = 'profile' AND r.scope_value = $2::text), '')) AS epoch
      FROM fim_reg_jobs j WHERE j.id = $1`;
    const guard = async () => rowsOf(await db.query(epochSql, [id, profileId]))[0];
    let epoch0: string | null = null;
    for (let i = 0; i < hosts.length; i += FIM_REG_JOB_CHUNK) {
      // The profile must still be what was reviewed: otherwise stop before publishing more nodes.
      if (job.params.expectedDigest && await currentProfileDigest(db, profileId) !== job.params.expectedDigest) {
        await db.query(`UPDATE fim_reg_jobs SET status = 'aborted', error = 'profile changed during publish', finished_at = $2, lease_token = NULL WHERE ${owned}`, [id, now()]);
        await configAlert(db, null, `FIM registry profile publish job #${id} aborted: the profile changed during the publish`, 'high',
          { jobId: id, profileId, done: job.done, by: job.createdBy });
        log?.('FIM_REG_JOB_ABORTED', { jobId: id });
        return;
      }
      if (now() - job.createdAt > FIM_REG_JOB_MAX_AGE_SECS) throw new Error(`job exceeded its maximum age of ${FIM_REG_JOB_MAX_AGE_SECS} s`);
      const chunk = hosts.slice(i, i + FIM_REG_JOB_CHUNK);
      let done = 0, failed = 0;
      const results: unknown[] = [];
      if (epoch0 === null) epoch0 = String((await guard())?.epoch ?? '');
      let stop: 'lease' | 'changed' | null = null;
      for (const h of chunk) {
        const g = await guard();
        if (!g || g.status !== 'running' || g.lease_token !== lease) { stop = 'lease'; break; }
        if (String(g.epoch) !== epoch0) { stop = 'changed'; break; }
        try {
          const r = await publishNode(db, h, { actor, note: `profile publish job #${id}${job.params.note ? `: ${job.params.note}` : ''}` });
          if (r.status === 'invalid') { failed++; results.push({ host: h, status: r.status, error: r.error }); } else { done++; results.push({ host: h, status: 'ok' }); }
        } catch (err) {
          failed++; results.push({ host: h, error: (err as Error).message.slice(0, 300) });
        }
      }
      const st = rowsOf(await db.query(
        `UPDATE fim_reg_jobs SET done = done + $2, failed = failed + $3, cursor = $4, heartbeat_at = $5,
           results = CASE WHEN jsonb_array_length(results) < 500 THEN results || $6::jsonb ELSE results END
         WHERE ${owned} AND status = 'running' RETURNING status`, [id, done, failed, chunk[chunk.length - 1], now(), JSON.stringify(results)]))[0];
      // Lease, layer 2 (layer 1 = the per-node guard above): progress is only written while the lease is ours.
      if (!st) { log?.('FIM registry job lease lost (cancelled or taken over)', { jobId: id }); return; }
      job.done += done;
      if (stop === 'lease') { log?.('FIM registry job lease lost (cancelled or taken over)', { jobId: id }); return; }
      if (stop === 'changed') {
        await db.query(`UPDATE fim_reg_jobs SET status = 'aborted', error = 'profile changed during publish', finished_at = $2, lease_token = NULL WHERE ${owned}`, [id, now()]);
        await configAlert(db, null, `FIM registry profile publish job #${id} aborted: the profile changed during the publish`, 'high', { jobId: id, profileId, done: job.done, by: job.createdBy });
        return;
      }
      await new Promise<void>((r) => setImmediate(r));
    }
    await db.query(`UPDATE fim_reg_jobs SET status = 'done', finished_at = $2, heartbeat_at = $2, lease_token = NULL WHERE ${owned}`, [id, now()]);
    log?.('FIM_REG_JOB_DONE', { jobId: id, total });
  } catch (err) {
    const u = rowsOf(await db.query(`UPDATE fim_reg_jobs SET status = 'failed', error = $2, finished_at = $3, lease_token = NULL WHERE ${owned} RETURNING id`, [id, (err as Error).message.slice(0, 1000), now()]));
    if (u.length) await configAlert(db, null, `FIM registry job #${id} failed: ${(err as Error).message.slice(0, 200)}`, 'high', { jobId: id });
    log?.('FIM registry job failed', { err, jobId: id });
  }
}
/** Picks up queued jobs and running jobs whose runner died (stale heartbeat). */
export async function resumeRegistryJobs(db: FimDb, log?: (msg: string, extra?: Record<string, unknown>) => void): Promise<number> {
  for (const r of rowsOf(await db.query(
    `UPDATE fim_reg_jobs SET status = 'failed', error = 'job exceeded its maximum age', finished_at = $1, lease_token = NULL
     WHERE status IN ('queued','running') AND created_at < $2 RETURNING id`, [now(), now() - FIM_REG_JOB_MAX_AGE_SECS]))) {
    await configAlert(db, null, `FIM registry job #${r.id} was stuck and has been failed (maximum age exceeded)`, 'high', { jobId: num(r.id) });
  }
  const rows = rowsOf(await db.query(
    `SELECT id FROM fim_reg_jobs WHERE status = 'queued' OR (status = 'running' AND COALESCE(heartbeat_at, 0) < $1) ORDER BY id`, [now() - FIM_REG_JOB_STALE_SECS]));
  for (const r of rows) void runRegistryJob(db, num(r.id), log);
  return rows.length;
}

/** Digest of a profile's settings + active rules: a profile publish states the digest it reviewed. */
function profileDigestOf(data: LayerData, id: number): string | null {
  const p = data.profiles.find((x) => x.id === id);
  if (!p) return null;
  const rules = data.rules.filter((r) => r.layer === 'profile' && r.scopeValue === String(id)).map((r) => ({ id: r.id, op: r.op, target: r.target, spec: r.spec, waiverId: r.waiverId ?? null }))
    .sort((a, b) => a.id - b.id);
  return sha256Hex(canonicalJson({ tier: p.tier, isDefault: p.isDefault, scanIntervalSecs: p.scanIntervalSecs, mode: p.mode, version: p.version, rules }));
}
export async function currentProfileDigest(q: FimQ, id: number): Promise<string | null> {
  return profileDigestOf(await loadLayerData(q), id);
}
/** Hash of a group's resolved coverage (catalog + profile + group layers): what a group publish reviewed. */
export async function currentGroupHash(q: FimQ, gid: string): Promise<string> {
  const data = await loadLayerData(q, { group: gid });
  return resolveFor({ host: '\u0000group', hostname: null, ownerGroupId: gid }, data, { skipNodeLayer: true }).hash || 'invalid';
}

export async function listProfiles(q: FimQ, actor: RegActor) {
  const data = await loadLayerData(q);
  const affected = await profileAffected(q, data);
  return data.profiles.map((p) => ({
    ...p, affectedNodes: affected.get(p.id) ?? 0, digest: profileDigestOf(data, p.id),
    rules: data.rules.filter((r) => r.layer === 'profile' && r.scopeValue === String(p.id)).map((r) => ({
      id: r.id, layer: r.layer, scopeValue: r.scopeValue, op: r.op, target: r.target, spec: r.spec, reason: r.reason, waiverId: r.waiverId,
      status: 'active', createdBy: r.createdBy, createdAt: r.createdAt, revokedBy: null, revokedAt: null, canManage: actor.superAdmin,
    })),
  }));
}

export async function saveProfile(db: FimDb, id: number | null, input: ProfileInput, actor: RegActor) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can change profiles');
  return db.transaction(async (q) => {
    let before: any = null;
    if (id !== null) {
      before = rowsOf(await q.query('SELECT * FROM fim_reg_profiles WHERE id = $1 FOR UPDATE', [id]))[0];
      if (!before) throw new FimNotFoundError('Profile not found');
      if (input.version === undefined) throw new FimValidationError('version is required to update a profile');
      if (before.is_default && !input.isDefault) throw new FimValidationError('make another profile the default instead of unsetting the default');
    }
    if (input.isDefault) await q.query('UPDATE fim_reg_profiles SET is_default = false, version = version + 1, updated_at = now(), updated_by = $2 WHERE is_default AND id IS DISTINCT FROM $1', [id, actorName(actor)]);
    let row: any;
    try {
      if (id === null) {
        row = rowsOf(await q.query(
          `INSERT INTO fim_reg_profiles (name, description, tier, is_default, scan_interval_secs, mode, created_by, updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING *`,
          [input.name, input.description, input.tier, input.isDefault, input.scanIntervalSecs, input.mode, actorName(actor)]))[0];
      } else {
        row = rowsOf(await q.query(
          `UPDATE fim_reg_profiles SET name = $2, description = $3, tier = $4, is_default = $5, scan_interval_secs = $6, mode = $7,
             version = version + 1, updated_by = $8, updated_at = now() WHERE id = $1 AND version = $9 RETURNING *`,
          [id, input.name, input.description, input.tier, input.isDefault, input.scanIntervalSecs, input.mode, actorName(actor), input.version]))[0];
        if (!row) throw new FimConflictError('The profile was changed by someone else; reload it');
      }
    } catch (err) {
      if (isUniqueViolation(err)) throw new FimConflictError(`A profile named '${input.name}' already exists`);
      throw err;
    }
    const pid = num(row.id);
    const affected = (await profileAffected(q)).get(pid) ?? 0;
    if (before && REG_TIER_RANK[input.tier] < REG_TIER_RANK[before.tier as RegTier] && affected > FIM_REG_DOWNGRADE_ALERT_NODES) {
      await configAlert(q, null, `FIM registry profile '${input.name}' downgraded from ${before.tier} to ${input.tier} (${affected} nodes)`, 'high',
        { profileId: pid, from: before.tier, to: input.tier, affectedNodes: affected, by: actorName(actor), byUserId: actor.userId, requestId: actor.requestId });
    }
    const head = await recordScopeChange(q, 'profile', String(pid), actor, input.reason || null);
    await auditTx(q, actor, 'FIM_REG_PROFILE_CHANGE', { profileId: pid, before: before ? { tier: before.tier, mode: before.mode, isDefault: before.is_default } : null, after: input });
    return { profile: { id: pid, name: row.name, tier: row.tier, isDefault: !!row.is_default, version: num(row.version), affectedNodes: affected }, before: before ? { tier: before.tier, mode: before.mode, scanIntervalSecs: num(before.scan_interval_secs), isDefault: !!before.is_default } : null, rowHash: head.rowHash, historyHead: head };
  });
}

export async function deleteProfile(db: FimDb, id: number, actor: RegActor, reason: string) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can delete profiles');
  return db.transaction(async (q) => {
    const p = rowsOf(await q.query('SELECT * FROM fim_reg_profiles WHERE id = $1 FOR UPDATE', [id]))[0];
    if (!p) throw new FimNotFoundError('Profile not found');
    if (p.is_default) throw new FimConflictError('The default profile cannot be deleted');
    await q.query(`UPDATE fim_reg_rules SET status = 'revoked', revoked_by = $2, revoked_at = $3 WHERE layer = 'profile' AND scope_value = $1 AND status = 'active'`, [String(id), actorName(actor), now()]);
    try {
      await q.query('DELETE FROM fim_reg_profiles WHERE id = $1', [id]);
    } catch (err) {
      if (isFkViolation(err)) throw new FimConflictError('The profile is assigned to groups or nodes; change those assignments first');
      throw err;
    }
    const head = await appendHistory(q, 'profile', String(id), { deleted: true, profile: { name: p.name, tier: p.tier } }, actorName(actor), reason || null);
    await auditTx(q, actor, 'FIM_REG_PROFILE_CHANGE', { op: 'delete', profileId: id, name: p.name, reason });
    return { name: p.name as string, rowHash: head.rowHash, historyHead: head };
  });
}

// ---------------------------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------------------------

export async function listAssignments(q: FimQ, f: { scopeType?: string; scopeValue?: string }, actor: RegActor) {
  const rows = rowsOf(await q.query(
    `SELECT * FROM fim_reg_assignments WHERE ($1::text IS NULL OR scope_type = $1) AND ($2::text IS NULL OR scope_value = $2) ORDER BY scope_type, scope_value LIMIT 5000`,
    [f.scopeType ?? null, f.scopeValue ?? null]));
  return rows.filter((a) => ruleVisible(actor, a.scope_type, a.scope_value)).map(mapAssignment);
}

const mapAssignment = (a: any) => ({ scopeType: a.scope_type, scopeValue: a.scope_value, profileId: numOrNull(a.profile_id), tier: a.tier ?? null, version: num(a.version), updatedBy: a.updated_by ?? null, updatedAt: tsec(a.updated_at) });

export async function putAssignment(db: FimDb, scopeType: 'group' | 'node', scopeValue: string, body: any, actor: RegActor) {
  if (scopeType !== 'group' && scopeType !== 'node') throw new FimValidationError('scope type must be group or node');
  assertWrite(actor, scopeType, scopeValue);
  const profileId = body?.profileId === undefined || body?.profileId === null ? null : body.profileId;
  if (profileId !== null && (!Number.isSafeInteger(profileId) || profileId <= 0)) throw new FimValidationError('profileId must be a profile id or null');
  const tier = body?.tier === undefined || body?.tier === null ? null : body.tier;
  if (tier !== null && !REG_TIERS.includes(tier)) throw new FimValidationError('tier must be essential, recommended, comprehensive or null');
  const reason = cleanText(body?.reason, 'reason', 2000);
  return db.transaction(async (q) => {
    await assertScopeExists(q, scopeType, scopeValue);
    const before = rowsOf(await q.query('SELECT * FROM fim_reg_assignments WHERE scope_type = $1 AND scope_value = $2 FOR UPDATE', [scopeType, scopeValue]))[0] ?? null;
    // Optimistic concurrency is mandatory once an assignment exists.
    if (before && body?.version === undefined) throw new FimValidationError('version is required to change an existing assignment');
    if (before && num(before.version) !== body.version) throw new FimConflictError('The assignment was changed by someone else; reload it');
    if (profileId !== null && !rowsOf(await q.query('SELECT 1 AS x FROM fim_reg_profiles WHERE id = $1', [profileId])).length) throw new FimNotFoundError('Profile not found');
    // A profile carrying waiver-backed (protected-coverage reducing) rules would extend that waiver
    // to new nodes: only a Super Administrator may assign it.
    if (profileId !== null && !actor.superAdmin && rowsOf(await q.query(
      `SELECT 1 AS x FROM fim_reg_rules WHERE layer = 'profile' AND scope_value = $1 AND status = 'active' AND waiver_id IS NOT NULL LIMIT 1`, [String(profileId)])).length) {
      throw new FimForbiddenError('This profile reduces protected coverage under a waiver; only a Super Administrator can assign it');
    }
    let after: any = null;
    if (profileId === null && tier === null) {
      await q.query('DELETE FROM fim_reg_assignments WHERE scope_type = $1 AND scope_value = $2', [scopeType, scopeValue]);
    } else if (!before) {
      // Create: a concurrent create of the same scope must not silently overwrite (409 instead).
      const ins = rowsOf(await q.query(
        `INSERT INTO fim_reg_assignments (scope_type, scope_value, profile_id, tier, updated_by) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (scope_type, scope_value) DO NOTHING RETURNING *`,
        [scopeType, scopeValue, profileId, tier, actorName(actor)]));
      if (!ins.length) throw new FimConflictError('The assignment was created by someone else meanwhile; reload it');
      after = ins[0];
    } else {
      after = rowsOf(await q.query(
        `UPDATE fim_reg_assignments SET profile_id = $3, tier = $4, version = version + 1, updated_by = $5, updated_at = now()
         WHERE scope_type = $1 AND scope_value = $2 AND version = $6 RETURNING *`,
        [scopeType, scopeValue, profileId, tier, actorName(actor), body.version]))[0];
      if (!after) throw new FimConflictError('The assignment was changed by someone else; reload it');
    }
    const head = await recordScopeChange(q, scopeType, scopeValue, actor, reason || null);
    await auditTx(q, actor, 'FIM_REG_ASSIGN', { scopeType, scopeValue, before: before ? mapAssignment(before) : null, after: after ? mapAssignment(after) : null, reason });
    return { before: before ? mapAssignment(before) : null, after: after ? mapAssignment(after) : null, rowHash: head.rowHash, historyHead: head };
  });
}

// ---------------------------------------------------------------------------------------------
// Waivers (§4.3): requested by GA/SA in scope, approved by a DIFFERENT Super Admin, ≤ 30 days
// ---------------------------------------------------------------------------------------------

export function mapWaiver(w: any, actor?: RegActor) {
  const requester = String(w.requested_by ?? '');
  const requesterId = numOrNull(w.requested_by_user_id);
  const isRequester = !!actor && ((actor.userId !== null && requesterId !== null && actor.userId === requesterId) || (actor.email ?? '').toLowerCase() === requester.toLowerCase());
  return {
    id: num(w.id), entryKey: w.entry_key, scopeType: w.scope_type as RegLayer, scopeValue: w.scope_value, action: w.action as RegWaiverAction,
    reason: w.reason, requestedBy: requester, requestedAt: num(w.requested_at), approvedBy: w.approved_by ?? null, approvedAt: numOrNull(w.approved_at),
    decisionNote: w.decision_note ?? null, expiresAt: num(w.expires_at), status: w.status, revokedBy: w.revoked_by ?? null, revokedAt: numOrNull(w.revoked_at),
    rule: w.rule_op ? { op: w.rule_op, target: w.rule_target, spec: w.rule_spec ?? {} } : null,
    ruleId: numOrNull(w.rule_id),
    canDecide: !!actor && (actor.superAdmin || !!actor.isApprover) && actor.userId !== null && w.status === 'pending' && !isRequester,
    canRevoke: !!actor && ['pending', 'approved'].includes(w.status) && w.rule_id == null
      && (actor.superAdmin || (isRequester && canWriteScope(actor, w.scope_type, w.scope_value))),
  };
}

export async function listWaivers(q: FimQ, f: { status?: string; scopeType?: string; scopeValue?: string }, actor: RegActor) {
  const rows = rowsOf(await q.query(
    `SELECT * FROM fim_reg_waivers WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR scope_type = $2) AND ($3::text IS NULL OR scope_value = $3)
     ORDER BY id DESC LIMIT 1000`, [f.status ?? null, f.scopeType ?? null, f.scopeValue ?? null]));
  return rows.filter((w) => ruleVisible(actor, w.scope_type, w.scope_value)).map((w) => mapWaiver(w, actor));
}

/**
 * Request a waiver for ONE exact change (body.rule = {op, target, spec}); the stored rule and its
 * hash are what the approver approves and the only rule the waiver can ever back (once).
 */
export async function requestWaiver(db: FimDb, body: any, actor: RegActor) {
  const entryKey = body?.entryKey;
  const c = typeof entryKey === 'string' ? getRegCatalogEntry(entryKey) : undefined;
  if (!c || !c.protected) throw new FimValidationError('waivers are only needed (and only accepted) for protected catalog entries');
  const scopeType = body?.scopeType;
  if (!LAYERS.includes(scopeType)) throw new FimValidationError('scopeType must be profile, group or node');
  const scopeValue = cleanText(body?.scopeValue, 'scopeValue', 255, true);
  if (!['disable', 'narrow', 'lower_severity', 'opt_out'].includes(body?.action)) throw new FimValidationError('action must be disable, narrow, lower_severity or opt_out');
  const reason = cleanText(body?.reason, 'reason', 2000, true);
  if (reason.length < 10) throw new FimValidationError('reason must be at least 10 characters');
  const t = now();
  if (!Number.isSafeInteger(body?.expiresAt) || body.expiresAt <= t || body.expiresAt > t + FIM_REG_CAPS.waiverMaxDays * 86400) {
    throw new FimValidationError(`expiresAt must be in the future and at most ${FIM_REG_CAPS.waiverMaxDays} days from now`);
  }
  if (!body?.rule || typeof body.rule !== 'object') throw new FimValidationError('rule (the exact change this waiver allows) is required');
  const rule = validateRuleInput({ ...body.rule, layer: scopeType, scopeValue, reason, waiverId: null }, actor);
  if (!touchesProtected(rule).some((x) => x.id === entryKey)) throw new FimValidationError(`the rule does not reduce coverage of ${entryKey}; no waiver is needed`);
  if (!WAIVER_ACTIONS[rule.op].includes(body.action)) throw new FimValidationError(`action ${body.action} does not match a ${rule.op} rule`);
  assertWrite(actor, scopeType, scopeValue);
  return db.transaction(async (q) => {
    await assertScopeExists(q, scopeType, scopeValue);
    const row = rowsOf(await q.query(
      `INSERT INTO fim_reg_waivers (entry_key, scope_type, scope_value, action, reason, requested_by, requested_by_user_id, requested_at, expires_at,
         rule_op, rule_target, rule_spec, rule_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13) RETURNING *`,
      [entryKey, scopeType, scopeValue, body.action, reason, actorName(actor), actor.userId, t, body.expiresAt, rule.op, rule.target, JSON.stringify(rule.spec), regRuleHash(rule)]))[0];
    await auditTx(q, actor, 'FIM_REG_WAIVER_REQUEST', { waiverId: num(row.id), entryKey, scopeType, scopeValue, action: body.action, rule: { op: rule.op, target: rule.target, spec: rule.spec } });
    await configAlert(q, scopeType === 'node' ? scopeValue : null, `FIM registry waiver #${row.id} requested: ${body.action} ${entryKey} on ${scopeType} ${scopeValue}`, 'high',
      { waiverId: num(row.id), entryKey, scopeType, scopeValue, action: body.action, rule: { op: rule.op, target: rule.target, spec: rule.spec }, by: actorName(actor), byUserId: actor.userId, requestId: actor.requestId });
    return mapWaiver(row, actor);
  });
}

export async function decideWaiver(db: FimDb, id: number, decision: 'approve' | 'reject' | 'revoke', note: string, actor: RegActor) {
  return db.transaction(async (q) => {
    const w = rowsOf(await q.query('SELECT * FROM fim_reg_waivers WHERE id = $1 FOR UPDATE', [id]))[0];
    if (!w || !ruleVisible(actor, w.scope_type, w.scope_value)) throw new FimNotFoundError('Waiver not found');
    const t = now();
    const isRequester = (actor.userId !== null && numOrNull(w.requested_by_user_id) === actor.userId)
      || (actor.email ?? '').toLowerCase() === String(w.requested_by).toLowerCase();
    let row: any;
    if (decision === 'approve' || decision === 'reject') {
      if (w.scope_type === 'profile' && !actor.superAdmin) throw new FimForbiddenError('Profile-wide (fleet) waivers must be approved by a Super Administrator');
      if (!(await canApproveWaivers(q, actor, w))) {
        throw new FimForbiddenError('Only a Super Administrator or a designated waiver approver with access to this scope can approve or reject this waiver');
      }
      if (isRequester || actor.userId === null) throw new FimForbiddenError('A waiver must be approved by someone other than the requester');
      if (w.status !== 'pending') throw new FimConflictError(`The waiver is already ${w.status}`);
      if (decision === 'approve' && num(w.expires_at) <= t) throw new FimConflictError('The waiver has already expired');
      if (decision === 'approve' && !w.rule_hash) throw new FimConflictError('The waiver is not bound to a rule and cannot be approved');
      try {
        row = rowsOf(await q.query(
          `UPDATE fim_reg_waivers SET status = $2, approved_by = $3, approved_by_user_id = $4, approved_at = $5, decision_note = $6, approved_by_role = $7 WHERE id = $1 AND status = 'pending' RETURNING *`,
          [id, decision === 'approve' ? 'approved' : 'rejected', actorName(actor), actor.userId, t, note || null, actor.superAdmin ? 'super_admin' : 'approver']))[0];
      } catch (err) {
        if (isCheckViolation(err)) throw new FimForbiddenError('A waiver must be approved by someone other than the requester');
        throw err;
      }
    } else {
      if (!['pending', 'approved'].includes(w.status)) throw new FimConflictError(`The waiver is already ${w.status}`);
      if (!actor.superAdmin && !(isRequester && canWriteScope(actor, w.scope_type, w.scope_value))) throw new FimForbiddenError('Only a Super Administrator or the requester can revoke this waiver');
      row = rowsOf(await q.query(
        `UPDATE fim_reg_waivers SET status = 'revoked', revoked_by = $2, revoked_at = $3, decision_note = COALESCE(decision_note, $4) WHERE id = $1 RETURNING *`,
        [id, actorName(actor), t, note || null]))[0];
    }
    await auditTx(q, actor, 'FIM_REG_WAIVER_DECISION', { waiverId: id, decision, status: row.status, note });
    await configAlert(q, w.scope_type === 'node' ? w.scope_value : null, `FIM registry waiver #${id} ${row.status}: ${w.action} ${w.entry_key} on ${w.scope_type} ${w.scope_value}`, 'high',
      { waiverId: id, status: row.status, by: actorName(actor), byUserId: actor.userId, note, requestId: actor.requestId });
    return mapWaiver(row, actor);
  });
}

/** Creates the waiver's stored rule (once). Super Admin, or the requester while still in scope. */
export async function applyWaiver(db: FimDb, id: number, actor: RegActor, note: string) {
  return db.transaction(async (q) => {
    const w = rowsOf(await q.query('SELECT * FROM fim_reg_waivers WHERE id = $1 FOR UPDATE', [id]))[0];
    if (!w || !ruleVisible(actor, w.scope_type, w.scope_value)) throw new FimNotFoundError('Waiver not found');
    const isRequester = actor.userId !== null && numOrNull(w.requested_by_user_id) === actor.userId;
    if (!actor.superAdmin && !(isRequester && canWriteScope(actor, w.scope_type, w.scope_value))) throw new FimForbiddenError('Only a Super Administrator or the requester can apply this waiver');
    if (w.status !== 'approved') throw new FimConflictError(`The waiver is ${w.status}`);
    if (w.rule_id != null) throw new FimConflictError('The waiver was already used');
    const r = validateRuleInput({ layer: w.scope_type, scopeValue: w.scope_value, op: w.rule_op, target: w.rule_op === 'add' ? 'custom' : w.rule_target, spec: w.rule_spec, reason: `${w.reason} (waiver #${id}${note ? `: ${note}` : ''})`.slice(0, 2000), waiverId: id }, { ...actor, superAdmin: true });
    // An approver reviewed exactly this change (incl. its size): no separate measurement needed.
    const row = await insertRuleTx(q, r, actor, { skipMeasure: true });
    if (r.spec?.dropsAllMonitored) {
      await configAlert(q, r.layer === 'node' ? r.scopeValue : null, `FIM registry: waiver #${id} applied a filter that drops ALL monitored values of ${w.entry_key} on ${r.layer} ${r.scopeValue}`, 'critical',
        { waiverId: id, entryKey: w.entry_key, layer: r.layer, scopeValue: r.scopeValue, by: actorName(actor), byUserId: actor.userId });
    }
    const head = await recordScopeChange(q, r.layer, r.scopeValue, actor, r.reason);
    await auditTx(q, actor, 'FIM_REG_RULE_ADD', { waiverId: id, rule: mapRule(row) });
    return { rule: mapRule(row, actor), historyHead: head };
  });
}

/** Hosts whose PUBLISHED coverage relies on this waiver (republished at once when it is revoked). */
export async function hostsUsingWaiver(q: FimQ, id: number): Promise<string[]> {
  return rowsOf(await q.query(
    `SELECT host_identifier FROM fim_reg_effective WHERE published_waivers @> to_jsonb($1::bigint) ORDER BY host_identifier`, [id])).map((r) => r.host_identifier);
}

// ---------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------

function tierOptions(node: WinNode, data: LayerData, skipNodeLayer = false) {
  const out: Record<string, { entries: number; rows: number; bytes: number }> = {};
  for (const t of REG_TIERS) out[t] = resolveFor(node, data, { tierOverride: t, skipNodeLayer }).totals;
  return out;
}

async function realtimeAvailable(q: FimQ, host: string): Promise<boolean> {
  try {
    return rowsOf(await q.query(
      `SELECT 1 AS x FROM win_registry_events WHERE host_identifier = $1 AND unixtime >= extract(epoch FROM now())::bigint - 86400 LIMIT 1`, [host])).length > 0;
  } catch {
    return false;
  }
}

async function relevantWaivers(q: FimQ, node: WinNode | null, gid: string | null, profileId: number | null, actor: RegActor) {
  const rows = rowsOf(await q.query(
    `SELECT * FROM fim_reg_waivers WHERE (scope_type = 'node' AND scope_value = $1) OR (scope_type = 'group' AND scope_value = $2) OR (scope_type = 'profile' AND scope_value = $3)
     ORDER BY id DESC LIMIT 200`, [node?.host ?? '', gid ?? '', profileId !== null ? String(profileId) : '']));
  return rows.map((w) => mapWaiver(w, actor));
}

async function legacyWarnings(q: FimQ, host: string, entries: EffectiveEntry[]): Promise<string[]> {
  const pols = rowsOf(await q.query(
    `SELECT p.id, p.name, p.paths FROM fim_policies p WHERE p.enabled AND p.managed_kind IS NULL AND p.os_platform = 'windows'
       AND EXISTS (SELECT 1 FROM jsonb_array_elements(p.paths) e WHERE e->>'kind' = 'registry')
       AND EXISTS (SELECT 1 FROM fim_policy_targets t JOIN nodes n ON n.host_identifier = $1 WHERE t.policy_id = p.id
         AND (t.target_type = 'all' OR (t.target_type = 'node' AND t.target_value = n.host_identifier) OR (t.target_type = 'group' AND t.target_value = n.owner_group_id)))`, [host]));
  const out: string[] = [];
  const byPath = new Map(entries.map((e) => [asciiLower(e.path), e.entryKey]));
  for (const p of pols) {
    for (const e of (p.paths ?? []) as FimPathEntry[]) {
      if (e.kind !== 'registry' || !e.path) continue;
      const k = byPath.get(asciiLower(canonicalRegistryKey(e.path)));
      if (k) out.push(`legacy policy '${p.name}' also covers ${k}: each change raises two drifts until its registry entries are removed`);
    }
  }
  return out;
}

export async function getNodeCoverage(q: FimQ, host: string, actor: RegActor) {
  if (!canViewHost(actor, host)) throw new FimNotFoundError('Node not found');
  const node = await getWindowsNode(q, host);
  const settings = await getSettings(q);
  const data = await loadLayerData(q, { host, group: node.ownerGroupId });
  const res = resolveFor(node, data);
  const pol = await getManagedPolicy(q, host);
  const eff = rowsOf(await q.query('SELECT * FROM fim_reg_effective WHERE host_identifier = $1', [host]))[0] ?? null;
  const published = pol ? publishedEntries(pol.paths) : [];
  const pubByKey = new Map(published.map((p) => [p.entryKey, p]));
  const diff = diffCoverage(published, res.entries);
  const ni = await needsInitSlots(q, pol?.id ?? null, host);
  const baseline = new Map<number, number>();
  const entryScan = new Map<number, { lastScanAt: number | null; hives: Record<string, number> | null }>();
  let hostState: string | null = null;
  if (pol) {
    for (const r of rowsOf(await q.query(`SELECT entry_idx, count(*)::int AS n FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 GROUP BY entry_idx`, [pol.id, host]))) baseline.set(num(r.entry_idx), num(r.n));
    for (const r of rowsOf(await q.query(`SELECT entry_idx, last_scan_at, hive_seen FROM fim_host_entry WHERE policy_id = $1 AND host_identifier = $2`, [pol.id, host]))) entryScan.set(num(r.entry_idx), { lastScanAt: numOrNull(r.last_scan_at), hives: r.hive_seen ?? null });
    hostState = rowsOf(await q.query(`SELECT state FROM fim_host_state WHERE policy_id = $1 AND host_identifier = $2`, [pol.id, host]))[0]?.state ?? null;
  }
  const changedKeys = new Set(diff.changed.map((e) => e.entryKey));
  const addedKeys = new Set(diff.added.map((e) => e.entryKey));
  const sevKeys = new Set(diff.severityOnly.map((e) => e.entryKey));
  const entries = res.entries.map((e) => {
    const p = pubByKey.get(e.entryKey);
    const slot = p && p.fingerprint === e.fingerprint ? p.slot : null;
    const scan = slot !== null ? entryScan.get(slot) : undefined;
    return {
      ...e, slot,
      baseline: slot !== null ? { rows: baseline.get(slot) ?? 0, lastScanAt: scan?.lastScanAt ?? null, state: (hostState ?? 'none') as 'locked' | 'learning' | 'none' } : null,
      hives: e.hiveScoped && scan?.hives ? Object.entries(scan.hives).map(([sid, ts]) => ({ sid, lastSeen: num(ts) })).sort((a, b) => b.lastSeen - a.lastSeen) : null,
      pending: addedKeys.has(e.entryKey) ? 'added' as const : changedKeys.has(e.entryKey) ? 'changed' as const : sevKeys.has(e.entryKey) ? 'severity' as const : null,
      needsInit: slot === null || ni.includes(slot),
    };
  });
  let status: string;
  if (!res.ok) status = 'invalid';
  else if (!pol || !pol.enabled) status = 'unmanaged';
  else if (eff?.published_hash !== res.hash) status = 'pending';
  else status = ni.length ? 'needs_init' : 'in_sync';
  const warnings = [...res.warnings, ...(await legacyWarnings(q, host, res.entries))];
  if (pol) {
    const retiredSlots = pol.paths.filter((p) => p.retired).length;
    if (retiredSlots > FIM_REG_CAPS.compactRetiredAbove || pol.paths.length > FIM_REG_CAPS.compactPathsAbove) {
      warnings.push(`compaction recommended: ${retiredSlots} retired slots / ${pol.paths.length} slots (renumbers slots; needs a full re-initialisation)`);
    }
  }
  const rules = { profile: [] as unknown[], group: [] as unknown[], node: [] as unknown[] };
  for (const r of rowsOf(await q.query(
    `SELECT * FROM fim_reg_rules WHERE status = 'active' AND ((layer = 'profile' AND scope_value = $1) OR (layer = 'group' AND scope_value = $2) OR (layer = 'node' AND scope_value = $3)) ORDER BY id`,
    [String(res.profile.id), node.ownerGroupId ?? '', host]))) rules[r.layer as RegLayer].push(mapRule(r, actor));
  const rev = pol?.rev ?? null;
  return {
    host, hostname: node.hostname, ownerGroupId: node.ownerGroupId, policyId: pol?.id ?? null, rev, publishedRev: pol?.publishedRev ?? null,
    profile: res.profile, tier: res.tier, scanIntervalSecs: res.scanIntervalSecs, mode: res.mode, status,
    realtimeAvailable: await realtimeAvailable(q, host), resolvedHash: res.hash, publishedHash: eff?.published_hash ?? null, catalogVersion: REG_CATALOG_VERSION,
    entries, retiredPending: diff.removed, blocked: res.blocked, warnings, errors: res.errors, totals: res.totals,
    tierOptions: tierOptions(node, data), rules,
    assignment: {
      node: data.assignments.get(`node:${host}`) ?? null,
      group: node.ownerGroupId ? data.assignments.get(`group:${node.ownerGroupId}`) ?? null : null,
    },
    waivers: await relevantWaivers(q, node, node.ownerGroupId, res.profile.id, actor),
    needsInitSlots: ni, canManage: canWriteScope(actor, 'node', host), managedEnabled: settings.managedEnabled,
  };
}

export async function previewNode(q: FimQ, host: string, body: any, actor: RegActor) {
  if (!canViewHost(actor, host)) throw new FimNotFoundError('Node not found');
  if (!canWriteScope(actor, 'node', host)) throw new FimForbiddenError('You do not have access to this node');
  const node = await getWindowsNode(q, host);
  const data = await loadLayerData(q, { host, group: node.ownerGroupId });
  const changes = body?.changes ?? [];
  if (!Array.isArray(changes) || changes.length > 100) throw new FimValidationError('changes must be an array of at most 100 changes');
  const extra: RegRule[] = [];
  const drop = new Set<number>();
  const errors: string[] = [];
  const warnings: string[] = [];
  changes.forEach((c: any, i: number) => {
    try {
      if (c?.action === 'revoke') {
        const id = c.ruleId;
        const r = data.rules.find((x) => x.id === id);
        if (!r || r.layer !== 'node' || r.scopeValue !== host) throw new FimValidationError(`change ${i + 1}: rule ${id} is not a node rule of this host`);
        drop.add(id);
      } else if (c?.action === 'add') {
        const r = validateRuleInput({ ...(c.rule ?? {}), layer: 'node', scopeValue: host }, actor);
        const prot = touchesProtected(r);
        // Not an error: on Apply such a change becomes a waiver request (the rule is created once a
        // different approver approves). Parseable prefix for the UI.
        if (prot.length) warnings.push(`protected coverage: ${prot[0].id} change ${i + 1} (${r.op} ${r.target}) needs an approved waiver for exactly this change`);
        extra.push({ id: -(i + 1), layer: 'node', scopeValue: host, op: r.op, target: r.target, spec: r.spec, waiverId: r.waiverId });
      } else {
        throw new FimValidationError(`change ${i + 1}: action must be add or revoke`);
      }
    } catch (err) {
      errors.push((err as Error).message);
    }
  });
  let nodeAssignment: RegAssignment | null | undefined;
  if (body?.assignment !== undefined && body.assignment !== null) {
    const a = body.assignment;
    if (a.tier !== null && a.tier !== undefined && !REG_TIERS.includes(a.tier)) errors.push('assignment.tier is invalid');
    if (a.profileId !== null && a.profileId !== undefined && !data.profiles.some((p) => p.id === a.profileId)) errors.push('assignment.profileId does not exist');
    nodeAssignment = { scopeType: 'node', scopeValue: host, profileId: a.profileId ?? null, tier: a.tier ?? null };
  }
  const res = resolveFor(node, data, { extraRules: extra, dropRuleIds: drop, nodeAssignment });
  const pol = await getManagedPolicy(q, host);
  const published = pol ? publishedEntries(pol.paths) : [];
  const diff = diffCoverage(published, res.entries);
  const slots = await loadSlots(q, host);
  const plan = allocateSlots(slots, res.entries, now());
  const slotKey = new Map(plan.slots.map((s) => [s.slotIdx, s.entryKey]));
  const before = resolveFor(node, data);
  const nextRev = pol ? (pathsChanged(pol.paths, plan.paths as unknown as FimPathEntry[]) ? pol.rev + 1 : pol.rev) : 1;
  const view = (e: EffectiveEntry) => ({ ...e, slot: plan.entrySlot.get(e.entryKey) ?? null, baseline: null, hives: null, pending: null, needsInit: plan.needsInit.includes(plan.entrySlot.get(e.entryKey) ?? -1) });
  return {
    ok: res.ok && errors.length === 0, resolvedHash: res.hash,
    entries: res.entries.map(view),
    diff: { added: diff.added.map(view), removed: diff.removed, changed: diff.changed.map(view), severityOnly: diff.severityOnly.map(view) },
    needsInit: plan.needsInit.map((s) => slotKey.get(s) ?? String(s)),
    estimate: { before: before.totals, after: res.totals },
    rev: { current: pol?.rev ?? null, next: nextRev },
    blocked: res.blocked, errors: [...errors, ...res.errors], warnings: [...warnings, ...res.warnings],
  };
}

export async function listNodes(q: FimQ, f: { q?: string; status?: string; group?: string }, actor: RegActor, page: number, pageSize: number) {
  const like = f.q ? `%${f.q.replace(/[\\%_]/g, (m) => `\\${m}`)}%` : null;
  const viewHosts = actor.viewHosts ? [...actor.viewHosts] : null;
  const where = `WHERE lower(COALESCE(n.os_platform,'')) = 'windows'
      AND ($1::text[] IS NULL OR n.host_identifier = ANY($1))
      AND ($2::text IS NULL OR n.host_identifier ILIKE $2 ESCAPE '\\' OR COALESCE(n.hostname,'') ILIKE $2 ESCAPE '\\')
      AND ($3::text IS NULL OR COALESCE(CASE WHEN p.id IS NULL OR NOT p.enabled THEN 'unmanaged' ELSE e.status END, 'unmanaged') = $3)
      AND ($4::text IS NULL OR n.owner_group_id = $4)`;
  const from = `FROM nodes n LEFT JOIN fim_reg_effective e ON e.host_identifier = n.host_identifier
      LEFT JOIN fim_policies p ON p.managed_kind = 'registry_node' AND p.managed_host = n.host_identifier`;
  const params = [viewHosts, like, f.status || null, f.group || null];
  const total = num(rowsOf(await q.query(`SELECT count(*) AS n ${from} ${where}`, params))[0]?.n);
  const rows = rowsOf(await q.query(
    `SELECT n.host_identifier, n.hostname, n.owner_group_id, e.status, e.resolved, e.published_at, p.id AS policy_id, p.enabled,
       (SELECT count(*) FROM fim_reg_rules r WHERE r.layer = 'node' AND r.scope_value = n.host_identifier AND r.status = 'active')::int AS node_rules,
       EXISTS (SELECT 1 FROM win_registry_events w WHERE w.host_identifier = n.host_identifier AND w.unixtime >= extract(epoch FROM now())::bigint - 86400) AS rt
     ${from} ${where} ORDER BY n.host_identifier LIMIT $5 OFFSET $6`, [...params, pageSize, (page - 1) * pageSize]));
  return {
    items: rows.map((r) => ({
      host: r.host_identifier, hostname: r.hostname ?? null, ownerGroupId: r.owner_group_id ?? null,
      status: !r.policy_id || !r.enabled ? 'unmanaged' : (r.status ?? 'pending'), policyId: numOrNull(r.policy_id),
      profileName: r.resolved?.profile?.name ?? null, tier: r.resolved?.tier?.value ?? null,
      entries: Number(r.resolved?.totals?.entries ?? 0),
      needsInit: Array.isArray(r.resolved?.needsInitSlots) ? r.resolved.needsInitSlots.length : 0,
      nodeRules: num(r.node_rules), realtimeAvailable: !!r.rt, publishedAt: numOrNull(r.published_at),
    })),
    total, page, pageSize,
  };
}

export async function getGroupCoverage(q: FimQ, gid: string, actor: RegActor) {
  if (!canViewGroup(actor, gid)) throw new FimNotFoundError('Group not found');
  await assertScopeExists(q, 'group', gid);
  const data = await loadLayerData(q, { group: gid });
  const synthetic: WinNode = { host: '\u0000group', hostname: null, ownerGroupId: gid };
  const res = resolveFor(synthetic, data, { skipNodeLayer: true });
  const members = await listNodes(q, { group: gid }, actor, 1, 5000);
  const rules = { group: [] as unknown[], profile: [] as unknown[] };
  for (const r of rowsOf(await q.query(
    `SELECT * FROM fim_reg_rules WHERE status = 'active' AND ((layer = 'group' AND scope_value = $1) OR (layer = 'profile' AND scope_value = $2)) ORDER BY id`,
    [gid, String(res.profile.id)]))) (r.layer === 'group' ? rules.group : rules.profile).push(mapRule(r, actor));
  return {
    groupId: gid, assignment: data.assignments.get(`group:${gid}`) ?? null, resolvedHash: res.hash || 'invalid',
    profile: { ...res.profile, source: res.profile.source === 'node' ? 'group' : res.profile.source },
    tier: { ...res.tier, source: res.tier.source === 'node' ? 'group' : res.tier.source },
    entries: res.entries.map((e) => ({ ...e, slot: null, baseline: null, hives: null, pending: null, needsInit: false })),
    blocked: res.blocked, warnings: res.warnings, errors: res.errors, totals: res.totals, tierOptions: tierOptions(synthetic, data, true),
    rules, waivers: await relevantWaivers(q, null, gid, res.profile.id, actor), members: members.items, canManage: canWriteScope(actor, 'group', gid),
  };
}

export async function listNeedsInit(q: FimQ, actor: RegActor) {
  const viewHosts = actor.viewHosts ? [...actor.viewHosts] : null;
  const rows = rowsOf(await q.query(
    `SELECT p.id AS policy_id, p.managed_host AS host, n.hostname, e.needs_init_since, p.paths,
       COALESCE((SELECT state FROM fim_host_state h WHERE h.policy_id = p.id AND h.host_identifier = p.managed_host), 'none') AS state,
       ARRAY(SELECT s.slot_idx FROM fim_reg_slots s WHERE s.host_identifier = p.managed_host AND s.retired_at IS NULL
               AND (NOT EXISTS (SELECT 1 FROM fim_host_state h WHERE h.policy_id = p.id AND h.host_identifier = p.managed_host AND h.state = 'locked')
                    OR NOT EXISTS (SELECT 1 FROM fim_init_requests r WHERE r.policy_id = p.id AND r.host_identifier = p.managed_host
                                   AND r.entry_idx = s.slot_idx AND r.status = 'done' AND r.completed_at >= s.created_at))
             ORDER BY s.slot_idx) AS slots
     FROM fim_policies p LEFT JOIN nodes n ON n.host_identifier = p.managed_host LEFT JOIN fim_reg_effective e ON e.host_identifier = p.managed_host
     WHERE p.managed_kind = 'registry_node' AND p.enabled AND ($1::text[] IS NULL OR p.managed_host = ANY($1))
     ORDER BY p.managed_host LIMIT 5000`, [viewHosts]));
  return rows.filter((r) => (r.slots ?? []).length > 0).map((r) => ({
    host: r.host, hostname: r.hostname ?? null, policyId: num(r.policy_id), since: numOrNull(r.needs_init_since),
    slots: (r.slots as number[]).map((s) => ({ slot: Number(s), entryKey: (r.paths?.[Number(s)]?.entryKey as string) ?? '', path: (r.paths?.[Number(s)]?.path as string) ?? '' })),
  }));
}

// ---------------------------------------------------------------------------------------------
// Rollback (§4.8): forward-only; recreates the snapshot's rules as NEW rules; result is pending
// ---------------------------------------------------------------------------------------------

export async function rollback(db: FimDb, historyId: number, actor: RegActor, note: string) {
  return db.transaction(async (q) => {
    const h = rowsOf(await q.query('SELECT * FROM fim_reg_history WHERE id = $1', [historyId]))[0];
    if (!h || !LAYERS.includes(h.scope_type)) throw new FimNotFoundError('History entry not found');
    const layer = h.scope_type as RegLayer;
    if (!ruleVisible(actor, layer, h.scope_value)) throw new FimNotFoundError('History entry not found');
    assertWrite(actor, layer, h.scope_value);
    const snap = h.snapshot ?? {};
    if (snap.deleted) throw new FimBadRequestError('A deleted profile cannot be restored by rollback');
    await assertScopeExists(q, layer, h.scope_value);
    const t = now();
    await q.query(`UPDATE fim_reg_rules SET status = 'revoked', revoked_by = $3, revoked_at = $4 WHERE layer = $1 AND scope_value = $2 AND status = 'active'`, [layer, h.scope_value, actorName(actor), t]);
    let n = 0;
    const skipped: string[] = [];
    const reason = `rollback to history #${historyId}: ${note}`.slice(0, 2000);
    for (const r of (snap.rules ?? []) as any[]) {
      // Snapshot rules re-enter through EXACTLY the checks a new rule gets, as the caller (no
      // privilege upgrade). Waivers are single-use, so a waiver-backed narrowing is not recreated:
      // the restored scope then has MORE coverage, never less.
      try {
        const input = validateRuleInput({ layer, scopeValue: h.scope_value, op: r.op, target: r.target.startsWith('custom:') && r.op === 'add' ? 'custom' : r.target, spec: { ...(r.spec ?? {}), measureOverride: undefined }, reason, waiverId: null }, actor);
        if (touchesProtected(input).length) { skipped.push(`${r.op} ${r.target}: needed a waiver (single-use); request a new one`); continue; }
        await q.query('SAVEPOINT fim_rb');
        try {
          await insertRuleTx(q, input, actor);
          await q.query('RELEASE SAVEPOINT fim_rb');
          n++;
        } catch (err) {
          await q.query('ROLLBACK TO SAVEPOINT fim_rb');
          skipped.push(`${r.op} ${r.target}: ${(err as Error).message}`);
        }
      } catch (err) {
        skipped.push(`${r.op} ${r.target}: ${(err as Error).message}`);
      }
    }
    if (layer === 'profile' && snap.profile) {
      if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can roll back profile settings');
      const p = snap.profile;
      await q.query(`UPDATE fim_reg_profiles SET description = $2, tier = $3, scan_interval_secs = $4, mode = $5, version = version + 1, updated_by = $6, updated_at = now() WHERE id = $1`,
        [Number(h.scope_value), p.description ?? '', p.tier, p.scanIntervalSecs, p.mode, actorName(actor)]);
    } else if (layer !== 'profile') {
      const a = snap.assignment;
      if (a?.profileId != null && !rowsOf(await q.query('SELECT 1 AS x FROM fim_reg_profiles WHERE id = $1', [a.profileId])).length) skipped.push('assignment: its profile no longer exists');
      else if (!a) await q.query('DELETE FROM fim_reg_assignments WHERE scope_type = $1 AND scope_value = $2', [layer, h.scope_value]);
      else await q.query(
        `INSERT INTO fim_reg_assignments (scope_type, scope_value, profile_id, tier, updated_by) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (scope_type, scope_value) DO UPDATE SET profile_id = EXCLUDED.profile_id, tier = EXCLUDED.tier, version = fim_reg_assignments.version + 1, updated_by = EXCLUDED.updated_by, updated_at = now()`,
        [layer, h.scope_value, a.profileId ?? null, a.tier ?? null, actorName(actor)]);
    }
    const head = await recordScopeChange(q, layer, h.scope_value, actor, reason);
    await auditTx(q, actor, 'FIM_REG_ROLLBACK', { historyId, scopeType: layer, scopeValue: h.scope_value, rules: n, skipped });
    return { status: 'pending', rules: n, skipped, scopeType: layer, scopeValue: h.scope_value as string, rowHash: head.rowHash, historyHead: head };
  });
}

// ---------------------------------------------------------------------------------------------
// Measure (§3.7): count-only distributed query; returns two numbers and no registry data
// ---------------------------------------------------------------------------------------------

function measureSql(scanSql: string): string {
  return `SELECT count(*) AS rows, COALESCE(sum(length(path) + length(name) + length(type) + length(data) + 48), 0) AS bytes FROM (${scanSql})`;
}

export async function requestMeasure(db: FimDb, host: string, entries: unknown, actor: RegActor) {
  if (!canWriteScope(actor, 'node', host)) throw new FimForbiddenError('You do not have access to this node');
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > FIM_REG_CAPS.measurePerHostPer10Min) {
    throw new FimValidationError(`entries must be an array of 1-${FIM_REG_CAPS.measurePerHostPer10Min} catalog ids or custom specs`);
  }
  return db.transaction(async (q) => {
    await q.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [ADVISORY_PUBLISH, `measure:${host}`]);
    await getWindowsNode(q, host);
    const recent = num(rowsOf(await q.query(
      `SELECT count(*) AS n FROM fim_reg_measure WHERE host_identifier = $1 AND created_at >= $2`, [host, now() - 600]))[0]?.n);
    if (recent + entries.length > FIM_REG_CAPS.measurePerHostPer10Min) {
      throw new FimRateLimitError(`at most ${FIM_REG_CAPS.measurePerHostPer10Min} measurements per node per 10 minutes`);
    }
    const out: any[] = [];
    const osBuild = String(rowsOf(await q.query('SELECT os_build FROM nodes WHERE host_identifier = $1', [host]))[0]?.os_build ?? '');
    const after = num(rowsOf(await q.query('SELECT COALESCE(max(id),0) AS m FROM query_result'))[0]?.m);
    for (const raw of entries) {
      let entry: EffectiveEntry;
      if (typeof raw === 'string') {
        const c = getRegCatalogEntry(raw);
        if (!c) throw new FimValidationError(`unknown catalog id '${String(raw).slice(0, 60)}'`);
        const w = fromCatalog(c);
        entry = { ...w, fingerprint: entryFingerprint(w) };
      } else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
        const spec = raw as Record<string, unknown>;
        const v2 = normalizeRegistryEntryV2({ ...spec, entryKey: undefined }, { allowRecursive: actor.superAdmin });
        const w = customEntry(customEntryKey(v2.path), { ...spec, ...v2 });
        entry = { ...w, fingerprint: entryFingerprint(w) };
      } else {
        throw new FimValidationError('entries must be catalog ids or custom key specs');
      }
      const sql = measureSql(buildRegistryScanSqlV2(entry));
      const qq = rowsOf(await q.query(`INSERT INTO query_queue (host_identifier, query, sent, send_time) VALUES ($1, $2, false, 0) RETURNING id`, [host, sql]))[0];
      const row = rowsOf(await q.query(
        `INSERT INTO fim_reg_measure (host_identifier, entry_key, fingerprint, spec, queue_id, after_result_id, requested_by, created_at, os_build)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9) RETURNING *`,
        [host, entry.entryKey, entry.fingerprint, JSON.stringify({ path: entry.path, values: entry.values, ignoreValues: entry.ignoreValues, excludeKeys: entry.excludeKeys }), num(qq.id), after, actorName(actor), now(), osBuild]))[0];
      out.push(mapMeasure(row));
    }
    return out;
  });
}

const mapMeasure = (m: any) => ({
  id: num(m.id), host: m.host_identifier, entryKey: m.entry_key, status: m.status, rows: numOrNull(m.rows_count), bytes: numOrNull(m.bytes_count),
  error: m.error ?? null, createdAt: num(m.created_at), completedAt: numOrNull(m.completed_at),
});

export async function getMeasure(db: FimDb, id: number, actor: RegActor) {
  return db.transaction(async (q) => {
    const m = rowsOf(await q.query('SELECT * FROM fim_reg_measure WHERE id = $1 FOR UPDATE', [id]))[0];
    if (!m || !canViewHost(actor, m.host_identifier)) throw new FimNotFoundError('Measurement not found');
    if (m.status !== 'pending') return mapMeasure(m);
    // A failure row counts only for THIS host (same rule as the worker): rows tagged with another
    // host are ignored; untagged legacy rows ("... on host (status=") still count.
    const prefix = 'distributed query failed on host ';
    const dl = rowsOf(await q.query('SELECT error_message FROM dead_letter_queue WHERE table_name = $1 ORDER BY id DESC LIMIT 20', [String(m.queue_id)]))
      .find((r) => { const e = String(r.error_message ?? ''); return !e.startsWith(prefix) || e.startsWith(`${prefix}(`) || e.startsWith(`${prefix}${m.host_identifier} (`); });
    if (dl) {
      const u = rowsOf(await q.query(`UPDATE fim_reg_measure SET status = 'failed', error = $2, completed_at = $3 WHERE id = $1 RETURNING *`, [id, String(dl.error_message ?? 'query failed').slice(0, 500), now()]))[0];
      return mapMeasure(u);
    }
    const r = rowsOf(await q.query(
      `SELECT result FROM query_result WHERE id > $1 AND host_identifier = $2 AND query_name = $3 ORDER BY id DESC LIMIT 1`, [num(m.after_result_id), m.host_identifier, String(m.queue_id)]))[0];
    if (!r) return mapMeasure(m);
    let rowsN: number | null = null, bytesN: number | null = null;
    try {
      const doc = JSON.parse(r.result ?? '[]');
      const first = Array.isArray(doc) ? doc[0] : null;
      const rr = Number(first?.rows), bb = Number(first?.bytes);
      // Agent-reported numbers are bounded by what the query can produce: each row adds 48 bytes
      // plus its text, and nothing beyond osquery's own limits is plausible.
      if (Number.isFinite(rr) && Number.isFinite(bb) && rr >= 0 && bb >= 0 && rr <= 10_000_000 && bb <= 10 * 1024 ** 3 && bb >= rr * 48 && (rr > 0 || bb === 0)) {
        rowsN = Math.floor(rr); bytesN = Math.floor(bb);
      }
    } catch { /* invalid result: failed below */ }
    const u = rowsN === null
      ? rowsOf(await q.query(`UPDATE fim_reg_measure SET status = 'failed', error = 'unexpected or implausible result', completed_at = $2 WHERE id = $1 RETURNING *`, [id, now()]))[0]
      : rowsOf(await q.query(`UPDATE fim_reg_measure SET status = 'done', rows_count = $2, bytes_count = $3, completed_at = $4 WHERE id = $1 RETURNING *`, [id, rowsN, bytesN, now()]))[0];
    return mapMeasure(u);
  });
}

// ---------------------------------------------------------------------------------------------
// Baseline hygiene (§4.5): flag (never block) suspicious values adopted by Initialize
// ---------------------------------------------------------------------------------------------

const USER_WRITABLE = ['\\appdata\\', '\\temp\\', '\\users\\public\\', '\\programdata\\'];
const KNOWN_VENDOR_DIRS = ['\\programdata\\microsoft\\', '\\programdata\\package cache\\'];
const DEFAULT_PKG: Record<string, Set<string>> = {
  'authentication packages': new Set(['msv1_0']),
  'notification packages': new Set(['scecli', 'rassfm']),
  'security packages': new Set(['', '""', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts']),
};

export function hygieneFindings(items: { path: string; sha256: string | null; data: any }[]): { itemPath: string; sha256: string; rule: string; detail: string; severity: 'low' | 'medium' | 'high' | 'critical' }[] {
  const out: ReturnType<typeof hygieneFindings> = [];
  for (const it of items) {
    const d = it.data ?? {};
    if (d.type === 'anchor') continue;
    const p = String(it.path).toLowerCase();
    const data = String(d.data ?? '');
    const dl = data.toLowerCase();
    const name = p.slice(p.lastIndexOf('\\') + 1);
    const push = (rule: string, detail: string, severity: 'low' | 'medium' | 'high' | 'critical') => out.push({ itemPath: it.path, sha256: it.sha256 ?? '', rule, detail, severity });
    const isRunKey = /\\currentversion\\(run|runonce|runservices|runservicesonce|policies\\explorer\\run)\\[^\\]+$/.test(p) || (p.includes('\\active setup\\installed components\\') && name === 'stubpath');
    if (isRunKey && USER_WRITABLE.some((w) => dl.includes(w)) && !KNOWN_VENDOR_DIRS.some((v) => dl.includes(v))) push('autostart-user-writable', 'autostart value points into a user-writable directory', 'high');
    if (p.includes('\\image file execution options\\') && (name === 'debugger' || name === 'verifierdlls') && data.trim()) push('ifeo-debugger', `IFEO ${name} is set`, 'critical');
    if (p.includes('\\windows nt\\currentversion\\windows\\') && name === 'appinit_dlls' && data.trim()) push('appinit-dlls', 'AppInit_DLLs is not empty', 'critical');
    if (p.includes('\\windows nt\\currentversion\\windows\\') && name === 'loadappinit_dlls' && data.trim() === '1') push('appinit-enabled', 'LoadAppInit_DLLs = 1', 'critical');
    if (p.includes('\\control\\lsa\\') && DEFAULT_PKG[name]) {
      // The worker stores control characters escaped (<U+000A>, <U+0000>): split on both forms.
      const extra = data.split(/,|\n|\0|<U\+000A>|<U\+0000>|<U\+000D>/i).map((s) => s.trim().toLowerCase()).filter((s) => s && !DEFAULT_PKG[name].has(s));
      if (extra.length) push('lsa-packages', `${name} has non-default package(s): ${extra.join(', ').slice(0, 200)}`, 'high');
    }
    if (p.includes('\\control\\lsa\\') && name === 'runasppl' && data.trim() === '0') push('runasppl-off', 'RunAsPPL = 0 (LSA protection off)', 'medium');
    if (p.includes('\\securityproviders\\wdigest\\') && name === 'uselogoncredential' && data.trim() === '1') push('wdigest-cleartext', 'WDigest UseLogonCredential = 1 (clear-text credentials)', 'critical');
    if (p.includes('\\windows defender\\exclusions\\')) push('defender-exclusion', 'Defender exclusion present', 'high');
    if (/\\currentcontrolset\\control\\minint$/.test(p)) push('minint', 'MiniNt key present (event logging disabled)', 'critical');
  }
  return out;
}

export async function getHygiene(q: FimQ, host: string, actor: RegActor) {
  if (!canViewHost(actor, host)) throw new FimNotFoundError('Node not found');
  const pol = await getManagedPolicy(q, host);
  if (!pol) return [];
  const items = rowsOf(await q.query(`SELECT path, sha256, data FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 AND kind = 'item' LIMIT 50000`, [pol.id, host]));
  const findings = hygieneFindings(items.map((r) => ({ path: r.path, sha256: r.sha256 ?? null, data: r.data })));
  // Fleet rarity: a value seen on < 2 % of the hosts that baselined the same item (≥ 10 hosts).
  const rare = rowsOf(await q.query(
    `WITH mine AS (
       SELECT path, COALESCE(sha256,'') AS sha, regexp_replace(path, '^registry\\|HKEY_USERS\\\\[^\\\\]+', 'registry|HKEY_USERS\\\\%') AS np
       FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 AND kind = 'item' AND COALESCE(data->>'type','') <> 'anchor'),
     fleet AS (
       SELECT regexp_replace(b.path, '^registry\\|HKEY_USERS\\\\[^\\\\]+', 'registry|HKEY_USERS\\\\%') AS np, COALESCE(b.sha256,'') AS sha, count(DISTINCT b.host_identifier) AS n
       FROM fim_baseline b JOIN fim_policies p ON p.id = b.policy_id AND p.managed_kind = 'registry_node'
       WHERE b.kind = 'item' AND regexp_replace(b.path, '^registry\\|HKEY_USERS\\\\[^\\\\]+', 'registry|HKEY_USERS\\\\%') IN (SELECT np FROM mine)
       GROUP BY 1, 2),
     tot AS (SELECT np, sum(n) AS total FROM fleet GROUP BY np)
     SELECT m.path, m.sha, f.n, t.total FROM mine m JOIN fleet f ON f.np = m.np AND f.sha = m.sha JOIN tot t ON t.np = m.np
     WHERE t.total >= 10 AND f.n::float / t.total < 0.02 LIMIT 500`, [pol.id, host]));
  for (const r of rare) findings.push({ itemPath: r.path, sha256: r.sha, rule: 'fleet-rarity', detail: `value seen on ${num(r.n)} of ${num(r.total)} hosts with this item`, severity: 'low' });
  const acks = new Map(rowsOf(await q.query('SELECT * FROM fim_reg_hygiene_ack WHERE host_identifier = $1', [host])).map((a) => [`${a.item_path}\u0000${a.sha256}`, a]));
  return findings.map((f) => {
    const a = acks.get(`${f.itemPath}\u0000${f.sha256}`);
    return { ...f, acked: !!a, ackedBy: a?.acked_by ?? null, ackedAt: numOrNull(a?.acked_at), note: a?.note ?? null };
  });
}

export async function ackHygiene(db: FimDb, host: string, body: any, actor: RegActor) {
  if (!canWriteScope(actor, 'node', host)) throw new FimForbiddenError('You do not have access to this node');
  const itemPath = cleanText(body?.itemPath, 'itemPath', 4096, true);
  const sha = typeof body?.sha256 === 'string' && /^[0-9a-f]{0,64}$/.test(body.sha256) ? body.sha256 : null;
  if (sha === null) throw new FimValidationError('sha256 must be a hex digest (or empty)');
  const note = cleanText(body?.note, 'note', 2000, true);
  await db.query(
    `INSERT INTO fim_reg_hygiene_ack (host_identifier, item_path, sha256, acked_by, acked_at, note) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (host_identifier, item_path, sha256) DO UPDATE SET acked_by = EXCLUDED.acked_by, acked_at = EXCLUDED.acked_at, note = EXCLUDED.note`,
    [host, itemPath, sha, actorName(actor), now(), note]);
  return { itemPath, sha256: sha, note };
}

// ---------------------------------------------------------------------------------------------
// Migration assistant (§3.15 step 3): legacy hand-made registry entries -> layer rules
// ---------------------------------------------------------------------------------------------

function mapLegacyEntry(e: FimPathEntry, index: number) {
  const path = canonicalRegistryKey(e.path ?? '');
  const err = validateRegistryKeyV2(path, { allowRecursive: true });
  if (err) return { index, path: e.path ?? '', mapping: { type: 'invalid' as const, error: err } };
  const cat = REG_CATALOG.find((c) => asciiLower(c.path) === asciiLower(path));
  if (cat) {
    const same = (a: string[] = [], b: string[] = []) => a.length === b.length && a.every((x) => b.some((y) => asciiLower(y) === asciiLower(x)));
    const exact = !e.values ? cat.values.length === 0 : same(e.values, cat.values);
    return { index, path, mapping: { type: 'catalog' as const, entryKey: cat.id, exact } };
  }
  const spec = { path, values: e.values ?? [], ignoreValues: e.ignoreValues ?? [], excludeKeys: e.excludeKeys ?? [], severity: e.severity, category: e.category || 'custom', label: e.label || 'Migrated registry key' };
  try {
    normalizeRegistryEntryV2(spec, { allowRecursive: true });
    return { index, path, mapping: { type: 'custom' as const, spec } };
  } catch (x) {
    return { index, path, mapping: { type: 'invalid' as const, error: (x as Error).message } };
  }
}

/**
 * Stored policies with entries that can no longer be built (e.g. non-ASCII registry keys saved
 * before the ASCII-only rule): such a policy cannot be republished until the entry is fixed or
 * removed. Reported (Super Admin endpoint + a daily oversight alert) with the offending entry.
 */
export async function listUnbuildablePolicies(q: FimQ): Promise<{ policyId: number; name: string; entries: { index: number; path: string; error: string }[] }[]> {
  const out: { policyId: number; name: string; entries: { index: number; path: string; error: string }[] }[] = [];
  // Managed per-node policies are generated (always buildable): only hand-made ones are checked.
  // Yields regularly (this runs inside the reconcile sweep).
  let last = Date.now();
  for (const p of rowsOf(await q.query(`SELECT id, name, os_platform, paths FROM fim_policies WHERE managed_kind IS NULL ORDER BY id`))) {
    if (Date.now() - last > 20) { await new Promise<void>((r) => setImmediate(r)); last = Date.now(); }
    const bad: { index: number; path: string; error: string }[] = [];
    ((p.paths ?? []) as FimPathEntry[]).forEach((e, i) => {
      if (e.retired) return;
      try { buildScanSql(e as never, (e.kind === 'registry' || e.kind === 'acl') ? 'windows' : p.os_platform); } catch (err) {
        bad.push({ index: i, path: String(e.path ?? '').slice(0, 300), error: (err as Error).message.slice(0, 300) });
      }
    });
    if (bad.length) out.push({ policyId: num(p.id), name: p.name, entries: bad });
  }
  return out;
}

export async function listLegacy(q: FimQ, actor: RegActor) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can use the migration assistant');
  const pols = rowsOf(await q.query(
    `SELECT id FROM fim_policies WHERE managed_kind IS NULL AND os_platform = 'windows'
       AND EXISTS (SELECT 1 FROM jsonb_array_elements(paths) e WHERE e->>'kind' = 'registry') ORDER BY id`));
  const out: any[] = [];
  for (const { id } of pols) {
    const p = (await fetchPolicy(q, num(id), false))!;
    const entries = (p.paths as FimPathEntry[]).map((e, i) => ({ e, i })).filter(({ e }) => e.kind === 'registry').map(({ e, i }) => mapLegacyEntry(e, i));
    const overlap = num(rowsOf(await q.query(
      `SELECT count(*) AS n FROM fim_policies m WHERE m.managed_kind = 'registry_node' AND m.enabled AND m.managed_host IN (
         SELECT n.host_identifier FROM nodes n JOIN fim_policy_targets t ON t.policy_id = $1
         WHERE t.target_type = 'all' OR (t.target_type = 'node' AND t.target_value = n.host_identifier) OR (t.target_type = 'group' AND t.target_value = n.owner_group_id))`, [p.id]))[0]?.n);
    out.push({ id: p.id, name: p.name, template: p.template, targets: p.targets, entries, overlapHosts: overlap, templateUpgradeAvailable: templateUpgradeAvailable(p) });
  }
  return out;
}

export async function applyLegacy(db: FimDb, policyId: number, actor: RegActor, note: string) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can use the migration assistant');
  return db.transaction(async (q) => {
    const p = await fetchPolicy(q, policyId, false);
    if (!p || p.managedKind) throw new FimNotFoundError('Legacy policy not found');
    const data = await loadLayerData(q);
    const dflt = data.profiles.find((x) => x.isDefault);
    const scopes: { layer: RegLayer; scopeValue: string }[] = p.targets.map((t) => (
      t.type === 'all' ? { layer: 'profile' as const, scopeValue: String(dflt?.id ?? '') } : { layer: t.type as RegLayer, scopeValue: t.value }
    )).filter((s) => s.scopeValue);
    const maps = (p.paths as FimPathEntry[]).filter((e) => e.kind === 'registry').map((e, i) => mapLegacyEntry(e, i));
    let created = 0, skipped = 0;
    const reason = `migrated from legacy policy '${p.name}' (#${p.id}): ${note}`.slice(0, 2000);
    for (const s of scopes) {
      for (const m of maps) {
        let input: RuleInput;
        if (m.mapping.type === 'catalog') {
          const c = getRegCatalogEntry(m.mapping.entryKey)!;
          if (c.tier === 'essential') { skipped++; continue; } // always in coverage
          input = { layer: s.layer, scopeValue: s.scopeValue, op: 'add', target: c.id, spec: {}, reason, waiverId: null };
        } else if (m.mapping.type === 'custom') {
          input = validateRuleInput({ layer: s.layer, scopeValue: s.scopeValue, op: 'add', target: 'custom', spec: { ...m.mapping.spec, measureOverride: true }, reason }, actor);
        } else { skipped++; continue; }
        // Same checks as any new rule (a legacy key that would narrow protected coverage is skipped).
        try {
          await q.query('SAVEPOINT fim_mig');
          await insertRuleTx(q, input, actor, { skipMeasure: true });
          await q.query('RELEASE SAVEPOINT fim_mig');
          created++;
        } catch (err) {
          await q.query('ROLLBACK TO SAVEPOINT fim_mig');
          if (err instanceof FimConflictError || err instanceof FimValidationError || isUniqueViolation(err)) { skipped++; continue; }
          throw err;
        }
      }
      await recordScopeChange(q, s.layer, s.scopeValue, actor, reason);
    }
    return { rules: created, skipped, scopes: scopes.length };
  });
}

export async function removeLegacyRegistry(db: FimDb, policyId: number, actor: RegActor) {
  if (!actor.superAdmin) throw new FimForbiddenError('Only a Super Administrator can use the migration assistant');
  return db.transaction(async (q) => {
    const lk = rowsOf(await q.query('SELECT id FROM fim_policies WHERE id = $1 FOR UPDATE', [policyId]));
    const p = lk.length ? await fetchPolicy(q, policyId, false) : null;
    if (!p || p.managedKind) throw new FimNotFoundError('Legacy policy not found');
    const keep = (p.paths as FimPathEntry[]).filter((e) => e.kind !== 'registry');
    const removed = p.paths.length - keep.length;
    if (!removed) throw new FimBadRequestError('The policy has no registry entries');
    if (keep.length) {
      const paths = normalizePaths(keep, p.osPlatform, { superAdmin: true });
      await q.query('UPDATE fim_policies SET paths = $2::jsonb, rev = rev + 1, updated_at = now() WHERE id = $1', [policyId, JSON.stringify(paths)]);
    } else {
      // A policy must keep at least one entry: disable it instead of emptying it.
      await q.query('UPDATE fim_policies SET enabled = false, updated_at = now() WHERE id = $1', [policyId]);
    }
    if (p.configQueryId) await publishPolicyTx(q, policyId);
    return { removed, disabled: keep.length === 0, policy: await fetchPolicy(q, policyId, false) };
  });
}

// ---------------------------------------------------------------------------------------------
// Reconcile job (§3.10, §4.3, §4.4): runs in the backend's 60 s loop
// ---------------------------------------------------------------------------------------------

export interface ReconcileStats { nodes: number; autoPublished: number; pending: number; invalid: number; disabled: number; deleted: number; purgedSlots: number; expiredWaivers: number; errors: number; resolved: number; cached: number; writes: number; skipped?: boolean; timeBoxed?: boolean; ms?: number }
const lastDaily = { chain: 0, digest: 0 };
const chainState = { unverifiableSince: 0 };
const sweepCursor = { host: '' };
const cmpStr = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const ADVISORY_SWEEP = 727204;

export async function reconcileRegistryNodes(db: FimDb, log?: (msg: string, extra?: Record<string, unknown>) => void,
  opts: { onlyHosts?: Set<string>; anchor?: HistoryAnchorFn; anchorWrite?: AnchorWriter } = {}): Promise<ReconcileStats> {
  const st: ReconcileStats = { nodes: 0, autoPublished: 0, pending: 0, invalid: 0, disabled: 0, deleted: 0, purgedSlots: 0, expiredWaivers: 0, errors: 0, resolved: 0, cached: 0, writes: 0 };
  const started = Date.now();
  // One sweep at a time across backend instances: the lock lives as long as this wrapper transaction.
  await db.transaction(async (lockQ) => {
    const got = rowsOf(await lockQ.query('SELECT pg_try_advisory_xact_lock($1) AS ok', [ADVISORY_SWEEP]))[0]?.ok;
    if (!got) { st.skipped = true; return; }
    await sweep(db, st, log, opts);
  });
  st.ms = Date.now() - started;
  return st;
}

async function sweep(db: FimDb, st: ReconcileStats, log: ((msg: string, extra?: Record<string, unknown>) => void) | undefined,
  opts: { onlyHosts?: Set<string>; anchor?: HistoryAnchorFn; anchorWrite?: AnchorWriter }): Promise<void> {
  // Retry pending anchor writes (outbox) before anything else; an overdue anchor is alerted.
  if (opts.anchorWrite) await flushHistoryAnchors(db, opts.anchorWrite).catch((err) => log?.('FIM registry history anchor write failed (will retry)', { err }));
  const overdue = rowsOf(await db.query('SELECT count(*)::int AS n, min(created_at) AS t FROM fim_reg_anchor_outbox WHERE anchored_at IS NULL'))[0];
  if (overdue && num(overdue.n) > 0 && num(overdue.t) < now() - FIM_HISTORY_ANCHOR_OVERDUE_SECS) {
    await configAlert(db, null, 'FIM registry history anchor writes are overdue: tail truncation cannot be detected until they succeed', 'critical', { pending: num(overdue.n), since: num(overdue.t) }, true);
  }
  const only = (h: string) => !opts.onlyHosts || opts.onlyHosts.has(h);
  const settings = await getSettings(db);
  const t = now();
  // Waiver expiry (always, even when coverage is off).
  const expired = rowsOf(await db.query(
    `UPDATE fim_reg_waivers SET status = 'expired' WHERE status = 'approved' AND expires_at <= $1 RETURNING *`, [t]));
  st.expiredWaivers = expired.length;
  for (const w of expired) {
    await configAlert(db, w.scope_type === 'node' ? w.scope_value : null, `FIM registry waiver #${w.id} expired: ${w.action} ${w.entry_key} on ${w.scope_type} ${w.scope_value} (affected nodes are republished in this sweep; a node whose coverage cannot be resolved gets the fail-safe catalog-only coverage)`, 'high',
      { waiverId: num(w.id), entryKey: w.entry_key, scopeType: w.scope_type, scopeValue: w.scope_value });
  }
  // Soft-retire purge: baseline rows of slots retired > 7 days ago. Re-checked under the host's
  // publish lock and a row lock, so a slot revived meanwhile is never purged.
  for (const c of rowsOf(await db.query(
    `SELECT host_identifier, slot_idx FROM fim_reg_slots WHERE retired_at IS NOT NULL AND purged_at IS NULL AND purge_after <= $1 LIMIT 5000`, [t]))) {
    if (!only(c.host_identifier)) continue;
    await db.transaction(async (q) => {
      await q.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [ADVISORY_PUBLISH, c.host_identifier]);
      const s0 = rowsOf(await q.query(
        `SELECT 1 AS x FROM fim_reg_slots WHERE host_identifier = $1 AND slot_idx = $2 AND retired_at IS NOT NULL AND purged_at IS NULL AND purge_after <= $3 FOR UPDATE`,
        [c.host_identifier, c.slot_idx, t]));
      if (!s0.length) return;
      const pid = rowsOf(await q.query(`SELECT id FROM fim_policies WHERE managed_kind = 'registry_node' AND managed_host = $1`, [c.host_identifier]))[0]?.id;
      if (pid) await q.query('DELETE FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 AND entry_idx = $3', [pid, c.host_identifier, c.slot_idx]);
      await q.query('UPDATE fim_reg_slots SET purged_at = $3 WHERE host_identifier = $1 AND slot_idx = $2', [c.host_identifier, c.slot_idx, t]);
      // Slot state is an input of publishing (slot cap, reuse of purged slots): drop the cached
      // input digest so an invalid node is re-evaluated (and retried) on the next pass.
      await q.query('UPDATE fim_reg_effective SET inputs_key = NULL WHERE host_identifier = $1', [c.host_identifier]);
      st.purgedSlots++;
    });
  }
  // Nodes that disappeared (or stopped being Windows): disable now, delete after retention.
  for (const p of rowsOf(await db.query(
    `SELECT p.id, p.enabled, p.updated_at, p.managed_host FROM fim_policies p
     WHERE p.managed_kind = 'registry_node' AND NOT EXISTS (SELECT 1 FROM nodes n WHERE n.host_identifier = p.managed_host AND lower(COALESCE(n.os_platform,'')) = 'windows')`))) {
    if (!only(p.managed_host)) continue;
    try {
      await db.transaction(async (q) => {
        if (p.enabled) {
          await q.query('UPDATE fim_policies SET enabled = false, updated_at = now() WHERE id = $1', [p.id]);
          await publishPolicyTx(q, num(p.id));
          st.disabled++;
        } else if (tsec(p.updated_at) < t - FIM_REG_DELETED_NODE_RETENTION_DAYS * 86400) {
          const cq = rowsOf(await q.query('SELECT config_query_id FROM fim_policies WHERE id = $1', [p.id]))[0]?.config_query_id;
          if (cq) await q.query('DELETE FROM config_queries WHERE id = $1', [cq]);
          await q.query('DELETE FROM fim_policies WHERE id = $1', [p.id]); // drift is kept (no FK)
          await q.query('DELETE FROM fim_reg_slots WHERE host_identifier = $1', [p.managed_host]);
          await q.query('DELETE FROM fim_reg_effective WHERE host_identifier = $1', [p.managed_host]);
          st.deleted++;
        }
      });
    } catch (err) { st.errors++; log?.('FIM registry: cleanup of a removed node failed', { err, policyId: p.id }); }
  }
  if (settings.managedEnabled && registryDisabled) log?.('FIM registry disabled; automatic publishing skipped', { reason: registryDisabled.reason });
  if (settings.managedEnabled && !registryDisabled) {
    const data = await loadLayerData(db);
    const validWaivers = new Set(data.waivers.filter((w) => w.status === 'approved' && w.expiresAt > t).map((w) => w.id));
    let budget = FIM_REG_AUTO_PUBLISH_PER_SWEEP;
    const deadline = Date.now() + FIM_REG_SWEEP_BUDGET_MS;
    const effRows = new Map(rowsOf(await db.query(
      `SELECT host_identifier, owner_group_id, resolved_hash, published_hash, status, invalid_since, inputs_key, auto_attempt_hash, published_waivers FROM fim_reg_effective`))
      .map((r) => [r.host_identifier, r]));
    const pols = new Map(rowsOf(await db.query(`SELECT id, managed_host, enabled FROM fim_policies WHERE managed_kind = 'registry_node'`)).map((r) => [r.managed_host, r]));
    // Needs-init for all managed hosts in ONE query (not one per node).
    const needsInit = new Set(rowsOf(await db.query(
      `SELECT p.managed_host FROM fim_policies p WHERE p.managed_kind = 'registry_node' AND p.enabled AND EXISTS (
         SELECT 1 FROM fim_reg_slots s WHERE s.host_identifier = p.managed_host AND s.retired_at IS NULL
           AND (NOT EXISTS (SELECT 1 FROM fim_host_state h WHERE h.policy_id = p.id AND h.host_identifier = p.managed_host AND h.state = 'locked')
                OR NOT EXISTS (SELECT 1 FROM fim_init_requests r WHERE r.policy_id = p.id AND r.host_identifier = p.managed_host
                               AND r.entry_idx = s.slot_idx AND r.status = 'done' AND r.completed_at >= s.created_at)))`)).map((r) => r.managed_host));
    const allNodes = (await allWindowsNodes(db)).filter((n) => only(n.host));
    // Pass 1 (cheap, every node, no resolution): automatic publishes, in priority order -
    // restoring coverage behind an invalid waiver (budget-exempt), then new nodes, group moves,
    // feature re-enable. The rate is configurable (FIM_REG_AUTO_PUBLISH_PER_SWEEP).
    const prio: Record<string, number> = { waiver_invalid: 0, new_node: 1, group_change: 2, feature_enabled: 3, retry_invalid: 4 };
    const cands: { n: WinNode; reason: string }[] = [];
    // Yield to the event loop at least every ~20 ms of synchronous work (API stays responsive).
    let lastYield = Date.now();
    const maybeYield = async () => { if (Date.now() - lastYield >= 20) { await new Promise<void>((r) => setImmediate(r)); lastYield = Date.now(); } };
    for (const n of allNodes) {
      await maybeYield();
      const eff = effRows.get(n.host);
      const pol = pols.get(n.host);
      const published: number[] = Array.isArray(eff?.published_waivers) ? eff.published_waivers.map(Number) : [];
      let reason: string | null = null;
      if (pol?.enabled && published.some((id) => !validWaivers.has(id))) reason = 'waiver_invalid';
      else if (!pol) reason = 'new_node';
      else if (!pol.enabled) reason = 'feature_enabled';
      else if (eff && (eff.owner_group_id ?? null) !== (n.ownerGroupId ?? null)) reason = 'group_change';
      // An invalid node whose inputs changed (or whose cache was invalidated, e.g. by a slot purge) is retried.
      else if (eff?.status === 'invalid' && eff.inputs_key !== inputsKeyFor(n, data, t)) reason = 'retry_invalid';
      if (reason) cands.push({ n, reason });
    }
    cands.sort((x, y) => prio[x.reason] - prio[y.reason] || cmpStr(x.n.host, y.n.host));
    const published = new Set<string>();
    // Pass 1 gets at most half of the sweep budget so pass 2 (status of every node) always runs.
    const pass1Deadline = Date.now() + Math.floor(FIM_REG_SWEEP_BUDGET_MS / 2);
    // Phase A: cheap pre-check (resolution only). Phase B: publish HEALTHY nodes (budgeted: only
    // successful publishes count). Phase C: fail-safe catalog-only publish for INVALID nodes with
    // the time left (they never delay healthy nodes; an invalid node with a policy is backed off by
    // input digest and not re-resolved while its inputs are unchanged).
    const healthy: { n: WinNode; reason: string; pre?: PreResolved }[] = [];
    const invalidQ: { n: WinNode; reason: string; pre?: PreResolved }[] = [];
    for (const c of cands) {
      if (Date.now() > pass1Deadline) { st.timeBoxed = true; break; }
      await maybeYield();
      if (c.reason === 'waiver_invalid') { healthy.push(c); continue; }
      const eff = effRows.get(c.n.host);
      const pol = pols.get(c.n.host);
      const key = inputsKeyFor(c.n, data, t);
      if (eff?.status === 'invalid' && eff.inputs_key === key) {
        st.cached++;
        // Known invalid, inputs unchanged: never re-resolved. Until its published config IS the
        // fail-safe catalog-only coverage it is queued for that (phase C); then it is backed off.
        if (!pol || eff.auto_attempt_hash !== 'failsafe') invalidQ.push(c);
        continue;
      }
      // Enough healthy candidates to fill the budget: no need to pre-check more this sweep.
      if (healthy.filter((h) => h.reason !== 'waiver_invalid').length >= budget) continue;
      const pre = resolveFor(c.n, data, { now: t });
      st.resolved++;
      if (pre.ok) { healthy.push({ ...c, pre: { res: pre, inputsKey: key } }); continue; }
      // Record the invalid result at once (input digest), so it is never re-resolved while its
      // inputs are unchanged; it gets the fail-safe coverage in phase C (now or a later sweep).
      await upsertEffective(db, c.n.host, { policyId: pol ? num(pol.id) : null, ownerGroupId: c.n.ownerGroupId, resolved: resolvedJson(pre, new Map(), []), resolvedHash: pre.hash || 'invalid',
        status: 'invalid', error: pre.errors.join('; ').slice(0, 4000), inputsKey: key });
      published.add(c.n.host); // recorded here: pass 2 must not resolve it a second time
      // Keep only what the fail-safe publish needs (ok=false + errors): holding thousands of full
      // resolutions would cost memory and long GC pauses.
      invalidQ.push({ ...c, pre: { res: { ...pre, entries: [], blocked: [], warnings: [] }, inputsKey: key } });
    }
    const run = async (n: WinNode, reason: string, pre?: PreResolved) => {
      const r = await publishNode(db, n.host, { actor: systemActor(), note: `automatic: ${reason}`, auto: reason, pre });
      published.add(n.host);
      log?.('FIM_REG_AUTO_REPUBLISH', { host: n.host, reason, status: r.status, rev: r.rev, needsInit: r.needsInit.length, retired: r.retired.length, error: r.error });
      return r;
    };
    for (const { n, reason, pre } of healthy) {
      if (Date.now() > pass1Deadline) { st.timeBoxed = true; break; }
      if (reason !== 'waiver_invalid' && budget <= 0) continue;
      try {
        const r = await run(n, reason, pre);
        if (r.status === 'invalid') st.invalid++; else { st.autoPublished++; if (reason !== 'waiver_invalid') budget--; }
      } catch (err) { st.errors++; log?.('FIM registry automatic publish failed', { err, host: n.host, reason }); }
    }
    // Fail-safe publishes are protective: limited only by the pass-1 time box (no count budget).
    for (const { n, reason, pre } of invalidQ) {
      if (Date.now() > pass1Deadline) { st.timeBoxed = true; break; }
      try { await run(n, reason, pre); st.invalid++; } catch (err) { st.errors++; log?.('FIM registry fail-safe publish failed', { err, host: n.host, reason }); }
    }
    // Pass 2: status of every node, time-boxed and resumable (cursor) so a cold sweep of a large
    // fleet never overruns the 60 s interval; cached by input digest, writes only on change.
    const ordered = [...allNodes].sort((x, y) => cmpStr(x.host, y.host));
    // Resumable cursor, persisted (survives restarts; shared by all backend instances).
    const cursor = String(rowsOf(await db.query('SELECT sweep_cursor FROM fim_reg_settings WHERE id'))[0]?.sweep_cursor ?? sweepCursor.host ?? '');
    let startIdx = ordered.findIndex((n) => cmpStr(n.host, cursor) > 0);
    if (startIdx < 0) startIdx = 0;
    for (let i = 0; i < ordered.length; i++) {
      const n = ordered[(startIdx + i) % ordered.length];
      if (Date.now() > deadline) { st.timeBoxed = true; break; }
      sweepCursor.host = n.host;
      // Yield to the event loop regularly: a cold sweep resolves many nodes synchronously.
      await maybeYield();
      if (published.has(n.host)) continue;
      st.nodes++;
      const eff = effRows.get(n.host);
      const pol = pols.get(n.host);
      try {
        const key = inputsKeyFor(n, data, t);
        let res: ResolveResult | null = null;
        const resolve = () => { if (!res) { res = resolveFor(n, data, { now: t }); st.resolved++; } return res; };
        let resolvedHash: string;
        let ok: boolean;
        if (eff && eff.inputs_key === key && eff.resolved_hash) {
          st.cached++;
          resolvedHash = eff.resolved_hash;
          ok = eff.status !== 'invalid';
        } else {
          const rr = resolve();
          resolvedHash = rr.hash || 'invalid';
          ok = rr.ok;
        }
        const finalStatus = !ok ? 'invalid' : !pol?.enabled || eff?.published_hash !== resolvedHash ? 'pending' : needsInit.has(n.host) ? 'needs_init' : 'in_sync';
        if (finalStatus === 'invalid') st.invalid++;
        if (finalStatus === 'pending') st.pending++;
        // Write only when something changed (no per-sweep rewrite).
        if (!eff || eff.status !== finalStatus || eff.resolved_hash !== resolvedHash || eff.inputs_key !== key) {
          const rr = resolve();
          await upsertEffective(db, n.host, { policyId: pol ? num(pol.id) : null, ownerGroupId: n.ownerGroupId, resolved: resolvedJson(rr, new Map(), []), resolvedHash, status: finalStatus,
            error: ok ? null : rr.errors.join('; ').slice(0, 4000), inputsKey: key });
          st.writes++;
        }
      } catch (err) {
        st.errors++;
        log?.('FIM registry reconcile failed for node', { err, host: n.host });
      }
    }
    await db.query('UPDATE fim_reg_settings SET sweep_cursor = $1 WHERE id', [st.timeBoxed ? sweepCursor.host : '']);
    await invalidSummaryAlerts(db);
    await checkMeasureDiscrepancies(db);
  }
  // History chain: an incremental (window + tail + anchor + high-water mark) check every sweep and
  // a full re-hash daily. 'broken' (hash/row evidence) alerts at once; 'unverifiable' (anchor store
  // unreachable or lagging) only after it persisted across checks at least 10 minutes apart, and
  // the alert closes itself when verification succeeds again.
  {
    const full = now() - lastDaily.chain >= 86400;
    if (full) lastDaily.chain = now();
    let chain = await verifyHistoryChain(db, { anchor: opts.anchor, fromCache: !full });
    if (!chain.ok && chain.unverifiable && opts.anchorWrite) {
      await flushHistoryAnchors(db, opts.anchorWrite).catch(() => undefined);
      chain = await verifyHistoryChain(db, { anchor: opts.anchor, fromCache: true });
    }
    const UNVERIFIABLE = 'FIM registry history chain cannot be verified (anchor store unreachable or lagging)';
    if (chain.ok) {
      chainState.unverifiableSince = 0;
      await db.query(`UPDATE alerts SET is_open = false, remarks = 'verification succeeded again' WHERE alert_type = 'fim_config' AND is_open AND event_code = $1`, [UNVERIFIABLE]);
    } else if (chain.unverifiable) {
      if (!chainState.unverifiableSince) chainState.unverifiableSince = now();
      else if (now() - chainState.unverifiableSince >= 600) await configAlert(db, null, UNVERIFIABLE, 'high', { reason: chain.reason, since: chainState.unverifiableSince }, true);
    } else {
      await configAlert(db, null, `FIM registry history hash chain BROKEN at row ${chain.brokenAt}: ${chain.reason}`.slice(0, 480), 'critical', { brokenAt: chain.brokenAt, reason: chain.reason }, true);
    }
    if (full) {
      // Daily schema invariant check (also run at boot): alerts, the next boot repairs.
      const inv = await fimSchemaInvariants(db);
      setHealthWarning('schema:invariants', inv.length ? `FIM schema invariants broken: ${inv.join('; ')}`.slice(0, 500) : null);
      if (inv.length) await configAlert(db, null, `FIM schema invariants broken: ${inv.join('; ')}`.slice(0, 480), 'critical', { problems: inv }, true);
      const unbuildable = await listUnbuildablePolicies(db);
      if (unbuildable.length) {
        await configAlert(db, null, `FIM: ${unbuildable.length} policy(ies) contain entries that can no longer be built (republish blocked)`, 'high',
          { policies: unbuildable.slice(0, 50).map((u) => ({ policyId: u.policyId, name: u.name, entries: u.entries.slice(0, 10) })) }, true);
      }
      const div = await rulesDivergence(db);
      if (div.length) await configAlert(db, null, `FIM registry rules differ from the last recorded history snapshot in ${div.length} scope(s)`, 'critical', { scopes: div.slice(0, 50) }, true);
    }
  }
  if (settings.managedEnabled && now() - lastDaily.digest >= 86400) {
    lastDaily.digest = now();
    const stale = rowsOf(await db.query(`SELECT host_identifier FROM fim_reg_effective WHERE status = 'needs_init' AND needs_init_since < $1 ORDER BY host_identifier LIMIT 1000`, [now() - FIM_REG_NEEDS_INIT_DIGEST_SECS]));
    if (stale.length) {
      await configAlert(db, null, `FIM registry: ${stale.length} node(s) still need Initialize after 24 h`, 'medium', { hosts: stale.map((r) => r.host_identifier).slice(0, 200) });
    }
  }
}

/**
 * Live rules vs the latest hash-chained snapshot of each scope: a rule written or changed outside
 * the API (direct SQL) shows up here even though fim_reg_history itself is intact.
 */
export async function rulesDivergence(q: FimQ): Promise<{ scopeType: string; scopeValue: string }[]> {
  const sig = (rules: any[]) => JSON.stringify(rules.map((r) => [Number(r.id), r.op, r.target, canonicalJson(r.spec ?? {}), numOrNull(r.waiverId ?? r.waiver_id ?? null)]).sort((a, b) => Number(a[0]) - Number(b[0])));
  const latest = rowsOf(await q.query(
    `SELECT DISTINCT ON (scope_type, scope_value) scope_type, scope_value, snapshot FROM fim_reg_history
     WHERE scope_type IN ('profile','group','node') ORDER BY scope_type, scope_value, id DESC`));
  const live = new Map<string, any[]>();
  for (const r of rowsOf(await q.query(`SELECT id, layer, scope_value, op, target, spec, waiver_id FROM fim_reg_rules WHERE status = 'active'`))) {
    const k = `${r.layer}\u0000${r.scope_value}`;
    if (!live.has(k)) live.set(k, []);
    live.get(k)!.push(r);
  }
  const out: { scopeType: string; scopeValue: string }[] = [];
  const seen = new Set<string>();
  for (const h of latest) {
    const k = `${h.scope_type}\u0000${h.scope_value}`;
    seen.add(k);
    if (h.snapshot?.deleted) continue;
    if (sig(h.snapshot?.rules ?? []) !== sig(live.get(k) ?? [])) out.push({ scopeType: h.scope_type, scopeValue: h.scope_value });
  }
  for (const k of live.keys()) if (!seen.has(k)) { const [a, b] = k.split('\u0000'); out.push({ scopeType: a, scopeValue: b }); }
  return out;
}

/**
 * After an Initialize of a managed slot, compare what the host really returned with the size the
 * slot was measured at: a much larger baseline means the (agent-reported) measurement understated it.
 */
const measureCheck = { lastInitId: 0 };
async function checkMeasureDiscrepancies(q: FimQ): Promise<void> {
  const rows = rowsOf(await q.query(
    `SELECT r.id, r.host_identifier, r.entry_idx, r.file_count, s.fingerprint, s.entry_key,
            (SELECT max(m.rows_count) FROM fim_reg_measure m WHERE m.fingerprint = s.fingerprint AND m.status = 'done') AS measured
     FROM fim_init_requests r JOIN fim_policies p ON p.id = r.policy_id AND p.managed_kind = 'registry_node'
     JOIN fim_reg_slots s ON s.host_identifier = r.host_identifier AND s.slot_idx = r.entry_idx AND s.retired_at IS NULL
     WHERE r.status = 'done' AND r.id > $1 ORDER BY r.id LIMIT 5000`, [measureCheck.lastInitId]));
  for (const r of rows) {
    measureCheck.lastInitId = Math.max(measureCheck.lastInitId, num(r.id));
    if (r.measured === null || r.measured === undefined || !String(r.entry_key).startsWith('custom:')) continue;
    if (num(r.file_count) > 2 * num(r.measured) + 100) {
      await configAlert(q, r.host_identifier, `FIM registry: ${r.entry_key} returned ${num(r.file_count)} rows at Initialize but was measured at ${num(r.measured)}`, 'medium',
        { host: r.host_identifier, entryKey: r.entry_key, initRows: num(r.file_count), measuredRows: num(r.measured) }, true);
    }
  }
}

/**
 * ONE alert per cause for nodes whose coverage has been invalid for over an hour (not one per
 * node: a bad profile rule must not raise thousands of alerts). The open alert of a cause is
 * updated in place with the current count and examples.
 */
export async function invalidSummaryAlerts(q: FimQ): Promise<void> {
  const groups = rowsOf(await q.query(
    `SELECT left(regexp_replace(COALESCE(error, 'invalid'), '^fail-safe catalog-only coverage published[^;]*; resolution error: ', ''), 300) AS cause,
            count(*)::int AS n, (array_agg(host_identifier ORDER BY host_identifier))[1:20] AS hosts
     FROM fim_reg_effective WHERE status = 'invalid' AND invalid_since IS NOT NULL AND invalid_since < $1 GROUP BY 1 ORDER BY 2 DESC LIMIT 100`,
    [now() - FIM_REG_INVALID_ALERT_SECS]));
  for (const g of groups) {
    const tag = sha256Hex(String(g.cause)).slice(0, 12);
    const code = `FIM registry coverage invalid for over an hour on ${g.n} node(s) (cause ${tag}; fail-safe catalog-only coverage is published where possible)`;
    const meta = { cause: g.cause, causeTag: tag, nodes: num(g.n), examples: g.hosts };
    const upd = rowsOf(await q.query(
      `UPDATE alerts SET event_code = $1, metadata = $2 WHERE alert_type = 'fim_config' AND is_open AND host_identifier IS NULL AND event_code LIKE $3 RETURNING id`,
      [code, JSON.stringify({ fim_config: true, ...meta }), `FIM registry coverage invalid for over an hour on % (cause ${tag}%`]));
    if (!upd.length) await configAlert(q, null, code, 'high', meta);
  }
}

/** Test hook: reset the once-a-day timers. */
export function resetReconcileTimers(): void {
  lastDaily.chain = 0;
  lastDaily.digest = 0;
  chainState.unverifiableSince = 0;
  sweepCursor.host = '';
}

// ---------------------------------------------------------------------------------------------
// Catalog view
// ---------------------------------------------------------------------------------------------

export function catalogView() {
  const items = REG_CATALOG.map((c) => {
    const w = fromCatalog(c);
    return {
      id: c.id, tier: c.tier, optInOnly: c.optInOnly, path: c.path, values: [...c.values], ignoreValues: [...c.ignoreValues], redactValues: [...c.redactValues],
      includeSubkeys: w.includeSubkeys, anchor: true, hiveScoped: w.hiveScoped, label: c.label, category: c.category, severity: c.severity, attack: [...c.attack],
      estimate: w.estimate, noise: c.noise, verified: c.verified, protected: c.protected, realtimeRequired: c.realtimeRequired, notes: c.notes,
    };
  });
  const tiers: Record<string, { entries: number; rows: number; bytes: number }> = {};
  for (const t of REG_TIERS) {
    const es = regTierEntries(t);
    tiers[t] = { entries: es.length, rows: es.reduce((a, c) => a + c.est.rows + c.anchorRows, 0), bytes: es.reduce((a, c) => a + c.est.bytes + anchorBytes(c), 0) };
  }
  return { version: REG_CATALOG_VERSION, items, tiers, limits: regLimits() };
}

export function regLimits() {
  return {
    entryBytesBlock: FIM_REG_CAPS.entryBytesBlock, entryBytesWarn: FIM_REG_CAPS.entryBytesWarn, entryRowsBlock: FIM_REG_CAPS.entryRowsBlock,
    entryRowsWarn: FIM_REG_CAPS.entryRowsWarn, entriesPerNode: FIM_REG_CAPS.entriesPerNode, totalRowsPerNode: FIM_REG_CAPS.totalRowsPerNode,
    pathsMax: FIM_REG_CAPS.pathsMax, rulesPerScope: FIM_REG_CAPS.rulesPerScope, valuesMax: REG_LIMITS.valuesMax, ignoreValuesMax: REG_LIMITS.ignoreValuesMax,
    excludeKeysMax: REG_LIMITS.excludeKeysMax, waiverMaxDays: FIM_REG_CAPS.waiverMaxDays, measurePerHostPer10Min: FIM_REG_CAPS.measurePerHostPer10Min,
    publishBatchMax: FIM_REG_CAPS.publishBatchMax, publishConfirmAbove: FIM_REG_CAPS.publishConfirmAbove,
  };
}
