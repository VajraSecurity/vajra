/**
 * File Integrity Monitoring data access (fleet DB: fim_* tables, config_queries,
 * nodes.config_id). Parameterized SQL only. Contract: docs/FIM_DESIGN.md in the
 * vajra_server repo. Takes a minimal DB interface so it can be driven by a
 * TypeORM DataSource (production) or any equivalent in tests.
 */
import { createHash, randomUUID } from 'crypto';
import {
  FimPolicyInput,
  FimTarget,
  FimOsPlatform,
  buildFimConfig,
  fimConfigOsName,
  fimQueryName,
  pathsChanged,
  buildScanSql,
  escapeLike,
  entryRevKey,
  normalizePaths,
  FimPathEntry,
} from '../utils/fim/fimLogic';
import { FIM_TEMPLATES } from '../utils/fim/fimTemplates';
import { getRegCatalogEntry } from '../utils/fim/fimRegistryCatalog';

export interface FimQ {
  query(sql: string, params?: any[]): Promise<any>;
}
export interface FimDb extends FimQ {
  transaction<T>(fn: (q: FimQ) => Promise<T>): Promise<T>;
}

export class FimNotFoundError extends Error {}
export class FimConflictError extends Error {}
/** Maps to HTTP 400. */
export class FimBadRequestError extends Error {}
/** Approve refused: a real-time registry drift a check scan has not confirmed yet (HTTP 409). */
export class FimUnconfirmedError extends Error {
  constructor(message: string, public ids: number[]) { super(message); }
}
/** Approve refused: the drift changed since the analyst reviewed it (HTTP 409, current values attached). */
export class FimDriftChangedError extends Error {
  constructor(message: string, public current: { id: number; contentHash: string; newSha256: string | null; changeType: string; lastSeenAt: number; newAttrs: unknown }[]) { super(message); }
}
/** Stable JSON (sorted keys) for content hashing. */
function stableJson(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (Array.isArray(v)) return `[${v.map(stableJson).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stableJson((v as any)[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
/**
 * What an analyst approves: the drift's CONTENT (change type, kind, entry, new hash, new
 * attributes). last_seen_at / occurrences are bumped by every rescan of a still-drifted item
 * and are deliberately not part of it, so an unchanged rescan never invalidates a review.
 *
 * SECURITY NOTE: this is an UNKEYED SHA-256 over fields that are returned to every caller who can
 * view the drift, so anyone can recompute it. It is only a TOCTOU (compare-and-swap) guard that
 * makes an approve fail when the drift content changed after it was reviewed. It is NOT a secret,
 * a MAC, a capability token or an integrity proof of the drift row, and must never be used as one;
 * authorization of the approve is enforced separately (host / policy scope in resolveDriftTx).
 */
export function driftContentHash(r: { change_type?: unknown; kind?: unknown; entry_idx?: unknown; new_sha256?: unknown; new_attrs?: unknown }): string {
  let attrs: unknown = r.new_attrs ?? null;
  if (typeof attrs === 'string') { try { attrs = JSON.parse(attrs); } catch { /* keep the string */ } }
  const doc = stableJson({ c: r.change_type ?? null, k: r.kind ?? 'file', e: r.entry_idx === null || r.entry_idx === undefined ? null : Number(r.entry_idx), s: r.new_sha256 ?? null, a: attrs });
  return createHash('sha256').update(doc, 'utf8').digest('hex');
}
/** Seconds between check scans of one host entry (worker uses the same limit). */
export const FIM_VERIFY_MIN_GAP_SECS = 30;
/** Approve refused: drift has no content hash. Maps to HTTP 409. */
export class FimUnverifiedError extends Error {
  constructor(message: string, public ids: number[]) { super(message); }
}

export const FIM_PAGE_SIZE_DEFAULT = 50;
export const FIM_PAGE_SIZE_MAX = 200;
export const FIM_RESOLVE_MAX_IDS = 500;

/** TypeORM returns [rows, affected] for UPDATE/DELETE; plain pg returns rows. */
export function rowsOf(res: any): any[] {
  if (Array.isArray(res) && res.length === 2 && Array.isArray(res[0]) && typeof res[1] === 'number') return res[0];
  return Array.isArray(res) ? res : (res?.rows ?? []);
}

const num = (v: any): number => (v === null || v === undefined ? 0 : Number(v));
const numOrNull = (v: any): number | null => (v === null || v === undefined ? null : Number(v));

export function clampPage(pageRaw: unknown, sizeRaw: unknown): { page: number; pageSize: number; offset: number } {
  const page = Math.max(1, parseInt(String(pageRaw ?? '1'), 10) || 1);
  const pageSize = Math.min(FIM_PAGE_SIZE_MAX, Math.max(1, parseInt(String(sizeRaw ?? FIM_PAGE_SIZE_DEFAULT), 10) || FIM_PAGE_SIZE_DEFAULT));
  return { page, pageSize, offset: (page - 1) * pageSize };
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

const POLICY_SELECT = `
  SELECT p.*,
    COALESCE((SELECT json_agg(json_build_object('type', t.target_type, 'value', t.target_value)
                              ORDER BY t.target_type, t.target_value)
              FROM fim_policy_targets t WHERE t.policy_id = p.id), '[]'::json) AS targets,
    (SELECT count(*) FROM fim_baseline b WHERE b.policy_id = p.id) AS st_baseline,
    (SELECT count(*) FROM fim_drift d WHERE d.policy_id = p.id AND d.status = 'open') AS st_open
  FROM fim_policies p`;

export function mapPolicy(r: any) {
  return {
    id: num(r.id),
    name: r.name,
    description: r.description ?? '',
    osPlatform: r.os_platform as FimOsPlatform,
    paths: r.paths ?? [],
    scanIntervalSecs: num(r.scan_interval_secs),
    realtime: !!r.realtime,
    mode: r.mode,
    learnScans: num(r.learn_scans),
    enabled: !!r.enabled,
    rev: num(r.rev),
    publishedRev: numOrNull(r.published_rev),
    template: r.template ?? null,
    configQueryId: numOrNull(r.config_query_id),
    // 'all' is stored with value '' and presented as '*' (what the client sends).
    targets: ((r.targets ?? []) as FimTarget[]).map((t) => (t.type === 'all' ? { type: t.type, value: '*' } : t)),
    stats: {
      // Filled in by withScopeStats(): in-scope hosts, and how many have a locked baseline.
      hosts: 0,
      hostsBaselined: 0,
      hostsNotBaselined: 0,
      learning: 0, // legacy alias of hostsNotBaselined
      locked: 0, // legacy alias of hostsBaselined
      baselineFiles: num(r.st_baseline),
      openDrift: num(r.st_open),
    },
    /** 'registry_node' = per-node registry coverage policy (managed only through /api/fim/registry). */
    managedKind: (r.managed_kind ?? null) as 'registry_node' | null,
    managedHost: (r.managed_host ?? null) as string | null,
    createdBy: r.created_by ?? null,
    createdAt: r.created_at ? Math.floor(new Date(r.created_at).getTime() / 1000) : 0,
    updatedAt: r.updated_at ? Math.floor(new Date(r.updated_at).getTime() / 1000) : 0,
  };
}

export type FimPolicyView = ReturnType<typeof mapPolicy>;

/**
 * CTE `pscope(policy_id, host_identifier)`: the in-scope hosts of every policy whose id is in $1
 * (NULL = all policies), set-based. Same rule as resolveTargetHosts (platform + 'all' / group /
 * node targets; no targets = no hosts). One join per target type (UNION ALL) instead of an OR join,
 * so node targets use the nodes primary key.
 */
const POLICY_SCOPE_CTE = `
  pt AS (SELECT p.id AS policy_id, p.os_platform, t.target_type, t.target_value
         FROM fim_policies p JOIN fim_policy_targets t ON t.policy_id = p.id
         WHERE ($1::bigint[] IS NULL OR p.id = ANY($1::bigint[]))),
  pscope AS (
    SELECT DISTINCT x.policy_id, x.host_identifier FROM (
      SELECT pt.policy_id, pt.os_platform, n.host_identifier, n.os_platform AS nplat
        FROM pt JOIN nodes n ON pt.target_type = 'node' AND n.host_identifier = pt.target_value
      UNION ALL
      SELECT pt.policy_id, pt.os_platform, n.host_identifier, n.os_platform
        FROM pt JOIN nodes n ON pt.target_type = 'group' AND n.owner_group_id = pt.target_value
      UNION ALL
      SELECT pt.policy_id, pt.os_platform, n.host_identifier, n.os_platform
        FROM pt CROSS JOIN nodes n WHERE pt.target_type = 'all'
    ) x
    WHERE (CASE WHEN x.os_platform = 'windows' THEN lower(COALESCE(x.nplat,'')) = 'windows'
                ELSE lower(COALESCE(x.nplat,'')) NOT IN ('', 'windows', 'darwin') END))`;

/** In-scope / baselined host counts for many policies in ONE query (no per-policy round trips). */
async function scopeStatsFor(q: FimQ, ids: number[] | null): Promise<Map<number, { hosts: number; baselined: number }>> {
  const rows = rowsOf(await q.query(
    `WITH ${POLICY_SCOPE_CTE}
     SELECT s.policy_id, count(*)::int AS hosts, count(*) FILTER (WHERE hs.state = 'locked')::int AS baselined
     FROM pscope s LEFT JOIN fim_host_state hs ON hs.policy_id = s.policy_id AND hs.host_identifier = s.host_identifier
     GROUP BY s.policy_id`, [ids]));
  return new Map(rows.map((r) => [Number(r.policy_id), { hosts: num(r.hosts), baselined: num(r.baselined) }]));
}

function applyScopeStats(pol: FimPolicyView, st: { hosts: number; baselined: number } | undefined): void {
  const hosts = st?.hosts ?? 0;
  const baselined = st?.baselined ?? 0;
  pol.stats.hosts = hosts;
  pol.stats.hostsBaselined = baselined;
  pol.stats.hostsNotBaselined = hosts - baselined;
  pol.stats.locked = baselined;
  pol.stats.learning = hosts - baselined;
}

/** All policies (unpaginated server-side), newest first. Two queries regardless of the policy count. */
export async function fetchAllPolicies(q: FimQ, withStats = true): Promise<FimPolicyView[]> {
  const rows = rowsOf(await q.query(`${POLICY_SELECT} ORDER BY p.id DESC`));
  const views = rows.map(mapPolicy);
  if (withStats && views.length) {
    const st = await scopeStatsFor(q, null);
    for (const v of views) applyScopeStats(v, st.get(v.id));
  }
  return views;
}

export async function fetchPolicy(q: FimQ, id: number, withStats = true): Promise<FimPolicyView | null> {
  const rows = rowsOf(await q.query(`${POLICY_SELECT} WHERE p.id = $1`, [id]));
  if (!rows.length) return null;
  const v = mapPolicy(rows[0]);
  if (withStats) applyScopeStats(v, (await scopeStatsFor(q, [id])).get(id));
  return v;
}

/** Hosts of a policy's scope that have / lack a locked (initialised) baseline. */
export async function baselineCoverage(q: FimQ, pol: FimPolicyView): Promise<{ inScope: string[]; baselined: Set<string> }> {
  const inScope = await resolveTargetHosts(q, pol.osPlatform, pol.targets);
  const locked = rowsOf(await q.query(
    `SELECT host_identifier FROM fim_host_state WHERE policy_id = $1 AND state = 'locked' AND host_identifier = ANY($2::text[])`,
    [pol.id, inScope],
  ));
  return { inScope, baselined: new Set(locked.map((r) => r.host_identifier as string)) };
}

async function replaceTargets(q: FimQ, policyId: number, targets: FimTarget[]): Promise<void> {
  await q.query('DELETE FROM fim_policy_targets WHERE policy_id = $1', [policyId]);
  if (targets.length === 0) return;
  await q.query(
    `INSERT INTO fim_policy_targets (policy_id, target_type, target_value)
     SELECT $1, t.type, t.value FROM unnest($2::text[], $3::text[]) AS t(type, value)`,
    [policyId, targets.map((t) => t.type), targets.map((t) => (t.type === 'all' ? '' : t.value))],
  );
}

function isUniqueViolation(err: any): boolean {
  return err?.code === '23505' || err?.driverError?.code === '23505';
}

// ---------------------------------------------------------------------------
// Transactional audit (fim_audit row written in the SAME transaction as the change)
// ---------------------------------------------------------------------------

/** Who performed a FIM change (fim_audit.actor / user_id / request_id). */
export interface FimAuditActor {
  /** E-mail (or 'system'); null is recorded as 'unknown'. */
  user: string | null;
  /** vajra_users.id; null = unknown / system. */
  userId?: number | null;
  requestId?: string | null;
}

const safeUserId = (v: unknown): number | null => (v !== null && v !== undefined && Number.isSafeInteger(Number(v)) ? Number(v) : null);

/**
 * Inserts the fim_audit row through the caller's transaction handle, so the audit record commits or
 * rolls back together with the change it describes (no fire-and-forget gap).
 */
export async function fimAuditTx(q: FimQ, actor: FimAuditActor | null | undefined, action: string, details: Record<string, unknown>): Promise<void> {
  await q.query(
    `INSERT INTO fim_audit (at, actor, user_id, action, outcome, request_id, details)
     VALUES (extract(epoch FROM now())::bigint, $1, $2, $3, 'success', $4, $5::jsonb)`,
    [actor?.user ?? 'unknown', safeUserId(actor?.userId), action, actor?.requestId ?? null, JSON.stringify(details ?? {})]);
}

export async function createPolicy(db: FimDb, input: FimPolicyInput, createdBy: string | null, auditActor?: FimAuditActor | null): Promise<FimPolicyView> {
  try {
    const id = await db.transaction(async (q) => {
      const rows = rowsOf(await q.query(
        `INSERT INTO fim_policies (name, description, os_platform, paths, scan_interval_secs, realtime, mode, learn_scans, enabled, template, created_by)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
        [input.name, input.description, input.osPlatform, JSON.stringify(input.paths), input.scanIntervalSecs,
          input.realtime, input.mode, input.learnScans, input.enabled, input.template, createdBy],
      ));
      const pid = Number(rows[0].id);
      await replaceTargets(q, pid, input.targets);
      await fimAuditTx(q, auditActor ?? { user: createdBy }, 'FIM_POLICY_CREATE',
        { policyId: pid, name: input.name, osPlatform: input.osPlatform, targets: input.targets.length, entries: input.paths.length, enabled: input.enabled });
      return pid;
    });
    return (await fetchPolicy(db, id))!;
  } catch (err) {
    if (isUniqueViolation(err)) throw new FimConflictError(`A FIM policy named '${input.name}' already exists`);
    throw err;
  }
}

/** Updates a policy; bumps rev in the same UPDATE when paths or os_platform change. */
export async function updatePolicy(db: FimDb, id: number, input: FimPolicyInput, auditActor?: FimAuditActor | null): Promise<FimPolicyView> {
  try {
    await db.transaction(async (q) => {
      const cur = rowsOf(await q.query('SELECT paths, os_platform, managed_kind FROM fim_policies WHERE id = $1 FOR UPDATE', [id]));
      if (!cur.length) throw new FimNotFoundError('FIM policy not found');
      const bump = cur[0].os_platform !== input.osPlatform || pathsChanged(cur[0].paths ?? [], input.paths);
      await q.query(
        `UPDATE fim_policies SET name=$2, description=$3, os_platform=$4, paths=$5::jsonb, scan_interval_secs=$6,
           realtime=$7, mode=$8, learn_scans=$9, enabled=$10, template=$11,
           rev = CASE WHEN $12::boolean THEN rev + 1 ELSE rev END, updated_at = now()
         WHERE id = $1`,
        [id, input.name, input.description, input.osPlatform, JSON.stringify(input.paths), input.scanIntervalSecs,
          input.realtime, input.mode, input.learnScans, input.enabled, input.template, bump],
      );
      await replaceTargets(q, id, input.targets);
      await fimAuditTx(q, auditActor, 'FIM_POLICY_UPDATE',
        { policyId: id, name: input.name, revBumped: bump, enabled: input.enabled, targets: input.targets.length, entries: input.paths.length, managedKind: cur[0].managed_kind ?? null });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw new FimConflictError(`A FIM policy named '${input.name}' already exists`);
    throw err;
  }
  return (await fetchPolicy(db, id))!;
}

// ---------------------------------------------------------------------------
// Publish / unpublish
// ---------------------------------------------------------------------------

/** Host identifiers a policy currently applies to (platform + targets). */
export async function resolveTargetHosts(q: FimQ, platform: FimOsPlatform, targets: FimTarget[]): Promise<string[]> {
  if (targets.length === 0) return [];
  const all = targets.some((t) => t.type === 'all');
  const groups = targets.filter((t) => t.type === 'group').map((t) => t.value);
  const hosts = targets.filter((t) => t.type === 'node').map((t) => t.value);
  const rows = rowsOf(await q.query(
    `SELECT host_identifier FROM nodes
     WHERE (CASE WHEN $1 = 'windows' THEN lower(COALESCE(os_platform,'')) = 'windows'
                 ELSE lower(COALESCE(os_platform,'')) NOT IN ('', 'windows', 'darwin') END)
       AND ($2::boolean OR owner_group_id = ANY($3::text[]) OR host_identifier = ANY($4::text[]))`,
    [platform, all, groups, hosts],
  ));
  return rows.map((r) => r.host_identifier);
}

/**
 * nodes.config_id as a cleaned text[] IN ITS ORIGINAL LIST ORDER. The fleet server merges the
 * config_queries of a node last-writer-wins in list order, so every rewrite of config_id must keep
 * the other ids exactly where they are: WITH ORDINALITY + ORDER BY makes the order a guarantee
 * instead of a property of whatever plan the subquery gets (an anti/merge join may sort).
 * `col` is the (optionally table-qualified) config_id column.
 */
const orderedIds = (col = 'config_id') =>
  `ARRAY(SELECT btrim(t.x) FROM unnest(string_to_array(COALESCE(${col}, ''), ',')) WITH ORDINALITY AS t(x, ord) WHERE btrim(t.x) <> '' ORDER BY t.ord)`;
/** Same as SQL_CLEAN_IDS (membership tests) but order-preserving, for rewrites. */
const SQL_ORDERED_IDS = orderedIds();

async function removeIdFromAllNodes(q: FimQ, id: number): Promise<number> {
  const rows = rowsOf(await q.query(
    `WITH u AS (
       UPDATE nodes SET config_id = array_to_string(array_remove(${SQL_ORDERED_IDS}, $1::text), ',')
       WHERE $1::text = ANY(${SQL_ORDERED_IDS}) RETURNING 1)
     SELECT count(*)::int AS n FROM u`,
    [String(id)],
  ));
  return num(rows[0]?.n);
}

export interface PublishResult {
  published: boolean;
  configQueryId: number | null;
  nodesAdded: number;
  nodesRemoved: number;
  nodesInScope: number;
  /** Alias of nodesInScope (frontend contract). */
  hostsInScope: number;
}

export async function publishPolicy(db: FimDb, id: number, auditActor?: FimAuditActor | null, auditExtra?: Record<string, unknown>): Promise<PublishResult> {
  return db.transaction(async (q) => {
    const r = await publishPolicyTx(q, id);
    // Registry-managed policies are published through publishPolicyTx inside the registry
    // service's own (audited) transactions; this wrapper is the plain-policy path.
    const name = rowsOf(await q.query('SELECT name FROM fim_policies WHERE id = $1', [id]))[0]?.name ?? null;
    await fimAuditTx(q, auditActor, 'FIM_POLICY_PUBLISH', { policyId: id, name, ...(auditExtra ?? {}), ...r });
    return r;
  });
}

/** Transaction body of publishPolicy (the registry service publishes inside its own transaction). */
export async function publishPolicyTx(q: FimQ, id: number): Promise<PublishResult> {
  {
    const locked = rowsOf(await q.query('SELECT id FROM fim_policies WHERE id = $1 FOR UPDATE', [id]));
    if (!locked.length) throw new FimNotFoundError('FIM policy not found');
    const pol = (await fetchPolicy(q, id, false))!;

    if (!pol.enabled) {
      const removed = pol.configQueryId ? await removeIdFromAllNodes(q, pol.configQueryId) : 0;
      if (pol.configQueryId) {
        await q.query('DELETE FROM config_queries WHERE id = $1', [pol.configQueryId]);
        await q.query('UPDATE fim_policies SET config_query_id = NULL, published_rev = NULL WHERE id = $1', [id]);
      }
      return { published: false, configQueryId: null, nodesAdded: 0, nodesRemoved: removed, nodesInScope: 0, hostsInScope: 0 };
    }

    const cfg = JSON.stringify(buildFimConfig({
      id: pol.id, rev: pol.rev, osPlatform: pol.osPlatform, paths: pol.paths,
      scanIntervalSecs: pol.scanIntervalSecs, realtime: pol.realtime,
    }));
    const qname = fimQueryName(pol.name);
    const osName = fimConfigOsName(pol.osPlatform);

    let cqId: number | null = null;
    if (pol.configQueryId) {
      const upd = rowsOf(await q.query(
        `UPDATE config_queries SET query = $2, query_name = $3, os_name = $4, kernel_version = '', os_arch = ''
         WHERE id = $1 RETURNING id`,
        [pol.configQueryId, cfg, qname, osName],
      ));
      if (upd.length) cqId = pol.configQueryId;
    }
    if (cqId === null) {
      const ins = rowsOf(await q.query(
        `INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch)
         VALUES ($1, $2, $3, '', '') RETURNING id`,
        [cfg, qname, osName],
      ));
      cqId = Number(ins[0].id);
    }
    await q.query('UPDATE fim_policies SET config_query_id = $2, published_rev = $3 WHERE id = $1', [id, cqId, pol.rev]);

    const rec = await reconcileNodes(q, pol, cqId);
    return { published: true, configQueryId: cqId, nodesAdded: rec.added, nodesRemoved: rec.removed, nodesInScope: rec.inScope, hostsInScope: rec.inScope };
  }
}

/**
 * Makes nodes.config_id match the policy scope: adds the config_queries id to
 * in-scope nodes, removes it from all others. Touches only this policy's own id.
 */
async function reconcileNodes(q: FimQ, pol: FimPolicyView, cqId: number): Promise<{ added: number; removed: number; inScope: number }> {
  const desired = await resolveTargetHosts(q, pol.osPlatform, pol.targets);
  // Our id is appended at the END; other ids keep their exact order (last-writer-wins merge).
  const added = rowsOf(await q.query(
    `WITH u AS (
       UPDATE nodes SET config_id = array_to_string(array_append(${SQL_ORDERED_IDS}, $1::text), ',')
       WHERE host_identifier = ANY($2::text[]) AND NOT ($1::text = ANY(${SQL_ORDERED_IDS})) RETURNING 1)
     SELECT count(*)::int AS n FROM u`,
    [String(cqId), desired],
  ));
  const removed = rowsOf(await q.query(
    `WITH u AS (
       UPDATE nodes SET config_id = array_to_string(array_remove(${SQL_ORDERED_IDS}, $1::text), ',')
       WHERE $1::text = ANY(${SQL_ORDERED_IDS}) AND NOT (host_identifier = ANY($2::text[])) RETURNING 1)
     SELECT count(*)::int AS n FROM u`,
    [String(cqId), desired],
  ));
  return { added: num(added[0]?.n), removed: num(removed[0]?.n), inScope: desired.length };
}

/**
 * Re-applies the scope reconcile for every enabled, published policy so nodes that
 * enrolled later, joined a target group, or re-enrolled (the server resets
 * nodes.config_id to its default list) pick up the FIM config id. Idempotent; one
 * transaction per policy; a failing policy is skipped and does not stop the rest.
 */
export async function reconcileAllPublishedPolicies(
  db: FimDb, onError?: (err: unknown, policyId: number) => void,
): Promise<{ policies: number; added: number; removed: number }> {
  // Managed per-node registry policies (one per Windows node) are reconciled set-based below:
  // looping them through the generic per-policy path is O(policies x nodes).
  const ids = rowsOf(await db.query(
    `SELECT id FROM fim_policies WHERE enabled AND config_query_id IS NOT NULL AND managed_kind IS NULL ORDER BY id`,
  )).map((r) => Number(r.id));
  const total = { policies: 0, added: 0, removed: 0 };
  try {
    const m = await reconcileManagedNodes(db);
    total.added += m.added; total.removed += m.removed; total.policies += m.policies;
  } catch (err) {
    onError?.(err, 0);
  }
  for (const id of ids) {
    try {
      const r = await db.transaction(async (q) => {
        const lk = rowsOf(await q.query('SELECT id FROM fim_policies WHERE id = $1 FOR UPDATE', [id]));
        if (!lk.length) return null;
        const pol = await fetchPolicy(q, id, false);
        if (!pol || !pol.enabled || !pol.configQueryId) return null;
        const exists = rowsOf(await q.query('SELECT 1 AS x FROM config_queries WHERE id = $1', [pol.configQueryId]));
        if (!exists.length) return null; // row gone: never reference a missing config id
        return reconcileNodes(q, pol, pol.configQueryId);
      });
      if (r) { total.policies++; total.added += r.added; total.removed += r.removed; }
    } catch (err) {
      onError?.(err, id);
    }
  }
  return total;
}

/**
 * Set-based reconcile of all managed registry policies (each targets exactly its own host):
 * add the policy's config id to its host where missing, and strip managed config ids from every
 * node that is not their host. Two statements regardless of fleet size.
 */
export async function reconcileManagedNodes(db: FimQ): Promise<{ policies: number; added: number; removed: number }> {
  // Order of a node's OTHER config ids is preserved exactly (WITH ORDINALITY ... ORDER BY ord):
  // the managed id is appended at the end, and stripping keeps the survivors in list order.
  const added = rowsOf(await db.query(
    `WITH u AS (
       UPDATE nodes n SET config_id = array_to_string(array_append(${orderedIds('n.config_id')}, p.config_query_id::text), ',')
       FROM fim_policies p
       WHERE p.managed_kind = 'registry_node' AND p.enabled AND p.config_query_id IS NOT NULL AND n.host_identifier = p.managed_host
         AND NOT (p.config_query_id::text = ANY(${orderedIds('n.config_id')}))
       RETURNING 1)
     SELECT count(*)::int AS n FROM u`));
  const removed = rowsOf(await db.query(
    `WITH m AS (SELECT config_query_id::text AS cid, managed_host FROM fim_policies WHERE managed_kind = 'registry_node' AND config_query_id IS NOT NULL),
     bad AS (
       SELECT n.host_identifier, array_to_string(ARRAY(
                SELECT btrim(t.x) FROM unnest(string_to_array(COALESCE(n.config_id, ''), ',')) WITH ORDINALITY AS t(x, ord)
                WHERE btrim(t.x) <> '' AND NOT EXISTS (SELECT 1 FROM m WHERE m.cid = btrim(t.x) AND m.managed_host <> n.host_identifier)
                ORDER BY t.ord), ',') AS cleaned
       FROM nodes n
       WHERE EXISTS (SELECT 1 FROM unnest(string_to_array(COALESCE(n.config_id, ''), ',')) AS x JOIN m ON m.cid = btrim(x) AND m.managed_host <> n.host_identifier)),
     u AS (UPDATE nodes n SET config_id = bad.cleaned FROM bad WHERE n.host_identifier = bad.host_identifier RETURNING 1)
     SELECT count(*)::int AS n FROM u`));
  const pols = num(rowsOf(await db.query(`SELECT count(*)::int AS n FROM fim_policies WHERE managed_kind = 'registry_node' AND enabled AND config_query_id IS NOT NULL`))[0]?.n);
  return { policies: pols, added: num(added[0]?.n), removed: num(removed[0]?.n) };
}

/** True when the edit changes what gets published (config JSON, scope, name, enabled). */
export function affectsPublishedConfig(a: FimPolicyView, b: FimPolicyView): boolean {
  const k = (p: FimPolicyView) => JSON.stringify([
    p.name, p.enabled, p.osPlatform, (p.paths as FimPathEntry[]).map(entryRevKey), p.scanIntervalSecs, p.realtime,
    [...p.targets].map((t) => `${t.type}:${t.value}`).sort(),
  ]);
  return k(a) !== k(b);
}


// ---------------------------------------------------------------------------
// Baseline initialisation (Tripwire --init equivalent)
// ---------------------------------------------------------------------------

export const FIM_INIT_MAX_HOSTS = 5000;
export interface InitializeOpts {
  hosts?: string[] | null;
  note: string | null;
  requestedBy: string | null;
  /** vajra_users.id of the requester (oversight alerts name it as byUserId; audit user_id). */
  requestedByUserId?: number | null;
  /** Hosts the caller may administer; null = unrestricted. */
  visibleHosts?: string[] | null;
  /** Initialise only these entry indices (slots), e.g. the new slots after an Apply. Default: all. */
  entries?: number[] | null;
  /** Managed registry policies: re-initialising slots with open CRITICAL drift needs force (alerted). */
  force?: boolean;
}
export interface InitializeResult {
  batchId: string | null;
  hosts: number;
  requests: number;
  skipped: { hostIdentifier: string; reason: 'out-of-scope' }[];
  /** Pending requests of the same hosts that this call replaced. */
  superseded: number;
}

/**
 * Queues one immediate distributed scan query per (in-scope host, path entry) and a
 * matching fim_init_requests row. The worker consumes the answers; this never touches
 * fim_baseline or fim_host_state.
 */
export async function initializeBaselineTx(q: FimQ, policyId: number, opts: InitializeOpts): Promise<InitializeResult> {
  const system = opts.requestedBy === 'system';
  if (!system && !(opts.note && opts.note.trim())) throw new FimBadRequestError('A note is required to initialize baselines');
  const locked = rowsOf(await q.query('SELECT id FROM fim_policies WHERE id = $1 FOR UPDATE', [policyId]));
  if (!locked.length) throw new FimNotFoundError('FIM policy not found');
  const pol = (await fetchPolicy(q, policyId, false))!;
  if (!pol.enabled) throw new FimBadRequestError('The policy is disabled; enable it before initializing baselines');

  const scope = new Set(await resolveTargetHosts(q, pol.osPlatform, pol.targets));
  const skipped: InitializeResult['skipped'] = [];
  let hosts: string[];
  if (opts.hosts && opts.hosts.length) {
    hosts = [];
    for (const h of new Set(opts.hosts)) {
      if (scope.has(h)) hosts.push(h);
      else skipped.push({ hostIdentifier: h, reason: 'out-of-scope' });
    }
  } else {
    hosts = Array.from(scope);
  }
  if (opts.visibleHosts) {
    const allowed = new Set(opts.visibleHosts);
    hosts = hosts.filter((h) => allowed.has(h));
    // hosts the caller may not administer are silently dropped (the controller 403s explicit ones)
  }
  if (hosts.length > FIM_INIT_MAX_HOSTS) throw new FimBadRequestError(`At most ${FIM_INIT_MAX_HOSTS} hosts per call; select fewer hosts`);
  if (hosts.length === 0) return { batchId: null, hosts: 0, requests: 0, skipped, superseded: 0 };

  // Entries to initialise: all live entries, or the requested subset. Tombstone (retired) slots
  // of managed policies are never scanned.
  const paths = pol.paths as FimPathEntry[];
  const live = paths.map((e, k) => (e.retired ? -1 : k)).filter((k) => k >= 0);
  let entries = live;
  if (opts.entries && opts.entries.length) {
    const want = new Set(opts.entries);
    for (const k of want) {
      if (!Number.isInteger(k) || k < 0 || k >= paths.length) throw new FimBadRequestError(`entry ${k} does not exist in this policy`);
      if (paths[k].retired) throw new FimBadRequestError(`entry ${k} is a retired slot and cannot be initialised`);
    }
    entries = live.filter((k) => want.has(k));
  }
  if (entries.length === 0) throw new FimBadRequestError('The policy has no entries to initialise');

  // Re-initialising adopts whatever is on the host now, and supersedes open drift of those slots.
  // On managed registry policies, slots with open CRITICAL drift need an explicit force (and raise
  // an alert) so a re-init can never quietly erase evidence (FIM_REGISTRY_DESIGN §4.5).
  if (pol.managedKind === 'registry_node') {
    const crit = rowsOf(await q.query(
      `SELECT host_identifier, entry_idx, count(*)::int AS n FROM fim_drift
       WHERE policy_id = $1 AND status = 'open' AND severity = 'critical' AND host_identifier = ANY($2::text[])
         AND entry_idx = ANY($3::int[]) GROUP BY host_identifier, entry_idx`,
      [policyId, hosts, entries],
    ));
    if (crit.length && !opts.force) {
      throw new FimConflictError(`${crit.reduce((a, r) => a + num(r.n), 0)} open critical drift(s) on the selected slots would be superseded; review them first or resend with force=true (an alert is raised)`);
    }
    if (crit.length) {
      await q.query(
        `INSERT INTO alerts (host_identifier, hostname, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, os_name, detection_time)
         SELECT c.h, n.hostname, extract(epoch FROM now())::bigint, 'FIM registry slot re-initialised with open critical drift [' || $2 || ']',
                $3, true, true, 'high', 'fim_config', 'File Integrity', '', '', n.os_platform, extract(epoch FROM now())::bigint
         FROM unnest($1::text[]) AS c(h) LEFT JOIN nodes n ON n.host_identifier = c.h`,
        [[...new Set(crit.map((r) => r.host_identifier as string))], pol.name,
          JSON.stringify({ fim_config: 'forced_reinit', policy_id: policyId, by: opts.requestedBy, byUserId: safeUserId(opts.requestedByUserId), note: opts.note, slots: crit.map((r) => ({ host: r.host_identifier, entry: num(r.entry_idx), open: num(r.n) })) })],
      );
    }
  }

  // A newer request supersedes any pending one for the same policy+host: mark the old
  // rows expired and drop their still-unsent queue entries so the agent only answers
  // the newest scan.
  // Only requests for the SAME entries are superseded: initialising slot 7 must not cancel a
  // pending Initialize of slot 3 on the same host.
  const old = rowsOf(await q.query(
    `UPDATE fim_init_requests SET status = 'expired', error = 'superseded by a newer request',
       completed_at = extract(epoch FROM now())::bigint
     WHERE policy_id = $1 AND status = 'pending' AND host_identifier = ANY($2::text[]) AND entry_idx = ANY($3::int[])
     RETURNING queue_id`,
    [policyId, hosts, entries],
  ));
  const oldQueue = old.map((r) => r.queue_id).filter((x) => x !== null && x !== undefined).map(Number);
  if (oldQueue.length) await q.query('DELETE FROM query_queue WHERE id = ANY($1::bigint[]) AND sent = false', [oldQueue]);

  const batchId = randomUUID();
  const now = Math.floor(Date.now() / 1000);
  let requests = 0;
  for (const k of entries) {
    const sql = buildScanSql(pol.paths[k], pol.osPlatform);
    const ins = rowsOf(await q.query(
      `INSERT INTO query_queue (host_identifier, query, sent, send_time)
       SELECT h, $2, false, 0 FROM unnest($1::text[]) AS h RETURNING id, host_identifier`,
      [hosts, sql],
    ));
    await q.query(
      `INSERT INTO fim_init_requests (batch_id, policy_id, host_identifier, entry_idx, rev, queue_id, after_result_id, status, requested_by, note, created_at)
       SELECT $1, $2, t.h, $3, $4, t.qid, (SELECT COALESCE(max(id), 0) FROM query_result), 'pending', $5, $6, $7
       FROM unnest($8::text[], $9::bigint[]) AS t(h, qid)`,
      [batchId, policyId, k, pol.rev, opts.requestedBy, opts.note ?? null, now, ins.map((r) => r.host_identifier), ins.map((r) => Number(r.id))],
    );
    requests += ins.length;
  }
  await q.query(
    `INSERT INTO fim_audit (at, actor, user_id, action, details) VALUES (extract(epoch FROM now())::bigint, $1, $3, 'FIM_BASELINE_INIT', $2::jsonb)`,
    [opts.requestedBy ?? 'unknown', JSON.stringify({ policyId, batchId, hosts, entries, note: opts.note, force: !!opts.force, superseded: old.length }), safeUserId(opts.requestedByUserId)]);
  return { batchId, hosts: hosts.length, requests, skipped, superseded: old.length };
}

export async function initializeBaseline(db: FimDb, policyId: number, opts: InitializeOpts): Promise<InitializeResult> {
  return db.transaction((q) => initializeBaselineTx(q, policyId, opts));
}

// ---------------------------------------------------------------------------
// Initialization status + baseline versions
// ---------------------------------------------------------------------------

export type InitHostStatus = 'none' | 'pending' | 'partial' | 'done' | 'failed';

export async function getInitialization(
  q: FimQ, policyId: number, hostFilter: string[] | null,
  f: { status?: string; q?: string }, page: number, pageSize: number,
) {
  const pol = await fetchPolicy(q, policyId);
  if (!pol) throw new FimNotFoundError('FIM policy not found');
  let scope = await resolveTargetHosts(q, pol.osPlatform, pol.targets);
  if (hostFilter) { const a = new Set(hostFilter); scope = scope.filter((h) => a.has(h)); }
  const cte = `
    WITH h AS (SELECT n.host_identifier, n.hostname FROM nodes n WHERE n.host_identifier = ANY($2::text[])),
    lb AS (SELECT DISTINCT ON (host_identifier) host_identifier, batch_id FROM fim_init_requests
           WHERE policy_id = $1 AND host_identifier = ANY($2::text[])
           ORDER BY host_identifier, created_at DESC, id DESC),
    c AS (SELECT r.host_identifier,
                 count(*) FILTER (WHERE r.status = 'done')::int AS done,
                 count(*) FILTER (WHERE r.status = 'pending')::int AS pending,
                 count(*) FILTER (WHERE r.status = 'failed')::int AS failed,
                 count(*) FILTER (WHERE r.status = 'expired')::int AS expired,
                 max(r.created_at) AS last_init
          FROM fim_init_requests r JOIN lb ON lb.host_identifier = r.host_identifier AND lb.batch_id = r.batch_id
          WHERE r.policy_id = $1 GROUP BY r.host_identifier),
    v AS (SELECT host_identifier, max(version) AS ver FROM fim_baseline_version WHERE policy_id = $1 GROUP BY host_identifier),
    x AS (SELECT h.host_identifier, h.hostname, COALESCE(c.done,0) AS done, COALESCE(c.pending,0) AS pending,
                 COALESCE(c.failed,0) AS failed, COALESCE(c.expired,0) AS expired, c.last_init, v.ver,
                 CASE WHEN c.host_identifier IS NULL THEN 'none'
                      WHEN c.done > 0 AND c.pending = 0 AND c.failed = 0 AND c.expired = 0 THEN 'done'
                      WHEN c.done > 0 THEN 'partial'
                      WHEN c.pending > 0 THEN 'pending'
                      ELSE 'failed' END AS status
          FROM h LEFT JOIN c ON c.host_identifier = h.host_identifier LEFT JOIN v ON v.host_identifier = h.host_identifier)`;
  const like = f.q ? `%${escapeLike(f.q)}%` : null;
  const tot = rowsOf(await q.query(`${cte} SELECT status, count(*)::int AS n FROM x
      WHERE ($3::text IS NULL OR host_identifier ILIKE $3 ESCAPE '\\' OR COALESCE(hostname,'') ILIKE $3 ESCAPE '\\') GROUP BY status`, [policyId, scope, like]));
  const totals = { none: 0, pending: 0, done: 0, partial: 0, failed: 0 } as Record<string, number>;
  for (const r of tot) totals[r.status] = num(r.n);
  const where = `WHERE ($3::text IS NULL OR host_identifier ILIKE $3 ESCAPE '\\' OR COALESCE(hostname,'') ILIKE $3 ESCAPE '\\') AND ($4::text IS NULL OR status = $4)`;
  const total = num(rowsOf(await q.query(`${cte} SELECT count(*) AS n FROM x ${where}`, [policyId, scope, like, f.status || null]))[0]?.n);
  const rows = rowsOf(await q.query(`${cte} SELECT * FROM x ${where} ORDER BY host_identifier LIMIT $5 OFFSET $6`,
    [policyId, scope, like, f.status || null, pageSize, (page - 1) * pageSize]));
  const hostsOut = rows.map((r) => ({
      hostIdentifier: r.host_identifier,
      hostname: r.hostname ?? null,
      status: r.status as InitHostStatus,
      entries: { done: num(r.done), pending: num(r.pending), failed: num(r.failed), expired: num(r.expired) },
      lastInitAt: numOrNull(r.last_init),
      latestVersion: numOrNull(r.ver),
  }));
  const lockedRows = rowsOf(await q.query(
    `SELECT host_identifier FROM fim_host_state WHERE policy_id = $1 AND state = 'locked' AND host_identifier = ANY($2::text[])`, [policyId, scope]));
  const hostsBaselined = lockedRows.length;
  return { totals, hosts: hostsOut, items: hostsOut, total, page, pageSize, hostsBaselined, hostsNotBaselined: scope.length - hostsBaselined };
}

export async function listBaselineVersions(
  q: FimQ, f: { policy?: number | null; host?: string }, hostFilter: string[] | null, page: number, pageSize: number,
) {
  const where = `WHERE ($1::bigint IS NULL OR v.policy_id = $1) AND ($2::text IS NULL OR v.host_identifier = $2)
      AND ($3::text[] IS NULL OR v.host_identifier = ANY($3))`;
  const params = [f.policy ?? null, f.host || null, hostFilter];
  const total = num(rowsOf(await q.query(`SELECT count(*) AS n FROM fim_baseline_version v ${where}`, params))[0]?.n);
  const rows = rowsOf(await q.query(
    `SELECT v.*, p.name AS policy_name, n.hostname FROM fim_baseline_version v
     JOIN fim_policies p ON p.id = v.policy_id LEFT JOIN nodes n ON n.host_identifier = v.host_identifier
     ${where} ORDER BY v.created_at DESC, v.id DESC LIMIT $4 OFFSET $5`,
    [...params, pageSize, (page - 1) * pageSize],
  ));
  return {
    items: rows.map((r) => ({
      policyId: num(r.policy_id), policyName: r.policy_name, hostIdentifier: r.host_identifier, hostname: r.hostname ?? null,
      version: num(r.version), reason: r.reason, createdBy: r.created_by ?? null, note: r.note ?? null,
      createdAt: num(r.created_at), fileCount: num(r.file_count), digest: r.digest,
    })),
    total, page, pageSize,
  };
}

export async function deletePolicy(db: FimDb, id: number, auditActor?: FimAuditActor | null): Promise<{ name: string }> {
  return db.transaction(async (q) => {
    const rows = rowsOf(await q.query('SELECT name, config_query_id, managed_kind FROM fim_policies WHERE id = $1 FOR UPDATE', [id]));
    if (!rows.length) throw new FimNotFoundError('FIM policy not found');
    let nodesRemoved = 0;
    if (rows[0].config_query_id) {
      const cq = Number(rows[0].config_query_id);
      nodesRemoved = await removeIdFromAllNodes(q, cq);
      await q.query('DELETE FROM config_queries WHERE id = $1', [cq]);
    }
    // baseline/host_state/host_entry/targets cascade; fim_drift is audit evidence and has
    // no FK, so it survives (rows carry policy_name).
    await q.query('DELETE FROM fim_policies WHERE id = $1', [id]);
    await fimAuditTx(q, auditActor, 'FIM_POLICY_DELETE',
      { policyId: id, name: rows[0].name, configQueryId: numOrNull(rows[0].config_query_id), nodesRemoved, managedKind: rows[0].managed_kind ?? null });
    return { name: rows[0].name };
  });
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

export function mapDrift(r: any) {
  return {
    id: num(r.id),
    policyId: num(r.policy_id),
    policyName: r.policy_name ?? null,
    policyDeleted: !!r.policy_deleted,
    hostIdentifier: r.host_identifier,
    hostname: r.hostname ?? null,
    path: r.path,
    kind: (r.kind ?? 'file') as 'file' | 'directory' | 'item',
    entryIdx: numOrNull(r.entry_idx),
    changeType: r.change_type,
    source: r.source,
    severity: r.severity,
    oldSha256: r.old_sha256 ?? null,
    newSha256: r.new_sha256 ?? null,
    oldAttrs: r.old_attrs ?? null,
    newAttrs: r.new_attrs ?? null,
    actorProcess: r.actor_process ?? null,
    actorUser: r.actor_user ?? null,
    status: r.status,
    occurrences: num(r.occurrences),
    detectedAt: num(r.detected_at),
    lastSeenAt: num(r.last_seen_at),
    resolvedBy: r.resolved_by ?? null,
    resolvedAt: numOrNull(r.resolved_at),
    note: r.note ?? null,
    /** Registry check scan (migration 0006): value back to baseline after a real-time change. */
    reverted: !!r.reverted,
    confirmedAt: numOrNull(r.confirmed_at),
    /** Send back as expected[id].contentHash when approving (content-only review guard). */
    contentHash: driftContentHash(r),
  };
}

const DRIFT_SELECT = `SELECT d.*, COALESCE(d.policy_name, p.name) AS policy_name, (p.id IS NULL) AS policy_deleted
  FROM fim_drift d LEFT JOIN fim_policies p ON p.id = d.policy_id`;

export interface DriftFilters {
  status?: string; severity?: string; host?: string; policy?: number | null; q?: string;
}

export async function listDrift(q: FimQ, f: DriftFilters, hostFilter: string[] | null, page: number, pageSize: number) {
  const where = `WHERE ($1::text IS NULL OR d.status = $1)
      AND ($2::text IS NULL OR d.severity = $2)
      AND ($3::text IS NULL OR d.host_identifier = $3 OR lower(COALESCE(d.hostname,'')) = lower($3))
      AND ($4::bigint IS NULL OR d.policy_id = $4)
      AND ($5::text IS NULL OR d.path ILIKE $5 ESCAPE '\\' OR COALESCE(d.hostname,'') ILIKE $5 ESCAPE '\\')
      AND ($6::text[] IS NULL OR d.host_identifier = ANY($6))`;
  const params = [
    f.status || null, f.severity || null, f.host || null, f.policy ?? null,
    f.q ? `%${escapeLike(f.q)}%` : null, hostFilter,
  ];
  const total = num(rowsOf(await q.query(`SELECT count(*) AS n FROM fim_drift d ${where}`, params))[0]?.n);
  const rows = rowsOf(await q.query(
    `${DRIFT_SELECT} ${where} ORDER BY d.detected_at DESC, d.id DESC LIMIT $7 OFFSET $8`,
    [...params, pageSize, (page - 1) * pageSize],
  ));
  return { items: rows.map(mapDrift), total, page, pageSize };
}

export async function getDrift(q: FimQ, id: number, hostFilter: string[] | null) {
  const rows = rowsOf(await q.query(
    `${DRIFT_SELECT} WHERE d.id = $1 AND ($2::text[] IS NULL OR d.host_identifier = ANY($2))`, [id, hostFilter]));
  return rows.length ? mapDrift(rows[0]) : null;
}

/** drift_id embedded in alerts.metadata (TEXT, possibly legacy/non-JSON): regex only, never a JSON cast. */
const META_DRIFT_ID = `NULLIF(substring(a.metadata from '"drift_id"\\s*:\\s*"?([0-9]{1,15})'), '')::bigint`;

export type ResolveAction = 'approve' | 'reject' | 'ignore';

/**
 * Resolves open drift rows in one transaction. Only status='open' rows (and, for
 * scoped callers, rows on hosts in `hostFilter`) are touched.
 */
/** The reviewed content of a drift (driftContentHash of the row the analyst saw). */
export interface ExpectedDrift { contentHash: string }
export type ResolveOutcome = 'resolved' | 'drift_changed' | 'awaiting_confirmation' | 'skipped';
export interface ResolveItemResult {
  id: number; outcome: ResolveOutcome;
  current?: { contentHash: string; newSha256: string | null; changeType: string; lastSeenAt: number };
}
export interface ResolveOpts {
  acceptUnverified?: boolean;
  /** approve: the values the analyst reviewed, per drift id (mandatory). */
  expected?: Record<string, ExpectedDrift> | null;
  /**
   * approve: all-or-nothing. Default for one id; for several ids the default is per item
   * (changed / unconfirmed items are left open and reported in `results`).
   */
  atomic?: boolean;
  /** vajra_users.id of the resolver (oversight alerts name it as byUserId; audit user_id). */
  actorUserId?: number | null;
}

export async function resolveDrift(
  db: FimDb, ids: number[], action: ResolveAction, user: string | null, note: string | null, hostFilter: string[] | null, policyFilter: number[] | null = null,
  opts: ResolveOpts = {},
): Promise<{ resolved: number; skipped: number; ids: number[]; results: ResolveItemResult[] }> {
  return db.transaction((q) => resolveDriftTx(q, ids, action, user, note, hostFilter, policyFilter, opts));
}

/** Transaction body of resolveDrift (also used when closing alerts). Closes linked alerts. */
export async function resolveDriftTx(
  q: FimQ, ids: number[], action: ResolveAction, user: string | null, note: string | null, hostFilter: string[] | null, policyFilter: number[] | null = null,
  opts: ResolveOpts = {},
): Promise<{ resolved: number; skipped: number; ids: number[]; results: ResolveItemResult[] }> {
  const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'ignored';
  {
    // Drift of a deleted policy is read-only except 'ignore' (no baseline to act on).
    let cand = rowsOf(await q.query(
      `SELECT d.id, d.change_type, d.kind, d.new_sha256 IS NULL AS nohash, d.new_sha256, d.last_seen_at, d.new_attrs, d.source, d.path,
              d.confirmed_at, d.severity, d.policy_id, d.entry_idx FROM fim_drift d
       WHERE d.id = ANY($1::bigint[]) AND d.status = 'open' AND ($2::text[] IS NULL OR d.host_identifier = ANY($2))
         AND ($3::bigint[] IS NULL OR d.policy_id = ANY($3))
         AND ($4::text = 'ignore' OR EXISTS (SELECT 1 FROM fim_policies p WHERE p.id = d.policy_id))
       FOR UPDATE OF d`,
      [ids, hostFilter, policyFilter, action],
    ));
    const refused = new Map<number, ResolveItemResult>();
    if (action === 'approve') {
      const atomic = opts.atomic === true || ids.length === 1;
      // 1. Real-time registry drift carries the EVENT's format; only a check scan's (osquery format)
      //    values may enter the baseline, otherwise the next scan raises 'modified' forever.
      const unconfirmed = cand.filter((r) => r.source === 'realtime' && r.kind === 'item' && String(r.path).startsWith('registry|') && (r.confirmed_at === null || r.confirmed_at === undefined)).map((r) => Number(r.id));
      if (unconfirmed.length && atomic) {
        throw new FimUnconfirmedError(`Awaiting confirmation scan: ${unconfirmed.length} real-time registry change(s) have not been confirmed by a check scan yet (requested automatically; usually within a minute). Reject or ignore is possible now; approve after confirmation.`, unconfirmed);
      }
      for (const id of unconfirmed) refused.set(id, { id, outcome: 'awaiting_confirmation' });
      // 2. TOCTOU: approve exactly the CONTENT that was reviewed (rescans that only bump
      //    last_seen_at / occurrences do not count as a change).
      const exp = opts.expected ?? {};
      const missing = cand.filter((r) => !exp[String(r.id)] || typeof exp[String(r.id)].contentHash !== 'string').map((r) => Number(r.id));
      if (missing.length) throw new FimBadRequestError(`expected values (contentHash of the reviewed drift) are required to approve drift ${missing.slice(0, 20).join(', ')}`);
      const changed = cand.filter((r) => !refused.has(Number(r.id)) && driftContentHash(r) !== exp[String(r.id)].contentHash);
      const current = (r: any) => ({ contentHash: driftContentHash(r), newSha256: r.new_sha256 ?? null, changeType: r.change_type, lastSeenAt: Number(r.last_seen_at) });
      if (changed.length && atomic) {
        throw new FimDriftChangedError(`The drift changed since it was reviewed (${changed.length} item(s)); review the new values before approving.`,
          changed.map((r) => ({ id: Number(r.id), ...current(r), newAttrs: r.new_attrs ?? null })));
      }
      for (const r of changed) refused.set(Number(r.id), { id: Number(r.id), outcome: 'drift_changed', current: current(r) });
      cand = cand.filter((r) => !refused.has(Number(r.id)));
    }
    if (action === 'approve' && !opts.acceptUnverified) {
      // Only regular files are expected to carry a content hash: directories have none by
      // design and item kinds hash their observed columns.
      const bad = cand.filter((r) => r.change_type !== 'removed' && r.nohash && (r.kind ?? 'file') === 'file').map((r) => Number(r.id));
      if (bad.length) {
        throw new FimUnverifiedError(
          `${bad.length} selected change(s) have no content hash; approving would make the next scan trust whatever is on disk. Resend with acceptUnverified=true to confirm.`, bad);
      }
    }
    const upd = rowsOf(await q.query(
      `UPDATE fim_drift SET status = $2, resolved_by = $3, resolved_at = extract(epoch FROM now())::bigint, note = $4
       WHERE id = ANY($1::bigint[]) AND status = 'open'
       RETURNING id, change_type, kind`,
      [cand.map((r) => Number(r.id)), status, user, note],
    ));
    const done = upd.map((r) => Number(r.id));
    if (done.length) {
      await q.query(
        `INSERT INTO fim_audit (at, actor, user_id, action, details) VALUES (extract(epoch FROM now())::bigint, $1, $3, 'FIM_DRIFT_RESOLVE', $2::jsonb)`,
        [user ?? 'unknown', JSON.stringify({ action, ids: done.slice(0, 500), note }), safeUserId(opts.actorUserId)]);
    }
    if (action === 'approve' && done.length) {
      // Registry item identity is case-insensitive (ASCII letters only, COLLATE "C" - the same rule as
      // the worker's ascii_lower and uq_fim_drift_open_ci): adopt the baseline row's spelling so the
      // upsert updates it instead of creating a second row the scan keys can never match.
      await q.query(
        `UPDATE fim_drift d SET path = b.path FROM fim_baseline b
         WHERE d.id = ANY($1::bigint[]) AND d.kind = 'item' AND d.path LIKE 'registry|%' AND b.policy_id = d.policy_id
           AND b.host_identifier = d.host_identifier AND lower(b.path COLLATE "C") = lower(d.path COLLATE "C") AND b.path <> d.path`, [done]);
      const upserts = upd.filter((r) => r.change_type !== 'removed').map((r) => Number(r.id));
      const removals = upd.filter((r) => r.change_type === 'removed').map((r) => Number(r.id));
      if (upserts.length) {
        await q.query(
          `INSERT INTO fim_baseline (policy_id, host_identifier, path, kind, entry_idx, data, sha256, md5, size, mode, uid, gid, mtime, first_seen, last_seen, approved_by)
           SELECT d.policy_id, d.host_identifier, d.path, d.kind, d.entry_idx,
                  CASE WHEN d.kind = 'item' THEN d.new_attrs END,
                  d.new_sha256,
                  CASE WHEN d.kind = 'file' THEN d.new_attrs->>'md5' END,
                  CASE WHEN d.kind = 'file' AND d.new_attrs->>'size'  ~ '^-?[0-9]{1,18}$' THEN (d.new_attrs->>'size')::bigint END,
                  CASE WHEN d.kind <> 'item' THEN d.new_attrs->>'mode' END,
                  CASE WHEN d.kind <> 'item' AND d.new_attrs->>'uid'   ~ '^-?[0-9]{1,18}$' THEN (d.new_attrs->>'uid')::bigint END,
                  CASE WHEN d.kind <> 'item' AND d.new_attrs->>'gid'   ~ '^-?[0-9]{1,18}$' THEN (d.new_attrs->>'gid')::bigint END,
                  CASE WHEN d.kind = 'file' AND d.new_attrs->>'mtime' ~ '^-?[0-9]{1,18}$' THEN (d.new_attrs->>'mtime')::bigint END,
                  extract(epoch FROM now())::bigint, extract(epoch FROM now())::bigint, $2
           FROM fim_drift d WHERE d.id = ANY($1::bigint[])
           ON CONFLICT (policy_id, host_identifier, path) DO UPDATE SET
             -- Exactly the drift's new values (NULL if absent): the worker treats a NULL
             -- baseline hash as 'pending' and backfills it from the next scan; unknown
             -- attributes are skipped in comparisons. Directories carry mode/uid/gid only;
             -- items carry their observed columns in data.
             kind = EXCLUDED.kind, entry_idx = EXCLUDED.entry_idx, data = EXCLUDED.data,
             sha256 = EXCLUDED.sha256,
             md5    = EXCLUDED.md5,
             size = EXCLUDED.size,
             mode = EXCLUDED.mode,
             uid = EXCLUDED.uid,
             gid = EXCLUDED.gid,
             mtime = EXCLUDED.mtime,
             last_seen = EXCLUDED.last_seen, approved_by = EXCLUDED.approved_by`,
          [upserts, user],
        );
      }
      if (removals.length) {
        await q.query(
          `DELETE FROM fim_baseline b USING fim_drift d
           WHERE d.id = ANY($1::bigint[]) AND b.policy_id = d.policy_id AND b.host_identifier = d.host_identifier
             AND (b.path = d.path OR (d.kind = 'item' AND d.path LIKE 'registry|%' AND lower(b.path COLLATE "C") = lower(d.path COLLATE "C")))`,
          [removals],
        );
      }
      // §4.5: approving CRITICAL drift of a protected registry entry into the baseline is alerted
      // (fim_config: closable by a Super Admin other than the approver).
      const crit = cand.filter((r) => done.includes(Number(r.id)) && r.severity === 'critical');
      if (crit.length) {
        const pols = rowsOf(await q.query(`SELECT id, paths, managed_kind, name FROM fim_policies WHERE id = ANY($1::bigint[])`, [[...new Set(crit.map((r) => Number(r.policy_id)))]]));
        const byId = new Map(pols.map((p) => [Number(p.id), p]));
        const prot = crit.filter((r) => {
          const p = byId.get(Number(r.policy_id));
          const k = p?.managed_kind === 'registry_node' ? p.paths?.[Number(r.entry_idx)]?.entryKey : null;
          return !!k && !!getRegCatalogEntry(k)?.protected;
        });
        if (prot.length) {
          await q.query(
            `INSERT INTO alerts (host_identifier, hostname, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, os_name, detection_time)
             SELECT d.host_identifier, d.hostname, extract(epoch FROM now())::bigint, 'FIM critical drift on a protected registry entry approved into the baseline: ' || d.path,
                    $2, true, true, 'high', 'fim_config', 'File Integrity', '', '', (SELECT os_platform FROM nodes WHERE host_identifier = d.host_identifier), extract(epoch FROM now())::bigint
             FROM fim_drift d WHERE d.id = ANY($1::bigint[])`,
            [prot.map((r) => Number(r.id)), JSON.stringify({ fim_config: 'critical_approved', by: user, byUserId: safeUserId(opts.actorUserId), note, driftIds: prot.map((r) => Number(r.id)) })]);
        }
      }
    }
    if (done.length) {
      // Keep the console alert in step: approve -> false positive, reject -> true positive,
      // ignore -> closed only (mark left as is).
      const mark = action === 'approve' ? 'false_positive' : action === 'reject' ? 'true_positive' : null;
      await q.query(
        `UPDATE alerts a SET is_open = false, mark_type = COALESCE($2::text, a.mark_type), remarks = COALESCE($3::text, a.remarks)
         FROM fim_drift d
         WHERE d.id = ANY($1::bigint[]) AND a.is_open AND a.alert_type = 'fim' AND a.host_identifier = d.host_identifier
           AND (a.id = d.alert_id OR ${META_DRIFT_ID} = d.id)`,
        [done, mark, note],
      );
    }
    const results: ResolveItemResult[] = ids.map((id) => refused.get(Number(id)) ?? { id: Number(id), outcome: done.includes(Number(id)) ? 'resolved' : 'skipped' });
    return { resolved: done.length, skipped: ids.length - done.length, ids: done, results };
  }
}

// ---------------------------------------------------------------------------
// FIM alerts (rows in `alerts` written by vajra_fim: alert_type 'fim' / 'fim_health')
// ---------------------------------------------------------------------------

const ALERT_FROM = `
  FROM alerts a
  LEFT JOIN nodes n ON n.host_identifier = a.host_identifier
  LEFT JOIN LATERAL (
    SELECT d.* FROM fim_drift d
    WHERE a.alert_type = 'fim' AND (d.alert_id = a.id OR d.id = ${META_DRIFT_ID})
    ORDER BY COALESCE(d.alert_id = a.id, false) DESC LIMIT 1
  ) d ON true
  LEFT JOIN fim_policies hp ON a.alert_type = 'fim_health'
       AND hp.name = substring(a.event_code from '\\[(.*)\\]\\s*$')`;

const ALERT_COLS = `a.id AS alert_id, a.alert_type, a.severity, a.event_code, a.host_identifier,
  COALESCE(n.hostname, a.hostname) AS hostname, COALESCE(a.detection_time, a.unixtime) AS detected_at,
  COALESCE(a.is_open, false) AS is_open, a.mark_type, a.remarks,
  COALESCE(d.policy_id, hp.id) AS policy_id, COALESCE(d.policy_name, hp.name) AS policy_name,
  d.id AS drift_id, d.kind AS drift_kind, d.change_type, d.path, d.source, d.old_sha256, d.new_sha256,
  d.actor_process, d.actor_user, d.occurrences, d.status AS drift_status, d.last_seen_at AS drift_last_seen_at, d.confirmed_at AS drift_confirmed_at, d.reverted AS drift_reverted, a.metadata AS alert_metadata,
  d.entry_idx AS drift_entry_idx, d.new_attrs AS drift_new_attrs`;

export function mapAlert(r: any) {
  return {
    alertId: num(r.alert_id),
    alertType: r.alert_type as 'fim' | 'fim_health' | 'fim_config',
    severity: String(r.severity ?? '').toLowerCase(),
    eventCode: r.event_code ?? '',
    hostIdentifier: r.host_identifier,
    hostname: r.hostname ?? null,
    detectedAt: numOrNull(r.detected_at),
    isOpen: !!r.is_open,
    markType: r.mark_type ?? null,
    remarks: r.remarks ?? null,
    policyId: numOrNull(r.policy_id),
    policyName: r.policy_name ?? null,
    driftId: numOrNull(r.drift_id),
    kind: (r.drift_kind ?? null) as 'file' | 'directory' | 'item' | null,
    changeType: r.change_type ?? null,
    path: r.path ?? null,
    source: r.source ?? null,
    oldSha256: r.old_sha256 ?? null,
    newSha256: r.new_sha256 ?? null,
    actorProcess: r.actor_process ?? null,
    actorUser: r.actor_user ?? null,
    occurrences: numOrNull(r.occurrences),
    driftStatus: r.drift_status ?? null,
    driftLastSeenAt: numOrNull(r.drift_last_seen_at),
    driftConfirmedAt: numOrNull(r.drift_confirmed_at),
    driftReverted: !!r.drift_reverted,
    /** Content hash of the linked drift (send as expected[driftId].contentHash with approveChange). */
    contentHash: r.drift_id === null || r.drift_id === undefined ? null
      : driftContentHash({ change_type: r.change_type, kind: r.drift_kind, entry_idx: r.drift_entry_idx, new_sha256: r.new_sha256, new_attrs: r.drift_new_attrs }),
    /** fim_config alerts are closed by Super Admins only (set by listAlerts for the caller). */
    canClose: true,
  };
}

export interface AlertFilters {
  status?: string; verdict?: string; severity?: string; type?: string; policy?: number | null; host?: string; q?: string;
}

export async function listAlerts(q: FimQ, f: AlertFilters, hostFilter: string[] | null, page: number, pageSize: number, superAdmin = true, me: { user?: string | null; userId?: number | null } = {}) {
  const base = `FROM (SELECT ${ALERT_COLS} ${ALERT_FROM}
       WHERE a.alert_type IN ('fim','fim_health','fim_config') AND ($1::text[] IS NULL OR a.host_identifier = ANY($1))) x`;
  const cnt = rowsOf(await q.query(`SELECT
      count(*) FILTER (WHERE is_open)::int AS open, count(*) FILTER (WHERE NOT is_open)::int AS closed,
      count(*) FILTER (WHERE mark_type = 'true_positive')::int AS tp, count(*) FILTER (WHERE mark_type = 'false_positive')::int AS fp
    ${base}`, [hostFilter]))[0] ?? {};
  const status = f.status === 'closed' ? 'closed' : f.status === 'all' ? 'all' : 'open';
  const where = `WHERE ($2::text = 'all' OR (CASE WHEN is_open THEN 'open' ELSE 'closed' END) = $2)
      AND ($3::text IS NULL OR ($3 = 'unmarked' AND mark_type IS NULL) OR mark_type = $3)
      AND ($4::text IS NULL OR lower(severity) = lower($4))
      AND ($5::text IS NULL OR ($5 = 'drift' AND alert_type = 'fim') OR ($5 = 'health' AND alert_type = 'fim_health') OR ($5 = 'config' AND alert_type = 'fim_config'))
      AND ($6::bigint IS NULL OR policy_id = $6)
      AND ($7::text IS NULL OR host_identifier = $7 OR lower(COALESCE(hostname,'')) = lower($7))
      AND ($8::text IS NULL OR event_code ILIKE $8 ESCAPE '\\' OR COALESCE(path,'') ILIKE $8 ESCAPE '\\' OR COALESCE(hostname,'') ILIKE $8 ESCAPE '\\')`;
  const params = [hostFilter, status, f.verdict || null, f.severity || null, f.type || null, f.policy ?? null, f.host || null, f.q ? `%${escapeLike(f.q)}%` : null];
  const total = num(rowsOf(await q.query(`SELECT count(*) AS n ${base} ${where}`, params))[0]?.n);
  const rows = rowsOf(await q.query(`SELECT * ${base} ${where} ORDER BY detected_at DESC NULLS LAST, alert_id DESC LIMIT $9 OFFSET $10`,
    [...params, pageSize, (page - 1) * pageSize]));
  return {
    // fim_config: Super Admins only, and never the actor the oversight alert is about.
    items: rows.map((r) => ({ ...mapAlert(r), canClose: r.alert_type !== 'fim_config' || (superAdmin && !isOwnOversightAlert(r.alert_metadata, me)) })), total, page, pageSize,
    counts: { open: num(cnt.open), closed: num(cnt.closed), truePositive: num(cnt.tp), falsePositive: num(cnt.fp) },
  };
}

export type AlertVerdict = 'true_positive' | 'false_positive';
export interface AlertActor {
  /** Hosts the caller may act on (null = unrestricted). */
  hostFilter: string[] | null;
  /** Group ids the caller may act on (matches alerts.group_id, as alert_update does). */
  groupIds: string[];
  /** Policies the caller may manage (null = unrestricted); linked open drift outside it blocks the close. */
  policyFilter: number[] | null;
  user: string | null;
  /** vajra_users.id: "own oversight alert" is decided by id whenever the alert metadata carries byUserId. */
  userId?: number | null;
  /** Correlation id recorded in fim_audit.request_id. */
  requestId?: string | null;
  /** fim_config (oversight) alerts are closed/reopened by Super Admins only, never by the actor they are about. */
  superAdmin?: boolean;
}

/**
 * True when a fim_config (oversight) alert is about the caller's own action. Compared by USER ID when
 * the metadata carries byUserId and the caller's id is known; otherwise by e-mail (metadata.by,
 * case-insensitive). Legacy / non-JSON metadata names nobody.
 */
export function isOwnOversightAlert(metadata: unknown, actor: { user?: string | null; userId?: number | null }): boolean {
  let meta: any = null;
  if (typeof metadata === 'string') { try { meta = JSON.parse(metadata); } catch { meta = null; } }
  else if (metadata && typeof metadata === 'object') meta = metadata;
  if (!meta || typeof meta !== 'object') return false;
  const byId = safeUserId(meta.byUserId);
  const myId = safeUserId(actor.userId);
  if (byId !== null && myId !== null) return byId === myId;
  const by = meta.by;
  return typeof by === 'string' && !!actor.user && by.toLowerCase() === actor.user.toLowerCase();
}

async function actableAlerts(q: FimQ, ids: number[], actor: AlertActor, wantOpen: boolean) {
  const rows = rowsOf(await q.query(
    `SELECT x.alert_id, x.alert_type, x.drift_id, x.drift_status, x.policy_id, x.alert_metadata FROM (SELECT ${ALERT_COLS}, a.group_id AS agroup ${ALERT_FROM}
       WHERE a.alert_type IN ('fim','fim_health','fim_config') AND a.id = ANY($1::bigint[])
         AND COALESCE(a.is_open, false) = $2
         AND ($3::text[] IS NULL OR a.host_identifier = ANY($3) OR a.group_id = ANY($4::text[]))
         AND (a.alert_type <> 'fim_config' OR $5::boolean)) x`,
    [ids, wantOpen, actor.hostFilter, actor.groupIds, actor.superAdmin === true],
  ));
  // An oversight alert about the caller's own action cannot be closed by that caller.
  return rows.filter((r) => r.alert_type !== 'fim_config' || !isOwnOversightAlert(r.alert_metadata, actor));
}

export interface GenericAlertUpdateActor {
  /** jwt id (vajra_users.id). */
  userId: number | null;
  email: string | null;
  /** Unrestricted scope (Super Administrator). */
  superAdmin: boolean;
}
/** What the generic request does: is_open=false, is_open=true, or a mark (true/false positive, unmarked). */
export type GenericAlertOp = 'close' | 'reopen' | 'mark';
export type GenericAlertBlockReason = 'oversight_super_admin_only' | 'oversight_own_action' | 'fim_drift_open_use_fim_routes';
export interface GenericAlertUpdateGuard {
  /** Ids the generic /api/alerts/update may change. */
  allowed: string[];
  /** Ids refused, with the reason. */
  blocked: { id: string; alertType: string; reason: GenericAlertBlockReason }[];
}

/**
 * Rule of the generic POST /api/alerts/update (close / reopen / mark), mirroring the rules of the
 * FIM routes (closeAlerts / reopenAlerts -> actableAlerts):
 *  - fim_config (oversight) alerts: Super Administrators only, and never the actor the alert is about
 *    (by user id when metadata.byUserId is present, else by e-mail), for every operation;
 *  - fim (drift) alerts whose linked drift is still OPEN: close and mark are refused; they must go
 *    through POST /api/fim/alerts/close, which resolves the drift in the same transaction (policy
 *    scope, approve guards, baseline). Closing here would leave an open drift behind a closed alert.
 *    Reopen is allowed (the FIM reopen route does not touch drift either), as are alerts whose drift
 *    is already resolved or that have no linked drift;
 *  - fim_health alerts: no extra rule (the FIM routes let any caller with act scope close / reopen
 *    them, and the generic endpoint already enforces that scope).
 * Throws on a DB error: the caller must fail closed (500), never skip the rule.
 *
 * SQL CASE yielding the GenericAlertBlockReason of alert row `a`, or NULL when the generic endpoint
 * may change it. Parameters: $2 superAdmin boolean, $3 caller user id (bigint|null), $4 caller
 * e-mail (text|null), $5 op ('close'|'reopen'|'mark'). Used INSIDE the UPDATE (atomic: the rule is
 * evaluated against the rows as they are when the update runs) and by the read-only previews.
 * Own-alert rule = isOwnOversightAlert, read with regexes so legacy non-JSON metadata (TEXT) can
 * never make the statement fail: byUserId compared by id when both ids are known, else metadata.by
 * compared case-insensitively with the caller's e-mail.
 */
const GENERIC_BLOCK_REASON_SQL = `
  CASE
    WHEN a.alert_type = 'fim_config' AND NOT $2::boolean THEN 'oversight_super_admin_only'
    WHEN a.alert_type = 'fim_config' AND (
      CASE WHEN NULLIF(substring(a.metadata from '"byUserId"\\s*:\\s*"?([0-9]{1,15})'), '') IS NOT NULL AND $3::bigint IS NOT NULL
           THEN NULLIF(substring(a.metadata from '"byUserId"\\s*:\\s*"?([0-9]{1,15})'), '')::bigint = $3::bigint
           ELSE ($4::text IS NOT NULL AND lower(substring(a.metadata from '"by"\\s*:\\s*"([^"]*)"')) = lower($4::text)) END)
      THEN 'oversight_own_action'
    WHEN a.alert_type = 'fim' AND $5::text <> 'reopen' AND EXISTS (
      SELECT 1 FROM fim_drift d WHERE d.status = 'open' AND d.host_identifier = a.host_identifier
        AND (d.alert_id = a.id OR d.id = ${META_DRIFT_ID}))
      THEN 'fim_drift_open_use_fim_routes'
  END`;

const guardParams = (actor: GenericAlertUpdateActor, op: GenericAlertOp) =>
  [actor.superAdmin === true, safeUserId(actor.userId), actor.email ?? null, op];

/**
 * Read-only preview of the generic-endpoint rule (same SQL as applyGenericAlertUpdate). The
 * endpoint itself must use applyGenericAlertUpdate: a preview followed by a separate UPDATE races.
 * Ids that do not exist are passed through as allowed.
 */
export async function guardGenericAlertUpdate(
  q: FimQ, ids: Array<string | number | bigint>, actor: GenericAlertUpdateActor, op: GenericAlertOp = 'close',
): Promise<GenericAlertUpdateGuard> {
  const want = ids.map((i) => String(i));
  if (want.length === 0) return { allowed: [], blocked: [] };
  const rows = rowsOf(await q.query(
    `SELECT a.id::text AS id, a.alert_type, ${GENERIC_BLOCK_REASON_SQL} AS reason FROM alerts a WHERE a.id = ANY($1::bigint[])`,
    [want, ...guardParams(actor, op)]));
  const blocked: GenericAlertUpdateGuard['blocked'] = rows.filter((r) => r.reason)
    .map((r) => ({ id: String(r.id), alertType: r.alert_type, reason: r.reason as GenericAlertBlockReason }));
  const bad = new Set(blocked.map((x) => x.id));
  return { allowed: want.filter((id) => !bad.has(id)), blocked };
}

export type GenericAlertSet = { column: 'is_open'; value: unknown } | { column: 'mark_type'; value: string | null };
export interface GenericAlertUpdateResult {
  /** Ids actually updated (RETURNING). */
  updated: string[];
  /** Existing ids that were not updated, with the reason ('concurrent_change' = the rule matched during the UPDATE but no longer does). */
  blocked: { id: string; alertType: string; reason: GenericAlertBlockReason | 'concurrent_change' }[];
}

/**
 * The generic POST /api/alerts/update in ONE statement: the FIM rule (see guardGenericAlertUpdate)
 * is part of the UPDATE's WHERE clause, so an oversight / own-alert condition or a drift linked
 * between a check and the write can never slip through. Reasons for the rows that were not updated
 * are read afterwards (informational only; the write itself is already decided).
 */
export async function applyGenericAlertUpdate(
  q: FimQ, ids: Array<string | number | bigint>, actor: GenericAlertUpdateActor, op: GenericAlertOp, set: GenericAlertSet,
): Promise<GenericAlertUpdateResult> {
  const want = ids.map((i) => String(i));
  if (want.length === 0) return { updated: [], blocked: [] };
  const setSql = set.column === 'is_open' ? 'is_open = $6::boolean' : 'mark_type = $6::text';
  const upd = rowsOf(await q.query(
    `UPDATE alerts a SET ${setSql} WHERE a.id = ANY($1::bigint[]) AND (${GENERIC_BLOCK_REASON_SQL}) IS NULL RETURNING a.id::text AS id`,
    [want, ...guardParams(actor, op), set.value]));
  const updated = upd.map((r) => String(r.id));
  const done = new Set(updated);
  const rest = want.filter((id) => !done.has(id));
  if (rest.length === 0) return { updated, blocked: [] };
  const why = rowsOf(await q.query(
    `SELECT a.id::text AS id, a.alert_type, ${GENERIC_BLOCK_REASON_SQL} AS reason FROM alerts a WHERE a.id = ANY($1::bigint[])`,
    [rest, ...guardParams(actor, op)]));
  return { updated, blocked: why.map((r) => ({ id: String(r.id), alertType: r.alert_type, reason: (r.reason ?? 'concurrent_change') as GenericAlertUpdateResult['blocked'][number]['reason'] })) };
}

/** Row-locks the given alerts (id order, so concurrent callers cannot deadlock on each other). */
async function lockAlertRows(q: FimQ, ids: number[]): Promise<void> {
  if (ids.length) await q.query('SELECT id FROM alerts WHERE id = ANY($1::bigint[]) ORDER BY id FOR UPDATE', [ids]);
}

function alertTypeCounts(rows: { alert_type: string }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) out[r.alert_type] = (out[r.alert_type] ?? 0) + 1;
  return out;
}

/**
 * Closes open FIM alerts with a verdict, resolving the linked open drift in the same
 * transaction (true positive -> rejected; false positive -> ignored, or approved into the
 * baseline when approveChange). Alerts outside the caller's scope are counted as skipped.
 */
export async function closeAlerts(
  db: FimDb, ids: number[], verdict: AlertVerdict, note: string, actor: AlertActor,
  opts: { approveChange?: boolean; acceptUnverified?: boolean; expected?: Record<string, ExpectedDrift> | null; atomic?: boolean } = {},
): Promise<{ closed: number; skipped: number; ids: number[]; results: { id: number; driftId: number | null; outcome: 'closed' | 'drift_changed' | 'awaiting_confirmation' | 'skipped'; current?: ResolveItemResult['current'] }[] }> {
  if (!note || !note.trim()) throw new FimBadRequestError('A note is required to close alerts');
  if (opts.approveChange && verdict !== 'false_positive') throw new FimBadRequestError('approveChange is only valid for false positives');
  return db.transaction(async (q) => {
    // Lock the requested alert rows for the whole transaction: open/closed state and metadata read
    // by actableAlerts cannot change under us (a concurrent close / reopen waits).
    await lockAlertRows(q, ids);
    const cand = await actableAlerts(q, ids, actor, true);
    const ok = cand.filter((r) => {
      const open = r.drift_id !== null && r.drift_status === 'open';
      return !open || actor.policyFilter === null || (r.policy_id !== null && actor.policyFilter.includes(Number(r.policy_id)));
    });
    const skippedAll = () => ids.map((id) => ({ id: Number(id), driftId: null, outcome: 'skipped' as const }));
    if (ok.length === 0) return { closed: 0, skipped: ids.length, ids: [], results: skippedAll() };
    const driftIds = ok.filter((r) => r.drift_id !== null && r.drift_status === 'open').map((r) => Number(r.drift_id));
    const refused = new Map<number, ResolveItemResult>();
    const resolvedDrift = new Set<number>();
    if (driftIds.length) {
      const action: ResolveAction = verdict === 'true_positive' ? 'reject' : opts.approveChange ? 'approve' : 'ignore';
      const rr = await resolveDriftTx(q, Array.from(new Set(driftIds)), action, actor.user, note.trim(), actor.hostFilter, actor.policyFilter,
        { acceptUnverified: opts.acceptUnverified, expected: opts.expected, atomic: opts.atomic === true || ids.length === 1, actorUserId: actor.userId ?? null });
      for (const x of rr.results) {
        if (x.outcome === 'drift_changed' || x.outcome === 'awaiting_confirmation') refused.set(x.id, x);
        else if (x.outcome === 'resolved') resolvedDrift.add(x.id);
      }
    }
    // An alert with an OPEN linked drift is closed only when that drift was actually resolved here.
    // Not approved (content changed / unconfirmed) -> stays open for re-review with that outcome;
    // skipped by resolveDriftTx (drift host outside the caller's act scope, policy deleted for
    // reject/approve, resolved concurrently, ...) -> stays open and is reported as skipped, so
    // `closed` never counts an alert whose drift is still open.
    const alertIds = ok.filter((r) => {
      if (r.drift_id === null || r.drift_status !== 'open') return true;
      return resolvedDrift.has(Number(r.drift_id));
    }).map((r) => Number(r.alert_id));
    const byAlert = new Map(ok.map((r) => [Number(r.alert_id), r]));
    // The write re-checks, atomically, that no OPEN drift is linked to the alert: a drift linked
    // after actableAlerts read the alert (drift rows are not covered by the alert row lock) keeps
    // the alert open (reported as skipped) instead of closing it with its change unresolved. The
    // drift resolved above is no longer open inside this transaction, so it does not count.
    const closedIds = alertIds.length === 0 ? [] : rowsOf(await q.query(
      `UPDATE alerts a SET is_open = false, mark_type = $2, remarks = $3
       WHERE a.id = ANY($1::bigint[])
         AND NOT (a.alert_type = 'fim' AND EXISTS (
           SELECT 1 FROM fim_drift d WHERE d.status = 'open' AND d.host_identifier = a.host_identifier
             AND (d.alert_id = a.id OR d.id = ${META_DRIFT_ID})))
       RETURNING a.id`,
      [alertIds, verdict, note.trim()],
    )).map((r) => Number(r.id));
    const results = ids.map((id) => {
      const r = byAlert.get(Number(id));
      const driftId = r && r.drift_id !== null ? Number(r.drift_id) : null;
      const ref = driftId !== null ? refused.get(driftId) : undefined;
      if (ref) return { id: Number(id), driftId, outcome: ref.outcome as 'drift_changed' | 'awaiting_confirmation', current: ref.current };
      return { id: Number(id), driftId, outcome: closedIds.includes(Number(id)) ? 'closed' as const : 'skipped' as const };
    });
    if (closedIds.length === 0) return { closed: 0, skipped: ids.length, ids: [], results };
    await fimAuditTx(q, actor, 'FIM_ALERT_CLOSE', {
      verdict, note: note.trim(), approveChange: opts.approveChange === true, acceptUnverified: opts.acceptUnverified === true,
      ids: closedIds.slice(0, 500), byType: alertTypeCounts(ok.filter((r) => closedIds.includes(Number(r.alert_id)))),
      oversightIds: ok.filter((r) => r.alert_type === 'fim_config' && closedIds.includes(Number(r.alert_id))).map((r) => Number(r.alert_id)).slice(0, 500),
      driftIds: Array.from(new Set(driftIds)).slice(0, 500), requested: ids.length,
    });
    return { closed: closedIds.length, skipped: ids.length - closedIds.length, ids: closedIds, results };
  });
}

/** Reopens closed FIM alerts (mark cleared); linked drift is not touched. */
export async function reopenAlerts(db: FimDb, ids: number[], actor: AlertActor, note: string | null = null): Promise<{ reopened: number; skipped: number; ids: number[] }> {
  return db.transaction(async (q) => {
    await lockAlertRows(q, ids); // state / metadata checked below cannot change before the write
    const cand0 = await actableAlerts(q, ids, actor, false);
    const alertIds = cand0.length === 0 ? [] : rowsOf(await q.query(
      `UPDATE alerts SET is_open = true, mark_type = NULL WHERE id = ANY($1::bigint[]) AND NOT COALESCE(is_open, false) RETURNING id`,
      [cand0.map((r) => Number(r.alert_id))])).map((r) => Number(r.id));
    const cand = cand0.filter((r) => alertIds.includes(Number(r.alert_id)));
    if (alertIds.length) {
      await fimAuditTx(q, actor, 'FIM_ALERT_REOPEN', {
        note, ids: alertIds.slice(0, 500), byType: alertTypeCounts(cand),
        oversightIds: cand.filter((r) => r.alert_type === 'fim_config').map((r) => Number(r.alert_id)).slice(0, 500), requested: ids.length,
      });
    }
    return { reopened: alertIds.length, skipped: ids.length - alertIds.length, ids: alertIds };
  });
}

// ---------------------------------------------------------------------------
// Baseline + summary
// ---------------------------------------------------------------------------

export function mapBaseline(r: any) {
  return {
    policyId: num(r.policy_id),
    hostIdentifier: r.host_identifier,
    path: r.path,
    kind: (r.kind ?? 'file') as 'file' | 'directory' | 'item',
    entryIdx: numOrNull(r.entry_idx),
    data: r.data ?? null,
    sha256: r.sha256 ?? null,
    md5: r.md5 ?? null,
    size: numOrNull(r.size),
    mode: r.mode ?? null,
    uid: numOrNull(r.uid),
    gid: numOrNull(r.gid),
    mtime: numOrNull(r.mtime),
    firstSeen: num(r.first_seen),
    lastSeen: num(r.last_seen),
    approvedBy: r.approved_by ?? null,
  };
}

export async function listBaseline(
  q: FimQ, f: { policy?: number | null; host?: string; q?: string; kind?: string }, hostFilter: string[] | null, page: number, pageSize: number,
) {
  const where = `WHERE ($1::bigint IS NULL OR b.policy_id = $1)
      AND ($5::text IS NULL OR b.kind = $5)
      AND ($2::text IS NULL OR b.host_identifier = $2)
      AND ($3::text IS NULL OR b.path ILIKE $3 ESCAPE '\\')
      AND ($4::text[] IS NULL OR b.host_identifier = ANY($4))`;
  const params = [f.policy ?? null, f.host || null, f.q ? `%${escapeLike(f.q)}%` : null, hostFilter, f.kind || null];
  const total = num(rowsOf(await q.query(`SELECT count(*) AS n FROM fim_baseline b ${where}`, params))[0]?.n);
  const rows = rowsOf(await q.query(
    `SELECT b.* FROM fim_baseline b ${where} ORDER BY b.host_identifier, b.path LIMIT $6 OFFSET $7`,
    [...params, pageSize, (page - 1) * pageSize],
  ));
  return { items: rows.map(mapBaseline), total, page, pageSize };
}

export async function getSummary(q: FimQ, hostFilter: string[] | null) {
  const hf = [hostFilter];
  const one = async (sql: string) => rowsOf(await q.query(sql, hf));
  const sev = await one(`SELECT severity, count(*) AS n FROM fim_drift WHERE status='open' AND ($1::text[] IS NULL OR host_identifier = ANY($1)) GROUP BY severity`);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const r of sev) bySeverity[r.severity] = num(r.n);
  const hs = (await one(`SELECT
      count(DISTINCT host_identifier) AS monitored,
      count(DISTINCT host_identifier) FILTER (WHERE state='locked') AS locked
    FROM fim_host_state WHERE ($1::text[] IS NULL OR host_identifier = ANY($1))`))[0] ?? {};
  // Hosts in scope of an enabled policy that lack a locked baseline for it (distinct hosts):
  // one set-based query, not one per policy.
  const notBaselinedCount = num(rowsOf(await q.query(
    `WITH ${POLICY_SCOPE_CTE}
     SELECT count(DISTINCT s.host_identifier)::int AS n
     FROM pscope s JOIN fim_policies p ON p.id = s.policy_id AND p.enabled
     LEFT JOIN fim_host_state hs ON hs.policy_id = s.policy_id AND hs.host_identifier = s.host_identifier
     WHERE hs.state IS DISTINCT FROM 'locked' AND ($2::text[] IS NULL OR s.host_identifier = ANY($2::text[]))`,
    [null, hostFilter]))[0]?.n);
  const hostsBaselined = num(hs.locked);
  const alertSev = rowsOf(await q.query(
    `SELECT lower(severity) AS sev, count(*)::int AS n FROM alerts
     WHERE alert_type IN ('fim','fim_health','fim_config') AND COALESCE(is_open, false) AND ($1::text[] IS NULL OR host_identifier = ANY($1)) GROUP BY 1`, hf));
  const openAlertsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  let openAlerts = 0;
  for (const r of alertSev) { openAlerts += num(r.n); if (r.sev in openAlertsBySeverity) openAlertsBySeverity[r.sev] = num(r.n); }
  const kindRows = (sql: string) => one(sql);
  const baselineByKind = { file: 0, directory: 0, item: 0 } as Record<string, number>;
  for (const r of await kindRows(`SELECT kind, count(*)::int AS n FROM fim_baseline WHERE ($1::text[] IS NULL OR host_identifier = ANY($1)) GROUP BY kind`)) baselineByKind[r.kind] = num(r.n);
  const openDriftByKind = { file: 0, directory: 0, item: 0 } as Record<string, number>;
  for (const r of await kindRows(`SELECT kind, count(*)::int AS n FROM fim_drift WHERE status = 'open' AND ($1::text[] IS NULL OR host_identifier = ANY($1)) GROUP BY kind`)) openDriftByKind[r.kind] = num(r.n);
  // What is covered: live (non-retired) entries of enabled policies, by entry kind (one query).
  const entriesByKind = { path: 0, xattr: 0, registry: 0, acl: 0, table: 0 } as Record<string, number>;
  for (const r of rowsOf(await q.query(
    `SELECT COALESCE(NULLIF(e->>'kind', ''), 'path') AS k, count(*)::int AS n
     FROM fim_policies p CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(p.paths) = 'array' THEN p.paths ELSE '[]'::jsonb END) AS e
     WHERE p.enabled AND jsonb_typeof(e) = 'object' AND COALESCE(e->>'retired', 'false') NOT IN ('true')
     GROUP BY 1`))) entriesByKind[r.k] = (entriesByKind[r.k] ?? 0) + num(r.n);
  const baselineFiles = num((await one(`SELECT count(*) AS n FROM fim_baseline WHERE ($1::text[] IS NULL OR host_identifier = ANY($1))`))[0]?.n);
  const last24 = num((await one(`SELECT count(*) AS n FROM fim_drift WHERE detected_at >= extract(epoch FROM now())::bigint - 86400 AND ($1::text[] IS NULL OR host_identifier = ANY($1))`))[0]?.n);
  const topHosts = await one(`SELECT host_identifier, max(hostname) AS hostname, count(*) AS n FROM fim_drift
      WHERE status='open' AND ($1::text[] IS NULL OR host_identifier = ANY($1))
      GROUP BY host_identifier ORDER BY n DESC, host_identifier LIMIT 5`);
  const topPaths = await one(`SELECT path, count(*) AS n FROM fim_drift
      WHERE status='open' AND ($1::text[] IS NULL OR host_identifier = ANY($1))
      GROUP BY path ORDER BY n DESC, path LIMIT 5`);
  const trend = await one(`SELECT to_char(g.day, 'YYYY-MM-DD') AS day, COALESCE(c.n, 0) AS n
      FROM generate_series((now() AT TIME ZONE 'UTC')::date - 13, (now() AT TIME ZONE 'UTC')::date, interval '1 day') AS g(day)
      LEFT JOIN (SELECT (to_timestamp(detected_at) AT TIME ZONE 'UTC')::date AS day, count(*) AS n FROM fim_drift
                 WHERE detected_at >= extract(epoch FROM now())::bigint - 15 * 86400
                   AND ($1::text[] IS NULL OR host_identifier = ANY($1)) GROUP BY 1) c ON c.day = g.day::date
      ORDER BY g.day`);
  return {
    openDrift: Object.values(bySeverity).reduce((a, b) => a + b, 0),
    bySeverity,
    openAlerts,
    openAlertsBySeverity,
    hostsMonitored: num(hs.monitored),
    hostsBaselined,
    hostsNotBaselined: notBaselinedCount,
    hostsLearning: notBaselinedCount, // legacy alias
    hostsLocked: hostsBaselined, // legacy alias
    baselineFiles,
    baselineByKind,
    openDriftByKind,
    entriesByKind,
    driftLast24h: last24,
    topHosts: topHosts.map((r) => ({ hostIdentifier: r.host_identifier, hostname: r.hostname ?? null, count: num(r.n) })),
    topPaths: topPaths.map((r) => ({ path: r.path, count: num(r.n) })),
    trend: trend.map((r) => ({ day: r.day, count: num(r.n) })),
  };
}


// ---------------------------------------------------------------------------
// Template v2 upgrade (FIM_REGISTRY_DESIGN §3.15 step 1)
// ---------------------------------------------------------------------------

/** Templates whose current version can replace an older policy's entries. */
export const UPGRADABLE_TEMPLATES = new Set(['windows-registry-persistence']);

export function templateUpgradeAvailable(p: Pick<FimPolicyView, 'template' | 'paths' | 'osPlatform' | 'managedKind'>): boolean {
  if (p.managedKind || !p.template || !UPGRADABLE_TEMPLATES.has(p.template)) return false;
  const t = FIM_TEMPLATES.find((x) => x.id === p.template);
  if (!t || t.osPlatform !== p.osPlatform) return false;
  return pathsChanged(p.paths as FimPathEntry[], normalizePaths(t.paths, t.osPlatform, { superAdmin: true }));
}

/**
 * Replaces a template-based policy's entries with the template's current version (rev bump;
 * baselines are NOT touched: the policy shows drift for the new rows until Initialize).
 * Re-publishes when the policy is published. Existing policies are only changed on request.
 */
export async function upgradePolicyTemplate(db: FimDb, id: number): Promise<{ policy: FimPolicyView; published: PublishResult | null }> {
  return db.transaction(async (q) => {
    const cur = rowsOf(await q.query('SELECT id FROM fim_policies WHERE id = $1 FOR UPDATE', [id]));
    if (!cur.length) throw new FimNotFoundError('FIM policy not found');
    const pol = (await fetchPolicy(q, id, false))!;
    if (!templateUpgradeAvailable(pol)) throw new FimBadRequestError('No template upgrade is available for this policy');
    const t = FIM_TEMPLATES.find((x) => x.id === pol.template)!;
    const paths = normalizePaths(t.paths, t.osPlatform, { superAdmin: true });
    await q.query(
      `UPDATE fim_policies SET paths = $2::jsonb, realtime = $3, rev = rev + 1, updated_at = now() WHERE id = $1`,
      [id, JSON.stringify(paths), t.realtime],
    );
    const published = pol.configQueryId ? await publishPolicyTx(q, id) : null;
    return { policy: (await fetchPolicy(q, id, false))!, published };
  });
}


// ---------------------------------------------------------------------------
// Check scan on demand (real-time registry drift awaiting confirmation)
// ---------------------------------------------------------------------------

/**
 * Queues a check scan (same entry SQL as the scheduled scan) for an open real-time registry drift,
 * at most one per host + entry per FIM_VERIFY_MIN_GAP_SECS (the worker applies the same limit).
 */
export async function recheckDrift(db: FimDb, id: number, hostFilter: string[] | null): Promise<{ queued: boolean; retryAfterSecs: number }> {
  return db.transaction(async (q) => {
    const d = rowsOf(await q.query(
      `SELECT d.*, p.rev, p.paths, p.os_platform FROM fim_drift d JOIN fim_policies p ON p.id = d.policy_id
       WHERE d.id = $1 AND ($2::text[] IS NULL OR d.host_identifier = ANY($2)) FOR UPDATE OF d`, [id, hostFilter]))[0];
    if (!d) throw new FimNotFoundError('Drift not found');
    if (d.status !== 'open' || d.source !== 'realtime' || d.kind !== 'item' || !String(d.path).startsWith('registry|') || d.entry_idx === null) {
      throw new FimConflictError('Only open real-time registry drift can be re-checked');
    }
    const t = Math.floor(Date.now() / 1000);
    const recent = rowsOf(await q.query(
      `SELECT created_at FROM fim_verify_requests WHERE policy_id = $1 AND host_identifier = $2 AND entry_idx = $3 AND created_at > $4 ORDER BY created_at DESC LIMIT 1`,
      [d.policy_id, d.host_identifier, d.entry_idx, t - FIM_VERIFY_MIN_GAP_SECS]))[0];
    if (recent) return { queued: false, retryAfterSecs: Math.max(1, FIM_VERIFY_MIN_GAP_SECS - (t - Number(recent.created_at))) };
    const entry = (d.paths ?? [])[Number(d.entry_idx)];
    if (!entry || entry.retired) throw new FimConflictError('The entry of this drift is no longer monitored');
    const sql = buildScanSql(entry, d.os_platform);
    const after = Number(rowsOf(await q.query('SELECT COALESCE(max(id),0) AS m FROM query_result'))[0]?.m ?? 0);
    const qq = rowsOf(await q.query(`INSERT INTO query_queue (host_identifier, query, sent, send_time) VALUES ($1, $2, false, 0) RETURNING id`, [d.host_identifier, sql]))[0];
    await q.query(
      `INSERT INTO fim_verify_requests (policy_id, host_identifier, entry_idx, rev, drift_id, queue_id, after_result_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [d.policy_id, d.host_identifier, d.entry_idx, d.rev, id, Number(qq.id), after, t]);
    return { queued: true, retryAfterSecs: FIM_VERIFY_MIN_GAP_SECS };
  });
}
