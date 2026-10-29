import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { dbSourceConnection } from '../../index';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { AuditTrailAction } from '../../orm/entities/audit/AuditTrail';
import {
  getUserNodeScope,
  getScopedHostIdentifiers,
  getActableHostIdentifiers,
  actableGroupIds,
  scopeGroupIds,
  NodeScope,
} from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import {
  FimValidationError,
  validatePolicyInput,
  isFimPolicyInScope,
  FimPolicyInput,
  FimTarget,
  fimPathWarnings,
} from '../../utils/fim/fimLogic';
import { FIM_TEMPLATES } from '../../utils/fim/fimTemplates';
import { catalogMetadata } from '../../utils/fim/fimCatalog';
import * as svc from '../../services/fimService';

const logger = getLogger('controllers.fimManagement');

function getFleetDb(): svc.FimDb {
  const db = dbSourceConnection()?.[1];
  if (!db) throw new CustomError(500, 'Database', 'Fleet database connection not available');
  // DataSource.transaction hands an EntityManager, whose query() matches FimQ.
  return db as unknown as svc.FimDb;
}

const getJwt = (req: Request) => (req as any).jwtPayload as JwtPayload | undefined;

/** Actor recorded in fim_audit (written inside the service transaction). */
function auditActor(req: Request): svc.FimAuditActor {
  const jwt = getJwt(req);
  const hdr = req.headers['x-request-id'];
  return {
    user: jwt?.email ?? null,
    userId: Number.isSafeInteger(Number(jwt?.id)) && jwt?.id !== undefined && jwt?.id !== null ? Number(jwt.id) : null,
    requestId: typeof hdr === 'string' && /^[A-Za-z0-9._-]{1,100}$/.test(hdr) ? hdr : randomUUID(),
  };
}

interface Ctx {
  scope: NodeScope;
  viewGroups: Set<string>;
  /** null = unrestricted */
  viewHosts: string[] | null;
  actGroups: Set<string>;
  actHosts: string[] | null;
}

async function getCtx(req: Request): Promise<Ctx> {
  const jwt = getJwt(req);
  const scope = jwt?.id ? await getUserNodeScope(jwt.id) : ({ unrestricted: false, groups: [] } as NodeScope);
  if (scope.unrestricted) {
    return { scope, viewGroups: new Set(), viewHosts: null, actGroups: new Set(), actHosts: null };
  }
  const [viewHosts, actHosts] = await Promise.all([getScopedHostIdentifiers(scope), getActableHostIdentifiers(scope)]);
  return {
    scope,
    viewGroups: new Set(scopeGroupIds(scope)),
    viewHosts: viewHosts ?? [],
    actGroups: new Set(actableGroupIds(scope)),
    actHosts: actHosts ?? [],
  };
}

function canManage(ctx: Ctx, p: { targets: FimTarget[]; createdBy: string | null }, email?: string | null): boolean {
  if (ctx.scope.unrestricted) return true;
  return isFimPolicyInScope(p, ctx.actGroups, ctx.actHosts ?? [], email ?? null);
}

function canView(ctx: Ctx, p: { targets: FimTarget[]; createdBy: string | null }, email?: string | null): boolean {
  if (ctx.scope.unrestricted) return true;
  if (p.targets.some((t) => t.type === 'all')) return true; // org-wide: read-only
  return isFimPolicyInScope(p, ctx.viewGroups, ctx.viewHosts ?? [], email ?? null);
}

function handleErr(err: unknown, next: NextFunction, what: string, extra?: Record<string, unknown>) {
  if (err instanceof CustomError) return next(err);
  if (err instanceof FimValidationError) return next(new CustomError(422, 'Validation', err.message));
  if (err instanceof svc.FimNotFoundError) return next(new CustomError(404, 'General', err.message));
  if (err instanceof svc.FimBadRequestError) return next(new CustomError(400, 'Validation', err.message));
  if (err instanceof svc.FimUnverifiedError) return next(new CustomError(409, 'General', err.message, err.ids.slice(0, 100).map(String)));
  if (err instanceof svc.FimUnconfirmedError) return next(new CustomError(409, 'General', err.message, ['awaiting_confirmation', ...err.ids.slice(0, 100).map(String)]));
  if (err instanceof svc.FimDriftChangedError) return next(new CustomError(409, 'General', err.message, ['drift_changed', ...err.current.slice(0, 100).map((c) => JSON.stringify(c))]));
  if (err instanceof svc.FimConflictError) return next(new CustomError(409, 'General', err.message));
  logger.error({ err, ...extra }, `Failed to ${what}`);
  return next(new CustomError(500, 'Raw', `Failed to ${what}`, null, err));
}

function audit(req: Request, action: AuditTrailAction, details: Record<string, unknown>) {
  const jwt = getJwt(req);
  logAuditTrail({
    action,
    status: 'success',
    userId: jwt?.id ?? null,
    email: jwt?.email ?? null,
    ipAddress: req.ip ?? null,
    userAgent: req.headers['user-agent'] ?? null,
    details,
  }).catch((err) => logger.error({ err }, 'Failed to log audit trail'));
}

function parseId(raw: unknown, what = 'id'): number {
  const s = String(raw);
  if (!/^[0-9]{1,15}$/.test(s)) throw new CustomError(400, 'Validation', `Invalid ${what}`);
  return Number(s);
}

function optStr(v: unknown, max = 255): string | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || v.length > max) throw new CustomError(400, 'Validation', 'Invalid query parameter');
  return v;
}

/** Verifies referenced groups/nodes exist; throws 422 otherwise. */
async function assertTargetsExist(db: svc.FimDb, targets: FimTarget[]): Promise<void> {
  const groups = targets.filter((t) => t.type === 'group').map((t) => t.value);
  const nodes = targets.filter((t) => t.type === 'node').map((t) => t.value);
  if (groups.length) {
    const found = new Set(svc.rowsOf(await db.query('SELECT group_id FROM nodes_groups WHERE group_id = ANY($1::text[])', [groups])).map((r) => r.group_id));
    const missing = groups.filter((g) => !found.has(g));
    if (missing.length) throw new FimValidationError(`Unknown group IDs: ${missing.slice(0, 5).join(', ')}`);
  }
  if (nodes.length) {
    const found = new Set(svc.rowsOf(await db.query('SELECT host_identifier FROM nodes WHERE host_identifier = ANY($1::text[])', [nodes])).map((r) => r.host_identifier));
    const missing = nodes.filter((n) => !found.has(n));
    if (missing.length) throw new FimValidationError(`Unknown node IDs: ${missing.slice(0, 5).join(', ')}`);
  }
}

function assertCandidateTargetsAllowed(ctx: Ctx, targets: FimTarget[]) {
  if (ctx.scope.unrestricted) return;
  if (targets.some((t) => t.type === 'all')) throw new CustomError(403, 'General', 'Group Admins cannot create org-wide FIM policies');
  if (!isFimPolicyInScope({ targets }, ctx.actGroups, ctx.actHosts ?? [])) {
    throw new CustomError(403, 'General', 'You can only target nodes/groups you have Group Admin access to');
  }
}

/** Loads a policy and enforces view/manage access. */
async function loadPolicy(req: Request, ctx: Ctx, db: svc.FimDb, mode: 'view' | 'manage') {
  const id = parseId(req.params.id, 'policy id');
  const policy = await svc.fetchPolicy(db, id);
  if (!policy) throw new CustomError(404, 'General', 'FIM policy not found');
  const email = getJwt(req)?.email;
  if (!canView(ctx, policy, email)) throw new CustomError(404, 'General', 'FIM policy not found');
  if (mode === 'manage' && !canManage(ctx, policy, email)) throw new CustomError(403, 'General', 'You do not have access to this policy');
  return policy;
}

const withWarnings = <T extends { paths: { path: string }[]; osPlatform: any }>(p: T) =>
  ({ ...p, warnings: fimPathWarnings(p.paths, p.osPlatform) });

/** Managed per-node registry policies are changed only through /api/fim/registry. */
function assertNotManaged(p: { managedKind?: string | null }) {
  if (p.managedKind) throw new CustomError(409, 'General', 'This policy is managed by Registry coverage; change it there');
}

// GET /api/fim/policies
export const listPolicies = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const email = getJwt(req)?.email;
    const { page, pageSize, offset } = svc.clampPage(req.query.page, req.query.pageSize);
    const all = (await svc.fetchAllPolicies(getFleetDb())).filter((p) => canView(ctx, p, email));
    const items = all.slice(offset, offset + pageSize).map((p) => ({ ...p, canManage: canManage(ctx, p, email) }));
    return res.json({ items, total: all.length, page, pageSize });
  } catch (err) {
    return handleErr(err, next, 'list FIM policies');
  }
};

// GET /api/fim/policies/:id
export const getPolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const policy = await loadPolicy(req, ctx, getFleetDb(), 'view');
    return res.json({ ...policy, canManage: canManage(ctx, policy, getJwt(req)?.email) });
  } catch (err) {
    return handleErr(err, next, 'get FIM policy');
  }
};

// POST /api/fim/policies
export const createPolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const input = validatePolicyInput(req.body, undefined, { superAdmin: ctx.scope.unrestricted });
    assertCandidateTargetsAllowed(ctx, input.targets);
    const db = getFleetDb();
    await assertTargetsExist(db, input.targets);
    const jwt = getJwt(req);
    const policy = await svc.createPolicy(db, input, jwt?.email ?? null, auditActor(req));
    audit(req, 'FIM_POLICY_CREATE', { policyId: policy.id, name: policy.name, osPlatform: policy.osPlatform, targets: policy.targets.length });
    return res.status(201).json({ ...withWarnings(policy), canManage: true });
  } catch (err) {
    return handleErr(err, next, 'create FIM policy');
  }
};

// PUT /api/fim/policies/:id  (partial fields allowed; unspecified keep current values)
export const updatePolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'manage');
    assertNotManaged(existing);
    const cur: FimPolicyInput = {
      name: existing.name, description: existing.description, osPlatform: existing.osPlatform,
      paths: existing.paths, scanIntervalSecs: existing.scanIntervalSecs, realtime: existing.realtime,
      mode: existing.mode, learnScans: existing.learnScans, enabled: existing.enabled,
      template: existing.template, targets: existing.targets,
    };
    const input = validatePolicyInput(req.body, cur, { superAdmin: ctx.scope.unrestricted });
    if (req.body?.targets !== undefined) {
      assertCandidateTargetsAllowed(ctx, input.targets);
      await assertTargetsExist(db, input.targets);
    }
    const actorA = auditActor(req);
    let policy = await svc.updatePolicy(db, existing.id, input, actorA);
    audit(req, 'FIM_POLICY_UPDATE', { policyId: policy.id, name: policy.name, fields: Object.keys(req.body ?? {}), rev: policy.rev });
    // A policy that is already published is re-published automatically when the edit
    // changes the published config, so "saved" never differs silently from "deployed".
    // Never-published policies stay unpublished until an explicit Publish.
    let publishResult: svc.PublishResult | null = null;
    if (existing.configQueryId && svc.affectsPublishedConfig(existing, policy)) {
      publishResult = await svc.publishPolicy(db, policy.id, actorA, { auto: true });
      audit(req, 'FIM_POLICY_PUBLISH', { policyId: policy.id, name: policy.name, auto: true, ...publishResult });
      policy = (await svc.fetchPolicy(db, policy.id)) ?? policy;
    }
    return res.json({ ...withWarnings(policy), canManage: true, publishResult });
  } catch (err) {
    return handleErr(err, next, 'update FIM policy', { policyId: req.params.id });
  }
};

// DELETE /api/fim/policies/:id
export const deletePolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'manage');
    assertNotManaged(existing);
    await svc.deletePolicy(db, existing.id, auditActor(req));
    audit(req, 'FIM_POLICY_DELETE', { policyId: existing.id, name: existing.name });
    return res.json({ status: 'Success' });
  } catch (err) {
    return handleErr(err, next, 'delete FIM policy', { policyId: req.params.id });
  }
};

// POST /api/fim/policies/:id/publish
export const publishPolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'manage');
    const result = await svc.publishPolicy(db, existing.id, auditActor(req));
    audit(req, 'FIM_POLICY_PUBLISH', { policyId: existing.id, name: existing.name, ...result });
    const policy = await svc.fetchPolicy(db, existing.id);
    return res.json({ ...result, warnings: policy ? fimPathWarnings(policy.paths, policy.osPlatform) : [], policy: policy ? { ...policy, canManage: true } : null });
  } catch (err) {
    return handleErr(err, next, 'publish FIM policy', { policyId: req.params.id });
  }
};

// GET /api/fim/catalog?platform=linux|windows  (metadata only; SQL never leaves the server)
export const listCatalog = (req: Request, res: Response, next: NextFunction) => {
  try {
    const platform = optStr(req.query.platform, 10);
    if (platform && platform !== 'linux' && platform !== 'windows') throw new CustomError(400, 'Validation', 'platform must be linux or windows');
    const items = catalogMetadata(platform as 'linux' | 'windows' | undefined);
    return res.json({ items, total: items.length });
  } catch (err) {
    return handleErr(err, next, 'list FIM catalog');
  }
};

// GET /api/fim/templates
export const listTemplates = (_req: Request, res: Response) => res.json({ items: FIM_TEMPLATES, total: FIM_TEMPLATES.length });

// POST /api/fim/policies/:id/initialize  {hosts?: string[], note}
// A baseline is created or replaced ONLY here (or by approving drift).
export const initializeBaseline = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'manage');
    const { hosts, note, entries, force } = req.body ?? {};
    if (entries !== undefined && entries !== null && (!Array.isArray(entries) || entries.length === 0 || entries.length > 500 || entries.some((k: unknown) => !Number.isSafeInteger(k) || (k as number) < 0))) {
      throw new FimValidationError('entries must be a non-empty array of entry (slot) indices');
    }
    if (force !== undefined && typeof force !== 'boolean') throw new FimValidationError('force must be a boolean');
    if (typeof note !== 'string' || note.trim() === '' || note.length > 2000) throw new CustomError(400, 'Validation', 'A note (at most 2000 characters) is required to initialize baselines');
    if (hosts !== undefined && hosts !== null) {
      if (!Array.isArray(hosts) || hosts.length > svc.FIM_INIT_MAX_HOSTS || hosts.some((h: unknown) => typeof h !== 'string' || h.length === 0 || h.length > 40)) {
        throw new FimValidationError(`hosts must be an array of at most ${svc.FIM_INIT_MAX_HOSTS} host_identifier strings`);
      }
      if (ctx.actHosts && hosts.some((h: string) => !ctx.actHosts!.includes(h))) {
        throw new CustomError(403, 'General', 'You do not have access to one or more of these hosts');
      }
    }
    const jwt = getJwt(req);
    const result = await svc.initializeBaseline(db, existing.id, {
      hosts: hosts ?? null, note: note.trim(), requestedBy: jwt?.email ?? null, requestedByUserId: auditActor(req).userId, visibleHosts: ctx.actHosts,
      entries: entries ?? null, force: force === true,
    });
    audit(req, 'FIM_BASELINE_INIT', { policyId: existing.id, note: note.trim(), batchId: result.batchId, entries: entries ?? null, force: force === true, hosts: result.hosts, requests: result.requests, superseded: result.superseded, skipped: result.skipped.length });
    return res.json({ status: 'Success', ...result });
  } catch (err) {
    return handleErr(err, next, 'initialize FIM baselines', { policyId: req.params.id });
  }
};

// GET /api/fim/policies/:id/initialization
export const getInitialization = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'view');
    const status = optStr(req.query.status, 20);
    if (status && !['none', 'pending', 'partial', 'done', 'failed'].includes(status)) throw new CustomError(400, 'Validation', 'Invalid status');
    const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
    return res.json(await svc.getInitialization(db, existing.id, ctx.viewHosts, { status, q: optStr(req.query.q, 200) }, page, pageSize));
  } catch (err) {
    return handleErr(err, next, 'get FIM initialization status', { policyId: req.params.id });
  }
};

// GET /api/fim/baseline/versions
export const listBaselineVersions = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const policy = req.query.policy === undefined || req.query.policy === '' ? null : parseId(req.query.policy, 'policy');
    const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
    return res.json(await svc.listBaselineVersions(getFleetDb(), { policy, host: optStr(req.query.host, 100) }, ctx.viewHosts, page, pageSize));
  } catch (err) {
    return handleErr(err, next, 'list FIM baseline versions');
  }
};

const STATUSES = ['open', 'approved', 'rejected', 'ignored'];

/** `expected` (approve): {"<driftId>": {newSha256, changeType, lastSeenAt}} = what the analyst reviewed. */
function parseExpected(raw: unknown): Record<string, svc.ExpectedDrift> | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new FimValidationError('expected must be an object keyed by drift id');
  const out: Record<string, svc.ExpectedDrift> = {};
  const entries = Object.entries(raw as Record<string, any>);
  if (entries.length > svc.FIM_RESOLVE_MAX_IDS) throw new FimValidationError('too many expected entries');
  for (const [k, v] of entries) {
    if (!/^[0-9]{1,15}$/.test(k) || !v || typeof v !== 'object') throw new FimValidationError('expected entries must be {contentHash} keyed by drift id');
    // Content-only guard: lastSeenAt / occurrences (bumped by every rescan) are ignored if sent.
    if (typeof v.contentHash !== 'string' || !/^[0-9a-f]{64}$/.test(v.contentHash)) throw new FimValidationError('expected.contentHash must be the contentHash of the reviewed drift');
    out[k] = { contentHash: v.contentHash };
  }
  return out;
}
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

// GET /api/fim/drift
export const listDrift = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const status = optStr(req.query.status, 20);
    const severity = optStr(req.query.severity, 20);
    if (status && !STATUSES.includes(status)) throw new CustomError(400, 'Validation', `status must be one of ${STATUSES.join(', ')}`);
    if (severity && !SEVERITIES.includes(severity)) throw new CustomError(400, 'Validation', `severity must be one of ${SEVERITIES.join(', ')}`);
    const policy = req.query.policy === undefined || req.query.policy === '' ? null : parseId(req.query.policy, 'policy');
    const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
    const out = await svc.listDrift(getFleetDb(), {
      status, severity, host: optStr(req.query.host, 100), policy, q: optStr(req.query.q, 200),
    }, ctx.viewHosts, page, pageSize);
    return res.json(out);
  } catch (err) {
    return handleErr(err, next, 'list FIM drift');
  }
};

// GET /api/fim/drift/:id
export const getDrift = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const d = await svc.getDrift(getFleetDb(), parseId(req.params.id, 'drift id'), ctx.viewHosts);
    if (!d) throw new CustomError(404, 'General', 'Drift not found');
    return res.json(d);
  } catch (err) {
    return handleErr(err, next, 'get FIM drift');
  }
};

// POST /api/fim/drift/resolve
export const resolveDrift = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { ids, action, note, acceptUnverified, atomic } = req.body ?? {};
    const expected = parseExpected(req.body?.expected);
    if (!Array.isArray(ids) || ids.length === 0) throw new FimValidationError('ids must be a non-empty array');
    if (ids.length > svc.FIM_RESOLVE_MAX_IDS) throw new FimValidationError(`at most ${svc.FIM_RESOLVE_MAX_IDS} ids per request`);
    const clean = Array.from(new Set(ids.map((i: unknown) => {
      const n = typeof i === 'number' ? i : Number(i);
      if (!Number.isSafeInteger(n) || n <= 0) throw new FimValidationError('ids must be positive integers');
      return n;
    })));
    if (!['approve', 'reject', 'ignore'].includes(action)) throw new FimValidationError('action must be approve, reject or ignore');
    if (note !== undefined && note !== null && (typeof note !== 'string' || note.length > 2000)) throw new FimValidationError('note must be a string of at most 2000 characters');
    if ((action === 'approve' || action === 'reject') && (typeof note !== 'string' || note.trim() === '')) {
      throw new CustomError(400, 'Validation', 'A note is required to approve or reject drift');
    }
    if (acceptUnverified !== undefined && typeof acceptUnverified !== 'boolean') throw new FimValidationError('acceptUnverified must be a boolean');
    if (atomic !== undefined && typeof atomic !== 'boolean') throw new FimValidationError('atomic must be a boolean');
    const ctx = await getCtx(req);
    const jwt = getJwt(req);
    const db = getFleetDb();
    // A scoped caller may resolve drift only for policies they can manage (all
    // targets inside their act scope); org-wide policies stay read-only for them.
    let policyFilter: number[] | null = null;
    if (!ctx.scope.unrestricted) {
      const email = jwt?.email;
      policyFilter = (await svc.fetchAllPolicies(db, false)).filter((p) => canManage(ctx, p, email)).map((p) => p.id);
    }
    const out = await svc.resolveDrift(db, clean, action, jwt?.email ?? null, note ?? null, ctx.actHosts, policyFilter, { acceptUnverified: acceptUnverified === true, expected, atomic: atomic === true, actorUserId: auditActor(req).userId });
    audit(req, 'FIM_DRIFT_RESOLVE', { action, acceptUnverified: acceptUnverified === true, note: note ?? null, requested: clean.length, resolved: out.resolved, skipped: out.skipped, ids: out.ids.slice(0, 100) });
    return res.json({ status: 'Success', resolved: out.resolved, skipped: out.skipped, results: out.results });
  } catch (err) {
    return handleErr(err, next, 'resolve FIM drift');
  }
};

const VERDICTS = ['true_positive', 'false_positive'];

async function alertActor(req: Request, ctx: Ctx, db: svc.FimDb): Promise<svc.AlertActor> {
  const jwt = getJwt(req);
  let policyFilter: number[] | null = null;
  if (!ctx.scope.unrestricted) {
    policyFilter = (await svc.fetchAllPolicies(db, false)).filter((p) => canManage(ctx, p, jwt?.email)).map((p) => p.id);
  }
  const a = auditActor(req);
  return { hostFilter: ctx.actHosts, groupIds: actableGroupIds(ctx.scope), policyFilter, user: jwt?.email ?? null, userId: a.userId, requestId: a.requestId, superAdmin: ctx.scope.unrestricted };
}

function parseAlertIds(ids: unknown): number[] {
  if (!Array.isArray(ids) || ids.length === 0) throw new FimValidationError('ids must be a non-empty array');
  if (ids.length > svc.FIM_RESOLVE_MAX_IDS) throw new FimValidationError(`at most ${svc.FIM_RESOLVE_MAX_IDS} ids per request`);
  return Array.from(new Set(ids.map((i: unknown) => {
    const n = typeof i === 'number' ? i : Number(i);
    if (!Number.isSafeInteger(n) || n <= 0) throw new FimValidationError('ids must be positive integers');
    return n;
  })));
}

// GET /api/fim/alerts
export const listAlerts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const status = optStr(req.query.status, 10) ?? 'open';
    if (!['open', 'closed', 'all'].includes(status)) throw new CustomError(400, 'Validation', 'status must be open, closed or all');
    const verdict = optStr(req.query.verdict, 20);
    if (verdict && ![...VERDICTS, 'unmarked'].includes(verdict)) throw new CustomError(400, 'Validation', 'Invalid verdict');
    const severity = optStr(req.query.severity, 20);
    if (severity && !SEVERITIES.includes(severity.toLowerCase())) throw new CustomError(400, 'Validation', 'Invalid severity');
    const type = optStr(req.query.type, 10);
    if (type && !['drift', 'health', 'config'].includes(type)) throw new CustomError(400, 'Validation', 'type must be drift, health or config');
    const unrestricted = ctx.scope.unrestricted;
    const policy = req.query.policy === undefined || req.query.policy === '' ? null : parseId(req.query.policy, 'policy');
    const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
    return res.json(await svc.listAlerts(getFleetDb(), { status, verdict, severity, type, policy, host: optStr(req.query.host, 100), q: optStr(req.query.q, 200) }, ctx.viewHosts, page, pageSize, unrestricted,
      { user: getJwt(req)?.email ?? null, userId: Number.isSafeInteger(Number(getJwt(req)?.id)) ? Number(getJwt(req)?.id) : null }));
  } catch (err) {
    return handleErr(err, next, 'list FIM alerts');
  }
};

// POST /api/fim/alerts/close  {ids, verdict, note, approveChange?, acceptUnverified?}
export const closeAlerts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { ids, verdict, note, approveChange, acceptUnverified, atomic } = req.body ?? {};
    const expected = parseExpected(req.body?.expected);
    const clean = parseAlertIds(ids);
    if (!VERDICTS.includes(verdict)) throw new FimValidationError('verdict must be true_positive or false_positive');
    if (typeof note !== 'string' || note.trim() === '' || note.length > 2000) throw new CustomError(400, 'Validation', 'A note (at most 2000 characters) is required to close alerts');
    for (const [k, v] of [['approveChange', approveChange], ['acceptUnverified', acceptUnverified], ['atomic', atomic]] as const) {
      if (v !== undefined && typeof v !== 'boolean') throw new FimValidationError(`${k} must be a boolean`);
    }
    if (approveChange && verdict !== 'false_positive') throw new FimValidationError('approveChange is only valid for false positives');
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const actor = await alertActor(req, ctx, db);
    const out = await svc.closeAlerts(db, clean, verdict, note.trim(), actor, { approveChange: approveChange === true, acceptUnverified: acceptUnverified === true, expected, atomic: atomic === true });
    audit(req, 'FIM_ALERT_CLOSE', { verdict, note: note.trim(), approveChange: approveChange === true, acceptUnverified: acceptUnverified === true, requested: clean.length, closed: out.closed, skipped: out.skipped, ids: out.ids.slice(0, 100) });
    return res.json({ status: 'Success', closed: out.closed, skipped: out.skipped, results: out.results });
  } catch (err) {
    return handleErr(err, next, 'close FIM alerts');
  }
};

// POST /api/fim/alerts/reopen  {ids, note?}
export const reopenAlerts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { ids, note } = req.body ?? {};
    const clean = parseAlertIds(ids);
    if (note !== undefined && note !== null && (typeof note !== 'string' || note.length > 2000)) throw new FimValidationError('note must be a string of at most 2000 characters');
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const out = await svc.reopenAlerts(db, clean, await alertActor(req, ctx, db), typeof note === 'string' ? note : null);
    audit(req, 'FIM_ALERT_REOPEN', { note: note ?? null, requested: clean.length, reopened: out.reopened, skipped: out.skipped, ids: out.ids.slice(0, 100) });
    return res.json({ status: 'Success', reopened: out.reopened, skipped: out.skipped });
  } catch (err) {
    return handleErr(err, next, 'reopen FIM alerts');
  }
};

// GET /api/fim/baseline
export const listBaseline = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const policy = req.query.policy === undefined || req.query.policy === '' ? null : parseId(req.query.policy, 'policy');
    const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
    const kind = optStr(req.query.kind, 10);
    if (kind && !['file', 'directory', 'item'].includes(kind)) throw new CustomError(400, 'Validation', 'kind must be file, directory or item');
    const out = await svc.listBaseline(getFleetDb(), { policy, host: optStr(req.query.host, 100), q: optStr(req.query.q, 200), kind }, ctx.viewHosts, page, pageSize);
    return res.json(out);
  } catch (err) {
    return handleErr(err, next, 'list FIM baseline');
  }
};

// GET /api/fim/summary
export const getSummary = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    return res.json(await svc.getSummary(getFleetDb(), ctx.viewHosts));
  } catch (err) {
    return handleErr(err, next, 'get FIM summary');
  }
};

// POST /api/fim/policies/:id/upgrade-template {note}  (template v2; rev bump, Initialize afterwards)
export const upgradeTemplate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const db = getFleetDb();
    const existing = await loadPolicy(req, ctx, db, 'manage');
    assertNotManaged(existing);
    const { note } = req.body ?? {};
    if (typeof note !== 'string' || note.trim() === '' || note.length > 2000) throw new CustomError(400, 'Validation', 'A note (at most 2000 characters) is required');
    const out = await svc.upgradePolicyTemplate(db, existing.id);
    audit(req, 'FIM_POLICY_TEMPLATE_UPGRADE', { policyId: existing.id, template: existing.template, note: note.trim(), rev: out.policy.rev, published: !!out.published });
    return res.json({ ...withWarnings(out.policy), canManage: true });
  } catch (err) {
    return handleErr(err, next, 'upgrade FIM policy template', { policyId: req.params.id });
  }
};

// POST /api/fim/drift/:id/recheck  (queue a check scan for a real-time registry drift)
export const recheckDrift = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ctx = await getCtx(req);
    const id = parseId(req.params.id, 'drift id');
    const out = await svc.recheckDrift(getFleetDb(), id, ctx.actHosts);
    audit(req, 'FIM_DRIFT_RESOLVE', { op: 'recheck', driftId: id, queued: out.queued });
    return res.json({ status: 'Success', ...out });
  } catch (err) {
    return handleErr(err, next, 'queue FIM check scan', { driftId: req.params.id });
  }
};
