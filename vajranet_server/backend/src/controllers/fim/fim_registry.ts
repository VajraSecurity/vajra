/**
 * /api/fim/registry/* : per-node Windows registry coverage (docs/FIM_REGISTRY_DESIGN.md §3.13,
 * §4.1). Same middleware as the rest of /api/fim (JWT, Super Admin or Group Admin, rate limits,
 * CSRF on writes). Authorisation happens in the service against the caller's scope as resolved
 * on THIS request (RegActor); every mutation is audited with a request id that also goes into
 * the hash-chained fim_reg_history.
 */
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { dbSourceConnection } from '../../index';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { AuditTrail, AuditTrailAction } from '../../orm/entities/audit/AuditTrail';
import {
  getUserNodeScope, getScopedHostIdentifiers, getActableHostIdentifiers, actableGroupIds, scopeGroupIds, NodeScope,
} from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { FimValidationError } from '../../utils/fim/fimLogic';
import { FIM_REG_CAPS } from '../../utils/fim/fimRegistryResolver';
import * as svc from '../../services/fimService';
import * as reg from '../../services/fimRegistryService';

const logger = getLogger('controllers.fimRegistry');

function getFleetDb(): svc.FimDb {
  const db = dbSourceConnection()?.[1];
  if (!db) throw new CustomError(500, 'Database', 'Fleet database connection not available');
  return db as unknown as svc.FimDb;
}
const getJwt = (req: Request) => (req as any).jwtPayload as JwtPayload | undefined;

async function actorOf(req: Request): Promise<reg.RegActor> {
  const jwt = getJwt(req);
  const scope: NodeScope = jwt?.id ? await getUserNodeScope(jwt.id) : { unrestricted: false, groups: [] };
  const hdr = req.headers['x-request-id'];
  const requestId = typeof hdr === 'string' && /^[A-Za-z0-9._-]{1,100}$/.test(hdr) ? hdr : randomUUID();
  const userId = Number.isSafeInteger(Number(jwt?.id)) ? Number(jwt?.id) : null;
  const settings = await reg.getSettings(getFleetDb());
  // Designated AND currently an active admin account (re-checked on every request: a suspended or
  // demoted user loses approver rights at once).
  const designated = userId !== null && settings.approvers.some((a) => a.userId === userId);
  const u = designated ? (await dbSourceConnection()?.[0]?.query(`SELECT role, suspended FROM vajra_users WHERE id = $1`, [userId]))?.[0] : null;
  const isApprover = reg.isActiveApprover(userId, settings.approvers, u);
  if (scope.unrestricted) {
    return { email: jwt?.email ?? null, userId, isApprover, superAdmin: true, actGroups: new Set(), actHosts: null, viewHosts: null, viewGroups: new Set(), requestId };
  }
  const [viewHosts, actHosts] = await Promise.all([getScopedHostIdentifiers(scope), getActableHostIdentifiers(scope)]);
  return {
    email: jwt?.email ?? null, userId, isApprover, superAdmin: false, actGroups: new Set(actableGroupIds(scope)), actHosts: new Set(actHosts ?? []),
    viewHosts: new Set(viewHosts ?? []), viewGroups: new Set(scopeGroupIds(scope)), requestId,
  };
}

/**
 * Head of the history chain as last anchored in the audit trail (primary database, outside the
 * fleet DB holding fim_reg_history). Used by verification to detect tail truncation / rewrites.
 */
export const historyAnchor: reg.HistoryAnchorFn = async () => {
  const primary = dbSourceConnection()?.[0];
  // No primary database = the anchor store is unavailable (verification reports 'unverifiable').
  if (!primary) throw new Error('primary database (audit trail) not available');
  const rows = await primary.query(
    // The anchor is the head with the LARGEST history id (not the newest audit row: after-commit
    // audit rows and anchor writes can land out of order).
    `SELECT details->'historyHead' AS h FROM audit_trail WHERE action LIKE 'FIM_REG_%' AND details ? 'historyHead'
       AND (details->'historyHead'->>'id') ~ '^[0-9]{1,18}$' ORDER BY (details->'historyHead'->>'id')::bigint DESC LIMIT 1`);
  const h = rows?.[0]?.h;
  return h && Number.isSafeInteger(Number(h.id)) ? { id: Number(h.id), rowHash: String(h.rowHash), count: Number(h.count) } : null;
};

/**
 * Writes a history head into the audit trail (primary database). Unlike logAuditTrail it THROWS on
 * failure, so the outbox row stays pending and is retried (by the next mutation or the reconcile job).
 */
export const historyAnchorWriter: reg.AnchorWriter = async (head) => {
  const primary = dbSourceConnection()?.[0];
  if (!primary) throw new Error('primary database not available');
  const repo = primary.getRepository(AuditTrail);
  await repo.save(repo.create({ action: 'FIM_REG_ANCHOR', status: 'success', userId: null, email: 'system', details: { historyHead: head } }));
};
const lastFullVerify = { at: 0 };
function flushAnchors(): void {
  reg.flushHistoryAnchors(getFleetDb(), historyAnchorWriter).catch((err) => logger.error({ err }, 'FIM registry history anchor write failed (will retry)'));
}

function handleErr(err: unknown, next: NextFunction, what: string, extra?: Record<string, unknown>) {
  if (err instanceof CustomError) return next(err);
  if (err instanceof FimValidationError) return next(new CustomError(422, 'Validation', err.message));
  if (err instanceof reg.FimForbiddenError) return next(new CustomError(403, 'General', err.message));
  if (err instanceof reg.FimUnavailableError) return next(new CustomError(503, 'General', err.message, [err.code]));
  if (err instanceof reg.FimRateLimitError) return next(new CustomError(429, 'General', err.message));
  if (err instanceof svc.FimNotFoundError) return next(new CustomError(404, 'General', err.message));
  if (err instanceof svc.FimBadRequestError) return next(new CustomError(400, 'Validation', err.message));
  if (err instanceof svc.FimConflictError) return next(new CustomError(409, 'General', err.message));
  logger.error({ err, ...extra }, `Failed to ${what}`);
  return next(new CustomError(500, 'Raw', `Failed to ${what}`, null, err));
}

function audit(req: Request, actor: reg.RegActor, action: AuditTrailAction, details: Record<string, unknown>, status: 'success' | 'failure' = 'success') {
  const jwt = getJwt(req);
  logAuditTrail({
    action, status, userId: jwt?.id ?? null, email: jwt?.email ?? null, ipAddress: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null,
    details: { requestId: actor.requestId, role: actor.superAdmin ? 'super_admin' : 'group_admin', ...details },
  }).catch((err) => logger.error({ err }, 'Failed to log audit trail'));
  if (details.historyHead) flushAnchors();
}

function parseId(raw: unknown, what = 'id'): number {
  const s = String(raw);
  if (!/^[0-9]{1,15}$/.test(s)) throw new CustomError(400, 'Validation', `Invalid ${what}`);
  return Number(s);
}
function hostParam(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length < 1 || raw.length > 40) throw new CustomError(400, 'Validation', 'Invalid host identifier');
  return raw;
}
function optStr(v: unknown, max = 255): string | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || v.length > max) throw new CustomError(400, 'Validation', 'Invalid query parameter');
  return v;
}
function note(v: unknown, required = true): string {
  if (v === undefined || v === null || v === '') { if (required) throw new CustomError(400, 'Validation', 'A note (at most 2000 characters) is required'); return ''; }
  if (typeof v !== 'string' || v.length > 2000 || (required && !v.trim())) throw new CustomError(400, 'Validation', 'A note (at most 2000 characters) is required');
  return v.trim();
}

const wrap = (what: string, fn: (req: Request, res: Response, actor: reg.RegActor) => Promise<unknown>) =>
  async (req: Request, res: Response, next: NextFunction) => {
    let actor: reg.RegActor | null = null;
    try {
      actor = await actorOf(req);
      await fn(req, res, actor);
    } catch (err) {
      // Denied privileged attempts are audited too (fleet-DB outbox + audit trail).
      const denied = err instanceof reg.FimForbiddenError || err instanceof svc.FimConflictError || err instanceof FimValidationError || err instanceof reg.FimRateLimitError;
      if (denied && actor && req.method !== 'GET') {
        const details = { what, method: req.method, path: req.path, error: (err as Error).message.slice(0, 500) };
        reg.auditTx(getFleetDb(), actor, 'FIM_REG_DENIED', details, 'denied').catch((e) => logger.error({ err: e }, 'denied-attempt audit failed'));
        audit(req, actor, 'FIM_REG_DENIED', details, 'failure');
      }
      handleErr(err, next, what, { params: req.params });
    }
  };

// ---- settings / catalog
const settingsView = async (actor: reg.RegActor) => {
  const s = await reg.getSettings(getFleetDb());
  return { ...s, catalogVersion: reg.catalogView().version, limits: reg.regLimits(), isSuperAdmin: actor.superAdmin, canApproveWaivers: actor.superAdmin || !!actor.isApprover };
};
export const getSettings = wrap('get registry settings', async (_req, res, actor) => { res.json(await settingsView(actor)); });

// GET /registry/approver-candidates (Super Admin): admins who can be designated waiver approvers.
export const approverCandidates = wrap('list approver candidates', async (_req, res, actor) => {
  if (!actor.superAdmin) throw new CustomError(403, 'General', 'Only a Super Administrator can designate waiver approvers');
  const primary = dbSourceConnection()?.[0];
  if (!primary) throw new CustomError(500, 'Database', 'Primary database not available');
  const rows = await primary.query(`SELECT id, email, role FROM vajra_users WHERE role IN ('Super Administrator', 'Group Admin') ORDER BY email LIMIT 1000`);
  res.json({ items: rows.map((r: any) => ({ userId: Number(r.id), email: r.email, role: r.role })) });
});

// PUT /registry/settings/approvers {userIds, note} (Super Admin)
export const putApprovers = wrap('update waiver approvers', async (req, res, actor) => {
  const ids = req.body?.userIds;
  if (!Array.isArray(ids) || ids.length > 50 || ids.some((x: unknown) => !Number.isSafeInteger(x) || (x as number) <= 0)) throw new FimValidationError('userIds must be an array of at most 50 user ids');
  const n = note(req.body?.note);
  const primary = dbSourceConnection()?.[0];
  if (!primary) throw new CustomError(500, 'Database', 'Primary database not available');
  const rows = ids.length ? await primary.query(`SELECT id, email FROM vajra_users WHERE id = ANY($1::int[]) AND role IN ('Super Administrator', 'Group Admin')`, [ids]) : [];
  if (rows.length !== new Set(ids).size) throw new FimValidationError('every approver must be an existing Super Administrator or Group Admin');
  const out = await reg.setApprovers(getFleetDb(), rows.map((r: any) => ({ userId: Number(r.id), email: r.email })), actor, n);
  audit(req, actor, 'FIM_REG_SETTINGS', { op: 'approvers', before: out.before, after: out.after, note: n, historyHead: out.historyHead });
  res.json(await settingsView(actor));
});
export const putSettings = wrap('update registry settings', async (req, res, actor) => {
  const { managedEnabled, confirm } = req.body ?? {};
  if (typeof managedEnabled !== 'boolean') throw new FimValidationError('managedEnabled must be a boolean');
  if (confirm !== true) throw new FimValidationError('confirm=true is required (this changes registry coverage on every Windows node)');
  const n = note(req.body?.note);
  const out = await reg.setManagedEnabled(getFleetDb(), managedEnabled, actor, n);
  audit(req, actor, 'FIM_REG_SETTINGS', { before: out.before, after: out.after, disabledPolicies: out.disabledPolicies, note: n, historyHead: out.historyHead });
  res.json(await settingsView(actor));
});
export const getCatalog = wrap('get registry catalog', async (_req, res) => { res.json(reg.catalogView()); });

// ---- profiles
export const listProfiles = wrap('list registry profiles', async (_req, res, actor) => { res.json({ items: await reg.listProfiles(getFleetDb(), actor) }); });
export const getProfile = wrap('get registry profile', async (req, res, actor) => {
  const id = parseId(req.params.id, 'profile id');
  const p = (await reg.listProfiles(getFleetDb(), actor)).find((x) => x.id === id);
  if (!p) throw new CustomError(404, 'General', 'Profile not found');
  res.json(p);
});
export const createProfile = wrap('create registry profile', async (req, res, actor) => {
  const input = reg.validateProfileInput(req.body);
  const out = await reg.saveProfile(getFleetDb(), null, input, actor);
  audit(req, actor, 'FIM_REG_PROFILE_CHANGE', { op: 'create', profileId: out.profile.id, after: out.profile, reason: input.reason, historyHead: out.historyHead });
  res.status(201).json((await reg.listProfiles(getFleetDb(), actor)).find((x) => x.id === out.profile.id));
});
export const updateProfile = wrap('update registry profile', async (req, res, actor) => {
  const id = parseId(req.params.id, 'profile id');
  const input = reg.validateProfileInput(req.body);
  const out = await reg.saveProfile(getFleetDb(), id, input, actor);
  audit(req, actor, 'FIM_REG_PROFILE_CHANGE', { op: 'update', profileId: id, before: out.before, after: out.profile, reason: input.reason, historyHead: out.historyHead });
  res.json((await reg.listProfiles(getFleetDb(), actor)).find((x) => x.id === id));
});
export const deleteProfile = wrap('delete registry profile', async (req, res, actor) => {
  const id = parseId(req.params.id, 'profile id');
  const reason = note(req.body?.reason, false);
  const out = await reg.deleteProfile(getFleetDb(), id, actor, reason);
  audit(req, actor, 'FIM_REG_PROFILE_CHANGE', { op: 'delete', profileId: id, name: out.name, reason, historyHead: out.historyHead });
  res.json({ status: 'Success' });
});

// ---- assignments
export const listAssignments = wrap('list registry assignments', async (req, res, actor) => {
  const scopeType = optStr(req.query.scope_type, 10);
  if (scopeType && !['group', 'node'].includes(scopeType)) throw new CustomError(400, 'Validation', 'scope_type must be group or node');
  res.json({ items: await reg.listAssignments(getFleetDb(), { scopeType, scopeValue: optStr(req.query.scope_value) }, actor) });
});
export const putAssignment = wrap('update registry assignment', async (req, res, actor) => {
  const scopeType = req.params.scopeType;
  if (scopeType !== 'group' && scopeType !== 'node') throw new CustomError(400, 'Validation', 'scope type must be group or node');
  const scopeValue = String(req.params.scopeValue ?? '');
  if (!scopeValue || scopeValue.length > 255) throw new CustomError(400, 'Validation', 'Invalid scope value');
  const out = await reg.putAssignment(getFleetDb(), scopeType, scopeValue, req.body ?? {}, actor);
  audit(req, actor, 'FIM_REG_ASSIGN', { scopeType, scopeValue, before: out.before, after: out.after, reason: req.body?.reason ?? null, historyHead: out.historyHead });
  res.json(out.after);
});

// ---- rules
export const listRules = wrap('list registry rules', async (req, res, actor) => {
  const layer = optStr(req.query.layer, 10) as any;
  if (layer && !['profile', 'group', 'node'].includes(layer)) throw new CustomError(400, 'Validation', 'layer must be profile, group or node');
  res.json({ items: await reg.listRules(getFleetDb(), { layer, scopeValue: optStr(req.query.scope_value) }, actor) });
});
export const createRule = wrap('create registry rule', async (req, res, actor) => {
  const out = await reg.createRule(getFleetDb(), req.body, actor);
  audit(req, actor, 'FIM_REG_RULE_ADD', { rule: out.rule, historyHead: out.historyHead });
  res.status(201).json(out.rule);
});
export const revokeRule = wrap('revoke registry rule', async (req, res, actor) => {
  const id = parseId(req.params.id, 'rule id');
  const reason = note(req.body?.reason, false);
  const out = await reg.revokeRule(getFleetDb(), id, actor, reason);
  audit(req, actor, 'FIM_REG_RULE_REVOKE', { rule: out.rule, reason, historyHead: out.historyHead });
  res.json({ status: 'Success' });
});

// ---- waivers
export const listWaivers = wrap('list registry waivers', async (req, res, actor) => {
  const status = optStr(req.query.status, 20);
  if (status && !['pending', 'approved', 'rejected', 'revoked', 'expired'].includes(status)) throw new CustomError(400, 'Validation', 'Invalid status');
  res.json({ items: await reg.listWaivers(getFleetDb(), { status, scopeType: optStr(req.query.scope_type, 10), scopeValue: optStr(req.query.scope_value) }, actor) });
});
export const requestWaiver = wrap('request registry waiver', async (req, res, actor) => {
  const w = await reg.requestWaiver(getFleetDb(), req.body, actor);
  audit(req, actor, 'FIM_REG_WAIVER_REQUEST', { waiver: w });
  res.status(201).json(w);
});
const decide = (decision: 'approve' | 'reject' | 'revoke') => wrap(`${decision} registry waiver`, async (req, res, actor) => {
  const id = parseId(req.params.id, 'waiver id');
  const n = note(req.body?.note, decision !== 'approve');
  const db = getFleetDb();
  const w = await reg.decideWaiver(db, id, decision, n, actor);
  audit(req, actor, 'FIM_REG_WAIVER_DECISION', { waiverId: id, decision, status: w.status, note: n, rule: w.rule });
  if (decision === 'revoke') {
    // Restore protected coverage at once on every node whose published config relies on it
    // (the reconcile job also does this persistently, without a budget).
    for (const h of await reg.hostsUsingWaiver(db, id)) {
      try {
        const r = await reg.publishNode(db, h, { actor: reg.systemActor(actor.requestId), note: `waiver #${id} revoked`, auto: 'waiver_revoked' });
        audit(req, actor, 'FIM_REG_AUTO_REPUBLISH', { host: h, reason: 'waiver_revoked', waiverId: id, status: r.status, rev: r.rev });
        if (r.status === 'invalid' && !r.error?.startsWith('fail-safe')) logger.error({ host: h, waiverId: id, error: r.error }, 'republish after waiver revoke left the node invalid');
      } catch (err) {
        logger.error({ err, host: h, waiverId: id }, 'republish after waiver revoke failed (the reconcile job retries)');
      }
    }
  }
  res.json(w);
});

// POST /registry/waivers/:id/apply {note}: create the waiver's bound rule (once).
export const applyWaiver = wrap('apply registry waiver', async (req, res, actor) => {
  const id = parseId(req.params.id, 'waiver id');
  const n = note(req.body?.note, false);
  const out = await reg.applyWaiver(getFleetDb(), id, actor, n);
  audit(req, actor, 'FIM_REG_RULE_ADD', { waiverId: id, rule: out.rule, historyHead: out.historyHead });
  res.status(201).json(out.rule);
});
export const approveWaiver = decide('approve');
export const rejectWaiver = decide('reject');
export const revokeWaiver = decide('revoke');

// ---- nodes / groups
export const listNodes = wrap('list registry nodes', async (req, res, actor) => {
  const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
  const status = optStr(req.query.status, 20);
  if (status && !['in_sync', 'pending', 'needs_init', 'invalid', 'unmanaged'].includes(status)) throw new CustomError(400, 'Validation', 'Invalid status');
  res.json(await reg.listNodes(getFleetDb(), { q: optStr(req.query.q, 200), status, group: optStr(req.query.group) }, actor, page, pageSize));
});
export const getNode = wrap('get registry coverage', async (req, res, actor) => { res.json(await reg.getNodeCoverage(getFleetDb(), hostParam(req.params.host), actor)); });
export const previewNode = wrap('preview registry coverage', async (req, res, actor) => { res.json(await reg.previewNode(getFleetDb(), hostParam(req.params.host), req.body ?? {}, actor)); });
export const getGroup = wrap('get group registry coverage', async (req, res, actor) => {
  const gid = String(req.params.groupId ?? '');
  if (!gid || gid.length > 255) throw new CustomError(400, 'Validation', 'Invalid group id');
  res.json(await reg.getGroupCoverage(getFleetDb(), gid, actor));
});
export const needsInit = wrap('list registry nodes needing init', async (_req, res, actor) => { res.json({ items: await reg.listNeedsInit(getFleetDb(), actor) }); });

// ---- measure
export const measure = wrap('measure registry entries', async (req, res, actor) => {
  const host = hostParam(req.params.host);
  const items = await reg.requestMeasure(getFleetDb(), host, req.body?.entries, actor);
  audit(req, actor, 'FIM_REG_MEASURE', { host, entries: items.map((m) => m.entryKey) });
  res.json({ items });
});
export const getMeasure = wrap('get registry measurement', async (req, res, actor) => { res.json(await reg.getMeasure(getFleetDb(), parseId(req.params.id, 'measurement id'), actor)); });

// ---- publish / compact
export const publish = wrap('publish registry coverage', async (req, res, actor) => {
  const b = req.body ?? {};
  const n = note(b.note);
  if (b.hosts !== undefined && (!Array.isArray(b.hosts) || b.hosts.some((h: unknown) => typeof h !== 'string' || !h || (h as string).length > 40))) throw new FimValidationError('hosts must be an array of host identifiers');
  if (b.group !== undefined && (typeof b.group !== 'string' || !b.group || b.group.length > 255)) throw new FimValidationError('group must be a group id');
  if (b.profile !== undefined && (!Number.isSafeInteger(b.profile) || b.profile <= 0)) throw new FimValidationError('profile must be a profile id');
  if (b.expected !== undefined && (typeof b.expected !== 'object' || Array.isArray(b.expected) || b.expected === null)) throw new FimValidationError('expected must map host -> resolvedHash');
  if (b.hosts === undefined && b.group === undefined && b.profile === undefined) throw new FimValidationError('hosts, group or profile is required');
  const db = getFleetDb();
  if (b.profile !== undefined) {
    // Profile-wide publish: checked against the reviewed digest, then run as a background job
    // (chunked, resumable, one at a time) - poll GET /registry/jobs/:id for progress.
    if (b.hosts !== undefined || b.group !== undefined) throw new FimValidationError('a profile publish cannot be combined with hosts or group');
    // The reviewed digest is checked inside the job's creating transaction and re-checked per chunk.
    const job = await reg.startProfilePublishJob(db, b.profile, actor, n, b.expectedProfileDigest);
    void reg.runRegistryJob(db, job.id, (msg, extra) => logger.info({ ...extra }, msg));
    audit(req, actor, 'FIM_REG_JOB', { op: 'start', jobId: job.id, profile: b.profile, note: n });
    res.status(202).json({ job });
    return;
  }
  const hosts = await reg.publishTargets(db, b, actor);
  // An interactive single-node Apply must state what the user reviewed (stale view -> 409).
  // Interactive Apply must state what was reviewed for EVERY target host (stale view -> 409).
  // Group / profile publishes state the reviewed group hash / profile digest instead (checked below).
  if (b.group === undefined && b.profile === undefined) {
    const missing = hosts.filter((h) => typeof b.expected?.[h] !== 'string' || !b.expected[h]);
    if (missing.length) throw new FimValidationError(`expected (host -> resolvedHash of the reviewed coverage, non-empty) is required for every host: missing for ${missing.slice(0, 5).join(', ')}`);
  }
  // Group / profile Apply must also state what was reviewed (stale view -> 409 before anything is published).
  if (b.group !== undefined) {
    if (typeof b.expectedGroupHash !== 'string' || !b.expectedGroupHash) throw new FimValidationError('expectedGroupHash (resolvedHash of the reviewed group coverage) is required for a group publish');
    if (await reg.currentGroupHash(db, b.group) !== b.expectedGroupHash) throw new svc.FimConflictError('The coverage of this group changed since it was reviewed; reload and review it again');
  }
  if (b.profile !== undefined) {
    if (typeof b.expectedProfileDigest !== 'string' || !b.expectedProfileDigest) throw new FimValidationError('expectedProfileDigest (digest of the reviewed profile) is required for a profile publish');
    if (await reg.currentProfileDigest(db, b.profile) !== b.expectedProfileDigest) throw new svc.FimConflictError('This profile changed since it was reviewed; reload and review it again');
  }
  if (hosts.length > FIM_REG_CAPS.publishBatchMax) throw new FimValidationError(`at most ${FIM_REG_CAPS.publishBatchMax} nodes per request; publish in batches`);
  if (hosts.length > FIM_REG_CAPS.publishConfirmAbove && b.confirm !== true) throw new FimValidationError(`publishing ${hosts.length} nodes needs confirm=true`);
  const results: reg.PublishNodeResult[] = [];
  for (const h of hosts) {
    const exp = b.expected?.[h];
    try {
      results.push(await reg.publishNode(db, h, { actor, expectedHash: typeof exp === 'string' ? exp : null, note: n }));
    } catch (err) {
      // A single requested host: surface the real error (409 stale, 403, ...). In bulk: per-host result.
      if (hosts.length === 1) throw err;
      results.push({ host: h, status: 'invalid', policyId: null, rev: null, revChanged: false, needsInit: [], newSlots: [], retired: [], revived: [], error: (err as Error).message, blocked: 0, usedWaivers: [] });
    }
  }
  const failed = results.filter((r) => r.error).length;
  audit(req, actor, 'FIM_REG_PUBLISH', { note: n, hosts: hosts.length, failed, group: b.group ?? null, profile: b.profile ?? null, results: results.slice(0, 200).map((r) => ({ host: r.host, status: r.status, rev: r.rev, revChanged: r.revChanged, needsInit: r.needsInit, retired: r.retired, error: r.error })) });
  if (hosts.length > FIM_REG_CAPS.publishConfirmAbove) {
    await db.query(
      `INSERT INTO alerts (host_identifier, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, detection_time)
       VALUES (NULL, extract(epoch FROM now())::bigint, $1, $2, true, true, 'high', 'fim_config', 'File Integrity', '', '', extract(epoch FROM now())::bigint)`,
      [`FIM registry coverage published to ${hosts.length} nodes`, JSON.stringify({ fim_config: true, by: actor.email, requestId: actor.requestId, hosts: hosts.length })]);
  }
  res.json({ results, published: results.length - failed, failed });
});
// GET /registry/policy-problems (Super Admin): stored entries that can no longer be built
export const policyProblems = wrap('list unbuildable FIM policies', async (_req, res, actor) => {
  if (!actor.superAdmin) throw new CustomError(403, 'General', 'Super Administrators only');
  res.json({ items: await reg.listUnbuildablePolicies(getFleetDb()) });
});
// POST /registry/jobs/:id/cancel (Super Admin)
export const cancelJob = wrap('cancel registry job', async (req, res, actor) => {
  const id = parseId(req.params.id);
  const out = await reg.cancelJob(getFleetDb(), id, actor, note(req.body?.note, false) || null);
  audit(req, actor, 'FIM_REG_JOB', { op: 'cancel', jobId: id });
  res.json(out);
});
// GET /registry/jobs/:id (Super Admin): background job progress
export const getJob = wrap('get registry job', async (req, res, actor) => {
  res.json(await reg.getJob(getFleetDb(), parseId(req.params.id), actor));
});
export const compact = wrap('compact registry coverage', async (req, res, actor) => {
  const host = hostParam(req.params.host);
  const n = note(req.body?.note);
  const out = await reg.compactNode(getFleetDb(), host, actor, n);
  audit(req, actor, 'FIM_REG_COMPACT', { host, note: n, rev: out.rev, needsInit: out.needsInit });
  res.json(out);
});

// ---- history / rollback
export const history = wrap('list registry history', async (req, res, actor) => {
  const scopeType = optStr(req.query.scope_type, 10);
  const scopeValue = optStr(req.query.scope_value);
  if (!scopeType || !['profile', 'group', 'node', 'settings'].includes(scopeType) || !scopeValue) throw new CustomError(400, 'Validation', 'scope_type and scope_value are required');
  if (scopeType === 'node' && !reg.canViewHost(actor, scopeValue)) throw new CustomError(404, 'General', 'Not found');
  if (scopeType === 'group' && !reg.canViewGroup(actor, scopeValue)) throw new CustomError(404, 'General', 'Not found');
  if (scopeType === 'settings' && !actor.superAdmin) throw new CustomError(404, 'General', 'Not found');
  const { page, pageSize } = svc.clampPage(req.query.page, req.query.pageSize);
  // A full chain verification re-hashes every row: Super Admins only, at most once a minute
  // (others get the incremental check from the last verified prefix).
  let full = false;
  if (req.query.verify === 'full') {
    if (!actor.superAdmin) throw new CustomError(403, 'General', 'Only a Super Administrator can run a full history verification');
    if (Date.now() - lastFullVerify.at < 60_000) throw new CustomError(429, 'General', 'A full verification ran less than a minute ago; try again shortly');
    lastFullVerify.at = Date.now();
    full = true;
  }
  res.json(await reg.listHistory(getFleetDb(), scopeType, scopeValue, page, pageSize, { full, anchor: historyAnchor }));
});
export const rollback = wrap('roll back registry configuration', async (req, res, actor) => {
  const historyId = Number(req.body?.historyId);
  if (!Number.isSafeInteger(historyId) || historyId <= 0) throw new FimValidationError('historyId must be a positive integer');
  const n = note(req.body?.note);
  const out = await reg.rollback(getFleetDb(), historyId, actor, n);
  audit(req, actor, 'FIM_REG_ROLLBACK', { historyId, note: n, scopeType: out.scopeType, scopeValue: out.scopeValue, rules: out.rules, skipped: out.skipped, historyHead: out.historyHead });
  res.json({ status: out.status, rules: out.rules, skipped: out.skipped });
});

// ---- hygiene
export const hygiene = wrap('get baseline hygiene', async (req, res, actor) => { res.json({ items: await reg.getHygiene(getFleetDb(), hostParam(req.params.host), actor) }); });
export const ackHygiene = wrap('acknowledge hygiene finding', async (req, res, actor) => {
  const host = hostParam(req.params.host);
  const out = await reg.ackHygiene(getFleetDb(), host, req.body, actor);
  audit(req, actor, 'FIM_REG_HYGIENE_ACK', { host, ...out });
  res.json({ status: 'Success' });
});

// ---- migration assistant (Super Admin)
export const listLegacy = wrap('list legacy registry policies', async (_req, res, actor) => { res.json({ items: await reg.listLegacy(getFleetDb(), actor) }); });
export const applyLegacy = wrap('migrate legacy registry policy', async (req, res, actor) => {
  const id = parseId(req.params.policyId, 'policy id');
  const n = note(req.body?.note);
  const out = await reg.applyLegacy(getFleetDb(), id, actor, n);
  audit(req, actor, 'FIM_REG_MIGRATION', { op: 'apply', policyId: id, note: n, ...out });
  res.json(out);
});
export const removeLegacy = wrap('remove legacy registry entries', async (req, res, actor) => {
  const id = parseId(req.params.policyId, 'policy id');
  const n = note(req.body?.note);
  const out = await reg.removeLegacyRegistry(getFleetDb(), id, actor);
  audit(req, actor, 'FIM_REG_MIGRATION', { op: 'remove-registry', policyId: id, note: n, removed: out.removed, disabled: out.disabled });
  res.json({ removed: out.removed, policy: out.policy });
});
