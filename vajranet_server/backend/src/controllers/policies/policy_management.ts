import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { Policy } from '../../orm/entities/fleet/Policy';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import {
  getUserNodeScope,
  getScopedHostIdentifiers,
  getActableHostIdentifiers,
  actableGroupIds,
  scopeGroupIds,
  NodeScope,
} from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { dispatchToAgent, isHostConnected, getConnectedHostIdentifiers } from '../../websocket/node';
import { applyPolicyToConnectedTargets, reapplyEnabledPoliciesForHost } from '../../services/policyEnforcement';
import { PAGINATION_MAX_ROWS_ADMIN_ACTIVITY, PAGINATION_DEFAULT_ROWS } from '../../consts/pagination';

const logger = getLogger('controllers.policyManagement');

// Fire-and-forget: never let a policy push delay or fail the HTTP response.
// Only enabled policies are ever pushed — disabling/deleting intentionally
// does not send a reverting command (see policyEnforcement.ts doc comment).
function pushPolicyIfEnabled(policy: Policy): void {
  if (!policy.enabled) return;
  applyPolicyToConnectedTargets(policy, dispatchToAgent, isHostConnected).catch((err) =>
    logger.error({ err, policyId: policy.id }, 'Failed to push policy to connected targets'),
  );
}

// Periodic reconciliation sweep: a safety net for a mutation-time push
// (pushPolicyIfEnabled) or a reconnect push (nodeExt ->
// reapplyEnabledPoliciesForHost) that failed silently, re-applying every enabled
// policy to every connected host on a fixed interval. Same setInterval(...).unref()
// idiom as patch_management.ts's sweepStalePatchJobs, so it never blocks process
// shutdown. Deliberately sequential rather than Promise.all: nobody waits on a
// background maintenance pass, so there is no reason to burst concurrent queries.
const POLICY_RECONCILE_INTERVAL_MS = 5 * 60 * 1000;

async function reconcileConnectedHostPolicies(): Promise<void> {
  for (const hostId of getConnectedHostIdentifiers()) {
    await reapplyEnabledPoliciesForHost(hostId, dispatchToAgent);
  }
}

// In-flight guard: a sweep over every connected host could in principle run
// longer than POLICY_RECONCILE_INTERVAL_MS on a large/slow fleet — without
// this, tick N+1 would start stacking DB load on top of a still-running
// tick N. Explicit .catch(): reapplyEnabledPoliciesForHost already try/catches
// internally and shouldn't reject, but nothing here should rely on that
// invariant holding forever and turn into an unhandled rejection if it doesn't.
let sweepInFlight = false;
setInterval(() => {
  if (sweepInFlight) return;
  sweepInFlight = true;
  reconcileConnectedHostPolicies()
    .catch((err) => logger.error({ err }, 'Policy reconciliation sweep failed'))
    .finally(() => { sweepInFlight = false; });
}, POLICY_RECONCILE_INTERVAL_MS).unref();

const DEFAULT_PORT_RULES = { enabled: false, action: 'block', protocol: 'tcp', ports: [] };
const DEFAULT_IP_RULES   = { enabled: false, action: 'block', direction: 'both', ips: []  };
const DEFAULT_USB        = { enabled: false, action: 'block', scope: 'all'                };
const DEFAULT_BLUETOOTH  = { enabled: false, action: 'block'                               };

const isPlainObject = (v: unknown): boolean =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

function getFleetDb() {
  const sources = dbSourceConnection();
  const db = sources?.[1];
  if (!db) throw new CustomError(500, 'Database', 'Fleet database connection not available');
  return db;
}

function getPolicyRepo() {
  return getFleetDb().getRepository(Policy);
}

function toResponse(p: Policy) {
  const c = (p.config as Record<string, any>) || {};
  return {
    id:               p.id,
    name:             p.name,
    type:             p.type,
    description:      p.description ?? '',
    enabled:          p.enabled,
    platforms:        p.platforms ?? [],
    portRules:        c.portRules        ?? DEFAULT_PORT_RULES,
    ipRules:          c.ipRules          ?? DEFAULT_IP_RULES,
    usb:              c.usb              ?? DEFAULT_USB,
    bluetooth:        c.bluetooth        ?? DEFAULT_BLUETOOTH,
    complianceChecks: c.complianceChecks ?? [],
    customQuery:      c.customQuery      ?? '',
    target: {
      mode:     (p.target_mode as 'all' | 'nodes' | 'groups' | 'mixed' | 'none') ?? 'all',
      nodeIds:  p.target_node_ids  ?? [],
      groupIds: p.target_group_ids ?? [],
    },
    createdBy: p.created_by,
    createdAt: p.created_at?.toISOString?.() ?? '',
    updatedAt: p.updated_at?.toISOString?.() ?? '',
  };
}

function validateConfig(body: Record<string, any>, next: NextFunction): boolean {
  const { portRules, ipRules, usb, bluetooth, complianceChecks, customQuery } = body;
  if (portRules        !== null && portRules        !== undefined && !isPlainObject(portRules))        { next(new CustomError(400, 'Validation', 'portRules must be an object'));        return false; }
  if (ipRules          !== null && ipRules          !== undefined && !isPlainObject(ipRules))          { next(new CustomError(400, 'Validation', 'ipRules must be an object'));          return false; }
  if (usb              !== null && usb              !== undefined && !isPlainObject(usb))              { next(new CustomError(400, 'Validation', 'usb must be an object'));              return false; }
  if (bluetooth        !== null && bluetooth        !== undefined && !isPlainObject(bluetooth))        { next(new CustomError(400, 'Validation', 'bluetooth must be an object'));        return false; }
  if (complianceChecks !== null && complianceChecks !== undefined && !Array.isArray(complianceChecks)) { next(new CustomError(400, 'Validation', 'complianceChecks must be an array')); return false; }
  if (customQuery      !== null && customQuery      !== undefined) {
    if (typeof customQuery !== 'string') { next(new CustomError(400, 'Validation', 'customQuery must be a string')); return false; }
    const q = customQuery.trim().toUpperCase();
    if (q && !q.startsWith('SELECT')) { next(new CustomError(400, 'Validation', 'customQuery must be a SELECT statement')); return false; }
  }
  return true;
}

function getJwt(req: Request) {
  return (req as any).jwtPayload as JwtPayload | undefined;
}

interface ScopeContext {
  scope: NodeScope;
  /** Only meaningful when scope is restricted; empty otherwise. */
  // "view" = every group id the caller is a member of, Group Admin or Group
  // Viewer alike — used only to decide whether a policy is visible at all.
  viewGroupIds: Set<string>;
  viewHostIds: string[];
  // "act" = only group ids where the caller holds Group Admin (not Group
  // Viewer) membership — used to decide whether the caller may create,
  // edit, retarget, or delete a policy. A Group Viewer must see-not-touch,
  // same distinction as assertHostInScope vs assertCanActOnHost.
  actGroupIds: Set<string>;
  actHostIds: string[];
}

async function getScopeContext(req: Request): Promise<ScopeContext> {
  const jwt = getJwt(req);
  const scope = jwt?.id ? await getUserNodeScope(jwt.id) : ({ unrestricted: false, groups: [] } as NodeScope);
  if (scope.unrestricted) {
    return { scope, viewGroupIds: new Set(), viewHostIds: [], actGroupIds: new Set(), actHostIds: [] };
  }
  // Policy targets are stored as group ids (target_group_ids), the same shape
  // scopeGroupIds/actableGroupIds return, so no name resolution is needed.
  const [viewHostIds, actHostIds] = await Promise.all([
    getScopedHostIdentifiers(scope),
    getActableHostIdentifiers(scope),
  ]);
  return {
    scope,
    viewGroupIds: new Set(scopeGroupIds(scope)),
    viewHostIds: viewHostIds ?? [],
    actGroupIds: new Set(actableGroupIds(scope)),
    actHostIds: actHostIds ?? [],
  };
}

/**
 * Whether every target this policy references (nodes and/or groups, depending
 * on target_mode) lies entirely within a scoped caller's own group. Org-wide
 * ('all') policies are deliberately never "fully in scope" — Group Admin can
 * see them (listPolicies renders them read-only) but never owns/edits them.
 *
 * 'none' has no group/node to scope against. For a *candidate* target being
 * validated (createPolicy, or assignTargets checking its new value) that's
 * fine to allow through — callerEmail is omitted there and it stays
 * trivially in scope, since the caller is about to become/remain the owner.
 * For an *existing persisted* policy (callerEmail passed), only its creator
 * may manage it — otherwise any Group Admin could adopt, retarget, or delete
 * another admin's untargeted/draft policy purely because it hasn't been
 * assigned a target yet.
 */
function isPolicyFullyInScope(
  policy: { target_mode: string | null; target_node_ids: string[] | null; target_group_ids: string[] | null; created_by?: string | null },
  groupIdsInScope: Set<string>,
  hostIdsInScope: string[],
  callerEmail?: string | null,
): boolean {
  const mode = policy.target_mode ?? 'all';
  if (mode === 'all') return false;
  if (mode === 'none') {
    if (callerEmail === undefined) return true;
    return !!policy.created_by && !!callerEmail && policy.created_by.toLowerCase() === callerEmail.toLowerCase();
  }

  const nodeIds = policy.target_node_ids ?? [];
  const groupIds = policy.target_group_ids ?? [];

  // An empty target set carries the same adoption hazard as mode 'none', since
  // `[].every()` is vacuously true: without this, any Group Admin could claim
  // and retarget an untargeted policy created by another. Routed through the
  // same ownership check rather than a second copy of the rule.
  const targetsEmpty =
    (mode === 'nodes' && nodeIds.length === 0) ||
    (mode === 'groups' && groupIds.length === 0) ||
    (mode === 'mixed' && nodeIds.length === 0 && groupIds.length === 0);
  if (targetsEmpty) {
    if (callerEmail === undefined) return true;
    return !!policy.created_by && !!callerEmail && policy.created_by.toLowerCase() === callerEmail.toLowerCase();
  }

  const nodesOk = mode !== 'nodes' && mode !== 'mixed' ? true : nodeIds.every((id) => hostIdsInScope.includes(id));
  const groupsOk = mode !== 'groups' && mode !== 'mixed' ? true : groupIds.every((id) => groupIdsInScope.has(id));
  return nodesOk && groupsOk;
}

/**
 * Rejects (via `next`) with 400 if any submitted nodeId/groupId doesn't
 * actually exist, so a typo'd/bogus id doesn't silently no-op for that
 * target forever. Shared by createPolicy and assignTargets.
 *
 * Deliberately only checks nodeIds when mode === 'nodes' and groupIds when
 * mode === 'groups'. 'mixed' mode is not validated here at all — a known gap.
 */
async function validateTargetIdsExist(
  db: ReturnType<typeof getFleetDb>,
  mode: string,
  nodeIds: string[],
  groupIds: string[],
  next: NextFunction,
): Promise<boolean> {
  if (mode === 'nodes' && nodeIds.length > 0) {
    const rows: { host_identifier: string }[] = await db.query(
      'SELECT host_identifier FROM nodes WHERE host_identifier = ANY($1)',
      [nodeIds],
    );
    const found = new Set(rows.map((r) => r.host_identifier));
    const missing = nodeIds.filter((nid) => !found.has(nid));
    if (missing.length > 0) {
      next(new CustomError(400, 'Validation', `Unknown node IDs: ${missing.slice(0, 5).join(', ')}`));
      return false;
    }
  }

  if (mode === 'groups' && groupIds.length > 0) {
    const rows: { group_id: string }[] = await db.query(
      'SELECT group_id FROM nodes_groups WHERE group_id = ANY($1)',
      [groupIds],
    );
    const found = new Set(rows.map((r) => r.group_id));
    const missing = groupIds.filter((g) => !found.has(g));
    if (missing.length > 0) {
      next(new CustomError(400, 'Validation', `Unknown group IDs: ${missing.slice(0, 5).join(', ')}`));
      return false;
    }
  }

  return true;
}

// GET /api/policies
export const listPolicies = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page  = Math.max(1, parseInt(String(req.query.page  ?? '1'),   10) || 1);
    const limit = Math.min(PAGINATION_MAX_ROWS_ADMIN_ACTIVITY, Math.max(1, parseInt(String(req.query.limit ?? '100'), 10) || PAGINATION_DEFAULT_ROWS));
    const repo = getPolicyRepo();
    const jwt = getJwt(req);
    const { scope, viewGroupIds, viewHostIds, actGroupIds, actHostIds } = await getScopeContext(req);

    if (scope.unrestricted) {
      const [policies, total] = await repo.findAndCount({
        order: { created_at: 'DESC' },
        take:  limit,
        skip:  (page - 1) * limit,
      });
      logger.debug({ count: policies.length, total, page }, 'Policies listed');
      return res.json({
        status: 'Success',
        policies: policies.map((p) => ({ ...toResponse(p), canManage: true })),
        total,
        page,
        limit,
      });
    }

    // Visible to anyone who's at least a Group Viewer member of the target
    // group(s): org-wide policies read-only, plus anything targeted within a
    // group they belong to. A policy targeting another group's nodes is
    // hidden entirely rather than leaking that group's existence. Only
    // act-level (Group Admin) membership makes it editable — see canManage.
    const all = await repo.find({ order: { created_at: 'DESC' } });
    const visible = all.filter(
      // callerEmail must be passed here too (not just in the canManage
      // computation below) — omitting it makes isPolicyFullyInScope treat
      // an untargeted ('none' mode) policy as a *candidate* being validated
      // (trivially in scope for anyone), when this is actually the read path
      // over *persisted* policies, where only the creator should see it.
      (p) => (p.target_mode ?? 'all') === 'all' || isPolicyFullyInScope(p, viewGroupIds, viewHostIds, jwt?.email),
    );
    const total = visible.length;
    const paged = visible.slice((page - 1) * limit, (page - 1) * limit + limit);
    const policies = paged.map((p) => ({
      ...toResponse(p),
      canManage: (p.target_mode ?? 'all') !== 'all' && isPolicyFullyInScope(p, actGroupIds, actHostIds, jwt?.email),
    }));
    logger.debug({ count: policies.length, total, page }, 'Policies listed');
    return res.json({ status: 'Success', policies, total, page, limit });
  } catch (err) {
    logger.error({ err }, 'Failed to list policies');
    return next(err instanceof CustomError ? err : new CustomError(500, 'Raw', 'Failed to list policies', null, err));
  }
};

// POST /api/policies
export const createPolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, type, description, platforms, portRules, ipRules, usb, bluetooth, complianceChecks, customQuery, target } = req.body;

    if (!name?.trim()) return next(new CustomError(400, 'Validation', 'Policy name is required'));
    const VALID_TYPES = ['network', 'device-control', 'compliance', 'custom'];
    if (!VALID_TYPES.includes(type)) return next(new CustomError(400, 'Validation', `type must be one of: ${VALID_TYPES.join(', ')}`));
    if (!validateConfig(req.body, next)) return;

    const targetMode     = target?.mode ?? 'all';
    const targetNodeIds  = Array.isArray(target?.nodeIds)  ? target.nodeIds  : [];
    const targetGroupIds = Array.isArray(target?.groupIds) ? target.groupIds : [];

    const { scope, actGroupIds, actHostIds } = await getScopeContext(req);
    if (!scope.unrestricted) {
      if (targetMode === 'all') {
        return next(new CustomError(403, 'General', 'Group Admins cannot create org-wide policies'));
      }
      if (!isPolicyFullyInScope(
        { target_mode: targetMode, target_node_ids: targetNodeIds, target_group_ids: targetGroupIds },
        actGroupIds,
        actHostIds,
      )) {
        return next(new CustomError(403, 'General', 'You can only target nodes/groups you have Group Admin access to'));
      }
    }

    const db = getFleetDb();
    if (!(await validateTargetIdsExist(db, targetMode, targetNodeIds, targetGroupIds, next))) return;

    const jwt = getJwt(req);
    const repo = db.getRepository(Policy);
    const policy = repo.create({
      name:             name.trim(),
      type,
      description:      description?.trim() || null,
      platforms:        Array.isArray(platforms) ? platforms : [],
      config:           { portRules, ipRules, usb, bluetooth, complianceChecks, customQuery },
      target_mode:      targetMode,
      target_node_ids:  targetNodeIds,
      target_group_ids: targetGroupIds,
      created_by:       jwt?.email ?? null,
    });
    const saved = await repo.save(policy);
    pushPolicyIfEnabled(saved);

    logAuditTrail({
      action:    'POLICY_CREATE',
      status:    'success',
      userId:    jwt?.id    ?? null,
      email:     jwt?.email ?? null,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      details:   { policyId: saved.id, name: saved.name, type: saved.type },
    }).catch(err => logger.error({ err }, 'Failed to log audit trail'));

    logger.info({ policyId: saved.id, name: saved.name, type: saved.type }, 'Policy created');
    return res.status(201).json({ status: 'Success', policy: toResponse(saved) });
  } catch (err) {
    logger.error({ err, name: req.body?.name, type: req.body?.type }, 'Failed to create policy');
    return next(err instanceof CustomError ? err : new CustomError(500, 'Raw', 'Failed to create policy', null, err));
  }
};

// PATCH /api/policies/:id  — metadata + config fields
export const updatePolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = String(req.params.id);
    const { enabled, name, description, portRules, ipRules, usb, bluetooth, complianceChecks, customQuery } = req.body;

    if (!validateConfig(req.body, next)) return;

    const repo = getPolicyRepo();
    const policy = await repo.findOne({ where: { id } });
    if (!policy) return next(new CustomError(404, 'General', 'Policy not found'));

    const jwt = getJwt(req);
    const { scope, actGroupIds, actHostIds } = await getScopeContext(req);
    if (!scope.unrestricted && !isPolicyFullyInScope(policy, actGroupIds, actHostIds, jwt?.email)) {
      return next(new CustomError(403, 'General', 'You do not have access to this policy'));
    }

    if (typeof enabled === 'boolean')            policy.enabled     = enabled;
    if (typeof name === 'string' && name.trim()) policy.name        = name.trim();
    if (typeof description === 'string')         policy.description = description.trim() || null;

    const configPatch: Record<string, any> = {};
    if (portRules        !== undefined) configPatch.portRules        = portRules;
    if (ipRules          !== undefined) configPatch.ipRules          = ipRules;
    if (usb              !== undefined) configPatch.usb              = usb;
    if (bluetooth        !== undefined) configPatch.bluetooth        = bluetooth;
    if (complianceChecks !== undefined) configPatch.complianceChecks = complianceChecks;
    if (customQuery      !== undefined) configPatch.customQuery      = customQuery;
    if (Object.keys(configPatch).length > 0) {
      policy.config = { ...((policy.config as Record<string, any>) ?? {}), ...configPatch };
    }

    const saved = await repo.save(policy);
    pushPolicyIfEnabled(saved);

    logAuditTrail({
      action:    'POLICY_UPDATE',
      status:    'success',
      userId:    jwt?.id    ?? null,
      email:     jwt?.email ?? null,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      details:   { policyId: id, fields: Object.keys(req.body) },
    }).catch(err => logger.error({ err }, 'Failed to log audit trail'));

    logger.info({ policyId: id }, 'Policy updated');
    return res.json({ status: 'Success', policy: toResponse(saved) });
  } catch (err) {
    logger.error({ err, policyId: req.params.id }, 'Failed to update policy');
    return next(err instanceof CustomError ? err : new CustomError(500, 'Raw', 'Failed to update policy', null, err));
  }
};

// PATCH /api/policies/:id/targets
export const assignTargets = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = String(req.params.id);
    const { mode, nodeIds, groupIds } = req.body;

    if (!['all', 'nodes', 'groups', 'mixed', 'none'].includes(mode)) {
      return next(new CustomError(400, 'Validation', "mode must be 'all', 'nodes', 'groups', 'mixed', or 'none'"));
    }

    const db = getFleetDb();
    const repo = db.getRepository(Policy);
    const policy = await repo.findOne({ where: { id } });
    if (!policy) return next(new CustomError(404, 'General', 'Policy not found'));

    const jwt = getJwt(req);
    const { scope, actGroupIds, actHostIds } = await getScopeContext(req);
    if (!scope.unrestricted) {
      if (!isPolicyFullyInScope(policy, actGroupIds, actHostIds, jwt?.email)) {
        return next(new CustomError(403, 'General', 'You do not have access to this policy'));
      }
      if (mode === 'all') {
        return next(new CustomError(403, 'General', 'Group Admins cannot make a policy org-wide'));
      }
      if (!isPolicyFullyInScope(
        {
          target_mode: mode,
          target_node_ids: Array.isArray(nodeIds) ? nodeIds : [],
          target_group_ids: Array.isArray(groupIds) ? groupIds : [],
        },
        actGroupIds,
        actHostIds,
      )) {
        return next(new CustomError(403, 'General', 'You can only target nodes/groups you have Group Admin access to'));
      }
    }

    if (!(await validateTargetIdsExist(
      db,
      mode,
      Array.isArray(nodeIds) ? nodeIds : [],
      Array.isArray(groupIds) ? groupIds : [],
      next,
    ))) return;

    policy.target_mode      = mode;
    policy.target_node_ids  = Array.isArray(nodeIds)  ? nodeIds  : [];
    policy.target_group_ids = Array.isArray(groupIds) ? groupIds : [];
    const saved = await repo.save(policy);
    pushPolicyIfEnabled(saved);

    logAuditTrail({
      action:    'POLICY_ASSIGN_TARGETS',
      status:    'success',
      userId:    jwt?.id    ?? null,
      email:     jwt?.email ?? null,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      details:   { policyId: id, mode, nodeCount: nodeIds?.length ?? 0, groupCount: groupIds?.length ?? 0 },
    }).catch(err => logger.error({ err }, 'Failed to log audit trail'));

    logger.info({ policyId: id, mode }, 'Policy targets assigned');
    return res.json({ status: 'Success', policy: toResponse(saved) });
  } catch (err) {
    logger.error({ err, policyId: req.params.id }, 'Failed to assign policy targets');
    return next(err instanceof CustomError ? err : new CustomError(500, 'Raw', 'Failed to assign targets', null, err));
  }
};

// DELETE /api/policies/:id
export const deletePolicy = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = String(req.params.id);
    const repo = getPolicyRepo();
    const policy = await repo.findOne({ where: { id } });
    if (!policy) return next(new CustomError(404, 'General', 'Policy not found'));

    const jwt = getJwt(req);
    const { scope, actGroupIds, actHostIds } = await getScopeContext(req);
    if (!scope.unrestricted && !isPolicyFullyInScope(policy, actGroupIds, actHostIds, jwt?.email)) {
      return next(new CustomError(403, 'General', 'You do not have access to this policy'));
    }

    const { name, type } = policy;
    await repo.remove(policy);

    logAuditTrail({
      action:    'POLICY_DELETE',
      status:    'success',
      userId:    jwt?.id    ?? null,
      email:     jwt?.email ?? null,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      details:   { policyId: id, name, type },
    }).catch(err => logger.error({ err }, 'Failed to log audit trail'));

    logger.info({ policyId: id, name }, 'Policy deleted');
    return res.json({ status: 'Success', message: 'Policy deleted' });
  } catch (err) {
    logger.error({ err, policyId: req.params.id }, 'Failed to delete policy');
    return next(err instanceof CustomError ? err : new CustomError(500, 'Raw', 'Failed to delete policy', null, err));
  }
};
