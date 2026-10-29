import { Request, Response, NextFunction } from 'express';
import * as cron from 'node-cron';
import { In } from 'typeorm';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getDomainReputationSchedulerInstance } from '../../services/domainReputation/scheduler';
import { getUserNodeScope } from '../../utils/nodeScope';
import { getDomainReputationScopeContext, resolveWriteGroupId } from '../../services/domainReputation/scopeContext';
import type { DomainReputationScopeContext } from '../../services/domainReputation/scopeContext';
import { normalizeDomainInput, normalizeIpInput } from '../../services/domainReputation/validation';
import type { DomainReputationTargetType } from '../../orm/entities/fleet/DomainReputationTarget';
import { getLogger } from '../../utils/logger';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';

const logger = getLogger('controllers.domainReputation.targets');

// The scheduled watchlist only supports the Threat Intel APIs — the manual server's
// Manual Check tab has no schedule.
const SCHEDULABLE_PROVIDERS = ['virustotal', 'abuseipdb'];

function isValidType(value: unknown): value is DomainReputationTargetType {
  return value === 'domain' || value === 'ip';
}

function parseIdParam(raw: string | string[]): number | null {
  const s = Array.isArray(raw) ? raw[0] : raw;
  if (!s) return null;
  const n = parseInt(s, 10);
  return Number.isNaN(n) ? null : n;
}

/** A NULL-group (org-wide) target is visible read-only to every Group Admin; otherwise it must be one of the caller's own groups. */
function isTargetVisible(t: { groupId: string | null }, ctx: DomainReputationScopeContext): boolean {
  if (ctx.scope.unrestricted) return true;
  if (t.groupId === null) return true;
  return ctx.viewGroupIds.has(t.groupId);
}

/** Org-wide (NULL-group) targets are Super-Admin-managed only — a Group Admin can see but never act on one. */
function isTargetActable(t: { groupId: string | null }, ctx: DomainReputationScopeContext): boolean {
  if (ctx.scope.unrestricted) return true;
  if (t.groupId === null) return false;
  return ctx.actGroupIds.has(t.groupId);
}

function ambiguousMessage(actGroupIds: string[]): string {
  return `group_id is required — you administer multiple groups: ${actGroupIds.join(', ')}`;
}

/**
 * Normalizes a raw entity into the DTO the frontend actually types
 * (DomainReputationTarget expects snake_case group_id) — spreading the
 * entity directly leaves `groupId` (its real TypeORM property name) instead,
 * which silently doesn't match the declared contract.
 */
function toTargetDto<T extends { groupId: string | null }>(
  t: T,
  groupName: string | null,
  ctx: import('../../services/domainReputation/scopeContext').DomainReputationScopeContext,
) {
  const { groupId, ...rest } = t as any;
  return { ...rest, group_id: groupId, group_name: groupId ? groupName : null, canManage: isTargetActable(t, ctx) };
}

async function lookupGroupName(groupId: string | null): Promise<string | null> {
  if (!groupId) return null;
  const groupRepo = await getGroupRepo();
  const row = await groupRepo.findOne({ where: { groupId } });
  return row?.name ?? groupId;
}

async function getRepos() {
  const { dbSourceConnection } = await import('../../index');
  const { DomainReputationTarget } = await import('../../orm/entities/fleet/DomainReputationTarget');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    throw new Error('Fleet database not available');
  }
  return { targetRepo: ds[1].getRepository(DomainReputationTarget) };
}

async function getGroupRepo() {
  const { dbSourceConnection } = await import('../../index');
  const { EndpointGroup } = await import('../../orm/entities/fleet/EndpointGroup');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    throw new Error('Fleet database not available');
  }
  return ds[1].getRepository(EndpointGroup);
}

export const listTargets = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { targetRepo } = await getRepos();
    const ctx = await getDomainReputationScopeContext(req);
    const all = await targetRepo.find({ order: { created_at: 'DESC' } });
    const visible = all.filter((t) => isTargetVisible(t, ctx));

    const groupIds = [...new Set(visible.map((t) => t.groupId).filter((id): id is string => !!id))];
    let nameById = new Map<string, string>();
    if (groupIds.length) {
      const groupRepo = await getGroupRepo();
      const rows = await groupRepo.find({ where: { groupId: In(groupIds) } });
      nameById = new Map(rows.map((r) => [r.groupId, r.name]));
    }

    const data = visible.map((t) => toTargetDto(t, t.groupId ? nameById.get(t.groupId) ?? t.groupId : null, ctx));

    logger.debug({ count: data.length }, 'Domain reputation watchlist retrieved');
    return res.status(200).json({ success: true, data });
  } catch (err: any) {
    logger.error({ err }, 'Failed to load domain reputation watchlist');
    return res.status(500).json({ success: false, message: err.message || 'Failed to load watchlist' });
  }
};

export const createTarget = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { value, type, providers, cronExpression } = req.body;

    if (!value || typeof value !== 'string' || !value.trim()) {
      return res.status(400).json({ success: false, message: 'value is required' });
    }
    if (!isValidType(type)) {
      return res.status(400).json({ success: false, message: `type must be 'domain' or 'ip'` });
    }
    if (!Array.isArray(providers) || providers.length === 0 || !providers.every((p) => SCHEDULABLE_PROVIDERS.includes(p))) {
      return res.status(400).json({ success: false, message: `providers must be a non-empty subset of: ${SCHEDULABLE_PROVIDERS.join(', ')}` });
    }
    if (!cronExpression || typeof cronExpression !== 'string' || !cron.validate(cronExpression)) {
      return res.status(400).json({ success: false, message: 'cronExpression is not a valid cron expression' });
    }

    const cleanValue = type === 'ip' ? normalizeIpInput(value) : normalizeDomainInput(value);
    if (!cleanValue) {
      return res.status(400).json({ success: false, message: `"${value}" doesn't look like a valid ${type === 'ip' ? 'IP address' : 'domain'}` });
    }

    const ctx = await getDomainReputationScopeContext(req);
    const resolution = resolveWriteGroupId(ctx, req.body.group_id);
    if (!resolution.ok) {
      if (resolution.reason === 'ambiguous') {
        return res.status(400).json({ success: false, message: ambiguousMessage(resolution.actGroupIds) });
      }
      return res.status(403).json({ success: false, message: 'You can only add watchlist entries for a group you administer' });
    }

    const { targetRepo } = await getRepos();
    const jwt = jwtFrom(req);

    const target = targetRepo.create({
      value: cleanValue,
      type,
      groupId: resolution.groupId,
      providers,
      cronExpression,
      isActive: true,
      lastVerdict: null,
      lastCheckedAt: null,
      created_by_user_id: jwt?.id ?? null,
      created_by_name: jwt?.name ?? null,
    });
    await targetRepo.save(target);

    const scheduler = getDomainReputationSchedulerInstance();
    if (scheduler) {
      scheduler.scheduleJob(target);
    } else {
      logger.warn({ targetId: target.id }, 'Domain reputation watchlist entry created but scheduler is not available; it will not run until the scheduler is up');
    }

    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_TARGET_CREATE',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { value: target.value, type, providers, cronExpression, group_id: target.groupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ targetId: target.id, value: target.value, type, groupId: target.groupId }, 'Domain reputation watchlist entry created');
    return res.status(201).json({ success: true, data: toTargetDto(target, await lookupGroupName(target.groupId), ctx) });
  } catch (err: any) {
    logger.error({ err, value: req.body?.value, type: req.body?.type }, 'Failed to create domain reputation watchlist entry');
    return res.status(500).json({ success: false, message: err.message || 'Failed to create watchlist entry' });
  }
};

export const updateTarget = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const id = parseIdParam(req.params.id);
    if (id === null) return res.status(400).json({ success: false, message: 'Invalid target ID' });

    const { targetRepo } = await getRepos();
    const target = await targetRepo.findOne({ where: { id } });
    if (!target) return res.status(404).json({ success: false, message: 'Watchlist entry not found' });

    const ctx = await getDomainReputationScopeContext(req);
    if (!isTargetActable(target, ctx)) {
      return res.status(403).json({ success: false, message: 'You can only manage watchlist entries for a group you administer' });
    }

    // group_id is intentionally not accepted here — a target's group is fixed
    // at creation, not reassignable via update.
    const { providers, cronExpression, isActive } = req.body;

    if (providers !== undefined) {
      if (!Array.isArray(providers) || providers.length === 0 || !providers.every((p) => SCHEDULABLE_PROVIDERS.includes(p))) {
        return res.status(400).json({ success: false, message: `providers must be a non-empty subset of: ${SCHEDULABLE_PROVIDERS.join(', ')}` });
      }
      target.providers = providers;
    }
    if (cronExpression !== undefined) {
      if (typeof cronExpression !== 'string' || !cron.validate(cronExpression)) {
        return res.status(400).json({ success: false, message: 'cronExpression is not a valid cron expression' });
      }
      target.cronExpression = cronExpression;
    }
    if (isActive !== undefined) {
      target.isActive = !!isActive;
    }

    await targetRepo.save(target);

    const scheduler = getDomainReputationSchedulerInstance();
    if (!scheduler) {
      logger.warn({ targetId: id, isActive: target.isActive }, 'Domain reputation watchlist entry updated but scheduler is not available; schedule change will not take effect until the scheduler is up');
    } else if (target.isActive) {
      scheduler.scheduleJob(target);
    } else {
      scheduler.unscheduleJob(target.id);
    }

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_TARGET_UPDATE',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { id, providers: target.providers, cronExpression: target.cronExpression, isActive: target.isActive },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ targetId: id, isActive: target.isActive }, 'Domain reputation watchlist entry updated');
    return res.status(200).json({ success: true, data: toTargetDto(target, await lookupGroupName(target.groupId), ctx) });
  } catch (err: any) {
    logger.error({ err, targetId: req.params.id }, 'Failed to update domain reputation watchlist entry');
    return res.status(500).json({ success: false, message: err.message || 'Failed to update watchlist entry' });
  }
};

export const deleteTarget = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const id = parseIdParam(req.params.id);
    if (id === null) return res.status(400).json({ success: false, message: 'Invalid target ID' });

    const { targetRepo } = await getRepos();
    const target = await targetRepo.findOne({ where: { id } });
    if (!target) return res.status(404).json({ success: false, message: 'Watchlist entry not found' });

    const ctx = await getDomainReputationScopeContext(req);
    if (!isTargetActable(target, ctx)) {
      return res.status(403).json({ success: false, message: 'You can only manage watchlist entries for a group you administer' });
    }

    await targetRepo.remove(target);
    getDomainReputationSchedulerInstance()?.unscheduleJob(id);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_TARGET_DELETE',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { id, value: target.value },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ targetId: id }, 'Domain reputation watchlist entry deleted');
    return res.status(200).json({ success: true, message: 'Watchlist entry removed' });
  } catch (err: any) {
    logger.error({ err, targetId: req.params.id }, 'Failed to delete domain reputation watchlist entry');
    return res.status(500).json({ success: false, message: err.message || 'Failed to delete watchlist entry' });
  }
};

export const runTargetNow = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const id = parseIdParam(req.params.id);
    if (id === null) return res.status(400).json({ success: false, message: 'Invalid target ID' });

    const { targetRepo } = await getRepos();
    const target = await targetRepo.findOne({ where: { id } });
    if (!target) return res.status(404).json({ success: false, message: 'Watchlist entry not found' });

    const ctx = await getDomainReputationScopeContext(req);
    if (!isTargetActable(target, ctx)) {
      return res.status(403).json({ success: false, message: 'You can only run watchlist entries for a group you administer' });
    }

    const scheduler = getDomainReputationSchedulerInstance();
    if (!scheduler) return res.status(503).json({ success: false, message: 'Scheduler not available' });

    const results = await scheduler.runCheck(id, 'manual');
    logger.info({ targetId: id }, 'Domain reputation manual check completed');
    return res.status(200).json({ success: true, data: results });
  } catch (err: any) {
    logger.error({ err, targetId: req.params.id }, 'Failed to run domain reputation check');
    return res.status(500).json({ success: false, message: err.message || 'Failed to run check' });
  }
};

/**
 * Suggestions for the watchlist's "add from inventory" autocomplete. Nodes
 * don't carry a public IP column and Network-Scan output is unstructured free
 * text, so this is scoped to enrolled-device hostnames only.
 */
export const listInventorySuggestions = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const ds = dbSourceConnection();
    const fleetDb = ds?.[1];
    if (!fleetDb || !fleetDb.isInitialized) {
      logger.warn({}, 'Inventory suggestions fetch aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };

    const conditions = [`hostname IS NOT NULL`, `hostname != ''`];
    const params: unknown[] = [];
    if (!scope.unrestricted) {
      conditions.push(`owner_group_id = ANY($1::text[])`);
      params.push(scope.groups.map((g) => g.id));
    }

    const rows: { hostname: string }[] = await fleetDb.query(
      `SELECT DISTINCT hostname FROM nodes WHERE ${conditions.join(' AND ')} ORDER BY hostname LIMIT 200`,
      params,
    );

    logger.debug({ count: rows.length }, 'Inventory suggestions retrieved');
    return res.status(200).json({ success: true, data: rows.map((r) => r.hostname) });
  } catch (err: any) {
    logger.error({ err }, 'Failed to load inventory suggestions');
    return res.status(500).json({ success: false, message: err.message || 'Failed to load inventory suggestions' });
  }
};
