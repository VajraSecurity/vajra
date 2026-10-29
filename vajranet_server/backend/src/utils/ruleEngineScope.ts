/**
 * Group-scoped authorization for the Rule Engine proxy (routes/api/rule-engine.ts).
 *
 * The sibling engine console has no group/tenant concept at all (see
 * rule-engine.ts's header comment) — flat JSON files, a single global
 * live-instance process. So "scoping" here can only ever mean "which
 * vajranet group may manage this resource", never "whose nodes this rule
 * fires for" — the engine enforces detection fleet-wide regardless of who
 * created/owns a resource in our own bookkeeping. Ownership is tracked in
 * rule_engine_resource_owners (see that entity's header comment), since the
 * resources themselves have no local table to hang an owner_group_id column
 * off of the way nodes.owner_group_id does.
 *
 * Phase 1 scope: only IP watch-group IP *membership* (add/remove individual
 * IPs) is scoped this way. Everything else that changes detection/
 * enforcement/infra config (rules, correlation rules, threat-intel feeds,
 * live-instance, and IP watch-group create/delete/enable-disable) stays
 * requireSuperAdmin — read-only for Group Admin — because none of those have
 * a way to scope enforcement to one group even if we tracked an owner.
 */

import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../index';
import { getUserNodeScope, actableGroupIds, NodeScope } from './nodeScope';
import { JwtPayload } from '../types/JwtPayload';
import { CustomError } from './response/custom-error/CustomError';
import { getLogger } from './logger';
import type { RuleEngineResourceType } from '../orm/entities/rule_engine/RuleEngineResourceOwner';

const logger = getLogger('utils.ruleEngineScope');

function getPrimaryDb() {
  const sources = dbSourceConnection();
  const db = sources?.[0];
  if (!db) throw new CustomError(500, 'Database', 'Primary database connection not available');
  return db;
}

/** The vajranet group id that owns this resource, or null if never assigned one (fails closed — see canActOnRuleEngineResource). */
export async function getRuleEngineResourceOwner(resourceType: RuleEngineResourceType, resourceKey: string): Promise<string | null> {
  const db = getPrimaryDb();
  const rows = await db.query(
    `SELECT owner_group_id FROM rule_engine_resource_owners WHERE resource_type = $1 AND resource_key = $2`,
    [resourceType, resourceKey],
  );
  return rows?.[0]?.owner_group_id ?? null;
}

/** Batch form of getRuleEngineResourceOwner — one round trip for a whole list response instead of N. Returns a Map from resource_key to owner_group_id (unowned keys are simply absent). */
export async function getRuleEngineResourceOwners(resourceType: RuleEngineResourceType, resourceKeys: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (resourceKeys.length === 0) return map;
  const db = getPrimaryDb();
  const rows: { resource_key: string; owner_group_id: string }[] = await db.query(
    `SELECT resource_key, owner_group_id FROM rule_engine_resource_owners WHERE resource_type = $1 AND resource_key = ANY($2::text[])`,
    [resourceType, resourceKeys],
  );
  for (const row of rows) map.set(row.resource_key, row.owner_group_id);
  return map;
}

/** Assigns (or reassigns) which vajranet group owns a resource — Super-Admin-only call sites, since only Super Admin can create the resources this applies to in Phase 1. */
export async function setRuleEngineResourceOwner(
  resourceType: RuleEngineResourceType,
  resourceKey: string,
  ownerGroupId: string,
  createdBy: string | null,
): Promise<void> {
  const db = getPrimaryDb();
  await db.query(
    `INSERT INTO rule_engine_resource_owners (resource_type, resource_key, owner_group_id, created_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (resource_type, resource_key) DO UPDATE SET owner_group_id = EXCLUDED.owner_group_id`,
    [resourceType, resourceKey, ownerGroupId, createdBy],
  );
}

/** Cleans up the ownership row when the underlying resource is deleted — best-effort, never blocks the delete response on it (see call sites in rule-engine.ts). */
export async function deleteRuleEngineResourceOwner(resourceType: RuleEngineResourceType, resourceKey: string): Promise<void> {
  const db = getPrimaryDb();
  await db.query(`DELETE FROM rule_engine_resource_owners WHERE resource_type = $1 AND resource_key = $2`, [resourceType, resourceKey]);
}

/**
 * Whether this caller may write to the given rule-engine resource. Super
 * Admin always can. A Group Admin can only if the resource's tracked owner
 * is a group they hold act-level (Group Admin, not Viewer) membership in.
 * An unowned resource (never assigned, or created before this table
 * existed) fails closed — Super-Admin-only until explicitly assigned, same
 * "unowned means restricted, not open" convention as nodeScope.ts.
 */
export async function canActOnRuleEngineResource(
  scope: NodeScope,
  resourceType: RuleEngineResourceType,
  resourceKey: string,
): Promise<boolean> {
  if (scope.unrestricted) return true;
  const groupIds = actableGroupIds(scope);
  if (groupIds.length === 0) return false;
  const owner = await getRuleEngineResourceOwner(resourceType, resourceKey);
  if (!owner) return false;
  return groupIds.includes(owner);
}

/**
 * Express middleware gating a mutation on one rule-engine resource
 * identified by a route param (e.g. an IP watch group's :name) to Super
 * Admin or a Group Admin who owns it. Must run after checkAccessJwt. Unlike
 * requireAdmin (a global role check with no notion of *which* resource),
 * this is genuinely scoped — mirrors nodeScope.ts's assertCanActOnHost, just
 * backed by rule_engine_resource_owners instead of nodes.owner_group_id.
 */
export function requireCanActOnRuleEngineResource(resourceType: RuleEngineResourceType, paramName: string) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      if (!jwtPayload?.id) return next(new CustomError(401, 'General', 'Authentication required'));

      const resourceKey = req.params[paramName] as string;
      const scope = await getUserNodeScope(jwtPayload.id);
      const allowed = await canActOnRuleEngineResource(scope, resourceType, resourceKey);
      if (!allowed) {
        logger.warn(
          { userId: jwtPayload.id, resourceType, resourceKey },
          'Rule engine resource mutation denied: caller does not own this resource',
        );
        return next(new CustomError(403, 'General', 'You do not have access to manage this IP watch group'));
      }
      return next();
    } catch (err) {
      return next(new CustomError(500, 'Raw', 'Failed to resolve rule engine resource access', null, err));
    }
  };
}
