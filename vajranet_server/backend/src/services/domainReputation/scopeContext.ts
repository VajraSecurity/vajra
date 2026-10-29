/**
 * Domain Reputation's group-scoping glue. Wraps utils/nodeScope.ts's
 * getUserNodeScope in the request-level shape this feature's three
 * controllers (providerConfigController, targetsController, checkController)
 * all need — "which groups can this caller see" and "which groups can they
 * write into" — plus resolveWriteGroupId, which turns an optional
 * client-supplied group_id into the single group a write should target
 * (or a typed rejection reason) for VirusTotal/AbuseIPDB. The 'manual'
 * provider never goes through this module — it stays Super-Admin-only and
 * ungrouped, checked directly in providerConfigController.
 */

import { Request } from 'express';
import { getUserNodeScope, scopeGroupIds, actableGroupIds } from '../../utils/nodeScope';
import type { NodeScope } from '../../utils/nodeScope';
import { jwtFrom } from '../../utils/requestContext';

export interface DomainReputationScopeContext {
  scope: NodeScope;
  /** Every group (Group Admin or Group Viewer) the caller belongs to. Empty when scope.unrestricted. */
  viewGroupIds: Set<string>;
  /** Only groups where the caller holds Group Admin membership. Empty when scope.unrestricted. */
  actGroupIds: Set<string>;
}

export async function getDomainReputationScopeContext(req: Request): Promise<DomainReputationScopeContext> {
  const jwt = jwtFrom(req);
  const scope = jwt?.id ? await getUserNodeScope(jwt.id) : ({ unrestricted: false, groups: [] } as NodeScope);
  if (scope.unrestricted) return { scope, viewGroupIds: new Set(), actGroupIds: new Set() };
  return { scope, viewGroupIds: new Set(scopeGroupIds(scope)), actGroupIds: new Set(actableGroupIds(scope)) };
}

export type WriteGroupResolution =
  | { ok: true; groupId: string | null }
  | { ok: false; reason: 'forbidden' | 'ambiguous'; actGroupIds: string[] };

/**
 * Resolves which single group_id a write (save/test/delete provider config,
 * create a target, run an ad-hoc check) should be scoped to.
 * - Super Admin: requestedGroupId is honored verbatim (undefined/null ->
 *   the org-wide default). Existence of a non-null id is not verified here;
 *   callers that need that (provider config save) check it against
 *   nodes_groups themselves.
 * - Group Admin: a given requestedGroupId must be one of the caller's
 *   actable groups (else 'forbidden'). If omitted: exactly one actable
 *   group -> inferred silently; zero -> 'forbidden'; two or more ->
 *   'ambiguous' (the caller must say which group).
 */
export function resolveWriteGroupId(
  ctx: DomainReputationScopeContext,
  requestedGroupId: string | null | undefined,
): WriteGroupResolution {
  if (ctx.scope.unrestricted) return { ok: true, groupId: requestedGroupId ?? null };
  const ids = [...ctx.actGroupIds];
  if (requestedGroupId) {
    return ids.includes(requestedGroupId)
      ? { ok: true, groupId: requestedGroupId }
      : { ok: false, reason: 'forbidden', actGroupIds: ids };
  }
  if (ids.length === 1) return { ok: true, groupId: ids[0] };
  if (ids.length === 0) return { ok: false, reason: 'forbidden', actGroupIds: ids };
  return { ok: false, reason: 'ambiguous', actGroupIds: ids };
}
