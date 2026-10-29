/**
 * Group-scoping resolution for the Network Security scanner integrations
 * (Nessus/OpenVAS/Burp Suite config + Burp's local scan history) and the Scan
 * Scheduler. Built on top of nodeScope.ts's group-membership primitives —
 * same underlying data (user_group_memberships), same fail-closed posture —
 * but answers a different question: nodeScope.ts asks "is this host in my
 * scope", this asks "which single scope (a group, or the Super Administrator's
 * own null scope) should this request read/write for".
 *
 * null groupId means "the Super Administrator's own config/scan, not tied to
 * any group" — see the `groupId` column comment on NessusConfig/OpenVASConfig/
 * BurpsuiteConfig/BurpsuiteScanHistory/ScanSchedule for the full rationale.
 */

import type { Request } from 'express';
import { IsNull } from 'typeorm';
import { actableGroupIds, canActOnGroup, getUserNodeScope, scopeGroupIds, type NodeScope } from './nodeScope';
import type { JwtPayload } from '../types/JwtPayload';

export interface ScannerGroupContext {
  scope: NodeScope;
  /** Effective scope for this request. null = the Super Administrator's own
   *  config/scans, never a value a Group Admin can be resolved to. */
  groupId: string | null;
}

export type ScannerScopeResult =
  | { ok: true; ctx: ScannerGroupContext }
  | { ok: false; status: number; message: string };

/** undefined = caller didn't specify a group; null = caller explicitly asked
 *  for "my own" (only meaningful for a Super Administrator); a string = a
 *  specific group id. Accepted from either the query string (GET) or the
 *  body (POST/PUT), whichever the endpoint uses. */
function readRequestedGroupId(req: Request): string | null | undefined {
  const raw = (req.query?.groupId ?? (req.body as Record<string, unknown> | undefined)?.groupId) as unknown;
  if (raw === undefined) return undefined;
  if (raw === null || raw === '' || raw === 'self' || raw === 'null') return null;
  if (typeof raw === 'string') return raw;
  return undefined;
}

/**
 * Resolves which single scope a request should act on.
 *
 * - Super Administrator: may target any group (?groupId=<id>, or a `groupId`
 *   body field on writes) or their own scope (omit it, or pass
 *   groupId=self/null) — unrestricted either way. This is how a Super Admin
 *   both maintains their own config and views/manages any group's.
 * - Group Admin: forced onto a group they actually belong to; the null
 *   (Super Admin's own) scope is never reachable for them, so they can never
 *   see or act on the Super Administrator's config/scans. `forWrite` (default
 *   true) additionally requires act-level (Group Admin, not Group Viewer)
 *   membership, mirroring the read/act distinction nodeScope.ts already
 *   defines and Policy Management already uses.
 * - A Group Admin of more than one group who doesn't pass `groupId` gets a
 *   400 asking them to specify one — there's no safe default among several.
 */
export async function resolveScannerGroupContext(
  req: Request,
  opts: { forWrite?: boolean } = {},
): Promise<ScannerScopeResult> {
  const forWrite = opts.forWrite ?? true;
  const jwtPayload = (req as unknown as { jwtPayload?: JwtPayload }).jwtPayload;
  if (!jwtPayload?.id) {
    return { ok: false, status: 401, message: 'Unauthorized' };
  }

  const scope = await getUserNodeScope(jwtPayload.id);
  const requested = readRequestedGroupId(req);

  if (scope.unrestricted) {
    // Super Administrator: whatever was asked for, including their own
    // (requested === undefined or null) scope.
    return { ok: true, ctx: { scope, groupId: requested ?? null } };
  }

  if (requested === null) {
    return {
      ok: false,
      status: 403,
      message: 'Only a Super Administrator can access the shared/global configuration.',
    };
  }

  if (requested !== undefined) {
    const permitted = forWrite ? canActOnGroup(scope, requested) : scopeGroupIds(scope).includes(requested);
    if (!permitted) {
      return { ok: false, status: 403, message: 'You do not have access to this group.' };
    }
    return { ok: true, ctx: { scope, groupId: requested } };
  }

  const allowedIds = forWrite ? actableGroupIds(scope) : scopeGroupIds(scope);
  if (allowedIds.length === 0) {
    return {
      ok: false,
      status: 403,
      message: forWrite ? 'You are not a Group Admin of any group.' : 'You do not belong to any group.',
    };
  }
  if (allowedIds.length > 1) {
    return {
      ok: false,
      status: 400,
      message: 'You belong to more than one group — specify which one with a groupId parameter.',
    };
  }
  return { ok: true, ctx: { scope, groupId: allowedIds[0] } };
}

/**
 * TypeORM `where.groupId` value for a resolved scope. TypeORM's query
 * builder does not reliably turn a literal `null` in a `where` object into
 * `IS NULL` (older/some code paths silently drop the condition instead,
 * which would turn "give me the Super Admin's own config" into "give me any
 * active config") — `IsNull()` is the one correct way to express it.
 */
export function groupIdWhereValue(groupId: string | null): string | ReturnType<typeof IsNull> {
  return groupId === null ? IsNull() : groupId;
}

/**
 * Cache key for the per-group singleton client caches in nessusClient.ts /
 * openvasClient.ts — Map keys can't be `null`, so the Super Admin's own scope
 * needs a concrete sentinel that can never collide with a real group_id
 * (group ids come from nodes_groups.group_id, which this app never sets to
 * this literal value).
 */
export const SUPER_ADMIN_SCOPE_KEY = '__super_admin__';

export function scannerCacheKey(groupId: string | null): string {
  return groupId === null ? SUPER_ADMIN_SCOPE_KEY : groupId;
}
