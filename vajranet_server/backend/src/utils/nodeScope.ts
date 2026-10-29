/**
 * Central node-group access-scoping helper.
 *
 * Users and groups live in different PostgreSQL DataSources (primary vs fleet),
 * so scoping is always a two-step, app-level join: resolve the caller's group
 * membership from the primary DB, then filter fleet DB queries by those group
 * ids. Every enforcement point (REST controllers, websockets, threat hunting)
 * goes through this module rather than re-implementing the join.
 *
 * A node belongs to at most one group at a time (nodes.owner_group_id, a
 * single column — not a list). That is what makes a group's node set
 * exclusive: no node can ever satisfy two different groups' scope checks at
 * once, so there's no "which group does this shared node belong to" question
 * to get wrong.
 */

import type { Request } from 'express';
import { dbSourceConnection } from '../index';
import type { GroupMembershipRole } from '../orm/entities/users/UserGroupMembership';
import { GROUP_MEMBERSHIP_ROLE_ADMIN, GROUP_MEMBERSHIP_ROLE_VIEWER } from '../orm/entities/users/UserGroupMembership';
import { SUPER_ADMIN_ROLE } from '../orm/entities/users/Users';
import { getLogger } from './logger';

const logger = getLogger('nodes.scope');

export interface ScopedGroup {
  id: string;
  role: GroupMembershipRole;
}

export type NodeScope =
  | { unrestricted: true }
  | { unrestricted: false; groups: ScopedGroup[] };

/** IDs of every group this scope can see, regardless of role within it. */
export function scopeGroupIds(scope: NodeScope): string[] {
  return scope.unrestricted ? [] : scope.groups.map((g) => g.id);
}

/** IDs of only the groups this scope has act-level (Group Admin) membership in. */
export function actableGroupIds(scope: NodeScope): string[] {
  return scope.unrestricted ? [] : scope.groups.filter((g) => g.role === GROUP_MEMBERSHIP_ROLE_ADMIN).map((g) => g.id);
}

/** True if the caller has write/act-level access (not just read) on this group. */
export function canActOnGroup(scope: NodeScope, groupId: string): boolean {
  if (scope.unrestricted) return true;
  return scope.groups.some((g) => g.id === groupId && g.role === GROUP_MEMBERSHIP_ROLE_ADMIN);
}

/**
 * Resolves the node-group access scope for a user. Always re-reads role +
 * membership from the primary DB (same pattern as requireAdmin/requireSuperAdmin)
 * rather than trusting the JWT, so a demoted/reassigned user is scoped correctly
 * on their very next request.
 */
export async function getUserNodeScope(userId: number): Promise<NodeScope> {
  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb || !primaryDb.isInitialized) {
    // Fail closed: if we can't resolve scope, treat the caller as fully restricted
    // with no groups rather than granting unrestricted access.
    logger.warn({ userId }, 'Primary database not initialized, failing closed to no groups for node scope');
    return { unrestricted: false, groups: [] };
  }

  let rows: { role: string | null; group_id: string | null; membership_role: string | null }[];
  try {
    rows = await primaryDb.query(
      `SELECT u.role AS role, ugm.group_id AS group_id, ugm.role AS membership_role
       FROM vajra_users u
       LEFT JOIN user_group_memberships ugm ON ugm.user_id = u.id
       WHERE u.id = $1`,
      [userId],
    );
  } catch (err) {
    // Fail closed on a transient DB error too, not just an uninitialized DataSource.
    logger.warn({ err, userId }, 'Failed to resolve user node scope, failing closed to no groups');
    return { unrestricted: false, groups: [] };
  }

  if (!rows || rows.length === 0) {
    // A valid JWT for a userId with no vajra_users row: a deleted account, or a
    // stale or forged id. Logged so it is distinguishable from a caller who
    // simply belongs to no groups.
    logger.warn({ userId }, 'No matching user row for node scope resolution, failing closed to no groups');
    return { unrestricted: false, groups: [] };
  }

  const role = rows[0].role;
  if (role === SUPER_ADMIN_ROLE) {
    return { unrestricted: true };
  }

  const groups: ScopedGroup[] = rows
    .filter((r): r is typeof r & { group_id: string } => !!r.group_id)
    .map((r) => ({
      id: r.group_id,
      role: r.membership_role === GROUP_MEMBERSHIP_ROLE_VIEWER ? GROUP_MEMBERSHIP_ROLE_VIEWER : GROUP_MEMBERSHIP_ROLE_ADMIN,
    }));

  return { unrestricted: false, groups };
}

/**
 * Per-request memo slot. A Symbol rather than a string property so it cannot
 * collide with anything Express, a body parser, or another middleware hangs
 * off the request object, and so it never shows up in an accidental
 * JSON.stringify(req) or Object.keys walk.
 */
const NODE_SCOPE_MEMO = Symbol('vajra.nodeScopeMemo');

interface NodeScopeMemoHolder {
  [NODE_SCOPE_MEMO]?: Map<number, Promise<NodeScope>>;
}

/**
 * getUserNodeScope memoised for the lifetime of one HTTP request. The query
 * above runs from well over a hundred call sites, and a single page load fans
 * out into ~11 endpoints, so an unmemoised read repeats the same
 * `vajra_users LEFT JOIN user_group_memberships` many times per page against a
 * pool every other request shares.
 *
 * This preserves getUserNodeScope's freshness guarantee, which is stated per
 * request: the memo lives on one Request object, which Express discards when
 * the response ends, so scope is still re-read from the database once per
 * request and a demoted user is scoped correctly on their next one. All that is
 * given up is a role change taking effect partway through an already-running
 * request, which was never reliable anyway, and the memo makes a request at
 * least self-consistent rather than authorising half its work under each scope.
 *
 * Never turn this into a cross-request cache. Any TTL widens the window in which
 * a demoted user keeps their old scope and breaks that guarantee outright.
 *
 * Keyed by userId rather than a single slot, because some call sites resolve
 * another user's scope and must never be served the caller's. The memoised
 * value is the promise, not the scope, so concurrent call sites share one
 * in-flight query; getUserNodeScope handles its own errors and returns a
 * fail-closed scope, so no rejection can lodge in the memo.
 *
 * WebSocket and cron callers have no Request and call getUserNodeScope directly.
 */
export function getRequestNodeScope(req: Request, userId: number): Promise<NodeScope> {
  const holder = req as unknown as NodeScopeMemoHolder;
  let memo = holder[NODE_SCOPE_MEMO];
  if (!memo) {
    memo = new Map<number, Promise<NodeScope>>();
    holder[NODE_SCOPE_MEMO] = memo;
  }

  const pending = memo.get(userId);
  if (pending) return pending;

  const resolving = getUserNodeScope(userId);
  memo.set(userId, resolving);
  return resolving;
}

/**
 * SQL fragment + param builder for filtering a nodes-derived query by scope.
 * Reads nodes.owner_group_id — the single-owner column, indexed with a plain
 * btree — never the display-only group_ids array.
 */
export function scopeCondition(
  scope: NodeScope,
  paramIndex: number,
  column = 'owner_group_id',
): { clause: string | null; param: string[] | null } {
  if (scope.unrestricted) {
    return { clause: null, param: null };
  }
  const groupIds = scopeGroupIds(scope);
  // groupIds may be empty — `= ANY('{}')` against an empty array correctly
  // matches nothing, which is the desired "assigned to zero groups -> sees
  // nothing" behavior.
  return { clause: `${column} = ANY($${paramIndex}::text[])`, param: groupIds };
}

/**
 * Checks whether a single host is within the caller's scope. Used by every
 * host_identifier-keyed controller and both websocket handlers so there is
 * exactly one implementation of "is this host in this scope".
 */
export async function assertHostInScope(scope: NodeScope, hostIdentifier: unknown): Promise<boolean> {
  if (typeof hostIdentifier !== 'string' || !hostIdentifier) return false;
  if (scope.unrestricted) return true;
  const groupIds = scopeGroupIds(scope);
  if (groupIds.length === 0) return false;

  const dataSources = dbSourceConnection();
  const fleetDb = dataSources?.[1];
  if (!fleetDb || !fleetDb.isInitialized) {
    logger.warn({ hostIdentifier }, 'Fleet database not initialized, failing closed to host not in scope');
    return false;
  }

  let rows: unknown[];
  try {
    rows = await fleetDb.query(
      `SELECT 1 FROM nodes WHERE host_identifier = $1 AND owner_group_id = ANY($2::text[]) LIMIT 1`,
      [hostIdentifier, groupIds],
    );
  } catch (err) {
    logger.error({ err, hostIdentifier }, 'assertHostInScope query failed');
    throw err;
  }
  return Array.isArray(rows) && rows.length > 0;
}

/**
 * Like assertHostInScope, but additionally requires "act" (not just "read")
 * permission on the group that owns this host — i.e. it rejects a Group
 * Viewer membership even though the host is otherwise within that caller's
 * scope. Use this only at points that actually mutate a node or dispatch a
 * command to its agent (WS agent commands, the AI's propose_agent_action,
 * rename/critical endpoints); every read-only lookup should
 * keep using assertHostInScope so a Group Viewer keeps full read access.
 */
export async function assertCanActOnHost(scope: NodeScope, hostIdentifier: unknown): Promise<boolean> {
  if (typeof hostIdentifier !== 'string' || !hostIdentifier) return false;
  if (scope.unrestricted) return true;
  const groupIds = scopeGroupIds(scope);
  if (groupIds.length === 0) return false;

  const dataSources = dbSourceConnection();
  const fleetDb = dataSources?.[1];
  if (!fleetDb || !fleetDb.isInitialized) {
    logger.warn({ hostIdentifier }, 'Fleet database not initialized, failing closed to cannot-act-on-host');
    return false;
  }

  let rows: { owner_group_id: string | null }[];
  try {
    rows = await fleetDb.query(
      `SELECT owner_group_id FROM nodes WHERE host_identifier = $1 AND owner_group_id = ANY($2::text[]) LIMIT 1`,
      [hostIdentifier, groupIds],
    );
  } catch (err) {
    logger.error({ err, hostIdentifier }, 'assertCanActOnHost query failed');
    throw err;
  }
  if (!Array.isArray(rows) || rows.length === 0) return false;
  const ownerGroupId = rows[0]?.owner_group_id;
  return typeof ownerGroupId === 'string' && canActOnGroup(scope, ownerGroupId);
}

/**
 * Resolves the set of host_identifiers visible to a scoped caller. Used where
 * a single WHERE clause on the target table isn't practical — e.g. building
 * the in-memory host->group map for the live dashboard/WebSocket path.
 */
export async function getScopedHostIdentifiers(scope: NodeScope): Promise<string[] | null> {
  if (scope.unrestricted) return null; // null = no filtering needed
  const groupIds = scopeGroupIds(scope);
  if (groupIds.length === 0) return [];

  const dataSources = dbSourceConnection();
  const fleetDb = dataSources?.[1];
  if (!fleetDb || !fleetDb.isInitialized) {
    logger.warn({ groupIds }, 'Fleet database not initialized, failing closed to no scoped host identifiers');
    return [];
  }

  let rows: { host_identifier: string }[];
  try {
    rows = await fleetDb.query(
      `SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($1::text[])`,
      [groupIds],
    );
  } catch (err) {
    logger.error({ err, groupIds }, 'getScopedHostIdentifiers query failed');
    throw err;
  }
  return rows.map((r) => r.host_identifier);
}

/**
 * Like getScopedHostIdentifiers, but only nodes owned by a group where the
 * caller has act-level (Group Admin) membership — a Group Viewer membership
 * is excluded, same distinction as assertCanActOnHost vs assertHostInScope.
 * Use this where a bulk operation needs "everything I can act on" rather than
 * "everything I can see" (e.g. deciding which policies a caller may manage).
 */
export async function getActableHostIdentifiers(scope: NodeScope): Promise<string[] | null> {
  if (scope.unrestricted) return null;
  const groupIds = actableGroupIds(scope);
  if (groupIds.length === 0) return [];

  const dataSources = dbSourceConnection();
  const fleetDb = dataSources?.[1];
  if (!fleetDb || !fleetDb.isInitialized) {
    logger.warn({ groupIds }, 'Fleet database not initialized, failing closed to no actable host identifiers');
    return [];
  }

  let rows: { host_identifier: string }[];
  try {
    rows = await fleetDb.query(
      `SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($1::text[])`,
      [groupIds],
    );
  } catch (err) {
    logger.error({ err, groupIds }, 'getActableHostIdentifiers query failed');
    throw err;
  }
  return rows.map((r) => r.host_identifier);
}
