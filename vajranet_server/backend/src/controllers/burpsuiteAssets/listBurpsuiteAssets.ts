import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import {
  PAGINATION_DEFAULT_ROWS,
  PAGINATION_MAX_ROWS_NODES,
} from '../../consts';
import { getUserNodeScope, scopeGroupIds, type NodeScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.burpsuiteAssets.listBurpsuiteAssets');

/**
 * One "Burp Suite asset" -- every burpsuite_scan_history row in scope whose
 * normalized_target (see utils/urlIdentity.ts's normalizeBurpTarget, computed
 * at scan-launch time and backed by an index -- see the column's own comment
 * on BurpsuiteScanHistory) is the same host[:port], collapsed into a single
 * summary row. Shared with getBurpsuiteAsset.ts, which returns the same shape
 * as the `asset` half of its response so a list row and a detail row can
 * never disagree about one target's current state.
 */
export interface BurpsuiteAssetListItem {
  normalized_target: string;
  /** Same as normalized_target for now -- kept as a separate field in case a
   *  future revision prettifies it for display (e.g. adding back a scheme)
   *  without having to change the grouping key itself. */
  display_host: string;
  scan_count: number;
  last_status: string;
  last_scanned_at: string | null;
  first_scanned_at: string;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
  group_id: string | null;
}

/** undefined = caller didn't specify a group; null = caller explicitly asked
 *  for "my own"/the shared scope (only meaningful for a Super Administrator);
 *  a string = a specific group id. Mirrors scannerScope.ts's
 *  readRequestedGroupId (not exported from there, and this endpoint reads it
 *  from the query string only -- every route this feature adds is a GET). */
function readRequestedGroupId(req: Request): string | null | undefined {
  const raw = req.query?.groupId as unknown;
  if (raw === undefined) return undefined;
  if (raw === null || raw === '' || raw === 'self' || raw === 'null') return null;
  if (typeof raw === 'string') return raw;
  return undefined;
}

export type BurpAssetsScopeFilter =
  | { kind: 'all' }
  | { kind: 'exact'; groupId: string | null }
  | { kind: 'any'; groupIds: string[] };

export type BurpAssetsScopeResult =
  | { ok: true; filter: BurpAssetsScopeFilter }
  | { ok: false; status: number; message: string };

/**
 * Resolves which burpsuite_scan_history rows a caller may see for this
 * feature. Generalizes listBurpsuiteScans's group-scoping rule (see its own
 * long comment in burpsuiteController.ts) to a LIST that -- like
 * controllers/assets/listAssets.ts -- must span every group a multi-group
 * Group Admin belongs to, not just one. resolveScannerGroupContext cannot
 * express that (it always resolves a request to exactly one scope), so this
 * is built directly on raw getUserNodeScope()/scopeGroupIds(), same reasoning
 * as assetScopeClause in listAssets.ts.
 *
 * - Super Administrator, no ?groupId=: 'all' -- every row in the table, every
 *   group's scans AND the Super Administrator's own (null groupId) scans
 *   alike. Matches listBurpsuiteScans's isMergedView default. (Not reachable
 *   from this app's own UI today -- BurpsuiteAssetsList.tsx always passes an
 *   explicit selectedGroupId -- but a caller that omits it gets this, not a
 *   narrower "self" scope; see burpsuiteAssetsApi.ts's own comment.)
 * - Super Administrator, ?groupId=<id|self|null>: 'exact' -- narrows to just
 *   that one group (or the null/self bucket).
 * - Group Admin/Viewer, ?groupId=<id>: 'exact', but only if that id is one of
 *   their own groups -- 403 otherwise. groupId=self/null is always 403 for a
 *   non-Super-Administrator, same message resolveScannerGroupContext uses.
 * - Group Admin/Viewer, no ?groupId=: 'any' -- the union of every group they
 *   belong to. Belonging to zero groups is not an error here: it resolves to
 *   an empty group-id set, i.e. zero rows, matching listAssets.ts's fail-safe
 *   (a caller in no group sees nothing rather than getting a 403 on a list
 *   endpoint).
 */
export function resolveBurpAssetsScope(req: Request, scope: NodeScope): BurpAssetsScopeResult {
  const requested = readRequestedGroupId(req);

  if (scope.unrestricted) {
    if (requested === undefined) return { ok: true, filter: { kind: 'all' } };
    return { ok: true, filter: { kind: 'exact', groupId: requested } };
  }

  if (requested !== undefined) {
    if (requested === null) {
      return {
        ok: false,
        status: 403,
        message: 'Only a Super Administrator can access the shared/global configuration.',
      };
    }
    if (!scopeGroupIds(scope).includes(requested)) {
      return { ok: false, status: 403, message: 'You do not have access to this group.' };
    }
    return { ok: true, filter: { kind: 'exact', groupId: requested } };
  }

  return { ok: true, filter: { kind: 'any', groupIds: scopeGroupIds(scope) } };
}

/**
 * Turns a BurpAssetsScopeFilter into a SQL WHERE fragment (referencing an
 * unqualified `group_id` column) plus the params it needs, numbered starting
 * at `startIndex` so the caller can freely combine this with other
 * placeholders (normalized_target, LIMIT/OFFSET, ...) in the same query
 * without renumbering by hand.
 *
 * 'exact' with a null groupId is `group_id IS NULL`, never `group_id = NULL`
 * -- SQL's `=` never matches NULL, which is exactly the correctness bug this
 * function exists to avoid (the TypeORM equivalent, groupIdWhereValue, exists
 * for the same reason on the ORM-query-builder side).
 */
function scopeFilterToSql(
  filter: BurpAssetsScopeFilter,
  startIndex: number,
): { clause: string; params: unknown[] } {
  if (filter.kind === 'all') return { clause: 'TRUE', params: [] };
  if (filter.kind === 'exact') {
    if (filter.groupId === null) return { clause: 'group_id IS NULL', params: [] };
    return { clause: `group_id = $${startIndex}`, params: [filter.groupId] };
  }
  // 'any' -- an empty array must never reach `= ANY($1::text[])`: an empty
  // array literal there is valid SQL (correctly matches nothing), but the
  // caller-facing contract (see fetchScopedAssetRows below) short-circuits
  // this case before ever building a query, so this branch's `FALSE` is a
  // pure defensive backstop, not the real code path for that case.
  if (filter.groupIds.length === 0) return { clause: 'FALSE', params: [] };
  return { clause: `group_id = ANY($${startIndex}::text[])`, params: [filter.groupIds] };
}

interface BurpAssetAggregateRow {
  normalized_target: string;
  scan_count: string; // COUNT(*) comes back as a string from node-postgres for bigint-typed aggregates
  first_scanned_at: string;
  group_id: string | null;
  last_status: string;
  last_scanned_at: string | null;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
}

function toAssetListItem(row: BurpAssetAggregateRow): BurpsuiteAssetListItem {
  return {
    normalized_target: row.normalized_target,
    display_host: row.normalized_target,
    scan_count: Number(row.scan_count),
    last_status: row.last_status,
    last_scanned_at: row.last_scanned_at ? new Date(row.last_scanned_at).toISOString() : null,
    first_scanned_at: new Date(row.first_scanned_at).toISOString(),
    issues_high: row.issues_high,
    issues_medium: row.issues_medium,
    issues_low: row.issues_low,
    issues_total: row.issues_total,
    group_id: row.group_id,
  };
}

/**
 * Aggregation shared by listBurpsuiteAssets (paginated) and getBurpsuiteAsset
 * (one target). Does the grouping IN SQL -- a GROUP BY for scan_count/
 * first_scanned_at, joined via LATERAL to each target's single most-recent
 * row (by created_at DESC, id DESC) for its current status/issue
 * counts/group_id -- rather than pulling every scoped row into Node and
 * grouping there. That was this feature's original shape; it does not scale
 * (an unbounded `repo.find()` with no LIMIT on every request), which is
 * exactly why this column/query exist. `normalized_target IS NOT NULL` scopes
 * out unparsable targets the same way groupBurpScanRowsByTarget's null-skip
 * used to.
 *
 * `extraWhere`/`extraParams` (optional) let getBurpsuiteAsset narrow to one
 * target without duplicating this whole query.
 */
async function fetchBurpAssetAggregates(
  fleetDb: import('typeorm').DataSource,
  filter: BurpAssetsScopeFilter,
  options: { limit?: number; offset?: number; extraWhereOnNormalizedTarget?: string } = {},
): Promise<{ rows: BurpAssetAggregateRow[]; total: number }> {
  if (filter.kind === 'any' && filter.groupIds.length === 0) return { rows: [], total: 0 };

  const params: unknown[] = [];
  const scopeSql = scopeFilterToSql(filter, params.length + 1);
  params.push(...scopeSql.params);

  let whereClause = `normalized_target IS NOT NULL AND ${scopeSql.clause}`;
  if (options.extraWhereOnNormalizedTarget !== undefined) {
    params.push(options.extraWhereOnNormalizedTarget);
    whereClause += ` AND normalized_target = $${params.length}`;
  }

  let limitOffsetSql = '';
  if (options.limit !== undefined) {
    params.push(options.limit);
    limitOffsetSql += ` LIMIT $${params.length}`;
    params.push(options.offset ?? 0);
    limitOffsetSql += ` OFFSET $${params.length}`;
  }

  const sql = `
    WITH scoped AS (
      -- Explicit column list, not SELECT * -- results_json/metrics_json hold
      -- cached Burp issue_events/scan_metrics payloads (hundreds of KB to MB,
      -- TOASTed out-of-line) and nothing here reads them; a bare SELECT *
      -- would fetch them anyway and reintroduce exactly the cost this
      -- rewrite exists to remove.
      SELECT id, group_id, target, status, issues_high, issues_medium, issues_low,
             issues_total, created_at, updated_at, normalized_target
      FROM burpsuite_scan_history
      WHERE ${whereClause}
    ), grouped AS (
      SELECT normalized_target, COUNT(*) AS scan_count, MIN(created_at) AS first_scanned_at
      FROM scoped
      GROUP BY normalized_target
    )
    SELECT
      g.normalized_target,
      g.scan_count,
      g.first_scanned_at,
      latest.group_id,
      latest.status AS last_status,
      latest.updated_at AS last_scanned_at,
      latest.issues_high,
      latest.issues_medium,
      latest.issues_low,
      latest.issues_total,
      COUNT(*) OVER() AS total_count
    FROM grouped g
    JOIN LATERAL (
      SELECT group_id, status, updated_at, issues_high, issues_medium, issues_low, issues_total
      FROM scoped s
      WHERE s.normalized_target = g.normalized_target
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    ) latest ON TRUE
    ORDER BY latest.updated_at DESC NULLS LAST, g.normalized_target ASC
    ${limitOffsetSql}
  `;

  const rawRows: (BurpAssetAggregateRow & { total_count: string })[] = await fleetDb.query(sql, params);
  const total = rawRows.length > 0 ? Number(rawRows[0].total_count) : 0;
  return { rows: rawRows, total };
}

/**
 * GET /api/burpsuite/assets -- paginated list of distinct Burp Suite scan
 * targets in the caller's scope, one row per normalized host[:port], newest
 * activity first.
 *
 * Query params: `rows` (page size), `pageno` (1-based page), optional
 * `groupId` (see resolveBurpAssetsScope for its exact semantics).
 */
export async function listBurpsuiteAssets(req: Request, res: Response, _next: NextFunction): Promise<void> {
  try {
    const jwtPayload = (req as any).jwtPayload;
    if (!jwtPayload?.id) {
      res.status(401).json({ success: false, message: 'Unauthorized' });
      return;
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    const scopeResult = resolveBurpAssetsScope(req, scope);
    if (!scopeResult.ok) {
      res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
      return;
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb || !fleetDb.isInitialized) {
      logger.warn({}, 'Burp Suite asset listing aborted: fleet database not available');
      res.status(503).json({ success: false, message: 'Fleet database not available' });
      return;
    }

    const pageRows = Math.max(
      1,
      Math.min(parseInt(req.query.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_NODES),
    );
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * pageRows;

    const { rows, total } = await fetchBurpAssetAggregates(fleetDb, scopeResult.filter, {
      limit: pageRows,
      offset,
    });
    const pageItems = rows.map(toAssetListItem);

    logger.debug({ total, count: pageItems.length, page: pageno }, 'Burp Suite asset list retrieved');
    res.json({
      success: true,
      total,
      count: pageItems.length,
      page: pageno,
      rows: pageRows,
      data: pageItems,
    });
  } catch (error: any) {
    logger.error({ err: error }, 'Failed to list Burp Suite assets');
    res.status(500).json({ success: false, message: error.message || 'Internal server error' });
  }
}

export { fetchBurpAssetAggregates, scopeFilterToSql, toAssetListItem };
