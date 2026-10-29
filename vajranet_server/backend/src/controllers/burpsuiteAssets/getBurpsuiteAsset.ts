import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import {
  fetchBurpAssetAggregates,
  scopeFilterToSql,
  toAssetListItem,
  type BurpAssetsScopeFilter,
  type BurpsuiteAssetListItem,
} from './listBurpsuiteAssets';

const logger = getLogger('controllers.burpsuiteAssets.getBurpsuiteAsset');

/** One raw scan row for a Burp Suite asset's detail view, newest first. */
export interface BurpsuiteScanSummary {
  id: number;
  taskId: string;
  /** The RAW original URL as scanned (not normalized) -- so the UI can show
   *  e.g. "this specific scan hit https://www.example.com/login". */
  target: string;
  status: string;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
  created_at: string;
  updated_at: string;
}

interface BurpScanHistoryRow {
  id: number;
  task_id: string;
  target: string;
  status: string;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
  created_at: string;
  updated_at: string;
}

function toScanSummary(row: BurpScanHistoryRow): BurpsuiteScanSummary {
  return {
    id: Number(row.id),
    taskId: row.task_id,
    target: row.target,
    status: row.status,
    issues_high: row.issues_high,
    issues_medium: row.issues_medium,
    issues_low: row.issues_low,
    issues_total: row.issues_total,
    created_at: new Date(row.created_at).toISOString(),
    updated_at: new Date(row.updated_at).toISOString(),
  };
}

/**
 * GET /api/burpsuite/assets/:normalizedTarget -- one Burp Suite asset (a
 * distinct normalized scan target) plus every raw scan_history row that
 * target has ever seen, newest first.
 *
 * Unlike listBurpsuiteAssets, there is no ?groupId= narrowing here: this
 * endpoint always scopes to the caller's FULL visibility (every group they
 * belong to, or everything for a Super Administrator) and matches the
 * requested target against that already-scoped set. That ordering -- scope
 * first, target match second -- is what makes a target that exists only in a
 * group this caller cannot see 404 exactly like one that does not exist
 * anywhere at all, the same "don't reveal whether it exists in another scope"
 * principle controllers/assets/getAsset.ts uses for OpenVAS assets.
 *
 * Both queries below (the aggregate, and the raw scan list) apply the SAME
 * scope filter independently -- neither one ever sees a row the other
 * wouldn't, so there is no window where the aggregate's issue counts could
 * describe a scan the `scans` array doesn't also include.
 */
export async function getBurpsuiteAsset(req: Request, res: Response, _next: NextFunction): Promise<void> {
  // Express 5's ParamsDictionary types every param as `string | string[]` to
  // accommodate repeat-modifier route segments (e.g. ':name+'). This route
  // ('/assets/:normalizedTarget') has no such modifier, so this is always a
  // plain string at runtime -- the guard below is a type narrowing, not a
  // real expected case, and an array (which cannot occur here) is treated the
  // same as a missing param rather than risking a wrong string coercion.
  const rawParamValue = req.params.normalizedTarget;
  const rawParam = typeof rawParamValue === 'string' ? rawParamValue : undefined;
  try {
    const jwtPayload = (req as any).jwtPayload;
    if (!jwtPayload?.id) {
      res.status(401).json({ success: false, message: 'Unauthorized' });
      return;
    }

    if (!rawParam) {
      res.status(400).json({ success: false, message: 'Invalid target' });
      return;
    }

    // Express already URL-decodes a path segment (including a %3A-encoded
    // colon, e.g. "example.com%3A8080") before it lands in req.params, so
    // decodedTarget === rawParam in the ordinary case. The extra
    // decodeURIComponent only guards a client that double-encoded the value;
    // it is intentionally best-effort -- an already-decoded param containing
    // a literal "%" that isn't valid percent-encoding just falls back to the
    // raw value rather than 400ing on something that was never double-encoded.
    let decodedTarget: string;
    try {
      decodedTarget = decodeURIComponent(rawParam);
    } catch {
      decodedTarget = rawParam;
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    const filter: BurpAssetsScopeFilter = scope.unrestricted
      ? { kind: 'all' }
      : { kind: 'any', groupIds: scopeGroupIds(scope) };

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb || !fleetDb.isInitialized) {
      logger.warn({}, 'Burp Suite asset detail fetch aborted: fleet database not available');
      res.status(503).json({ success: false, message: 'Fleet database not available' });
      return;
    }

    // Scope-filtered FIRST, matched against the requested target SECOND -- see
    // this function's header comment for why that order is load-bearing.
    const { rows: aggregateRows } = await fetchBurpAssetAggregates(fleetDb, filter, {
      extraWhereOnNormalizedTarget: decodedTarget,
    });

    if (aggregateRows.length === 0) {
      logger.debug(
        { normalizedTarget: decodedTarget },
        'Burp Suite asset detail rejected: not found or out of scope for caller',
      );
      res.status(404).json({ success: false, message: 'Asset not found' });
      return;
    }

    const asset: BurpsuiteAssetListItem = toAssetListItem(aggregateRows[0]);

    const scopeSql = scopeFilterToSql(filter, 2);
    const scansSql = `
      SELECT id, task_id, target, status, issues_high, issues_medium, issues_low, issues_total, created_at, updated_at
      FROM burpsuite_scan_history
      WHERE normalized_target = $1 AND ${scopeSql.clause}
      ORDER BY created_at DESC, id DESC
    `;
    const scanRows: BurpScanHistoryRow[] = await fleetDb.query(scansSql, [decodedTarget, ...scopeSql.params]);
    const scans: BurpsuiteScanSummary[] = scanRows.map(toScanSummary);

    logger.debug(
      { normalizedTarget: decodedTarget, scanCount: scans.length },
      'Burp Suite asset detail retrieved',
    );
    res.json({ success: true, data: { asset, scans } });
  } catch (error: any) {
    logger.error({ err: error, normalizedTarget: rawParam }, 'Failed to fetch Burp Suite asset detail');
    res.status(500).json({ success: false, message: error.message || 'Internal server error' });
  }
}
