import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import {
  PAGINATION_DEFAULT_ROWS,
  PAGINATION_MAX_ROWS_NODES,
} from '../../consts';
import { getUserNodeScope, scopeGroupIds, type NodeScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import type {
  AssetListItemDto,
  IdentityKind,
  ObservationSource,
} from '../../types/assetIdentity';

const logger = getLogger('controllers.assets.listAssets');

/**
 * Cap on the IP list carried by a list row. An asset that has held a dozen
 * DHCP leases would otherwise push a dozen strings per row into the response
 * for no operator benefit — the full history is on the detail endpoint, which
 * returns every identity row. Matches the `ips: string[] // cap 5` contract in
 * types/assetIdentity.ts.
 */
const ASSET_LIST_MAX_IPS = 5;

/**
 * Identity kinds the list projection needs. `osquery_uuid` is deliberately
 * excluded: it is evidence for the audit trail (weight 0) and is not part of
 * AssetListItemDto, so fetching it would only add rows to the in-memory join.
 */
const LIST_IDENTITY_KINDS: IdentityKind[] = ['hostname', 'ip', 'mac', 'os'];

/** Shape of one row of the identity fan-out query. */
interface IdentityRow {
  asset_uuid: string;
  kind: IdentityKind;
  value_norm: string;
  last_seen: Date;
}

/** Shape of one row of the observation aggregate query. */
interface ObservationAggRow {
  asset_uuid: string;
  observation_count: string | number;
  sources: ObservationSource[] | null;
}

/** Shape of one row of the base `assets` page query. */
export interface AssetBaseRow {
  asset_uuid: string;
  identity_confidence: number;
  needs_review: boolean;
  first_seen: Date;
  last_seen: Date;
  owner_group_id: string | null;
  merged_into: string | null;
}

/**
 * SQL predicate + parameter restricting `assets` to what this caller may see.
 *
 * Scoped (non-Super-Admin) callers see only assets whose owner_group_id is one
 * of their groups. Assets with owner_group_id IS NULL are HIDDEN from them.
 * That is deliberate and matches node_list.ts's fail-safe default ("Nodes with
 * no group at all are hidden from scoped users"): an agentless asset — one only
 * nmap/OpenVAS/nuclei has ever seen — carries no group, because only an agent
 * observation can copy nodes.owner_group_id onto it. Showing those to every
 * Group Admin would leak the existence of hosts on subnets that group does not
 * own, which is exactly what group scoping exists to prevent. Such an asset
 * becomes visible to a group the moment it merges with an agent-backed asset,
 * at which point it has a real owner. The UI labels the null case
 * "Unassigned / discovered" so it does not read as a bug to a Super Admin.
 */
function assetScopeClause(scope: NodeScope, paramIndex: number): { clause: string; param?: string[] } {
  if (scope.unrestricted) return { clause: '' };
  return { clause: `a.owner_group_id = ANY($${paramIndex}::text[])`, param: scopeGroupIds(scope) };
}

/**
 * Fans a page of `assets` rows out into full AssetListItemDto values.
 *
 * Two extra queries total, never one per asset: identities are fetched for the
 * whole page in a single `asset_uuid = ANY(...)` lookup (the `asset_identities`
 * primary key is (asset_uuid, kind, value_norm), so that is an index scan) and
 * joined in memory, same shape as node_list.ts's security-products enrichment.
 * Shared with getAsset.ts so a detail row and a list row can never disagree.
 */
export async function buildAssetListItems(
  db: { query: (sql: string, params?: unknown[]) => Promise<any> },
  baseRows: AssetBaseRow[],
): Promise<AssetListItemDto[]> {
  if (baseRows.length === 0) return [];

  const assetUuids = baseRows.map((r) => r.asset_uuid);

  // Ordered last_seen DESC so the first hostname/os seen per asset is the most
  // recent one, and the IP cap keeps the newest leases rather than arbitrary ones.
  const identityRows: IdentityRow[] = await db
    .query(
      `
      SELECT asset_uuid, kind, value_norm, last_seen
      FROM asset_identities
      WHERE asset_uuid = ANY($1::uuid[])
        AND kind = ANY($2::text[])
      ORDER BY asset_uuid, last_seen DESC, value_norm
    `,
      [assetUuids, LIST_IDENTITY_KINDS],
    )
    .catch((err: unknown) => {
      logger.error({ err, step: 'identities' }, 'Asset list query failed for one step');
      throw err;
    });

  // asset_uuid is nullable on asset_observations (the matcher records rows it
  // declined to resolve), but `= ANY(<uuid list>)` never matches NULL, so those
  // audit rows are excluded here without a special case.
  const observationRows: ObservationAggRow[] = await db
    .query(
      `
      SELECT asset_uuid,
             COUNT(*)::bigint AS observation_count,
             ARRAY_AGG(DISTINCT source) AS sources
      FROM asset_observations
      WHERE asset_uuid = ANY($1::uuid[])
      GROUP BY asset_uuid
    `,
      [assetUuids],
    )
    .catch((err: unknown) => {
      logger.error({ err, step: 'observations' }, 'Asset list query failed for one step');
      throw err;
    });

  const identitiesByAsset = new Map<string, IdentityRow[]>();
  for (const row of identityRows) {
    const bucket = identitiesByAsset.get(row.asset_uuid);
    if (bucket) bucket.push(row);
    else identitiesByAsset.set(row.asset_uuid, [row]);
  }

  const observationsByAsset = new Map<string, ObservationAggRow>();
  for (const row of observationRows) observationsByAsset.set(row.asset_uuid, row);

  return baseRows.map((base) => {
    const identities = identitiesByAsset.get(base.asset_uuid) ?? [];
    const ips: string[] = [];
    const macs: string[] = [];
    let hostname: string | null = null;
    let osFamily: string | null = null;

    for (const identity of identities) {
      switch (identity.kind) {
        case 'hostname':
          if (hostname === null) hostname = identity.value_norm;
          break;
        case 'os':
          if (osFamily === null) osFamily = identity.value_norm;
          break;
        case 'ip':
          if (ips.length < ASSET_LIST_MAX_IPS) ips.push(identity.value_norm);
          break;
        case 'mac':
          macs.push(identity.value_norm);
          break;
        default:
          break;
      }
    }

    const observations = observationsByAsset.get(base.asset_uuid);

    return {
      asset_uuid: base.asset_uuid,
      hostname,
      ips,
      macs,
      os_family: osFamily,
      identity_confidence: Number(base.identity_confidence),
      needs_review: base.needs_review,
      // COUNT() comes back from node-postgres as a string for bigint.
      sources: observations?.sources ?? [],
      observation_count: Number(observations?.observation_count ?? 0),
      first_seen: new Date(base.first_seen).toISOString(),
      last_seen: new Date(base.last_seen).toISOString(),
      owner_group_id: base.owner_group_id,
      merged_into: base.merged_into,
    };
  });
}

/**
 * GET /api/assets — paginated list of resolved assets, newest sighting first.
 *
 * Query params: `rows`, `pageno`, `needs_review` ('true' to show only assets
 * the matcher flagged), `include_merged` ('true' to also show assets that have
 * been folded into another).
 */
export async function listAssets(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.error('Fleet database not available while listing assets');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const jwtPayload = (req as any).jwtPayload;
    if (!jwtPayload?.id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Raw NodeScope rather than resolveScannerGroupContext: that helper resolves
    // a request to a SINGLE target group and rejects a caller spanning several
    // (right for the single-config-row scanner settings it was built for). An
    // asset list spans groups — a Group Admin of three groups must see the union
    // of all three in one page — so this filters on scopeGroupIds directly, the
    // same reasoning as network/scanSchedules/list.ts.
    const scope = await getUserNodeScope(jwtPayload.id);

    const rows = Math.max(
      1,
      Math.min(parseInt(req.query.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_NODES),
    );
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;
    const needsReviewOnly = req.query.needs_review === 'true';
    const includeMerged = req.query.include_merged === 'true';

    const params: unknown[] = [rows, offset];
    const conditions: string[] = [];

    // A merged asset is a duplicate whose observations stay attached to it for
    // reversibility; surfacing it by default would show the same machine twice.
    if (!includeMerged) conditions.push('a.merged_into IS NULL');
    if (needsReviewOnly) conditions.push('a.needs_review');

    const { clause: scopeWhere, param: scopeParam } = assetScopeClause(scope, params.length + 1);
    if (scopeWhere) {
      conditions.push(scopeWhere);
      params.push(scopeParam);
    }

    const whereSql = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    // COUNT(*) OVER () rather than a second COUNT query: the window is computed
    // over the same already-filtered scan, so the total costs no extra pass.
    const baseRows: (AssetBaseRow & { total_count: string })[] = await fleetDb
      .query(
        `
        SELECT a.asset_uuid,
               a.identity_confidence,
               a.needs_review,
               a.first_seen,
               a.last_seen,
               a.owner_group_id,
               a.merged_into,
               COUNT(*) OVER () AS total_count
        FROM assets a
        ${whereSql}
        ORDER BY a.last_seen DESC, a.asset_uuid
        LIMIT $1 OFFSET $2
      `,
        params,
      )
      .catch((err: unknown) => {
        logger.error({ err, step: 'assets' }, 'Asset list query failed for one step');
        throw err;
      });

    // Zero when the page is empty, including a page requested past the end of
    // the result set — the window function has no row to carry the count on.
    // Consistent with every other paginated list here, which likewise reports
    // only what the current page can see.
    const total = baseRows.length > 0 ? Number(baseRows[0].total_count) : 0;
    const data = await buildAssetListItems(fleetDb, baseRows);

    logger.debug({ count: data.length, total, page: pageno }, 'Asset list retrieved');
    return res.status(200).json({
      success: true,
      total,
      count: data.length,
      page: pageno,
      rows,
      data,
    });
  } catch (err) {
    logger.error({ err }, 'Failed to fetch asset list');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
