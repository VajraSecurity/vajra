import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, type NodeScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import type { AssetDetailDto, AssetIdentityDto } from '../../types/assetIdentity';
import { buildAssetListItems, type AssetBaseRow } from './listAssets';

const logger = getLogger('controllers.assets.getAsset');

/**
 * Rejects anything that is not a UUID before it reaches Postgres. Without this
 * a junk path segment makes `$1::uuid` raise `invalid input syntax for type
 * uuid`, which surfaces as an opaque 500 instead of a 400.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidAssetUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * Loads one asset's base row, or null if it does not exist OR is out of the
 * caller's scope — the two cases are deliberately indistinguishable so the
 * endpoint cannot be used to probe for the existence of another group's hosts
 * (same reasoning as node_rename.ts answering 404 rather than 403).
 *
 * Assets with owner_group_id IS NULL are invisible to scoped callers; see the
 * long note on assetScopeClause in listAssets.ts for why.
 */
export async function loadScopedAssetRow(
  db: { query: (sql: string, params?: unknown[]) => Promise<any> },
  scope: NodeScope,
  assetUuid: string,
): Promise<AssetBaseRow | null> {
  const params: unknown[] = [assetUuid];
  let scopeWhere = '';
  if (!scope.unrestricted) {
    params.push(scopeGroupIds(scope));
    scopeWhere = ' AND a.owner_group_id = ANY($2::text[])';
  }

  const rows: AssetBaseRow[] = await db.query(
    `
    SELECT a.asset_uuid,
           a.identity_confidence,
           a.needs_review,
           a.first_seen,
           a.last_seen,
           a.owner_group_id,
           a.merged_into
    FROM assets a
    WHERE a.asset_uuid = $1::uuid${scopeWhere}
    LIMIT 1
  `,
    params,
  );

  return rows[0] ?? null;
}

/**
 * GET /api/assets/:assetUuid — one asset plus every identity ever recorded for
 * it. Identities are multi-valued and accumulate, so this is also the IP /
 * hostname / MAC history for the machine: one row per distinct value, with the
 * window it was observed in.
 */
export async function getAsset(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.error('Fleet database not available while fetching asset');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const jwtPayload = (req as any).jwtPayload;
    if (!jwtPayload?.id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const assetUuid = req.params.assetUuid;
    if (!isValidAssetUuid(assetUuid)) {
      return res.status(400).json({ success: false, message: 'Invalid asset id' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    const baseRow = await loadScopedAssetRow(fleetDb, scope, assetUuid);
    if (!baseRow) {
      logger.warn({ assetUuid }, 'Asset detail rejected: not found or out of scope for caller');
      return res.status(404).json({ success: false, message: 'Asset not found' });
    }

    const [asset] = await buildAssetListItems(fleetDb, [baseRow]);

    const identityRows: Array<{
      kind: AssetIdentityDto['kind'];
      value_norm: string;
      weight: number;
      first_seen: Date;
      last_seen: Date;
    }> = await fleetDb.query(
      `
      SELECT kind, value_norm, weight, first_seen, last_seen
      FROM asset_identities
      WHERE asset_uuid = $1::uuid
      ORDER BY weight DESC, kind, last_seen DESC, value_norm
    `,
      [assetUuid],
    );

    const identities: AssetIdentityDto[] = identityRows.map((row) => ({
      kind: row.kind,
      value_norm: row.value_norm,
      weight: Number(row.weight),
      first_seen: new Date(row.first_seen).toISOString(),
      last_seen: new Date(row.last_seen).toISOString(),
    }));

    const data: AssetDetailDto = { asset, identities };

    logger.debug({ assetUuid, identityCount: identities.length }, 'Asset detail retrieved');
    return res.status(200).json({ success: true, data });
  } catch (err) {
    logger.error({ err }, 'Failed to fetch asset detail');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
