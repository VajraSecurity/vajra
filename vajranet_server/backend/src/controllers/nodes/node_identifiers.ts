import { Request, Response, NextFunction } from 'express';
import { In } from 'typeorm';
import { dbSourceConnection } from '../../index';
import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS } from '../../consts';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.identifiers');

export async function node_identifiers(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error('Database connection not initialized while fetching node identifiers');
      return res.status(500).json({
        status: 'Error',
        message: 'Database connection not initialized or insufficient sources'
      });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    const scopeWhere = scope.unrestricted ? '' : 'WHERE owner_group_id = ANY($1::text[])';
    const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    const query = `
      SELECT
        hostname,
        host_identifier,
        os_platform,
        address,
        owner_group_id,
        CASE
          WHEN last_seen > (EXTRACT(EPOCH FROM NOW()) - ${NODE_STATUS_ONLINE_THRESHOLD_SECONDS}) THEN 'Online'
          ELSE 'Offline'
        END AS status
      FROM nodes
      ${scopeWhere}
      ORDER BY hostname ASC
    `;

    const result = await entityManager.query(query, params);

    logger.debug({ count: result?.length || 0 }, 'Node identifiers listed');

    return res.status(200).json({
      success: true,
      count: result?.length || 0,
      nodes: result || []
    });

  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch node identifiers');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}

/**
 * The caller's own group memberships with per-group role ('Group Admin' vs
 * view-only 'Group Viewer'), keyed by group_id — lets a page that already has
 * each node's owner_group_id (e.g. node_identifiers above) work out client-side
 * which nodes it may actually act on vs merely view, without a round trip per
 * node. Mirrors controllers/domain-reputation/scopeController.listMyGroups,
 * which serves the identical shape for that feature's group picker.
 */
export async function node_my_group_roles(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];
    if (!entityManager) {
      return res.status(500).json({ success: false, message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    if (scope.unrestricted) {
      return res.status(200).json({ success: true, data: { unrestricted: true, groups: [] } });
    }

    const groupRepo = entityManager.getRepository(EndpointGroup);
    const ids = scope.groups.map((g) => g.id);
    const rows = ids.length ? await groupRepo.find({ where: { groupId: In(ids) } }) : [];
    const nameById = new Map(rows.map((r) => [r.groupId, r.name]));
    const groups = scope.groups.map((g) => ({ group_id: g.id, name: nameById.get(g.id) ?? g.id, role: g.role }));

    return res.status(200).json({ success: true, data: { unrestricted: false, groups } });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch caller\'s group roles');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
