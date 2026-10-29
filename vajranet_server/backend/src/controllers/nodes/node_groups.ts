import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.groups');

export async function node_groups(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];

    if (!db) {
      logger.error('Database connection not available while fetching node groups');
      return res.status(500).json({ status: 'Error', message: 'Database connection not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    const result = scope.unrestricted
      ? await db.query('SELECT DISTINCT name FROM nodes_groups WHERE name IS NOT NULL ORDER BY name ASC')
      : await db.query(
          'SELECT DISTINCT name FROM nodes_groups WHERE name IS NOT NULL AND group_id = ANY($1::text[]) ORDER BY name ASC',
          [scopeGroupIds(scope)],
        );
    const groups: string[] = (result ?? []).map((r: { name: string }) => r.name).filter(Boolean);

    logger.debug({ count: groups.length }, 'Node groups listed');

    return res.status(200).json({ status: 'Success', groups });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch node groups');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
