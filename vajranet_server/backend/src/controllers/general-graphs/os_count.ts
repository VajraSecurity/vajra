import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.generalGraphs.osCount');

export const os_count = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const connections = dbSourceConnection();

        if (!connections || !connections[1]) {
            throw new Error('Database connection not initialized.');
        }

        const entityManager = connections[1];

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };
        const scopeWhere = scope.unrestricted ? '' : 'WHERE owner_group_id = ANY($1::text[])';
        const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

        const result = await entityManager.query(`
            SELECT
                COUNT(*)::INT as count,
                CASE
                    WHEN LOWER(os_name) LIKE '%windows%' THEN 'Windows'
                    WHEN LOWER(os_name) LIKE '%kali%'
                      OR LOWER(os_name) LIKE '%ubuntu%'
                      OR LOWER(os_name) LIKE '%linux%'
                      OR LOWER(os_name) LIKE '%arch%' THEN 'Linux'
                    WHEN LOWER(os_name) LIKE '%darwin%'
                      OR LOWER(os_name) LIKE '%mac%' THEN 'MacOS'
                    ELSE 'Other'
                END as "name"
            FROM nodes
            ${scopeWhere}
            GROUP BY "name"
        `, params);

        logger.debug({ count: result.length }, 'OS count breakdown retrieved');
        return res.status(200).json(result);
    } catch (err) {
        logger.error({ err }, 'Failed to compute OS count breakdown');
        return next(err);
    }
};