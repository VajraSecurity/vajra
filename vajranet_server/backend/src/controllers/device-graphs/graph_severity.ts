import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.deviceGraphs.severity');

interface SeverityResult {
    name: string;
    value: number;
}

export const alert_severity_count = async (req: Request, res: Response, _next: NextFunction) => {
    try {
        const entityManager = dbSourceConnection()?.[1];
        if (!entityManager) {
            logger.warn({}, 'Alert severity count aborted: database connection not initialized');
            return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
        }

        const hostId = req.body.host_identifier as string | undefined;
        const labels = ["Information", "Low", "Medium", "High", "Critical"];

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };

        if (hostId) {
            if (!(await assertHostInScope(scope, hostId))) {
                logger.warn({ host_identifier: hostId, userId: jwtPayload?.id ?? null }, "Alert severity count denied: host outside caller's node scope");
                return res.status(404).json({ status: 'Error', message: 'Node not found' });
            }
        } else if (!scope.unrestricted && scopeGroupIds(scope).length === 0) {
            logger.info({ host_identifier: hostId || null }, 'Alert severity counts retrieved: caller has no scoped groups');
            return res.status(200).json({ status: 'Success', message: 'No data available' });
        }

        const query = `
            SELECT v.lvl as severity, COUNT(a.id) as value
            FROM (VALUES ('0'), ('1'), ('2'), ('3'), ('4')) AS v(lvl)
            LEFT JOIN alerts a ON v.lvl = CASE
                WHEN LOWER(a.severity) = 'information' THEN '0'
                WHEN LOWER(a.severity) = 'low' THEN '1'
                WHEN LOWER(a.severity) = 'medium' THEN '2'
                WHEN LOWER(a.severity) = 'high' THEN '3'
                WHEN LOWER(a.severity) = 'critical' THEN '4'
                ELSE NULL
            END
            AND ($1::text IS NULL OR a.host_identifier = $1)
            AND ($2::text[] IS NULL OR a.host_identifier IN (SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($2::text[])))
            GROUP BY v.lvl
            ORDER BY v.lvl;
        `;

        const dbResult = await entityManager.query(query, [hostId || null, scope.unrestricted ? null : scopeGroupIds(scope)]);

        let hasData = false;
        const finalResult: SeverityResult[] = dbResult.map((row: any) => {
            const val = parseInt(row.value, 10) || 0;
            if (val > 0) hasData = true;
            
            const severityIndex = parseInt(row.severity, 10);
            return {
                name: labels[severityIndex] || "Unknown",
                value: val
            };
        });

        if (!hasData) {
            logger.info({ host_identifier: hostId || null }, 'Alert severity counts retrieved: no data available');
            return res.status(200).json({ status: "Success", message: "No data available" });
        }

        logger.info({ host_identifier: hostId || null, resultCount: finalResult.length }, 'Alert severity counts retrieved');
        return res.status(200).json(finalResult);

    } catch (err) {
        logger.error({ err, host_identifier: (req.body?.host_identifier as string | undefined) ?? null }, "Failed to retrieve severity counts");
        return res.status(500).json({ status: "Error", message: "Can't retrieve severity counts." });
    }
};