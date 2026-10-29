import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, actableGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertStatus');

/**
 * POST /api/alerts/status
 * Body: { event_id: Array<number|string> }
 * Returns the current is_open status of the requested alerts. Ids outside the
 * caller's scope are simply absent from the result, so a fully out-of-scope
 * request 404s rather than revealing that the alerts exist.
 */
export const alert_status = async (req: Request, res: Response, _next: NextFunction) => {
    const { event_id: eventIds } = req.body;

    if (!Array.isArray(eventIds) || eventIds.length === 0) {
        return res.status(400).json({ 
            status: 'Error', 
            message: "Invalid data: event_id must be a non-empty array of IDs." 
        });
    }

    const invalidIds = eventIds.filter((id: any) => {
        const n = Number(id);
        return isNaN(n) || !Number.isFinite(n) || !Number.isInteger(n);
    });
    if (invalidIds.length > 0) {
        return res.status(400).json({ 
            status: 'Error', 
            message: "Invalid data: all event_id values must be numeric." 
        });
    }

    try {
        const connections = dbSourceConnection();
        const entityManager = connections?.[1];

        if (!entityManager) {
            logger.error({ eventIds }, 'Database connection not established');
            return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
        }

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };

        const formattedIds = eventIds.map(id => BigInt(id));

        // Scoped callers only see alerts on nodes in their group(s). Alert types with
        // no matching `nodes` row (the Scan Scheduler's consolidated "Unmanaged Hosts
        // Detected" alert) qualify instead via the alert's own group_id, and that path
        // requires act-level (Group Admin) membership, not view-level, because this
        // endpoint is mutation-adjacent and sits behind requireAdmin.
        const scopeJoin = scope.unrestricted ? '' : 'LEFT JOIN nodes n ON n.host_identifier = alerts.host_identifier';
        const scopeWhere = scope.unrestricted
          ? ''
          : ' AND (n.owner_group_id = ANY($2::text[]) OR alerts.group_id = ANY($3::text[]))';
        const params: unknown[] = scope.unrestricted
          ? [formattedIds]
          : [formattedIds, scopeGroupIds(scope), actableGroupIds(scope)];
        const query = `
            SELECT alerts.id, alerts.is_open, alerts.mark_type
            FROM alerts
            ${scopeJoin}
            WHERE alerts.id = ANY($1)
            ${scopeWhere}
        `;

        const rows = await entityManager.query(query, params);

        if (!rows || rows.length === 0) {
            logger.info({ eventIds }, 'Alert status lookup found no matching alerts');
            return res.status(404).json({
                status: 'Error',
                message: 'No alerts found for the provided IDs.',
                searched_ids: eventIds
            });
        }

        if (rows.length < eventIds.length) {
            const foundIds = new Set(rows.map((row: any) => String(row.id)));
            const missingIds = eventIds.filter((id: any) => !foundIds.has(String(id)));
            logger.warn({ requested: eventIds.length, found: rows.length, missingIds }, 'Alert status lookup returned fewer alerts than requested, some ids not found or out of caller scope');
        }

        logger.info({ count: rows.length }, 'Alert status retrieved');
        return res.status(200).json({
            status: 'Success',
            count: rows.length,
            data: rows.map((row: any) => ({
                id: row.id.toString(),
                is_open: row.is_open,
                mark_type: row.mark_type,
            }))
        });

    } catch (error) {
        logger.error({ err: error, eventIds }, 'Failed to fetch alert status');
        return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
    }
};