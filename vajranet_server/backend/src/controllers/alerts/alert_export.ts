import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { ALERT_EXPORT_MAX_ROWS } from '../../consts';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertExport');

export const alerts_export = async (req: Request, res: Response, _next: NextFunction) => {
    const { start_time, end_time } = req.query;

    const start = Number(start_time);
    const end = Number(end_time);

    if (!Number.isFinite(start) || !Number.isFinite(end)) {
        return res.status(400).json({ status: 'Error', message: 'start_time and end_time must be valid numbers' });
    }

    try {
        const connections = dbSourceConnection();
        const entityManager = connections?.[1];

        if (!entityManager) {
            logger.error({ start, end }, 'Database connection not available');
            return res.status(500).json({ status: 'Error', message: 'Database connection not available' });
        }

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };
        // Same two-path scope test as alert_list.ts / alert_list_my.ts / alert_by_id.ts:
        // the host's node group, OR the alert's own group_id for alert types with no
        // matching `nodes` row (the Scan Scheduler's consolidated "Unmanaged Hosts
        // Detected" alert). Without the second half this export is under-inclusive —
        // not a leak, but a scoped user's CSV silently omits alerts they can see in
        // the UI, which reads as data loss rather than as a permission boundary.
        const scopeCondition = scope.unrestricted
          ? ''
          : 'AND (n.owner_group_id = ANY($4::text[]) OR a.group_id = ANY($4::text[]))';
        const params: unknown[] = scope.unrestricted
          ? [start, end, ALERT_EXPORT_MAX_ROWS]
          : [start, end, ALERT_EXPORT_MAX_ROWS, scopeGroupIds(scope)];

        const alerts = await entityManager.query(
            `SELECT
                a.id, a.host_identifier, COALESCE(n.hostname, a.hostname) AS hostname, a.unixtime, a.event_code,
                a.metadata, a.is_alert, a.is_open, a.context_data,
                a.severity, a.technique, a.technique_id, a.pid, a.link,
                a.mark_type AS mark_type,
                a.event_id, a.alert_type,
                COALESCE(n.os_name, a.os_name) AS os_name, n.os_platform, n.osquery_version
             FROM alerts AS a
             LEFT JOIN nodes AS n ON a.host_identifier = n.host_identifier
             WHERE a.unixtime >= $1 AND a.unixtime <= $2
             ${scopeCondition}
             ORDER BY a.unixtime DESC
             LIMIT $3;`,
            params
        );

        logger.debug({ start, end, count: alerts?.length ?? 0, userId: jwtPayload?.id }, 'Alerts exported');

        const truncated = !!alerts && alerts.length === ALERT_EXPORT_MAX_ROWS;
        if (truncated) {
            logger.warn({ start, end, count: alerts.length, limit: ALERT_EXPORT_MAX_ROWS }, 'Alerts export hit row limit, results may be truncated');
        }
        res.setHeader('X-Alerts-Truncated', String(truncated));

        if (!alerts || alerts.length === 0) {
            return res.status(200).json({
                status: 'Success',
                message: 'No data available',
                debug: { range: [start, end] }
            });
        }

        return res.status(200).json(alerts);

    } catch (error) {
        logger.error({ err: error, start, end }, 'Failed to export alerts');
        return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
    }
};