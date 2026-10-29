import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.deviceGraphs.weeklyAlerts');

interface WeeklyData {
    [date: string]: {
        [alertType: string]: number;
    };
}

export const weekly_alerts = async (req: Request, res: Response, _next: NextFunction) => {
    try {
        const entityManager = dbSourceConnection()?.[1];
        if (!entityManager) {
            logger.warn({}, 'Weekly alert totals computation aborted: database connection not initialized');
            return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
        }

        const hostId = req.body?.host_identifier ? String(req.body.host_identifier) : null;

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };

        if (hostId) {
            if (!(await assertHostInScope(scope, hostId))) {
                logger.warn({ host_identifier: hostId, userId: jwtPayload?.id ?? null }, "Weekly alert totals computation denied: host outside caller's node scope");
                return res.status(404).json({ status: 'Error', message: 'Node not found' });
            }
        } else if (!scope.unrestricted && scopeGroupIds(scope).length === 0) {
            logger.info({ host_identifier: hostId || null }, 'Weekly alert totals computed: caller has no scoped groups');
            return res.status(200).json({ status: 'Success', message: 'No data available' });
        }

        /**
         * Timezone coupling, deliberately left in place. The seven bucket keys below are
         * built by `new Date(...)` in the Node process's local timezone, while `date_label`
         * in the SQL comes from `to_char(to_timestamp(...))` in the Postgres session
         * timezone, and the two are matched as plain strings. A mismatch fails silently:
         * a day's alerts are dropped rather than miscounted, so the response is a
         * plausible week with a hole in it — or "No data available" for a host with
         * plenty. `startTime` ($1) is computed in Node-local time too.
         *
         * Both sides must therefore stay on the same timezone. The robust fix (label in
         * SQL with an explicit AT TIME ZONE, or bucket in Node from raw unixtimes) is not
         * applied because it moves bucket boundaries, and so the response body, on any
         * deployment that is not already UTC.
         */
        const now = new Date();
        const sevenDaysAgo = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6, 0, 0, 0);
        const startTime = Math.floor(sevenDaysAgo.getTime() / 1000);

        const scopeJoin = !hostId && !scope.unrestricted
          ? 'JOIN nodes n ON n.host_identifier = alerts.host_identifier AND n.owner_group_id = ANY($2::text[])'
          : '';

        const query = `
            SELECT
                alert_type,
                COUNT(*) as count,
                to_char(to_timestamp(CAST(alerts.unixtime AS BIGINT)), 'FMDD/FMMM/YYYY') as date_label,
                MIN(CAST(alerts.unixtime AS BIGINT)) as day_order
            FROM alerts
            ${scopeJoin}
            WHERE CAST(alerts.unixtime AS BIGINT) >= $1
            ${hostId ? 'AND alerts.host_identifier = $2' : ''}
            GROUP BY alert_type, date_label
            ORDER BY day_order DESC;
        `;

        const params = hostId
          ? [startTime, hostId]
          : (!scope.unrestricted ? [startTime, scopeGroupIds(scope)] : [startTime]);
        const dbResult = await entityManager.query(query, params);

        // Initialize the last 7 days (empty per day; types come only from DB)
        const alertsResultObject: WeeklyData = {};
        for (let i = 0; i < 7; i++) {
            const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
            const label = `${d.getDate()}/${d.getMonth() + 1}/${d.getFullYear()}`;
            alertsResultObject[label] = {};
        }

        dbResult.forEach((row: any) => {
            const dateLabel = row.date_label;
            if (alertsResultObject[dateLabel] && row.alert_type != null) {
                const typeKey = String(row.alert_type);
                const n = parseInt(row.count, 10) || 0;
                alertsResultObject[dateLabel][typeKey] =
                    (alertsResultObject[dateLabel][typeKey] || 0) + n;
            }
        });

        const hasData = Object.values(alertsResultObject).some((day) =>
            Object.values(day).some((val) => val > 0)
        );

        logger.info({ host_identifier: hostId || null, hasData }, 'Weekly alert totals computed');
        return hasData
            ? res.status(200).json(alertsResultObject)
            : res.status(200).json({ status: "Success", message: "No data available" });

    } catch (err) {
        logger.error({ err, host_identifier: (req.body?.host_identifier as string | undefined) ?? null }, 'Failed to compute weekly alert totals');
        return res.status(500).json({
            status: "Error",
            message: "Query failed due to a database error."
        });
    }
};