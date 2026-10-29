import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.deviceGraphs.alertStatus');

/**
 * POST /api/graph/alert_status
 * Body: { host_identifier?: string }
 * Open/closed alert counts, for one host when host_identifier is given and across the
 * caller's scope otherwise. A host outside the caller's scope 404s.
 *
 * Name collision: `alert_status` is also the exported name of
 * controllers/alerts/alert_status.ts, which backs POST /api/alerts/status. The two
 * resolve correctly only because they sit behind separate barrels — routes/api/graphs.ts
 * imports this one from '../../controllers/device-graphs', routes/api/alerts.ts imports
 * the other from '../../controllers/alerts'. They are NOT interchangeable: the alerts one
 * is behind requireAdmin and this one is not, so a combined barrel or a careless
 * auto-import would silently swap an admin-gated handler for an ungated one. Renaming
 * this export means editing routes/api/graphs.ts in the same change or it will not
 * compile.
 *
 * Two shapes for "nothing", deliberately not normalised:
 *   - caller has no scoped groups   -> array [{count:0,name:'Online'},{count:0,name:'Offline'}]
 *   - query returned 0 open, 0 closed -> object {status:'Success',message:'No data available'}
 * Both branches are reachable. dashboardApi.getAlertStatus absorbs either, but they are not
 * equivalent downstream: pages/Dashboard maps the array into chart series and renders two
 * zero slices, while the object coerces to [] and renders an empty chart. Normalising would
 * change what a live screen draws and the body seen by any non-browser caller.
 */
export const alert_status = async (req: Request, res: Response, _next: NextFunction) => {
    try {
        const dbSource = dbSourceConnection();
        const entityManager = dbSource?.[1];

        if (!entityManager) {
            logger.warn({}, 'Alert status count aborted: database connection not initialized');
            return res.status(500).json({
                status: 'Error',
                message: 'Database connection not initialized.'
            });
        }

        const host_identifier = req.body.host_identifier as string | undefined;

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };

        if (host_identifier) {
            if (!(await assertHostInScope(scope, host_identifier))) {
                logger.warn({ host_identifier, userId: jwtPayload?.id ?? null }, "Alert status count denied: host outside caller's node scope");
                return res.status(404).json({ status: 'Error', message: 'Node not found' });
            }
        } else if (!scope.unrestricted && scopeGroupIds(scope).length === 0) {
            logger.info({ host_identifier: null, open: 0, closed: 0 }, 'Alert status counts retrieved: caller has no scoped groups');
            return res.status(200).json([{ count: 0, name: 'Online' }, { count: 0, name: 'Offline' }]);
        }

        const scopeJoin = !host_identifier && !scope.unrestricted
          ? 'JOIN nodes n ON n.host_identifier = alerts.host_identifier AND n.owner_group_id = ANY($2::text[])'
          : '';
        const params: unknown[] = !host_identifier && !scope.unrestricted
          ? [host_identifier || null, scopeGroupIds(scope)]
          : [host_identifier || null];

        const query = `
            SELECT
                COUNT(*) FILTER (WHERE is_open = true) AS open_count,
                COUNT(*) FILTER (WHERE is_open = false) AS closed_count
            FROM alerts
            ${scopeJoin}
            WHERE ($1::text IS NULL OR alerts.host_identifier = $1);
        `;

        const [result] = await entityManager.query(query, params);
        const open = parseInt(result?.open_count, 10) || 0;
        const closed = parseInt(result?.closed_count, 10) || 0;

        // Latent: the two FILTERs test `is_open = true` / `is_open = false`, so a row with a
        // NULL `is_open` lands in neither bucket and enough of them would make a host with
        // real alerts report "No data available". Counting them would change the numbers
        // this endpoint returns, so it is left as is.

        if (open === 0 && closed === 0) {
            logger.info({ host_identifier: host_identifier || null }, 'Alert status counts retrieved: no data available');
            return res.status(200).json({ status: 'Success', message: 'No data available' });
        }

        logger.info({ host_identifier: host_identifier || null, open, closed }, 'Alert status counts retrieved');
        return res.status(200).json([
            { count: open, name: 'Online' },
            { count: closed, name: 'Offline' }
        ]);

    } catch (err) {
        logger.error({ err, host_identifier: (req.body as { host_identifier?: string })?.host_identifier ?? null }, 'Failed to retrieve alert status count');
        return res.status(500).json({
            status: 'Error', 
            message: "Can't retrieve alert status count."
        });
    }
};