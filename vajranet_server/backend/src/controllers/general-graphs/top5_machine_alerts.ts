import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.generalGraphs.top5MachineAlerts');

/**
 * Returns the top 5 host identifiers with the highest number of alerts,
 * pulling the current hostname from the nodes table.
 */
export async function top5_machine_alert(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.warn({}, 'Top 5 machines by alert count fetch aborted: database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    // Scoped users only see nodes in their group(s); ungrouped/unmatched hosts are hidden.
    const scopeWhere = scope.unrestricted ? '' : 'WHERE n.owner_group_id = ANY($1::text[])';
    const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    /**
     * Known defect, not fixed. `GROUP BY` carries `a.hostname` (and `n.hostname`), so a
     * host whose alert rows do not all agree on `hostname` splits into several rows, each
     * with a partial count and each competing separately for a top-5 slot. Because the
     * output column is `COALESCE(n.hostname, a.hostname)`, a host present in `nodes`
     * renders its split rows under the same name — one machine shown twice.
     *
     * It is reachable today but stays below the fifth place, so it does not surface. Note
     * that the obvious check misses it: `count(DISTINCT hostname) > 1` ignores NULLs, and
     * most `alerts.hostname` values are NULL, so NULL has to be coalesced to a sentinel
     * before the split becomes visible.
     *
     * The correct grouping is `GROUP BY a.host_identifier` with the hostname taken by an
     * aggregate such as `min(COALESCE(n.hostname, a.hostname))`. Not applied because it
     * changes the rows and counts this endpoint returns.
     *
     * Do not "simplify" the `LOWER(...) = LOWER(...)` join to plain equality. It looks
     * gratuitous and is not: a handful of alerts differ from their `nodes` row only in
     * hostname case and would lose their `nodes` hostname under an exact join.
     */
    /**
     * Hosts with no row in `nodes` (deleted / re-enrolled under another id) are excluded: an INNER
     * JOIN, so alerts from machines that no longer exist never surface as a blank-named entry in
     * the dashboard's top-5 panels. Their alerts are untouched elsewhere (alert lists, totals).
     */
    const query = `
      SELECT
        a.host_identifier,
        COALESCE(n.hostname, a.hostname) AS hostname,
        COUNT(*) AS total_alerts,
        COUNT(CASE WHEN LOWER(a.severity) = 'information' THEN 1 END) AS information,
        COUNT(CASE WHEN LOWER(a.severity) = 'low' THEN 1 END) AS low,
        COUNT(CASE WHEN LOWER(a.severity) = 'medium' THEN 1 END) AS medium,
        COUNT(CASE WHEN LOWER(a.severity) = 'high' THEN 1 END) AS high,
        COUNT(CASE WHEN LOWER(a.severity) = 'critical' THEN 1 END) AS critical
      FROM alerts a
      JOIN nodes n ON LOWER(a.host_identifier) = LOWER(n.host_identifier)
      ${scopeWhere}
      GROUP BY a.host_identifier, n.hostname, a.hostname
      ORDER BY total_alerts DESC
      LIMIT 5
    `;

    const topMachines = await entityManager.query(query, params);

    logger.debug({ count: topMachines?.length ?? 0 }, 'Top 5 machines by alert count retrieved');
    return res.status(200).json({
      success: true,
      data: topMachines ?? [],
    });

  } catch (error) {
    logger.error({ err: error }, 'Failed to compute top 5 machines by alert count');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}