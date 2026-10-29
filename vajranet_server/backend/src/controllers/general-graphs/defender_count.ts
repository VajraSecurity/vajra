import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.generalGraphs.defenderCount');

export async function defender_count(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const dataSources = dbSourceConnection();

  if (!dataSources?.[1]) {
    logger.warn({}, 'Firewall statistics fetch aborted: database connection error');
    return res.status(500).json({
      status: "Error",
      message: "Database connection error"
    });
  }

  const entityManager = dataSources[1];

  try {
    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    // The scope filter is an EXISTS rather than a JOIN. Equivalent here because every
    // aggregate below is a per-host existence test, so join-side row multiplication could
    // not have affected the result (and nodes.host_identifier is unique anyway).
    const scopeFilter = scope.unrestricted
      ? ''
      : `AND EXISTS (
             SELECT 1 FROM nodes n
             WHERE n.host_identifier = h.host_identifier
               AND n.owner_group_id = ANY($1::text[])
           )`;
    const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    /**
     * These are deliberately FULL-HISTORY counts, not "current state" counts. A host that
     * was ever 'On' and later 'Off' is counted in BOTH buckets, so `on + off` can
     * legitimately exceed `total_hosts`, and it does on live data.
     *
     * Rewriting this to "latest state per host" is the obvious-looking optimisation and
     * it silently changes the numbers the dashboard shows. Do not do it without a product
     * decision: if the dashboard is meant to show current state, that is a spec change,
     * not a performance fix.
     *
     * The access path is a loose index scan (skip scan): the recursive CTE hops
     * host_identifier to host_identifier through
     * idx_windows_security_products_name_host_state using min(... > previous), then asks
     * two EXISTS questions per host. Because that index is (name, host_identifier, state)
     * every probe is an index-only scan that stops at the first matching entry, so the
     * work is a few probes per host rather than a scan proportional to retained history —
     * the cost no longer grows as agents keep reporting.
     */
    const query = `
      WITH RECURSIVE h AS (
          SELECT (
            SELECT min(host_identifier)
            FROM windows_security_products
            WHERE name = 'Windows Firewall'
          ) AS host_identifier
        UNION ALL
          SELECT (
            SELECT min(w.host_identifier)
            FROM windows_security_products w
            WHERE w.name = 'Windows Firewall'
              AND w.host_identifier > h.host_identifier
          )
          FROM h
          WHERE h.host_identifier IS NOT NULL
      )
      SELECT
        COUNT(*) FILTER (WHERE EXISTS (
          SELECT 1 FROM windows_security_products w
          WHERE w.name = 'Windows Firewall'
            AND w.host_identifier = h.host_identifier
            AND w.state = 'On'
        )) AS firewall_on_count,
        COUNT(*) FILTER (WHERE EXISTS (
          SELECT 1 FROM windows_security_products w
          WHERE w.name = 'Windows Firewall'
            AND w.host_identifier = h.host_identifier
            AND w.state = 'Off'
        )) AS firewall_off_count,
        COUNT(*) AS total_unique_hosts
      FROM h
      WHERE h.host_identifier IS NOT NULL
      ${scopeFilter};
    `;

    const result = await entityManager.query(query, params);

    const stats = result[0] || { firewall_on_count: 0, firewall_off_count: 0, total_unique_hosts: 0 };

    logger.debug({ total_hosts: parseInt(stats.total_unique_hosts) || 0 }, 'Firewall statistics retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Firewall statistics fetched successfully.",
      data: {
        on: parseInt(stats.firewall_on_count),
        off: parseInt(stats.firewall_off_count),
        total_hosts: parseInt(stats.total_unique_hosts)
      }
    });

  } catch (error) {
    logger.error({ err: error }, "Failed to calculate firewall statistics");
    return res.status(500).json({
      status: "Error",
      message: "Failed to calculate firewall statistics."
    });
  }
}