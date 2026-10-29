import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { RECENT_ROWS_ID_WINDOW } from '../../consts/database';

const logger = getLogger('nodes.ip');

export async function node_ips(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.body;

    if (!host_identifier || typeof host_identifier !== 'string') {
      return res.status(400).json({
        status: 'Error',
        message: 'Host identifier is required and must be a string'
      });
    }

    const dataSources = dbSourceConnection();
    if (!dataSources || dataSources.length < 2) {
      logger.error({ host_identifier }, 'Database connection not initialized while fetching node IP interfaces');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Node IP interfaces request rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const entityManager = dataSources[1];

    // The `id > (SELECT MAX(id) - RECENT_ROWS_ID_WINDOW ...)` guard narrows the scan, but
    // written as a plain conjunct next to `host_identifier = $1` it becomes the *driving*
    // indexed predicate: the planner walks interface_addresses_pkey across the whole id
    // window and applies host_identifier as a post-filter, so
    // idx_interface_addresses_host_id (host_identifier, id DESC) — which covers both
    // conditions — never gets picked, and the cost is proportional to the table rather
    // than to the host.
    //
    // Feeding the host through a MATERIALIZED CTE hides its value from the planner at
    // plan time, so a constant-driven pkey walk is no longer an option and the
    // (host_identifier, id DESC) index has to lead; `lo` does the same for the id bound.
    //
    // The `id >` predicate must be preserved verbatim: it is what excludes hosts whose
    // newest row has aged out of the id window. No (host, interface, address) group has
    // two rows tied at max(unixtime) with differing payloads, so the ROW_NUMBER() dedupe
    // winner is unique and cannot shift with the plan.
    const query = `
      WITH lo AS MATERIALIZED (
        SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} AS min_id
        FROM interface_addresses
      ),
      scoped AS MATERIALIZED (
        SELECT $1::text AS hid
      ),
      LatestInterfaces AS (
        SELECT 
          interface,
          address,
          mask,
          friendly_name,
          type,
          unixtime,
          CASE 
            WHEN address != '127.0.0.1'
              AND address NOT LIKE '169.254.%'
              AND (friendly_name IS NULL OR friendly_name NOT ILIKE '%loopback%')
              AND (
                interface ~* '^(et|enp|eno|wl)'
                OR type ~* '(ethernet|dhcp)'
                OR friendly_name ~* '(ethernet|wi-fi)'
              )
            THEN 1
            ELSE 0
          END AS is_main_interface
        FROM (
          SELECT
            ia.interface,
            ia.address,
            ia.mask,
            ia.friendly_name,
            ia.type,
            ia.unixtime,
            ROW_NUMBER() OVER (PARTITION BY ia.interface, ia.address ORDER BY ia.unixtime DESC) AS rn
          FROM scoped s
          CROSS JOIN lo
          CROSS JOIN LATERAL (
            SELECT w.interface, w.address, w.mask, w.friendly_name, w.type, w.unixtime
              FROM interface_addresses w
             WHERE w.host_identifier = s.hid
               AND w.id > lo.min_id
               AND w.address IS NOT NULL
               AND w.address NOT LIKE '%:%'
          ) ia
        ) base
        WHERE rn = 1
      )
      SELECT 
        interface,
        address,
        mask,
        friendly_name,
        type,
        CASE 
          WHEN is_main_interface = 1 
           AND ROW_NUMBER() OVER (PARTITION BY is_main_interface ORDER BY unixtime DESC) = 1 
          THEN 1 
          ELSE 0 
        END AS priority
      FROM LatestInterfaces
      ORDER BY priority DESC, unixtime DESC;
    `;

    const ips = await entityManager.query(query, [host_identifier]);

    logger.debug({ host_identifier, count: Array.isArray(ips) ? ips.length : 0 }, 'Node IP interfaces retrieved');

    return res.status(200).json({
      host_identifier,
      interfaces: ips
    });

  } catch (error) {
    logger.error({ err: error, host_identifier: req.body?.host_identifier }, 'Failed to fetch node IP interfaces');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}