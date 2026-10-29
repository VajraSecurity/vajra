import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import {
  ERROR_MISSING_HOST_IDENTIFIER,
  ERROR_DATABASE_CONNECTION,
  ERROR_NODE_NOT_FOUND,
  ERROR_DATABASE_FETCH_FAILED,
} from '../../consts/http';
import { getLogger } from '../../utils/logger';

const logger = getLogger('windows.securityProducts');

export async function windows_security_products_fetch(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const { host_identifier } = req.body;

  if (!host_identifier || typeof host_identifier !== 'string') {
    return res.status(400).json({
      status: "Error",
      message: ERROR_MISSING_HOST_IDENTIFIER
    });
  }

  const dataSources = dbSourceConnection();
  if (!dataSources?.[1]) {
    logger.error({ host_identifier }, 'Database connection error');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_CONNECTION
    });
  }

  const entityManager = dataSources[1];

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Windows security products lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // Single read-only SELECT — no transaction needed for atomicity here.
    //
    // Single-host variant of utils/latestSecurityProducts.ts, shaped the same way
    // and for the same reason. The obvious form,
    //
    //   SELECT DISTINCT ON (host_identifier, name) * ... WHERE host_identifier = $1
    //     AND id > (SELECT MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE ...)
    //   ORDER BY host_identifier, name, unixtime DESC, id DESC
    //
    // reads as though it should ride idx_windows_security_products_host_name_time
    // (host_identifier, name, unixtime DESC, id DESC), which it matches column for
    // column. It does not: the `id >` guard is the only predicate the planner can
    // turn into an index bound cheaply, so it drives the scan off the primary key
    // across the whole id window, demotes host_identifier to a post-filter and
    // external-merge-sorts the result — to return two rows.
    //
    // Two rows is the point: a host has only a handful of distinct product names.
    // So enumerate those names with a recursive loose index scan, then take one row
    // per name. Both halves are pure index lookups on host_name_time, which already
    // covers the (name, unixtime DESC, id DESC) tie-break DISTINCT ON wanted.
    //
    // The `id >` guard survives as a residual filter inside the LATERAL rather than
    // as the driver. It is load-bearing: it excludes a (host, name) pair whose
    // newest row has aged out of the id window, and dropping it would add rows this
    // endpoint does not return. A name whose rows are all outside the window
    // contributes nothing, because the LATERAL is an inner join.
    const result = await entityManager.query(
      `WITH RECURSIVE lo AS (
         SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} AS min_id
         FROM windows_security_products
       ),
       names AS (
         SELECT (SELECT w.name
                   FROM windows_security_products w
                  WHERE w.host_identifier = $1
                  ORDER BY w.name
                  LIMIT 1) AS nm
         UNION ALL
         SELECT (SELECT w.name
                   FROM windows_security_products w
                  WHERE w.host_identifier = $1
                    AND w.name > n.nm
                  ORDER BY w.name
                  LIMIT 1)
           FROM names n
          WHERE n.nm IS NOT NULL
       )
       SELECT s.*
         FROM names n
         CROSS JOIN lo
         CROSS JOIN LATERAL (
           SELECT w.*
             FROM windows_security_products w
            WHERE w.host_identifier = $1
              AND w.name = n.nm
              AND w.id > lo.min_id
            ORDER BY w.unixtime DESC, w.id DESC
            LIMIT 1
         ) s
        WHERE n.nm IS NOT NULL

        UNION ALL

        -- The recursive walk seeds with ORDER BY w.name LIMIT 1 (NULLS LAST) and
        -- steps with w.name > n.nm, so a NULL-named group is unreachable by it.
        -- The DISTINCT ON form this replaced emitted that group like any other,
        -- so without this branch a NULL product name would silently disappear.
        -- windows_security_products.name has no NOT NULL constraint; production
        -- has zero NULL names today, so this is latent rather than live. The
        -- sibling loose index scans in utils/latestSecurityProducts.ts and
        -- controllers/nodes/node_storage.ts both carry the same branch.
        SELECT s.*
          FROM lo
          CROSS JOIN LATERAL (
            SELECT w.*
              FROM windows_security_products w
             WHERE w.host_identifier = $1
               AND w.name IS NULL
               AND w.id > lo.min_id
             ORDER BY w.unixtime DESC, w.id DESC
             LIMIT 1
          ) s
        -- Explicit column names, not ordinal positions: the select list is
        -- 's.*', whose first two columns are id and host_identifier, so
        -- ORDER BY 1, 2 would silently reorder the response.
        ORDER BY host_identifier, name`,
      [host_identifier]
    );

    if (!result?.length) {
      logger.info({ host_identifier }, 'No Windows security products found for host');
      return res.status(404).json({
        status: "Error",
        message: "No security products found for this host"
      });
    }

    logger.info({ host_identifier, count: result.length }, 'Windows security products retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Windows security products fetched successfully.",
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch Windows security products');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}