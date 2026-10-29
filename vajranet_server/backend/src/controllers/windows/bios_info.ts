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

const logger = getLogger('windows.biosInfo');

export async function bios_info_fetch(
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
  const entityManager = dataSources?.[1];

  if (!entityManager) {
    logger.error({ host_identifier }, 'Database connection error');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_CONNECTION
    });
  }

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'BIOS info lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // Keep one latest row per BIOS name for the host.
    //
    // Written as an aggregate over narrow keys plus a primary-key re-fetch rather
    // than the obvious `SELECT DISTINCT ON (name) ... ORDER BY name, <time> DESC,
    // id DESC`. DISTINCT ON is implemented as a sort, so it has to sort the host's
    // entire id-window slice carrying every output column just to keep one row per
    // name group, which spills to temp files at work_mem=4MB.
    // MAX(ARRAY[<time-key>, id]) expresses the same pick as an aggregate: Postgres
    // compares arrays element by element, so the largest array is the row with the
    // highest time key, ties broken by the highest id — exactly the DISTINCT ON
    // ordering. `id` is the primary key, so the ordering is total and the winner
    // unique; element [2] is that id and the join re-reads the winners by pkey.
    //
    // The scan still comes off wmi_bios_info_pkey rather than
    // idx_wmi_bios_info_host_name_id: the planner costs the host index higher on a
    // table this size, and a host's rows for one name are interleaved one per
    // ingestion batch across thousands of heap pages, so that is not obviously
    // wrong. The loose-index-scan shape used by utils/latestSecurityProducts.ts and
    // forcing the host bitmap both measured worse. A genuinely cheap plan needs an
    // index on (host_identifier, name, unixtime DESC, id DESC) — the shape
    // windows_security_products already has — which is a migration, not a query
    // change.
    //
    // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` guard is load-bearing for the
    // result set, not dead weight.
    const query = `
      WITH winners AS (
        SELECT (MAX(ARRAY[
                  CASE
                    WHEN unixtime::text ~ '^[0-9]+$' THEN unixtime::bigint
                    ELSE 0
                  END,
                  id
                ]))[2] AS id
        FROM wmi_bios_info
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM wmi_bios_info)
        GROUP BY name
      )
      SELECT b.id, b.host_identifier, b.unixtime, b.name, b.value
      FROM winners w
      JOIN wmi_bios_info b ON b.id = w.id
      ORDER BY b.name ASC
    `;

    const result = await entityManager.query(query, [host_identifier]);

    if (!result || result.length === 0) {
      logger.debug({ host_identifier }, 'No BIOS information found for host');
      return res.status(404).json({
        status: "Error",
        message: "No BIOS information found for this host"
      });
    }

    logger.debug({ host_identifier, count: result.length }, 'BIOS information retrieved');
    return res.status(200).json({
      status: "Success",
      message: "BIOS information fetched successfully.",
      count: result.length,
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch BIOS information');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}
