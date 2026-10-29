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

const logger = getLogger('windows.systemInfo');

export async function system_info_fetch(
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
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'System information lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // Single read-only SELECT — no transaction needed for atomicity here.
    const result = await entityManager.query(
      `SELECT *
       FROM system_info
       WHERE host_identifier = $1
         AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM system_info)
       ORDER BY unixtime DESC
       LIMIT 1`,
      [host_identifier]
    );

    if (!result?.length) {
      logger.debug({ host_identifier }, 'No system information found for host');
      return res.status(404).json({
        status: "Error",
        message: "No system information found for this host"
      });
    }

    logger.debug({ host_identifier, count: result.length }, 'System information retrieved');
    return res.status(200).json({
      status: "Success",
      message: "System information fetched successfully.",
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch system information');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}