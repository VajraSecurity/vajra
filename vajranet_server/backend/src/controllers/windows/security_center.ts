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

const logger = getLogger('windows.securityCenter');

export async function windows_security_center_fetch(
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
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Windows Security Center lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // Single read-only SELECT — no transaction needed for atomicity here.
    const result = await entityManager.query(
      `SELECT *
       FROM windows_security_center
       WHERE host_identifier = $1
         AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_security_center)
       ORDER BY unixtime DESC
       LIMIT 1`,
      [host_identifier]
    );

    if (!result?.length) {
      logger.info({ host_identifier }, 'No Windows Security Center data found for host');
      return res.status(404).json({
        status: "Error",
        message: "No Windows Security Center data found for this host"
      });
    }

    logger.info({ host_identifier, count: result.length }, 'Windows Security Center data retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Windows Security Center data fetched successfully.",
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch Windows Security Center data');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}