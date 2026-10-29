import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { NODE_COMPLIANCE_HISTORY_MAX_ROWS } from '../../consts/pagination';

const logger = getLogger('nodes.compliance');

/**
 * GET /api/nodes/compliance/latest/:host_identifier
 *
 * Returns the most recent compliance_results row for the given node.
 */
export async function node_compliance_latest(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error({ host_identifier }, 'Database connection not available while fetching latest compliance data');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Latest compliance data request rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const rows = await db.query(
      `SELECT id, host_identifier, unixtime, compliance_data
       FROM compliance_results
       WHERE host_identifier = $1
       ORDER BY id DESC
       LIMIT 1`,
      [host_identifier],
    );

    logger.debug({ host_identifier, found: !!rows?.[0] }, 'Latest compliance data retrieved');

    return res.status(200).json({ success: true, data: rows?.[0] ?? null });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to fetch latest compliance data');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}

/**
 * GET /api/nodes/compliance/history/:host_identifier
 *
 * Returns the newest compliance_results rows for the given node, capped at
 * NODE_COMPLIANCE_HISTORY_MAX_ROWS, to build the historical trend chart.
 */
export async function node_compliance_history(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error({ host_identifier }, 'Database connection not available while fetching compliance history');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Compliance history request rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const rows = await db.query(
      `SELECT id, host_identifier, unixtime, compliance_data
       FROM compliance_results
       WHERE host_identifier = $1
       ORDER BY id DESC
       LIMIT ${NODE_COMPLIANCE_HISTORY_MAX_ROWS}`,
      [host_identifier],
    );

    logger.debug({ host_identifier, count: rows?.length ?? 0 }, 'Compliance history retrieved');

    return res.status(200).json({ success: true, data: rows ?? [] });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to fetch compliance history');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
