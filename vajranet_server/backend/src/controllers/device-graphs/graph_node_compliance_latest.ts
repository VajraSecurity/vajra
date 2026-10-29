import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.deviceGraphs.nodeComplianceLatest');

/**
 * POST /api/graph/node_compliance_latest
 * body: { host_identifier: string }
 *
 * Returns the latest compliance_results row for the host and a flag indicating
 * whether historic compliance data exists.
 */
export async function graph_node_compliance_latest(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.body as { host_identifier?: string };
    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.warn({ host_identifier }, 'Latest node compliance fetch aborted: database not available');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier, userId: jwtPayload?.id ?? null }, "Latest node compliance fetch denied: host outside caller's node scope");
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

    const latest = rows?.[0] ?? null;
    logger.info({ host_identifier, exists: Boolean(latest) }, 'Latest node compliance result retrieved');
    return res.status(200).json({
      success: true,
      exists: Boolean(latest),
      data: latest,
    });
  } catch (error) {
    logger.error({ err: error, host_identifier: (req.body as { host_identifier?: string })?.host_identifier }, 'Failed to fetch latest node compliance result');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
