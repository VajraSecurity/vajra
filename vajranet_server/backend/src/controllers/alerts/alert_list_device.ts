import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_ALERTS } from '../../consts';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertListDevice');

export async function alert_list_device(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.body;

    if (!host_identifier) {
      return res.status(400).json({
        status: 'Error',
        message: 'Host identifier is required in the request body'
      });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier, userId: jwtPayload?.id }, 'Device alert list denied, host out of caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const rows = Math.min(parseInt(req.body.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_ALERTS);
    const pageno = Math.max(parseInt(req.body.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error({ host_identifier }, 'Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const query = `
      SELECT 
        id, host_identifier, hostname, unixtime, event_code, 
        metadata::json as metadata,
        is_alert, is_open, severity, alert_type, os_name
        , mark_type as mark_type
      FROM alerts
      WHERE host_identifier = $1
      ORDER BY id DESC
      LIMIT $2 OFFSET $3
    `;

    const alerts = await entityManager.query(query, [host_identifier, rows, offset]);

    logger.info({ host_identifier, count: alerts?.length ?? 0, page: pageno }, 'Device alert list retrieved');

    if (!alerts?.length) {
      return res.status(200).json({
        success: true,
        count: 0,
        page: pageno,
        alerts: [],
        message: 'No alerts found for this node'
      });
    }

    return res.status(200).json({
      success: true,
      count: alerts.length,
      page: pageno,
      alerts: alerts
    });

  } catch (error) {
    logger.error({ err: error, host_identifier: req.body?.host_identifier }, 'Failed to list alerts for device');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}