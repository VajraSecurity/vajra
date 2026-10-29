import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { ALERT_TYPE_CLAMAV_SCAN } from '../../consts/alerts';

const logger = getLogger('alerts.clamavScanLatest');

/**
 * GET /alerts/clamav-scan-latest?host_identifier=X&since=T
 *
 * Returns the most recent completed ClamAV scan for a host with
 * unixTime >= T (unix seconds). Used by the dashboard to poll for
 * scan results when the WebSocket push is missed (dropped connection,
 * page refresh mid-scan, etc.).
 *
 * Every clamav_scan_push from the agent is persisted to the alerts
 * table (alert_type = 'ClamAV Scan') by the nodeExt handler — clean
 * scans, error scans, and infected scans alike. This endpoint reads
 * that row back so the frontend does not need to receive the live push
 * to display the result.
 *
 * Response:
 *   { found: false }                      — scan not finished yet
 *   { found: true, scan: CommandResponse } — scan complete; same shape
 *                                           as clamav_scan_push response
 */
export async function clamav_scan_latest(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier, since } = req.query as Record<string, string>;

    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const sinceTs = Number(since) || 0;

    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];
    if (!entityManager) {
      logger.error({ host_identifier }, 'Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier, userId: jwtPayload?.id }, 'ClamAV scan lookup denied, host out of caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const rows = await entityManager.query(
      `SELECT metadata, unixtime
       FROM alerts
       WHERE host_identifier = $1
         AND alert_type      = '${ALERT_TYPE_CLAMAV_SCAN}'
         AND unixtime        >= $2
       ORDER BY unixtime DESC
       LIMIT 1`,
      [host_identifier, sinceTs]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      logger.debug({ host_identifier, since: sinceTs }, 'No ClamAV scan found yet');
      return res.status(200).json({ found: false });
    }

    const raw = rows[0].metadata;
    const scan = typeof raw === 'string' ? JSON.parse(raw) : raw;

    logger.debug({ host_identifier, since: sinceTs, foundUnixtime: rows[0].unixtime }, 'Latest ClamAV scan retrieved');
    return res.status(200).json({ found: true, scan });
  } catch (error) {
    logger.error({ err: error, host_identifier: (req.query as Record<string, string>)?.host_identifier }, 'Failed to fetch latest ClamAV scan');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
