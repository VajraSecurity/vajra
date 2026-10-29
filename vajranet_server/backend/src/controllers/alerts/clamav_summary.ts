import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { ALERT_TYPE_CLAMAV_ALERT } from '../../consts/alerts';

const logger = getLogger('alerts.clamavSummary');

/**
 * GET /alerts/clamav-summary
 *
 * Per-host ClamAV state, used by the MyDevices page to render the Linux
 * ClamAV tag. Combines two DB sources:
 *
 *   alerts        — open 'ClamAV Alert' rows (written by the nodeExt handler
 *                   when clamav_push detections arrive; store-and-forward
 *                   from the agent, idempotent ingest)
 *   clamav_status — latest daemon health + signature DB version per host
 *                   (upserted from clamav_status_push: on agent connect,
 *                   every 5 min, and after a freshclam update)
 *
 * The DB is the source of truth; the live WebSocket forwards of clamav_push /
 * clamav_status_push act only as refresh triggers on the client. A host with
 * an online agent but daemon_running=false means clamd is NOT running there —
 * the dashboard must not show ClamAV as active just because the agent is up.
 *
 * Response: { status: 'Success', data: [{
 *   host_identifier, count, last_alert_at,
 *   daemon_running, engine_version, db_version, db_date, status_updated_at
 * }] }
 */
export async function clamav_alert_summary(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error('Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    const scopeWhere = scope.unrestricted
      ? ''
      : `WHERE COALESCE(s.host_identifier, a.host_identifier) IN (SELECT host_identifier FROM nodes WHERE owner_group_id = ANY($1::text[]))`;
    const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    const rows = await entityManager.query(
      `SELECT COALESCE(s.host_identifier, a.host_identifier) AS host_identifier,
              COALESCE(a.count, 0)                           AS count,
              a.last_alert_at,
              s.daemon_running,
              s.engine_version,
              s.db_version,
              s.db_date,
              EXTRACT(EPOCH FROM s.updated_at)::bigint       AS status_updated_at
       FROM clamav_status s
       FULL OUTER JOIN (
         SELECT host_identifier,
                COUNT(*)::int AS count,
                MAX(unixtime) AS last_alert_at
         FROM alerts
         WHERE alert_type = '${ALERT_TYPE_CLAMAV_ALERT}'
           AND is_open = true
         GROUP BY host_identifier
       ) a ON a.host_identifier = s.host_identifier
       ${scopeWhere}`,
      params,
    );

    logger.debug({ count: Array.isArray(rows) ? rows.length : 0 }, 'ClamAV summary retrieved');
    return res.status(200).json({
      status: 'Success',
      data: Array.isArray(rows)
        ? rows.map((r: any) => ({
            host_identifier: String(r.host_identifier),
            count: Number(r.count) || 0,
            last_alert_at: r.last_alert_at != null ? Number(r.last_alert_at) : null,
            // null = no status report ever received from this host's agent
            daemon_running: r.daemon_running != null ? Boolean(r.daemon_running) : null,
            engine_version: r.engine_version != null ? String(r.engine_version) : null,
            db_version: r.db_version != null ? String(r.db_version) : null,
            db_date: r.db_date != null ? String(r.db_date) : null,
            status_updated_at: r.status_updated_at != null ? Number(r.status_updated_at) : null,
          }))
        : [],
    });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to fetch ClamAV summary');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
