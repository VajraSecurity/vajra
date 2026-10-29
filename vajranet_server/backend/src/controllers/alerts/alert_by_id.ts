import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertById');

/**
 * GET /alerts/by-id?id=eventId
 * Returns a full alert record suitable for the AlertsView UI.
 */
export const alert_by_id = async (req: Request, res: Response, _next: NextFunction) => {
  const rawId = req.query.id;
  const alertId = Number(rawId);
  if (!Number.isFinite(alertId) || alertId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Invalid query param: id' });
  }

  try {
    const connections = dbSourceConnection();
    const entityManager = connections?.[1];
    if (!entityManager) {
      logger.error({ alertId }, 'Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const rows = await entityManager.query(
      `
        SELECT
          a.id,
          a.host_identifier,
          COALESCE(n.hostname, a.hostname) AS hostname,
          COALESCE(n.os_name, a.os_name) AS os_name,
          a.unixTime AS unixtime,
          a.event_code,
          a.metadata::json AS metadata,
          a.is_alert,
          a.is_open,
          a.severity,
          a.alert_type,
          a.mark_type AS mark_type,
          a.assignee_id,
          a.assigned_by_id,
          a.assigned_at,
          a.group_id,
          a.alert_type AS title,
          a.event_code AS description,
          COALESCE(n.hostname, a.hostname) AS source
        FROM alerts a
        LEFT JOIN nodes n ON a.host_identifier = n.host_identifier
        WHERE a.id = $1
        LIMIT 1
      `,
      [BigInt(alertId)],
    );

    const row = Array.isArray(rows) ? rows[0] : undefined;
    if (!row) {
      logger.debug({ alertId }, 'Alert lookup failed, alert not found');
      return res.status(404).json({ status: 'Error', message: 'Alert not found' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    // Two independent ways a scoped caller can be in-scope for this alert:
    // the usual host_identifier -> nodes.owner_group_id check (every alert
    // type that references a real node), or — for alert types with no
    // matching `nodes` row, currently just the Scan Scheduler's consolidated
    // "Unmanaged Hosts Detected" alert, see createRunAlert in
    // scanSchedulerService.ts — the alert's own group_id column directly.
    // Fail closed: a scoped caller must earn access through the host or the
    // alert's own group_id. A row offering neither — including one with no
    // host_identifier at all — is denied rather than returned.
    const hostInScope = row.host_identifier ? await assertHostInScope(scope, row.host_identifier) : false;
    const groupInScope = !scope.unrestricted && !!row.group_id && scopeGroupIds(scope).includes(row.group_id);
    if (!scope.unrestricted && !hostInScope && !groupInScope) {
      logger.warn({ alertId, userId: jwtPayload?.id, host_identifier: row.host_identifier }, 'Alert lookup denied, host out of caller scope');
      return res.status(404).json({ status: 'Error', message: 'Alert not found' });
    }

    logger.debug({ alertId }, 'Alert details retrieved');
    return res.status(200).json({
      success: true,
      alert: row,
    });
  } catch (error) {
    logger.error({ err: error, alertId }, 'Failed to fetch alert by id');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

