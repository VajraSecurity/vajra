import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { JwtPayload } from '../../types/JwtPayload';
import { VajraUser } from '../../orm/entities/users/Users';
import { getUserNodeScope, assertHostInScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertAssignee');

/**
 * GET /alerts/assignee?id=eventId
 * Returns the current assignee for an alert (id/name/email when available).
 */
export const alert_assignee = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const rawId = req.query.id;
  if (rawId == null) {
    return res.status(400).json({ status: 'Error', message: 'Missing query param: id' });
  }

  const alertId = Number(rawId);
  if (!Number.isFinite(alertId) || alertId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Invalid query param: id' });
  }

  try {
    const connections = dbSourceConnection();
    const secondary = connections?.[1];
    const primary = connections?.[0];
    if (!secondary || !primary) {
      logger.error({ alertId }, 'Database connection not established');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }


    // The alert row (fleet DB) and the caller's node scope (primary DB) are
    // independent, so they run in parallel. Safe because getUserNodeScope never
    // rejects — it try/catches internally and fails closed — so it cannot turn a
    // would-be 404 into a 500; a missing alert just costs one extra read of the
    // caller's own user row.
    const [rows, scope] = await Promise.all([
      secondary.query(
        `SELECT host_identifier, group_id, assignee_id, assigned_by_id, assigned_at, assignment_reason, is_open, unixTime
         FROM alerts
         WHERE id = $1`,
        [BigInt(alertId)]
      ),
      getUserNodeScope(jwtPayload.id),
    ]);
    const row = Array.isArray(rows) ? rows[0] : undefined;
    if (!row) {
      logger.debug({ alertId }, 'Alert assignee lookup failed, alert not found');
      return res.status(404).json({ status: 'Error', message: 'Alert not found' });
    }

    // Same two-path, fail-closed check as alert_by_id.ts: a scoped caller must
    // earn access either through the alert's host (host_identifier ->
    // nodes.owner_group_id) or, for alert types with no matching `nodes` row —
    // currently just the Scan Scheduler's consolidated "Unmanaged Hosts
    // Detected" alert — through the alert's own group_id. Guarding on
    // `row.host_identifier &&` alone would skip the check entirely for a
    // host-less alert and hand its assignee's name and email to any scoped
    // caller who can guess an alert id.
    const hostInScope = row.host_identifier ? await assertHostInScope(scope, row.host_identifier) : false;
    const groupInScope = !scope.unrestricted && !!row.group_id && scopeGroupIds(scope).includes(row.group_id);
    if (!scope.unrestricted && !hostInScope && !groupInScope) {
      logger.warn({ alertId, userId: jwtPayload.id, host_identifier: row.host_identifier }, 'Alert assignee lookup denied, alert out of caller scope');
      return res.status(404).json({ status: 'Error', message: 'Alert not found' });
    }

    const assigneeId = row.assignee_id == null ? null : Number(row.assignee_id);
    const assignedById = row.assigned_by_id == null ? null : Number(row.assigned_by_id);

    const assignedAt = row.assigned_at ?? null;
    const assignmentReason = typeof row.assignment_reason === 'string' ? row.assignment_reason : null;
    const isOpen = typeof row.is_open === 'boolean' ? row.is_open : null;
    const unixTime = row.unixTime ?? null;

    const [assigneeUser, assignedByUser] = await Promise.all([
      assigneeId
        ? primary
            .getRepository(VajraUser)
            .findOne({ where: { id: assigneeId }, select: ['id', 'name', 'email'] })
        : Promise.resolve(null),
      assignedById
        ? primary
            .getRepository(VajraUser)
            .findOne({ where: { id: assignedById }, select: ['id', 'name', 'email'] })
        : Promise.resolve(null),
    ]);

    logger.debug({ alertId }, 'Alert assignee retrieved');
    return res.status(200).json({
      status: 'Success',
      data: {
        event_id: String(alertId),
        assignee: assigneeUser
          ? { id: assigneeUser.id, name: assigneeUser.name, email: assigneeUser.email }
          : assigneeId
            ? { id: assigneeId, name: null, email: null }
            : null,
        assignedBy: assignedByUser
          ? { id: assignedByUser.id, name: assignedByUser.name, email: assignedByUser.email }
          : assignedById
            ? { id: assignedById, name: null, email: null }
            : null,
        assignedAt,
        assignmentReason,
        status: isOpen == null ? null : isOpen ? 'Open' : 'Closed',
        unixTime,
      },
    });
  } catch (error) {
    logger.error({ err: error, alertId }, 'Failed to fetch alert assignee');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

