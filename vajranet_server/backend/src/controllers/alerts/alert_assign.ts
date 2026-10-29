import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { JwtPayload } from '../../types/JwtPayload';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getUserNodeScope, actableGroupIds, canActOnGroup } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertAssign');

/**
 * POST /alerts/assign
 * Body:
 *  - event_id: number | string | Array<number|string> (alert ids)
 *  - assignee_id: number | string (vajra_users.id), or null/0 to unassign
 *
 * Notes:
 *  - Writes to alerts.assignee_id (expects/creates this column).
 *  - Passing assignee_id as null (or 0) clears the assignee (unassign), while
 *    still recording who performed the change and when for audit purposes.
 */
export const alert_assign = async (req: Request, res: Response, _next: NextFunction) => {
  const { event_id: eventIdsRaw, assignee_id, reason } = req.body ?? {};
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const eventIds = Array.isArray(eventIdsRaw) ? eventIdsRaw : [eventIdsRaw];
  if (!Array.isArray(eventIds) || eventIds.length === 0) {
    return res.status(400).json({ status: 'Error', message: 'Invalid data: event_id must be provided.' });
  }

  const isUnassign = assignee_id === null || assignee_id === 0 || assignee_id === '0';
  const assigneeId = isUnassign ? null : Number(assignee_id);
  if (!isUnassign && (!Number.isFinite(assigneeId) || (assigneeId as number) <= 0)) {
    return res.status(400).json({ status: 'Error', message: 'Invalid data: assignee_id must be a positive number, or null to unassign.' });
  }
  const assignReason = typeof reason === 'string' ? reason.trim() : '';
  if (!assignReason) {
    return res.status(400).json({ status: 'Error', message: 'Invalid data: reason is required.' });
  }

  const invalidIds = eventIds.filter((id: any) => {
    const n = Number(id);
    return isNaN(n) || !Number.isFinite(n) || !Number.isInteger(n);
  });
  if (invalidIds.length > 0) {
    return res.status(400).json({ status: 'Error', message: 'Invalid data: all event_id values must be numeric.' });
  }

  try {
    const connections = dbSourceConnection();
    const entityManager = connections?.[1];
    if (!entityManager) {
      logger.error({ eventIds }, 'Database connection not established');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);

    // Best-effort fetch metadata for audit details
    let alertMeta: Array<{ id: string; host_identifier?: string; hostname?: string }> = [];
    let existingAssignments: Array<{ id: string; assignee_id: number | null }> = [];
    let inScopeIds = new Set<string>();
    try {
      const rows = await entityManager.query(
        `SELECT
           a.id::text as id,
           a.host_identifier,
           COALESCE(n.hostname, a.hostname) AS hostname,
           a.assignee_id,
           a.group_id,
           n.owner_group_id
         FROM alerts a
         LEFT JOIN nodes n
           ON a.host_identifier::text = n.host_identifier::text
         WHERE a.id = ANY($1)`,
        [eventIds.map((id: any) => BigInt(id))]
      );
      alertMeta = Array.isArray(rows)
        ? rows.map((r: any) => ({
            id: String(r?.id),
            host_identifier: r?.host_identifier != null ? String(r.host_identifier) : undefined,
            hostname: r?.hostname != null ? String(r.hostname) : undefined,
          }))
        : [];
      existingAssignments = Array.isArray(rows)
        ? rows.map((r: any) => ({
            id: String(r?.id),
            assignee_id:
              r?.assignee_id == null
                ? null
                : Number.isFinite(Number(r.assignee_id))
                  ? Number(r.assignee_id)
                  : null,
          }))
        : [];
      // Only alerts whose node is within the caller's ACT-level group scope may
      // be reassigned — a Group Viewer can see the alert but must not mutate it.
      // Alert types with no matching `nodes` row (e.g. the Scan Scheduler's
      // consolidated "Unmanaged Hosts Detected" alert) instead qualify via their
      // own group_id. Both paths require act-level (Group Admin) membership, never
      // view-level. See nodeScope.ts's actableGroupIds/canActOnGroup.
      inScopeIds = new Set(
        Array.isArray(rows)
          ? rows
              .filter((r: any) =>
                scope.unrestricted ||
                (r?.owner_group_id != null && actableGroupIds(scope).includes(r.owner_group_id)) ||
                (r?.group_id != null && canActOnGroup(scope, r.group_id)),
              )
              .map((r: any) => String(r.id))
          : [],
      );
    } catch (metaError) {
      logger.warn({ err: metaError, eventIds }, 'Failed to fetch alert metadata for assignment audit details, continuing without it');
      alertMeta = [];
      existingAssignments = [];
    }

    const scopedEventIds = scope.unrestricted ? eventIds : eventIds.filter((id: any) => inScopeIds.has(String(id)));
    if (scopedEventIds.length === 0) {
      logger.warn({ eventIds, userId: jwtPayload.id }, 'Alert assign denied, no requested alerts within caller scope');
      return res.status(404).json({ status: 'Error', message: 'No matching alerts found' });
    }
    if (scopedEventIds.length < eventIds.length) {
      logger.warn(
        { eventIds, scopedEventIds, userId: jwtPayload.id },
        'Alert assign partially denied, some requested alerts dropped as out of caller scope',
      );
    }

    const formattedIds = scopedEventIds.map((id: any) => BigInt(id));
    const result = await entityManager.query(
      `UPDATE alerts
       SET
         assignee_id = $1,
         assigned_by_id = $2,
         assigned_at = NOW(),
         assignment_reason = $4
       WHERE id = ANY($3)`,
      [assigneeId, jwtPayload.id, formattedIds, assignReason],
    );

    const affectedRows =
      Array.isArray(result) && typeof result[1] === 'number'
        ? result[1]
        : Array.isArray(result) && typeof (result[0] as any)?.rowCount === 'number'
          ? (result[0] as any).rowCount
          : 0;

    if (affectedRows > 0) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      const userAgent = req.get('user-agent') || null;
      const previousById = new Map(existingAssignments.map((row) => [row.id, row.assignee_id]));
      const baseAssignmentChanges = scopedEventIds.map((id: any) => {
        const eventId = String(id);
        const fromAssigneeId = previousById.get(eventId) ?? null;
        const toAssigneeId = assigneeId;
        const assignmentType =
          toAssigneeId == null
            ? 'unassigned'
            : fromAssigneeId == null
              ? 'assigned'
              : fromAssigneeId === toAssigneeId
                ? 'assigned'
                : 'reassigned';
        return {
          event_id: eventId,
          assignment_type: assignmentType,
          from_assignee_id: fromAssigneeId,
          to_assignee_id: toAssigneeId,
        };
      });
      const userIds = Array.from(
        new Set(
          baseAssignmentChanges.flatMap((c) => [c.from_assignee_id, c.to_assignee_id]).filter((v): v is number => v != null),
        ),
      );
      let userMap: Record<string, { id: number; name: string | null; email: string | null }> = {};
      try {
        if (userIds.length > 0) {
          const userRows = await entityManager.query(
            `SELECT id, name, email FROM vajra_users WHERE id = ANY($1)`,
            [userIds],
          );
          if (Array.isArray(userRows)) {
            userMap = userRows.reduce(
              (acc: Record<string, { id: number; name: string | null; email: string | null }>, row: any) => {
                const uid = Number(row?.id);
                if (!Number.isFinite(uid)) return acc;
                acc[String(uid)] = {
                  id: uid,
                  name: row?.name != null ? String(row.name) : null,
                  email: row?.email != null ? String(row.email) : null,
                };
                return acc;
              },
              {},
            );
          }
        }
      } catch (userLookupError) {
        logger.warn({ err: userLookupError, userIds }, 'Failed to fetch user details for assignment audit details, continuing without it');
        userMap = {};
      }
      const assignmentChanges = baseAssignmentChanges.map((c) => ({
        ...c,
        from_assignee:
          c.from_assignee_id != null
            ? (userMap[String(c.from_assignee_id)] ?? { id: c.from_assignee_id, name: null, email: null })
            : null,
        to_assignee:
          c.to_assignee_id != null
            ? (userMap[String(c.to_assignee_id)] ?? { id: c.to_assignee_id, name: null, email: null })
            : null,
      }));
      const hasAssigned = assignmentChanges.some((c) => c.assignment_type === 'assigned');
      const hasReassigned = assignmentChanges.some((c) => c.assignment_type === 'reassigned');
      const hasUnassigned = assignmentChanges.some((c) => c.assignment_type === 'unassigned');
      const distinctChangeTypes = [hasAssigned, hasReassigned, hasUnassigned].filter(Boolean).length;
      const assignmentType =
        distinctChangeTypes > 1 ? 'mixed' : hasUnassigned ? 'unassigned' : hasReassigned ? 'reassigned' : 'assigned';

      await logAuditTrail({
        action: 'ALERT_ASSIGN_UPDATE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent,
        details: {
          event_ids: scopedEventIds,
          assignment_type: assignmentType,
          assignment_changes: assignmentChanges,
          users: userMap,
          assignee_id: assigneeId,
          reason: assignReason,
          assigned_by_id: jwtPayload.id,
          alerts: alertMeta,
        },
      });
    }

    logger.info(
      { eventIds: scopedEventIds, assigneeId, affected: affectedRows },
      'Alert assignment updated',
    );
    return res.status(200).json({
      status: 'Success',
      message: `${affectedRows} alert(s) updated successfully.`,
      affected: affectedRows,
    });
  } catch (error) {
    logger.error({ err: error, eventIds }, 'Failed to assign alert');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

