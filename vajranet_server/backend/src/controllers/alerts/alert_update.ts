import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getUserNodeScope, actableGroupIds, canActOnGroup } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { applyGenericAlertUpdate, FimQ, GenericAlertOp } from '../../services/fimService';

const logger = getLogger('alerts.alertUpdate');

export const alert_update = async (req: Request, res: Response, _next: NextFunction) => {
    const { event_id: eventIds, is_open, action = 'None', reason } = req.body;
    const jwtPayload = (req as any).jwtPayload;
    let eventIdsBigInt: bigint[];

    if (!Array.isArray(eventIds) || eventIds.length === 0) {
        return res.status(400).json({ status: 'Error', message: "Invalid data: event_id must be a non-empty array." });
    }

    // Validate action values early to avoid writing unexpected strings into the DB.
    // 'unmarked' clears a previously-set true_positive/false_positive classification.
    const normalizedAction =
      typeof action === 'string' && ['None', 'true_positive', 'false_positive', 'unmarked'].includes(action)
        ? action
        : 'None';
    if (action !== undefined && normalizedAction === 'None' && action !== 'None') {
      return res.status(400).json({
        status: 'Error',
        message: "Invalid data: action must be one of 'true_positive', 'false_positive', or 'unmarked'.",
      });
    }

    const invalidIds = eventIds.filter((id: any) => {
        const n = Number(id);
        return isNaN(n) || !Number.isFinite(n) || !Number.isInteger(n) || n <= 0;
    });
    if (invalidIds.length > 0) {
        return res.status(400).json({ status: 'Error', message: "Invalid data: all event_id values must be numeric." });
    }

    const trimmedReason = typeof reason === 'string' ? reason.trim() : '';
    // `reason` is optional for marking an alert as true/false positive.
    // Some UI flows don't collect it, and marking should still succeed.

    if (is_open === undefined && normalizedAction === 'None') {
        return res.status(400).json({ status: 'Error', message: "Invalid data: is_open or action must be provided." });
    }

    try {
        eventIdsBigInt = eventIds.map((id: any) => BigInt(id));

        const connections = dbSourceConnection();
        const entityManager = connections?.[1];

        if (!entityManager) {
            logger.error({ eventIds }, 'Database connection not established');
            return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
        }

        // Marks are written to `alerts.mark_type` ('unmarked' stores NULL to undo
        // one). The legacy `alerts.action` column is a separate thing and must not
        // be repurposed for this.

        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };

        // Fetch minimal alert metadata for audit linking, and determine which
        // requested alerts are within the caller's group scope.
        let alertMeta: Array<{ id: string; host_identifier?: string; hostname?: string }> = [];
        // Fail closed: a scoped caller starts with an empty set and earns ids
        // through the filter below. Seeding it with every requested id would
        // authorise the whole fleet on any path that skips the narrowing —
        // the metadata query throwing, or returning a non-array.
        let inScopeIds = scope.unrestricted
            ? new Set<string>(eventIdsBigInt.map((id) => String(id)))
            : new Set<string>();
        try {
            const rows = await entityManager.query(
                `SELECT
                    a.id::text as id,
                    a.host_identifier,
                    COALESCE(n.hostname, a.hostname) AS hostname,
                    a.group_id,
                    n.owner_group_id
                 FROM alerts a
                 LEFT JOIN nodes n
                   ON a.host_identifier::text = n.host_identifier::text
                 WHERE a.id::bigint = ANY($1::bigint[])`,
                [eventIdsBigInt]
            );
            if (Array.isArray(rows)) {
                alertMeta = rows.map((r: any) => ({
                    id: String(r?.id),
                    host_identifier: r?.host_identifier != null ? String(r.host_identifier) : undefined,
                    hostname: r?.hostname != null ? String(r.hostname) : undefined,
                }));
                if (!scope.unrestricted) {
                    // Act-level (Group Admin membership), not view-level — a Group
                    // Viewer can see this alert but must not be able to mutate it.
                    // Alerts with no matching `nodes` row (e.g. the Scan Scheduler's
                    // consolidated "Unmanaged Hosts Detected" alert) qualify via their
                    // own group_id instead, also at act-level. See nodeScope.ts's
                    // actableGroupIds/canActOnGroup.
                    inScopeIds = new Set(
                        rows
                            .filter((r: any) =>
                                (r?.owner_group_id != null && actableGroupIds(scope).includes(r.owner_group_id)) ||
                                (r?.group_id != null && canActOnGroup(scope, r.group_id)),
                            )
                            .map((r: any) => String(r.id)),
                    );
                }
            }
        } catch (metaError) {
            // Best-effort only — don't fail the request if metadata fetch fails
            logger.warn({ err: metaError, eventIds: eventIdsBigInt.map((id) => id.toString()) }, 'Failed to fetch alert metadata for audit details, continuing without it');
            alertMeta = [];
        }

        const preScopeCount = eventIdsBigInt.length;
        eventIdsBigInt = eventIdsBigInt.filter((id) => inScopeIds.has(String(id)));
        if (eventIdsBigInt.length === 0) {
            logger.warn({ eventIds, userId: jwtPayload?.id }, 'Alert update denied, no requested alerts within caller scope');
            return res.status(404).json({ status: 'Error', message: 'No matching alerts found' });
        }
        if (eventIdsBigInt.length < preScopeCount) {
            logger.warn(
                { eventIds, scopedEventIds: eventIdsBigInt.map((id) => id.toString()), userId: jwtPayload?.id },
                'Alert update partially denied, some requested alerts dropped as out of caller scope',
            );
        }

        if (is_open !== undefined && normalizedAction !== 'None') {
            // Only one column is ever updated per request. When both is_open and a mark
            // action are sent together, the mark update below wins and is_open is dropped
            // silently unless logged here.
            logger.warn(
                { eventIds, is_open, action: normalizedAction },
                'Alert update received both is_open and a mark action, is_open change ignored and only the mark was applied',
            );
        }

        // ONE statement: the FIM rule is part of the UPDATE itself (applyGenericAlertUpdate), so a
        // check followed by a separate write cannot race (e.g. a drift linked in between):
        //  - oversight alerts (fim_config): Super Administrators only, never the actor they are about;
        //  - drift alerts (fim) whose linked drift is still open: close / mark are refused and must go
        //    through POST /api/fim/alerts/close, which resolves the drift in the same transaction.
        // Not wrapped in the best-effort catch above: a failure is a 500 (fail closed).
        // The mark wins when both is_open and a mark are sent; anything that is not an explicit
        // reopen is treated as a close (the stricter rule).
        const op: GenericAlertOp = normalizedAction !== 'None'
            ? 'mark'
            : (is_open === true || is_open === 'true' || is_open === 1) ? 'reopen' : 'close';
        const outcome = await applyGenericAlertUpdate(
            entityManager as unknown as FimQ,
            eventIdsBigInt,
            {
                userId: jwtPayload?.id != null && Number.isSafeInteger(Number(jwtPayload.id)) ? Number(jwtPayload.id) : null,
                email: jwtPayload?.email ?? null,
                superAdmin: scope.unrestricted === true,
            },
            op,
            normalizedAction === 'None'
                ? { column: 'is_open', value: is_open }
                : { column: 'mark_type', value: normalizedAction === 'unmarked' ? null : normalizedAction },
        );
        const blocked = outcome.blocked.map((b) => ({ id: b.id, alert_type: b.alertType, reason: b.reason }));
        const affectedRows = outcome.updated.length;
        eventIdsBigInt = outcome.updated.map((id) => BigInt(id));
        if (blocked.length > 0) {
            logger.warn(
                { userId: jwtPayload?.id, blocked },
                'Alert update refused for FIM alerts (oversight: Super Administrator only, never its subject; drift with open change: use the FIM routes)',
            );
            if (jwtPayload?.id) {
                await logAuditTrail({
                    action: normalizedAction === 'None' ? 'ALERT_STATUS_UPDATE' : 'ALERT_MARK_UPDATE',
                    status: 'failure',
                    userId: jwtPayload.id,
                    email: jwtPayload?.email ?? null,
                    ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
                    userAgent: req.get('user-agent') || null,
                    details: { blocked, is_open, mark: normalizedAction },
                }).catch((err) => logger.error({ err }, 'Failed to log audit trail'));
            }
            if (affectedRows === 0) {
                return res.status(403).json({
                    status: 'Error',
                    message: 'None of the requested alerts can be changed here: FIM oversight alerts can only be changed by a Super Administrator who is not their subject, and FIM drift alerts with an open change must be closed in File Integrity > Alerts (the change is resolved together with the alert).',
                    blocked,
                });
            }
        }

        // Audited only when is_open was the column actually updated.
        if (normalizedAction === 'None' && is_open !== undefined && jwtPayload?.id && affectedRows > 0) {
            const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
            const single = alertMeta.length === 1 ? alertMeta[0] : undefined;
            await logAuditTrail({
                action: 'ALERT_STATUS_UPDATE',
                status: 'success',
                userId: jwtPayload.id,
                email: (req as any).jwtPayload?.email ?? null,
                ipAddress: clientIp,
                userAgent: req.get('user-agent') || null,
                details: {
                    event_ids: eventIdsBigInt.map((id) => id.toString()),
                    is_open,
                    ...(trimmedReason ? { reason: trimmedReason } : {}),
                    alerts: alertMeta,
                    ...(single?.host_identifier ? { host_identifier: single.host_identifier } : {}),
                    ...(single?.hostname ? { hostname: single.hostname } : {}),
                },
            });
        }

        // Marks (true/false positive) are audited separately from is_open changes.
        if (normalizedAction !== 'None' && jwtPayload?.id && affectedRows > 0) {
            const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
            const single = alertMeta.length === 1 ? alertMeta[0] : undefined;
            await logAuditTrail({
                action: 'ALERT_MARK_UPDATE',
                status: 'success',
                userId: jwtPayload.id,
                email: (req as any).jwtPayload?.email ?? null,
                ipAddress: clientIp,
                userAgent: req.get('user-agent') || null,
                details: {
                    event_ids: eventIdsBigInt.map((id) => id.toString()),
                    mark: normalizedAction, // 'true_positive' | 'false_positive' | 'unmarked'
                    ...(trimmedReason ? { reason: trimmedReason } : {}),
                    alerts: alertMeta,
                    ...(single?.host_identifier ? { host_identifier: single.host_identifier } : {}),
                    ...(single?.hostname ? { hostname: single.hostname } : {}),
                },
            });
        }

        logger.debug(
            {
                eventIds: eventIdsBigInt.map((id) => id.toString()),
                action: normalizedAction,
                affected: affectedRows,
            },
            'Alert status updated',
        );
        return res.status(200).json({
            status: 'Success',
            message: blocked.length
                ? `${affectedRows} event(s) updated successfully; ${blocked.length} refused (see blocked).`
                : `${affectedRows} event(s) updated successfully.`,
            // ids actually updated (RETURNING of the guarded UPDATE)
            ids: eventIdsBigInt.map((id) => id.toString()),
            blocked,
        });

    } catch (error) {
        logger.error({ err: error, eventIds, action: normalizedAction }, 'Failed to update alert');
        return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
    }
};