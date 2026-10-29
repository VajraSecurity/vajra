import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { sanitizeString } from '../../utils/sanitization';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, assertCanActOnHost } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { NODE_CRITICAL_REASON_MAX_LENGTH } from '../../consts/database';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('nodes.critical');

export async function node_critical(req: Request, res: Response, _next: NextFunction) {
  const { host_identifier, reason } = req.body;

  if (typeof host_identifier !== 'string' || !host_identifier.trim()) {
    return res.status(400).json({ status: "Error", message: 'Invalid host_identifier' });
  }

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertCanActOnHost(scope, host_identifier))) {
    logger.warn({ host_identifier }, 'Mark-node-critical rejected: host not in caller scope');
    return res.status(404).json({ status: "Error", message: 'Node not found' });
  }

  const sanitizedReason = sanitizeString(reason?.toString().trim() || '');
  if (sanitizedReason.length < 1 || sanitizedReason.length > NODE_CRITICAL_REASON_MAX_LENGTH) {
    return res.status(400).json({ status: "Error", message: `Reason must be 1-${NODE_CRITICAL_REASON_MAX_LENGTH} characters` });
  }

  const dataSources = dbSourceConnection();
  const entityManager = dataSources?.[1];
  if (!entityManager) {
    logger.error({ host_identifier }, 'Database connection unavailable while marking node as critical');
    return res.status(500).json({ status: "Error", message: 'Database unavailable' });
  }

  try {
    return await entityManager.transaction(async (tx) => {
      const existing = await tx.query(
        'SELECT hostname FROM nodes WHERE host_identifier = $1 LIMIT 1 FOR UPDATE',
        [host_identifier]
      );
      if (existing.length === 0) {
        // Anomalous: assertCanActOnHost above confirmed this host is in the
        // caller's scope, yet the row is missing here — stale scope cache or
        // the node was deleted in between.
        logger.warn({ host_identifier }, 'Node not found in nodes table while marking as critical, despite passing scope check');
        return res.status(404).json({ status: "Error", message: 'Node not found' });
      }

      const updateNode = await tx.query(`
        UPDATE nodes 
        SET critical = true, critical_reason = $1, critical_marked_at = NOW()
        WHERE host_identifier = $2
        RETURNING id, hostname;
      `, [sanitizedReason, host_identifier]);

      // returningRows() is required: TypeORM's Postgres driver returns an
      // UPDATE ... RETURNING as the tuple [rows, rowCount], so the raw value's .length is
      // always 2 and `[0]` is the nested rows array rather than a row. Read raw, the
      // guard below can never fire and `hostname` comes back undefined in both the log
      // line and the response payload.
      const updatedRows = returningRows<{ id: number; hostname: string | null }>(updateNode);

      if (updatedRows.length === 0) {
        // Anomalous: the row was confirmed present (and locked) by the SELECT
        // above, in the same transaction, yet the UPDATE matched nothing.
        logger.warn({ host_identifier }, 'Node vanished between existence check and update while marking as critical');
        return res.status(404).json({ status: "Error", message: 'Failed to mark node as critical' });
      }

      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      if (jwtPayload?.id) {
        try {
          await logAuditTrail({
            action: 'MARK_NODE_CRITICAL',
            status: 'success',
            userId: jwtPayload.id,
            email: jwtPayload.email ?? null,
            ipAddress: clientIp,
            userAgent: req.get('user-agent') || null,
            details: { host_identifier, reason: sanitizedReason },
          });
        } catch (auditErr) {
          // Node row is already updated within this transaction at this point —
          // distinguish this from an actual mark-critical failure so the outer
          // catch's log below isn't misread as the UPDATE itself failing.
          logger.error({ err: auditErr, host_identifier }, 'Failed to record audit trail for mark-node-critical; node was already updated');
          throw auditErr;
        }
      }

      logger.info({ host_identifier, hostname: updatedRows[0]?.hostname }, 'Node marked as critical');

      return res.status(200).json({
        status: 'Success',
        message: 'Node marked as critical successfully',
        data: { 
          host_identifier, 
          hostname: updatedRows[0]?.hostname,
          critical_marked_at: new Date().toISOString()
        }
      });
    });
  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to mark node as critical');

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
    if (jwtPayload?.id) {
      try {
        await logAuditTrail({
          action: 'MARK_NODE_CRITICAL',
          status: 'failure',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: req.get('user-agent') || null,
          details: { host_identifier, error: error instanceof Error ? error.message : String(error) },
        });
      } catch (auditErr) {
        // The original mark-critical failure was already logged above — without
        // this, an audit-trail write failure here would abort the handler with
        // no log line at all, indistinguishable from the process simply hanging.
        logger.error({ err: auditErr, host_identifier }, 'Failed to record audit trail for mark-node-critical failure');
        throw auditErr;
      }
    }

    return res.status(500).json({ status: 'Error', message: 'Failed to mark node as critical' });
  }
}
