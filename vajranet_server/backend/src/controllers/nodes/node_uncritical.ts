import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { sanitizeString } from '../../utils/sanitization';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, assertCanActOnHost } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { NODE_CRITICAL_REASON_MAX_LENGTH } from '../../consts/database';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('nodes.nodeUncritical');

export async function node_uncritical(req: Request, res: Response, _next: NextFunction) {
  const { host_identifier, reason } = req.body;

  if (typeof host_identifier !== 'string' || !host_identifier.trim()) {
    return res.status(400).json({ status: "Error", message: 'Invalid host_identifier' });
  }

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertCanActOnHost(scope, host_identifier))) {
    logger.warn({ host_identifier }, 'Node uncritical rejected: host out of scope for caller');
    return res.status(404).json({ status: "Error", message: 'Node not found' });
  }

  const sanitizedReason = sanitizeString(reason?.toString().trim() || '');
  if (sanitizedReason.length > NODE_CRITICAL_REASON_MAX_LENGTH) {
    return res.status(400).json({ status: "Error", message: `Reason must be at most ${NODE_CRITICAL_REASON_MAX_LENGTH} characters` });
  }

  const dataSources = dbSourceConnection();
  const entityManager = dataSources?.[1];
  if (!entityManager) {
    logger.error({ host_identifier }, 'Node uncritical failed: database unavailable');
    return res.status(500).json({ status: "Error", message: 'Database unavailable' });
  }

  try {
    return await entityManager.transaction(async (tx) => {
      const existing = await tx.query(
        'SELECT hostname FROM nodes WHERE host_identifier = $1 LIMIT 1 FOR UPDATE',
        [host_identifier]
      );
      if (existing.length === 0) {
        logger.warn({ host_identifier }, 'Node uncritical rejected: node not found');
        return res.status(404).json({ status: "Error", message: 'Node not found' });
      }

      const updateNode = await tx.query(`
        UPDATE nodes
        SET critical = false, critical_reason = NULL, critical_marked_at = NULL
        WHERE host_identifier = $1
        RETURNING id, hostname;
      `, [host_identifier]);

      // returningRows() is required: TypeORM's Postgres driver returns an
      // UPDATE ... RETURNING as the tuple [rows, rowCount], so the raw value's .length is
      // always 2 and `[0]` is the nested rows array rather than a row. Read raw, the
      // guard below can never fire and `hostname` comes back undefined in both the log
      // line and the response payload.
      const updatedRows = returningRows<{ id: number; hostname: string | null }>(updateNode);

      if (updatedRows.length === 0) {
        logger.warn({ host_identifier }, 'Node uncritical rejected: node disappeared between lookup and update');
        return res.status(404).json({ status: "Error", message: 'Failed to mark node as non-critical' });
      }

      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      if (jwtPayload?.id) {
        await logAuditTrail({
          action: 'MARK_NODE_CRITICAL',
          status: 'success',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: req.get('user-agent') || null,
          details: { host_identifier, action: 'unmarked', reason: sanitizedReason },
        });
      }

      logger.info({ host_identifier }, 'Node marked as non-critical');
      return res.status(200).json({
        status: 'Success',
        message: 'Node marked as non-critical successfully',
        data: {
          host_identifier,
          hostname: updatedRows[0]?.hostname,
          critical_marked_at: null
        }
      });
    });
  } catch (err) {
    logger.error({ err, host_identifier }, 'Failed to mark node as non-critical');

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
    if (jwtPayload?.id) {
      await logAuditTrail({
        action: 'MARK_NODE_CRITICAL',
        status: 'failure',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { host_identifier, action: 'unmarked', error: err instanceof Error ? err.message : String(err) },
      });
    }

    return res.status(500).json({ status: 'Error', message: 'Failed to mark node as non-critical' });
  }
}
