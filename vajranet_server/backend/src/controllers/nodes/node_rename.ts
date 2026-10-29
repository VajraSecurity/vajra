import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { sanitizeString } from '../../utils/sanitization';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, assertCanActOnHost } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('nodes.nodeRename');

export async function node_rename(req: Request, res: Response, _next: NextFunction) {
  const { host_identifier, alias_name } = req.body;

  if (typeof host_identifier !== 'string' || !host_identifier.trim()) {
    return res.status(400).json({ status: "Error", message: 'Invalid host_identifier' });
  }
  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertCanActOnHost(scope, host_identifier))) {
    logger.warn({ host_identifier }, 'Node rename rejected: host out of scope for caller');
    return res.status(404).json({ status: "Error", message: 'Node not found' });
  }
  const rawName = alias_name?.toString().trim() || '';
  if (!/^[a-zA-Z0-9_\- ]+$/.test(rawName)) {
    return res.status(400).json({ status: "Error", message: 'Alias can only contain letters, numbers, hyphens, underscores, and spaces' });
  }
  const sanitizedName = sanitizeString(rawName);
  if (sanitizedName.length < 1 || sanitizedName.length > 255) {
    return res.status(400).json({ status: "Error", message: 'Alias must be 1-255 characters' });
  }

  const dataSources = dbSourceConnection();
  const entityManager = dataSources?.[1];
  if (!entityManager) {
    logger.error({ host_identifier }, 'Node rename failed: database unavailable');
    return res.status(500).json({ status: "Error", message: 'Database unavailable' });
  }

  try {
    return await entityManager.transaction(async (tx) => {
      const existing = await tx.query(
        'SELECT hostname FROM nodes WHERE host_identifier = $1 LIMIT 1 FOR UPDATE',
        [host_identifier]
      );
      if (existing.length === 0) {
        logger.warn({ host_identifier }, 'Node rename rejected: node not found');
        return res.status(404).json({ status: "Error", message: 'Node not found' });
      }
      const oldHostname = existing[0]?.hostname != null ? String(existing[0].hostname) : '';

      const updateNode = await tx.query(`
        UPDATE nodes 
        SET hostname = $1 
        WHERE host_identifier = $2 
          AND NOT EXISTS (
            SELECT 1 FROM nodes WHERE hostname = $1 AND host_identifier != $2
          )
        RETURNING id;
      `, [sanitizedName, host_identifier]);

      // returningRows() is required: TypeORM's Postgres driver returns an
      // UPDATE ... RETURNING as the tuple [rows, rowCount], so .length is always 2, even
      // on zero matches ([[], 0]). Read raw, this duplicate-hostname check never fires,
      // and a rename onto a taken hostname returns 200 without changing the hostname
      // while still running the `UPDATE alerts SET hostname = $1` below — retagging the
      // host's entire alert history to a hostname it does not have.
      const renamedRows = returningRows<{ id: number }>(updateNode);

      if (renamedRows.length === 0) {
        const exists = await tx.query('SELECT 1 FROM nodes WHERE hostname = $1 LIMIT 1', [sanitizedName]);
        logger.warn(
          { host_identifier, new_hostname: sanitizedName, reason: exists.length > 0 ? 'duplicate_hostname' : 'node_disappeared_mid_transaction' },
          'Node rename rejected',
        );
        return res.status(exists.length > 0 ? 409 : 404).json({
          status: "Error",
          message: exists.length > 0 ? 'Hostname already exists' : 'Node not found'
        });
      }

      await tx.query(
        'UPDATE alerts SET hostname = $1 WHERE host_identifier = $2 AND hostname != $1',
        [sanitizedName, host_identifier]
      );

      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      if (jwtPayload?.id) {
        await logAuditTrail({
          action: 'RENAME_NODE',
          status: 'success',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: req.get('user-agent') || null,
          details: { host_identifier, old_hostname: oldHostname, new_hostname: sanitizedName },
        });
      }

      logger.info({ host_identifier, old_hostname: oldHostname, new_hostname: sanitizedName }, 'Node renamed');
      return res.status(200).json({
        status: 'Success',
        message: 'Node renamed successfully',
        data: { host_identifier, new_hostname: sanitizedName }
      });
    });
  } catch (err) {
    logger.error({ err, host_identifier }, 'Node rename failed');
    return res.status(500).json({ status: "Error", message: 'Internal Server Error' });
  }
}