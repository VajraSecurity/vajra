import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { CertinCompliance } from '../../orm/entities/audit/CertinCompliance';
import { getUserNodeScope, assertHostInScope, assertCanActOnHost } from '../../utils/nodeScope';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { AUDIT_ACTION_COMPLIANCE } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.certinCompliance');

// Sentinel nodeHostIdentifier for the org-level aggregate CERT-In view, which no
// single node backs. The node-scope checks (assertHostInScope /
// assertCanActOnHost) resolve the identifier against the `nodes` table and would
// always 404 it; the record is instead scoped to the caller via userId (see the
// unique index on (userId, nodeHostIdentifier)), and requireAdmin on the route
// gates who may write it.
//
// The leading underscore is load-bearing: real host identifiers must match
// HOST_IDENTIFIER_PATTERN (^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$, see
// agentCertProvisioning.ts), so no enrolled node can ever collide with this value.
const ORG_LEVEL_HOST_ID = '__org_level__';

function getComplianceRepo() {
  return dbSourceConnection()?.[0]?.getRepository(CertinCompliance);
}

export async function saveCertinCompliance(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number; email?: string } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { nodeHostIdentifier, statusByPointer } = req.body as {
      nodeHostIdentifier?: string;
      statusByPointer?: Record<string, 'yes' | 'no'>;
    };

    const hostId = String(nodeHostIdentifier ?? '').trim();
    if (!hostId) return res.status(400).json({ error: 'nodeHostIdentifier is required' });
    if (!statusByPointer || typeof statusByPointer !== 'object') {
      return res.status(400).json({ error: 'statusByPointer is required' });
    }
    if (hostId !== ORG_LEVEL_HOST_ID && !(await assertCanActOnHost(await getUserNodeScope(userId), hostId))) {
      logger.warn({ userId, hostId }, 'CERT-In compliance save denied, host out of caller act-scope');
      return res.status(404).json({ error: 'Node not found' });
    }

    const repo = getComplianceRepo();
    if (!repo) {
      logger.error({ userId, hostId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }

    const existing = await repo.findOne({ where: { userId, nodeHostIdentifier: hostId } });
    if (existing) {
      existing.statusByPointer = statusByPointer;
      const updated = await repo.save(existing);
      logger.info({ userId, hostId, complianceId: updated.id }, 'CERT-In compliance updated');
      try {
        await logAuditTrail({
          action: AUDIT_ACTION_COMPLIANCE,
          status: 'success',
          userId,
          email: jwtPayload?.email ?? null,
          details: { framework: 'certin', host_identifier: hostId, source: 'checklist-update' },
        });
      } catch (auditErr) {
        // Row is already committed — distinguish this from an actual save
        // failure so it isn't misread as the update itself failing.
        logger.error({ err: auditErr, userId, hostId }, 'Failed to record audit trail for CERT-In compliance update; update itself was already saved');
        throw auditErr;
      }
      return res.json({ success: true, compliance: updated });
    }

    const created = repo.create({ userId, nodeHostIdentifier: hostId, statusByPointer });
    const saved = await repo.save(created);
    logger.info({ userId, hostId, complianceId: saved.id }, 'CERT-In compliance created');
    try {
      await logAuditTrail({
        action: AUDIT_ACTION_COMPLIANCE,
        status: 'success',
        userId,
        email: jwtPayload?.email ?? null,
        details: { framework: 'certin', host_identifier: hostId, source: 'checklist-create' },
      });
    } catch (auditErr) {
      logger.error({ err: auditErr, userId, hostId }, 'Failed to record audit trail for CERT-In compliance create; record itself was already saved');
      throw auditErr;
    }
    return res.json({ success: true, compliance: saved });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id, hostId: req.body?.nodeHostIdentifier }, 'Failed to save CERT-In compliance');
    return res.status(500).json({ error: 'Failed to save CERT-In compliance' });
  }
}

export async function getCertinCompliance(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const nodeHostIdentifier = String(req.query.nodeHostIdentifier ?? '').trim();
    if (!nodeHostIdentifier) return res.status(400).json({ error: 'nodeHostIdentifier is required' });
    if (
      nodeHostIdentifier !== ORG_LEVEL_HOST_ID &&
      !(await assertHostInScope(await getUserNodeScope(userId), nodeHostIdentifier))
    ) {
      logger.warn({ userId, hostId: nodeHostIdentifier }, 'CERT-In compliance fetch denied, host out of caller scope');
      return res.status(404).json({ error: 'Node not found' });
    }

    const repo = getComplianceRepo();
    if (!repo) {
      logger.error({ userId, hostId: nodeHostIdentifier }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }

    const compliance = await repo.findOne({ where: { userId, nodeHostIdentifier } });
    logger.debug({ userId, hostId: nodeHostIdentifier, found: !!compliance }, 'CERT-In compliance retrieved');
    return res.json({ success: true, compliance: compliance ?? null });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id, hostId: req.query?.nodeHostIdentifier }, 'Failed to fetch CERT-In compliance');
    return res.status(500).json({ error: 'Failed to fetch CERT-In compliance' });
  }
}

export async function resetCertinCompliance(req: Request, res: Response) {
  try {
    const jwtPayload = (req as any).jwtPayload as { id?: number; email?: string } | undefined;
    const userId = jwtPayload?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { nodeHostIdentifier } = req.body as { nodeHostIdentifier?: string };
    const hostId = String(nodeHostIdentifier ?? '').trim();
    if (!hostId) return res.status(400).json({ error: 'nodeHostIdentifier is required' });
    if (hostId !== ORG_LEVEL_HOST_ID && !(await assertCanActOnHost(await getUserNodeScope(userId), hostId))) {
      logger.warn({ userId, hostId }, 'CERT-In compliance reset denied, host out of caller act-scope');
      return res.status(404).json({ error: 'Node not found' });
    }

    const repo = getComplianceRepo();
    if (!repo) {
      logger.error({ userId, hostId }, 'Database connection not available');
      return res.status(500).json({ error: 'Database connection not available' });
    }

    const existing = await repo.findOne({ where: { userId, nodeHostIdentifier: hostId } });
    if (!existing) {
      logger.info({ userId, hostId }, 'CERT-In compliance reset skipped, nothing to reset');
      return res.json({ success: true, compliance: null });
    }

    existing.statusByPointer = {};
    const updated = await repo.save(existing);
    logger.info({ userId, hostId, complianceId: updated.id }, 'CERT-In compliance reset');
    try {
      await logAuditTrail({
        action: AUDIT_ACTION_COMPLIANCE,
        status: 'success',
        userId,
        email: jwtPayload?.email ?? null,
        details: { framework: 'certin', host_identifier: hostId, source: 'checklist-reset' },
      });
    } catch (auditErr) {
      logger.error({ err: auditErr, userId, hostId }, 'Failed to record audit trail for CERT-In compliance reset; reset itself was already saved');
      throw auditErr;
    }
    return res.json({ success: true, compliance: updated });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id, hostId: req.body?.nodeHostIdentifier }, 'Failed to reset CERT-In compliance');
    return res.status(500).json({ error: 'Failed to reset CERT-In compliance' });
  }
}
