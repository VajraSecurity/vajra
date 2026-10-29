import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { NodeAssignmentRule } from '../../orm/entities/fleet/NodeAssignmentRule';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodeAssignmentRules.delete');

export async function delete_rule(req: Request, res: Response) {
  try {
    const id = parseInt(req.params.id as string, 10);
    if (!Number.isFinite(id)) {
      logger.warn({ rawId: req.params.id }, 'Node assignment rule delete rejected: invalid rule id');
      return res.status(400).json({ success: false, message: 'Invalid rule id.' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ ruleId: id }, 'Fleet database not available while deleting node assignment rule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const ruleRepo = fleetDb.getRepository(NodeAssignmentRule);
    const rule = await ruleRepo.findOne({ where: { id } });
    if (!rule) {
      logger.warn({ ruleId: id }, 'Node assignment rule delete requested for a rule that does not exist');
      return res.status(404).json({ success: false, message: 'Rule not found.' });
    }

    await ruleRepo.remove(rule);

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'NODE_ASSIGNMENT_RULE_DELETE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { deletedRuleId: id, name: rule.name, conditionValue: rule.conditionValue, groupId: rule.groupId },
      }).catch((err) => logger.error({ err, ruleId: id }, 'Failed to log audit trail'));
    }

    logger.info({ ruleId: id }, 'Node assignment rule deleted');
    return res.status(200).json({ success: true });
  } catch (error) {
    logger.error({ err: error, ruleId: req.params?.id }, 'Failed to delete node assignment rule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
