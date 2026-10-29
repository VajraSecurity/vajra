import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { NodeAssignmentRule } from '../../orm/entities/fleet/NodeAssignmentRule';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { isValidIpv4Cidr } from './validateCondition';
import { getLogger } from '../../utils/logger';
import { toFiniteNumberOrNull } from '../../utils/numeric';

const logger = getLogger('nodeAssignmentRules.update');

export async function update_rule(req: Request, res: Response) {
  try {
    const id = parseInt(req.params.id as string, 10);
    const { name, conditionValue, groupId, priority, enabled } = req.body;

    if (!Number.isFinite(id)) {
      logger.warn({ rawId: req.params.id }, 'Node assignment rule update rejected: invalid rule id');
      return res.status(400).json({ success: false, message: 'Invalid rule id.' });
    }
    if (!name || typeof name !== 'string' || !name.trim()) {
      logger.warn({ ruleId: id }, 'Node assignment rule update rejected: missing name');
      return res.status(400).json({ success: false, message: 'Rule name is required.' });
    }
    if (!isValidIpv4Cidr(conditionValue)) {
      logger.warn({ ruleId: id, conditionValue }, 'Node assignment rule update rejected: invalid condition CIDR');
      return res.status(400).json({ success: false, message: 'Condition must be a valid IPv4 CIDR, e.g. 10.0.5.0/24.' });
    }
    if (!groupId || typeof groupId !== 'string') {
      logger.warn({ ruleId: id }, 'Node assignment rule update rejected: missing target group');
      return res.status(400).json({ success: false, message: 'A target group is required.' });
    }
    let parsedPriority: number | null = null;
    if (priority !== undefined) {
      parsedPriority = toFiniteNumberOrNull(priority);
      if (parsedPriority === null) {
        logger.warn({ ruleId: id, priority }, 'Node assignment rule update rejected: invalid priority');
        return res.status(400).json({ success: false, message: 'Priority must be a valid number.' });
      }
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ ruleId: id, groupId }, 'Fleet database not available while updating node assignment rule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const groupRepo = fleetDb.getRepository(EndpointGroup);
    const group = await groupRepo.findOne({ where: { groupId } });
    if (!group) {
      logger.warn({ ruleId: id, groupId }, 'Node assignment rule update requested with a target group that does not exist');
      return res.status(404).json({ success: false, message: 'Target group not found.' });
    }

    const ruleRepo = fleetDb.getRepository(NodeAssignmentRule);
    const rule = await ruleRepo.findOne({ where: { id } });
    if (!rule) {
      logger.warn({ ruleId: id }, 'Node assignment rule update requested for a rule that does not exist');
      return res.status(404).json({ success: false, message: 'Rule not found.' });
    }

    rule.name = name.trim();
    rule.conditionValue = conditionValue.trim();
    rule.groupId = groupId;
    rule.priority = parsedPriority === null ? rule.priority : parsedPriority;
    rule.enabled = enabled === undefined ? rule.enabled : Boolean(enabled);
    await ruleRepo.save(rule);

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'NODE_ASSIGNMENT_RULE_UPDATE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { ruleId: rule.id, name: rule.name, conditionValue: rule.conditionValue, groupId: rule.groupId },
      }).catch((err) => logger.error({ err, ruleId: rule.id }, 'Failed to log audit trail'));
    }

    logger.info({ ruleId: rule.id, name: rule.name, groupId: rule.groupId }, 'Node assignment rule updated');
    return res.status(200).json({ success: true, rule });
  } catch (error) {
    logger.error({ err: error, ruleId: req.params?.id, groupId: req.body?.groupId }, 'Failed to update node assignment rule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
