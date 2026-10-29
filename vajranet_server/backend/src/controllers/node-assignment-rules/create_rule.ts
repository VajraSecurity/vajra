import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import {
  NodeAssignmentRule,
  NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR,
  NODE_ASSIGNMENT_RULE_DEFAULT_PRIORITY,
} from '../../orm/entities/fleet/NodeAssignmentRule';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { isValidIpv4Cidr } from './validateCondition';
import { getLogger } from '../../utils/logger';
import { toFiniteNumberOrNull } from '../../utils/numeric';

const logger = getLogger('nodeAssignmentRules.create');

export async function create_rule(req: Request, res: Response) {
  try {
    const { name, conditionValue, groupId, priority, enabled } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      logger.debug('Node assignment rule create rejected: missing name');
      return res.status(400).json({ success: false, message: 'Rule name is required.' });
    }
    if (!isValidIpv4Cidr(conditionValue)) {
      logger.debug({ name, conditionValue }, 'Node assignment rule create rejected: invalid condition CIDR');
      return res.status(400).json({ success: false, message: 'Condition must be a valid IPv4 CIDR, e.g. 10.0.5.0/24.' });
    }
    if (!groupId || typeof groupId !== 'string') {
      logger.debug({ name }, 'Node assignment rule create rejected: missing target group');
      return res.status(400).json({ success: false, message: 'A target group is required.' });
    }
    let rulePriority = NODE_ASSIGNMENT_RULE_DEFAULT_PRIORITY;
    if (priority !== undefined) {
      const parsedPriority = toFiniteNumberOrNull(priority);
      if (parsedPriority === null) {
        logger.debug({ name, priority }, 'Node assignment rule create rejected: invalid priority');
        return res.status(400).json({ success: false, message: 'Priority must be a valid number.' });
      }
      rulePriority = parsedPriority;
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ name, groupId }, 'Fleet database not available while creating node assignment rule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const groupRepo = fleetDb.getRepository(EndpointGroup);
    const group = await groupRepo.findOne({ where: { groupId } });
    if (!group) {
      logger.debug({ groupId }, 'Node assignment rule create requested with a target group that does not exist');
      return res.status(404).json({ success: false, message: 'Target group not found.' });
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

    const ruleRepo = fleetDb.getRepository(NodeAssignmentRule);
    const rule = ruleRepo.create({
      name: name.trim(),
      conditionType: NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR,
      conditionValue: conditionValue.trim(),
      groupId,
      priority: rulePriority,
      enabled: enabled === undefined ? true : Boolean(enabled),
      createdBy: jwtPayload?.email || 'unknown',
    });
    await ruleRepo.save(rule);

    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'NODE_ASSIGNMENT_RULE_CREATE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { ruleId: rule.id, name: rule.name, conditionValue: rule.conditionValue, groupId: rule.groupId },
      }).catch((err) => logger.error({ err, ruleId: rule.id }, 'Failed to log audit trail'));
    }

    logger.info({ ruleId: rule.id, name: rule.name, groupId: rule.groupId }, 'Node assignment rule created');
    return res.status(200).json({ success: true, rule });
  } catch (error) {
    logger.error({ err: error, name: req.body?.name, groupId: req.body?.groupId }, 'Failed to create node assignment rule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
