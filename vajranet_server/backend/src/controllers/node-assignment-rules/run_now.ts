import { Request, Response } from 'express';
import { getNodeAutoAssignServiceInstance } from '../../services/nodeAutoAssignService';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodeAssignmentRules.runNow');

export async function run_now(req: Request, res: Response) {
  try {
    const service = getNodeAutoAssignServiceInstance();
    if (!service) {
      logger.warn('Node assignment scheduler service not available, cannot run rules now');
      return res.status(503).json({ success: false, message: 'Node assignment scheduler is not available.' });
    }

    const result = await service.runAssignment();
    logger.info({ rulesEvaluated: result.rulesEvaluated, totalAssigned: result.totalAssigned }, 'Manual node assignment rule run completed');

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'NODE_ASSIGNMENT_RULE_RUN',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: result,
      }).catch((err) => logger.error({ err }, 'Failed to log audit trail'));
    }

    return res.status(200).json({ success: true, ...result });
  } catch (error) {
    logger.error({ err: error }, 'Failed to run node assignment rules');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
