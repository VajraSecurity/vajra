import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { AuditTrail } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.teamForcePasswordChange');

export const team_force_password_change = async (req: Request, res: Response) => {
  const requesterId = Number((req as any).jwtPayload?.id);
  const requesterEmail = (req as any).jwtPayload?.email;
  const userId = Number(req.body?.id);
  const reason = req.body?.reason;

  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Valid user id is required' });
  }

  if (typeof reason !== 'string' || reason.trim() === '') {
    return res.status(400).json({ status: 'Error', message: 'Reason is required' });
  }

  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ requesterId, userId }, 'Database connection not established for force password change');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const repo = primaryDataSource.getRepository(VajraUser);
    const auditRepo = primaryDataSource.getRepository(AuditTrail);

    const targetUser = await repo.findOne({ where: { id: userId } });
    if (!targetUser) {
      logger.warn({ requesterId, userId }, 'Force password change rejected: user not found');
      return res.status(404).json({ status: 'Error', message: 'User not found' });
    }

    if (requesterId === targetUser.id) {
        logger.warn({ requesterId }, 'Force password change rejected: requester targeted own account');
        return res.status(403).json({ status: 'Error', message: 'You cannot force a password change on yourself from this interface' });
    }

    targetUser.forcePasswordChange = true;
    targetUser.session_version = (targetUser.session_version ?? 0) + 1;
    await repo.save(targetUser);

    const auditEntry = new AuditTrail();
    auditEntry.action = 'FORCE_PASSWORD_CHANGE';
    auditEntry.status = 'success';
    auditEntry.userId = requesterId;
    auditEntry.email = requesterEmail || null;
    auditEntry.ipAddress = req.ip || req.socket.remoteAddress || null;
    auditEntry.userAgent = req.get('user-agent') || null;
    auditEntry.details = {
      target_user_id: targetUser.id,
      target_user_email: targetUser.email,
      reason: reason.trim(),
    };
    try {
      await auditRepo.save(auditEntry);
    } catch (err) {
      // Target user is already flagged and session-bumped at this point — distinguish this
      // from a save failure so a 500 here isn't mistaken for the flag itself failing.
      logger.error({ err, userId: targetUser.id, requesterId }, 'Force password change applied but audit trail logging failed');
      throw err;
    }

    logger.info({ userId: targetUser.id, requesterId }, 'Force password change marked');

    return res.status(200).json({
      status: 'Success',
      message: 'Force password change marked successfully',
    });
  } catch (error) {
    logger.error({ err: error, userId }, 'Failed to force password change');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
