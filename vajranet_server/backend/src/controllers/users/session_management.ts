import { Request, Response } from 'express';
import { In } from 'typeorm';
import { UserSession } from '../../orm/entities/session/UserSession';
import { VajraUser } from '../../orm/entities/users/Users';
import { dbSourceConnection } from '../../index';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.sessionManagement');

const LOGOUT_REASON_ADMIN_FORCED = 'admin_forced_logout';

export const invalidate_sessions = async (req: Request, res: Response) => {
  const jwtPayload = (req as any).jwtPayload;
  const { sessionIds } = req.body;

  if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
    return res.status(400).json({ status: 'Error', message: 'sessionIds array is required' });
  }

  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ requestedCount: sessionIds.length }, 'Database connection not established for session invalidation');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const sessionRepo = dbSources[0].getRepository(UserSession);
    const sessions = await sessionRepo.find({
      where: { id: In(sessionIds), isActive: true },
      relations: ['user'],
    });

    if (sessions.length === 0) {
      logger.info({ requestedCount: sessionIds.length }, 'No active sessions found to invalidate');
      return res.status(200).json({ status: 'Success', message: 'No active sessions found to invalidate' });
    }

    const now = new Date();
    for (const session of sessions) {
      session.isActive = false;
      session.logoutTime = now;
      session.logoutReason = LOGOUT_REASON_ADMIN_FORCED;
      if (session.loginTime) {
        session.durationSeconds = Math.floor((now.getTime() - session.loginTime.getTime()) / 1000);
      }
    }

    await sessionRepo.save(sessions);

    // Sessions above are already invalidated and saved, so an audit-log failure here
    // must not be mistaken for the invalidation itself failing. The completed count is
    // tracked because sessions.length alone would make a failure on entry 9 of 10 look
    // identical to one on entry 1 of 10.
    let auditedCount = 0;
    try {
      for (const session of sessions) {
        if (session.user) {
          await logAuditTrail({
            action: 'LOGOUT',
            status: 'success',
            userId: session.user.id,
            email: session.user.email,
            ipAddress: session.ipAddress ?? undefined,
            userAgent: session.userAgent ?? undefined,
            details: {
              reason: 'invalidated_by_admin',
              session_id: session.id,
              invalidated_by_user_id: jwtPayload?.id ?? null,
              invalidated_by_email: jwtPayload?.email ?? null,
            },
          });
          auditedCount += 1;
        }
      }
    } catch (err) {
      logger.error({ err, count: sessions.length, auditedCount }, 'Sessions invalidated but audit trail logging failed partway through');
      throw err;
    }

    logger.info({ count: sessions.length }, 'Sessions invalidated');

    return res.status(200).json({ status: 'Success', message: `Invalidated ${sessions.length} sessions` });
  } catch (error) {
    logger.error({ err: error, sessionIds }, 'Failed to invalidate sessions');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

export const invalidate_user_sessions = async (req: Request, res: Response) => {
  const jwtPayload = (req as any).jwtPayload;
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ status: 'Error', message: 'email string is required' });
  }

  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ email }, 'Database connection not established for user session invalidation');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const userRepo = dbSources[0].getRepository(VajraUser);
    const user = await userRepo.findOne({ where: { email } });

    if (!user) {
      logger.warn({ email }, 'Session invalidation rejected: user not found');
      return res.status(404).json({ status: 'Error', message: 'User not found' });
    }

    // Increment session_version to invalidate all existing tokens instantly
    user.session_version += 1;
    await userRepo.save(user);

    const sessionRepo = dbSources[0].getRepository(UserSession);
    const sessions = await sessionRepo.find({
      where: { userId: user.id, isActive: true },
    });

    const now = new Date();
    for (const session of sessions) {
      session.isActive = false;
      session.logoutTime = now;
      session.logoutReason = LOGOUT_REASON_ADMIN_FORCED;
      if (session.loginTime) {
        session.durationSeconds = Math.floor((now.getTime() - session.loginTime.getTime()) / 1000);
      }
    }

    if (sessions.length > 0) {
      await sessionRepo.save(sessions);
    }

    // Sessions above are already invalidated and saved, so an audit-log failure here
    // must not be mistaken for the invalidation itself failing.
    try {
      await logAuditTrail({
        action: 'LOGOUT',
        status: 'success',
        userId: user.id,
        email: user.email,
        details: {
          reason: 'all_sessions_invalidated_by_admin',
          session_count: sessions.length,
          invalidated_by_user_id: jwtPayload?.id ?? null,
          invalidated_by_email: jwtPayload?.email ?? null,
        },
      });
    } catch (err) {
      logger.error({ err, userId: user.id, count: sessions.length }, 'Sessions invalidated but audit trail logging failed');
      throw err;
    }

    logger.info({ userId: user.id, count: sessions.length }, 'User sessions invalidated');

    return res.status(200).json({ status: 'Success', message: `Invalidated all sessions for ${email}` });
  } catch (error) {
    logger.error({ err: error, email }, 'Failed to invalidate user sessions');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
