import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from '../../types/JwtPayload';
import { UserSession } from '../../orm/entities/session/UserSession';
import { AuditTrail, AuditTrailAction } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';
import { PAGINATION_MAX_ROWS_ADMIN_ACTIVITY } from '../../consts/pagination';

const logger = getLogger('users.sessionActions');

/**
 * GET /users/session-actions - List audit trail entries for a specific session.
 * Query: session_id (required), page, limit, order (asc|desc), all_users=true (admin feed).
 *
 * Note: Session scoping is computed by filtering audit_trail by user_id and created_at between
 * session.login_time and session.logout_time (or now if active).
 */
export const session_actions_list = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const sessionId = parseInt(String(req.query.session_id ?? ''), 10);
  if (!Number.isFinite(sessionId) || sessionId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'session_id is required' });
  }

  const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
  const limit = Math.min(PAGINATION_MAX_ROWS_ADMIN_ACTIVITY, Math.max(1, parseInt(String(req.query.limit), 10) || PAGINATION_MAX_ROWS_ADMIN_ACTIVITY));
  const offset = (page - 1) * limit;
  const allUsers = req.query.all_users === 'true';
  const orderDir = req.query.order === 'asc' || req.query.order === 'desc' ? req.query.order.toUpperCase() : 'DESC';

  try {
    const { dbSourceConnection } = await import('../../index');
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId: jwtPayload.id, sessionId }, 'Database connection not established for session actions listing');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const sessionRepo = primaryDataSource.getRepository(UserSession);
    const session = await sessionRepo.findOne({ where: { id: sessionId }, relations: { user: true } });
    if (!session) {
      logger.warn({ userId: jwtPayload.id, sessionId }, 'Session actions lookup rejected: session not found');
      return res.status(404).json({ status: 'Error', message: 'Session not found' });
    }

    if (!allUsers && session.userId !== jwtPayload.id) {
      logger.warn({ userId: jwtPayload.id, sessionId, sessionOwnerId: session.userId }, 'Session actions lookup rejected: forbidden cross-user access attempt');
      return res.status(403).json({ status: 'Error', message: 'Forbidden' });
    }

    const start = session.loginTime;
    const end = session.logoutTime ?? new Date();

    const repo = primaryDataSource.getRepository(AuditTrail);
    const qb = repo
      .createQueryBuilder('trail')
      .leftJoinAndSelect('trail.user', 'user')
      .where('trail.userId = :userId', { userId: session.userId })
      .andWhere('trail.createdAt >= :start', { start })
      .andWhere('trail.createdAt <= :end', { end });

    const validActions: AuditTrailAction[] = [
      'LOGIN',
      'LOGOUT',
      'RENAME_NODE',
      'MARK_NODE_CRITICAL',
      'ISOLATE_NODE',
      'REENROLL_NODE',
      'ALERT_STATUS_UPDATE',
      'ALERT_ASSIGN_UPDATE',
      'ALERT_MARK_UPDATE',
      'USER_REGISTER',
      'PASSWORD_UPDATE',
      'FORCE_PASSWORD_CHANGE',
      'PORT_BLOCK',
      'IP_BLOCK',
      'COMPLIANCE',
      'WIFI',
      'BLUETOOTH',
      'DEFENDER',
      'USB',
      'CLAMAV',
      'CERTIN_DRAFT_START',
      'CERTIN_DRAFT_EDIT',
      'CERTIN_DRAFT_COMPLETE',
      'CERTIN_DRAFT_DOWNLOAD',
    ];

    if (session.ipAddress) {
      // WS agent actions (PORT_BLOCK, COMPLIANCE, etc.) don't carry an HTTP IP
      // (ipAddress is null in those rows). Including OR IS NULL ensures they
      // appear in the session timeline alongside HTTP-originated actions.
      qb.andWhere(
        '(trail.ipAddress = :ipAddress OR trail.ipAddress IS NULL)',
        { ipAddress: session.ipAddress },
      );
    }

    qb.andWhere('trail.action IN (:...validActions)', { validActions });

    qb.orderBy('trail.createdAt', orderDir as 'ASC' | 'DESC')
      .skip(offset)
      .take(limit);

    const [logs, total] = await qb.getManyAndCount();

    logger.debug({ count: logs.length, sessionId }, 'Session actions listed');

    return res.status(200).json({
      status: 'Success',
      data: {
        session: {
          id: session.id,
          user_id: session.userId,
          login_time: session.loginTime,
          logout_time: session.logoutTime,
          is_active: session.isActive,
        },
        logs: logs.map((l) => ({
          id: l.id,
          action: l.action,
          status: l.status,
          created_at: l.createdAt,
          user_name: l.user?.name ?? null,
          user_email: l.user?.email ?? l.email ?? null,
          ip_address: l.ipAddress ?? null,
          details: l.details ?? null,
        })),
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, userId: jwtPayload.id, sessionId }, 'Failed to list session actions');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

