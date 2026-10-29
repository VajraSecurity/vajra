import { Request, Response } from 'express';
import { JwtPayload } from '../../types/JwtPayload';
import { UserSession } from '../../orm/entities/session/UserSession';
import { getLogger } from '../../utils/logger';
import { PAGINATION_MAX_ROWS_AUDIT_TRAIL, PAGINATION_DEFAULT_ROWS_AUDIT } from '../../consts/pagination';
import { escapeIlikeSearchTerm } from '../../utils/sanitization';

const logger = getLogger('users.sessionHistory');

/**
 * GET /users/session-history - List user sessions (login time, logout time, duration).
 * Multi-device use is supported, so a user can hold several concurrent sessions and
 * every one of them is listed; active sessions sort first. A session still flagged
 * active in the database but older than 14 days is reported as inactive for display
 * only, without writing to the row.
 * Query: page, limit, all_users=true for all users, search (user name/email).
 */
export const session_history_list = async (req: Request, res: Response) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
  const limit = Math.min(PAGINATION_MAX_ROWS_AUDIT_TRAIL, Math.max(1, parseInt(String(req.query.limit), 10) || PAGINATION_DEFAULT_ROWS_AUDIT));
  const offset = (page - 1) * limit;
  const allUsers = req.query.all_users === 'true';
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  const sortBy = req.query.sort_by === 'login_time' || req.query.sort_by === 'logout_time' ? req.query.sort_by : 'login_time';
  const orderDir = (req.query.order === 'asc' || req.query.order === 'desc') ? req.query.order.toUpperCase() : 'DESC';

  try {
    const { dbSourceConnection } = await import('../../index');
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId: jwtPayload.id }, 'Database connection not established for session history listing');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const repo = primaryDataSource.getRepository(UserSession);
    const orderColumn = sortBy === 'login_time' ? 'session.loginTime' : 'session.logoutTime';
    const qb = repo
      .createQueryBuilder('session')
      .leftJoinAndSelect('session.user', 'user')
      .orderBy('session.isActive', 'DESC')
      .addOrderBy(orderColumn, orderDir as 'ASC' | 'DESC')
      .skip(offset)
      .take(limit);

    if (!allUsers) {
      qb.andWhere('session.userId = :userId', { userId: jwtPayload.id });
    }
    if (search.length > 0) {
      const searchPattern = `%${escapeIlikeSearchTerm(search)}%`;
      qb.andWhere(
        '(user.name ILIKE :search OR user.email ILIKE :search)',
        { search: searchPattern }
      );
    }

    const rawAndEntities = await qb.getRawAndEntities();
    // TypeORM's getCount() is safe here because ManyToOne joins do not produce duplicate rows.
    const total = await qb.getCount();
    const sessions = rawAndEntities.entities;

    let staleActiveCount = 0;
    const mappedSessions = sessions.map((s: UserSession) => {
      // Clean up IP address (e.g., ::1 -> 127.0.0.1, ::ffff:10.0.0.1 -> 10.0.0.1)
      let cleanIp = s.ipAddress;
      if (cleanIp === '::1') cleanIp = '127.0.0.1';
      else if (cleanIp?.startsWith('::ffff:')) cleanIp = cleanIp.replace('::ffff:', '');

      let effectiveIsActive = s.isActive;
      const fourteenDaysMs = 14 * 24 * 60 * 60 * 1000;
      if (effectiveIsActive && s.loginTime && (Date.now() - s.loginTime.getTime() > fourteenDaysMs)) {
        effectiveIsActive = false;
        staleActiveCount += 1;
      }

      return {
        id: s.id,
        user_name: s.user?.name ?? null,
        user_email: s.user?.email ?? null,
        login_time: s.loginTime,
        logout_time: s.logoutTime,
        logout_reason: s.logoutReason,
        duration_seconds: s.durationSeconds,
        is_active: effectiveIsActive,
        ip_address: cleanIp,
        user_agent: s.userAgent,
      };
    });

    if (staleActiveCount > 0) {
      // Still `isActive: true` in the database (no logout was ever recorded, e.g. a
      // crashed server) but shown as inactive due to age. Traced because it is a
      // display-only override, not a DB write.
      logger.debug({ staleActiveCount, page }, 'Session history: displaying stale active sessions as expired');
    }

    logger.debug({ count: sessions.length, page }, 'Session history listed');

    return res.status(200).json({
      status: 'Success',
      data: {
        sessions: mappedSessions,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, userId: jwtPayload.id, page }, 'Failed to list session history');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
