import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from '../../types/JwtPayload';
import { AuditTrail, AuditTrailAction, AUDIT_TRAIL_ACTIONS } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';
import { PAGINATION_MAX_ROWS_AUDIT_TRAIL, PAGINATION_DEFAULT_ROWS_AUDIT } from '../../consts/pagination';
import { escapeIlikeSearchTerm } from '../../utils/sanitization';

const logger = getLogger('users.auditTrail');

/**
 * GET /users/audit-trail - List audit trail entries.
 * Query: page, limit, action (optional filter), all_users=true for feed (all users, latest first).
 */
export const audit_trail_list = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
  const limit = Math.min(PAGINATION_MAX_ROWS_AUDIT_TRAIL, Math.max(1, parseInt(String(req.query.limit), 10) || PAGINATION_DEFAULT_ROWS_AUDIT));
  const offset = (page - 1) * limit;
  const action = req.query.action as AuditTrailAction | undefined;
  const allUsers = req.query.all_users === 'true';
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  const sortBy = req.query.sort_by === 'action' || req.query.sort_by === 'status' ? req.query.sort_by : 'created_at';
  const orderDir = (req.query.order === 'asc' || req.query.order === 'desc') ? req.query.order.toUpperCase() : 'DESC';

  const validActions: readonly AuditTrailAction[] = AUDIT_TRAIL_ACTIONS;

  // exclude_actions: comma-separated (e.g. ALERT_STATUS_UPDATE,ALERT_ASSIGN_UPDATE) — user-activity only
  const excludeActionsRaw = typeof req.query.exclude_actions === 'string' ? req.query.exclude_actions.trim() : '';
  const excludeActions: AuditTrailAction[] = excludeActionsRaw
    ? (excludeActionsRaw.split(',').map((a) => a.trim()).filter(Boolean) as AuditTrailAction[]).filter((a) =>
        validActions.includes(a)
      )
    : [];

  // only_actions: comma-separated — e.g. agent tab (PORT_BLOCK, IP_BLOCK, ...)
  const onlyActionsRaw = typeof req.query.only_actions === 'string' ? req.query.only_actions.trim() : '';
  const onlyActions: AuditTrailAction[] = onlyActionsRaw
    ? (onlyActionsRaw.split(',').map((a) => a.trim()).filter(Boolean) as AuditTrailAction[]).filter((a) =>
        validActions.includes(a)
      )
    : [];

  try {
    const { dbSourceConnection } = await import('../../index');
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId: jwtPayload.id }, 'Database connection not established for audit trail listing');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const repo = primaryDataSource.getRepository(AuditTrail);
    const orderColumn = sortBy === 'created_at' ? 'trail.createdAt' : sortBy === 'action' ? 'trail.action' : 'trail.status';
    const qb = repo
      .createQueryBuilder('trail')
      .leftJoinAndSelect('trail.user', 'user')
      .orderBy(orderColumn, orderDir as 'ASC' | 'DESC')
      .skip(offset)
      .take(limit);

    if (!allUsers) {
      qb.where('trail.userId = :userId', { userId: jwtPayload.id });
    }
    if (search.length > 0) {
      const searchPattern = `%${escapeIlikeSearchTerm(search)}%`;
      qb.andWhere(
        '(user.name ILIKE :search OR user.email ILIKE :search OR trail.email ILIKE :search)',
        { search: searchPattern }
      );
    }
    if (action && validActions.includes(action)) {
      qb.andWhere('trail.action = :action', { action });
    }
    if (excludeActions.length > 0) {
      qb.andWhere('trail.action NOT IN (:...excludeActions)', { excludeActions });
    }
    if (onlyActions.length > 0) {
      qb.andWhere('trail.action IN (:...onlyActions)', { onlyActions });
    }

    const [logs, total] = await qb.getManyAndCount();

    logger.debug({ count: logs.length, page }, 'Audit trail listed');

    return res.status(200).json({
      status: 'Success',
      data: {
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
    logger.error({ err: error, userId: jwtPayload.id, page, action }, 'Failed to list audit trail');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
