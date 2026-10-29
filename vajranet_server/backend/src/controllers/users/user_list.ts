import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from '../../types/JwtPayload';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { escapeIlikeSearchTerm } from '../../utils/sanitization';

const logger = getLogger('users.userList');

/**
 * GET /users/list
 * Returns registered users (id, name, email) for alert assignment UI.
 * Query: page, limit, search (optional)
 *
 * Scoped: Super Administrator sees everyone; anyone else only sees users who
 * share at least one group with them (via user_group_memberships), plus
 * themselves. Unauthenticated/no-membership callers see only themselves —
 * this endpoint has no admin gate (any authenticated role reaches it), so
 * fail-closed rather than fail-open is required here.
 */
export const users_list = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const page = Math.max(1, parseInt(String(req.query.page ?? 1), 10) || 1);
  const limit = Math.min(5000, Math.max(1, parseInt(String(req.query.limit ?? 1000), 10) || 1000));
  const offset = (page - 1) * limit;
  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId: jwtPayload.id }, 'Database connection not established for users listing');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);

    const repo = primaryDataSource.getRepository(VajraUser);
    const qb = repo
      .createQueryBuilder('u')
      .select(['u.id', 'u.name', 'u.email'])
      .orderBy('u.created_at', 'DESC')
      .skip(offset)
      .take(limit);

    if (!scope.unrestricted) {
      qb.andWhere(
        `u.id IN (
           SELECT user_id FROM user_group_memberships WHERE group_id = ANY(:groupIds)
           UNION SELECT :callerId::int
         )`,
        { groupIds: scopeGroupIds(scope), callerId: jwtPayload.id },
      );
    }

    if (search) {
      qb.andWhere('(u.name ILIKE :search OR u.email ILIKE :search)', {
        search: `%${escapeIlikeSearchTerm(search)}%`,
      });
    }

    const users = await qb.getMany();

    logger.debug({ count: users.length }, 'Users listed');

    return res.status(200).json({
      status: 'Success',
      data: {
        users: users.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
        })),
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list users');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

