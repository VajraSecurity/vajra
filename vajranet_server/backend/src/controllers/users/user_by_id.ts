import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from '../../types/JwtPayload';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.userById');

/**
 * GET /users/by-id?id=
 * Returns a single registered user (id, name, email) for UI lookups (e.g. audit trail user #id popovers).
 *
 * Scoped the same way as /users/list: Super Administrator can look up anyone;
 * anyone else only resolves a user who shares at least one group with them,
 * or themselves. A lookup outside that scope reports 404, same as "not
 * found", rather than a distinguishing 403 — this endpoint's whole purpose is
 * confirming/denying whether a given id resolves to a name, so a 403 would
 * itself leak "yes, that id exists, you're just not allowed to see it".
 */
export const user_by_id = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const rawId = req.query.id;
  const userId = parseInt(String(rawId ?? ''), 10);
  if (!Number.isFinite(userId) || userId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Invalid query param: id' });
  }

  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId }, 'Database connection not established for user lookup by id');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);

    const repo = primaryDataSource.getRepository(VajraUser);
    const qb = repo
      .createQueryBuilder('u')
      .select(['u.id', 'u.name', 'u.email'])
      .where('u.id = :userId', { userId });

    if (!scope.unrestricted) {
      qb.andWhere(
        `u.id IN (
           SELECT user_id FROM user_group_memberships WHERE group_id = ANY(:groupIds)
           UNION SELECT :callerId::int
         )`,
        { groupIds: scopeGroupIds(scope), callerId: jwtPayload.id },
      );
    }

    const u = await qb.getOne();

    if (!u) {
      logger.warn({ userId }, 'User lookup by id rejected: user not found or out of caller scope');
      return res.status(404).json({ status: 'Error', message: 'User not found' });
    }

    logger.debug({ userId: u.id }, 'User fetched by id');

    return res.status(200).json({
      status: 'Success',
      data: {
        user: {
          id: u.id,
          name: u.name,
          email: u.email,
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, userId }, 'Failed to fetch user by id');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
