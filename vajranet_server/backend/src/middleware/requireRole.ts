import { NextFunction, Request, Response } from 'express';
import { JwtPayload } from '../types/JwtPayload';
import { USER_ROLES, VajraUser, DEFAULT_USER_ROLE } from '../orm/entities/users/Users';
import { CustomError } from '../utils/response/custom-error/CustomError';
import { getLogger } from '../utils/logger';

const normalizeRole = (role: unknown): (typeof USER_ROLES)[number] => {
  return USER_ROLES.includes(role as (typeof USER_ROLES)[number])
    ? (role as (typeof USER_ROLES)[number])
    : DEFAULT_USER_ROLE;
};

/**
 * Shared factory behind requireAdmin and requireSuperAdmin: fetches the
 * requesting user's role, self-heals an invalid stored role to Viewer, and
 * denies access unless the (normalized) role is in allowedRoles.
 */
export const requireRole = (
  allowedRoles: (typeof USER_ROLES)[number][],
  options: { loggerName: string; roleLabel: string; deniedMessage: string }
) => {
  const logger = getLogger(options.loggerName);

  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      if (!jwtPayload?.id) {
        return next(new CustomError(401, 'General', 'Authentication required'));
      }

      const { dbSourceConnection } = await import('../index');
      const dbSources = dbSourceConnection();
      if (!dbSources || dbSources.length === 0) {
        return next(new CustomError(500, 'Database', 'Database connection not available.'));
      }

      const userRepository = dbSources[0].getRepository(VajraUser);
      const user = await userRepository.findOne({
        where: { id: jwtPayload.id },
        select: ['id', 'role'],
      });

      if (!user) {
        // jwtPayload.id here is the only identifier that distinguishes this from
        // any other reason "User not found" could be returned (deleted account,
        // stale/tampered token) — errorHandler logs the message text but not
        // which user id the request was carrying.
        logger.warn({ userId: jwtPayload.id }, `${options.roleLabel} access check failed: user no longer exists`);
        return next(new CustomError(401, 'General', 'User not found'));
      }

      const role = normalizeRole((user as any).role);
      if ((user as any).role !== role) {
        logger.warn({ userId: user.id, storedRole: (user as any).role, normalizedRole: role }, 'Correcting invalid stored role to Viewer');
        await userRepository.update(user.id, { role });
      }

      if (!allowedRoles.includes(role)) {
        // Authorization denial: who was denied and with what role, not just the
        // generic 403 errorHandler logs from message text alone.
        logger.warn({ userId: user.id, role }, `${options.roleLabel} access denied: insufficient role`);
        return next(new CustomError(403, 'General', options.deniedMessage));
      }

      return next();
    } catch (err) {
      // Read directly off req rather than the try-scoped jwtPayload (out of
      // scope in catch) — without it, a DB failure partway through this check
      // is indistinguishable from any other user's.
      logger.error({ err, userId: (req as any).jwtPayload?.id }, `Failed to validate ${options.roleLabel} access`);
      return next(new CustomError(500, 'Raw', `Error validating ${options.roleLabel} access`, null, err));
    }
  };
};
