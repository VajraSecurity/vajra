import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { USER_ROLES, VajraUser, DEFAULT_USER_ROLE } from '../../orm/entities/users/Users';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { JwtPayload } from '../../types/JwtPayload';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.userProfile');

export const userProfile = async (req: Request, res: Response, next: NextFunction) => {
  const jwtPayload: JwtPayload = (req as any).jwtPayload;
  const userId = jwtPayload?.id;

  if (!userId) {
    return next(new CustomError(401, 'General', 'Authentication required', ['User ID not found in token payload']));
  }

  const dbSources = dbSourceConnection();

  if (!dbSources || dbSources.length === 0) {
    logger.error({ userId }, 'Database connection not established for profile fetch');
    const customError = new CustomError(500, 'Database', 'Database connection source is missing or not initialized.', []);
    return next(customError);
  }

  const userRepository = dbSources[0].getRepository(VajraUser);

  try {
    const user = await userRepository
      .createQueryBuilder('user')
      .select(['user.id', 'user.name', 'user.email', 'user.mobile', 'user.address', 'user.company', 'user.role', 'user.suspended', 'user.mfa_enabled', 'user.avatar_id', 'user.avatar_image'])
      .where('user.id = :id', { id: userId })
      .getOne();

    if (!user) {
      logger.warn({ userId }, 'Profile fetch rejected: user not found');
      return next(new CustomError(404, 'General', 'User not found in database', [`User with ID ${userId} does not exist.`]));
    }

    const normalizedRole = USER_ROLES.includes((user as any).role) ? (user as any).role : DEFAULT_USER_ROLE;
    if ((user as any).role !== normalizedRole) {
      logger.warn({ userId, storedRole: (user as any).role, normalizedRole }, 'Invalid stored role corrected to default on profile fetch');
      await userRepository.update(user.id, { role: normalizedRole });
    }

    logger.debug({ userId }, 'User profile fetched');

    return res.status(200).json({
      status: 'Success',
      message: 'User profile fetched successfully',
      data: {
        ...user,
        role: normalizedRole,
      },
    });

  } catch (err) {
    logger.error({ err, userId }, 'Failed to fetch user profile');
    const customError = new CustomError(500, 'Raw', 'Error fetching user profile', null, err);
    return next(customError);
  }
};
