import { Request, Response, NextFunction } from 'express';
import { getRefreshTokenStatus } from '../../middleware/checkJWTStatus';
import { JwtPayload } from '../../types/JwtPayload';
import { dbSourceConnection } from '../..';
import { VajraUser } from '../../orm/entities/users/Users';
import { getLogger } from '../../utils/logger';
import { CSRF_COOKIE_NAME } from '../../utils/cookieConfig';
import { setCsrfTokenCookie } from '../../utils/renewCSRFToken';
import { generateCsrfToken } from '../../utils/createJwtToken';

const logger = getLogger('auth.sessionStatus');

export const getSessionStatus = async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
  const status = getRefreshTokenStatus(req);

  // Self-heal a session that still has valid access/refresh cookies but has lost its
  // CSRF cookie: without it the user cannot recover, because every mutating request —
  // logout included — requires that cookie. Safe to reissue here because this endpoint
  // is GET-only and never consumes the CSRF token, so it carries none of the risk the
  // CSRF check exists to prevent.
  if (status.isValid && !req.cookies[CSRF_COOKIE_NAME]) {
    setCsrfTokenCookie(res, generateCsrfToken());
    logger.info({ userId: (req as any).jwtPayload?.id }, 'CSRF cookie missing on valid session, reissued');
  }

  if (!status.isValid) {
    const statusCode = status.errorType === 'NotFound' ? 401 : 403;

    logger.debug({ errorType: status.errorType, statusCode }, 'Session status check failed: refresh token invalid');

    res.status(statusCode).json({
      status: 'Error',
      isValid: false,
      message: `No active session. Reason: ${status.errorType} token.`,
      errorType: status.errorType,
    });
    return;
  }

  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

  if (!jwtPayload?.id) {
    logger.warn('Session status check failed: refresh token valid but JWT payload missing user id');
    res.status(401).json({
      status: 'Error',
      isValid: false,
      message: 'Invalid JWT payload.',
    });
    return;
  }

  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length === 0) {
    logger.error({ userId: jwtPayload.id }, 'Database connection not established for session status check');
    res.status(500).json({
      status: 'Error',
      isValid: false,
      message: 'Database connection not available.',
    });
    return;
  }

  const userRepository = dbSources[0].getRepository(VajraUser);

  let user: Pick<VajraUser, 'id' | 'forcePasswordChange'> | null;
  try {
    user = await userRepository.findOne({
      where: { id: jwtPayload.id },
      select: ['id', 'forcePasswordChange'],
    });
  } catch (err) {
    logger.error({ err, userId: jwtPayload.id }, 'Failed to fetch user for session status check');
    res.status(500).json({
      status: 'Error',
      isValid: false,
      message: 'Failed to check session status.',
    });
    return;
  }

  if (!user) {
    logger.warn({ userId: jwtPayload.id }, 'Session status check failed: user not found');
    res.status(401).json({
      status: 'Error',
      isValid: false,
      message: 'User not found.',
    });
    return;
  }

  if (user.forcePasswordChange) {
    logger.debug({ userId: user.id }, 'Session status retrieved, password reset required');
    res.status(200).json({
      status: 'Success',
      isValid: true,
      forcePasswordChange: true,
      message: 'Password reset required.',
    });
    return;
  }

  logger.debug({ userId: user.id }, 'Session status retrieved');

  res.status(200).json({
    status: 'Success',
    isValid: true,
    forcePasswordChange: false,
    message: 'Active session found.',
  });
};