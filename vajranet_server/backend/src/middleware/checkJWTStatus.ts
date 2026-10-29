     import { Request } from 'express';
import jwt, { TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';
import { JwtPayload } from '../types/JwtPayload';
import { REFRESH_TOKEN_COOKIE } from '../utils/cookieConfig';
import { JWT_ALGORITHM } from '../consts';
import { stripJwtTimingClaims } from './checkJwt';
import { getLogger } from '../utils/logger';

const logger = getLogger('middleware.checkJWTStatus');

export const getRefreshTokenStatus = (req: Request): {
  isValid: boolean;
  payload?: JwtPayload;
  errorType?: 'Expired' | 'Invalid' | 'NotFound';
} => {
  const token = req.cookies[REFRESH_TOKEN_COOKIE];

  if (!token) {
    return { isValid: false, errorType: 'NotFound' };
  }

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] });

    const jwtPayload = decoded as { [key: string]: any };
    stripJwtTimingClaims(jwtPayload);

    return {
      isValid: true,
      payload: jwtPayload as JwtPayload
    };

  } catch (err) {
    if (err instanceof TokenExpiredError) {
      logger.warn('Refresh token status check failed: token expired');
      return { isValid: false, errorType: 'Expired' };
    }

    if (err instanceof JsonWebTokenError) {
      logger.warn({ reason: err.message }, 'Refresh token status check failed: token invalid');
      return { isValid: false, errorType: 'Invalid' };
    }

    logger.warn({ err }, 'Refresh token status check failed: unexpected verification error');
    return { isValid: false, errorType: 'Invalid' };
  }
};