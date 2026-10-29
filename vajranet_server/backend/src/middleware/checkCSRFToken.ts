import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { CustomError } from '../utils/response/custom-error/CustomError';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '../utils/cookieConfig';
import type { JwtPayload } from '../types/JwtPayload';
import { getLogger } from '../utils/logger';
import { getRedisClient, getCsrfSuccessor } from '../utils/redisClient';
import { getCsrfSuccessorMemory } from '../utils/memoryStore';

const logger = getLogger('middleware.checkCsrf');

/** See checkJwt.ts storeCsrfSuccessorForToken (write side) for why this exists. */
async function getGracedCsrfSuccessor(oldToken: string): Promise<string | null> {
  if (getRedisClient()) {
    return await getCsrfSuccessor(oldToken);
  }
  return getCsrfSuccessorMemory(oldToken);
}

export const checkCsrf = async (req: Request, _res: Response, next: NextFunction) => {

  const tokenFromCookie = req.cookies[CSRF_COOKIE_NAME];
  const tokenFromHeader = req.header(CSRF_HEADER_NAME);
  // checkCsrf runs after checkJwt/checkAccessJwt on every route that mounts it,
  // so jwtPayload is normally already attached to req — capture it here.
  // errorHandler logs 4xx responses by message text only (no userId), and the
  // three branches below produce distinct message text but not who was denied
  // — without userId, a report of one user repeatedly hitting CSRF failures is
  // indistinguishable in the logs from three different users each hitting it once.
  const userId = (req as any).jwtPayload?.id;

  if (!tokenFromCookie) {
    logger.warn({ userId, path: req.originalUrl }, 'CSRF validation failed: cookie not found');
    const customError = new CustomError(403, 'General', 'CSRF validation failed: Cookie not found.');
    return next(customError);
  }

  if (!tokenFromHeader) {
    logger.warn({ userId, path: req.originalUrl }, 'CSRF validation failed: header not found');
    const customError = new CustomError(403, 'General', `CSRF validation failed: Header '${CSRF_HEADER_NAME}' not found.`);
    return next(customError);
  }
  if (
    tokenFromCookie.length !== tokenFromHeader.length ||
    !crypto.timingSafeEqual(Buffer.from(tokenFromCookie), Buffer.from(tokenFromHeader))
  ) {
    // Concurrent-request rotation race: the header carries a token that WAS
    // current until a sibling request, racing this one, silently rotated it
    // (see checkJwt.ts tryRenewTokens / rotateRefreshToken). Accept only if
    // the cookie now carries EXACTLY what that specific token was rotated
    // into — this never accepts an arbitrary stale or guessed token, only
    // one this server itself minted and has a recorded successor for.
    const gracedToken = await getGracedCsrfSuccessor(tokenFromHeader);
    if (
      gracedToken &&
      gracedToken.length === tokenFromCookie.length &&
      crypto.timingSafeEqual(Buffer.from(gracedToken), Buffer.from(tokenFromCookie))
    ) {
      logger.info({ userId, path: req.originalUrl }, 'CSRF validated via rotation grace window');
      return next();
    }

    logger.warn({ userId, path: req.originalUrl }, 'CSRF validation failed: tokens do not match');
    const customError = new CustomError(403, 'General', 'CSRF validation failed: Tokens do not match.');
    return next(customError);
  }
  return next();
};

/**
 * Enforce CSRF only for authenticated callers. Used on endpoints that also
 * serve an UNauthenticated bootstrap path with no session/CSRF cookie yet —
 * e.g. the very first user_register when no users exist.
 *
 * Must run after an auth middleware that populates req.jwtPayload, such as
 * requireSuperAdminIfUsersExist into checkAccessWithRefreshFallback.
 *
 * "Authenticated" is read from req.jwtPayload, never from the presence of the
 * access-token cookie. checkAccessWithRefreshFallback can authenticate off the
 * refresh cookie alone and mints the new access and CSRF cookies on the
 * response only, leaving req.cookies untouched for the current request. Keying
 * off the cookie would misread such a request as the unauthenticated bootstrap
 * case and skip CSRF entirely.
 */
export const checkCsrfIfAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload) {
    return next();
  }
  return checkCsrf(req, res, next);
};
