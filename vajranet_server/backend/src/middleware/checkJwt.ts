import { Request, Response, NextFunction } from 'express';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import { JwtPayload } from '../types/JwtPayload';
import { CustomError } from '../utils/response/custom-error/CustomError';
import { createAccessToken } from '../utils/createJwtToken'; 
import { setAccessTokenCookie } from '../utils/renewAccessToken';
import { setCsrfTokenCookie } from '../utils/renewCSRFToken';
import { generateCsrfToken } from '../utils/createJwtToken';
import {
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  CSRF_COOKIE_NAME,
  SECURE_HTTP_ONLY_STRICT_OPTIONS,
  CLIENT_READABLE_STRICT_OPTIONS,
  REFRESH_TOKEN_MAX_AGE,
  SECURE_HTTP_ONLY_OPTIONS,
} from '../utils/cookieConfig';
import { isTokenBlacklisted, getRedisClient, claimTokenOnce, storeRefreshSuccessor, getRefreshSuccessor, storeCsrfSuccessor, type RefreshSuccessor } from '../utils/redisClient';
import { isTokenBlacklistedMemory, blacklistTokenMemory, claimTokenOnceMemory, storeRefreshSuccessorMemory, getRefreshSuccessorMemory, storeCsrfSuccessorMemory } from '../utils/memoryStore';
import { createRefreshToken } from '../utils/createJwtToken';
import { TOKEN_RENEWAL_THRESHOLD_SECONDS, JWT_ALGORITHM } from '../consts';
import { requireSuperAdmin } from './requireSuperAdmin';
import { getLogger } from '../utils/logger';

const logger = getLogger('middleware.checkJwt');

/** JWT claims stripped from a decoded payload before it's trusted as req.jwtPayload. */
export const JWT_TIMING_CLAIMS = ['iat', 'exp'] as const;

/** Removes iat/exp from a decoded JWT payload in place, so callers never mistake them for app claims. */
export function stripJwtTimingClaims(payload: { [key: string]: any }): void {
  JWT_TIMING_CLAIMS.forEach((keyToRemove) => delete payload[keyToRemove]);
}

/**
 * Checks if the user is required to change their password and restricts access to
 * only the password update, session status, and logout endpoints.
 */
function enforceForcePasswordChange(req: Request, jwtPayload: JwtPayload): CustomError | null {
  if (jwtPayload.force_password_change) {
    // .split('?')[0] strips the query string before matching — otherwise a
    // request to any locked-down route with a query string that happens to
    // contain one of these substrings (e.g. "?next=/auth/status") would
    // satisfy .includes() against the raw originalUrl and bypass the lockdown
    // entirely, since query content is attacker-controlled.
    const path = (req.originalUrl || req.path).split('?')[0];
    // Allow access to session status (so the frontend can detect this state),
    // the actual password update route, and logout routes only.
    const isAllowed =
      path.includes('/auth/profile/password-update') ||
      path.includes('/auth/status') ||
      path.includes('/auth/logout');
    if (!isAllowed) {
      // errorHandler logs 4xx responses by message text only, and that message
      // is identical for every user this blocks, so log which user and route.
      logger.warn({ userId: jwtPayload.id, path }, 'Blocked request: force_password_change is set for this session');
      return new CustomError(403, 'General', 'Password change required before accessing this resource.');
    }
  }
  return null;
}

/**
 * True if this is the interim MFA-challenge token from createMfaToken rather
 * than a full access token. It is signed with the same ACCESS_JWT_SECRET, so it
 * verifies anywhere a real access token would, but represents a session that
 * has completed only the password factor.
 *
 * Every verifier of an ACCESS_JWT_SECRET-signed token must therefore reject it.
 * Kept in sync with the verifiers that call jwt.verify directly instead of
 * going through this middleware: index.ts verifyWsJwt, utils/wsAuth.ts
 * getWsJwtPayload, and controllers/auth/validateGrafana.ts.
 */
export function isMfaChallengeToken(jwtPayload: { mfaToken?: boolean }): boolean {
  return jwtPayload?.mfaToken === true;
}

// Checks both the in-memory store and Redis: the memory store is the only
// blacklist that works when Redis is down, and Redis is the only one shared
// across instances, so a token is revoked if either says so.
export const checkTokenBlacklist = async (token: string): Promise<boolean> => {
  // Always check in-memory store first (fast)
  if (isTokenBlacklistedMemory(token)) {
    return true;
  }
  // Also check Redis if available
  if (getRedisClient()) {
    return await isTokenBlacklisted(token);
  }
  return false;
};

/**
 * Atomically claims a refresh token for single use before rotating it, so that
 * exactly one racer gets `true`. A check-then-blacklist pair would leave a
 * window in which two requests presenting the same refresh token both see "not
 * yet blacklisted" and both rotate, defeating reuse detection; Redis SET..NX is
 * atomic across instances and closes it.
 */
async function claimRefreshTokenOnce(token: string): Promise<boolean> {
  if (getRedisClient()) {
    const claimed = await claimTokenOnce(token, REFRESH_TOKEN_MAX_AGE / 1000);
    if (claimed) blacklistTokenMemory(token, REFRESH_TOKEN_MAX_AGE);
    return claimed;
  }
  return claimTokenOnceMemory(token, REFRESH_TOKEN_MAX_AGE);
}

// How long a losing racer's new-token triple stays available to other
// requests presenting the SAME old refresh token (see rotateRefreshToken).
const REFRESH_ROTATION_GRACE_SECONDS = 15;
// How long a just-rotated-away CSRF token is still accepted, paired with the
// cookie it was rotated into. See redisClient.ts storeCsrfSuccessor for why
// this is needed (browser Cookie: header vs JS-built custom header racing
// each other under connection-limited request queuing). Generous relative to
// how long that queuing delay can realistically run, without meaningfully
// weakening CSRF protection — a stolen/guessed token still can't get in here,
// this only ever accepts a token this server itself minted moments earlier.
const CSRF_ROTATION_GRACE_SECONDS = 30;
// How long a losing racer polls for the winner to finish writing that
// triple, before concluding this really is reuse rather than a concurrent
// request that lost the claim a moment before the winner published its result.
const REFRESH_SUCCESSOR_WAIT_MAX_MS = 2000;
const REFRESH_SUCCESSOR_POLL_INTERVAL_MS = 100;

async function storeRefreshSuccessorForToken(oldToken: string, successor: RefreshSuccessor): Promise<void> {
  if (getRedisClient()) {
    await storeRefreshSuccessor(oldToken, successor, REFRESH_ROTATION_GRACE_SECONDS);
  } else {
    storeRefreshSuccessorMemory(oldToken, successor, REFRESH_ROTATION_GRACE_SECONDS * 1000);
  }
}

async function getRefreshSuccessorForToken(oldToken: string): Promise<RefreshSuccessor | null> {
  if (getRedisClient()) {
    return await getRefreshSuccessor(oldToken);
  }
  return getRefreshSuccessorMemory(oldToken);
}

/**
 * Records a CSRF token rotation so checkCsrf can grace a legitimate racer
 * (see CSRF_ROTATION_GRACE_SECONDS). No-op when there's no prior token to
 * grace — e.g. the very first CSRF cookie issued at login, or a mistaken
 * call with equal old/new values, has no sibling request that could have
 * cached the old one.
 */
async function storeCsrfSuccessorForToken(oldToken: string | undefined, newToken: string): Promise<void> {
  if (!oldToken || oldToken === newToken) return;
  if (getRedisClient()) {
    await storeCsrfSuccessor(oldToken, newToken, CSRF_ROTATION_GRACE_SECONDS);
  } else {
    storeCsrfSuccessorMemory(oldToken, newToken, CSRF_ROTATION_GRACE_SECONDS * 1000);
  }
}

async function waitForRefreshSuccessor(oldToken: string): Promise<RefreshSuccessor | null> {
  const deadline = Date.now() + REFRESH_SUCCESSOR_WAIT_MAX_MS;
  for (;;) {
    const successor = await getRefreshSuccessorForToken(oldToken);
    if (successor) return successor;
    if (Date.now() >= deadline) return null;
    await new Promise((resolve) => setTimeout(resolve, REFRESH_SUCCESSOR_POLL_INTERVAL_MS));
  }
}

/**
 * Rotates a refresh token into a fresh access+refresh+CSRF triple, or detects
 * genuine reuse and revokes the session. Shared by the "access token expired"
 * and "no access token" branches below.
 *
 * Concurrency: claimRefreshTokenOnce lets exactly one racer rotate. Losing the
 * claim is not itself reuse — a burst of API calls firing as the access token
 * expires is routine in any SPA — so a loser is handed the winner's tokens from
 * the successor store instead. Only a claim loss with no successor appearing
 * within REFRESH_SUCCESSOR_WAIT_MAX_MS is treated as reuse: the token was fully
 * consumed and aged out of the grace window, or never rotated by this process.
 */
async function rotateRefreshToken(
  req: Request,
  res: Response,
  refreshToken: string,
  refreshPayload: JwtPayload,
): Promise<CustomError | null> {
  const claimed = await claimRefreshTokenOnce(refreshToken);
  if (!claimed) {
    const successor = await waitForRefreshSuccessor(refreshToken);
    if (successor) {
      setAccessTokenCookie(res, successor.accessToken);
      res.cookie(REFRESH_TOKEN_COOKIE, successor.refreshToken, {
        ...SECURE_HTTP_ONLY_OPTIONS,
        maxAge: REFRESH_TOKEN_MAX_AGE,
      });
      setCsrfTokenCookie(res, successor.csrfToken);
      logger.info({ userId: refreshPayload.id }, 'Refresh token already rotated by a concurrent request; reused its new tokens');
      return null;
    }

    logger.warn({ userId: refreshPayload.id }, 'Refresh token reuse detected, revoking session');
    const { dbSourceConnection } = await import('../index');
    const dbSources = dbSourceConnection();
    if (dbSources && dbSources.length > 0) {
      await dbSources[0].query('UPDATE vajra_users SET session_version = session_version + 1 WHERE id = $1', [refreshPayload.id]);
    }
    clearAuthCookies(res);
    return new CustomError(401, 'General', 'Session compromised. Please log in again.');
  }

  const isSessionValid = await validateSessionVersion(refreshPayload.id, refreshPayload.session_version, refreshPayload.sessionId);
  if (!isSessionValid) {
    clearAuthCookies(res);
    return new CustomError(401, 'General', 'Session invalidated. Please log in again.');
  }

  const forcePwError = enforceForcePasswordChange(req, refreshPayload);
  if (forcePwError) return forcePwError;

  try {
    const newAccessToken = createAccessToken(refreshPayload);
    const newRefreshToken = createRefreshToken(refreshPayload);
    const newCsrfToken = generateCsrfToken();

    // Publish before setting cookies so a racer that loses the claim right
    // after this point finds the successor as soon as it starts polling.
    await storeRefreshSuccessorForToken(refreshToken, {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      csrfToken: newCsrfToken,
    });
    // Separately grace the CSRF token itself for any request that isn't
    // racing on the refresh token at all — just an ordinary sibling request
    // built with the pre-rotation CSRF header moments before this response
    // rotates the cookie out from under it (see CSRF_ROTATION_GRACE_SECONDS).
    await storeCsrfSuccessorForToken(req.cookies[CSRF_COOKIE_NAME], newCsrfToken);

    setAccessTokenCookie(res, newAccessToken);
    res.cookie(REFRESH_TOKEN_COOKIE, newRefreshToken, {
      ...SECURE_HTTP_ONLY_OPTIONS,
      maxAge: REFRESH_TOKEN_MAX_AGE,
    });
    setCsrfTokenCookie(res, newCsrfToken);
    // Security-relevant state change with no other log line on this path.
    logger.info({ userId: refreshPayload.id }, 'Rotated access and refresh tokens from valid refresh token');
    return null;
  } catch (err) {
    logger.error({ err, userId: refreshPayload.id }, 'Failed to generate renewed access token');
    return new CustomError(500, 'Raw', 'Error generating renewed token', null, err);
  }
}

/**
 * Validates a JWT's session_version against the database. Uses a dynamic import
 * to avoid a circular dependency with index.ts.
 *
 * Fails closed: returns false — and so rejects the request — if the database is
 * unavailable, the query throws, the user row is missing or suspended, the
 * version does not match, or the referenced session is inactive. A database
 * outage therefore 401s every authenticated request rather than admitting them.
 */
export async function validateSessionVersion(userId: number, tokenSessionVersion: number | undefined, tokenSessionId?: number): Promise<boolean> {
  try {
    const { dbSourceConnection } = await import('../index');
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.warn('Cannot validate session_version: DB not available');
      return false; // Fail-closed if DB unavailable
    }
    // Both lookups run on the critical path of every authenticated request, and
    // neither depends on the other's result, so they are issued together to
    // spend one round-trip instead of two. The session row is fetched even when
    // a user-level check would reject first; that is a side-effect-free indexed
    // read, and the rejection checks below still run in order, so the outcome is
    // unchanged.
    const { VajraUser } = await import('../orm/entities/users/Users');
    const userRepo = dbSources[0].getRepository(VajraUser);
    const [user, session] = await Promise.all([
      userRepo.findOne({
        where: { id: userId },
        select: ['id', 'session_version', 'suspended'],
      }),
      tokenSessionId
        ? import('../orm/entities/session/UserSession').then(({ UserSession }) =>
            dbSources[0].getRepository(UserSession).findOne({
              where: { id: tokenSessionId },
              select: ['id', 'isActive'],
            }),
          )
        : Promise.resolve(null),
    ]);
    if (!user) {
      logger.warn({ userId }, 'Session version check failed: user no longer exists');
      return false; // User deleted
    }
    if (user.suspended) {
      logger.warn({ userId }, 'Session version check failed: user is suspended');
      return false;
    }
    if (user.session_version !== (tokenSessionVersion ?? 0)) {
      logger.warn({ userId, tokenSessionVersion, currentSessionVersion: user.session_version }, 'Session version check failed: version mismatch');
      return false;
    }

    // If session is found but inactive, deny
    if (session && !session.isActive) {
      logger.warn({ userId, sessionId: tokenSessionId }, 'Session version check failed: session is inactive');
      return false;
    }

    return true;
  } catch (err) {
    // Log the identifiers: without them a persistent database failure for one
    // user is indistinguishable from any other user's in the logs.
    logger.warn({ err, userId, tokenSessionVersion, tokenSessionId }, 'Session version check failed, rejecting request');
    return false; // Fail-closed on error
  }
}

/**
 * Renews the access and CSRF tokens only when the access token is within
 * TOKEN_RENEWAL_THRESHOLD_SECONDS of expiry. Returns true if it renewed them.
 */
async function tryRenewTokens(
  req: Request,
  res: Response,
  jwtPayload: JwtPayload,
  tokenExp: number | undefined,
): Promise<boolean> {
  if (tokenExp === undefined) return false;
  const now = Math.floor(Date.now() / 1000);
  const timeUntilExpiry = tokenExp - now;
  if (timeUntilExpiry < TOKEN_RENEWAL_THRESHOLD_SECONDS) {
    const newToken = createAccessToken(jwtPayload);
    setAccessTokenCookie(res, newToken);
    const newCsrfToken = generateCsrfToken();
    await storeCsrfSuccessorForToken(req.cookies[CSRF_COOKIE_NAME], newCsrfToken);
    setCsrfTokenCookie(res, newCsrfToken);
    // Otherwise this silently swaps the caller's access and CSRF cookies,
    // leaving reports of re-auth or CSRF mismatch near expiry untraceable.
    logger.info({ userId: jwtPayload.id, timeUntilExpiry }, 'Access token renewed: near expiry threshold');
    return true;
  }
  return false;
}

function clearAuthCookies(res: Response): void {
  res.clearCookie(ACCESS_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
  res.clearCookie(REFRESH_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
  res.clearCookie(CSRF_COOKIE_NAME, CLIENT_READABLE_STRICT_OPTIONS);
}

export const checkAccessJwt = async (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies[ACCESS_TOKEN_COOKIE];

  if (!token) {
    const customError = new CustomError(401, 'General', 'Access token cookie not found. Please log in.');
    return next(customError);
  }

  // Check if token is blacklisted (user logged out)
  if (await checkTokenBlacklist(token)) {
    const customError = new CustomError(401, 'General', 'Token has been blacklisted. Please log in again.');
    return next(customError);
  }

  let jwtPayload: { [key: string]: any };
  try {
    jwtPayload = jwt.verify(token, process.env.ACCESS_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as { [key: string]: any };

    // Reject the interim MFA-challenge token (see isMfaChallengeToken above).
    if (isMfaChallengeToken(jwtPayload)) {
      const customError = new CustomError(401, 'General', 'MFA verification not completed. Please log in again.');
      return next(customError);
    }

    // Save exp before stripping it, for the renewal check below.
    const tokenExp = jwtPayload.exp;
    stripJwtTimingClaims(jwtPayload);
    (req as any).jwtPayload = jwtPayload as JwtPayload;

    // Validate session_version against the database.
    const isSessionValid = await validateSessionVersion(
      jwtPayload.id,
      jwtPayload.session_version,
      jwtPayload.sessionId,
    );
    if (!isSessionValid) {
      clearAuthCookies(res);
      const customError = new CustomError(401, 'General', 'Session invalidated. Please log in again.');
      return next(customError);
    }

    // Enforce force_password_change server-side.
    const forcePwError = enforceForcePasswordChange(req, jwtPayload as JwtPayload);
    if (forcePwError) {
      return next(forcePwError);
    }

    // Only renew if close to expiry.
    try {
      await tryRenewTokens(req, res, jwtPayload as JwtPayload, tokenExp);
    } catch (err) {
      logger.error({ err, userId: jwtPayload.id }, 'Failed to generate renewed access token');
      const customError = new CustomError(500, 'Raw', "Error generating renewed token", null, err);
      return next(customError);
    }

    return next();
  } catch (err) {
    // errorHandler drops the underlying err for 4xx, so expired, tampered,
    // malformed and wrong-algorithm tokens all log identically without this.
    logger.warn({ err }, 'Access token verification failed');
    const customError = new CustomError(401, 'Raw', 'Invalid or expired access token', null, err);
    return next(customError);
  }
};

/**
 * Middleware that attempts to use access token, and if it's expired,
 * tries to renew it using the refresh token. This prevents the redirect loop
 * when access token expires but refresh token is still valid.
 */
export const checkAccessWithRefreshFallback = async (req: Request, res: Response, next: NextFunction) => {
  const accessToken = req.cookies[ACCESS_TOKEN_COOKIE];
  const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE];

  // Check if tokens are blacklisted
  if (accessToken && await checkTokenBlacklist(accessToken)) {
    const customError = new CustomError(401, 'General', 'Access token has been blacklisted. Please log in again.');
    return next(customError);
  }

  if (refreshToken && await checkTokenBlacklist(refreshToken)) {
    const customError = new CustomError(401, 'General', 'Session has been invalidated. Please log in again.');
    return next(customError);
  }

  // Try to verify access token first
  if (accessToken) {
    try {
      const jwtPayload = jwt.verify(accessToken, process.env.ACCESS_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as { [key: string]: any };

      // Reject the interim MFA-challenge token (see isMfaChallengeToken above).
      if (isMfaChallengeToken(jwtPayload)) {
        const customError = new CustomError(401, 'General', 'MFA verification not completed. Please log in again.');
        return next(customError);
      }

      const tokenExp = jwtPayload.exp;
      stripJwtTimingClaims(jwtPayload);
      (req as any).jwtPayload = jwtPayload as JwtPayload;

      // Validate session_version against the database.
      const isSessionValid = await validateSessionVersion(jwtPayload.id, jwtPayload.session_version, jwtPayload.sessionId);
      if (!isSessionValid) {
        clearAuthCookies(res);
        const customError = new CustomError(401, 'General', 'Session invalidated. Please log in again.');
        return next(customError);
      }

      // Enforce force_password_change server-side
      const forcePwError = enforceForcePasswordChange(req, jwtPayload as JwtPayload);
      if (forcePwError) {
        return next(forcePwError);
      }

      // Only renew if close to expiry.
      try {
        await tryRenewTokens(req, res, jwtPayload as JwtPayload, tokenExp);
        return next();
      } catch (err) {
        logger.error({ err, userId: jwtPayload.id }, 'Failed to generate renewed access token');
        const customError = new CustomError(500, 'Raw', "Error generating renewed token", null, err);
        return next(customError);
      }
    } catch (accessErr) {
      // Access token is invalid or expired, try refresh token
      if (!(accessErr instanceof TokenExpiredError)) {
        // errorHandler drops the underlying err for 4xx (see checkAccessJwt).
        logger.warn({ err: accessErr }, 'Access token verification failed (non-expiry)');
        const customError = new CustomError(401, 'Raw', 'Invalid access token', null, accessErr);
        return next(customError);
      }

      // Access token is expired, try to use refresh token
      if (!refreshToken) {
        const customError = new CustomError(401, 'General', 'Refresh token not found. Please log in again.');
        return next(customError);
      }

      try {
        const refreshPayload = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as { [key: string]: any };

        stripJwtTimingClaims(refreshPayload);
        (req as any).jwtPayload = refreshPayload as JwtPayload;

        const rotationError = await rotateRefreshToken(req, res, refreshToken, refreshPayload as JwtPayload);
        if (rotationError) return next(rotationError);
        return next();
      } catch (refreshErr) {
        // This block also covers the session_version UPDATE on the
        // reuse-detected path, so log the err: otherwise a database failure
        // reads in the logs as an ordinary invalid or expired refresh token.
        logger.warn({ err: refreshErr }, 'Refresh token verification or renewal failed');
        const customError = new CustomError(401, 'Raw', 'Refresh token expired or invalid. Please log in again.', null, refreshErr);
        return next(customError);
      }
    }
  } else if (refreshToken) {
    // No access token but refresh token exists
    try {
      const refreshPayload = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as { [key: string]: any };

      stripJwtTimingClaims(refreshPayload);
      (req as any).jwtPayload = refreshPayload as JwtPayload;

      const rotationError = await rotateRefreshToken(req, res, refreshToken, refreshPayload as JwtPayload);
      if (rotationError) return next(rotationError);
      return next();
    } catch (err) {
      // As above: this block also covers the session_version UPDATE on the
      // reuse-detected path, so a database failure would otherwise read as an
      // ordinary invalid or expired refresh token.
      logger.warn({ err }, 'Refresh token verification or renewal failed');
      const customError = new CustomError(401, 'Raw', 'Refresh token expired or invalid. Please log in again.', null, err);
      return next(customError);
    }
  } else {
    const customError = new CustomError(401, 'General', 'No tokens found. Please log in.');
    return next(customError);
  }
};

export const checkRefreshJwt = async (req: Request, _res: Response, next: NextFunction) => {
  const token = req.cookies[REFRESH_TOKEN_COOKIE];

  if (!token) {
    const customError = new CustomError(401, 'General', 'Refresh token cookie not found. Please log in.');
    return next(customError);
  }

  // Check if token is blacklisted
  if (await checkTokenBlacklist(token)) {
    const customError = new CustomError(401, 'General', 'Refresh token has been blacklisted. Please log in again.');
    return next(customError);
  }

  let jwtPayload: { [key: string]: any };
  try {
    jwtPayload = jwt.verify(token, process.env.REFRESH_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as { [key: string]: any };
    (req as any).jwtPayload = jwtPayload as JwtPayload;

  } catch (err) {
    // errorHandler drops the underlying err for 4xx (see checkAccessJwt).
    logger.warn({ err }, 'Refresh token verification failed');
    const customError = new CustomError(401, 'Raw', 'Invalid or expired refresh token', null, err);
    return next(customError);
  }

  return next();
};

/**
 * For registration only: require a valid refresh token only when at least one user exists.
 * When user count is 0 (first user), registration is allowed without a token.
 */
export const requireRefreshJwtIfUsersExist = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../index');
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      const customError = new CustomError(500, 'General', 'Database not available.');
      return next(customError);
    }
    const { VajraUser } = await import('../orm/entities/users/Users');
    const userRepo = dbSources[0].getRepository(VajraUser);
    const userCount = await userRepo.count();

    if (userCount === 0) {
      logger.info('Bootstrap registration: no users exist yet, allowing request without a refresh token');
      return next();
    }

    return checkRefreshJwt(req, res, next);
  } catch (err) {
    logger.error({ err }, 'Failed to check registration eligibility');
    const customError = new CustomError(500, 'Raw', 'Error checking registration eligibility', null, err);
    return next(customError);
  }
};

/**
 * For registration only: allow first-user bootstrap without auth,
 * otherwise require authenticated Super Administrator.
 */
export const requireSuperAdminIfUsersExist = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../index');
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      const customError = new CustomError(500, 'General', 'Database not available.');
      return next(customError);
    }
    const { VajraUser } = await import('../orm/entities/users/Users');
    const userRepo = dbSources[0].getRepository(VajraUser);
    const userCount = await userRepo.count();

    // Bootstrap flow: first user can be created without an authenticated session.
    if (userCount === 0) {
      logger.info('Bootstrap registration: no users exist yet, allowing request without Super Administrator auth');
      return next();
    }

    return checkAccessWithRefreshFallback(req, res, (authErr?: any) => {
      if (authErr) {
        return next(authErr);
      }
      return requireSuperAdmin(req, res, next);
    });
  } catch (err) {
    logger.error({ err }, 'Failed to check registration access');
    const customError = new CustomError(500, 'Raw', 'Error checking registration access', null, err);
    return next(customError);
  }
};

export const checkJwt = checkAccessWithRefreshFallback;