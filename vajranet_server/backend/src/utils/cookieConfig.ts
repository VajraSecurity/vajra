// cookieConfig.ts

// --------------------------------------------------------------------------------------
// COOKIE CONFIGURATION: Reads from environment variables
// --------------------------------------------------------------------------------------
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, CSRF_HEADER_DEFAULT } from '../consts';
import { getLogger } from './logger';

const logger = getLogger('utils.cookieConfig');

export const ACCESS_TOKEN_MAX_AGE = Number(process.env.ACCESS_TOKEN_MAX_AGE_MS);
export const REFRESH_TOKEN_MAX_AGE = Number(process.env.REFRESH_TOKEN_MAX_AGE_MS);
export const CSRF_COOKIE_NAME = String(process.env.CSRF_COOKIE_NAME);
export const CSRF_HEADER_NAME = String(process.env.CSRF_HEADER_NAME || CSRF_HEADER_DEFAULT);

// validateEnv.ts only checks these vars are present (non-empty), not that
// they're actually numeric — a typo'd value (e.g. "3600000ms") would pass
// that check and silently become NaN here, producing a `Set-Cookie` with an
// invalid Max-Age with zero trace anywhere else. Loud warning at module load
// instead, mirroring agentCertProvisioning.ts's parsePositiveNumberEnv
// rationale for why NaN must never propagate silently.
if (Number.isNaN(ACCESS_TOKEN_MAX_AGE)) {
  logger.warn({ raw: process.env.ACCESS_TOKEN_MAX_AGE_MS }, 'ACCESS_TOKEN_MAX_AGE_MS is not a valid number, access token cookie maxAge will be invalid');
}
if (Number.isNaN(REFRESH_TOKEN_MAX_AGE)) {
  logger.warn({ raw: process.env.REFRESH_TOKEN_MAX_AGE_MS }, 'REFRESH_TOKEN_MAX_AGE_MS is not a valid number, refresh token cookie maxAge will be invalid');
}

export { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE };
// --------------------------------------------------------------------------------------

// Standard secure options with Lax SameSite (for most regular requests)
export const SECURE_HTTP_ONLY_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production', 
  sameSite: 'lax' as const, 
};

// Client-readable options with Lax SameSite
export const CLIENT_READABLE_OPTIONS = {
  httpOnly: false, 
  secure: process.env.NODE_ENV === 'production', 
  sameSite: 'lax' as const,
};

// Strict options for security-critical operations (login, password change, logout)
// Strict SameSite prevents cross-site cookie inclusion entirely
export const SECURE_HTTP_ONLY_STRICT_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/',
};

export const CLIENT_READABLE_STRICT_OPTIONS = {
  httpOnly: false,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/',
};