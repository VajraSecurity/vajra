import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { getRedisClient } from '../utils/redisClient';
import { getLogger } from '../utils/logger';
import { normalizeEmail } from '../utils/sanitization';
import { verifyMfaToken } from '../utils/createJwtToken';
import {
  RATE_LIMIT_WINDOW_MS_15MIN,
  RATE_LIMIT_WINDOW_MS_1MIN,
  RATE_LIMIT_MAX_LOGIN,
  RATE_LIMIT_MAX_LOGIN_EMAIL,
  RATE_LIMIT_MAX_PASSWORD_UPDATE,
  RATE_LIMIT_MAX_PROFILE_UPDATE,
  RATE_LIMIT_MAX_SESSION_STATUS,
  RATE_LIMIT_MAX_API_DATA,
  RATE_LIMIT_MAX_API_EXPORT,
  RATE_LIMIT_MAX_API_MUTATION,
  RATE_LIMIT_MAX_GRAFANA_VALIDATE,
} from '../consts';

import type { Request } from 'express';

const logger = getLogger('middleware.rateLimiters');

const getUserIdFromJwtPayload = (req: Request): number | null => {
  const payload = (req as any).jwtPayload as { id?: unknown } | undefined;
  const id = payload?.id;
  return typeof id === 'number' ? id : null;
};

const userIdOrIpKeyGenerator = (req: Request) => {
  const userId = getUserIdFromJwtPayload(req);
  if (userId != null) return `uid:${userId}`;
  // express-rate-limit needs ipKeyGenerator for safe IPv6 handling.
  return ipKeyGenerator(req.ip ?? '0.0.0.0');
};

const emailOrIpKeyGenerator = (req: Request) => {
  const rawEmail = (req.body as any)?.email;
  const email = typeof rawEmail === 'string' ? normalizeEmail(rawEmail) : '';
  return email ? `email:${email}` : ipKeyGenerator(req.ip ?? '0.0.0.0');
};

// /mfa/verify and /mfa/recover carry an mfaToken (issued after the
// password-only login step), never an `email` body field — so
// emailOrIpKeyGenerator always fell through to IP-only there, silently
// degrading their per-account limiter into a duplicate of the IP limiter
// (no protection against a distributed attacker spreading requests across
// many IPs against one account's TOTP code / recovery code). Decode the
// mfaToken (same verification the controller itself does) to key by the
// account it identifies instead.
const mfaTokenOrIpKeyGenerator = (req: Request) => {
  const rawToken = (req.body as any)?.mfaToken;
  if (typeof rawToken === 'string' && rawToken) {
    try {
      const decoded = verifyMfaToken(rawToken);
      if (decoded?.id != null) return `uid:${decoded.id}`;
    } catch {
      // Invalid/expired mfaToken — fall through to IP; the controller will
      // reject the request on its own merits.
    }
  }
  return ipKeyGenerator(req.ip ?? '0.0.0.0');
};

/**
 * `prefix` is not cosmetic: it is the only thing that keeps these limiters apart
 * in Redis. rate-limit-redis derives a key as `store.prefix + keyGenerator(req)`
 * and nothing else — windowMs and max never enter it — so every limiter sharing
 * `userIdOrIpKeyGenerator` would otherwise collapse onto one key per user under
 * the default 'rl:' prefix. With RedisStore's `resetExpiryOnChange` defaulting
 * to false, whichever limiter touched that key first would also fix the TTL for
 * all of them, so a 60-second /auth/status poll could shrink a 15-minute
 * mutation window, and ordinary list reads could exhaust profileUpdate's budget.
 *
 * The prefixes are inert today: this factory runs at module load, during
 * `import routes from './routes/api'` in src/index.ts, which happens before
 * `initializeRedis()`. getRedisClient() therefore returns null, no RedisStore is
 * built, and each limiter uses its own private MemoryStore, which cannot
 * collide. They are here so that repairing the store wiring — a lazy store, or
 * awaiting Redis before importing routes — does not silently make the limiters
 * rewrite each other's windows. Keep the prefixes; that wiring repair also moves
 * limits from per-process to fleet-shared and needs its own sign-off.
 */
const storeConfig = (prefix: string) => {
  const client = getRedisClient();
  if (client) {
    return new RedisStore({
      prefix,
      sendCommand: (...args: string[]) => client.sendCommand(args),
    });
  }
  // prefix goes in the log record, not the message text — the message string is
  // left byte-identical for anything grepping these ten lines, while the field
  // makes the ten otherwise indistinguishable per-boot warnings attributable to
  // a specific limiter.
  logger.warn({ prefix }, 'Redis unavailable, rate limiter falling back to in-process memory store');
  return undefined; // Fallback to memory store if Redis is unavailable
};

/**
 * Logs every time a client actually gets rate-limited, then reproduces
 * express-rate-limit's own default `handler` behavior exactly (status +
 * message body) so the response sent to the client is unchanged. Without
 * this, a blocked client (e.g. a login brute-force attempt) leaves zero
 * trace in the logs — the request simply never reaches any other middleware
 * or route logger.
 */
const rateLimitExceededHandler = (limiterName: string) =>
  async (req: Request, res: any, _next: any, options: any) => {
    let key: string | undefined;
    try {
      key = await options.keyGenerator(req, res);
    } catch (keyErr) {
      logger.warn({ err: keyErr, limiter: limiterName, path: req.originalUrl }, 'Rate limit key generation failed, logging exceeded event without key');
      key = undefined;
    }
    logger.warn({ limiter: limiterName, key, path: req.originalUrl }, 'Rate limit exceeded');
    res.status(options.statusCode);
    const message = typeof options.message === 'function' ? await options.message(req, res) : options.message;
    if (!res.writableEnded) res.send(message);
  };

/** Login brute-force protection: limit by IP + by normalized email. */
export const loginIpLimiter = rateLimit({
  store: storeConfig('rl:login-ip:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_LOGIN,
  keyGenerator: (req) => ipKeyGenerator(req.ip ?? '0.0.0.0'),
  skipSuccessfulRequests: true,
  handler: rateLimitExceededHandler('loginIp'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many login attempts from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const loginEmailLimiter = rateLimit({
  store: storeConfig('rl:login-email:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_LOGIN_EMAIL,
  keyGenerator: emailOrIpKeyGenerator,
  skipSuccessfulRequests: true,
  handler: rateLimitExceededHandler('loginEmail'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many login attempts for this account, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Per-account brute-force protection for /mfa/verify and /mfa/recover, keyed off the decoded mfaToken's user id instead of a body `email` field these routes never send. */
export const mfaAccountLimiter = rateLimit({
  store: storeConfig('rl:mfa-account:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_LOGIN_EMAIL,
  keyGenerator: mfaTokenOrIpKeyGenerator,
  skipSuccessfulRequests: true,
  handler: rateLimitExceededHandler('mfaAccount'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many attempts for this account, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const passwordUpdateLimiter = rateLimit({
  store: storeConfig('rl:password-update:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_PASSWORD_UPDATE,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('passwordUpdate'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many password update attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const profileUpdateLimiter = rateLimit({
  store: storeConfig('rl:profile-update:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_PROFILE_UPDATE,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('profileUpdate'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many profile update attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const sessionStatusLimiter = rateLimit({
  store: storeConfig('rl:session-status:'),
  windowMs: RATE_LIMIT_WINDOW_MS_1MIN,
  max: RATE_LIMIT_MAX_SESSION_STATUS,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('sessionStatus'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many session status checks, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for general data-read API endpoints (nodes list, alerts list, graphs, etc.) */
export const apiDataLimiter = rateLimit({
  store: storeConfig('rl:api-data:'),
  windowMs: RATE_LIMIT_WINDOW_MS_1MIN,
  max: RATE_LIMIT_MAX_API_DATA,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('apiData'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for heavy export endpoints (alert export) */
export const apiExportLimiter = rateLimit({
  store: storeConfig('rl:api-export:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_API_EXPORT,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('apiExport'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many export requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for /api/auth/validate — the nginx auth_request gate in front of embedded Grafana */
export const grafanaValidateLimiter = rateLimit({
  store: storeConfig('rl:grafana-validate:'),
  windowMs: RATE_LIMIT_WINDOW_MS_1MIN,
  max: RATE_LIMIT_MAX_GRAFANA_VALIDATE,
  keyGenerator: (req) => ipKeyGenerator(req.ip ?? '0.0.0.0'),
  handler: rateLimitExceededHandler('grafanaValidate'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for mutation endpoints (update, rename) */
export const apiMutationLimiter = rateLimit({
  store: storeConfig('rl:api-mutation:'),
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_API_MUTATION,
  keyGenerator: userIdOrIpKeyGenerator,
  handler: rateLimitExceededHandler('apiMutation'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many update requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
