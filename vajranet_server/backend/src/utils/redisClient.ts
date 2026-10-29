import { createClient, RedisClientType } from 'redis';
import { createHash } from 'crypto';
import {
  REDIS_DEFAULT_HOST,
  REDIS_DEFAULT_PORT,
  REDIS_KEY_PREFIX_CAPTCHA,
  REDIS_KEY_PREFIX_LOGIN_ATTEMPTS,
  REDIS_KEY_PREFIX_BLACKLIST,
  REDIS_KEY_PREFIX_SHELL_TOKEN,
  REDIS_KEY_PREFIX_REFRESH_SUCCESSOR,
  REDIS_KEY_PREFIX_TOTP_CLAIM,
  REDIS_KEY_PREFIX_CSRF_SUCCESSOR,
  REDIS_RECONNECT_MULTIPLIER,
  REDIS_RECONNECT_CAP_MS,
  REDIS_CONNECT_TIMEOUT_MS,
  REDIS_BACKGROUND_RETRY_INTERVAL_MS,
  BLACKLIST_LEGACY_KEY_SUNSET,
  LOGIN_FAILED_ATTEMPTS_EXPIRY_SECONDS,
  TOTP_CODE_CLAIM_TTL_SECONDS,
} from '../consts';
import { getLogger } from './logger';
import { claimTokenOnceMemory } from './memoryStore';

const logger = getLogger('utils.redisClient');

let redisClient: RedisClientType | null = null;
// Background self-healing retry loop, started only once the initial connect
// attempt (below) gives up. Cleared as soon as a connect succeeds (from
// either the initial attempt or a background retry) or on disconnectRedis,
// so at most one retry loop is ever live.
let backgroundRetryTimer: ReturnType<typeof setInterval> | null = null;

/**
 * One connect attempt: creates a fresh client and tries to connect, bounded
 * by REDIS_CONNECT_TIMEOUT_MS of total wall-clock retrying (not a fixed
 * attempt count) — reconnectStrategy keeps retrying at a capped backoff
 * until that deadline passes, then gives up so connect() rejects and the
 * caller falls back to in-memory storage instead of hanging.
 *
 * The "has this attempt ever connected" flag gating that deadline is LOCAL
 * to this one client instance, not module state: a module-level flag would
 * stay stuck `true` after any earlier successful session, which could make a
 * later, independent connect attempt's reconnectStrategy never give up on a
 * dead Redis — hanging indefinitely instead of falling back.
 */
async function connectOnce(): Promise<boolean> {
  try {
    const REDIS_HOST = process.env.REDIS_HOST || REDIS_DEFAULT_HOST;
    const REDIS_PORT = Number(process.env.REDIS_PORT) || REDIS_DEFAULT_PORT;

    const connectDeadline = Date.now() + REDIS_CONNECT_TIMEOUT_MS;
    let connectedOnce = false;

    const client: RedisClientType = createClient({
      socket: {
        host: REDIS_HOST,
        port: REDIS_PORT,
        // Per-attempt TCP timeout (belt-and-suspenders alongside the
        // deadline-based reconnectStrategy below — irrelevant for the common
        // fast-failing ECONNREFUSED case, but bounds a connect that instead
        // stalls, e.g. against a host that silently drops packets).
        connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
        // reconnectStrategy MUST be able to give up (return false) during the
        // INITIAL connect — if it always returns a delay, connect() never
        // rejects when Redis is unreachable and the catch-based in-memory
        // fallback below becomes unreachable, hanging server startup. Give up
        // once REDIS_CONNECT_TIMEOUT_MS of wall-clock time has passed without
        // a successful connect, so this attempt gets the full documented
        // grace period regardless of how quickly each individual retry fails
        // (bounding by retry count instead would give up in well under the
        // grace period, since a refused connection fails near-instantly).
        // After a first success, retry indefinitely to survive outages.
        reconnectStrategy: (retries: number) =>
          !connectedOnce && Date.now() >= connectDeadline
            ? false
            : Math.min(retries * REDIS_RECONNECT_MULTIPLIER, REDIS_RECONNECT_CAP_MS),
      },
      ...(process.env.REDIS_PASSWORD ? { password: process.env.REDIS_PASSWORD } : {}),
    });

    client.on('error', (err) => {
      logger.error({ err }, 'Redis client error');
    });
    // reconnectStrategy above retries silently on its own — without these,
    // an outage/recovery after the initial connect leaves no trace beyond
    // per-operation errors from individual commands issued while down, and
    // no signal at all when it comes back (callers just stop erroring).
    let hasConnectedOnce = false;
    client.on('reconnecting', () => {
      logger.warn('Redis client reconnecting after connection loss');
    });
    client.on('ready', () => {
      if (hasConnectedOnce) {
        logger.info('Redis client reconnected and ready');
      }
    });
    client.on('end', () => {
      logger.warn('Redis client connection closed');
    });

    await client.connect();
    connectedOnce = true;
    hasConnectedOnce = true;
    redisClient = client;
    clearBackgroundRetry();
    logger.info('Redis connected successfully');
    return true;
  } catch (err) {
    logger.warn({ err }, 'Redis connection failed, using fallback in-memory storage');
    redisClient = null;
    return false;
  }
}

/**
 * Initialize Redis client connection. Falls back gracefully to in-memory
 * storage if Redis isn't reachable within REDIS_CONNECT_TIMEOUT_MS, then
 * keeps quietly retrying every REDIS_BACKGROUND_RETRY_INTERVAL_MS in the
 * background — self-healing off in-memory fallback if Redis was merely slow
 * to start (routine in orchestrated deployments where dependent containers
 * start concurrently without health-gated ordering) rather than staying
 * stuck on in-memory session/rate-limit/captcha state for the rest of the
 * process's life.
 */
export const initializeRedis = async (): Promise<boolean> => {
  const connected = await connectOnce();
  if (!connected) scheduleBackgroundRetry();
  return connected;
};

function scheduleBackgroundRetry(): void {
  if (backgroundRetryTimer) return; // a retry loop is already live
  backgroundRetryTimer = setInterval(async () => {
    if (redisClient) {
      // Connected via some other path meanwhile (shouldn't normally happen
      // since this is the only retry source, but guards against races).
      clearBackgroundRetry();
      return;
    }
    logger.debug('Retrying Redis connection...');
    await connectOnce();
  }, REDIS_BACKGROUND_RETRY_INTERVAL_MS);
  // Never let this background timer alone keep the process alive.
  backgroundRetryTimer.unref?.();
}

function clearBackgroundRetry(): void {
  if (backgroundRetryTimer) {
    clearInterval(backgroundRetryTimer);
    backgroundRetryTimer = null;
  }
}

/**
 * Get Redis client instance
 */
export const getRedisClient = (): RedisClientType | null => {
  return redisClient;
};

/**
 * Hash captcha text for secure storage (prevents plain text exposure)
 */
const hashCaptchaText = (text: string): string => {
  return createHash('sha256').update(text.toLowerCase()).digest('hex');
};

/**
 * Store captcha with expiry (stores hash instead of plain text for security)
 */
export const storeCaptcha = async (id: string, text: string, expiryMs: number): Promise<void> => {
  if (!redisClient) return;
  try {
    const hashedText = hashCaptchaText(text);
    await redisClient.setEx(
      `${REDIS_KEY_PREFIX_CAPTCHA}${id}`,
      Math.ceil(expiryMs / 1000),
      hashedText
    );
  } catch (err) {
    logger.error({ err }, 'Error storing captcha in Redis');
  }
};

/**
 * Verify and delete captcha (compares hash instead of plain text)
 */
export const verifyCaptcha = async (id: string, input: string): Promise<boolean> => {
  if (!redisClient) return false;
  try {
    const storedHash = await redisClient.get(`${REDIS_KEY_PREFIX_CAPTCHA}${id}`);
    if (!storedHash) return false;
    
    const inputHash = hashCaptchaText(input);
    const isMatch = storedHash === inputHash;
    
    // Delete after verification attempt (successful or not)
    await redisClient.del(`${REDIS_KEY_PREFIX_CAPTCHA}${id}`);
    return isMatch;
  } catch (err) {
    logger.error({ err }, 'Error verifying captcha in Redis');
    return false;
  }
};

/**
 * Get failed login attempts
 */
export const getFailedAttempts = async (email: string): Promise<number> => {
  if (!redisClient) return 0;
  try {
    const attempts = await redisClient.get(`${REDIS_KEY_PREFIX_LOGIN_ATTEMPTS}${email}`);
    return attempts ? Number(attempts) : 0;
  } catch (err) {
    logger.error({ err }, 'Error getting failed attempts from Redis');
    return 0;
  }
};

/**
 * Increment failed login attempts with 1-hour expiry
 */
export const incrementFailedAttempts = async (email: string): Promise<number> => {
  if (!redisClient) return 0;
  try {
    const key = `${REDIS_KEY_PREFIX_LOGIN_ATTEMPTS}${email}`;
    const current = await redisClient.get(key);
    const newCount = (current ? Number(current) : 0) + 1;
    await redisClient.setEx(key, LOGIN_FAILED_ATTEMPTS_EXPIRY_SECONDS, newCount.toString());
    return newCount;
  } catch (err) {
    logger.error({ err }, 'Error incrementing failed attempts in Redis');
    return 0;
  }
};

/**
 * Clear failed login attempts
 */
export const clearFailedAttempts = async (email: string): Promise<void> => {
  if (!redisClient) return;
  try {
    await redisClient.del(`${REDIS_KEY_PREFIX_LOGIN_ATTEMPTS}${email}`);
  } catch (err) {
    logger.error({ err }, 'Error clearing failed attempts in Redis');
  }
};

/**
 * Redis key for a token's blacklist entry: `blacklist:` + the first 32 hex
 * chars (128 bits) of the token's SHA-256.
 *
 * The digest, not the token itself: isTokenBlacklisted() runs on essentially
 * every authenticated request, and keying on the raw JWT puts a ~380-byte key
 * name on the wire each time, for a stored value of the single byte '1'. The
 * digest key is ~42 bytes.
 *
 * Security argument for the truncation. This value is a lookup key, never an
 * authenticator: the JWT's signature is verified by jsonwebtoken before any
 * caller reaches this function, so a digest collision cannot authenticate
 * anything. The only reachable effect of a collision is a FALSE positive —
 * treating a live token as revoked — which fails closed (a spurious
 * re-login), never open. 128 bits needs ~2^64 distinct tokens for an even
 * chance of any collision, against blacklist populations orders of magnitude
 * smaller than that. Secondary benefit:
 * complete (if already-revoked) JWTs stop sitting in plaintext Redis key
 * names, where any `redis-cli --scan` or RDB dump reads them back out.
 */
const blacklistKeyFor = (token: string): string =>
  `${REDIS_KEY_PREFIX_BLACKLIST}${createHash('sha256').update(token).digest('hex').slice(0, 32)}`;

/**
 * MIGRATION ONLY — the pre-digest key shape. Every blacklist write also lands
 * here and every blacklist read falls back to here until
 * BLACKLIST_LEGACY_KEY_SUNSET (consts/redis.ts), so that (a) tokens revoked by
 * the previous build stay revoked across the cutover instead of being silently
 * un-revoked, and (b) a rollback to the previous build still sees tokens
 * revoked by this one. Delete this function and its three call sites on that
 * date; the wire-byte saving described above only lands once it is gone.
 */
const legacyBlacklistKeyFor = (token: string): string => {
  // Called from the key builder rather than from each of the three call sites so
  // no future legacy-branch caller can be added without the check coming with it.
  warnIfLegacyKeysExpired();
  return `${REDIS_KEY_PREFIX_BLACKLIST}${token}`;
};

/**
 * Makes BLACKLIST_LEGACY_KEY_SUNSET enforce itself instead of being a date in a
 * comment that nobody is paged about. The dual-write/dual-read exists for one
 * max-token-lifetime window; past that it is pure cost — every blacklist lookup
 * still puts the full JWT on the wire, which is the exact thing the digest key
 * shape was introduced to stop.
 *
 * Warns rather than throws: the legacy branch stays correct after the date, just
 * pointless, so failing a boot (or a logout) over it would turn a cleanup
 * reminder into an outage. Logged once per process, on first use, so it surfaces
 * in normal operation without one line per blacklist call.
 */
let legacySunsetWarned = false;
const warnIfLegacyKeysExpired = (): void => {
  if (legacySunsetWarned) return;
  // Date-only compare: BLACKLIST_LEGACY_KEY_SUNSET is 'YYYY-MM-DD', which sorts
  // lexicographically, so no parsing or timezone handling is needed.
  if (new Date().toISOString().slice(0, 10) < BLACKLIST_LEGACY_KEY_SUNSET) return;
  legacySunsetWarned = true;
  logger.warn(
    { sunset: BLACKLIST_LEGACY_KEY_SUNSET },
    'Blacklist legacy key shape is past its sunset date — delete legacyBlacklistKeyFor and its three call sites; until then every blacklist lookup still sends the full JWT',
  );
};

/**
 * Add token to blacklist (for logout)
 */
export const blacklistToken = async (token: string, expirySeconds: number): Promise<void> => {
  if (!redisClient) return;
  try {
    // Dual-write for the migration window (see legacyBlacklistKeyFor). Both
    // SETs are issued before either is awaited so node-redis pipelines them
    // into one round trip rather than two. Logout is a per-session event, not
    // a per-request one, so the doubled write volume here is immaterial next
    // to the per-request read saving this migration buys.
    await Promise.all([
      redisClient.setEx(blacklistKeyFor(token), expirySeconds, '1'),
      redisClient.setEx(legacyBlacklistKeyFor(token), expirySeconds, '1'),
    ]);
  } catch (err) {
    logger.error({ err }, 'Error adding token to blacklist');
  }
};

/**
 * Check if token is blacklisted
 */
export const isTokenBlacklisted = async (token: string): Promise<boolean> => {
  if (!redisClient) return false;
  try {
    // Dual-read for the migration window (see legacyBlacklistKeyFor). One MGET
    // rather than two sequential GETs keeps this at one round trip, and is also
    // tighter than get-then-get: no concurrent write can land between the reads.
    const [digestHit, legacyHit] = await redisClient.mGet([
      blacklistKeyFor(token),
      legacyBlacklistKeyFor(token),
    ]);
    return !!digestHit || !!legacyHit;
  } catch (err) {
    logger.error({ err }, 'Error checking token blacklist');
    return false;
  }
};

/**
 * Atomically claim a (refresh) token for single use: blacklists it and reports
 * whether this call was the one that actually set it. Two concurrent requests
 * racing with the same stolen/replayed refresh token must not both observe
 * "not yet blacklisted" — a separate isTokenBlacklisted() check followed by a
 * later blacklistToken() call has exactly that gap. SET ... NX is atomic in
 * Redis, so only one caller ever gets `true` for a given token.
 */
export const claimTokenOnce = async (token: string, expirySeconds: number): Promise<boolean> => {
  if (!redisClient) return true;
  try {
    const digestKey = blacklistKeyFor(token);
    const legacyKey = legacyBlacklistKeyFor(token);
    // Writes into the same namespace isTokenBlacklisted reads — a claimed
    // refresh token is a blacklisted one — so this must use the digest key in
    // lockstep with the two functions above. On the legacy key shape, a consumed
    // refresh token would stop reading back as blacklisted the moment the legacy
    // read is removed at BLACKLIST_LEGACY_KEY_SUNSET.
    //
    // The two commands are pipelined. Atomicity is unaffected: SET NX on the
    // digest key remains the sole arbiter, so exactly one of N concurrent
    // replays gets `true`. The legacy GET can only downgrade a would-be winner
    // to `false`, never promote a loser, so it opens no replay window.
    const [claimedDigest, legacyAlreadyClaimed] = await Promise.all([
      redisClient.set(digestKey, '1', { NX: true, expiration: { type: 'EX', value: expirySeconds } }),
      redisClient.get(legacyKey),
    ]);
    const claimed = claimedDigest !== null && legacyAlreadyClaimed === null;
    // Dual-write for the migration window (see legacyBlacklistKeyFor): without
    // it, rolling back to the previous build would make every refresh token
    // consumed under this build claimable a second time.
    if (claimed) await redisClient.setEx(legacyKey, expirySeconds, '1');
    return claimed;
  } catch (err) {
    // Matches this file's existing fail-open convention (see isTokenBlacklisted
    // above) — a Redis error here should not itself lock a legitimate user out.
    logger.error({ err }, 'Error claiming token');
    return true;
  }
};

/**
 * Atomically claim a successfully-verified TOTP code as "used" for a given
 * user, for TOTP_CODE_CLAIM_TTL_SECONDS. Every verifyTotpCode() call
 * site in the codebase should call this immediately after a code passes
 * verification and reject the request if it returns false — without it, a
 * single code (with MFA_TOTP_VERIFICATION_WINDOW=1) stays valid for up to
 * ~90s and is fully replayable in that window, including across different
 * endpoints (the same code could authorize login, a patch-apply step-up, an
 * agent-release signing, etc.). Composes Redis + in-memory fallback
 * internally (unlike claimTokenOnce/claimTokenOnceMemory above, which
 * callers branch on getRedisClient() themselves) so every call site is a
 * single `await claimTotpCodeOnce(...)` regardless of Redis availability.
 */
export const claimTotpCodeOnce = async (userId: number | string, code: string): Promise<boolean> => {
  const key = `${userId}:${code}`;
  if (!redisClient) return claimTokenOnceMemory(key, TOTP_CODE_CLAIM_TTL_SECONDS * 1000);
  try {
    const result = await redisClient.set(`${REDIS_KEY_PREFIX_TOTP_CLAIM}${key}`, '1', {
      NX: true,
      expiration: { type: 'EX', value: TOTP_CODE_CLAIM_TTL_SECONDS },
    });
    // Matches claimTokenOnce's fail-open convention above — a Redis error
    // here should not itself lock a legitimate user out.
    return result !== null;
  } catch (err) {
    logger.error({ err }, 'Error claiming TOTP code');
    return true;
  }
};

export interface RefreshSuccessor {
  accessToken: string;
  refreshToken: string;
  csrfToken: string;
}

/**
 * Records the new token triple minted when a refresh token is rotated, keyed
 * by the OLD (just-consumed) token, for a short grace window. When several
 * requests race on the same refresh token (e.g. an idle SPA firing multiple
 * API calls right after the access token expires), exactly one wins
 * claimTokenOnce() and rotates; every other racer is a legitimate concurrent
 * request, not a replay attack — it should be handed the same new tokens the
 * winner minted, not treated as a compromised session. See
 * middleware/checkJwt.ts's rotation branches for the read side.
 */
export const storeRefreshSuccessor = async (
  oldToken: string,
  successor: RefreshSuccessor,
  graceSeconds: number,
): Promise<void> => {
  if (!redisClient) return;
  try {
    await redisClient.setEx(`${REDIS_KEY_PREFIX_REFRESH_SUCCESSOR}${oldToken}`, graceSeconds, JSON.stringify(successor));
  } catch (err) {
    logger.error({ err }, 'Error storing refresh token successor');
  }
};

export const getRefreshSuccessor = async (oldToken: string): Promise<RefreshSuccessor | null> => {
  if (!redisClient) return null;
  try {
    const raw = await redisClient.get(`${REDIS_KEY_PREFIX_REFRESH_SUCCESSOR}${oldToken}`);
    return raw ? (JSON.parse(raw) as RefreshSuccessor) : null;
  } catch (err) {
    logger.error({ err }, 'Error reading refresh token successor');
    return null;
  }
};

/**
 * Records the freshly-rotated CSRF token, keyed by the OLD (just-replaced)
 * token, for a short grace window. Browsers attach a request's `Cookie:`
 * header at actual network-dispatch time, not when the request object was
 * built — under connection-limited queuing (e.g. a burst of Windows
 * hardware-info calls firing together for one node view), a request can be
 * built with its CSRF header read from document.cookie BEFORE a concurrent
 * request's response silently rotates the cookie (see checkJwt.ts
 * tryRenewTokens / rotateRefreshToken), but not actually dispatched until
 * AFTER — so it arrives with the fresh cookie but the stale header. Without
 * this, checkCsrf rejects that as a mismatch even though both requests were
 * legitimate. See middleware/checkCSRFToken.ts for the read side.
 */
export const storeCsrfSuccessor = async (
  oldToken: string,
  newToken: string,
  graceSeconds: number,
): Promise<void> => {
  if (!redisClient) return;
  try {
    await redisClient.setEx(`${REDIS_KEY_PREFIX_CSRF_SUCCESSOR}${oldToken}`, graceSeconds, newToken);
  } catch (err) {
    logger.error({ err }, 'Error storing CSRF token successor');
  }
};

export const getCsrfSuccessor = async (oldToken: string): Promise<string | null> => {
  if (!redisClient) return null;
  try {
    return await redisClient.get(`${REDIS_KEY_PREFIX_CSRF_SUCCESSOR}${oldToken}`);
  } catch (err) {
    logger.error({ err }, 'Error reading CSRF token successor');
    return null;
  }
};

/**
 * Store single-use shell token in Redis
 */
export const storeShellToken = async (token: string, userId: string, expirySeconds: number): Promise<void> => {
  if (!redisClient) return;
  try {
    await redisClient.setEx(`${REDIS_KEY_PREFIX_SHELL_TOKEN}${token}`, expirySeconds, userId);
  } catch (err) {
    logger.error({ err }, 'Error storing shell token in Redis');
  }
};

/**
 * Verify and consume single-use shell token in Redis
 */
export const verifyShellToken = async (token: string, userId: string): Promise<boolean> => {
  if (!redisClient) return false;
  try {
    const key = `${REDIS_KEY_PREFIX_SHELL_TOKEN}${token}`;
    // getDel (atomic GET+DEL in one round trip) instead of get() then del() —
    // the previous get-then-delete had a race window where two concurrent
    // requests presenting the same token could both read it before either
    // deleted it, both passing the "single use" check and opening two
    // terminal sessions from one token.
    const storedUserId = await redisClient.getDel(key);

    if (!storedUserId) return false;

    return storedUserId === userId;
  } catch (err) {
    logger.error({ err }, 'Error verifying shell token in Redis');
    return false;
  }
};

/**
 * Disconnect Redis client
 */
export const disconnectRedis = async (): Promise<void> => {
  clearBackgroundRetry();
  if (redisClient) {
    try {
      await redisClient.quit();
      redisClient = null;
      logger.info('Redis disconnected');
    } catch (err) {
      logger.error({ err }, 'Error disconnecting Redis');
    }
  }
};
