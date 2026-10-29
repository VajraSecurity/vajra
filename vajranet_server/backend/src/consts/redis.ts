/** Redis literal constants: defaults, key prefixes, timeouts (no env). */

export const REDIS_DEFAULT_HOST = 'localhost';
export const REDIS_DEFAULT_PORT = 6379;

export const REDIS_KEY_PREFIX_CAPTCHA = 'captcha:';
export const REDIS_KEY_PREFIX_LOGIN_ATTEMPTS = 'login:attempts:';
export const REDIS_KEY_PREFIX_BLACKLIST = 'blacklist:';
export const REDIS_KEY_PREFIX_SHELL_TOKEN = 'ws:shell:token:';
export const REDIS_KEY_PREFIX_REFRESH_SUCCESSOR = 'refresh:successor:';
export const REDIS_KEY_PREFIX_TOTP_CLAIM = 'totp:claim:';
export const REDIS_KEY_PREFIX_CSRF_SUCCESSOR = 'csrf:successor:';

export const REDIS_RECONNECT_MULTIPLIER = 50;
export const REDIS_RECONNECT_CAP_MS = 500;

/** Max initial-connect time before giving up and using in-memory fallback. */
export const REDIS_CONNECT_TIMEOUT_MS = 3000;
/** How often to retry connecting in the background after the initial connect
 *  gave up, so a Redis that was merely slow to start (not actually down)
 *  self-heals off in-memory fallback without requiring a process restart. */
export const REDIS_BACKGROUND_RETRY_INTERVAL_MS = 30000;

/** Failed login attempts key expiry in seconds (1 hour). */
export const LOGIN_FAILED_ATTEMPTS_EXPIRY_SECONDS = 3600;

/** Failed login attempts key expiry in milliseconds (1 hour) — mirrors LOGIN_FAILED_ATTEMPTS_EXPIRY_SECONDS for in-memory store. */
export const LOGIN_FAILED_ATTEMPTS_EXPIRY_MS = LOGIN_FAILED_ATTEMPTS_EXPIRY_SECONDS * 1000;

/**
 * Blacklist keys are keyed on a truncated SHA-256 of the token, not on the
 * token itself (see utils/redisClient.ts blacklistKeyFor). The legacy
 * full-JWT key shape is still dual-written and dual-read for one full
 * max-token-lifetime window so that tokens revoked by the PREVIOUS build stay
 * revoked across the cutover — a straight switch would orphan every live
 * `blacklist:<jwt>` entry and silently un-revoke every logout that happened
 * in the preceding 7 days.
 *
 * The window is one BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS (604800s = 7 days,
 * consts/auth.ts) — the longest TTL any blacklist entry is ever written with,
 * so after it elapses no legacy-shaped key can still be live.
 *
 * Sunset: on or after this date, delete the legacy branch in blacklistToken,
 * isTokenBlacklisted and claimTokenOnce, and this constant with them. Until the
 * legacy read is gone, every blacklist lookup still puts the full JWT on the
 * wire, so none of the intended saving lands.
 */
export const BLACKLIST_LEGACY_KEY_SUNSET = '2026-09-14';
