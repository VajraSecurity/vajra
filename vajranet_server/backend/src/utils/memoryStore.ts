/**
 * In-memory fallback stores for when Redis is unavailable
 * These maintain existing functionality but without distributed support
 */

import { createHash } from 'crypto';
import { LOGIN_FAILED_ATTEMPTS_EXPIRY_MS } from '../consts';

const failedAttemptsStore: Map<string, { count: number; expiry: NodeJS.Timeout }> = new Map();
const captchaStore: Map<string, { hash: string; expiry: NodeJS.Timeout }> = new Map();
const tokenBlacklistStore: Map<string, NodeJS.Timeout> = new Map();
const shellTokenStore: Map<string, { userId: string; expiry: NodeJS.Timeout }> = new Map();
const refreshSuccessorStore: Map<string, { accessToken: string; refreshToken: string; csrfToken: string; expiry: NodeJS.Timeout }> = new Map();
const csrfSuccessorStore: Map<string, { newToken: string; expiry: NodeJS.Timeout }> = new Map();

/**
 * Hash captcha text for secure storage (prevents plain text exposure)
 */
const hashCaptchaText = (text: string): string => {
  return createHash('sha256').update(text.toLowerCase()).digest('hex');
};

/** Expiry for failed attempts entries (matches Redis TTL). */
const FAILED_ATTEMPTS_EXPIRY_MS = LOGIN_FAILED_ATTEMPTS_EXPIRY_MS;

/**
 * Get failed login attempts from in-memory store
 */
export const getFailedAttemptsMemory = (email: string): number => {
  const entry = failedAttemptsStore.get(email);
  return entry ? entry.count : 0;
};

/**
 * Increment failed login attempts in in-memory store with automatic expiry
 */
export const incrementFailedAttemptsMemory = (email: string): number => {
  const existing = failedAttemptsStore.get(email);
  const newCount = (existing ? existing.count : 0) + 1;

  // Clear previous expiry timer if exists
  if (existing) {
    clearTimeout(existing.expiry);
  }

  const expiry = setTimeout(() => {
    failedAttemptsStore.delete(email);
  }, FAILED_ATTEMPTS_EXPIRY_MS);

  failedAttemptsStore.set(email, { count: newCount, expiry });
  return newCount;
};

/**
 * Clear failed login attempts from in-memory store
 */
export const clearFailedAttemptsMemory = (email: string): void => {
  const existing = failedAttemptsStore.get(email);
  if (existing) {
    clearTimeout(existing.expiry);
  }
  failedAttemptsStore.delete(email);
};

/**
 * Store captcha in in-memory store with expiry (stores hash for security)
 */
export const storeCaptchaMemory = (id: string, text: string, expiryMs: number): void => {
  const hashedText = hashCaptchaText(text);
  const expiry = setTimeout(() => {
    captchaStore.delete(id);
  }, expiryMs);
  captchaStore.set(id, { hash: hashedText, expiry });
};

/**
 * Verify and delete captcha from in-memory store (compares hash instead of plain text)
 */
export const verifyCaptchaMemory = (id: string, input: string): boolean => {
  const stored = captchaStore.get(id);
  if (!stored) return false;
  
  clearTimeout(stored.expiry);
  captchaStore.delete(id);
  
  const inputHash = hashCaptchaText(input);
  return stored.hash === inputHash;
};

/**
 * Add token to in-memory blacklist
 */
export const blacklistTokenMemory = (token: string, expiryMs: number): void => {
  const existing = tokenBlacklistStore.get(token);
  if (existing) clearTimeout(existing);

  const expiry = setTimeout(() => {
    tokenBlacklistStore.delete(token);
  }, expiryMs);
  tokenBlacklistStore.set(token, expiry);
};

/**
 * Check if token is in in-memory blacklist
 */
export const isTokenBlacklistedMemory = (token: string): boolean => {
  return tokenBlacklistStore.has(token);
};

/**
 * Atomically claim a (refresh) token for single use, in-memory-fallback
 * counterpart to redisClient.ts's claimTokenOnce. Safe without extra locking:
 * Node is single-threaded and there is no `await` between the check and the
 * set, so no other request can interleave here.
 */
export const claimTokenOnceMemory = (token: string, expiryMs: number): boolean => {
  if (tokenBlacklistStore.has(token)) return false;
  blacklistTokenMemory(token, expiryMs);
  return true;
};

/** In-memory-fallback counterpart to redisClient.ts's storeRefreshSuccessor/getRefreshSuccessor. */
export const storeRefreshSuccessorMemory = (
  oldToken: string,
  successor: { accessToken: string; refreshToken: string; csrfToken: string },
  graceMs: number,
): void => {
  const existing = refreshSuccessorStore.get(oldToken);
  if (existing) clearTimeout(existing.expiry);
  const expiry = setTimeout(() => {
    refreshSuccessorStore.delete(oldToken);
  }, graceMs);
  refreshSuccessorStore.set(oldToken, { ...successor, expiry });
};

export const getRefreshSuccessorMemory = (
  oldToken: string,
): { accessToken: string; refreshToken: string; csrfToken: string } | null => {
  const entry = refreshSuccessorStore.get(oldToken);
  return entry ? { accessToken: entry.accessToken, refreshToken: entry.refreshToken, csrfToken: entry.csrfToken } : null;
};

/** In-memory-fallback counterpart to redisClient.ts's storeCsrfSuccessor/getCsrfSuccessor. */
export const storeCsrfSuccessorMemory = (oldToken: string, newToken: string, graceMs: number): void => {
  const existing = csrfSuccessorStore.get(oldToken);
  if (existing) clearTimeout(existing.expiry);
  const expiry = setTimeout(() => {
    csrfSuccessorStore.delete(oldToken);
  }, graceMs);
  csrfSuccessorStore.set(oldToken, { newToken, expiry });
};

export const getCsrfSuccessorMemory = (oldToken: string): string | null => {
  const entry = csrfSuccessorStore.get(oldToken);
  return entry ? entry.newToken : null;
};

/**
 * Store single-use shell token in memory
 */
export const storeShellTokenMemory = (token: string, userId: string, expiryMs: number): void => {
  const expiry = setTimeout(() => {
    shellTokenStore.delete(token);
  }, expiryMs);
  shellTokenStore.set(token, { userId, expiry });
};

/**
 * Verify and consume single-use shell token in memory
 */
export const verifyShellTokenMemory = (token: string, userId: string): boolean => {
  const entry = shellTokenStore.get(token);
  if (!entry) return false;
  
  clearTimeout(entry.expiry);
  shellTokenStore.delete(token); // Single-use
  
  return entry.userId === userId;
};
