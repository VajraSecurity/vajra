import { describe, it, expect, vi, beforeEach } from 'vitest';

// In-memory backing store shared by the mocked redis client's get/setEx/del,
// so tests exercise genuine round-trip behavior (set via one function, read
// via another) rather than hand-wiring return values per call.
let store: Map<string, string>;

const mockClient = {
  connect: vi.fn(),
  on: vi.fn(),
  quit: vi.fn(),
  get: vi.fn((key: string) => Promise.resolve(store.has(key) ? store.get(key)! : null)),
  // Dual-read for isTokenBlacklisted's digest/legacy key migration (see
  // redisClient.ts's blacklistKeyFor) — one MGET rather than two GETs.
  mGet: vi.fn((keys: string[]) => Promise.resolve(keys.map((key) => (store.has(key) ? store.get(key)! : null)))),
  setEx: vi.fn((key: string, _ttlSeconds: number, value: string) => {
    store.set(key, value);
    return Promise.resolve('OK');
  }),
  del: vi.fn((key: string) => {
    const existed = store.delete(key);
    return Promise.resolve(existed ? 1 : 0);
  }),
  // Atomic GET+DEL (used by verifyShellToken to close a get-then-delete
  // race where two concurrent requests could both read the token before
  // either deleted it) — mirrors real GETDEL: returns the value (or null)
  // and removes the key in one step.
  getDel: vi.fn((key: string) => {
    const value = store.has(key) ? store.get(key)! : null;
    store.delete(key);
    return Promise.resolve(value);
  }),
};

vi.mock('redis', () => ({
  createClient: vi.fn(() => mockClient),
}));

import {
  initializeRedis,
  getRedisClient,
  disconnectRedis,
  storeCaptcha,
  verifyCaptcha,
  getFailedAttempts,
  incrementFailedAttempts,
  clearFailedAttempts,
  blacklistToken,
  isTokenBlacklisted,
  storeShellToken,
  verifyShellToken,
} from '../../../utils/redisClient';

describe('redisClient', () => {
  beforeEach(async () => {
    store = new Map();
    vi.clearAllMocks();
    mockClient.connect.mockResolvedValue(undefined);
    mockClient.quit.mockResolvedValue(undefined);
    // Re-establish a connected client before each test (mockClient methods
    // above already have their default implementations from vi.fn(impl),
    // which vi.clearAllMocks() preserves).
    await initializeRedis();
  });

  describe('initializeRedis / getRedisClient / disconnectRedis', () => {
    it('connects successfully and exposes the client via getRedisClient', async () => {
      expect(mockClient.connect).toHaveBeenCalledTimes(1);
      expect(getRedisClient()).toBe(mockClient);
    });

    it('returns false and leaves the client null when connect() rejects', async () => {
      mockClient.connect.mockRejectedValueOnce(new Error('connection refused'));

      const result = await initializeRedis();

      expect(result).toBe(false);
      expect(getRedisClient()).toBeNull();
    });

    it('disconnects the client, calling quit and nulling the client reference', async () => {
      await disconnectRedis();

      expect(mockClient.quit).toHaveBeenCalledTimes(1);
      expect(getRedisClient()).toBeNull();
    });
  });

  describe('blacklistToken / isTokenBlacklisted', () => {
    it('round-trips: a blacklisted token is reported as blacklisted', async () => {
      await blacklistToken('token-abc', 60);

      expect(mockClient.setEx).toHaveBeenCalledWith('blacklist:token-abc', 60, '1');
      await expect(isTokenBlacklisted('token-abc')).resolves.toBe(true);
    });

    it('reports a token as not blacklisted when it was never stored', async () => {
      await expect(isTokenBlacklisted('never-seen')).resolves.toBe(false);
    });

    it('is a no-op when the client is not initialized', async () => {
      await disconnectRedis();

      await blacklistToken('token-xyz', 60);

      expect(mockClient.setEx).not.toHaveBeenCalled();
    });

    it('returns false from isTokenBlacklisted when the client is not initialized', async () => {
      await disconnectRedis();

      await expect(isTokenBlacklisted('token-xyz')).resolves.toBe(false);
    });

    it('swallows errors from the underlying client and returns false', async () => {
      mockClient.mGet.mockRejectedValueOnce(new Error('redis down'));

      await expect(isTokenBlacklisted('token-abc')).resolves.toBe(false);
    });
  });

  describe('getFailedAttempts / incrementFailedAttempts / clearFailedAttempts', () => {
    const email = 'user@example.com';

    it('returns 0 when there is no recorded attempt', async () => {
      await expect(getFailedAttempts(email)).resolves.toBe(0);
    });

    it('increments failed attempts against the correct key and returns the new count', async () => {
      const first = await incrementFailedAttempts(email);
      const second = await incrementFailedAttempts(email);

      expect(first).toBe(1);
      expect(second).toBe(2);
      expect(mockClient.setEx).toHaveBeenLastCalledWith(
        `login:attempts:${email}`,
        3600,
        '2'
      );
      await expect(getFailedAttempts(email)).resolves.toBe(2);
    });

    it('clears failed attempts using the correct key', async () => {
      await incrementFailedAttempts(email);

      await clearFailedAttempts(email);

      expect(mockClient.del).toHaveBeenCalledWith(`login:attempts:${email}`);
      await expect(getFailedAttempts(email)).resolves.toBe(0);
    });

    it('returns 0 from incrementFailedAttempts when the underlying call rejects', async () => {
      mockClient.get.mockRejectedValueOnce(new Error('redis down'));

      await expect(incrementFailedAttempts(email)).resolves.toBe(0);
    });

    it('returns 0 from getFailedAttempts when the underlying call rejects', async () => {
      mockClient.get.mockRejectedValueOnce(new Error('redis down'));

      await expect(getFailedAttempts(email)).resolves.toBe(0);
    });
  });

  describe('storeCaptcha / verifyCaptcha', () => {
    it('round-trips: a stored captcha verifies successfully with the matching code', async () => {
      await storeCaptcha('captcha-1', 'ABC123', 300000);

      await expect(verifyCaptcha('captcha-1', 'ABC123')).resolves.toBe(true);
    });

    it('stores the captcha as a hash rather than plain text, with expiry converted to seconds', async () => {
      await storeCaptcha('captcha-1', 'ABC123', 300000);

      const [key, ttlSeconds, storedValue] = mockClient.setEx.mock.calls[0];
      expect(key).toBe('captcha:captcha-1');
      expect(ttlSeconds).toBe(300);
      expect(storedValue).not.toBe('ABC123');
    });

    it('is case-insensitive because the stored text is lowercased before hashing', async () => {
      await storeCaptcha('captcha-1', 'ABC123', 300000);

      await expect(verifyCaptcha('captcha-1', 'abc123')).resolves.toBe(true);
    });

    it('fails verification when the input code is wrong', async () => {
      await storeCaptcha('captcha-1', 'ABC123', 300000);

      await expect(verifyCaptcha('captcha-1', 'WRONG1')).resolves.toBe(false);
    });

    it('is single-use: deletes the captcha after verification even when the code was wrong', async () => {
      await storeCaptcha('captcha-1', 'ABC123', 300000);

      await verifyCaptcha('captcha-1', 'WRONG1');

      expect(mockClient.del).toHaveBeenCalledWith('captcha:captcha-1');
      await expect(verifyCaptcha('captcha-1', 'ABC123')).resolves.toBe(false);
    });

    it('returns false when verifying a captcha id that was never stored', async () => {
      await expect(verifyCaptcha('missing-id', 'ABC123')).resolves.toBe(false);
    });

    it('returns false from verifyCaptcha when the underlying call rejects', async () => {
      mockClient.get.mockRejectedValueOnce(new Error('redis down'));

      await expect(verifyCaptcha('captcha-1', 'ABC123')).resolves.toBe(false);
    });
  });

  describe('storeShellToken / verifyShellToken', () => {
    it('round-trips: a stored shell token verifies successfully for the matching user', async () => {
      await storeShellToken('shell-token-1', 'user-42', 30);

      expect(mockClient.setEx).toHaveBeenCalledWith('ws:shell:token:shell-token-1', 30, 'user-42');
      await expect(verifyShellToken('shell-token-1', 'user-42')).resolves.toBe(true);
    });

    it('fails verification when the user id does not match', async () => {
      await storeShellToken('shell-token-1', 'user-42', 30);

      await expect(verifyShellToken('shell-token-1', 'someone-else')).resolves.toBe(false);
    });

    it('is single-use: a second verification attempt fails even with the correct user id', async () => {
      await storeShellToken('shell-token-1', 'user-42', 30);

      await verifyShellToken('shell-token-1', 'user-42');

      // Atomic GETDEL (not a separate get+del) — see the getDel mock above.
      expect(mockClient.getDel).toHaveBeenCalledWith('ws:shell:token:shell-token-1');
      await expect(verifyShellToken('shell-token-1', 'user-42')).resolves.toBe(false);
    });

    it('is single-use even on a mismatched user id: the token is consumed regardless', async () => {
      await storeShellToken('shell-token-1', 'user-42', 30);

      await verifyShellToken('shell-token-1', 'wrong-user');

      // Token was deleted on the first (failed) attempt, so even the correct
      // user id now fails.
      await expect(verifyShellToken('shell-token-1', 'user-42')).resolves.toBe(false);
    });

    it('returns false from verifyShellToken when the underlying call rejects', async () => {
      mockClient.get.mockRejectedValueOnce(new Error('redis down'));

      await expect(verifyShellToken('shell-token-1', 'user-42')).resolves.toBe(false);
    });
  });
});
