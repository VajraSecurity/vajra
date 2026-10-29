import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// memoryStore.ts keeps its state in module-scope Maps (failedAttemptsStore,
// captchaStore, tokenBlacklistStore, shellTokenStore) with no exported reset
// function, and entries schedule real setTimeout timers on the Node event
// loop. To keep tests fully independent (and to avoid leftover timers from
// one test firing during another test's fake-timer advancement), we
// vi.resetModules() and re-import a fresh module instance before every test.
type MemoryStoreModule = typeof import('../../../utils/memoryStore');

let memoryStore: MemoryStoreModule;

beforeEach(async () => {
  vi.resetModules();
  memoryStore = await import('../../../utils/memoryStore');
});

afterEach(() => {
  vi.useRealTimers();
});

describe('failed attempts (memory)', () => {
  const email = 'user@example.com';

  it('returns 0 when there is no recorded attempt for the key', () => {
    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(0);
  });

  it('increments the counter for a key and returns the new count', () => {
    expect(memoryStore.incrementFailedAttemptsMemory(email)).toBe(1);
    expect(memoryStore.incrementFailedAttemptsMemory(email)).toBe(2);
    expect(memoryStore.incrementFailedAttemptsMemory(email)).toBe(3);
    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(3);
  });

  it('tracks counters independently per key', () => {
    memoryStore.incrementFailedAttemptsMemory('a@example.com');
    memoryStore.incrementFailedAttemptsMemory('a@example.com');
    memoryStore.incrementFailedAttemptsMemory('b@example.com');

    expect(memoryStore.getFailedAttemptsMemory('a@example.com')).toBe(2);
    expect(memoryStore.getFailedAttemptsMemory('b@example.com')).toBe(1);
  });

  it('clears the counter for a key back to 0', () => {
    memoryStore.incrementFailedAttemptsMemory(email);
    memoryStore.incrementFailedAttemptsMemory(email);

    memoryStore.clearFailedAttemptsMemory(email);

    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(0);
  });

  it('is a no-op to clear a key that was never recorded', () => {
    expect(() => memoryStore.clearFailedAttemptsMemory('never@example.com')).not.toThrow();
    expect(memoryStore.getFailedAttemptsMemory('never@example.com')).toBe(0);
  });

  it('expires the counter automatically after the configured TTL (1 hour)', () => {
    vi.useFakeTimers();

    memoryStore.incrementFailedAttemptsMemory(email);
    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(1);

    vi.advanceTimersByTime(60 * 60 * 1000);

    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(0);
  });

  it('does not expire the counter before the TTL has elapsed', () => {
    vi.useFakeTimers();

    memoryStore.incrementFailedAttemptsMemory(email);
    vi.advanceTimersByTime(60 * 60 * 1000 - 1);

    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(1);
  });

  it('extends the expiry window each time the counter is incremented again', () => {
    vi.useFakeTimers();

    memoryStore.incrementFailedAttemptsMemory(email);
    vi.advanceTimersByTime(60 * 60 * 1000 - 1000); // just under 1h
    memoryStore.incrementFailedAttemptsMemory(email); // resets the timer

    vi.advanceTimersByTime(60 * 60 * 1000 - 1000); // would have expired the first timer, not the second

    expect(memoryStore.getFailedAttemptsMemory(email)).toBe(2);
  });
});

describe('captcha (memory)', () => {
  it('round-trips: a stored captcha verifies successfully with the matching code', () => {
    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(true);
  });

  it('is case-insensitive because the stored text is lowercased before hashing', () => {
    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'abc123')).toBe(true);
  });

  it('fails verification when the input code is wrong', () => {
    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'WRONG1')).toBe(false);
  });

  it('returns false when verifying a captcha id that was never stored', () => {
    expect(memoryStore.verifyCaptchaMemory('missing-id', 'ABC123')).toBe(false);
  });

  it('is single-use: a second verification attempt fails even with the correct code', () => {
    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(true);
    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(false);
  });

  it('is single-use even when the first attempt used the wrong code', () => {
    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'WRONG1')).toBe(false);
    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(false);
  });

  it('expires the captcha automatically after its configured TTL', () => {
    vi.useFakeTimers();

    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);
    vi.advanceTimersByTime(300000);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(false);
  });

  it('does not expire the captcha before its TTL has elapsed', () => {
    vi.useFakeTimers();

    memoryStore.storeCaptchaMemory('captcha-1', 'ABC123', 300000);
    vi.advanceTimersByTime(299999);

    expect(memoryStore.verifyCaptchaMemory('captcha-1', 'ABC123')).toBe(true);
  });
});

describe('token blacklist (memory)', () => {
  it('round-trips: a blacklisted token is reported as blacklisted', () => {
    memoryStore.blacklistTokenMemory('token-abc', 60000);

    expect(memoryStore.isTokenBlacklistedMemory('token-abc')).toBe(true);
  });

  it('reports a token as not blacklisted when it was never stored', () => {
    expect(memoryStore.isTokenBlacklistedMemory('never-seen')).toBe(false);
  });

  it('expires the blacklist entry automatically after its configured TTL', () => {
    vi.useFakeTimers();

    memoryStore.blacklistTokenMemory('token-abc', 60000);
    vi.advanceTimersByTime(60000);

    expect(memoryStore.isTokenBlacklistedMemory('token-abc')).toBe(false);
  });

  it('does not expire the blacklist entry before its TTL has elapsed', () => {
    vi.useFakeTimers();

    memoryStore.blacklistTokenMemory('token-abc', 60000);
    vi.advanceTimersByTime(59999);

    expect(memoryStore.isTokenBlacklistedMemory('token-abc')).toBe(true);
  });
});

describe('shell token (memory)', () => {
  it('round-trips: a stored shell token verifies successfully for the matching user', () => {
    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(true);
  });

  it('fails verification when the user id does not match', () => {
    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'someone-else')).toBe(false);
  });

  it('returns false when verifying a shell token that was never stored', () => {
    expect(memoryStore.verifyShellTokenMemory('missing-token', 'user-42')).toBe(false);
  });

  it('is single-use: a second verification attempt fails even with the correct user id', () => {
    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(true);
    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(false);
  });

  it('is single-use even on a mismatched user id: the token is consumed regardless', () => {
    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'wrong-user')).toBe(false);
    // Token was consumed by the failed attempt above, so even the correct
    // user id now fails.
    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(false);
  });

  it('expires the shell token automatically after its configured TTL', () => {
    vi.useFakeTimers();

    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);
    vi.advanceTimersByTime(30000);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(false);
  });

  it('does not expire the shell token before its TTL has elapsed', () => {
    vi.useFakeTimers();

    memoryStore.storeShellTokenMemory('shell-token-1', 'user-42', 30000);
    vi.advanceTimersByTime(29999);

    expect(memoryStore.verifyShellTokenMemory('shell-token-1', 'user-42')).toBe(true);
  });
});
