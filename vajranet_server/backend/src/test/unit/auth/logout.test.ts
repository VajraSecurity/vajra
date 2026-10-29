import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Response, NextFunction } from 'express';

import { UserSession } from '../../../orm/entities/session/UserSession';
import { VajraUser } from '../../../orm/entities/users/Users';
import {
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  CSRF_COOKIE_NAME,
  SECURE_HTTP_ONLY_STRICT_OPTIONS,
  CLIENT_READABLE_STRICT_OPTIONS,
} from '../../../utils/cookieConfig';
import {
  BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS,
  BLACKLIST_ACCESS_TOKEN_EXPIRY_MS,
  BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS,
  BLACKLIST_REFRESH_TOKEN_EXPIRY_MS,
} from '../../../consts';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { makeJwtPayload } from '../../factories';

// --- Hoisted fakes shared between the mock factories and the tests ---
const { sessionRepo, userRepo, fakeDataSource } = vi.hoisted(() => {
  const sessionRepo = {
    findOne: vi.fn(),
    find: vi.fn(),
    save: vi.fn(),
  };
  const userRepo = {
    increment: vi.fn(),
  };
  const fakeDataSource = {
    getRepository: vi.fn(),
  };
  return { sessionRepo, userRepo, fakeDataSource };
});

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(() => [fakeDataSource]),
}));

vi.mock('../../../utils/redisClient', () => ({
  blacklistToken: vi.fn().mockResolvedValue(undefined),
  getRedisClient: vi.fn(() => null),
}));

vi.mock('../../../utils/memoryStore', () => ({
  blacklistTokenMemory: vi.fn(),
}));

vi.mock('../../../utils/auditTrailLogger', () => ({
  logAuditTrail: vi.fn().mockResolvedValue(undefined),
}));

import { logout, logoutAllDevices } from '../../../controllers/auth/logout';
import { dbSourceConnection } from '../../../index';
import { blacklistToken, getRedisClient } from '../../../utils/redisClient';
import { blacklistTokenMemory } from '../../../utils/memoryStore';
import { logAuditTrail } from '../../../utils/auditTrailLogger';

function makeSession(overrides: Partial<UserSession> = {}): UserSession {
  const session = new UserSession();
  session.id = overrides.id ?? 1;
  session.userId = overrides.userId ?? 1;
  session.ipAddress = overrides.ipAddress ?? null;
  session.userAgent = overrides.userAgent ?? null;
  session.loginTime = overrides.loginTime ?? new Date('2026-07-10T09:00:00.000Z');
  session.logoutTime = overrides.logoutTime ?? null;
  session.isActive = overrides.isActive ?? true;
  session.durationSeconds = overrides.durationSeconds ?? null;
  session.logoutReason = overrides.logoutReason ?? null;
  return session;
}

function makeReq(overrides: any = {}) {
  return {
    body: {},
    cookies: {},
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  } as any;
}

function makeRes() {
  return {
    cookie: vi.fn(),
    clearCookie: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

beforeEach(() => {
  vi.clearAllMocks();

  fakeDataSource.getRepository.mockImplementation((entity: any) => {
    if (entity === UserSession) return sessionRepo;
    if (entity === VajraUser) return userRepo;
    throw new Error(`Unexpected entity passed to getRepository: ${entity}`);
  });

  (dbSourceConnection as unknown as ReturnType<typeof vi.fn>).mockReturnValue([fakeDataSource]);
  (getRedisClient as unknown as ReturnType<typeof vi.fn>).mockReturnValue(null);
  (blacklistToken as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
  (logAuditTrail as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

  sessionRepo.findOne.mockResolvedValue(null);
  sessionRepo.find.mockResolvedValue([]);
  sessionRepo.save.mockResolvedValue(undefined);
  userRepo.increment.mockResolvedValue(undefined);
});

describe('logout', () => {
  it('blacklists the access token in the in-memory store when the access token cookie is present', async () => {
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: 'access-token-value' } });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(blacklistTokenMemory).toHaveBeenCalledWith('access-token-value', BLACKLIST_ACCESS_TOKEN_EXPIRY_MS);
  });

  it('blacklists the refresh token in the in-memory store when the refresh token cookie is present', async () => {
    const req = makeReq({ cookies: { [REFRESH_TOKEN_COOKIE]: 'refresh-token-value' } });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(blacklistTokenMemory).toHaveBeenCalledWith('refresh-token-value', BLACKLIST_REFRESH_TOKEN_EXPIRY_MS);
  });

  it('also blacklists both tokens in Redis when a Redis client is available', async () => {
    (getRedisClient as unknown as ReturnType<typeof vi.fn>).mockReturnValue({} as any);
    const req = makeReq({
      cookies: {
        [ACCESS_TOKEN_COOKIE]: 'access-token-value',
        [REFRESH_TOKEN_COOKIE]: 'refresh-token-value',
      },
    });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(blacklistToken).toHaveBeenCalledWith('access-token-value', BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS);
    expect(blacklistToken).toHaveBeenCalledWith('refresh-token-value', BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS);
  });

  it('does not call the Redis blacklist function when no Redis client is available', async () => {
    const req = makeReq({
      cookies: {
        [ACCESS_TOKEN_COOKIE]: 'access-token-value',
        [REFRESH_TOKEN_COOKIE]: 'refresh-token-value',
      },
    });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(blacklistToken).not.toHaveBeenCalled();
  });

  it('does not blacklist anything when neither the access nor refresh token cookie is present', async () => {
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(blacklistTokenMemory).not.toHaveBeenCalled();
    expect(blacklistToken).not.toHaveBeenCalled();
  });

  it('clears the access, refresh, and CSRF cookies with the expected options', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(CSRF_COOKIE_NAME, CLIENT_READABLE_STRICT_OPTIONS);
  });

  it('responds with a 200 success payload', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      status: 'Success',
      message: 'Logout successful. All session and security cookies cleared.',
    });
  });

  it('marks the session matching jwtPayload.sessionId as inactive and saves it', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, sessionId: 7 });
    const activeSession = makeSession({ id: 7, userId: 42, isActive: true });
    sessionRepo.findOne.mockResolvedValueOnce(activeSession);

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(sessionRepo.findOne).toHaveBeenCalledWith({
      where: { id: 7, userId: 42, isActive: true },
    });
    expect(sessionRepo.save).toHaveBeenCalledTimes(1);
    const savedSession = sessionRepo.save.mock.calls[0][0];
    expect(savedSession.isActive).toBe(false);
    expect(savedSession.logoutReason).toBe('user_logout');
    expect(savedSession.logoutTime).toBeInstanceOf(Date);
  });

  it('falls back to the most recent active session when no session matches jwtPayload.sessionId', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, sessionId: 999 });
    const fallbackSession = makeSession({ id: 3, userId: 42, isActive: true });
    sessionRepo.findOne.mockResolvedValueOnce(null).mockResolvedValueOnce(fallbackSession);

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(sessionRepo.findOne).toHaveBeenNthCalledWith(2, {
      where: { userId: 42, isActive: true },
      order: { loginTime: 'DESC' },
    });
    expect(sessionRepo.save).toHaveBeenCalledWith(fallbackSession);
  });

  it('does not touch the session repository when there is no jwtPayload on the request', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(sessionRepo.findOne).not.toHaveBeenCalled();
    expect(sessionRepo.save).not.toHaveBeenCalled();
  });

  it('still responds with 200 when updating the session record throws', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, sessionId: 7 });
    sessionRepo.findOne.mockRejectedValueOnce(new Error('db down'));

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(next).not.toHaveBeenCalled();
  });

  it('logs a LOGOUT audit trail entry when jwtPayload has an id and email', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, email: 'user@example.com' });
    const req = makeReq({ jwtPayload, ip: '10.0.0.5' });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(logAuditTrail).toHaveBeenCalledWith({
      action: 'LOGOUT',
      status: 'success',
      userId: 42,
      email: 'user@example.com',
      ipAddress: '10.0.0.5',
    });
  });

  it('does not log an audit trail entry when there is no jwtPayload', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(logAuditTrail).not.toHaveBeenCalled();
  });

  it('calls next with a 500 CustomError when an unexpected error occurs outside the guarded session block', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, email: 'user@example.com' });
    (logAuditTrail as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('audit failure'));

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logout(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const errorArg = (next as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(errorArg).toBeInstanceOf(CustomError);
    expect(errorArg.HttpStatusCode).toBe(500);
    expect(res.json).not.toHaveBeenCalled();
  });
});

describe('logoutAllDevices', () => {
  it('blacklists the access and refresh tokens in the in-memory store when present', async () => {
    const req = makeReq({
      cookies: {
        [ACCESS_TOKEN_COOKIE]: 'access-token-value',
        [REFRESH_TOKEN_COOKIE]: 'refresh-token-value',
      },
    });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(blacklistTokenMemory).toHaveBeenCalledWith('access-token-value', BLACKLIST_ACCESS_TOKEN_EXPIRY_MS);
    expect(blacklistTokenMemory).toHaveBeenCalledWith('refresh-token-value', BLACKLIST_REFRESH_TOKEN_EXPIRY_MS);
  });

  it('also blacklists both tokens in Redis when a Redis client is available', async () => {
    (getRedisClient as unknown as ReturnType<typeof vi.fn>).mockReturnValue({} as any);
    const req = makeReq({
      cookies: {
        [ACCESS_TOKEN_COOKIE]: 'access-token-value',
        [REFRESH_TOKEN_COOKIE]: 'refresh-token-value',
      },
    });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(blacklistToken).toHaveBeenCalledWith('access-token-value', BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS);
    expect(blacklistToken).toHaveBeenCalledWith('refresh-token-value', BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS);
  });

  it('increments session_version for the user via the repository increment call', async () => {
    const jwtPayload = makeJwtPayload({ id: 42 });
    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(userRepo.increment).toHaveBeenCalledWith({ id: 42 }, 'session_version', 1);
  });

  it('marks every active session for the user as inactive with reason user_logout_all and saves them', async () => {
    const jwtPayload = makeJwtPayload({ id: 42 });
    const sessions = [
      makeSession({ id: 1, userId: 42, isActive: true }),
      makeSession({ id: 2, userId: 42, isActive: true }),
    ];
    sessionRepo.find.mockResolvedValueOnce(sessions);

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(sessionRepo.find).toHaveBeenCalledWith({ where: { userId: 42, isActive: true } });
    expect(sessionRepo.save).toHaveBeenCalledWith(sessions);
    for (const session of sessions) {
      expect(session.isActive).toBe(false);
      expect(session.logoutReason).toBe('user_logout_all');
    }
  });

  it('does not call save on the session repository when there are no active sessions', async () => {
    const jwtPayload = makeJwtPayload({ id: 42 });
    sessionRepo.find.mockResolvedValueOnce([]);

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(sessionRepo.save).not.toHaveBeenCalled();
  });

  it('skips DB session invalidation entirely when there is no jwtPayload on the request', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(userRepo.increment).not.toHaveBeenCalled();
    expect(sessionRepo.find).not.toHaveBeenCalled();
  });

  it('still clears cookies and responds with 200 when the DB increment throws', async () => {
    const jwtPayload = makeJwtPayload({ id: 42 });
    userRepo.increment.mockRejectedValueOnce(new Error('db down'));

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(CSRF_COOKIE_NAME, CLIENT_READABLE_STRICT_OPTIONS);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(next).not.toHaveBeenCalled();
  });

  it('clears the access, refresh, and CSRF cookies with the expected options', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(CSRF_COOKIE_NAME, CLIENT_READABLE_STRICT_OPTIONS);
  });

  it('responds with a 200 success payload for logging out of all devices', async () => {
    const req = makeReq();
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      status: 'Success',
      message: 'Logout successful from all devices and sessions.',
    });
  });

  it('logs a LOGOUT audit trail entry with the logout_all_devices reason', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, email: 'user@example.com' });
    const req = makeReq({ jwtPayload, ip: '10.0.0.5' });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(logAuditTrail).toHaveBeenCalledWith({
      action: 'LOGOUT',
      status: 'success',
      userId: 42,
      email: 'user@example.com',
      ipAddress: '10.0.0.5',
      details: { reason: 'logout_all_devices' },
    });
  });

  it('calls next with a 500 CustomError when an unexpected error occurs outside the guarded session block', async () => {
    const jwtPayload = makeJwtPayload({ id: 42, email: 'user@example.com' });
    (logAuditTrail as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('audit failure'));

    const req = makeReq({ jwtPayload });
    const res = makeRes();
    const next: NextFunction = vi.fn();

    await logoutAllDevices(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const errorArg = (next as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(errorArg).toBeInstanceOf(CustomError);
    expect(errorArg.HttpStatusCode).toBe(500);
    expect(res.json).not.toHaveBeenCalled();
  });
});
