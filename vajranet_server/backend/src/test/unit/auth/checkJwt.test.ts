import { describe, it, expect, vi, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

vi.mock('../../../utils/redisClient', () => ({
  isTokenBlacklisted: vi.fn(),
  getRedisClient: vi.fn(() => null),
  blacklistToken: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../utils/memoryStore', () => ({
  isTokenBlacklistedMemory: vi.fn(() => false),
  blacklistTokenMemory: vi.fn(),
  // claimTokenOnceMemory gates refresh-token rotation (single-use claim,
  // see checkJwt.ts's claimRefreshTokenOnce) — default to "claim succeeded"
  // so the happy-path rotation tests below can proceed past it.
  claimTokenOnceMemory: vi.fn(() => true),
  storeRefreshSuccessorMemory: vi.fn(),
  getRefreshSuccessorMemory: vi.fn(() => null),
  storeCsrfSuccessorMemory: vi.fn(),
}));

import { dbSourceConnection } from '../../../index';
import { isTokenBlacklisted, getRedisClient } from '../../../utils/redisClient';
import { isTokenBlacklistedMemory, blacklistTokenMemory } from '../../../utils/memoryStore';
import {
  checkAccessJwt,
  checkAccessWithRefreshFallback,
  checkRefreshJwt,
  requireRefreshJwtIfUsersExist,
  requireSuperAdminIfUsersExist,
  checkJwt,
} from '../../../middleware/checkJwt';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from '../../../utils/cookieConfig';
import { makeUser, makeSuperAdmin, makeJwtPayload } from '../../factories';

const ACCESS_SECRET = process.env.ACCESS_JWT_SECRET as string;
const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET as string;

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;
const mockedIsTokenBlacklistedMemory = isTokenBlacklistedMemory as unknown as ReturnType<typeof vi.fn>;
const mockedGetRedisClient = getRedisClient as unknown as ReturnType<typeof vi.fn>;
const mockedIsTokenBlacklisted = isTokenBlacklisted as unknown as ReturnType<typeof vi.fn>;
const mockedBlacklistTokenMemory = blacklistTokenMemory as unknown as ReturnType<typeof vi.fn>;

function signAccess(payload: Record<string, any>, opts: jwt.SignOptions = {}): string {
  return jwt.sign(payload, ACCESS_SECRET, { algorithm: 'HS256', expiresIn: '15m', ...opts });
}

function signRefresh(payload: Record<string, any>, opts: jwt.SignOptions = {}): string {
  return jwt.sign(payload, REFRESH_SECRET, { algorithm: 'HS256', expiresIn: '7d', ...opts });
}

function makeFakeDataSource(fakeRepo: any, query: ReturnType<typeof vi.fn> = vi.fn()) {
  return { getRepository: vi.fn(() => fakeRepo), query };
}

function makeReq(overrides: Partial<Request> & { cookies?: Record<string, string> } = {}): Request {
  return { cookies: {}, originalUrl: '/api/nodes', ...overrides } as unknown as Request;
}

function makeRes(): Response {
  return { cookie: vi.fn(), clearCookie: vi.fn() } as unknown as Response;
}

function getError(next: NextFunction): CustomError {
  return (next as any).mock.calls[0][0] as CustomError;
}

beforeEach(() => {
  mockedDbSourceConnection.mockReset();
  mockedIsTokenBlacklistedMemory.mockReset();
  mockedIsTokenBlacklistedMemory.mockReturnValue(false);
  mockedGetRedisClient.mockReset();
  mockedGetRedisClient.mockReturnValue(null);
  mockedIsTokenBlacklisted.mockReset();
  mockedBlacklistTokenMemory.mockReset();
});

describe('checkJwt alias', () => {
  it('checkJwt is an alias for checkAccessWithRefreshFallback', () => {
    expect(checkJwt).toBe(checkAccessWithRefreshFallback);
  });
});

describe('checkAccessJwt', () => {
  it('rejects when no access-token cookie is present', async () => {
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Access token cookie not found');
  });

  it('rejects a blacklisted access token', async () => {
    const token = signAccess(makeJwtPayload({ sessionId: undefined }));
    mockedIsTokenBlacklistedMemory.mockReturnValue(true);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('blacklisted');
  });

  it('accepts a valid token when the DB confirms matching session_version and an active user', async () => {
    const payload = makeJwtPayload({ id: 10, session_version: 3, sessionId: undefined });
    const token = signAccess(payload);
    const dbUser = makeUser({ id: 10, session_version: 3, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect((req as any).jwtPayload.id).toBe(10);
  });

  it('rejects with "Session invalidated" when the token session_version does not match the DB', async () => {
    const payload = makeJwtPayload({ id: 11, session_version: 1, sessionId: undefined });
    const token = signAccess(payload);
    const dbUser = makeUser({ id: 11, session_version: 5, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Session invalidated');
    expect(res.clearCookie).toHaveBeenCalled();
  });

  it('rejects a suspended user even with a matching session_version', async () => {
    const payload = makeJwtPayload({ id: 14, session_version: 0, sessionId: undefined });
    const token = signAccess(payload);
    const dbUser = makeUser({ id: 14, session_version: 0, suspended: true });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Session invalidated');
  });

  it('rejects with 403 when force_password_change is set and the path is not an allowed exception', async () => {
    const payload = makeJwtPayload({ id: 12, session_version: 0, sessionId: undefined, force_password_change: true });
    const token = signAccess(payload);
    const dbUser = makeUser({ id: 12, session_version: 0, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token }, originalUrl: '/api/nodes/list' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(403);
  });

  it('allows access to /auth/profile/password-update even when force_password_change is set', async () => {
    const payload = makeJwtPayload({ id: 15, session_version: 0, sessionId: undefined, force_password_change: true });
    const token = signAccess(payload);
    const dbUser = makeUser({ id: 15, session_version: 0, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token }, originalUrl: '/api/auth/profile/password-update' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  it('renews the access and CSRF cookies when the token is close to expiry', async () => {
    const payload = makeJwtPayload({ id: 13, session_version: 0, sessionId: undefined });
    // TOKEN_RENEWAL_THRESHOLD_SECONDS is 300s; 100s remaining should trigger renewal.
    const token = signAccess(payload, { expiresIn: 100 });
    const dbUser = makeUser({ id: 13, session_version: 0, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    expect(res.cookie).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });

  it('rejects a token signed with the wrong secret', async () => {
    const token = jwt.sign(makeJwtPayload({ sessionId: undefined }), 'a-totally-wrong-secret-value-123456', { algorithm: 'HS256' });
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
  });
});

describe('checkAccessWithRefreshFallback', () => {
  it('issues new access/refresh/CSRF tokens when the access token is expired but the refresh token is valid', async () => {
    const payload = makeJwtPayload({ id: 20, session_version: 0, sessionId: undefined });
    const expiredAccess = signAccess(payload, { expiresIn: -10 });
    const refreshToken = signRefresh(payload);
    const dbUser = makeUser({ id: 20, session_version: 0, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: expiredAccess, [REFRESH_TOKEN_COOKIE]: refreshToken } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessWithRefreshFallback(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(res.cookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, expect.any(String), expect.anything());
    expect(res.cookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, expect.any(String), expect.anything());
  });

  it('issues new tokens when there is no access token but a valid refresh token is present', async () => {
    const payload = makeJwtPayload({ id: 22, session_version: 0, sessionId: undefined });
    const refreshToken = signRefresh(payload);
    const dbUser = makeUser({ id: 22, session_version: 0, suspended: false });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(dbUser) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [REFRESH_TOKEN_COOKIE]: refreshToken } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessWithRefreshFallback(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(res.cookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, expect.any(String), expect.anything());
  });

  it('rejects with 401 when neither an access nor a refresh token cookie is present', async () => {
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessWithRefreshFallback(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('No tokens found');
  });

  // NOTE (source-code surprise): checkAccessWithRefreshFallback checks the refresh token
  // against the blacklist unconditionally at the very top of the function, before any JWT
  // verification happens. This means the "replay attack" branch further down (which detects
  // blacklisting *after* verifying the refresh token and revokes the session by bumping
  // session_version via a raw `.query()` call) is unreachable: any blacklisted refresh token
  // is always caught by the top-level guard first, with a different error message and without
  // ever touching the DB. This test documents the actual (dead-code) behavior.
  it('rejects a blacklisted refresh token via the top-level guard, without reaching the session-revocation query', async () => {
    const payload = makeJwtPayload({ id: 21, session_version: 0, sessionId: undefined });
    const refreshToken = signRefresh(payload);
    mockedIsTokenBlacklistedMemory.mockImplementation((t: string) => t === refreshToken);
    const fakeQuery = vi.fn();
    const fakeRepo = { findOne: vi.fn() };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo, fakeQuery)]);
    const req = makeReq({ cookies: { [REFRESH_TOKEN_COOKIE]: refreshToken } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessWithRefreshFallback(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Session has been invalidated');
    expect(fakeQuery).not.toHaveBeenCalled();
  });

  it('rejects an invalid (non-expired-error) access token without attempting the refresh fallback', async () => {
    const token = jwt.sign(makeJwtPayload({ sessionId: undefined }), 'wrong-secret-value-1234567890', { algorithm: 'HS256' });
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkAccessWithRefreshFallback(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Invalid access token');
  });
});

describe('checkRefreshJwt', () => {
  it('rejects when no refresh-token cookie is present', async () => {
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkRefreshJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('Refresh token cookie not found');
  });

  it('rejects a blacklisted refresh token', async () => {
    const token = signRefresh(makeJwtPayload({ sessionId: undefined }));
    mockedIsTokenBlacklistedMemory.mockReturnValue(true);
    const req = makeReq({ cookies: { [REFRESH_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkRefreshJwt(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
    expect(err.message).toContain('blacklisted');
  });

  it('accepts a valid refresh token and sets req.jwtPayload', async () => {
    const token = signRefresh(makeJwtPayload({ id: 25, sessionId: undefined }));
    const req = makeReq({ cookies: { [REFRESH_TOKEN_COOKIE]: token } });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await checkRefreshJwt(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect((req as any).jwtPayload.id).toBe(25);
  });
});

describe('requireRefreshJwtIfUsersExist', () => {
  it('allows registration through without a token when no users exist yet', async () => {
    const fakeRepo = { count: vi.fn().mockResolvedValue(0) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireRefreshJwtIfUsersExist(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  it('delegates to checkRefreshJwt once users already exist, rejecting a missing token', async () => {
    const fakeRepo = { count: vi.fn().mockResolvedValue(3) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireRefreshJwtIfUsersExist(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(401);
  });

  it('returns 500 when the database is unavailable', async () => {
    mockedDbSourceConnection.mockReturnValue([]);
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireRefreshJwtIfUsersExist(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(500);
  });
});

describe('requireSuperAdminIfUsersExist', () => {
  it('calls next unauthenticated when no users exist yet (bootstrap path)', async () => {
    const fakeRepo = { count: vi.fn().mockResolvedValue(0) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireSuperAdminIfUsersExist(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('falls through to the auth + Super Administrator role chain once users exist, and succeeds for a super admin', async () => {
    const payload = makeJwtPayload({ id: 30, session_version: 0, sessionId: undefined, role: 'Super Administrator' });
    const token = signAccess(payload);
    const dbSuperAdmin = makeSuperAdmin({ id: 30, session_version: 0, suspended: false });
    const fakeRepo = {
      count: vi.fn().mockResolvedValue(1),
      findOne: vi.fn().mockResolvedValue(dbSuperAdmin),
    };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token }, originalUrl: '/api/users/register' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireSuperAdminIfUsersExist(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('falls through to the role chain and rejects a non-super-admin with 403', async () => {
    const payload = makeJwtPayload({ id: 31, session_version: 0, sessionId: undefined, role: 'Viewer' });
    const token = signAccess(payload);
    const dbViewer = makeUser({ id: 31, session_version: 0, suspended: false, role: 'Viewer' });
    const fakeRepo = {
      count: vi.fn().mockResolvedValue(1),
      findOne: vi.fn().mockResolvedValue(dbViewer),
    };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ cookies: { [ACCESS_TOKEN_COOKIE]: token }, originalUrl: '/api/users/register' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireSuperAdminIfUsersExist(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(403);
  });

  it('returns 500 when the database is unavailable', async () => {
    mockedDbSourceConnection.mockReturnValue([]);
    const req = makeReq({ cookies: {} });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await requireSuperAdminIfUsersExist(req, res, next);

    const err = getError(next);
    expect(err.HttpStatusCode).toBe(500);
  });
});
