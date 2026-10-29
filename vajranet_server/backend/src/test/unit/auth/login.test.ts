import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

vi.mock('../../../utils/redisClient', () => ({
  getRedisClient: vi.fn(() => null),
  getFailedAttempts: vi.fn(),
  incrementFailedAttempts: vi.fn(),
  clearFailedAttempts: vi.fn(),
  storeCaptcha: vi.fn(),
  verifyCaptcha: vi.fn(),
}));

vi.mock('../../../utils/memoryStore', () => ({
  getFailedAttemptsMemory: vi.fn(() => 0),
  incrementFailedAttemptsMemory: vi.fn(() => 1),
  clearFailedAttemptsMemory: vi.fn(),
  storeCaptchaMemory: vi.fn(),
  verifyCaptchaMemory: vi.fn(() => true),
}));

import { dbSourceConnection } from '../../../index';
import {
  getFailedAttemptsMemory,
  incrementFailedAttemptsMemory,
  clearFailedAttemptsMemory,
  verifyCaptchaMemory,
} from '../../../utils/memoryStore';
import { login } from '../../../controllers/auth/login';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from '../../../consts';
import { makeUser } from '../../factories';

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;
const mockedGetFailedAttemptsMemory = getFailedAttemptsMemory as unknown as ReturnType<typeof vi.fn>;
const mockedIncrementFailedAttemptsMemory = incrementFailedAttemptsMemory as unknown as ReturnType<typeof vi.fn>;
const mockedClearFailedAttemptsMemory = clearFailedAttemptsMemory as unknown as ReturnType<typeof vi.fn>;
const mockedVerifyCaptchaMemory = verifyCaptchaMemory as unknown as ReturnType<typeof vi.fn>;

function makeFakeRepo(overrides: Partial<Record<string, any>> = {}) {
  return {
    findOne: vi.fn().mockResolvedValue(null),
    save: vi.fn().mockResolvedValue(undefined),
    update: vi.fn().mockResolvedValue(undefined),
    create: vi.fn((entity: any) => entity),
    ...overrides,
  };
}

function makeFakeDataSource(fakeRepo: any) {
  return { getRepository: vi.fn(() => fakeRepo) };
}

function makeReq(body: Record<string, any> = {}): Request {
  return {
    body,
    cookies: {},
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    get: vi.fn(() => 'test-user-agent'),
  } as unknown as Request;
}

function makeRes(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    cookie: vi.fn().mockReturnThis(),
    clearCookie: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

function getError(next: NextFunction): CustomError {
  return (next as any).mock.calls[0][0] as CustomError;
}

describe('login', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
    mockedGetFailedAttemptsMemory.mockReset().mockReturnValue(0);
    mockedIncrementFailedAttemptsMemory.mockReset().mockReturnValue(1);
    mockedClearFailedAttemptsMemory.mockReset();
    mockedVerifyCaptchaMemory.mockReset().mockReturnValue(true);
  });

  it('calls next with a 500 CustomError when the primary database connection is unavailable', async () => {
    mockedDbSourceConnection.mockReturnValue([]);
    const req = makeReq({ email: 'user@example.com', password: 'whatever' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(500);
    expect(res.status).not.toHaveBeenCalled();
  });

  it('responds with 401 and does not query the user repository when the failed-attempt count already requires a CAPTCHA and none is supplied', async () => {
    mockedGetFailedAttemptsMemory.mockReturnValue(5);
    const fakeRepo = makeFakeRepo();
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ email: 'user@example.com', password: 'whatever' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'CaptchaRequired' }),
    );
    expect(fakeRepo.findOne).not.toHaveBeenCalled();
  });

  it('responds with 401 "Invalid email or password" when no user matches the supplied email', async () => {
    const fakeRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(null) });
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ email: 'missing@example.com', password: 'whatever' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid email or password' });
    expect(mockedIncrementFailedAttemptsMemory).toHaveBeenCalledWith('missing@example.com');
    expect(next).not.toHaveBeenCalled();
  });

  it('responds with 401 "Invalid email or password" and records a failed attempt when the password is wrong', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password' });
    await user.hashPassword();
    const fakeRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ email: 'user@example.com', password: 'wrong-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid email or password' });
    expect(mockedIncrementFailedAttemptsMemory).toHaveBeenCalledWith('user@example.com');
    expect(res.cookie).not.toHaveBeenCalled();
  });

  it('responds with a CAPTCHA-required 401 when a wrong password pushes the failed-attempt count to the configured maximum', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password' });
    await user.hashPassword();
    const fakeRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    // First call (pre-check) is under the threshold; second call (post-increment) hits it.
    mockedGetFailedAttemptsMemory.mockReturnValueOnce(0).mockReturnValueOnce(5);
    const req = makeReq({ email: 'user@example.com', password: 'wrong-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'CaptchaRequired' }),
    );
  });

  it('responds with 403 when the credentials are correct but the account is suspended', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password', suspended: true });
    await user.hashPassword();
    const fakeRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ email: 'user@example.com', password: 'correct-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'Fail', message: expect.stringContaining('suspended') }),
    );
    expect(res.cookie).not.toHaveBeenCalled();
  });

  it('logs a non-MFA user in directly: clears failed attempts, sets access/refresh/CSRF cookies, and returns 200 Success', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password', mfa_enabled: false });
    await user.hashPassword();
    const sessionRepo = makeFakeRepo();
    const userRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    const fakeDataSource = {
      getRepository: vi.fn((entity: any) => (entity?.name === 'UserSession' ? sessionRepo : userRepo)),
    };
    mockedDbSourceConnection.mockReturnValue([fakeDataSource]);
    const req = makeReq({ email: 'user@example.com', password: 'correct-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'Success', message: 'Login successful.' });
    expect(res.cookie).toHaveBeenCalledTimes(3);
    const cookieNames = (res.cookie as any).mock.calls.map((call: any[]) => call[0]);
    expect(cookieNames).toContain(ACCESS_TOKEN_COOKIE);
    expect(cookieNames).toContain(REFRESH_TOKEN_COOKIE);
    expect(mockedClearFailedAttemptsMemory).toHaveBeenCalledWith('user@example.com');
    expect(sessionRepo.save).toHaveBeenCalledTimes(1);
  });

  it('still returns a 200 Success login when session tracking fails to persist', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password', mfa_enabled: false });
    await user.hashPassword();
    const sessionRepo = makeFakeRepo({ save: vi.fn().mockRejectedValue(new Error('db down')) });
    const userRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    const fakeDataSource = {
      getRepository: vi.fn((entity: any) => (entity?.name === 'UserSession' ? sessionRepo : userRepo)),
    };
    mockedDbSourceConnection.mockReturnValue([fakeDataSource]);
    const req = makeReq({ email: 'user@example.com', password: 'correct-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'Success', message: 'Login successful.' });
    expect(res.cookie).toHaveBeenCalledTimes(3);
  });

  it('returns an MFA-required response with an mfaToken, and does not set the normal auth cookies, when mfa_enabled is true', async () => {
    const user = makeUser({
      email: 'mfa-user@example.com',
      password_hash: 'correct-password',
      mfa_enabled: true,
      mfa_secret: 'JBSWY3DPEHPK3PXP',
    });
    await user.hashPassword();
    const fakeRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ email: 'mfa-user@example.com', password: 'correct-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'MfaRequired', message: 'MFA verification required.', mfaToken: expect.any(String) }),
    );
    expect(res.cookie).not.toHaveBeenCalled();
  });

  it('treats a user with mfa_enabled true but no mfa_secret as non-MFA and logs them in directly', async () => {
    const user = makeUser({
      email: 'partial-mfa@example.com',
      password_hash: 'correct-password',
      mfa_enabled: true,
      mfa_secret: null,
    });
    await user.hashPassword();
    const sessionRepo = makeFakeRepo();
    const userRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    const fakeDataSource = {
      getRepository: vi.fn((entity: any) => (entity?.name === 'UserSession' ? sessionRepo : userRepo)),
    };
    mockedDbSourceConnection.mockReturnValue([fakeDataSource]);
    const req = makeReq({ email: 'partial-mfa@example.com', password: 'correct-password' });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'Success', message: 'Login successful.' });
    expect(res.cookie).toHaveBeenCalledTimes(3);
  });

  it('accepts a valid CAPTCHA when the failed-attempt threshold has been reached and proceeds to authenticate', async () => {
    mockedGetFailedAttemptsMemory.mockReturnValue(5);
    mockedVerifyCaptchaMemory.mockReturnValue(true);
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password', mfa_enabled: false });
    await user.hashPassword();
    const sessionRepo = makeFakeRepo();
    const userRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    const fakeDataSource = {
      getRepository: vi.fn((entity: any) => (entity?.name === 'UserSession' ? sessionRepo : userRepo)),
    };
    mockedDbSourceConnection.mockReturnValue([fakeDataSource]);
    const req = makeReq({
      email: 'user@example.com',
      password: 'correct-password',
      captcha: 'ABCDE',
      captchaId: 'some-captcha-id',
    });
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(mockedVerifyCaptchaMemory).toHaveBeenCalledWith('some-captcha-id', 'ABCDE');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ status: 'Success', message: 'Login successful.' });
  });

  it('calls next with a 400 CustomError when token/session creation throws unexpectedly', async () => {
    const user = makeUser({ email: 'user@example.com', password_hash: 'correct-password', mfa_enabled: false });
    await user.hashPassword();
    const sessionRepo = makeFakeRepo();
    const userRepo = makeFakeRepo({ findOne: vi.fn().mockResolvedValue(user) });
    const fakeDataSource = {
      getRepository: vi.fn((entity: any) => (entity?.name === 'UserSession' ? sessionRepo : userRepo)),
    };
    mockedDbSourceConnection.mockReturnValue([fakeDataSource]);
    const req = makeReq({ email: 'user@example.com', password: 'correct-password' });
    const res = makeRes();
    (res.cookie as any).mockImplementation(() => {
      throw new Error('cookie serialization failed');
    });
    const next = vi.fn() as NextFunction;

    await login(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(400);
  });
});
