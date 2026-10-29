import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Response, NextFunction } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

import { dbSourceConnection } from '../../../index';
import { update_password } from '../../../controllers/auth/updatePassword';
import { VajraUser } from '../../../orm/entities/users/Users';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import {
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  CSRF_COOKIE_NAME,
  SECURE_HTTP_ONLY_STRICT_OPTIONS,
  CLIENT_READABLE_STRICT_OPTIONS,
} from '../../../utils/cookieConfig';
import { makeUser, makeJwtPayload } from '../../factories';

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;

const CURRENT_PLAINTEXT_PASSWORD = 'CurrentPass123!';
const NEW_PLAINTEXT_PASSWORD = 'BrandNewPass456!';

function makeFakeRepo(overrides: Partial<Record<string, any>> = {}) {
  return {
    findOne: vi.fn(),
    save: vi.fn((entity: any) => Promise.resolve(entity)),
    create: vi.fn((data: any) => data),
    update: vi.fn(),
    ...overrides,
  };
}

// The controller (and the audit helpers it calls) fetch a repository per-entity via
// dataSource.getRepository(Entity). We route VajraUser to its own fake repo so
// assertions about "was the user saved" aren't polluted by audit-log persistence,
// which shares the same dbSourceConnection() mock.
function makeFakeDataSource(userRepo: ReturnType<typeof makeFakeRepo>, auditRepo: ReturnType<typeof makeFakeRepo>) {
  return {
    getRepository: vi.fn((entity: any) => (entity === VajraUser ? userRepo : auditRepo)),
  };
}

function makeReq(body: Record<string, any>, jwtPayload: any): any {
  return {
    body,
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    jwtPayload,
  };
}

function makeRes(): Response {
  return {
    clearCookie: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
  } as unknown as Response;
}

function getError(next: NextFunction): CustomError {
  return (next as any).mock.calls[0][0] as CustomError;
}

describe('update_password', () => {
  let userRepo: ReturnType<typeof makeFakeRepo>;
  let auditRepo: ReturnType<typeof makeFakeRepo>;

  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
    userRepo = makeFakeRepo();
    auditRepo = makeFakeRepo();
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo, auditRepo)]);
  });

  it('rejects with 400 when currentPassword is missing from the request body', async () => {
    const req = makeReq({ newPassword: NEW_PLAINTEXT_PASSWORD }, makeJwtPayload({ id: 1 }));
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(400);
    expect(userRepo.findOne).not.toHaveBeenCalled();
  });

  it('rejects with 400 when newPassword is missing from the request body', async () => {
    const req = makeReq({ currentPassword: CURRENT_PLAINTEXT_PASSWORD }, makeJwtPayload({ id: 1 }));
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err.HttpStatusCode).toBe(400);
    expect(userRepo.findOne).not.toHaveBeenCalled();
  });

  // Previously a bug: the controller read `jwtPayload.id` before checking
  // `!jwtPayload`, so a missing JWT payload threw a raw TypeError instead of
  // the intended 401 CustomError. Now reads `jwtPayload?.id`, so the
  // `if (!jwtPayload || !userId)` guard is reached cleanly.
  it('returns a 401 CustomError (not a raw TypeError) when the request has no JWT payload', async () => {
    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      undefined,
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
  });

  it('rejects with 500 when the database connection source is unavailable', async () => {
    mockedDbSourceConnection.mockReturnValue([]);
    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 1 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err.HttpStatusCode).toBe(500);
  });

  it('rejects with 404 when the user identified by the JWT payload does not exist', async () => {
    userRepo.findOne.mockResolvedValue(null);
    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 42 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err.HttpStatusCode).toBe(404);
    expect(userRepo.save).not.toHaveBeenCalled();
  });

  it('rejects with 401 and does not persist changes when the current password is wrong', async () => {
    const user = makeUser({ id: 10, password_hash: CURRENT_PLAINTEXT_PASSWORD });
    await user.hashPassword();
    const originalHash = user.password_hash;
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: 'totally-wrong-password', newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 10 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
    expect(userRepo.save).not.toHaveBeenCalled();
    expect(userRepo.update).not.toHaveBeenCalled();
    expect(user.password_hash).toBe(originalHash);
    expect(res.json).not.toHaveBeenCalled();
  });

  it('re-hashes and persists the new password when the current password is correct', async () => {
    const user = makeUser({ id: 11, password_hash: CURRENT_PLAINTEXT_PASSWORD });
    await user.hashPassword();
    const originalHash = user.password_hash;
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 11 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(userRepo.save).toHaveBeenCalledTimes(1);
    const savedUser = userRepo.save.mock.calls[0][0];
    expect(savedUser.password_hash).not.toBe(originalHash);
    expect(savedUser.password_hash).not.toBe(NEW_PLAINTEXT_PASSWORD);
    expect(savedUser.password_hash).toMatch(/^\$2/);
    expect(next).not.toHaveBeenCalled();
  });

  it('increments session_version on a successful password change, invalidating other sessions', async () => {
    const user = makeUser({ id: 12, password_hash: CURRENT_PLAINTEXT_PASSWORD, session_version: 3 });
    await user.hashPassword();
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 12 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    const savedUser = userRepo.save.mock.calls[0][0];
    expect(savedUser.session_version).toBe(4);
  });

  it('clears forcePasswordChange on a successful password change', async () => {
    const user = makeUser({ id: 13, password_hash: CURRENT_PLAINTEXT_PASSWORD, forcePasswordChange: true });
    await user.hashPassword();
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 13 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    const savedUser = userRepo.save.mock.calls[0][0];
    expect(savedUser.forcePasswordChange).toBe(false);
  });

  it('clears the access, refresh, and CSRF cookies on a successful password change', async () => {
    const user = makeUser({ id: 14, password_hash: CURRENT_PLAINTEXT_PASSWORD });
    await user.hashPassword();
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 14 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, SECURE_HTTP_ONLY_STRICT_OPTIONS);
    expect(res.clearCookie).toHaveBeenCalledWith(CSRF_COOKIE_NAME, CLIENT_READABLE_STRICT_OPTIONS);
  });

  it('responds with a 200 success payload instructing the user to log in again', async () => {
    const user = makeUser({ id: 15, password_hash: CURRENT_PLAINTEXT_PASSWORD });
    await user.hashPassword();
    userRepo.findOne.mockResolvedValue(user);

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 15 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'Success',
        message: expect.stringContaining('log in again'),
      }),
    );
  });

  it('forwards a wrapped CustomError to next() when persisting the password update throws', async () => {
    const user = makeUser({ id: 16, password_hash: CURRENT_PLAINTEXT_PASSWORD });
    await user.hashPassword();
    userRepo.findOne.mockResolvedValue(user);
    userRepo.save.mockRejectedValue(new Error('db is down'));

    const req = makeReq(
      { currentPassword: CURRENT_PLAINTEXT_PASSWORD, newPassword: NEW_PLAINTEXT_PASSWORD },
      makeJwtPayload({ id: 16 }),
    );
    const res = makeRes();
    const next = vi.fn() as NextFunction;

    await update_password(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(500);
    expect(res.json).not.toHaveBeenCalled();
  });
});
