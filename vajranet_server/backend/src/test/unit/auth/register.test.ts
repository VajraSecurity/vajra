import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

vi.mock('../../../utils/auditTrailLogger', () => ({
  logAuditTrail: vi.fn().mockResolvedValue(undefined),
}));

import { dbSourceConnection } from '../../../index';
import { logAuditTrail } from '../../../utils/auditTrailLogger';
import { user_register } from '../../../controllers/auth/register';
import { makeUser } from '../../factories';

interface FakeEnvOptions {
  userCount?: number;
  superAdminCount?: number;
  existingUser?: unknown;
  // `any`, not a plain function signature: every real caller passes a
  // vi.fn() mock, and callers read `.mock.calls` off `fakeRepo.save` — a
  // precise function-signature type here would make TS pick the narrower
  // half of the `saveImpl ?? vi.fn(...)` union below and lose `.mock`.
  saveImpl?: any;
}

function createFakeEnv(options: FakeEnvOptions = {}) {
  const { userCount = 0, superAdminCount = 0, existingUser = null, saveImpl } = options;

  const fakeRepo = {
    count: vi.fn((queryOptions?: { where?: { role?: string } }) => {
      if (queryOptions?.where?.role) {
        return Promise.resolve(superAdminCount);
      }
      return Promise.resolve(userCount);
    }),
    findOne: vi.fn().mockResolvedValue(existingUser),
    save:
      saveImpl ??
      vi.fn(async (user: any) => {
        user.id = user.id ?? 42;
        return user;
      }),
  };

  const fakeQueryRunner = {
    connect: vi.fn().mockResolvedValue(undefined),
    startTransaction: vi.fn().mockResolvedValue(undefined),
    commitTransaction: vi.fn().mockResolvedValue(undefined),
    rollbackTransaction: vi.fn().mockResolvedValue(undefined),
    release: vi.fn().mockResolvedValue(undefined),
    manager: {
      getRepository: vi.fn(() => fakeRepo),
    },
  };

  const fakeDataSource = {
    createQueryRunner: vi.fn(() => fakeQueryRunner),
  };

  (dbSourceConnection as unknown as ReturnType<typeof vi.fn>).mockReturnValue([fakeDataSource]);

  return { fakeRepo, fakeQueryRunner, fakeDataSource };
}

function makeReq(body: Record<string, unknown>): Request {
  return {
    body,
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    get: vi.fn().mockReturnValue('test-agent'),
  } as unknown as Request;
}

function makeRes(): Response {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    cookie: vi.fn(),
    clearCookie: vi.fn(),
  } as unknown as Response;
}

describe('user_register', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates the first user as Super Administrator regardless of the requested role', async () => {
    const { fakeRepo, fakeQueryRunner } = createFakeEnv({ userCount: 0, superAdminCount: 0, existingUser: null });
    const req = makeReq({
      name: 'First User',
      email: 'first@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
      role: 'Viewer',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(fakeRepo.save).toHaveBeenCalledTimes(1);
    const savedUser = fakeRepo.save.mock.calls[0][0];
    expect(savedUser.role).toBe('Super Administrator');
    expect(fakeQueryRunner.commitTransaction).toHaveBeenCalledTimes(1);
    expect(fakeQueryRunner.rollbackTransaction).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(next).not.toHaveBeenCalled();
  });

  it('hashes the plaintext password before saving so it is never persisted in plaintext', async () => {
    const { fakeRepo } = createFakeEnv({ userCount: 0, superAdminCount: 0, existingUser: null });
    const plaintextPassword = 'PlaintextPass1!';
    const req = makeReq({
      name: 'First User',
      email: 'hashcheck@example.com',
      password: plaintextPassword,
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    const savedUser = fakeRepo.save.mock.calls[0][0];
    expect(savedUser.password_hash).not.toBe(plaintextPassword);
    expect(savedUser.password_hash.startsWith('$2')).toBe(true);
  });

  it('assigns the requested valid role when a Super Administrator already exists', async () => {
    const { fakeRepo } = createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser: null });
    const req = makeReq({
      name: 'Second User',
      email: 'second@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
      role: 'Group Admin',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    const savedUser = fakeRepo.save.mock.calls[0][0];
    expect(savedUser.role).toBe('Group Admin');
  });

  it('defaults to Viewer when the requested role is not a recognized USER_ROLES value', async () => {
    const { fakeRepo } = createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser: null });
    const req = makeReq({
      name: 'Third User',
      email: 'third@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
      role: 'NotARealRole',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    const savedUser = fakeRepo.save.mock.calls[0][0];
    expect(savedUser.role).toBe('Viewer');
  });

  it('rejects registration with a 409 CustomError when the email already exists', async () => {
    const existingUser = makeUser({ email: 'dup@example.com' });
    const { fakeRepo, fakeQueryRunner } = createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser });
    const req = makeReq({
      name: 'Duplicate User',
      email: 'dup@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(fakeRepo.save).not.toHaveBeenCalled();
    expect(fakeQueryRunner.rollbackTransaction).toHaveBeenCalledTimes(1);
    expect(fakeQueryRunner.commitTransaction).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0][0];
    expect(err.HttpStatusCode).toBe(409);
    expect(err.message).toBe('User already exists');
  });

  it('logs a failed audit trail entry when the email already exists', async () => {
    const existingUser = makeUser({ email: 'dup@example.com' });
    createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser });
    const req = makeReq({
      name: 'Duplicate User',
      email: 'dup@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(logAuditTrail).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'USER_REGISTER',
        status: 'failure',
        email: 'dup@example.com',
        details: { reason: 'user_already_exists' },
      }),
    );
  });

  it('rejects registration with a 403 CustomError when the max user count has been reached', async () => {
    const { fakeRepo, fakeQueryRunner } = createFakeEnv({ userCount: 100, superAdminCount: 1, existingUser: null });
    const req = makeReq({
      name: 'Overflow User',
      email: 'overflow@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(fakeRepo.save).not.toHaveBeenCalled();
    expect(fakeQueryRunner.rollbackTransaction).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0][0];
    expect(err.HttpStatusCode).toBe(403);
  });

  it('blocks creating a second Super Administrator with a 409 CustomError', async () => {
    const { fakeRepo, fakeQueryRunner } = createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser: null });
    const req = makeReq({
      name: 'Aspiring Admin',
      email: 'aspiring@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
      role: 'Super Administrator',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(fakeRepo.save).not.toHaveBeenCalled();
    expect(fakeQueryRunner.rollbackTransaction).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0][0];
    expect(err.HttpStatusCode).toBe(409);
    expect(err.message).toBe('Only one Super Administrator is allowed.');
  });

  it('returns a 500 CustomError when no database connection source is available', async () => {
    (dbSourceConnection as unknown as ReturnType<typeof vi.fn>).mockReturnValue([]);
    const req = makeReq({
      name: 'No DB User',
      email: 'nodb@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0][0];
    expect(err.HttpStatusCode).toBe(500);
  });

  it('wraps unexpected save errors in a 400 CustomError and rolls back the transaction', async () => {
    const saveImpl = vi.fn().mockRejectedValue(new Error('unique constraint violation'));
    const { fakeQueryRunner } = createFakeEnv({ userCount: 5, superAdminCount: 1, existingUser: null, saveImpl });
    const req = makeReq({
      name: 'Erroring User',
      email: 'erroring@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(fakeQueryRunner.rollbackTransaction).toHaveBeenCalledTimes(1);
    expect(fakeQueryRunner.commitTransaction).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0][0];
    expect(err.HttpStatusCode).toBe(400);
  });

  it('logs a successful audit trail entry with the created user id and email on success', async () => {
    createFakeEnv({ userCount: 0, superAdminCount: 0, existingUser: null });
    const req = makeReq({
      name: 'Audit User',
      email: 'audit@example.com',
      password: 'PlaintextPass1!',
      mobile: '9999999999',
      company: 'Acme',
      address: '123 Main St',
    });
    const res = makeRes();
    const next = vi.fn();

    await user_register(req, res, next);

    expect(logAuditTrail).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'USER_REGISTER',
        status: 'success',
        userId: 42,
        email: 'audit@example.com',
      }),
    );
  });
});
