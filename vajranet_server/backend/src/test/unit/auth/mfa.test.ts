import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { generateSync as generateTotpToken } from 'otplib';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

import { dbSourceConnection } from '../../../index';
import {
  setupMfa,
  verifyMfaSetup,
  verifyMfa,
  recoverMfa,
  disableMfa,
} from '../../../controllers/auth/mfa';
import { VajraUser } from '../../../orm/entities/users/Users';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { createMfaToken } from '../../../utils/createJwtToken';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from '../../../utils/cookieConfig';
import { generateTotpSecret, TOTP_DIGITS, TOTP_PERIOD_SECONDS } from '../../../utils/totp';
import { makeUser, makeJwtPayload } from '../../factories';

/** Generates a currently-valid TOTP code for a base32 secret, matching verifyTotpCode's params. */
function generateValidTotpToken(secret: string): string {
  return generateTotpToken({ secret, digits: TOTP_DIGITS, period: TOTP_PERIOD_SECONDS, algorithm: 'sha1' });
}

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;

function makeFakeDataSource(userRepo: any, sessionRepo: any = { save: vi.fn().mockResolvedValue(undefined) }) {
  return {
    getRepository: vi.fn((entity: any) => (entity === VajraUser ? userRepo : sessionRepo)),
    // recoverMfa consumes a recovery code via a raw, atomic
    // array_remove(...) ... RETURNING query rather than repository.update()
    // (see its comment: prevents a race where two concurrent requests both
    // read the pre-splice array and both succeed with the same one-time
    // code). Unused by tests that never reach that code path; configured
    // per-test below where it matters.
    query: vi.fn(),
  };
}

function makeUserRepo(user: any) {
  return {
    findOne: vi.fn().mockResolvedValue(user),
    update: vi.fn().mockResolvedValue(undefined),
    save: vi.fn().mockResolvedValue(undefined),
  };
}

function makeRes(): Response {
  const res: any = {};
  res.status = vi.fn(() => res);
  res.json = vi.fn(() => res);
  res.cookie = vi.fn(() => res);
  return res as Response;
}

function makeReq(overrides: Partial<Request> & { jwtPayload?: any } = {}): Request {
  const req: any = {
    body: {},
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    get: vi.fn(() => 'test-agent'),
    ...overrides,
  };
  return req as Request;
}

function getErrorPassedToNext(next: NextFunction): CustomError {
  return (next as any).mock.calls[0][0] as CustomError;
}

const RECOVERY_CODE_REGEX = /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/;

describe('mfa controller', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
  });

  describe('setupMfa', () => {
    it('returns 401 when the requester is not authenticated', async () => {
      const req = makeReq({ jwtPayload: undefined });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await setupMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Unauthorized' });
    });

    it('forwards a 500 CustomError when the database connection is unavailable', async () => {
      mockedDbSourceConnection.mockReturnValue([]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }) });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await setupMfa(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const err = getErrorPassedToNext(next);
      expect(err).toBeInstanceOf(CustomError);
      expect(err.HttpStatusCode).toBe(500);
    });

    it('returns 400 when MFA is already enabled for the user', async () => {
      const user = makeUser({ id: 1, mfa_enabled: true });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }) });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await setupMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'MFA already enabled' });
    });

    it('generates a secret, QR code and 10 plaintext recovery codes without enabling MFA yet', async () => {
      const user = makeUser({ id: 1, email: 'setup@example.com', mfa_enabled: false, mfa_secret: null });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }) });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await setupMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
      const payload = (res.json as any).mock.calls[0][0];
      expect(payload.status).toBe('Success');
      expect(typeof payload.secret).toBe('string');
      expect(payload.secret.length).toBeGreaterThan(0);
      expect(payload.qrCode).toMatch(/^data:image\/png;base64,/);
      expect(Array.isArray(payload.recoveryCodes)).toBe(true);
      expect(payload.recoveryCodes).toHaveLength(10);
      payload.recoveryCodes.forEach((code: string) => expect(code).toMatch(RECOVERY_CODE_REGEX));
      // Codes should be unique.
      expect(new Set(payload.recoveryCodes).size).toBe(10);

      // Persists the pending secret and hashed recovery codes, but does not enable MFA yet.
      expect(userRepo.update).toHaveBeenCalledTimes(1);
      const [updatedId, updatedFields] = userRepo.update.mock.calls[0];
      expect(updatedId).toBe(1);
      expect(updatedFields.mfa_secret).toBe(payload.secret);
      expect(updatedFields).not.toHaveProperty('mfa_enabled');
      expect(updatedFields.recovery_codes).toHaveLength(10);
      updatedFields.recovery_codes.forEach((hash: string, i: number) => {
        expect(hash).not.toBe(payload.recoveryCodes[i]);
        expect(bcrypt.compareSync(payload.recoveryCodes[i], hash)).toBe(true);
      });
    });
  });

  describe('verifyMfaSetup', () => {
    const securityBody = {
      securityQuestion1: 'First pet name?',
      securityAnswer1: 'Rex',
      securityQuestion2: 'Birth city?',
      securityAnswer2: 'Springfield',
    };

    it('returns 400 when the MFA code is missing', async () => {
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { ...securityBody } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfaSetup(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Missing MFA code' });
    });

    it('returns 400 when security questions/answers are missing', async () => {
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { token: '123456' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfaSetup(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Missing security questions or answers' });
    });

    it('returns 400 when the user has no pending mfa_secret', async () => {
      const user = makeUser({ id: 1, mfa_secret: null });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { token: '123456', ...securityBody } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfaSetup(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'MFA not set up for this user' });
    });

    it('enables MFA and stores hashed security answers when given a correct TOTP code', async () => {
      const secret = generateTotpSecret();
      const validToken = generateValidTotpToken(secret);
      const user = makeUser({ id: 1, mfa_secret: secret, mfa_enabled: false });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { token: validToken, ...securityBody } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfaSetup(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'Success',
        message: 'MFA setup completed successfully.',
      });

      expect(userRepo.update).toHaveBeenCalledTimes(1);
      const [updatedId, updatedFields] = userRepo.update.mock.calls[0];
      expect(updatedId).toBe(1);
      expect(updatedFields.mfa_enabled).toBe(true);
      expect(updatedFields.security_question_1).toBe(securityBody.securityQuestion1);
      expect(updatedFields.security_question_2).toBe(securityBody.securityQuestion2);
      expect(bcrypt.compareSync('rex', updatedFields.security_answer_1_hash)).toBe(true);
      expect(bcrypt.compareSync('springfield', updatedFields.security_answer_2_hash)).toBe(true);
    });

    // The setup dialog sends the code only here, once; the code must stay
    // single-use so a captured code can't be replayed to enable MFA.
    it('rejects the same TOTP code a second time', async () => {
      const secret = generateTotpSecret();
      const validToken = generateValidTotpToken(secret);
      const user = makeUser({ id: 42, mfa_secret: secret, mfa_enabled: false });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const body = { token: validToken, ...securityBody };

      const first = makeRes();
      await verifyMfaSetup(makeReq({ jwtPayload: makeJwtPayload({ id: 42 }), body }), first, vi.fn() as NextFunction);
      expect(first.status).toHaveBeenCalledWith(200);

      const second = makeRes();
      await verifyMfaSetup(makeReq({ jwtPayload: makeJwtPayload({ id: 42 }), body }), second, vi.fn() as NextFunction);
      expect(second.status).toHaveBeenCalledWith(401);
      expect(userRepo.update).toHaveBeenCalledTimes(1);
    });

    it('rejects and does not enable MFA when given an incorrect TOTP code', async () => {
      const secret = generateTotpSecret();
      const user = makeUser({ id: 1, mfa_secret: secret, mfa_enabled: false });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { token: '000000', ...securityBody } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfaSetup(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid MFA code' });
      expect(userRepo.update).not.toHaveBeenCalled();
    });
  });

  describe('verifyMfa (login-time verification)', () => {
    it('returns 401 for an invalid or expired mfaToken', async () => {
      // A normal (non-MFA) JWT signed with the same secret should be rejected because it lacks the mfaToken flag.
      const bogusToken = jwt.sign({ id: 1, email: 'a@example.com' }, process.env.ACCESS_JWT_SECRET as string);
      const req = makeReq({ body: { mfaToken: bogusToken, token: '123456' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid or expired MFA token' });
    });

    it('logs the user in and sets cookies when given a correct TOTP code', async () => {
      const secret = generateTotpSecret();
      const validToken = generateValidTotpToken(secret);
      const user = makeUser({ id: 1, email: 'login@example.com', mfa_secret: secret, mfa_enabled: true });
      const userRepo = makeUserRepo(user);
      const sessionRepo = { save: vi.fn().mockResolvedValue(undefined) };
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo, sessionRepo)]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, token: validToken } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'Success',
        message: 'Login successful. All security tokens set in cookies.',
      });
      expect(sessionRepo.save).toHaveBeenCalledTimes(1);
      expect(res.cookie).toHaveBeenCalledTimes(3);
      const cookieNames = (res.cookie as any).mock.calls.map((c: any[]) => c[0]);
      expect(cookieNames).toContain(ACCESS_TOKEN_COOKIE);
      expect(cookieNames).toContain(REFRESH_TOKEN_COOKIE);
    });

    it('enables MFA on the fly if it was not yet enabled but the secret matched', async () => {
      const secret = generateTotpSecret();
      const validToken = generateValidTotpToken(secret);
      const user = makeUser({ id: 1, email: 'notyetenabled@example.com', mfa_secret: secret, mfa_enabled: false });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, token: validToken } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfa(req, res, next);

      expect(userRepo.save).toHaveBeenCalledTimes(1);
      expect(userRepo.save.mock.calls[0][0].mfa_enabled).toBe(true);
    });

    it('returns 401 when given an incorrect TOTP code', async () => {
      const secret = generateTotpSecret();
      const user = makeUser({ id: 1, mfa_secret: secret, mfa_enabled: true });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, token: '000000' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await verifyMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid MFA code' });
      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  describe('recoverMfa', () => {
    it('returns 401 for an invalid or expired mfaToken', async () => {
      const req = makeReq({ body: { mfaToken: 'not-a-real-token', recoveryCode: 'abcd-abcd-abcd' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await recoverMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid or expired MFA token' });
    });

    it('returns 400 when the user has no recovery codes available', async () => {
      const user = makeUser({ id: 1, recovery_codes: [] });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, recoveryCode: 'abcd-abcd-abcd' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await recoverMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'No recovery codes available for this user' });
    });

    it('logs the user in, consumes the matching recovery code, and makes it single-use', async () => {
      const plainCode = 'abcd-1234-ef56';
      const otherCode = '1111-2222-3333';
      const hashedCodes = [bcrypt.hashSync(otherCode, 12), bcrypt.hashSync(plainCode, 12)];
      const user = makeUser({ id: 1, email: 'recover@example.com', recovery_codes: [...hashedCodes] });
      const userRepo = makeUserRepo(user);
      const sessionRepo = { save: vi.fn().mockResolvedValue(undefined) };
      const dataSource = makeFakeDataSource(userRepo, sessionRepo);
      // Mirrors the real `array_remove(...) ... RETURNING recovery_codes`
      // query: the used code's hash is gone, the other one remains.
      const remainingCodes = [hashedCodes[0]];
      dataSource.query.mockResolvedValue([{ recovery_codes: remainingCodes }]);
      mockedDbSourceConnection.mockReturnValue([dataSource]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, recoveryCode: plainCode } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await recoverMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'Success',
        message: 'Login successful via recovery code. All security tokens set in cookies.',
      });
      expect(res.cookie).toHaveBeenCalledTimes(3);
      expect(sessionRepo.save).toHaveBeenCalledTimes(1);

      // The atomic UPDATE targeted this user id and the matched code's hash
      // (not a blind array write), and only the used code was removed.
      expect(dataSource.query).toHaveBeenCalledTimes(1);
      const [, queryParams] = dataSource.query.mock.calls[0];
      expect(queryParams).toEqual([user.id, hashedCodes[1]]);
      expect(remainingCodes).toEqual([hashedCodes[0]]);

      // Simulate the persisted state after the first successful use, then retry with the same code.
      const userAfterFirstUse = makeUser({
        id: 1,
        email: 'recover@example.com',
        recovery_codes: [...remainingCodes],
      });
      const userRepo2 = makeUserRepo(userAfterFirstUse);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo2, sessionRepo)]);
      const req2 = makeReq({ body: { mfaToken, recoveryCode: plainCode } });
      const res2 = makeRes();
      const next2 = vi.fn() as NextFunction;

      await recoverMfa(req2, res2, next2);

      expect(res2.status).toHaveBeenCalledWith(401);
      expect(res2.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid recovery code' });
      expect(userRepo2.update).not.toHaveBeenCalled();
    });

    it('returns 401 when the recovery code does not match any stored hash', async () => {
      const user = makeUser({ id: 1, recovery_codes: [bcrypt.hashSync('real-code-here', 12)] });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const mfaToken = createMfaToken({ id: 1, email: user.email });
      const req = makeReq({ body: { mfaToken, recoveryCode: 'totally-wrong-code' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await recoverMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Invalid recovery code' });
      expect(userRepo.update).not.toHaveBeenCalled();
    });

    it('returns 404 when the decoded user cannot be found', async () => {
      const userRepo = makeUserRepo(null);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const mfaToken = createMfaToken({ id: 999, email: 'ghost@example.com' });
      const req = makeReq({ body: { mfaToken, recoveryCode: 'abcd-1234-ef56' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await recoverMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'User not found' });
    });
  });

  describe('disableMfa', () => {
    it('returns 400 when no password is provided', async () => {
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: {} });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await disableMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Password is required to disable MFA' });
    });

    it('returns 401 when the requester is not authenticated', async () => {
      const req = makeReq({ jwtPayload: undefined, body: { password: 'whatever' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await disableMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Unauthorized' });
    });

    it('returns 401 and does not persist changes when the password is incorrect', async () => {
      const user = makeUser({ id: 1, password_hash: bcrypt.hashSync('CorrectPassw0rd!', 12), mfa_enabled: true });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { password: 'WrongPassword!' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await disableMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'Incorrect password' });
      expect(userRepo.update).not.toHaveBeenCalled();
    });

    it('clears mfa_enabled, mfa_secret, recovery_codes and security questions when the password is correct', async () => {
      const user = makeUser({
        id: 1,
        password_hash: bcrypt.hashSync('CorrectPassw0rd!', 12),
        mfa_enabled: true,
        mfa_secret: 'SOMEBASE32SECRET',
        recovery_codes: [bcrypt.hashSync('leftover-code', 12)],
        security_question_1: 'Q1',
        security_answer_1_hash: bcrypt.hashSync('a1', 12),
        security_question_2: 'Q2',
        security_answer_2_hash: bcrypt.hashSync('a2', 12),
      });
      const userRepo = makeUserRepo(user);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { password: 'CorrectPassw0rd!' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await disableMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'Success',
        message: 'MFA has been successfully disabled.',
      });
      expect(userRepo.update).toHaveBeenCalledWith(1, {
        mfa_enabled: false,
        mfa_secret: null,
        recovery_codes: [],
        security_question_1: null,
        security_answer_1_hash: null,
        security_question_2: null,
        security_answer_2_hash: null,
      });
    });

    it('returns 404 when the user cannot be found', async () => {
      const userRepo = makeUserRepo(null);
      mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(userRepo)]);
      const req = makeReq({ jwtPayload: makeJwtPayload({ id: 1 }), body: { password: 'whatever' } });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await disableMfa(req, res, next);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ status: 'Fail', message: 'User not found' });
    });
  });
});
