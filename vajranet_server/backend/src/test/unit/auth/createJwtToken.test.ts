import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';

import {
  createAccessToken,
  createRefreshToken,
  createMfaToken,
  verifyMfaToken,
  generateCsrfToken,
} from '../../../utils/createJwtToken';
import { makeJwtPayload } from '../../factories';

const ACCESS_SECRET = process.env.ACCESS_JWT_SECRET as string;
const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET as string;

describe('createAccessToken', () => {
  it('produces a token that verifies with the access secret and carries the payload claims', () => {
    const payload = makeJwtPayload({ id: 42, email: 'alice@example.com' });

    const token = createAccessToken(payload);
    const decoded = jwt.verify(token, ACCESS_SECRET) as jwt.JwtPayload;

    expect(decoded.id).toBe(42);
    expect(decoded.email).toBe('alice@example.com');
    expect(decoded.name).toBe(payload.name);
  });

  it('throws when verified with the wrong secret', () => {
    const token = createAccessToken(makeJwtPayload());

    expect(() => jwt.verify(token, 'totally-wrong-secret-value')).toThrow();
  });

  it('is not verifiable with the refresh secret', () => {
    const token = createAccessToken(makeJwtPayload());

    expect(() => jwt.verify(token, REFRESH_SECRET)).toThrow();
  });
});

describe('createRefreshToken', () => {
  it('produces a token that verifies with the refresh secret and carries the payload claims', () => {
    const payload = makeJwtPayload({ id: 7, sessionId: 99 });

    const token = createRefreshToken(payload);
    const decoded = jwt.verify(token, REFRESH_SECRET) as jwt.JwtPayload;

    expect(decoded.id).toBe(7);
    expect(decoded.sessionId).toBe(99);
  });

  it('throws when verified with the wrong secret', () => {
    const token = createRefreshToken(makeJwtPayload());

    expect(() => jwt.verify(token, ACCESS_SECRET)).toThrow();
  });
});

describe('createMfaToken', () => {
  it('produces a token that verifies with the access secret and is flagged as an mfa token', () => {
    const token = createMfaToken({ id: 5, email: 'mfa@example.com' });
    const decoded = jwt.verify(token, ACCESS_SECRET) as jwt.JwtPayload & { mfaToken?: boolean };

    expect(decoded.id).toBe(5);
    expect(decoded.email).toBe('mfa@example.com');
    expect(decoded.mfaToken).toBe(true);
  });

  it('throws when verified with the wrong secret', () => {
    const token = createMfaToken({ id: 5, email: 'mfa@example.com' });

    expect(() => jwt.verify(token, 'wrong-secret')).toThrow();
  });
});

describe('verifyMfaToken', () => {
  it('returns the decoded payload for a genuine mfa token', () => {
    const token = createMfaToken({ id: 12, email: 'valid@example.com' });

    const decoded = verifyMfaToken(token);

    expect(decoded.id).toBe(12);
    expect(decoded.email).toBe('valid@example.com');
    expect(decoded.mfaToken).toBe(true);
  });

  it('rejects a plain access token that lacks the mfaToken flag', () => {
    const token = createAccessToken(makeJwtPayload());

    expect(() => verifyMfaToken(token)).toThrow('Invalid token type');
  });

  it('rejects a manually signed token without mfaToken: true', () => {
    const token = jwt.sign({ id: 1, email: 'x@example.com' }, ACCESS_SECRET, { expiresIn: '15m' });

    expect(() => verifyMfaToken(token)).toThrow('Invalid token type');
  });

  it('rejects a token signed with the wrong secret', () => {
    const token = jwt.sign({ id: 1, email: 'x@example.com', mfaToken: true }, 'wrong-secret', { expiresIn: '15m' });

    expect(() => verifyMfaToken(token)).toThrow();
  });
});

describe('generateCsrfToken', () => {
  it('returns a UUID-shaped token when CSRF_TOKEN_STRATEGY is UUID', () => {
    expect(process.env.CSRF_TOKEN_STRATEGY).toBe('UUID');

    const token = generateCsrfToken();

    expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });

  it('returns a different token on each call', () => {
    const first = generateCsrfToken();
    const second = generateCsrfToken();

    expect(first).not.toBe(second);
  });
});
