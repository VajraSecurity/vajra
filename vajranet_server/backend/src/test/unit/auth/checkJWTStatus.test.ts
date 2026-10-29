import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import type { Request } from 'express';

import { getRefreshTokenStatus } from '../../../middleware/checkJWTStatus';
import { REFRESH_TOKEN_COOKIE } from '../../../utils/cookieConfig';
import { makeJwtPayload } from '../../factories';

const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET as string;

function makeReq(cookies: Record<string, string>): Request {
  return { cookies } as unknown as Request;
}

describe('getRefreshTokenStatus', () => {
  it('returns NotFound when no refresh token cookie is present', () => {
    const req = makeReq({});

    const result = getRefreshTokenStatus(req);

    expect(result).toEqual({ isValid: false, errorType: 'NotFound' });
  });

  it('returns Expired for an expired refresh token', () => {
    const payload = makeJwtPayload();
    const token = jwt.sign(payload, REFRESH_SECRET, { algorithm: 'HS256', expiresIn: -10 });
    const req = makeReq({ [REFRESH_TOKEN_COOKIE]: token });

    const result = getRefreshTokenStatus(req);

    expect(result).toEqual({ isValid: false, errorType: 'Expired' });
  });

  it('returns Invalid for a token signed with the wrong secret', () => {
    const payload = makeJwtPayload();
    const token = jwt.sign(payload, 'a-completely-different-secret-value-1234567890', { algorithm: 'HS256' });
    const req = makeReq({ [REFRESH_TOKEN_COOKIE]: token });

    const result = getRefreshTokenStatus(req);

    expect(result).toEqual({ isValid: false, errorType: 'Invalid' });
  });

  it('returns Invalid for a malformed token string', () => {
    const req = makeReq({ [REFRESH_TOKEN_COOKIE]: 'not-a-real-jwt' });

    const result = getRefreshTokenStatus(req);

    expect(result).toEqual({ isValid: false, errorType: 'Invalid' });
  });

  it('returns isValid true with iat/exp stripped from the payload for a valid token', () => {
    const payload = makeJwtPayload({ id: 42, email: 'valid@example.com' });
    const token = jwt.sign(payload, REFRESH_SECRET, { algorithm: 'HS256', expiresIn: '7d' });
    const req = makeReq({ [REFRESH_TOKEN_COOKIE]: token });

    const result = getRefreshTokenStatus(req);

    expect(result.isValid).toBe(true);
    expect(result.errorType).toBeUndefined();
    expect(result.payload).toBeDefined();
    expect(result.payload).not.toHaveProperty('iat');
    expect(result.payload).not.toHaveProperty('exp');
    expect(result.payload?.id).toBe(42);
    expect(result.payload?.email).toBe('valid@example.com');
  });
});
