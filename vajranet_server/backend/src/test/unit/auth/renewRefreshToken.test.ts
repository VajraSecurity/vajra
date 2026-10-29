import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';

import { setRefreshTokenCookie } from '../../../utils/renewRefreshToken';
import { REFRESH_TOKEN_MAX_AGE, SECURE_HTTP_ONLY_OPTIONS, REFRESH_TOKEN_COOKIE } from '../../../utils/cookieConfig';

describe('setRefreshTokenCookie', () => {
  it('sets the refresh token cookie with the correct name, value, and options', () => {
    const res = { cookie: vi.fn() } as unknown as Response;

    setRefreshTokenCookie(res, 'my-refresh-token');

    expect(res.cookie).toHaveBeenCalledTimes(1);
    expect(res.cookie).toHaveBeenCalledWith(REFRESH_TOKEN_COOKIE, 'my-refresh-token', {
      ...SECURE_HTTP_ONLY_OPTIONS,
      maxAge: REFRESH_TOKEN_MAX_AGE,
    });
  });
});
