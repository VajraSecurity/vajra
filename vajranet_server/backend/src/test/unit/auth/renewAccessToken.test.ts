import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';

import { setAccessTokenCookie } from '../../../utils/renewAccessToken';
import { ACCESS_TOKEN_MAX_AGE, SECURE_HTTP_ONLY_OPTIONS, ACCESS_TOKEN_COOKIE } from '../../../utils/cookieConfig';

describe('setAccessTokenCookie', () => {
  it('sets the access token cookie with the correct name, value, and options', () => {
    const res = { cookie: vi.fn() } as unknown as Response;

    setAccessTokenCookie(res, 'my-access-token');

    expect(res.cookie).toHaveBeenCalledTimes(1);
    expect(res.cookie).toHaveBeenCalledWith(ACCESS_TOKEN_COOKIE, 'my-access-token', {
      ...SECURE_HTTP_ONLY_OPTIONS,
      maxAge: ACCESS_TOKEN_MAX_AGE,
    });
  });
});
