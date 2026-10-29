import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';

import { setCsrfTokenCookie } from '../../../utils/renewCSRFToken';
import { CSRF_COOKIE_NAME, CLIENT_READABLE_OPTIONS, REFRESH_TOKEN_MAX_AGE } from '../../../utils/cookieConfig';

describe('setCsrfTokenCookie', () => {
  it('sets the csrf token cookie with the correct name, value, and options', () => {
    const res = { cookie: vi.fn() } as unknown as Response;

    setCsrfTokenCookie(res, 'my-csrf-token');

    expect(res.cookie).toHaveBeenCalledTimes(1);
    // maxAge matches the refresh token's lifetime (see setCsrfTokenCookie's
    // comment) — without it this was a session cookie, wiped on browser
    // restart while the user was still authenticated via the surviving
    // access/refresh cookies, breaking every mutating request until the
    // access token happened to near expiry and get silently renewed.
    expect(res.cookie).toHaveBeenCalledWith(CSRF_COOKIE_NAME, 'my-csrf-token', {
      ...CLIENT_READABLE_OPTIONS,
      maxAge: REFRESH_TOKEN_MAX_AGE,
    });
  });
});
