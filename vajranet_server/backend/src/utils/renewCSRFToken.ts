import { Response } from 'express';
import { CSRF_COOKIE_NAME, CLIENT_READABLE_OPTIONS, REFRESH_TOKEN_MAX_AGE } from './cookieConfig';


export const setCsrfTokenCookie = (res: Response, csrfToken: string): void => {
  res.cookie(CSRF_COOKIE_NAME, csrfToken, {
    ...CLIENT_READABLE_OPTIONS,
    // Without an explicit maxAge this is a browser-session cookie, while the
    // access/refresh token cookies both carry one and survive a browser/PC
    // restart. That mismatch left the CSRF cookie wiped on restart while the
    // user was still authenticated — every mutating request then failed
    // checkCsrf with "Cookie not found" until the access token happened to
    // near expiry and get silently renewed. Match the refresh token's
    // lifetime so the CSRF cookie never outlives (or under-lives) the
    // session it protects.
    maxAge: REFRESH_TOKEN_MAX_AGE,
  });
};