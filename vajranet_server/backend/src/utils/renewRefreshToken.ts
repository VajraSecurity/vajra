import { Response } from 'express';
import { REFRESH_TOKEN_MAX_AGE, SECURE_HTTP_ONLY_OPTIONS, REFRESH_TOKEN_COOKIE } from './cookieConfig';

export const setRefreshTokenCookie = (res: Response, token: string): void => {
  res.cookie(REFRESH_TOKEN_COOKIE, token, {
    ...SECURE_HTTP_ONLY_OPTIONS,
    maxAge: REFRESH_TOKEN_MAX_AGE, 
  });
};