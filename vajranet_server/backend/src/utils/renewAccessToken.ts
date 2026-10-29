import { Response } from 'express';
import { ACCESS_TOKEN_MAX_AGE, SECURE_HTTP_ONLY_OPTIONS, ACCESS_TOKEN_COOKIE } from './cookieConfig';


export const setAccessTokenCookie = (res: Response, token: string): void => {
  res.cookie(ACCESS_TOKEN_COOKIE, token, {
    ...SECURE_HTTP_ONLY_OPTIONS,
    maxAge: ACCESS_TOKEN_MAX_AGE, 
  });
};