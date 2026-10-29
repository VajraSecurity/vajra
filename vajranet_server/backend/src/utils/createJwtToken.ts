import jwt, { SignOptions } from 'jsonwebtoken';
import type { StringValue as MsStringValue } from 'ms';

import { JwtPayload } from '../types/JwtPayload';
import { RenewAccessJwtPayload } from '../types/RenewAccessJwtPayload';
import { JWT_ALGORITHM } from '../consts';
import { getLogger } from './logger';

const logger = getLogger('auth.tokens');

const createAccessTokenInternal = (payload: any, expiresIn: MsStringValue): string => {
  const secret = process.env.ACCESS_JWT_SECRET!;
  const options: SignOptions = {
    expiresIn: expiresIn,
    algorithm: JWT_ALGORITHM,
  };

  try {
    return jwt.sign(payload, secret, options);
  } catch (err) {
    // Every caller (login.ts, mfa.ts, updateProfile.ts) wraps this behind its
    // own generic outer catch shared with unrelated steps (cookie setting,
    // CSRF generation, session save) — without a log here, a signing failure
    // (e.g. missing/invalid secret) is indistinguishable in the logs from
    // whichever other step happened to throw in the same try block.
    logger.error({ err, userId: payload?.id }, 'Failed to sign access token');
    throw err;
  }
};

const createRefreshTokenInternal = (payload: any, expiresIn: MsStringValue): string => {
  const secret = process.env.REFRESH_JWT_SECRET!;
  const options: SignOptions = {
    expiresIn: expiresIn,
    algorithm: JWT_ALGORITHM,
  };

  try {
    return jwt.sign(payload, secret, options);
  } catch (err) {
    logger.error({ err, userId: payload?.id }, 'Failed to sign refresh token');
    throw err;
  }
};

export const createAccessToken = (payload: JwtPayload): string => {
  const expiresIn = process.env.ACCESS_JWT_EXPIRATION as MsStringValue;
  if (!expiresIn) throw new Error('ACCESS_JWT_EXPIRATION environment variable is missing.');

  return createAccessTokenInternal(payload, expiresIn);
};


export const createRefreshToken = (payload: JwtPayload | RenewAccessJwtPayload): string => {
  const expiresIn = process.env.REFRESH_JWT_EXPIRATION as MsStringValue;
  if (!expiresIn) throw new Error('REFRESH_JWT_EXPIRATION environment variable is missing.');

  return createRefreshTokenInternal(payload, expiresIn);
};
export const createMfaToken = (payload: { id: number, email: string }): string => {
  const secret = process.env.ACCESS_JWT_SECRET!;
  const options: SignOptions = { expiresIn: '15m' };
  try {
    return jwt.sign({ ...payload, mfaToken: true }, secret, options);
  } catch (err) {
    // Same rationale as createAccessTokenInternal/createRefreshTokenInternal:
    // login.ts's only caller wraps this in a generic catch shared with the
    // MFA-required response path, so a signing failure here would otherwise
    // leave no trace distinguishing it from anything else in that block.
    logger.error({ err, userId: payload?.id }, 'Failed to sign MFA token');
    throw err;
  }
};

export const verifyMfaToken = (token: string): any => {
  const secret = process.env.ACCESS_JWT_SECRET!;
  const decoded = jwt.verify(token, secret, { algorithms: [JWT_ALGORITHM] }) as any;
  if (!decoded.mfaToken) throw new Error('Invalid token type');
  return decoded;
};


import { randomBytes, randomUUID } from 'crypto';
import { CSRF_STRATEGY_RANDOM_BYTES, CSRF_STRATEGY_UUID } from '../consts';

const CSRF_TOKEN_STRATEGY = String(process.env.CSRF_TOKEN_STRATEGY);

export const generateCsrfToken = (): string => {
  try {
    switch (CSRF_TOKEN_STRATEGY.toUpperCase()) {
      case CSRF_STRATEGY_RANDOM_BYTES:
        return randomBytes(16).toString('hex');

      case CSRF_STRATEGY_UUID:
      default:
        return randomUUID();
    }
  } catch (error) {
    // Distinguish between different types of crypto failures
    if (error instanceof Error) {
      if (error.message.includes('ENOTDIR') || error.message.includes('ENOENT')) {
        logger.error({ err: error }, 'Crypto entropy source unavailable');
        throw new Error('System entropy source unavailable. Cannot generate secure CSRF token.', { cause: error });
      }
      if (error.message.includes('permission')) {
        logger.error({ err: error }, 'Permission denied accessing entropy source');
        throw new Error('Permission denied. Cannot generate secure CSRF token.', { cause: error });
      }
    }
    logger.error({ err: error }, 'Failed to generate cryptographically secure CSRF token');
    throw new Error('Could not generate CSRF token due to system crypto error.', { cause: error });
  }
};

