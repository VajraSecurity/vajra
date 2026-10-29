import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

import { checkCsrf } from '../../../middleware/checkCSRFToken';
import { CSRF_COOKIE_NAME } from '../../../utils/cookieConfig';
import { CustomError } from '../../../utils/response/custom-error/CustomError';

const CSRF_HEADER_NAME = process.env.CSRF_HEADER_NAME as string;

function makeReq(cookies: Record<string, string>, headerValue: string | undefined): Request {
  return {
    cookies,
    header: vi.fn((name: string) => (name === CSRF_HEADER_NAME ? headerValue : undefined)),
  } as unknown as Request;
}

describe('checkCsrf', () => {
  it('rejects when the CSRF cookie is missing', async () => {
    const req = makeReq({}, 'some-token');
    const next = vi.fn() as NextFunction;

    await checkCsrf(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = (next as any).mock.calls[0][0] as CustomError;
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
    expect(err.message).toContain('Cookie not found');
  });

  it('rejects when the CSRF header is missing', async () => {
    const req = makeReq({ [CSRF_COOKIE_NAME]: 'some-token' }, undefined);
    const next = vi.fn() as NextFunction;

    await checkCsrf(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = (next as any).mock.calls[0][0] as CustomError;
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
    expect(err.message).toContain('Header');
  });

  // A cookie/header mismatch is no longer an immediate reject — checkCsrf now
  // consults a grace-period "successor" token (Redis or its in-memory
  // fallback) before rejecting, which makes the mismatch branch async.
  it('rejects when the cookie and header differ in length', async () => {
    const req = makeReq({ [CSRF_COOKIE_NAME]: 'short' }, 'much-longer-token-value');
    const next = vi.fn() as NextFunction;

    await checkCsrf(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = (next as any).mock.calls[0][0] as CustomError;
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
    expect(err.message).toContain('do not match');
  });

  it('rejects when the cookie and header are the same length but different content', async () => {
    const req = makeReq({ [CSRF_COOKIE_NAME]: 'aaaaaaaaaa' }, 'bbbbbbbbbb');
    const next = vi.fn() as NextFunction;

    await checkCsrf(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = (next as any).mock.calls[0][0] as CustomError;
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
    expect(err.message).toContain('do not match');
  });

  it('calls next with no error when the cookie and header tokens match', async () => {
    const token = 'matching-csrf-token-value';
    const req = makeReq({ [CSRF_COOKIE_NAME]: token }, token);
    const next = vi.fn() as NextFunction;

    await checkCsrf(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });
});
