import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

import { dbSourceConnection } from '../../../index';
import { requireAdmin } from '../../../middleware/requireAdmin';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { makeUser, makeSuperAdmin } from '../../factories';

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;

function makeFakeDataSource(fakeRepo: any) {
  return { getRepository: vi.fn(() => fakeRepo) };
}

function makeReq(jwtPayload: any): Request {
  return { jwtPayload } as unknown as Request;
}

function getError(next: NextFunction): CustomError {
  return (next as any).mock.calls[0][0] as CustomError;
}

describe('requireAdmin', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
  });

  it('rejects when req.jwtPayload is missing', async () => {
    const req = makeReq(undefined);
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
  });

  it('returns 500 when the database is unavailable', async () => {
    mockedDbSourceConnection.mockReturnValue([]);
    const req = makeReq({ id: 1 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(500);
  });

  it('rejects when the user is not found', async () => {
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(null), update: vi.fn() };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ id: 999 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
  });

  it('rejects a Viewer with 403', async () => {
    const user = makeUser({ id: 5, role: 'Viewer' });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(user), update: vi.fn() };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ id: 5 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
    expect(fakeRepo.update).not.toHaveBeenCalled();
  });

  it('allows a Group Admin through with no error', async () => {
    const user = makeUser({ id: 6, role: 'Group Admin' });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(user), update: vi.fn() };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ id: 6 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(fakeRepo.update).not.toHaveBeenCalled();
  });

  it('allows a Super Administrator through with no error', async () => {
    const user = makeSuperAdmin({ id: 7 });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(user), update: vi.fn() };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ id: 7 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('normalizes an invalid stored role to Viewer, persists the correction, and rejects with 403', async () => {
    const user = makeUser({ id: 8, role: 'BogusRole' as any });
    const fakeRepo = { findOne: vi.fn().mockResolvedValue(user), update: vi.fn().mockResolvedValue(undefined) };
    mockedDbSourceConnection.mockReturnValue([makeFakeDataSource(fakeRepo)]);
    const req = makeReq({ id: 8 });
    const next = vi.fn() as NextFunction;

    await requireAdmin(req, {} as Response, next);

    expect(fakeRepo.update).toHaveBeenCalledWith(8, { role: 'Viewer' });
    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
  });
});
