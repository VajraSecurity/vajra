import type { NextFunction, Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { saveNessusConfig, testNessusConnection } from '../../../controllers/nessus/nessusController';
import { createNessusInstanceFromRaw } from '../../../utils/nessusClient';

vi.mock('../../../index', () => ({ dbSourceConnection: vi.fn() }));
vi.mock('../../../utils/nessusClient', () => ({
  getNessusClient: vi.fn(),
  invalidateNessusClientCache: vi.fn(),
  createNessusInstanceFromRaw: vi.fn(),
}));
vi.mock('../../../utils/scannerScope', () => ({
  resolveScannerGroupContext: vi.fn().mockResolvedValue({ ok: true, ctx: { groupId: null } }),
  groupIdWhereValue: vi.fn(),
}));

const keys = { access_key: 'a', secret_key: 's' };

function response() {
  return { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
}

describe('Nessus URL validation', () => {
  const get = vi.fn();

  beforeEach(() => {
    get.mockReset().mockResolvedValue({ data: { status: 'ready' } });
    vi.mocked(createNessusInstanceFromRaw).mockReset().mockReturnValue({ get } as never);
  });

  it('tests an internal scanner at its canonical URL', async () => {
    const res = response();
    await testNessusConnection({ body: { nessus_url: 'https://192.168.1.50:8834/', ...keys } } as Request, res as unknown as Response, vi.fn() as NextFunction);
    expect(createNessusInstanceFromRaw).toHaveBeenCalledWith('https://192.168.1.50:8834', 'a', 's');
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: true }));
  });

  it.each([['http://169.254.169.254'], ['http://127.0.0.1:6379'], ['file:///etc/passwd'], [['https://8.8.8.8']]])(
    'reports %j as a failed test without contacting it',
    async (nessus_url) => {
      const res = response();
      await testNessusConnection({ body: { nessus_url, ...keys } } as Request, res as unknown as Response, vi.fn() as NextFunction);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
      expect(createNessusInstanceFromRaw).not.toHaveBeenCalled();
    },
  );

  it('refuses to save a reserved address', async () => {
    const res = response();
    await saveNessusConfig({ body: { nessus_url: 'http://169.254.169.254', ...keys } } as Request, res as unknown as Response, vi.fn() as NextFunction);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(createNessusInstanceFromRaw).not.toHaveBeenCalled();
  });
});
