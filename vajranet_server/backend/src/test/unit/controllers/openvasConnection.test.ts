import type { NextFunction, Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { saveOpenVASConfig, testOpenVASConnection } from '../../../controllers/openvas/openvasController';
import { testConnectionWithConfig } from '../../../utils/openvasClient';

vi.mock('../../../index', () => ({ dbSourceConnection: vi.fn() }));
vi.mock('../../../utils/openvasClient', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  testConnectionWithConfig: vi.fn(),
}));
vi.mock('../../../utils/scannerScope', () => ({
  resolveScannerGroupContext: vi.fn().mockResolvedValue({ ok: true, ctx: { groupId: null } }),
  groupIdWhereValue: vi.fn(),
}));

const creds = { gmp_username: 'u', gmp_password: 'p' };

function call(handler: typeof testOpenVASConnection, gsa_url: unknown) {
  const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
  return handler({ body: { gsa_url, ...creds } } as Request, res as unknown as Response, vi.fn() as NextFunction).then(() => res);
}

describe('OpenVAS GSA URL validation', () => {
  beforeEach(() => {
    vi.mocked(testConnectionWithConfig).mockReset().mockResolvedValue({ success: true, version: '1' });
  });

  it.each([
    ['https://10.0.5.187/', 'https://10.0.5.187'],
    [' 10.0.5.187 ', 'https://10.0.5.187'],
    ['http://192.168.1.9:9392', 'http://192.168.1.9:9392'],
  ])('tests %j at %s', async (input, expected) => {
    await call(testOpenVASConnection, input);
    expect(testConnectionWithConfig).toHaveBeenCalledWith({ gsaUrl: expected, gmpUsername: 'u', gmpPassword: 'p' });
  });

  it.each([['http://169.254.169.254'], ['169.254.169.254'], ['http://127.0.0.1:6379'], ['localhost'], ['file:///etc/passwd']])(
    'does not contact or save %s',
    async (input) => {
      const tested = await call(testOpenVASConnection, input);
      expect(tested.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
      const saved = await call(saveOpenVASConfig, input);
      expect(saved.status).toHaveBeenCalledWith(400);
      expect(testConnectionWithConfig).not.toHaveBeenCalled();
    },
  );

  it('rejects a non-string URL', async () => {
    const res = await call(testOpenVASConnection, ['https://10.0.5.187']);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(testConnectionWithConfig).not.toHaveBeenCalled();
  });
});
