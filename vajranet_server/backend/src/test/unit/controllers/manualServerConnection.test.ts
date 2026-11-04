import type { NextFunction, Request, Response } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { saveProviderConfig, testProviderConnection } from '../../../controllers/domain-reputation/providerConfigController';
import { getProviderConfig } from '../../../services/domainReputation/client';
import { testManualServerConnection } from '../../../services/domainReputation/providers/manualServer';

const repo = { update: vi.fn(), create: vi.fn((row) => row), save: vi.fn() };

vi.mock('../../../index', () => ({
  dbSourceConnection: () => [null, { isInitialized: true, getRepository: () => repo }],
}));
vi.mock('../../../services/domainReputation/client', () => ({
  getProviderConfig: vi.fn(),
  invalidateDomainReputationConfigCache: vi.fn(),
}));
vi.mock('../../../services/domainReputation/providers/manualServer', () => ({
  testManualServerConnection: vi.fn(),
}));
vi.mock('../../../services/domainReputation/scopeContext', () => ({
  getDomainReputationScopeContext: vi.fn().mockResolvedValue({ scope: { unrestricted: true } }),
  resolveWriteGroupId: vi.fn(),
}));
vi.mock('../../../utils/auditTrailLogger', () => ({ logAuditTrail: vi.fn().mockResolvedValue(undefined) }));

function call(handler: typeof testProviderConnection, body: unknown) {
  const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
  const req = { params: { provider: 'manual' }, body, headers: {} } as unknown as Request;
  return Promise.resolve(handler(req, res as unknown as Response, vi.fn() as NextFunction)).then(() => res);
}

describe('Vajra Reputation Engine URL validation', () => {
  beforeEach(() => {
    vi.mocked(testManualServerConnection).mockReset().mockResolvedValue({ success: true, message: 'ok' });
    vi.mocked(getProviderConfig).mockReset().mockResolvedValue(null);
    repo.save.mockReset();
  });

  it('tests an internal server at its canonical URL', async () => {
    await call(testProviderConnection, { base_url: 'https://10.0.0.5:9000/api/', api_key: 'k' });
    expect(vi.mocked(testManualServerConnection).mock.calls[0][0]).toBe('https://10.0.0.5:9000/api');
  });

  it('also validates a stored URL when none is supplied', async () => {
    vi.mocked(getProviderConfig).mockResolvedValue({ baseUrl: 'http://169.254.169.254', apiKey: 'k' } as never);
    const res = await call(testProviderConnection, {});
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
    expect(testManualServerConnection).not.toHaveBeenCalled();
  });

  it.each([['http://169.254.169.254'], ['http://127.0.0.1:6379'], ['file:///etc/passwd']])(
    'does not contact or save %s',
    async (base_url) => {
      const tested = await call(testProviderConnection, { base_url, api_key: 'k' });
      expect(tested.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
      expect(testManualServerConnection).not.toHaveBeenCalled();

      const saved = await call(saveProviderConfig, { base_url, auth_mode: 'none' });
      expect(saved.status).toHaveBeenCalledWith(400);
      expect(repo.save).not.toHaveBeenCalled();
    },
  );

  it('saves the canonical URL', async () => {
    await call(saveProviderConfig, { base_url: 'https://10.0.0.5:9000/', auth_mode: 'none' });
    expect(repo.save).toHaveBeenCalledWith(expect.objectContaining({ baseUrl: 'https://10.0.0.5:9000' }));
  });
});
