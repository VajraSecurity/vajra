import type { Request, Response } from 'express';
import { describe, expect, it, vi } from 'vitest';
import { saveProviderConfig } from '../../../controllers/domain-reputation/providerConfigController';
import { isValidHeaderName } from '../../../services/domainReputation/validation';

const repo = { update: vi.fn(), create: vi.fn((row) => row), save: vi.fn() };

vi.mock('../../../index', () => ({
  dbSourceConnection: () => [null, { isInitialized: true, getRepository: () => repo }],
}));
vi.mock('../../../services/domainReputation/client', () => ({
  getProviderConfig: vi.fn(),
  invalidateDomainReputationConfigCache: vi.fn(),
}));
vi.mock('../../../services/domainReputation/scopeContext', () => ({
  getDomainReputationScopeContext: vi.fn().mockResolvedValue({ scope: { unrestricted: true } }),
  resolveWriteGroupId: vi.fn(),
}));
vi.mock('../../../utils/auditTrailLogger', () => ({ logAuditTrail: vi.fn().mockResolvedValue(undefined) }));

describe('isValidHeaderName', () => {
  it.each(['X-API-Key', 'Authorization', 'x_api_key'])('accepts %s', (name) => {
    expect(isValidHeaderName(name)).toBe(true);
  });
  it.each(['__proto__', 'constructor!', '', 'bad header', 'x\r\ny', 'a'.repeat(129)])('rejects %j', (name) => {
    expect(isValidHeaderName(name)).toBe(false);
  });
  it('refuses to save a config with an invalid header name', async () => {
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
    const req = {
      params: { provider: 'manual' },
      headers: {},
      body: { base_url: 'https://8.8.8.8', api_key: 'k', auth_mode: 'header', auth_header_name: '__proto__' },
    } as unknown as Request;
    await saveProviderConfig(req, res as unknown as Response, vi.fn());
    expect(res.status).toHaveBeenCalledWith(400);
    expect(repo.save).not.toHaveBeenCalled();
  });
});
