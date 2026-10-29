import { Request, Response, NextFunction } from 'express';
import { In, IsNull } from 'typeorm';
import { encrypt } from '../../utils/encryption';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { getProviderConfig, invalidateDomainReputationConfigCache } from '../../services/domainReputation/client';
import { testVirusTotalApiKey } from '../../services/domainReputation/providers/virustotal';
import { testAbuseIPDBApiKey } from '../../services/domainReputation/providers/abuseipdb';
import { testManualServerConnection } from '../../services/domainReputation/providers/manualServer';
import { getDomainReputationScopeContext, resolveWriteGroupId } from '../../services/domainReputation/scopeContext';
import type { DomainReputationAuthMode, DomainReputationProviderName } from '../../orm/entities/fleet/DomainReputationProviderConfig';
import { API_KEY_MASK_SUFFIX_LENGTH } from '../../consts/auth';
import { getLogger } from '../../utils/logger';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';

const logger = getLogger('controllers.domainReputation.providerConfig');

const VALID_PROVIDERS: DomainReputationProviderName[] = ['manual', 'virustotal', 'abuseipdb'];
const GROUP_SCOPED_PROVIDERS: DomainReputationProviderName[] = ['virustotal', 'abuseipdb'];

function isValidProvider(value: unknown): value is DomainReputationProviderName {
  return typeof value === 'string' && VALID_PROVIDERS.includes(value as DomainReputationProviderName);
}

/** req.body.group_id / req.query.group_id, normalized: '' and undefined both mean "not given". */
function readRequestedGroupId(raw: unknown): string | null | undefined {
  if (raw === null) return null;
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  return raw.trim();
}

async function getRepo() {
  const { dbSourceConnection } = await import('../../index');
  const { DomainReputationProviderConfig } = await import('../../orm/entities/fleet/DomainReputationProviderConfig');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    throw new Error('Fleet database not available');
  }
  return ds[1].getRepository(DomainReputationProviderConfig);
}

async function getGroupRepo() {
  const { dbSourceConnection } = await import('../../index');
  const { EndpointGroup } = await import('../../orm/entities/fleet/EndpointGroup');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    throw new Error('Fleet database not available');
  }
  return ds[1].getRepository(EndpointGroup);
}

function ambiguousMessage(actGroupIds: string[]): string {
  return `group_id is required — you administer multiple groups: ${actGroupIds.join(', ')}`;
}

export const listProviderConfigs = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const repo = await getRepo();
    const ctx = await getDomainReputationScopeContext(req);

    const manualRow = await repo.findOne({ where: { provider: 'manual', isActive: true, groupId: IsNull() } });
    const manualEntry = manualRow
      ? {
        provider: 'manual' as const,
        scope: 'global' as const,
        configured: true,
        base_url: manualRow.baseUrl,
        auth_mode: manualRow.authMode,
        auth_header_name: manualRow.authHeaderName,
        api_key_masked: manualRow.apiKeySuffix ? `****${manualRow.apiKeySuffix}` : null,
        updated_at: manualRow.updated_at,
        created_by_name: manualRow.created_by_name,
      }
      : { provider: 'manual' as const, scope: 'global' as const, configured: false };

    const groupRepo = await getGroupRepo();
    const groupScopedEntries = [] as Array<{
      provider: DomainReputationProviderName;
      scope: 'per_group';
      configs: Array<{
        group_id: string | null;
        group_name: string | null;
        is_org_default: boolean;
        configured: boolean;
        api_key_masked: string | null;
        updated_at: Date | null;
        created_by_name: string | null;
      }>;
    }>;

    for (const provider of GROUP_SCOPED_PROVIDERS) {
      const activeRows = await repo.find({ where: { provider, isActive: true } });

      let slots: { id: string | null; name: string | null }[];
      if (ctx.scope.unrestricted) {
        const allGroups = await groupRepo.find({ order: { name: 'ASC' } });
        slots = [{ id: null, name: null }, ...allGroups.map((g) => ({ id: g.groupId, name: g.name }))];
      } else {
        const ids = [...ctx.viewGroupIds];
        const rows = ids.length ? await groupRepo.find({ where: { groupId: In(ids) } }) : [];
        const nameById = new Map(rows.map((r) => [r.groupId, r.name]));
        slots = ids.map((id) => ({ id, name: nameById.get(id) ?? id }));
      }

      const configs = slots.map(({ id, name }) => {
        const row = activeRows.find((r) => r.groupId === id);
        return {
          group_id: id,
          group_name: name,
          is_org_default: id === null,
          configured: !!row,
          api_key_masked: row?.apiKeySuffix ? `****${row.apiKeySuffix}` : null,
          updated_at: row?.updated_at ?? null,
          created_by_name: row?.created_by_name ?? null,
        };
      });
      groupScopedEntries.push({ provider, scope: 'per_group', configs });
    }

    const data = [manualEntry, ...groupScopedEntries];
    logger.debug({ count: data.length }, 'Domain reputation provider configs retrieved');
    return res.status(200).json({ success: true, data });
  } catch (err: any) {
    logger.error({ err }, 'Failed to load domain reputation provider configs');
    return res.status(err.message === 'Fleet database not available' ? 503 : 500).json({ success: false, message: err.message || 'Failed to load provider configs' });
  }
};

export const saveProviderConfig = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const provider = req.params.provider;
    if (!isValidProvider(provider)) {
      return res.status(400).json({ success: false, message: `Unknown provider: ${provider}` });
    }

    const repo = await getRepo();
    const jwt = jwtFrom(req);
    const ctx = await getDomainReputationScopeContext(req);

    if (provider === 'manual') {
      if (!ctx.scope.unrestricted) {
        return res.status(403).json({ success: false, message: 'Only Super Administrator can configure Vajra Reputation Engine' });
      }

      const { base_url, api_key, auth_mode, auth_header_name } = req.body;
      if (!base_url || typeof base_url !== 'string') {
        return res.status(400).json({ success: false, message: 'base_url is required' });
      }
      const baseUrl = base_url.replace(/\/+$/, '');
      const authMode: DomainReputationAuthMode = ['none', 'header', 'bearer'].includes(auth_mode) ? auth_mode : 'bearer';
      const authHeaderName = typeof auth_header_name === 'string' && auth_header_name.trim() ? auth_header_name.trim() : 'X-API-Key';

      let apiKeyEncrypted: string | null = null;
      let apiKeyIv: string | null = null;
      let apiKeyAuthTag: string | null = null;
      let apiKeySuffix = '';
      if (authMode !== 'none') {
        if (!api_key || typeof api_key !== 'string') {
          return res.status(400).json({ success: false, message: 'api_key is required for the selected auth mode' });
        }
        const enc = encrypt(api_key);
        apiKeyEncrypted = enc.ciphertext;
        apiKeyIv = enc.iv;
        apiKeyAuthTag = enc.authTag;
        apiKeySuffix = api_key.length > API_KEY_MASK_SUFFIX_LENGTH ? api_key.slice(-API_KEY_MASK_SUFFIX_LENGTH) : '';
      }

      await repo.update({ provider, groupId: IsNull(), isActive: true }, { isActive: false });
      const config = repo.create({
        provider, groupId: null, baseUrl, authMode, authHeaderName,
        apiKeyEncrypted, apiKeyIv, apiKeyAuthTag, apiKeySuffix,
        isActive: true, created_by_user_id: jwt?.id ?? null, created_by_name: jwt?.name ?? null,
      });
      await repo.save(config);
      invalidateDomainReputationConfigCache('manual', null);

      if (jwt?.id) {
        logAuditTrail({
          action: 'DOMAIN_REPUTATION_CONFIG', status: 'success', userId: jwt.id, email: jwt.email ?? null,
          ipAddress: clientIpFrom(req), userAgent: null,
          details: { event: 'PROVIDER_CONFIGURED', provider, group_id: null },
        }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
      }

      logger.info({ provider }, 'Domain reputation provider configuration saved');
      return res.status(200).json({ success: true, message: `${provider} configuration saved` });
    }

    // virustotal / abuseipdb — group-scoped.
    const resolution = resolveWriteGroupId(ctx, readRequestedGroupId(req.body?.group_id));
    if (!resolution.ok) {
      if (resolution.reason === 'ambiguous') {
        return res.status(400).json({ success: false, message: ambiguousMessage(resolution.actGroupIds) });
      }
      return res.status(403).json({ success: false, message: 'You can only configure providers for a group you administer' });
    }
    const targetGroupId = resolution.groupId;
    if (targetGroupId !== null && ctx.scope.unrestricted) {
      const groupRepo = await getGroupRepo();
      const exists = await groupRepo.findOne({ where: { groupId: targetGroupId } });
      if (!exists) return res.status(400).json({ success: false, message: `Unknown group_id: ${targetGroupId}` });
    }

    const { api_key } = req.body;
    if (!api_key || typeof api_key !== 'string') {
      return res.status(400).json({ success: false, message: 'api_key is required' });
    }
    const enc = encrypt(api_key);
    const apiKeySuffix = api_key.length > API_KEY_MASK_SUFFIX_LENGTH ? api_key.slice(-API_KEY_MASK_SUFFIX_LENGTH) : '';

    await repo.update(
      { provider, groupId: targetGroupId === null ? IsNull() : targetGroupId, isActive: true },
      { isActive: false },
    );
    const config = repo.create({
      provider, groupId: targetGroupId, baseUrl: null, authMode: 'none', authHeaderName: 'X-API-Key',
      apiKeyEncrypted: enc.ciphertext, apiKeyIv: enc.iv, apiKeyAuthTag: enc.authTag, apiKeySuffix,
      isActive: true, created_by_user_id: jwt?.id ?? null, created_by_name: jwt?.name ?? null,
    });
    await repo.save(config);
    invalidateDomainReputationConfigCache(provider, targetGroupId);

    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_CONFIG', status: 'success', userId: jwt.id, email: jwt.email ?? null,
        ipAddress: clientIpFrom(req), userAgent: null,
        details: { event: 'PROVIDER_CONFIGURED', provider, group_id: targetGroupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ provider, groupId: targetGroupId }, 'Domain reputation provider configuration saved');
    return res.status(200).json({ success: true, message: `${provider} configuration saved` });
  } catch (err: any) {
    logger.error({ err, provider: req.params.provider }, 'Failed to save domain reputation provider configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to save provider configuration' });
  }
};

export const deleteProviderConfig = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const provider = req.params.provider;
    if (!isValidProvider(provider)) {
      return res.status(400).json({ success: false, message: `Unknown provider: ${provider}` });
    }

    const repo = await getRepo();
    const ctx = await getDomainReputationScopeContext(req);
    let targetGroupId: string | null = null;

    if (provider === 'manual') {
      if (!ctx.scope.unrestricted) {
        return res.status(403).json({ success: false, message: 'Only Super Administrator can configure Vajra Reputation Engine' });
      }
    } else {
      const resolution = resolveWriteGroupId(ctx, readRequestedGroupId(req.query?.group_id));
      if (!resolution.ok) {
        if (resolution.reason === 'ambiguous') {
          return res.status(400).json({ success: false, message: ambiguousMessage(resolution.actGroupIds) });
        }
        return res.status(403).json({ success: false, message: 'You can only remove providers for a group you administer' });
      }
      targetGroupId = resolution.groupId;
    }

    await repo.update({ provider, groupId: targetGroupId === null ? IsNull() : targetGroupId, isActive: true }, { isActive: false });
    invalidateDomainReputationConfigCache(provider, targetGroupId);

    const jwt = jwtFrom(req);
    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_CONFIG', status: 'success', userId: jwt.id, email: jwt.email ?? null,
        ipAddress: clientIpFrom(req), userAgent: null,
        details: { event: 'PROVIDER_REMOVED', provider, group_id: targetGroupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    logger.info({ provider, groupId: targetGroupId }, 'Domain reputation provider configuration removed');
    return res.status(200).json({ success: true, message: `${provider} configuration removed` });
  } catch (err: any) {
    logger.error({ err, provider: req.params.provider }, 'Failed to remove domain reputation provider configuration');
    return res.status(500).json({ success: false, message: err.message || 'Failed to remove provider configuration' });
  }
};

export const testProviderConnection = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const provider = req.params.provider;
    if (!isValidProvider(provider)) {
      return res.status(400).json({ success: false, message: `Unknown provider: ${provider}` });
    }

    const ctx = await getDomainReputationScopeContext(req);

    if (provider === 'virustotal' || provider === 'abuseipdb') {
      const resolution = resolveWriteGroupId(ctx, readRequestedGroupId(req.body?.group_id));
      if (!resolution.ok) {
        if (resolution.reason === 'ambiguous') {
          return res.status(400).json({ success: false, message: ambiguousMessage(resolution.actGroupIds) });
        }
        return res.status(403).json({ success: false, message: 'You can only test providers for a group you administer' });
      }
      const targetGroupId = resolution.groupId;

      // A blank api_key means "test the key already saved" rather than "no key
      // given" — the UI never re-populates the field with a real key once
      // masked, so requiring it to be retyped here would make Test unusable
      // for an already-configured provider.
      let apiKey = req.body?.api_key;
      if (!apiKey) {
        const stored = await getProviderConfig(provider, targetGroupId);
        apiKey = stored?.apiKey ?? null;
      }
      if (!apiKey) return res.status(400).json({ success: false, message: 'api_key is required' });
      const result = provider === 'virustotal' ? await testVirusTotalApiKey(apiKey) : await testAbuseIPDBApiKey(apiKey);
      logger.debug({ provider, groupId: targetGroupId, success: result.success }, 'Domain reputation provider connection test completed');
      return res.status(200).json(result);
    }

    // manual — Super-Admin-only, same fallback: any field left out of the
    // request is filled in from the stored config so Test works without
    // retyping an existing key.
    if (!ctx.scope.unrestricted) {
      return res.status(403).json({ success: false, message: 'Only Super Administrator can test Vajra Reputation Engine' });
    }

    const { base_url, api_key, auth_mode, auth_header_name } = req.body;
    let effectiveBaseUrl = typeof base_url === 'string' && base_url ? base_url : undefined;
    let effectiveApiKey = typeof api_key === 'string' && api_key ? api_key : null;
    let effectiveAuthMode = ['none', 'header', 'bearer'].includes(auth_mode) ? auth_mode : undefined;
    let effectiveAuthHeaderName = typeof auth_header_name === 'string' && auth_header_name ? auth_header_name : undefined;

    if (!effectiveBaseUrl || !effectiveApiKey) {
      const stored = await getProviderConfig('manual');
      if (!effectiveBaseUrl) effectiveBaseUrl = stored?.baseUrl ?? undefined;
      if (!effectiveApiKey) effectiveApiKey = stored?.apiKey ?? null;
      if (!effectiveAuthMode) effectiveAuthMode = stored?.authMode;
      if (!effectiveAuthHeaderName) effectiveAuthHeaderName = stored?.authHeaderName;
    }

    if (!effectiveBaseUrl) return res.status(400).json({ success: false, message: 'base_url is required' });
    const result = await testManualServerConnection(
      effectiveBaseUrl,
      effectiveApiKey,
      effectiveAuthMode || 'none',
      effectiveAuthHeaderName || 'X-API-Key',
    );
    logger.debug({ provider: 'manual', success: result.success }, 'Domain reputation provider connection test completed');
    return res.status(200).json(result);
  } catch (err: any) {
    logger.warn({ err, provider: req.params.provider }, 'Domain reputation provider connection test failed');
    return res.status(200).json({ success: false, message: err.message || 'Connection test failed' });
  }
};
