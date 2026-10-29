import { IsNull } from 'typeorm';
import { decrypt } from '../../utils/encryption';
import type { DomainReputationAuthMode, DomainReputationProviderName } from '../../orm/entities/fleet/DomainReputationProviderConfig';
import { getLogger } from '../../utils/logger';
import { CONFIG_CACHE_TTL_MS } from '../../consts/timeout';

const logger = getLogger('services.domainReputation.client');

export interface LoadedProviderConfig {
  apiKey: string | null;
  baseUrl: string | null;
  authMode: DomainReputationAuthMode;
  authHeaderName: string;
}

const cache = new Map<string, { config: LoadedProviderConfig; expiresAt: number }>();
const CACHE_TTL_MS = CONFIG_CACHE_TTL_MS;

// null groupId (the org-wide default / 'manual''s only slot) is folded into
// the same key space as a real group id via '' — group ids are never empty
// strings (see EndpointGroup.groupId), so this can't collide with a real one.
function cacheKey(provider: DomainReputationProviderName, groupId: string | null): string {
  return `${provider}:${groupId ?? ''}`;
}

export function invalidateDomainReputationConfigCache(
  provider?: DomainReputationProviderName,
  groupId?: string | null,
): void {
  if (provider && groupId !== undefined) {
    logger.info({ provider, groupId }, 'Domain reputation provider config cache invalidated');
    cache.delete(cacheKey(provider, groupId));
    return;
  }
  if (provider) {
    logger.info({ provider }, 'Domain reputation provider config cache invalidated');
    for (const key of [...cache.keys()]) {
      if (key.startsWith(`${provider}:`)) cache.delete(key);
    }
    return;
  }
  logger.info({ provider: 'all' }, 'Domain reputation provider config cache invalidated');
  cache.clear();
}

/**
 * Loads + decrypts the active config row for a provider, scoped to groupId
 * (null = the org-wide default; also the only value 'manual' ever uses).
 * Null if never configured for that (provider, groupId) pair.
 */
export async function getProviderConfig(
  provider: DomainReputationProviderName,
  groupId: string | null = null,
): Promise<LoadedProviderConfig | null> {
  const key = cacheKey(provider, groupId);
  const cached = cache.get(key);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.config;
  }

  const { dbSourceConnection } = await import('../../index');
  const { DomainReputationProviderConfig } = await import('../../orm/entities/fleet/DomainReputationProviderConfig');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    logger.error({ provider, groupId }, 'Fleet database not available while loading domain reputation provider config');
    throw new Error('Fleet database not available');
  }

  const repo = ds[1].getRepository(DomainReputationProviderConfig);
  let row: InstanceType<typeof DomainReputationProviderConfig> | null;
  try {
    row = await repo.findOne({ where: { provider, isActive: true, groupId: groupId === null ? IsNull() : groupId } });
  } catch (err) {
    // No caller wraps this, so a DB error would otherwise propagate uncaught into
    // the provider checker and show up as an opaque failure with no indication
    // that config loading is what broke.
    logger.error({ err, provider, groupId }, 'Failed to load domain reputation provider config from the database');
    throw err;
  }
  if (!row) return null;

  const apiKey = row.apiKeyEncrypted && row.apiKeyIv && row.apiKeyAuthTag
    ? decrypt(row.apiKeyEncrypted, row.apiKeyIv, row.apiKeyAuthTag)
    : null;

  const config: LoadedProviderConfig = {
    apiKey,
    baseUrl: row.baseUrl,
    authMode: row.authMode,
    authHeaderName: row.authHeaderName,
  };

  cache.set(key, { config, expiresAt: Date.now() + CACHE_TTL_MS });
  return config;
}
