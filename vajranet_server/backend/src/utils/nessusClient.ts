import axios, { AxiosInstance } from 'axios';
import https from 'https';
import { decrypt } from './encryption';
import { getLogger } from './logger';
import { SCANNER_CONFIG_CACHE_TTL_MS } from '../consts/scanning';
import { groupIdWhereValue, scannerCacheKey } from './scannerScope';

const logger = getLogger('scanner.nessus');

interface CachedNessusClient {
  instance: AxiosInstance;
  configId: number;
  expiresAt: number;
}

// Keyed by scannerCacheKey(groupId) — one cached client per scope (the Super
// Administrator's own null scope, plus one per group with its own config).
const cachedClients = new Map<string, CachedNessusClient>();

const CACHE_TTL_MS = SCANNER_CONFIG_CACHE_TTL_MS;

const nessusHttpsAgent = new https.Agent({ rejectUnauthorized: false });

function createNessusInstance(nessusUrl: string, accessKey: string, secretKey: string): AxiosInstance {
  return axios.create({
    baseURL: nessusUrl,
    headers: {
      'X-ApiKeys': `accessKey=${accessKey};secretKey=${secretKey}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    httpsAgent: nessusHttpsAgent,
    timeout: 30_000,
  });
}

export function createNessusInstanceFromRaw(nessusUrl: string, accessKey: string, secretKey: string): AxiosInstance {
  return createNessusInstance(nessusUrl, accessKey, secretKey);
}

export function invalidateNessusClientCache(groupId?: string | null): void {
  if (groupId === undefined) {
    cachedClients.clear();
    return;
  }
  cachedClients.delete(scannerCacheKey(groupId));
}

export async function getNessusClient(groupId: string | null): Promise<AxiosInstance> {
  const cacheKey = scannerCacheKey(groupId);
  const cached = cachedClients.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.instance;
  }

  const { dbSourceConnection } = await import('../index');
  const { NessusConfig } = await import('../orm/entities/fleet/NessusConfig');
  const ds = dbSourceConnection();

  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    logger.warn('Cannot build Nessus client: fleet database not available');
    throw new Error('Fleet database not available');
  }

  const repo = ds[1].getRepository(NessusConfig);
  let config: InstanceType<typeof NessusConfig> | null;
  try {
    config = await repo.findOne({ where: { isActive: true, groupId: groupIdWhereValue(groupId) } });
  } catch (err) {
    // Callers' generic catch (e.g. handleNessusError) reports everything as
    // "Nessus API request failed", so log here to distinguish a config-lookup
    // failure from an actual Nessus API call failing.
    logger.error({ err, groupId }, 'Failed to query active Nessus configuration from database');
    throw err;
  }

  if (!config) {
    logger.warn({ groupId }, 'Cannot build Nessus client: no active Nessus configuration in Settings');
    throw new Error('Nessus is not configured. Please add your Nessus API credentials in Settings.');
  }

  let accessKey: string;
  let secretKey: string;
  try {
    accessKey = decrypt(config.accessKeyEncrypted, config.accessKeyIv, config.accessKeyAuthTag);
    secretKey = decrypt(config.secretKeyEncrypted, config.secretKeyIv, config.secretKeyAuthTag);
  } catch (err) {
    logger.error({ err, configId: config.id }, 'Failed to decrypt stored Nessus API credentials');
    throw new Error('Failed to decrypt stored Nessus API credentials', { cause: err });
  }

  const instance = createNessusInstance(config.nessusUrl, accessKey, secretKey);

  const entry: CachedNessusClient = {
    instance,
    configId: Number(config.id),
    expiresAt: Date.now() + CACHE_TTL_MS,
  };
  cachedClients.set(cacheKey, entry);

  logger.info({ configId: entry.configId, groupId }, 'Refreshed cached Nessus client from active configuration');

  return instance;
}
