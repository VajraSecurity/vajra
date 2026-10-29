import axios from 'axios';
import { promises as dns } from 'dns';
import { getProviderConfig } from '../client';
import { throttleAbuseIPDB } from '../rateLimiter';
import { isPrivateOrLoopbackIp } from '../validation';
import type { NormalizedReputationResult } from './types';
import type { DomainReputationTargetType } from '../../../orm/entities/fleet/DomainReputationTarget';
import { getLogger } from '../../../utils/logger';
import { sanitizeAxiosError } from '../../../utils/sanitizeAxiosError';
import { DOMAIN_REPUTATION_CHECK_TIMEOUT_MS, DOMAIN_REPUTATION_TEST_TIMEOUT_MS } from '../../../consts/timeout';

const logger = getLogger('services.domainReputation.abuseipdb');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';

// AbuseIPDB defines no official verdict buckets; these thresholds on its 0-100
// abuseConfidenceScore follow the common community convention.
const MALICIOUS_THRESHOLD = 75;
const SUSPICIOUS_THRESHOLD = 25;

export class AbuseIPDBNotConfiguredError extends Error {
  constructor() {
    super('AbuseIPDB is not configured. Add your API key in Domain Reputation settings.');
    this.name = 'AbuseIPDBNotConfiguredError';
  }
}

/** AbuseIPDB only checks IPs, so a domain target is resolved to an IP first. */
async function resolveToIp(value: string, type: DomainReputationTargetType): Promise<string> {
  if (type === 'ip') return value;
  const result = await dns.lookup(value);
  return result.address;
}

/** https://docs.abuseipdb.com/ : GET /check?ipAddress=&maxAgeInDays=&verbose, header `Key`. */
export async function checkAbuseIPDB(value: string, type: DomainReputationTargetType, groupId: string | null = null): Promise<NormalizedReputationResult> {
  const config = await getProviderConfig('abuseipdb', groupId);
  if (!config?.apiKey) {
    throw new AbuseIPDBNotConfiguredError();
  }

  let ip: string;
  try {
    ip = await resolveToIp(value, type);
  } catch (err) {
    logger.warn({ err, value, type }, 'Failed to resolve target to an IP address');
    return {
      provider: 'abuseipdb',
      verdict: 'error',
      score: null,
      summary: `Could not resolve "${value}" to an IP address — AbuseIPDB only checks IPs.`,
      raw: null,
    };
  }

  if (isPrivateOrLoopbackIp(ip)) {
    logger.info({ value, type, ip }, 'AbuseIPDB check skipped: target resolves to a private/loopback address');
    const resolvedNote = type === 'domain' ? ` (resolved from ${value})` : '';
    return {
      provider: 'abuseipdb',
      verdict: 'unknown',
      score: null,
      summary: `${ip}${resolvedNote} is a private/non-routable address — AbuseIPDB has no public reputation data for it.`,
      raw: null,
    };
  }

  let resp;
  try {
    resp = await throttleAbuseIPDB(() => axios.get(`${ABUSEIPDB_BASE}/check`, {
      headers: { Key: config.apiKey, Accept: 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
      timeout: DOMAIN_REPUTATION_CHECK_TIMEOUT_MS,
    }));
  } catch (err: any) {
    // The API key travels in the `Key` request header, which axios embeds
    // verbatim into a failed request's `err.config.headers`. Logging the raw
    // error would leak it, so only an allowlisted subset is ever logged.
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.error({ err: sanitizeAxiosError(err), ip, status: err.response?.status }, 'AbuseIPDB rejected the stored API key');
      throw new Error('AbuseIPDB rejected the stored API key. Check it in Domain Reputation settings.', { cause: err });
    }
    if (err.response?.status === 429) {
      logger.warn({ ip }, 'AbuseIPDB daily rate limit exceeded');
      throw new Error('AbuseIPDB daily rate limit exceeded (free tier: 1,000 requests/day). Try again tomorrow.', { cause: err });
    }
    logger.error({ err: sanitizeAxiosError(err), ip, status: err.response?.status }, 'AbuseIPDB check request failed');
    throw err;
  }

  const data = resp.data?.data ?? {};
  const score = Number(data.abuseConfidenceScore ?? 0);
  const resolvedNote = type === 'domain' ? ` (resolved to ${ip})` : '';

  // A non-numeric abuse score (malformed response, API change, partial outage)
  // must never fall through to the 'clean' default below, which would render a
  // real hit as a green badge.
  if (!Number.isFinite(score)) {
    return {
      provider: 'abuseipdb',
      verdict: 'error',
      score: null,
      summary: `AbuseIPDB returned a malformed response (non-numeric abuse score) for ${ip}${resolvedNote} — treat as unverified, not clean.`,
      raw: resp.data,
    };
  }

  let verdict: NormalizedReputationResult['verdict'] = 'clean';
  if (score >= MALICIOUS_THRESHOLD) verdict = 'malicious';
  else if (score >= SUSPICIOUS_THRESHOLD) verdict = 'suspicious';

  return {
    provider: 'abuseipdb',
    verdict,
    score,
    summary: `${score}% abuse confidence${resolvedNote}, ${data.totalReports ?? 0} reports from ${data.numDistinctUsers ?? 0} distinct users.`,
    raw: resp.data,
  };
}

export async function testAbuseIPDBApiKey(apiKey: string): Promise<{ success: boolean; message: string }> {
  try {
    await throttleAbuseIPDB(() => axios.get(`${ABUSEIPDB_BASE}/check`, {
      headers: { Key: apiKey, Accept: 'application/json' },
      params: { ipAddress: '8.8.8.8', maxAgeInDays: 30 },
      timeout: DOMAIN_REPUTATION_TEST_TIMEOUT_MS,
    }));
    return { success: true, message: 'AbuseIPDB API key is valid' };
  } catch (err: any) {
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.warn({ status: err.response?.status }, 'AbuseIPDB API key test rejected: invalid key');
      return { success: false, message: 'Invalid AbuseIPDB API key' };
    }
    if (err.response?.status === 429) {
      logger.warn('AbuseIPDB API key test failed: daily rate limit exceeded');
      return { success: false, message: 'AbuseIPDB daily rate limit exceeded (free tier: 1,000 requests/day). Try again tomorrow.' };
    }
    logger.warn({ err: sanitizeAxiosError(err), status: err.response?.status, code: err.code }, 'AbuseIPDB connection test failed with an unclassified error');
    return { success: false, message: err.message || 'Connection test failed' };
  }
}
