import axios from 'axios';
import { getProviderConfig } from '../client';
import { throttleVirusTotal } from '../rateLimiter';
import { isPrivateOrLoopbackIp } from '../validation';
import type { NormalizedReputationResult } from './types';
import type { DomainReputationTargetType } from '../../../orm/entities/fleet/DomainReputationTarget';
import { getLogger } from '../../../utils/logger';
import { sanitizeAxiosError } from '../../../utils/sanitizeAxiosError';
import { DOMAIN_REPUTATION_CHECK_TIMEOUT_MS, DOMAIN_REPUTATION_TEST_TIMEOUT_MS } from '../../../consts/timeout';

const logger = getLogger('services.domainReputation.virustotal');

const VT_BASE = 'https://www.virustotal.com/api/v3';

export class VirusTotalNotConfiguredError extends Error {
  constructor() {
    super('VirusTotal is not configured. Add your API key in Domain Reputation settings.');
    this.name = 'VirusTotalNotConfiguredError';
  }
}

/**
 * GET /domains/{domain} or /ip_addresses/{ip} with header `x-apikey`; see
 * https://docs.virustotal.com/reference/domain-info and /ip-info. The verdict is
 * derived from last_analysis_stats (per-engine AV and blocklist votes).
 */
export async function checkVirusTotal(value: string, type: DomainReputationTargetType, groupId: string | null = null): Promise<NormalizedReputationResult> {
  const config = await getProviderConfig('virustotal', groupId);
  if (!config?.apiKey) {
    throw new VirusTotalNotConfiguredError();
  }

  if (type === 'ip' && isPrivateOrLoopbackIp(value)) {
    logger.info({ value, type }, 'VirusTotal check skipped: target is a private/loopback address');
    return {
      provider: 'virustotal',
      verdict: 'unknown',
      score: null,
      summary: `${value} is a private/non-routable address — VirusTotal has no public reputation data for it.`,
      raw: null,
    };
  }

  const path = type === 'ip' ? `/ip_addresses/${encodeURIComponent(value)}` : `/domains/${encodeURIComponent(value)}`;

  try {
    const resp = await throttleVirusTotal(() => axios.get(`${VT_BASE}${path}`, {
      headers: { 'x-apikey': config.apiKey },
      timeout: DOMAIN_REPUTATION_CHECK_TIMEOUT_MS,
    }));

    const attrs = resp.data?.data?.attributes ?? {};
    const stats = attrs.last_analysis_stats ?? {};
    const malicious = Number(stats.malicious ?? 0);
    const suspicious = Number(stats.suspicious ?? 0);

    // A non-numeric malicious/suspicious count (malformed response, API change,
    // partial outage) must never fall through to the 'clean' default below,
    // which would render a real hit as a green badge.
    if (!Number.isFinite(malicious) || !Number.isFinite(suspicious)) {
      return {
        provider: 'virustotal',
        verdict: 'error',
        score: null,
        summary: `VirusTotal returned a malformed analysis for this ${type} (non-numeric vendor stats) — treat as unverified, not clean.`,
        raw: resp.data,
      };
    }

    const totalEngines = Object.values(stats).reduce((sum: number, v) => sum + (Number(v) || 0), 0);

    let verdict: NormalizedReputationResult['verdict'] = 'clean';
    if (malicious > 0) verdict = 'malicious';
    else if (suspicious > 0) verdict = 'suspicious';

    const reputationNote = typeof attrs.reputation === 'number' ? ` Community reputation score: ${attrs.reputation}.` : '';

    return {
      provider: 'virustotal',
      verdict,
      score: malicious,
      summary: `${malicious}/${totalEngines} security vendors flagged this ${type} as malicious`
        + (suspicious > 0 ? `, ${suspicious} flagged suspicious` : '')
        + `.${reputationNote}`,
      raw: resp.data,
    };
  } catch (err: any) {
    if (err.response?.status === 404) {
      logger.info({ value, type }, 'VirusTotal has no analysis on record for this target yet');
      return {
        provider: 'virustotal',
        verdict: 'unknown',
        score: null,
        summary: `VirusTotal has no analysis on record for this ${type} yet.`,
        raw: err.response.data ?? null,
      };
    }
    // The API key travels in the `x-apikey` request header, which axios embeds
    // verbatim into a failed request's `err.config.headers`. Logging the raw
    // error would leak it, so only an allowlisted subset is ever logged.
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.error({ err: sanitizeAxiosError(err), value, type, status: err.response?.status }, 'VirusTotal rejected the stored API key');
      throw new Error('VirusTotal rejected the stored API key. Check it in Domain Reputation settings.', { cause: err });
    }
    if (err.response?.status === 429) {
      logger.warn({ value, type }, 'VirusTotal rate limit exceeded');
      throw new Error('VirusTotal rate limit exceeded (free tier: 4 requests/minute, 500/day). Try again shortly.', { cause: err });
    }
    logger.error({ err: sanitizeAxiosError(err), value, type, status: err.response?.status }, 'VirusTotal check request failed');
    throw err;
  }
}

export async function testVirusTotalApiKey(apiKey: string): Promise<{ success: boolean; message: string }> {
  try {
    await throttleVirusTotal(() => axios.get(`${VT_BASE}/domains/google.com`, {
      headers: { 'x-apikey': apiKey },
      timeout: DOMAIN_REPUTATION_TEST_TIMEOUT_MS,
    }));
    return { success: true, message: 'VirusTotal API key is valid' };
  } catch (err: any) {
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.warn({ status: err.response?.status }, 'VirusTotal API key test rejected: invalid key');
      return { success: false, message: 'Invalid VirusTotal API key' };
    }
    if (err.response?.status === 429) {
      logger.warn('VirusTotal API key test failed: rate limit exceeded');
      return { success: false, message: 'VirusTotal rate limit exceeded (free tier: 4 requests/minute, 500/day). Try again shortly.' };
    }
    logger.warn({ err: sanitizeAxiosError(err), status: err.response?.status, code: err.code }, 'VirusTotal connection test failed with an unclassified error');
    return { success: false, message: err.message || 'Connection test failed' };
  }
}
