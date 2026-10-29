import axios from 'axios';
import { promises as dns } from 'dns';
import { getProviderConfig, type LoadedProviderConfig } from '../client';
import { isPrivateOrLoopbackIp } from '../validation';
import type { NormalizedReputationResult } from './types';
import type { DomainReputationTargetType } from '../../../orm/entities/fleet/DomainReputationTarget';
import type { DomainReputationAuthMode } from '../../../orm/entities/fleet/DomainReputationProviderConfig';
import { getLogger } from '../../../utils/logger';
import { sanitizeAxiosError } from '../../../utils/sanitizeAxiosError';

const logger = getLogger('services.domainReputation.manualServer');

export class ManualServerNotConfiguredError extends Error {
  constructor() {
    super('Vajra Reputation Engine is not configured. Add its URL in Domain Reputation settings.');
    this.name = 'ManualServerNotConfiguredError';
  }
}

// Must stay meaningfully larger than the manual server's own per-request budget.
// If the two are equal the client aborts with ECONNABORTED at the moment the
// server gives up, so the graceful `partial: true` response never arrives.
const MANUAL_SERVER_TIMEOUT_MS = 30_000;

/**
 * Adapter for the manual server's POST {baseUrl}/check response
 * ({ verdict, score, message, partial, requestId, ... }). A handful of
 * plausible field-name variants (verdict/result/status, score/confidence/
 * risk_score, message/summary/details) are still normalized so a
 * differently-shaped response degrades to 'unknown' rather than throwing.
 *
 * `partial: true` means the manual server's request budget elapsed before every
 * provider answered, so the verdict rests on whoever replied in time. That must
 * never read as a fully-corroborated answer — a 'clean' built from half a check
 * is precisely the fail-open case — so the summary is flagged and the caller
 * gets the flag on the result. The full raw body (which carries `requestId`,
 * `providersOk`/`providersFailed`) is preserved into raw_response for
 * correlation with the manual server's own logs.
 */
export function normalizeManualServerResponse(raw: any): NormalizedReputationResult {
  const rawVerdict = String(raw?.verdict ?? raw?.result ?? raw?.status ?? '').toLowerCase();

  // A best-effort guess at the manual server's vocabulary, like the field-name
  // fallbacks above. An unrecognized word becomes 'unknown' rather than
  // 'malicious', so the list errs wide. Confirm against the manual server's
  // documented vocabulary if that becomes available.
  let verdict: NormalizedReputationResult['verdict'] = 'unknown';
  if ([
    'malicious', 'malware', 'bad', 'blacklisted', 'blocked', 'phishing', 'botnet',
    'c2', 'trojan', 'ransomware', 'spam', 'scam', 'compromised', 'exploit',
  ].includes(rawVerdict)) verdict = 'malicious';
  else if (['suspicious', 'warning', 'risky', 'grayware', 'greylisted'].includes(rawVerdict)) verdict = 'suspicious';
  else if (['clean', 'safe', 'good', 'benign', 'ok'].includes(rawVerdict)) verdict = 'clean';
  else if (rawVerdict) {
    // Falls through to 'unknown' below. Logged because an unrecognized word from
    // the manual server (new vocabulary, API change) would otherwise read as a
    // benign result rather than a failed mapping.
    logger.warn({ rawVerdict, requestId: raw?.requestId ?? null }, 'Manual server returned an unrecognized verdict word; treating as unknown');
  }

  const rawScore = raw?.score ?? raw?.confidence ?? raw?.risk_score;
  const score = typeof rawScore === 'number' ? rawScore : null;

  const partial = raw?.partial === true;
  const requestId = typeof raw?.requestId === 'string' && raw.requestId ? raw.requestId : null;

  const message = String(raw?.message ?? raw?.summary ?? raw?.details ?? `Vajra Reputation Engine verdict: ${rawVerdict || 'unknown'}`);

  return {
    provider: 'manual',
    verdict,
    score,
    summary: partial ? `[partial result — not every provider answered in time] ${message}` : message,
    raw,
    partial,
    requestId,
  };
}

function buildAuthHeaders(config: Pick<LoadedProviderConfig, 'apiKey' | 'authMode' | 'authHeaderName'>): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (config.authMode === 'bearer' && config.apiKey) {
    headers['Authorization'] = `Bearer ${config.apiKey}`;
  } else if (config.authMode === 'header' && config.apiKey) {
    headers[config.authHeaderName || 'X-API-Key'] = config.apiKey;
  }
  return headers;
}

export async function checkManualServer(value: string, type: DomainReputationTargetType): Promise<NormalizedReputationResult> {
  const config = await getProviderConfig('manual');
  if (!config?.baseUrl) {
    throw new ManualServerNotConfiguredError();
  }

  // The manual server's sub-providers only evaluate IP addresses: sending
  // type:'domain' returns zero provider answers, because it resolves the domain
  // for its summary text but never forwards that address onward. Resolving here
  // and always sending type:'ip' works around that, as abuseipdb.ts does.
  let ip: string;
  try {
    ip = type === 'ip' ? value : (await dns.lookup(value)).address;
  } catch (err) {
    logger.warn({ err, value, type }, 'Failed to resolve target to an IP address');
    return {
      provider: 'manual',
      verdict: 'error',
      score: null,
      summary: `Could not resolve "${value}" to an IP address — Vajra Reputation Engine only checks IPs.`,
      raw: null,
    };
  }

  // The manual server rejects private and reserved addresses outright, so it
  // cannot become a way to probe internal infrastructure through third-party
  // APIs. Catching it here turns an opaque round-tripped 400 into a plain answer.
  if (isPrivateOrLoopbackIp(ip)) {
    logger.info({ value, type, ip }, 'Manual server check skipped: target resolves to a private/reserved address');
    const resolvedNote = type === 'domain' ? ` (resolved from ${value})` : '';
    return {
      provider: 'manual',
      verdict: 'unknown',
      score: null,
      summary: `${ip}${resolvedNote} is a private/reserved address — Vajra Reputation Engine does not accept it as a lookup target.`,
      raw: null,
    };
  }

  const headers = buildAuthHeaders(config);
  let resp;
  try {
    resp = await axios.post(
      `${config.baseUrl.replace(/\/+$/, '')}/check`,
      { value: ip, type: 'ip' },
      { headers, timeout: MANUAL_SERVER_TIMEOUT_MS, maxRedirects: 0 }, // don't let a validated-at-save-time host 30x us to an unvalidated internal target
    );
  } catch (err: any) {
    // The credential (bearer token or custom header, per buildAuthHeaders)
    // travels in a request header, which axios embeds verbatim into a failed
    // request's `err.config.headers`. Logging the raw error would leak it, so
    // only an allowlisted subset is ever logged.
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.error({ err: sanitizeAxiosError(err), ip, status: err.response?.status }, 'Manual server rejected the stored credentials');
      throw new Error('Vajra Reputation Engine rejected the stored credentials. Check them in Domain Reputation settings.', { cause: err });
    }
    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      logger.warn({ ip, code: err.code }, 'Manual server check timed out');
      throw new Error('Vajra Reputation Engine did not respond in time.', { cause: err });
    }
    logger.error({ err: sanitizeAxiosError(err), ip, status: err.response?.status, code: err.code }, 'Manual server check request failed');
    throw err;
  }

  const result = normalizeManualServerResponse(resp.data);
  if (type === 'domain') {
    result.summary = `${result.summary} (resolved to ${ip})`;
  }
  return result;
}

/**
 * Connection test. Deliberately GET /providers rather than a throwaway /check: a
 * 200 from /check only proves the server answered, so a server with no API keys
 * configured would pass while every real check came back empty. /providers
 * reports the configured/total inventory without exposing key material.
 */
export async function testManualServerConnection(
  baseUrl: string,
  apiKey: string | null,
  authMode: DomainReputationAuthMode,
  authHeaderName: string,
): Promise<{ success: boolean; message: string; data?: any }> {
  try {
    const headers = buildAuthHeaders({ apiKey, authMode, authHeaderName });
    const resp = await axios.get(
      `${baseUrl.replace(/\/+$/, '')}/providers`,
      { headers, timeout: MANUAL_SERVER_TIMEOUT_MS, maxRedirects: 0 }, // don't let a validated-at-save-time host 30x us to an unvalidated internal target
    );

    const data = resp.data ?? {};
    const list = Array.isArray(data.providers) ? data.providers : null;
    const configured = typeof data.configuredCount === 'number'
      ? data.configuredCount
      : list?.filter((p: any) => p?.configured).length ?? null;
    const total = typeof data.totalCount === 'number' ? data.totalCount : list?.length ?? null;

    if (configured === null || total === null) {
      return { success: true, message: 'Connected to Vajra Reputation Engine, but it did not report a provider inventory', data };
    }
    if (configured === 0) {
      return {
        success: false,
        message: `Connected, but 0 of ${total} providers are configured on Vajra Reputation Engine — checks would return no signal`,
        data,
      };
    }
    return { success: true, message: `Connected — ${configured} of ${total} providers configured`, data };
  } catch (err: any) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT' || err.code === 'ECONNABORTED') {
      logger.warn({ code: err.code, baseUrl }, 'Manual server connection test failed: server unreachable');
      return { success: false, message: `Cannot reach Vajra Reputation Engine: ${err.code}` };
    }
    if (err.response?.status === 401 || err.response?.status === 403) {
      logger.warn({ status: err.response?.status, baseUrl }, 'Manual server connection test failed: credentials rejected');
      return { success: false, message: 'Vajra Reputation Engine rejected the credentials' };
    }
    if (err.response?.status === 404) {
      logger.warn({ baseUrl }, 'Manual server connection test failed: no GET /providers endpoint found');
      return { success: false, message: 'Reached the server but it has no GET /providers endpoint — check the base URL points at the reputation service root' };
    }
    // Prefer the server's own error body ({ error, requestId }) over axios'
    // generic "Request failed with status code NNN".
    const body = err.response?.data;
    const detail = typeof body === 'string' ? body : body?.error ?? body?.message;
    logger.warn({ err: sanitizeAxiosError(err), status: err.response?.status, code: err.code }, 'Manual server connection test failed with an unclassified error');
    return { success: false, message: detail || err.message || 'Connection test failed' };
  }
}
