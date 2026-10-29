import axios, { AxiosInstance } from 'axios';
import https from 'https';
import { XMLParser, type JPathOrMatcher } from 'fast-xml-parser';
import { decrypt } from './encryption';
import { getLogger } from './logger';
import { sanitizeAxiosError } from './sanitizeAxiosError';
import { SCANNER_CONFIG_CACHE_TTL_MS } from '../consts/scanning';
import { EXTERNAL_API_TIMEOUT_MS } from '../consts/timeout';
import { groupIdWhereValue, scannerCacheKey } from './scannerScope';

const logger = getLogger('scanner.openvas');

export interface OpenVASConnectionConfig {
  gsaUrl: string;
  gmpUsername: string;
  gmpPassword: string;
}

interface GsaSession {
  client: AxiosInstance;
  token: string;
  cookie: string;
  expiresAt: number;
}

// Group-scoped: one config/session per group (see scannerScope.ts), keyed by
// scannerCacheKey(groupId). Operational note: a GSA login session is now
// established PER GROUP the first time each is used (not just once globally
// as before group-scoping) — each group's session is independent, with its
// own ~10min TTL (SESSION_TTL_MS below). A deployment with many actively-used
// groups will hold that many concurrent GSA sessions open against the GVM
// server, not just one.
const configCache = new Map<string, { config: OpenVASConnectionConfig; configId: number; expiresAt: number }>();
const sessionCache = new Map<string, GsaSession>();

const CONFIG_CACHE_TTL_MS = SCANNER_CONFIG_CACHE_TTL_MS;
const SESSION_TTL_MS = 600_000; // 10 min (GSA session timeout is ~15 min)

const gsaHttpsAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * GMP response paths that must always parse as arrays, even when the response
 * happens to carry exactly one of them (fast-xml-parser otherwise collapses a
 * single occurrence to a bare object, so `results.result.map(...)` downstream
 * would throw on a one-result report but work on a two-result one).
 *
 * Kept at module scope rather than built inside the isArray callback below:
 * fast-xml-parser invokes isArray once per node and once per attribute, so a
 * literal declared there is rebuilt hundreds of thousands of times for a single
 * large get_reports parse. The array is a compile-time constant with no
 * per-call state, so there is nothing to gain from rebuilding it.
 */
const GMP_ARRAY_PATHS = [
  'get_tasks_response.task',
  'get_targets_response.target',
  'get_configs_response.config',
  'get_scanners_response.scanner',
  'get_results_response.result',
  'get_reports_response.report',
  'get_report_formats_response.report_format',
  'get_tasks_response.task.report',
  'get_reports_response.report.report.results.result',
  'get_port_lists_response.port_list',
  'get_credentials_response.credential',
  'result.detection.result.details.detail',
];

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  isArray: (_name: string, jpath: JPathOrMatcher) => {
    const jp = typeof jpath === 'string' ? jpath : (jpath as any).jPath ?? String(jpath);
    return GMP_ARRAY_PATHS.some(p => jp.endsWith(p));
  },
});

export function invalidateOpenVASClientCache(groupId?: string | null): void {
  if (groupId !== undefined) {
    const key = scannerCacheKey(groupId);
    configCache.delete(key);
    sessionCache.delete(key);
    return;
  }
  configCache.clear();
  sessionCache.clear();
}

export async function getOpenVASConfig(groupId: string | null): Promise<OpenVASConnectionConfig> {
  const cacheKey = scannerCacheKey(groupId);
  const cached = configCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.config;
  }

  const { dbSourceConnection } = await import('../index');
  const { OpenVASConfig } = await import('../orm/entities/fleet/OpenVASConfig');
  const ds = dbSourceConnection();

  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    logger.warn('Cannot build OpenVAS config: fleet database not available');
    throw new Error('Fleet database not available');
  }

  const repo = ds[1].getRepository(OpenVASConfig);
  let entity: InstanceType<typeof OpenVASConfig> | null;
  try {
    entity = await repo.findOne({ where: { isActive: true, groupId: groupIdWhereValue(groupId) } });
  } catch (err) {
    // Same rationale as nessusClient.ts's getNessusClient: without this, a
    // DB-query failure here is indistinguishable in the logs from a genuine
    // GSA/GMP command failure once it reaches a caller's generic catch — this
    // is the config-lookup step, before any request to OpenVAS is even made.
    logger.error({ err, groupId }, 'Failed to query active OpenVAS configuration from database');
    throw err;
  }

  if (!entity) {
    logger.warn({ groupId }, 'Cannot build OpenVAS config: no active OpenVAS/GVM configuration in Settings');
    throw new Error('OpenVAS is not configured. Please add your GVM connection details in Settings.');
  }

  let gmpPassword: string;
  try {
    gmpPassword = decrypt(entity.gmpPasswordEncrypted, entity.gmpPasswordIv, entity.gmpPasswordAuthTag);
  } catch (err) {
    logger.error({ err, configId: entity.id }, 'Failed to decrypt stored OpenVAS GMP password');
    throw new Error('Failed to decrypt stored OpenVAS GMP password', { cause: err });
  }

  const config: OpenVASConnectionConfig = {
    gsaUrl: entity.nessusUrl,
    gmpUsername: entity.gmpUsername,
    gmpPassword,
  };

  const entry = {
    config,
    configId: Number(entity.id),
    expiresAt: Date.now() + CONFIG_CACHE_TTL_MS,
  };
  configCache.set(cacheKey, entry);

  // Mirrors nessusClient.ts's getNessusClient success log — without this,
  // "which stored config is currently active" (and when it was last
  // refreshed into the cache) leaves no trace at all, unlike its Nessus
  // counterpart.
  logger.info({ configId: entry.configId, groupId }, 'Refreshed cached OpenVAS config from active configuration');

  return config;
}

async function createGsaSession(config: OpenVASConnectionConfig): Promise<GsaSession> {
  const baseURL = config.gsaUrl.replace(/\/+$/, '');

  // gsad 21.04+ (this deployment runs 27.2.0) serves authentication from a
  // dedicated `/login` endpoint. The older `POST /gmp` with `cmd=login` is no
  // longer recognised as a login at all: gsad never reaches its auth code and
  // answers 401 with an empty <token></token> and the generic body
  // "Token missing or bad. Please login again." — which reads like an expired
  // session but actually means the endpoint was wrong, regardless of whether
  // the credentials were correct.
  const loginResp = await axios.post(
    `${baseURL}/login`,
    `login=${encodeURIComponent(config.gmpUsername)}&password=${encodeURIComponent(config.gmpPassword)}`,
    {
      httpsAgent: gsaHttpsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15_000,
      maxRedirects: 0,
      validateStatus: () => true,
    },
  );

  const setCookie = loginResp.headers['set-cookie'];
  let sidCookie = '';
  if (setCookie) {
    for (const c of setCookie) {
      const match = c.match(/GSAD_SID=([^;]+)/);
      if (match) { sidCookie = match[1]; break; }
    }
  }

  const body = typeof loginResp.data === 'string' ? loginResp.data : '';
  // `[^<]*` rather than `[^<]+`: a rejected login returns a well-formed but
  // EMPTY <token></token>, which `+` fails to match at all, making a genuine
  // auth failure indistinguishable from a malformed response below.
  const tokenMatch = body.match(/<token>([^<]*)<\/token>/);
  if (!tokenMatch || !tokenMatch[1]) {
    if (loginResp.status === 401) {
      throw new Error('GSA login rejected: invalid GMP username or password');
    }
    const errMatch = body.match(/<message>([^<]+)<\/message>/);
    throw new Error(errMatch ? errMatch[1] : 'GSA login failed — no token returned');
  }

  const token = tokenMatch[1];

  const client = axios.create({
    baseURL,
    httpsAgent: gsaHttpsAgent,
    headers: {
      'Cookie': `GSAD_SID=${sidCookie}`,
    },
    timeout: 30_000,
    validateStatus: () => true,
  });

  logger.info({ gsaUrl: baseURL }, 'Established OpenVAS GSA session');

  return {
    client,
    token,
    cookie: sidCookie,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
}

async function getGsaSession(groupId: string | null, config?: OpenVASConnectionConfig): Promise<GsaSession> {
  const cacheKey = scannerCacheKey(groupId);
  const cached = sessionCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached;
  }

  const cfg = config || await getOpenVASConfig(groupId);
  const session = await createGsaSession(cfg);
  sessionCache.set(cacheKey, session);
  return session;
}

export async function executeGmpCommand(groupId: string | null, cmd: string, config?: OpenVASConnectionConfig, timeoutMs = EXTERNAL_API_TIMEOUT_MS, extraParams?: Record<string, string>): Promise<any> {
  const cfg = config || await getOpenVASConfig(groupId);

  let session: GsaSession;
  try {
    session = await getGsaSession(groupId, cfg);
  } catch (err: any) {
    // Include `cmd` like executeGmpPost's identical catch below does —
    // without it, a login failure here is indistinguishable in the logs
    // from a login failure triggered by any other concurrent GMP command.
    // GSA login sends gmp_username/gmp_password as a plaintext POST body
    // (see createGsaSession above), which axios embeds verbatim into a
    // failed request's `err.config.data` — logging the raw error here would
    // leak the password into the log stream, so only an allowlisted subset
    // is ever logged.
    logger.error({ err: sanitizeAxiosError(err), cmd }, 'OpenVAS GSA login failed');
    throw new Error(`GSA login failed: ${err.message}`, { cause: err });
  }

  const buildUrl = (token: string) => {
    let url = `/gmp?token=${encodeURIComponent(token)}&cmd=${encodeURIComponent(cmd)}`;
    if (extraParams) {
      for (const [k, v] of Object.entries(extraParams)) {
        url += `&${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
      }
    }
    return url;
  };

  // One catch around the request, the response parsing and the re-auth retry,
  // so a network failure talking to GSA and a rejected or malformed GMP
  // response are distinguishable in the logs from the command never running.
  try {
    const resp = await session.client.get(buildUrl(session.token), { timeout: timeoutMs });
    const body = typeof resp.data === 'string' ? resp.data : String(resp.data);

    if (body.includes('Token missing or bad') || body.includes('Please login again')) {
      // GSA session expired mid-use (its ~15min timeout is shorter than
      // SESSION_TTL_MS's 10min cache in some deployments, or GSA restarted).
      // Transparent to the caller by design, but worth a trace: otherwise an
      // occasional extra ~15s of latency on this command is unexplained.
      logger.info({ cmd }, 'OpenVAS GSA session expired mid-request, re-authenticating and retrying');
      sessionCache.delete(scannerCacheKey(groupId));
      session = await getGsaSession(groupId, cfg);
      const retryResp = await session.client.get(buildUrl(session.token), { timeout: timeoutMs });
      return parseGmpResponse(typeof retryResp.data === 'string' ? retryResp.data : String(retryResp.data));
    }

    return parseGmpResponse(body);
  } catch (err) {
    // The session-authenticated request carries the GSA session cookie
    // (Cookie: GSAD_SID=...) and the GMP token in the URL, both of which
    // axios embeds verbatim into a failed request's `err.config.headers`/
    // `err.config.url` — sanitize before logging for the same reason as the
    // GSA login catch above.
    logger.error({ err: sanitizeAxiosError(err), cmd }, 'OpenVAS GMP command failed');
    throw err;
  }
}

export async function executeGmpPost(groupId: string | null, cmd: string, formParams: Record<string, string>, config?: OpenVASConnectionConfig, timeoutMs = EXTERNAL_API_TIMEOUT_MS): Promise<any> {
  const cfg = config || await getOpenVASConfig(groupId);

  let session: GsaSession;
  try {
    session = await getGsaSession(groupId, cfg);
  } catch (err: any) {
    // GSA login sends gmp_username/gmp_password as a plaintext POST body
    // (see createGsaSession above), which axios embeds verbatim into a
    // failed request's `err.config.data` — logging the raw error here would
    // leak the password into the log stream, so only an allowlisted subset
    // is ever logged.
    logger.error({ err: sanitizeAxiosError(err), cmd }, 'OpenVAS GSA login failed');
    throw new Error(`GSA login failed: ${err.message}`, { cause: err });
  }

  const params = new URLSearchParams();
  params.set('cmd', cmd);
  params.set('token', session.token);
  for (const [k, v] of Object.entries(formParams)) {
    params.set(k, v);
  }

  // Same rationale as executeGmpCommand's try/catch: without this, a
  // network/timeout failure or a rejected/malformed GMP response for a
  // mutating command (create_target, start_task, delete_task, ...) left no
  // trace here at all.
  try {
    let resp = await session.client.post('/gmp', params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: timeoutMs,
    });

    let body = typeof resp.data === 'string' ? resp.data : String(resp.data);

    if (body.includes('Token missing or bad') || body.includes('Please login again')) {
      logger.info({ cmd }, 'OpenVAS GSA session expired mid-request, re-authenticating and retrying');
      sessionCache.delete(scannerCacheKey(groupId));
      session = await getGsaSession(groupId, cfg);
      params.set('token', session.token);
      resp = await session.client.post('/gmp', params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: timeoutMs,
      });
      body = typeof resp.data === 'string' ? resp.data : String(resp.data);
    }

    return parseGmpResponse(body);
  } catch (err) {
    // The session-authenticated request carries the GSA session cookie
    // (Cookie: GSAD_SID=...) and the GMP token in the URL, both of which
    // axios embeds verbatim into a failed request's `err.config.headers`/
    // `err.config.url` — sanitize before logging for the same reason as the
    // GSA login catch above.
    logger.error({ err: sanitizeAxiosError(err), cmd }, 'OpenVAS GMP command failed');
    throw err;
  }
}

function parseGmpResponse(xml: string): any {
  const parsed = xmlParser.parse(xml);

  const envelope = parsed?.envelope;
  if (!envelope) {
    throw new Error(`Unexpected GSA response: ${xml.substring(0, 200)}`);
  }

  if (envelope.gsad_response?.message) {
    const msg = envelope.gsad_response.message;
    if (msg.includes('Unknown command') || msg.includes('internal error')) {
      throw new Error(`GSA error: ${msg}`);
    }
  }

  // Mutating "action" commands (create_target, delete_target, start_task,
  // stop_task, resume_task, delete_task, create_credential, delete_credential,
  // ...) respond with a flat <action_result> sibling of <envelope> — not a
  // <cmd_response> wrapped inside a <cmd> element like get_* commands use, and
  // with no status attribute. GVM's convention is that a successful message
  // always starts with "OK" (e.g. "OK, resource created", "OK"); anything else
  // ("Given target_source was invalid", "Failed to find target '...'") is a
  // failure that would otherwise be silently treated as success by callers.
  if (envelope.action_result?.message && !String(envelope.action_result.message).startsWith('OK')) {
    throw new Error(`GMP action failed: ${envelope.action_result.message}`);
  }

  for (const key of Object.keys(envelope)) {
    if (key.startsWith('get_') || key.startsWith('create_') || key.startsWith('delete_') || key.startsWith('start_') || key.startsWith('stop_') || key.startsWith('resume_')) {
      const inner = envelope[key];
      const respKey = Object.keys(inner).find(k => k.endsWith('_response'));
      if (respKey) {
        const respObj = inner[respKey];
        const status = respObj?.['@_status'];
        if (status && parseInt(status, 10) >= 400) {
          throw new Error(`GMP ${status}: ${respObj['@_status_text'] || 'error'}`);
        }
      }
      return inner;
    }
  }

  return envelope;
}

export async function testConnectionWithConfig(config: OpenVASConnectionConfig): Promise<{ success: boolean; version?: string; message?: string }> {
  try {
    const session = await createGsaSession(config);
    const resp = await session.client.get(`/gmp?token=${encodeURIComponent(session.token)}&cmd=get_version`, { timeout: 15_000 });
    const body = typeof resp.data === 'string' ? resp.data : String(resp.data);
    const versionMatch = body.match(/<version>([^<]+)<\/version>/);
    return { success: true, version: versionMatch?.[1] || 'unknown' };
  } catch (err: any) {
    // Covers both createGsaSession's login (plaintext password in the POST
    // body) and the subsequent get_version request (session token in the
    // URL) — same leak risk as the catches above.
    logger.warn({ err: sanitizeAxiosError(err), gsaUrl: config.gsaUrl }, 'OpenVAS connection test failed');
    return { success: false, message: err.message };
  }
}
