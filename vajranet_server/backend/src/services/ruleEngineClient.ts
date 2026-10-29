/**
 * Server-to-server client for the Rule Engine Console API
 * (`~/Videos/vajra_server/rule_engine_ui` — a FastAPI console fronting
 * `engine_v2`'s rule store, running unauthenticated on the internal network
 * at RULE_ENGINE_API_URL). See that repo's `API_CONTRACT.md` /
 * `API_CONTRACT_V2.md` for the full HTTP contract this wraps.
 *
 * That console has NO authentication of its own (a documented, accepted
 * risk for a temporary internal tool) — every real access-control decision
 * for THIS app's users happens before a call ever reaches this module (see
 * routes/api/rule-engine.ts's middleware chains). This module's job is only
 * to forward requests/responses faithfully, including real non-2xx status
 * codes and bodies (a validation failure must read to the caller as the
 * engine's real validation error, not a generic 500) — so every function
 * here resolves rather than throws on an HTTP error response; only a
 * genuine network-level failure (engine unreachable, timeout, DNS) rejects.
 *
 * Shared by two callers: routes/api/rule-engine.ts (proxies the full
 * contract to the frontend) and mcp/executor.ts (propose_rule /
 * propose_correlation_rule call validateRule/validateCorrelationRule
 * directly — no HTTP loopback to this app's own routes).
 */

import axios, { AxiosInstance } from 'axios';
import { getLogger } from '../utils/logger';
import { sanitizeAxiosError } from '../utils/sanitizeAxiosError';

const logger = getLogger('services.ruleEngineClient');

/** Default: a rule engine console running on this machine. Override with RULE_ENGINE_API_URL. */
const DEFAULT_RULE_ENGINE_API_URL = 'http://127.0.0.1:8001';

/** Plain read/write calls. Validate/reload can shell out to the engine binary on the far side, so this is generous relative to the 5s DEFAULT_TIMEOUT_MS used for simple external calls elsewhere in this app. */
const RULE_ENGINE_TIMEOUT_MS = 30_000;
/** POST /api/threat-intel-feeds/{name}/preview performs a real outbound HTTPS fetch of an operator-supplied feed URL on the engine side — allow more headroom than an ordinary API call. */
const RULE_ENGINE_PREVIEW_TIMEOUT_MS = 45_000;

function baseUrl(): string {
  return process.env.RULE_ENGINE_API_URL?.trim() || DEFAULT_RULE_ENGINE_API_URL;
}

let cachedClient: { instance: AxiosInstance; baseUrl: string } | null = null;

function client(): AxiosInstance {
  const url = baseUrl();
  if (cachedClient && cachedClient.baseUrl === url) return cachedClient.instance;
  const instance = axios.create({
    baseURL: url,
    timeout: RULE_ENGINE_TIMEOUT_MS,
    // Resolve on any status so callers can pass through the engine's own
    // status code + body verbatim (e.g. 422 on a validation failure, 403 on
    // "delete a non-custom rule") instead of every non-2xx becoming a caught
    // exception collapsed into a generic 500 by the caller.
    validateStatus: () => true,
    maxRedirects: 0,
  });
  cachedClient = { instance, baseUrl: url };
  return instance;
}

export interface RuleEngineResult<T = unknown> {
  /** true only for a real network-level failure (unreachable, timeout, DNS, etc.) — never set for a real HTTP error response from the engine, which instead comes back as a normal {status, data} with status >= 400. */
  unreachable: boolean;
  status: number;
  data: T;
  errorMessage?: string;
}

/**
 * Rejects a `.`/`..` path segment, or one containing a literal `/` or `\`, before it ever
 * reaches a template-literal URL path below.
 *
 * encodeURIComponent does NOT escape `.` (it is an RFC 3986 unreserved character), so a
 * param value of exactly ".." passes straight through unchanged, sitting between two
 * literal "/" characters supplied by the surrounding template string. Express's router
 * captures it as an ordinary literal route param with no special handling — but axios/
 * Node's own URL resolution against the axios instance's baseURL DOES apply RFC 3986
 * dot-segment collapsing to that literal, unescaped "/../" sequence, landing the outbound
 * request on a completely different far-side path than the one this function's caller
 * built (e.g. GET /api/rules/../health actually reaches /api/health on the engine host).
 * Confirmed real and reachable by an authenticated Viewer on the GET routes — see
 * docs/team/vajranet-sage.md Finding 1 for the full repro. Every path parameter (source,
 * id, name, ip) is checked here before encodeURIComponent runs.
 */
function invalidPathSegment(value: string): boolean {
  return value === '.' || value === '..' || value.includes('/') || value.includes('\\');
}

/**
 * A clean, synchronous 400 — never thrown — for a path parameter that fails
 * invalidPathSegment(). Deliberately resolves rather than throws, consistent with this
 * module's existing "every function resolves rather than throws on an error response"
 * contract (see file header): the caller (routes/api/rule-engine.ts's relay()) already
 * forwards {status, data} verbatim with no special-casing needed, so this reaches the
 * client as a real 400 with no risk of the route layer's generic try/catch turning it
 * into a 500 instead.
 */
function invalidSegmentResult(paramName: string, value: string): RuleEngineResult {
  logger.warn({ paramName, value }, 'Rejected outbound rule engine request: unsafe path segment');
  return {
    unreachable: false,
    status: 400,
    data: { error: `Invalid ${paramName}: must not be "." or ".." and must not contain "/" or "\\"` },
  };
}

/** Validates every named path segment before a request is built. Returns the first failure as a ready-to-return RuleEngineResult, or null if every segment is safe. */
function checkSegments(segments: Record<string, string>): RuleEngineResult | null {
  for (const [name, value] of Object.entries(segments)) {
    if (invalidPathSegment(value)) return invalidSegmentResult(name, value);
  }
  return null;
}

async function request<T = unknown>(
  method: 'get' | 'post' | 'patch' | 'delete',
  path: string,
  opts: { params?: Record<string, unknown>; data?: unknown; timeoutMs?: number; headers?: Record<string, string> } = {},
): Promise<RuleEngineResult<T>> {
  try {
    const res = await client().request<T>({
      method,
      url: path,
      params: opts.params,
      data: opts.data,
      headers: opts.headers,
      timeout: opts.timeoutMs ?? RULE_ENGINE_TIMEOUT_MS,
    });
    return { unreachable: false, status: res.status, data: res.data };
  } catch (err: any) {
    logger.error({ err: sanitizeAxiosError(err), method, path, baseUrl: baseUrl() }, 'Rule engine console request failed at the network level');
    return {
      unreachable: true,
      status: 502,
      data: undefined as unknown as T,
      errorMessage: err instanceof Error ? err.message : 'Rule engine console unreachable',
    };
  }
}

// ─── Health ────────────────────────────────────────────────────────────────

export const getHealth = () => request('get', '/api/health');

// ─── Detection rules ───────────────────────────────────────────────────────

export const listRules = (params: Record<string, unknown>) => request('get', '/api/rules', { params });

export const getRule = (source: string, id: string) => {
  const invalid = checkSegments({ source, id });
  if (invalid) return Promise.resolve(invalid);
  return request('get', `/api/rules/${encodeURIComponent(source)}/${encodeURIComponent(id)}`);
};

export const validateRule = (rule: unknown) => request('post', '/api/rules/validate', { data: rule });
export const createRule = (rule: unknown) => request('post', '/api/rules', { data: rule });

export const patchRule = (source: string, id: string, body: unknown) => {
  const invalid = checkSegments({ source, id });
  if (invalid) return Promise.resolve(invalid);
  return request('patch', `/api/rules/${encodeURIComponent(source)}/${encodeURIComponent(id)}`, { data: body });
};

export const deleteRule = (source: string, id: string) => {
  const invalid = checkSegments({ source, id });
  if (invalid) return Promise.resolve(invalid);
  return request('delete', `/api/rules/${encodeURIComponent(source)}/${encodeURIComponent(id)}`);
};

// ─── Correlation rules ──────────────────────────────────────────────────────

export const listCorrelationRules = (params: Record<string, unknown>) => request('get', '/api/correlation-rules', { params });

export const getCorrelationRule = (source: string, id: string) => {
  const invalid = checkSegments({ source, id });
  if (invalid) return Promise.resolve(invalid);
  return request('get', `/api/correlation-rules/${encodeURIComponent(source)}/${encodeURIComponent(id)}`);
};

export const validateCorrelationRule = (rule: unknown) => request('post', '/api/correlation-rules/validate', { data: rule });
export const createCorrelationRule = (rule: unknown) => request('post', '/api/correlation-rules', { data: rule });

export const patchCorrelationRule = (source: string, id: string, body: unknown) => {
  const invalid = checkSegments({ source, id });
  if (invalid) return Promise.resolve(invalid);
  return request('patch', `/api/correlation-rules/${encodeURIComponent(source)}/${encodeURIComponent(id)}`, { data: body });
};

// ─── Lists / test-event / metrics ──────────────────────────────────────────

export const getLists = () => request('get', '/api/lists');
export const getTestEventExamples = () => request('get', '/api/test-event/examples');
export const postTestEvent = (event: unknown) => request('post', '/api/test-event', { data: event });
export const getMetrics = () => request('get', '/api/metrics');

/**
 * Correlation Simulation — feeds a real ordered event sequence through the
 * actual CorrelationEngine (the only way to exercise event_count/value_count/
 * temporal/temporal_ordered end-to-end; POST /test-event only evaluates
 * detection rules). NOT documented in API_CONTRACT.md / API_CONTRACT_V2.md —
 * confirmed live by reading rule_engine_ui/backend/simulate.py directly
 * (read-only reference) and by a real GET against the running console.
 */
export const getSimulationSamples = () => request('get', '/api/simulate-correlation/samples');
export const simulateCorrelation = (body: unknown) => request('post', '/api/simulate-correlation', { data: body });

// ─── Live instance / reload (v2) ───────────────────────────────────────────

export const getLiveInstance = () => request('get', '/api/live-instance');
export const setLiveInstance = (body: unknown) => request('post', '/api/live-instance', { data: body });
export const reloadLiveInstance = () => request('post', '/api/live-instance/reload', { timeoutMs: RULE_ENGINE_TIMEOUT_MS });

// ─── IP watch groups (v2) ───────────────────────────────────────────────────

export const listIpWatchGroups = () => request('get', '/api/ip-watch-groups');
export const createIpWatchGroup = (body: unknown) => request('post', '/api/ip-watch-groups', { data: body });

export const patchIpWatchGroup = (name: string, body: unknown) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('patch', `/api/ip-watch-groups/${encodeURIComponent(name)}`, { data: body });
};

export const deleteIpWatchGroup = (name: string) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('delete', `/api/ip-watch-groups/${encodeURIComponent(name)}`);
};

export const listIpWatchGroupIps = (name: string, params: Record<string, unknown>) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('get', `/api/ip-watch-groups/${encodeURIComponent(name)}/ips`, { params });
};

export const addIpWatchGroupIps = (name: string, body: unknown) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('post', `/api/ip-watch-groups/${encodeURIComponent(name)}/ips`, { data: body });
};

export const deleteIpWatchGroupIp = (name: string, ip: string) => {
  const invalid = checkSegments({ name, ip });
  if (invalid) return Promise.resolve(invalid);
  return request('delete', `/api/ip-watch-groups/${encodeURIComponent(name)}/ips/${encodeURIComponent(ip)}`);
};

/** CSV/text bulk import — forwarded as multipart, field name mirrors what rule_engine_ui's own frontend sends ("file"). Uses the WHATWG FormData/Blob globals (Node >=18) rather than adding the 'form-data' package as a new dependency; axios ^1.x natively streams a spec FormData body under Node and sets the multipart boundary header itself. */
export async function importIpWatchGroupIpsCsv(
  name: string,
  fileBuffer: Buffer,
  filename: string,
  mimetype: string,
): Promise<RuleEngineResult> {
  const invalid = checkSegments({ name });
  if (invalid) return invalid;
  const form = new FormData();
  form.append('file', new Blob([fileBuffer], { type: mimetype || 'text/csv' }), filename || 'import.csv');
  return request('post', `/api/ip-watch-groups/${encodeURIComponent(name)}/ips/csv`, { data: form });
}

// ─── Threat-intel feeds (v2) ────────────────────────────────────────────────

export const listThreatIntelFeeds = () => request('get', '/api/threat-intel-feeds');
export const createThreatIntelFeed = (body: unknown) => request('post', '/api/threat-intel-feeds', { data: body });

export const patchThreatIntelFeed = (name: string, body: unknown) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('patch', `/api/threat-intel-feeds/${encodeURIComponent(name)}`, { data: body });
};

export const deleteThreatIntelFeed = (name: string) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('delete', `/api/threat-intel-feeds/${encodeURIComponent(name)}`);
};

export const previewThreatIntelFeed = (name: string) => {
  const invalid = checkSegments({ name });
  if (invalid) return Promise.resolve(invalid);
  return request('post', `/api/threat-intel-feeds/${encodeURIComponent(name)}/preview`, { timeoutMs: RULE_ENGINE_PREVIEW_TIMEOUT_MS });
};

export const RULE_ENGINE_DEFAULT_BASE_URL = DEFAULT_RULE_ENGINE_API_URL;
