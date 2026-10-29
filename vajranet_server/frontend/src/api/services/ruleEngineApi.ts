/**
 * Rule Engine (vajra_engine detection/correlation rules) API.
 *
 * Every call here hits THIS app's own authenticated `/api/rule-engine/*`
 * routes (proxied server-side to the sibling repo's real, unauthenticated
 * `engine_v2` console at 10.0.5.32:8001 — see
 * `docs/RULE_ENGINE_UI_SPEC.md` and `~/Videos/vajra_server/rule_engine_ui/
 * API_CONTRACT.md` / `API_CONTRACT_V2.md`, read-only references this file's
 * shapes were taken from verbatim). The frontend never talks to
 * 10.0.5.32:8001 directly — same same-origin/CSRF pattern as every other
 * feature via `api/axiosInstance.ts`.
 *
 * Path prefix note: every path below is relative to axiosInstance's
 * `${API_BASE_URL}/api` baseURL, so `api.get('/rule-engine/rules')` resolves
 * to `.../api/rule-engine/rules` — matching the backend route file the spec
 * names, `backend/src/routes/api/rule-engine.ts`.
 */

import api from '../axiosInstance';

// ── Shared / rule identity ──────────────────────────────────────────────

/** A rule is uniquely identified by (source, id) — ids repeat across source files. See API_CONTRACT.md "Rule identity". */
export interface RuleRef {
  source: string;
  id: number | string;
}

// ── Detection rule condition / rule shapes (RULE_AUTHORING_TEMPLATE.md) ──

/**
 * The real, full operator list — RULE_AUTHORING_TEMPLATE.md §5. Do not add
 * ops not in this list; the engine's loader silently drops the whole
 * ruleset (falls back to 6 built-ins) on an unrecognized op.
 */
export const RULE_ENGINE_OPERATORS = [
  'equals', 'not_equals', 'contains', 'not_contains', 'regex', 'exists',
  'gt', 'lt', 'gte', 'lte', 'between', 'in_list', 'in_list_active',
  'startswith', 'endswith', 'cidr', 'windash_contains', 'base64offset_contains',
] as const;
export type RuleEngineOperator = typeof RULE_ENGINE_OPERATORS[number];

export interface RuleCondition {
  field: string;
  op: RuleEngineOperator;
  /** Always a JSON string on the wire, even for numeric-looking values (e.g. "5145" not 5145) — RULE_AUTHORING_TEMPLATE.md §1. Not required for `exists`. */
  value?: string;
  icase?: boolean;
}

export interface DetectionRule {
  source: string;
  id: number | string;
  event_type: string;
  level: number;
  description: string;
  groups: string[];
  mitre: string[];
  conditions: RuleCondition[];
  enabled: boolean;
  /** true only when source === "custom" — only custom rules can be edited/deleted. */
  editable: boolean;
  raw?: Record<string, unknown>;
}

export interface RuleListResponse {
  items: DetectionRule[];
  total: number;
}

export interface RuleListParams {
  source?: string;
  event_type?: string;
  enabled?: boolean;
  q?: string;
  mitre?: string;
  page?: number;
  page_size?: number;
}

export const listRules = async (params: RuleListParams): Promise<RuleListResponse> => {
  const response = await api.get('/rule-engine/rules', { params });
  return response.data;
};

export const getRule = async (ref: RuleRef): Promise<DetectionRule> => {
  const response = await api.get(`/rule-engine/rules/${encodeURIComponent(String(ref.source))}/${encodeURIComponent(String(ref.id))}`);
  return response.data;
};

export interface ValidateResult {
  ok: boolean;
  message: string;
  /** RULE_AUTHORING_TEMPLATE.md §8 — set when a referenced rule id collides across source files. */
  warnings?: string[];
}

/** Candidate rule JSON, e.g. `{ id?, event_type, level, description, groups, mitre, conditions, enabled? }`. `id` optional on create. */
export type NewDetectionRule = Omit<DetectionRule, 'source' | 'editable' | 'raw' | 'enabled' | 'id'> & {
  id?: number | string;
  enabled?: boolean;
};

export const validateRule = async (rule: NewDetectionRule): Promise<ValidateResult> => {
  const response = await api.post('/rule-engine/rules/validate', rule);
  return response.data;
};

export const createRule = async (rule: NewDetectionRule): Promise<DetectionRule> => {
  const response = await api.post('/rule-engine/rules', rule);
  return response.data;
};

export const setRuleEnabled = async (ref: RuleRef, enabled: boolean): Promise<DetectionRule> => {
  const response = await api.patch(`/rule-engine/rules/${encodeURIComponent(String(ref.source))}/${encodeURIComponent(String(ref.id))}`, { enabled });
  return response.data;
};

export const deleteRule = async (ref: RuleRef): Promise<void> => {
  await api.delete(`/rule-engine/rules/${encodeURIComponent(String(ref.source))}/${encodeURIComponent(String(ref.id))}`);
};

// ── Correlation rules (RULE_AUTHORING_TEMPLATE.md §8) ───────────────────

export const CORRELATION_TYPES = ['event_count', 'value_count', 'temporal', 'temporal_ordered'] as const;
export type CorrelationType = typeof CORRELATION_TYPES[number];

export interface CorrelationRule {
  source: string;
  id: number | string;
  type: CorrelationType;
  description: string;
  /** Detection rule ids this correlation references. Order matters for temporal_ordered only. */
  rules: (number | string)[];
  group_by: string[];
  /** Seconds; must be > 0 or the rule fails closed. */
  timespan: number;
  level: number;
  groups?: string[];
  mitre?: string[];
  /** event_count only */
  threshold?: number;
  /** value_count only — distinct-value field, paired with threshold */
  field?: string;
  enabled: boolean;
  editable: boolean;
  raw?: Record<string, unknown>;
}

export interface CorrelationRuleListResponse {
  items: CorrelationRule[];
  total: number;
}

export const listCorrelationRules = async (params: { source?: string; enabled?: boolean; q?: string; page?: number; page_size?: number } = {}): Promise<CorrelationRuleListResponse> => {
  const response = await api.get('/rule-engine/correlation-rules', { params });
  return response.data;
};

export const getCorrelationRule = async (ref: RuleRef): Promise<CorrelationRule> => {
  const response = await api.get(`/rule-engine/correlation-rules/${encodeURIComponent(String(ref.source))}/${encodeURIComponent(String(ref.id))}`);
  return response.data;
};

export type NewCorrelationRule = Omit<CorrelationRule, 'source' | 'editable' | 'raw' | 'enabled' | 'id'> & {
  id?: number | string;
  enabled?: boolean;
};

export const validateCorrelationRule = async (rule: NewCorrelationRule): Promise<ValidateResult> => {
  const response = await api.post('/rule-engine/correlation-rules/validate', rule);
  return response.data;
};

export const createCorrelationRule = async (rule: NewCorrelationRule): Promise<CorrelationRule> => {
  const response = await api.post('/rule-engine/correlation-rules', rule);
  return response.data;
};

export const setCorrelationRuleEnabled = async (ref: RuleRef, enabled: boolean): Promise<CorrelationRule> => {
  const response = await api.patch(`/rule-engine/correlation-rules/${encodeURIComponent(String(ref.source))}/${encodeURIComponent(String(ref.id))}`, { enabled });
  return response.data;
};

// ── Lists (CDB / threat-intel lists, read-only display) ─────────────────

export interface RuleEngineList {
  source: string;
  name: string;
  entry_count: number;
  /** Capped at 50 server-side — note truncation if entry_count > entries.length. */
  entries: string[];
}

export const getLists = async (): Promise<{ items: RuleEngineList[] }> => {
  const response = await api.get('/rule-engine/lists');
  return response.data;
};

// ── Test Event ────────────────────────────────────────────────────────

export interface TestEventExample {
  event_type: string;
  label: string;
  event: Record<string, unknown>;
}

export const getTestEventExamples = async (): Promise<{ items: TestEventExample[] }> => {
  const response = await api.get('/rule-engine/test-event/examples');
  return response.data;
};

export interface TestEventMatch {
  source: string;
  id: number | string;
  level: number;
  description: string;
}

export interface TestEventResult {
  matches: TestEventMatch[];
  /** Always present — states plainly that correlation rules are NOT evaluated by this endpoint. */
  note: string;
}

export const testEvent = async (event: Record<string, unknown>): Promise<TestEventResult> => {
  const response = await api.post('/rule-engine/test-event', { event });
  return response.data;
};

// ── Correlation Simulation (feeds a real ordered event sequence through the
// actual CorrelationEngine — the only way to exercise event_count/
// value_count/temporal/temporal_ordered end-to-end; see
// rule_engine_ui/backend/simulate.py, read read-only for this exact
// contract since it isn't in API_CONTRACT.md/_V2.md) ────────────────────

export interface SimulationSample {
  name: string;
  correlation_id: number | string;
  label: string;
  expect_incident: boolean;
  events: Record<string, unknown>[];
}

export const getSimulationSamples = async (): Promise<{ items: SimulationSample[]; total: number }> => {
  const response = await api.get('/rule-engine/simulate-correlation/samples');
  return response.data;
};

export interface SimulationAlert {
  rule_id: number | string;
  level: number;
  host: string;
  event_type: string;
  description: string;
}

export interface SimulationIncident {
  correlation_rule_id: number | string;
  type: CorrelationType;
  level: number;
  group_key: string;
  description: string;
  contributing: { rule_id: number | string; alert_id: number | string }[];
}

export interface SimulationResult {
  ok: boolean;
  message?: string;
  alerts?: SimulationAlert[];
  incidents?: SimulationIncident[];
  summary?: string;
  meta?: Record<string, unknown>;
  stderr_tail?: string;
}

export const simulateCorrelation = async (events: Record<string, unknown>[]): Promise<SimulationResult> => {
  const response = await api.post('/rule-engine/simulate-correlation', { events });
  return response.data;
};

// ── IP Watch Groups (API_CONTRACT_V2.md §2) ──────────────────────────────

export interface IpWatchGroup {
  id: number | string;
  name: string;
  list: string;
  enabled: boolean;
  level: number;
  description: string;
  event_types: string[];
  groups?: string[];
  ip_count?: number;
  /**
   * Server-computed (routes/api/rule-engine.ts's GET /ip-watch-groups):
   * whether the caller may add/remove IPs on this specific group. Always
   * true for a Super Admin; for a Group Admin, true only if their group owns
   * this watch group (see utils/ruleEngineScope.ts) — create/delete/enable-
   * disable stay Super-Admin-only regardless, so this only ever gates the
   * IP add/remove control.
   */
  canManageIps?: boolean;
}

export const listIpWatchGroups = async (): Promise<{ items: IpWatchGroup[] }> => {
  const response = await api.get('/rule-engine/ip-watch-groups');
  return response.data;
};

export type NewIpWatchGroup = Omit<IpWatchGroup, 'ip_count' | 'enabled' | 'id' | 'canManageIps'> & {
  id?: number | string;
  enabled?: boolean;
  /** Super-Admin-only, at create time: the vajranet group id to record as this watch group's owner. Never forwarded to the engine — stripped server-side. */
  ownerGroupId?: string;
};

export const createIpWatchGroup = async (group: NewIpWatchGroup): Promise<IpWatchGroup> => {
  const response = await api.post('/rule-engine/ip-watch-groups', group);
  return response.data;
};

export const setIpWatchGroupEnabled = async (name: string, enabled: boolean): Promise<IpWatchGroup> => {
  const response = await api.patch(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}`, { enabled });
  return response.data;
};

export const deleteIpWatchGroup = async (name: string): Promise<void> => {
  await api.delete(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}`);
};

export const getIpWatchGroupIps = async (name: string, params: { page?: number; page_size?: number } = {}): Promise<{ items: string[]; total: number }> => {
  const response = await api.get(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}/ips`, { params });
  return response.data;
};

// Matches rule_engine_ui's real add_ips() response shape exactly (backend/
// ip_watch_groups.py) -- NOT the same shape as CsvImportSummary below
// (that endpoint really does return "skipped"; this one returns "errors"/
// "duplicates"/"cap_hit" separately). Fixed here after a review found this
// interface previously claimed a non-existent "skipped" field, which meant
// a duplicate/invalid/cap-hit add response (still HTTP 200, added: 0) was
// silently treated as full success by the caller.
export interface AddIpsSummary {
  added: number;
  duplicates: number;
  errors: { value: string; reason: string }[];
  list: string;
  cap_hit: boolean;
}

export const addIpWatchGroupIps = async (name: string, ips: string[]): Promise<AddIpsSummary> => {
  const response = await api.post(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}/ips`, { ips });
  return response.data;
};

export interface CsvImportSummary {
  added: number;
  skipped: { line: number; value: string; reason: string }[];
  duplicates: number;
}

export const importIpWatchGroupCsv = async (name: string, file: File): Promise<CsvImportSummary> => {
  const form = new FormData();
  form.append('file', file);
  // Deliberately no explicit Content-Type header: axios/the browser must set
  // `multipart/form-data; boundary=...` itself from the FormData instance —
  // a hand-set header without the boundary parameter would break server-side
  // multipart parsing.
  const response = await api.post(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}/ips/csv`, form);
  return response.data;
};

export const deleteIpWatchGroupIp = async (name: string, ip: string): Promise<void> => {
  await api.delete(`/rule-engine/ip-watch-groups/${encodeURIComponent(name)}/ips/${encodeURIComponent(ip)}`);
};

// ── STIX / threat-intel feeds (API_CONTRACT_V2.md §3 — "STIX Feeds", never
// "STIX/TAXII": TAXII polling is not implemented anywhere in the engine) ──

export type ThreatIntelFeedFormat = 'abuseipdb' | 'stix';
export const THREAT_INTEL_STIX_TYPES = ['ip', 'domain', 'hash'] as const;
export type ThreatIntelStixType = typeof THREAT_INTEL_STIX_TYPES[number];

export interface ThreatIntelFeed {
  name: string;
  format: ThreatIntelFeedFormat;
  enabled: boolean;
  url: string;
  api_key?: string;
  target_list: string;
  refresh_interval_seconds: number;
  max_entries: number;
  stix_types?: ThreatIntelStixType[];
}

export const listThreatIntelFeeds = async (): Promise<{ items: ThreatIntelFeed[] }> => {
  const response = await api.get('/rule-engine/threat-intel-feeds');
  return response.data;
};

export const createThreatIntelFeed = async (feed: ThreatIntelFeed): Promise<ThreatIntelFeed> => {
  const response = await api.post('/rule-engine/threat-intel-feeds', feed);
  return response.data;
};

export const updateThreatIntelFeed = async (name: string, feed: Partial<ThreatIntelFeed>): Promise<ThreatIntelFeed> => {
  const response = await api.patch(`/rule-engine/threat-intel-feeds/${encodeURIComponent(name)}`, feed);
  return response.data;
};

export const deleteThreatIntelFeed = async (name: string): Promise<void> => {
  await api.delete(`/rule-engine/threat-intel-feeds/${encodeURIComponent(name)}`);
};

export interface ThreatIntelPreviewResult {
  ok: boolean;
  message?: string;
  counts?: Partial<Record<ThreatIntelStixType, number>>;
}

export const previewThreatIntelFeed = async (name: string): Promise<ThreatIntelPreviewResult> => {
  const response = await api.post(`/rule-engine/threat-intel-feeds/${encodeURIComponent(name)}/preview`);
  return response.data;
};

// ── Live Reload (API_CONTRACT_V2.md §1) — surfaced read-mostly here; pushing
// a reload is a deliberately heavier action, gated the same as other writes. ──

export interface LiveInstanceConfig {
  configured: boolean;
  ruleset_path?: string;
  pid?: number;
  metrics_url?: string | null;
  /** Backend's liveness probe result — not just the stored config. */
  alive?: boolean;
}

export const getLiveInstance = async (): Promise<LiveInstanceConfig> => {
  const response = await api.get('/rule-engine/live-instance');
  return response.data;
};

export const setLiveInstance = async (config: { ruleset_path: string; pid: number; metrics_url?: string | null }): Promise<LiveInstanceConfig> => {
  const response = await api.post('/rule-engine/live-instance', config);
  return response.data;
};

export interface ReloadResult {
  ok: boolean;
  message: string;
  active_rules?: number;
  confirmed?: boolean;
}

export const reloadLiveInstance = async (): Promise<ReloadResult> => {
  const response = await api.post('/rule-engine/live-instance/reload');
  return response.data;
};
