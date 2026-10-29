/**
 * File Integrity Monitoring (FIM) API — this app's own authenticated
 * `/api/fim/*` routes. Shapes follow docs/FIM_DESIGN.md ("API shapes") in the
 * vajra_server repo. All paths are relative to axiosInstance's `/api` baseURL.
 * Times are unix seconds. List endpoints return {items,total,page,pageSize}.
 */

import api from '../axiosInstance';

export type FimSeverity = 'critical' | 'high' | 'medium' | 'low';
export type FimOsPlatform = 'linux' | 'windows';
export type FimMode = 'learn' | 'enforce';
export type FimChangeType = 'added' | 'removed' | 'modified' | 'attributes';
export type FimDriftStatus = 'open' | 'approved' | 'rejected' | 'ignored';
export type FimResolveAction = 'approve' | 'reject' | 'ignore';

export type FimEntryKind = 'path' | 'xattr' | 'registry' | 'acl' | 'table';
export type FimItemKind = 'file' | 'directory' | 'item';

/**
 * One policy entry (= one scan query). `kind` defaults to 'path'. For item kinds the server
 * fills label/prefix/keyColumns/valueColumns (never send them).
 */
export interface FimPolicyPath {
  kind?: FimEntryKind;
  path?: string;
  severity: FimSeverity;
  category: string;
  ignore: string[];
  hash: boolean;
  /** table only: catalog source id. */
  source?: string;
  label?: string;
  keyColumns?: string[];
  valueColumns?: string[];
  extensionEnabled?: boolean;
}

export interface FimCatalogSource {
  id: string;
  label: string;
  platform: FimOsPlatform;
  description: string;
  category: string;
  severity: FimSeverity;
  keyColumns: string[];
  valueColumns: string[];
  intervalHint: number;
  notes: string | null;
  /** false = written from the osquery schema but not executed against a real agent. */
  verified: boolean;
  requiresExtension: boolean;
}

/** type: contract leaves the exact vocabulary open; see FileIntegrity/constants TARGET_TYPES. */
export interface FimTarget {
  type: string;
  value: string;
}

export interface FimPolicyStats {
  /** In-scope hosts, and how many do / do not have an initialised (locked) baseline. */
  hosts: number;
  hostsBaselined?: number;
  hostsNotBaselined?: number;
  /** Legacy aliases of hostsNotBaselined / hostsBaselined. */
  learning: number;
  locked: number;
  baselineFiles: number;
  openDrift: number;
}

export interface FimPolicy {
  id: number;
  name: string;
  description: string;
  osPlatform: FimOsPlatform;
  paths: FimPolicyPath[];
  scanIntervalSecs: number;
  realtime: boolean;
  mode: FimMode;
  learnScans: number;
  enabled: boolean;
  template: string | null;
  configQueryId: number | null;
  /** Policy revision (bumped when paths/platform change) and the revision last published. */
  rev?: number;
  publishedRev?: number | null;
  /** Soft warnings (e.g. patterns likely to exceed the osquery line limit). */
  warnings?: string[];
  targets: FimTarget[];
  stats: FimPolicyStats;
  /** 'registry_node' = per-node registry coverage policy, managed only via /fim/registry (read-only here). */
  managedKind?: 'registry_node' | null;
  managedHost?: string | null;
  createdBy: string | null;
  createdAt: number;
  updatedAt: number;
}

export type FimPolicyInput = Pick<
  FimPolicy,
  'name' | 'description' | 'osPlatform' | 'paths' | 'scanIntervalSecs' | 'realtime' | 'mode' | 'enabled' | 'targets'
> & { template?: string | null };

export interface FimTemplate {
  id: string;
  name: string;
  description: string;
  osPlatform: FimOsPlatform;
  paths: FimPolicyPath[];
  scanIntervalSecs: number;
  realtime: boolean;
}

export interface FimDrift {
  id: number;
  policyId: number;
  policyName: string;
  /** True when the policy was deleted; the drift is kept as audit history (only 'ignore' is allowed). */
  policyDeleted?: boolean;
  hostIdentifier: string;
  hostname: string | null;
  path: string;
  kind?: FimItemKind;
  entryIdx?: number | null;
  changeType: FimChangeType;
  source: string;
  severity: FimSeverity;
  oldSha256: string | null;
  newSha256: string | null;
  /** Attribute snapshots (size/mode/uid/gid/mtime...); may arrive as object or JSON string. */
  oldAttrs: Record<string, unknown> | string | null;
  newAttrs: Record<string, unknown> | string | null;
  actorProcess: string | null;
  actorUser: string | null;
  status: FimDriftStatus;
  occurrences: number;
  detectedAt: number;
  lastSeenAt: number;
  resolvedBy: string | null;
  resolvedAt: number | null;
  note: string | null;
  /** Registry: a check scan found the value back at the baseline after a real-time change (kept open). */
  reverted?: boolean;
  /** Registry: a check scan confirmed the change in osquery's own format. */
  confirmedAt?: number | null;
  /** Digest of the drift's reviewed CONTENT (change type, hash, attributes); sent back in `expected` when approving. */
  contentHash: string | null;
}

export interface FimBaselineItem {
  policyId: number;
  hostIdentifier: string;
  path: string;
  kind?: FimItemKind;
  entryIdx?: number | null;
  /** Observed columns of an item-kind baseline entry. */
  data?: Record<string, unknown> | null;
  sha256: string | null;
  md5: string | null;
  size: number | null;
  mode: string | null;
  uid: number | null;
  gid: number | null;
  mtime: number | null;
  firstSeen: number;
  lastSeen: number;
  approvedBy: string | null;
}

export interface FimSummary {
  openDrift: number;
  bySeverity: Record<FimSeverity, number>;
  baselineByKind?: Record<FimItemKind, number>;
  openDriftByKind?: Record<FimItemKind, number>;
  /** Entries of enabled policies by entry kind (what is covered). */
  entriesByKind?: Record<FimEntryKind, number>;
  openAlerts?: number;
  openAlertsBySeverity?: Record<FimSeverity, number>;
  hostsMonitored: number;
  hostsBaselined?: number;
  hostsNotBaselined?: number;
  /** Legacy aliases. */
  hostsLearning: number;
  hostsLocked: number;
  baselineFiles: number;
  driftLast24h: number;
  topHosts: { hostIdentifier: string; hostname: string | null; count: number }[];
  topPaths: { path: string; count: number }[];
  trend: { day: string; count: number }[];
}

export interface FimPage<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface FimDriftQuery {
  status?: string;
  severity?: string;
  host?: string;
  policy?: string | number;
  q?: string;
  page?: number;
}

export interface FimBaselineQuery {
  kind?: string;
  policy?: string | number;
  host?: string;
  q?: string;
  page?: number;
}

const clean = <T extends object>(p: T): Partial<T> =>
  Object.fromEntries(Object.entries(p).filter(([, v]) => v !== undefined && v !== '')) as Partial<T>;

export const listFimPolicies = async (): Promise<FimPage<FimPolicy>> =>
  (await api.get('/fim/policies')).data;
export const getFimPolicy = async (id: number): Promise<FimPolicy> =>
  (await api.get(`/fim/policies/${id}`)).data;
export const createFimPolicy = async (body: FimPolicyInput): Promise<FimPolicy> =>
  (await api.post('/fim/policies', body)).data;
export const updateFimPolicy = async (id: number, body: Partial<FimPolicyInput>): Promise<FimPolicy> =>
  (await api.put(`/fim/policies/${id}`, body)).data;
export const deleteFimPolicy = async (id: number): Promise<void> => {
  await api.delete(`/fim/policies/${id}`);
};
export const publishFimPolicy = async (id: number): Promise<unknown> =>
  (await api.post(`/fim/policies/${id}/publish`)).data;
export const listFimCatalog = async (platform?: FimOsPlatform): Promise<{ items: FimCatalogSource[]; total: number }> =>
  (await api.get('/fim/catalog', { params: platform ? { platform } : {} })).data;
export const listFimTemplates = async (): Promise<FimTemplate[] | FimPage<FimTemplate>> =>
  (await api.get('/fim/templates')).data;

export const listFimDrift = async (q: FimDriftQuery): Promise<FimPage<FimDrift>> =>
  (await api.get('/fim/drift', { params: clean(q) })).data;
export const getFimDrift = async (id: number): Promise<FimDrift> =>
  (await api.get(`/fim/drift/${id}`)).data;
/** What the analyst saw for one drift when approving it (TOCTOU guard; 409 'drift_changed' when it moved since). */
/** What the analyst reviewed for one drift: only its content digest (occurrences / last-seen do not matter). */
export interface FimDriftExpectedItem { contentHash: string }
/** `expected` body for approving, keyed by drift id. */
export type FimDriftExpected = Record<string, FimDriftExpectedItem>;

/** Per-item outcome of a bulk resolve / alert close. */
export type FimBulkOutcome = 'resolved' | 'closed' | 'drift_changed' | 'awaiting_confirmation' | 'skipped';
export interface FimBulkItemResult {
  /** resolve: the drift id; alerts/close: the alert id. */
  id: number;
  /** alerts/close: the linked drift id. */
  driftId?: number | null;
  outcome: FimBulkOutcome;
  /** drift_changed: the drift's current values. */
  current?: { contentHash: string | null; newSha256: string | null; changeType: string; lastSeenAt: number };
}
export interface FimResolveResult { resolved: number; skipped: number; ids?: number[]; results?: FimBulkItemResult[] }
export interface FimCloseAlertsResult { closed: number; skipped: number; ids?: number[]; results?: FimBulkItemResult[] }

export interface FimResolveOpts {
  acceptUnverified?: boolean;
  /** Required by the server for action 'approve'. */
  expected?: FimDriftExpected;
  /** All-or-nothing approve (server default: true for one id, per item for several). */
  atomic?: boolean;
}

/**
 * Single id (or atomic): a refused approve is a 409 (errors[0] 'drift_changed' / 'awaiting_confirmation').
 * Several ids: 200 with per-item `results`; refused items stay open.
 */
export const resolveFimDrift = async (ids: number[], action: FimResolveAction, note: string, opts: FimResolveOpts = {}): Promise<FimResolveResult> =>
  (await api.post('/fim/drift/resolve', {
    ids, action, note,
    ...(opts.acceptUnverified ? { acceptUnverified: true } : {}),
    ...(opts.expected ? { expected: opts.expected } : {}),
    ...(opts.atomic !== undefined ? { atomic: opts.atomic } : {}),
  })).data;

/** Ask for a check scan of an unconfirmed real-time registry drift. queued=false: one is already pending / rate-limited. */
export const recheckFimDrift = async (id: number): Promise<{ status: string; queued: boolean; retryAfterSecs: number }> =>
  (await api.post(`/fim/drift/${id}/recheck`)).data;

export interface FimInitResult {
  status: string;
  batchId: string | null;
  hosts: number;
  requests: number;
  skipped: { hostIdentifier: string; reason: 'out-of-scope' }[];
  /** Pending requests of the same hosts that this call replaced. */
  superseded?: number;
}
export type FimInitStatus = 'none' | 'pending' | 'partial' | 'done' | 'failed';
export interface FimInitHost {
  hostIdentifier: string;
  hostname: string | null;
  status: FimInitStatus;
  entries: { done: number; pending: number; failed: number; expired: number };
  lastInitAt: number | null;
  latestVersion: number | null;
}
export interface FimInitialization {
  totals: Record<FimInitStatus, number>;
  hostsBaselined?: number;
  hostsNotBaselined?: number;
  hosts: FimInitHost[];
  total: number;
  page: number;
  pageSize: number;
}
export interface FimAlert {
  alertId: number;
  /** fim_config: registry-coverage configuration events (waivers, coverage reductions, invalid nodes). */
  alertType: 'fim' | 'fim_health' | 'fim_config';
  severity: string;
  eventCode: string;
  hostIdentifier: string;
  hostname: string | null;
  detectedAt: number | null;
  isOpen: boolean;
  markType: 'true_positive' | 'false_positive' | null;
  remarks: string | null;
  policyId: number | null;
  policyName: string | null;
  driftId: number | null;
  kind?: FimItemKind | null;
  changeType: FimChangeType | null;
  path: string | null;
  source: string | null;
  oldSha256: string | null;
  newSha256: string | null;
  actorProcess: string | null;
  actorUser: string | null;
  occurrences: number | null;
  driftStatus: FimDriftStatus | null;
  /** lastSeenAt of the linked drift (display only). */
  driftLastSeenAt?: number | null;
  /** Content digest of the linked drift (sent back in `expected` when approving); null without linked drift. */
  contentHash: string | null;
  /** Linked registry drift: confirmed by a check scan (real-time drift is approvable only then). */
  driftConfirmedAt?: number | null;
  /** Linked registry drift: value back at the baseline after a real-time change (kept open). */
  driftReverted?: boolean;
  /** Caller may close / reopen this alert (fim_config alerts: Super Admins only). */
  canClose?: boolean;
  /**
   * Raw alert metadata when the server includes it (fim_config: `by` e-mail / `byUserId` of the
   * user whose action raised it). Used client-side to hide Close on one's own oversight alert.
   */
  metadata?: unknown;
}
export interface FimAlertPage extends FimPage<FimAlert> {
  counts: { open: number; closed: number; truePositive: number; falsePositive: number };
}
export interface FimAlertQuery {
  status?: 'open' | 'closed' | 'all';
  verdict?: string;
  severity?: string;
  type?: string;
  policy?: string | number;
  host?: string;
  q?: string;
  page?: number;
}
export type FimAlertVerdict = 'true_positive' | 'false_positive';

export interface FimBaselineVersion {
  policyId: number;
  policyName: string;
  hostIdentifier: string;
  hostname: string | null;
  version: number;
  reason: string;
  createdBy: string | null;
  note: string | null;
  createdAt: number;
  fileCount: number;
  digest: string;
}

export const initializeFimBaseline = async (id: number, note: string, hosts?: string[]): Promise<FimInitResult> =>
  (await api.post(`/fim/policies/${id}/initialize`, { note, ...(hosts && hosts.length ? { hosts } : {}) })).data;
export const getFimInitialization = async (id: number, params: { status?: string; q?: string; page?: number; pageSize?: number } = {}): Promise<FimInitialization> =>
  (await api.get(`/fim/policies/${id}/initialization`, { params: clean(params) })).data;
export const listFimBaselineVersions = async (q: { policy?: string | number; host?: string; page?: number }): Promise<FimPage<FimBaselineVersion>> =>
  (await api.get('/fim/baseline/versions', { params: clean(q) })).data;

export const listFimAlerts = async (q: FimAlertQuery): Promise<FimAlertPage> =>
  (await api.get('/fim/alerts', { params: clean(q) })).data;
export interface FimCloseAlertsOpts {
  approveChange?: boolean;
  acceptUnverified?: boolean;
  /** Keyed by the alerts' driftId; required by the server with approveChange. */
  expected?: FimDriftExpected;
  /** All-or-nothing (server default: true for one id, per item for several). */
  atomic?: boolean;
}
/** Several ids: alerts whose drift approval was refused stay open and are reported in `results`. */
export const closeFimAlerts = async (ids: number[], verdict: FimAlertVerdict, note: string, opts: FimCloseAlertsOpts = {}): Promise<FimCloseAlertsResult> =>
  (await api.post('/fim/alerts/close', {
    ids, verdict, note,
    ...(opts.approveChange ? { approveChange: true } : {}),
    ...(opts.acceptUnverified ? { acceptUnverified: true } : {}),
    ...(opts.expected ? { expected: opts.expected } : {}),
    ...(opts.atomic !== undefined ? { atomic: opts.atomic } : {}),
  })).data;
export const reopenFimAlerts = async (ids: number[], note?: string): Promise<{ reopened: number; skipped: number }> =>
  (await api.post('/fim/alerts/reopen', { ids, ...(note ? { note } : {}) })).data;

export const listFimBaseline = async (q: FimBaselineQuery): Promise<FimPage<FimBaselineItem>> =>
  (await api.get('/fim/baseline', { params: clean(q) })).data;
export const getFimSummary = async (): Promise<FimSummary> =>
  (await api.get('/fim/summary')).data;

// =============================================================================================
// Per-node Windows registry coverage (/api/fim/registry/*). Contract:
// docs/FIM_REGISTRY_DESIGN.md (vajra_server repo) §3.12-§3.14. Everything that comes back from
// endpoints (registry paths, value names, data) is UNTRUSTED: render as text only.
// =============================================================================================

export type FimRegTier = 'essential' | 'recommended' | 'comprehensive';
export type FimRegLayer = 'profile' | 'group' | 'node';
export type FimRegOp = 'add' | 'disable' | 'exclude' | 'filter' | 'severity';
export type FimRegStatus = 'in_sync' | 'pending' | 'needs_init' | 'invalid' | 'unmanaged';
export type FimRegWaiverAction = 'disable' | 'narrow' | 'lower_severity' | 'opt_out';
export type FimRegWaiverStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';

export interface FimRegEstimate { rows: number; bytes: number; basis: 'measured' | 'estimated' | 'unknown' }

export interface FimRegLimits {
  entryBytesBlock: number; entryBytesWarn: number; entryRowsBlock: number; entryRowsWarn: number;
  entriesPerNode: number; totalRowsPerNode: number; pathsMax: number; rulesPerScope: number;
  valuesMax: number; ignoreValuesMax: number; excludeKeysMax: number; waiverMaxDays: number;
  measurePerHostPer10Min: number; publishBatchMax: number; publishConfirmAbove: number;
}

export interface FimRegCatalogItem {
  id: string;
  tier: FimRegTier;
  /** Not part of any tier: only included by an explicit 'add' rule. */
  optInOnly: boolean;
  path: string;
  values: string[];
  ignoreValues: string[];
  redactValues: string[];
  includeSubkeys: boolean;
  anchor: boolean;
  hiveScoped: boolean;
  label: string;
  category: string;
  severity: FimSeverity;
  attack: string[];
  estimate: FimRegEstimate;
  noise: 'none' | 'low' | 'medium' | 'high';
  /** false = estimate/behaviour not yet confirmed on a Windows agent. */
  verified: boolean;
  protected: boolean;
  realtimeRequired: boolean;
  notes: string | null;
}

export interface FimRegTierSummary { entries: number; rows: number; bytes: number }

export interface FimRegCatalog {
  version: number;
  items: FimRegCatalogItem[];
  tiers: Record<FimRegTier, FimRegTierSummary>;
  limits: FimRegLimits;
}

export interface FimRegSettings {
  managedEnabled: boolean;
  updatedBy: string | null;
  updatedAt: number | null;
  catalogVersion: number;
  limits: FimRegLimits;
  /** Caller can change settings / profiles / approve waivers (Super Admin). */
  isSuperAdmin: boolean;
  /** Designated waiver approvers (in addition to Super Admins). */
  approvers?: FimRegApprover[];
  /** Caller is a Super Admin or a designated approver (never for their own requests). */
  canApproveWaivers?: boolean;
  /** Health: the registry history hash chain is keyed (false = FIM_HISTORY_ALLOW_UNKEYED, weaker tamper evidence). */
  historyKeyed?: boolean;
  /** Non-null when the server disabled registry writes (e.g. FIM_HISTORY_HMAC_KEY missing while managed coverage is on). */
  registryDisabledReason?: string | null;
  /** Server health warnings (perf indexes building / missing, schema invariants re-applied, ...). */
  healthWarnings?: string[];
}

export interface FimRegApprover { userId: number; email: string }
export interface FimRegApproverCandidate { userId: number; email: string; role: string }

export interface FimRegRule {
  id: number;
  layer: FimRegLayer;
  scopeValue: string;
  op: FimRegOp;
  /** catalog id | custom:<16 hex> | '*' (exclude only) */
  target: string;
  spec: Record<string, unknown>;
  reason: string;
  waiverId: number | null;
  status: 'active' | 'revoked';
  createdBy: string;
  createdAt: number;
  revokedBy: string | null;
  revokedAt: number | null;
  /** Caller may revoke this rule. */
  canManage?: boolean;
}

/** Body of POST /rules (and of a preview change). spec by op:
 *  add (catalog): {} ; add (custom): {path, values?, ignoreValues?, excludeKeys?, severity, category?, label?, measureOverride?}
 *  disable: {} ; exclude: {ignoreValues?, excludeKeys?} ; filter: {values} ; severity: {severity} */
export interface FimRegRuleInput {
  layer: FimRegLayer;
  scopeValue: string;
  op: FimRegOp;
  target: string;
  spec: Record<string, unknown>;
  reason: string;
  waiverId?: number | null;
}

export interface FimRegProfile {
  id: number;
  name: string;
  description: string;
  tier: FimRegTier;
  isDefault: boolean;
  scanIntervalSecs: number;
  mode: FimMode;
  version: number;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: number;
  updatedAt: number;
  /** Windows nodes whose effective profile is this one. */
  affectedNodes: number;
  rules: FimRegRule[];
  /** Digest of the profile as listed; sent back as expectedProfileDigest when publishing (409 when stale). */
  digest: string;
}

export interface FimRegProfileInput {
  name: string;
  description: string;
  tier: FimRegTier;
  isDefault: boolean;
  scanIntervalSecs: number;
  mode: FimMode;
  reason: string;
  /** Required on update (optimistic concurrency; 409 when stale). */
  version?: number;
}

export interface FimRegAssignment {
  scopeType: 'group' | 'node';
  scopeValue: string;
  profileId: number | null;
  tier: FimRegTier | null;
  version: number;
  updatedBy: string | null;
  updatedAt: number;
}

export interface FimRegWaiver {
  id: number;
  entryKey: string;
  scopeType: FimRegLayer;
  scopeValue: string;
  action: FimRegWaiverAction;
  reason: string;
  requestedBy: string;
  requestedAt: number;
  approvedBy: string | null;
  approvedAt: number | null;
  decisionNote: string | null;
  expiresAt: number;
  status: FimRegWaiverStatus;
  revokedBy: string | null;
  revokedAt: number | null;
  /** Caller may approve/reject (Super Admin and not the requester). */
  canDecide: boolean;
  /** Caller may revoke (Super Admin or the requester while in scope). */
  canRevoke: boolean;
  /** The one exact rule this waiver is bound to (single use). */
  rule?: FimRegWaiverRule | null;
  /** Rule created from this waiver via POST /waivers/:id/apply (null until used). */
  ruleId?: number | null;
}

/** Rule body a waiver is bound to (layer/scopeValue come from the waiver's scopeType/scopeValue). */
export interface FimRegWaiverRule { op: FimRegOp | string; target: string; spec: Record<string, unknown> }

export interface FimRegWaiverInput {
  entryKey: string;
  scopeType: FimRegLayer;
  scopeValue: string;
  action: FimRegWaiverAction;
  reason: string;
  /** unix seconds; at most 30 days from now */
  expiresAt: number;
  /** The exact rule the waiver authorises (required). */
  rule: FimRegWaiverRule;
}

export type FimRegSourceBadge =
  | { layer: 'builtin'; tier: FimRegTier }
  | { layer: 'profile' | 'group' | 'node'; ruleId: number; op: FimRegOp; scopeValue: string }
  | { layer: 'merge'; from: string[] }
  | { layer: 'carve'; from: string };

export interface FimRegEntry {
  /** Slot index in the managed policy (null = not published yet). */
  slot: number | null;
  entryKey: string;
  path: string;
  values: string[];
  ignoreValues: string[];
  excludeKeys: string[];
  includeSubkeys: boolean;
  anchor: boolean;
  hiveScoped: boolean;
  redactValues: string[];
  severity: FimSeverity;
  category: string;
  label: string;
  protected: boolean;
  verified: boolean;
  realtimeRequired: boolean;
  tier: FimRegTier | null;
  sources: FimRegSourceBadge[];
  attack: string[];
  estimate: FimRegEstimate;
  fingerprint: string;
  /** Present on node views once published. */
  baseline: { rows: number; lastScanAt: number | null; state: 'locked' | 'learning' | 'none' } | null;
  /** Hive-scoped entries: when each user hive was last seen in a scan. */
  hives: { sid: string; lastSeen: number }[] | null;
  /** Unpublished change relative to the published config. */
  pending: 'added' | 'changed' | 'severity' | null;
  needsInit: boolean;
}

export interface FimRegBlocked { ruleId: number; layer: FimRegLayer; op: FimRegOp; target: string; entryKey: string; reason: string }

export interface FimRegNodeCoverage {
  host: string;
  hostname: string | null;
  ownerGroupId: string | null;
  policyId: number | null;
  rev: number | null;
  publishedRev: number | null;
  profile: { id: number; name: string; source: 'node' | 'group' | 'default' };
  tier: { value: FimRegTier; source: 'node' | 'group' | 'profile' };
  scanIntervalSecs: number;
  mode: FimMode;
  status: FimRegStatus;
  /** win_registry_events seen from this host in the last 24 h (plgx agents only). */
  realtimeAvailable: boolean;
  resolvedHash: string;
  publishedHash: string | null;
  catalogVersion: number;
  entries: FimRegEntry[];
  /** Published slots that the current resolution no longer contains (removed on next Apply). */
  retiredPending: { slot: number; entryKey: string; path: string }[];
  blocked: FimRegBlocked[];
  warnings: string[];
  errors: string[];
  totals: FimRegTierSummary;
  tierOptions: Record<FimRegTier, FimRegTierSummary>;
  rules: Record<FimRegLayer, FimRegRule[]>;
  assignment: { node: FimRegAssignment | null; group: FimRegAssignment | null };
  waivers: FimRegWaiver[];
  needsInitSlots: number[];
  canManage: boolean;
  managedEnabled: boolean;
}

export interface FimRegNodeRow {
  host: string;
  hostname: string | null;
  ownerGroupId: string | null;
  status: FimRegStatus;
  policyId: number | null;
  profileName: string | null;
  tier: FimRegTier | null;
  entries: number;
  needsInit: number;
  nodeRules: number;
  realtimeAvailable: boolean;
  publishedAt: number | null;
  /** Resolved coverage hash of this node as listed (the reviewed value for a hosts publish). */
  resolvedHash?: string;
}

/** A preview change: add a rule at the node layer or revoke an existing rule. */
export type FimRegChange =
  | { action: 'add'; rule: Omit<FimRegRuleInput, 'layer' | 'scopeValue'> }
  | { action: 'revoke'; ruleId: number };

export interface FimRegPreview {
  ok: boolean;
  resolvedHash: string;
  entries: FimRegEntry[];
  diff: {
    added: FimRegEntry[];
    removed: { slot: number | null; entryKey: string; path: string }[];
    changed: FimRegEntry[];
    severityOnly: FimRegEntry[];
  };
  needsInit: string[];
  estimate: { before: FimRegTierSummary; after: FimRegTierSummary };
  rev: { current: number | null; next: number | null };
  blocked: FimRegBlocked[];
  errors: string[];
  warnings: string[];
}

export interface FimRegMeasure {
  id: number;
  host: string;
  entryKey: string;
  status: 'pending' | 'done' | 'failed';
  rows: number | null;
  bytes: number | null;
  error: string | null;
  createdAt: number;
  completedAt: number | null;
}

export interface FimRegPublishResult {
  host: string;
  status: FimRegStatus;
  policyId: number | null;
  rev: number | null;
  revChanged: boolean;
  needsInit: number[];
  retired: number[];
  error: string | null;
}

export interface FimRegHistoryItem {
  id: number;
  scopeType: string;
  scopeValue: string;
  actor: string;
  at: number;
  reason: string | null;
  snapshot: Record<string, unknown>;
  rowHash: string;
  prevHash: string | null;
}

export interface FimRegNeedsInit {
  host: string;
  hostname: string | null;
  policyId: number;
  slots: { slot: number; entryKey: string; path: string }[];
  since: number | null;
}

export interface FimRegGroupCoverage {
  groupId: string;
  assignment: FimRegAssignment | null;
  profile: { id: number; name: string; source: 'group' | 'default' };
  tier: { value: FimRegTier; source: 'group' | 'profile' };
  /** Effective entries for a member with no node-level rules. */
  entries: FimRegEntry[];
  blocked: FimRegBlocked[];
  warnings: string[];
  errors: string[];
  totals: FimRegTierSummary;
  tierOptions: Record<FimRegTier, FimRegTierSummary>;
  rules: { group: FimRegRule[]; profile: FimRegRule[] };
  waivers: FimRegWaiver[];
  members: FimRegNodeRow[];
  canManage: boolean;
  /** Digest of the resolved group coverage as shown; sent back as expectedGroupHash when publishing (409 when stale). */
  resolvedHash: string;
}

export interface FimRegHygieneFinding {
  itemPath: string;
  sha256: string;
  rule: string;
  detail: string;
  severity: FimSeverity;
  acked: boolean;
  ackedBy: string | null;
  ackedAt: number | null;
  note: string | null;
}

export interface FimRegLegacyMapping {
  index: number;
  path: string;
  mapping: { type: 'catalog'; entryKey: string; exact: boolean } | { type: 'custom'; spec: Record<string, unknown> } | { type: 'invalid'; error: string };
}
export interface FimRegLegacyPolicy {
  id: number;
  name: string;
  template: string | null;
  targets: FimTarget[];
  entries: FimRegLegacyMapping[];
  /** Hosts that also have a managed registry policy (both alert until the legacy entries are removed). */
  overlapHosts: number;
  templateUpgradeAvailable: boolean;
}

const R = '/fim/registry';
export const getFimRegSettings = async (): Promise<FimRegSettings> => (await api.get(`${R}/settings`)).data;
export const updateFimRegSettings = async (body: { managedEnabled: boolean; note: string; confirm: boolean }): Promise<FimRegSettings> =>
  (await api.put(`${R}/settings`, body)).data;
export const listFimRegApproverCandidates = async (): Promise<{ items: FimRegApproverCandidate[] }> => (await api.get(`${R}/approver-candidates`)).data;
export const putFimRegApprovers = async (body: { userIds: number[]; note: string }): Promise<FimRegSettings> => (await api.put(`${R}/settings/approvers`, body)).data;
export const getFimRegCatalog = async (): Promise<FimRegCatalog> => (await api.get(`${R}/catalog`)).data;

export const listFimRegProfiles = async (): Promise<{ items: FimRegProfile[] }> => (await api.get(`${R}/profiles`)).data;
export const getFimRegProfile = async (id: number): Promise<FimRegProfile> => (await api.get(`${R}/profiles/${id}`)).data;
export const createFimRegProfile = async (body: FimRegProfileInput): Promise<FimRegProfile> => (await api.post(`${R}/profiles`, body)).data;
export const updateFimRegProfile = async (id: number, body: FimRegProfileInput): Promise<FimRegProfile> => (await api.put(`${R}/profiles/${id}`, body)).data;
export const deleteFimRegProfile = async (id: number, reason: string): Promise<void> => { await api.delete(`${R}/profiles/${id}`, { data: { reason } }); };

export const listFimRegAssignments = async (q: { scopeType?: 'group' | 'node'; scopeValue?: string } = {}): Promise<{ items: FimRegAssignment[] }> =>
  (await api.get(`${R}/assignments`, { params: clean({ scope_type: q.scopeType, scope_value: q.scopeValue }) })).data;
export const putFimRegAssignment = async (scopeType: 'group' | 'node', scopeValue: string, body: { profileId: number | null; tier: FimRegTier | null; reason: string; version?: number }): Promise<FimRegAssignment | null> =>
  (await api.put(`${R}/assignments/${scopeType}/${encodeURIComponent(scopeValue)}`, body)).data;

export const listFimRegRules = async (q: { layer?: FimRegLayer; scopeValue?: string } = {}): Promise<{ items: FimRegRule[] }> =>
  (await api.get(`${R}/rules`, { params: clean({ layer: q.layer, scope_value: q.scopeValue }) })).data;
export const createFimRegRule = async (body: FimRegRuleInput): Promise<FimRegRule> => (await api.post(`${R}/rules`, body)).data;
export const revokeFimRegRule = async (id: number, reason: string): Promise<void> => { await api.delete(`${R}/rules/${id}`, { data: { reason } }); };

export const listFimRegWaivers = async (q: { status?: FimRegWaiverStatus; scopeType?: FimRegLayer; scopeValue?: string } = {}): Promise<{ items: FimRegWaiver[] }> =>
  (await api.get(`${R}/waivers`, { params: clean({ status: q.status, scope_type: q.scopeType, scope_value: q.scopeValue }) })).data;
export const requestFimRegWaiver = async (body: FimRegWaiverInput): Promise<FimRegWaiver> => (await api.post(`${R}/waivers`, body)).data;
/** Creates the approved, unused waiver's stored rule (201 FimRegRule; 409 if used / not approved / expired). */
export const applyFimRegWaiver = async (id: number, note: string): Promise<FimRegRule> =>
  (await api.post(`${R}/waivers/${id}/apply`, { note })).data;
export const decideFimRegWaiver = async (id: number, decision: 'approve' | 'reject' | 'revoke', note: string): Promise<FimRegWaiver> =>
  (await api.post(`${R}/waivers/${id}/${decision}`, { note })).data;

export const listFimRegNodes = async (q: { q?: string; status?: string; group?: string; page?: number } = {}): Promise<FimPage<FimRegNodeRow>> =>
  (await api.get(`${R}/nodes`, { params: clean(q) })).data;
export const getFimRegNode = async (host: string): Promise<FimRegNodeCoverage> => (await api.get(`${R}/nodes/${encodeURIComponent(host)}`)).data;
export const previewFimRegNode = async (host: string, body: { changes: FimRegChange[]; assignment?: { profileId: number | null; tier: FimRegTier | null } }): Promise<FimRegPreview> =>
  (await api.post(`${R}/nodes/${encodeURIComponent(host)}/preview`, body)).data;
export const measureFimRegNode = async (host: string, entries: (string | Record<string, unknown>)[]): Promise<{ items: FimRegMeasure[] }> =>
  (await api.post(`${R}/nodes/${encodeURIComponent(host)}/measure`, { entries })).data;
export const getFimRegMeasure = async (id: number): Promise<FimRegMeasure> => (await api.get(`${R}/measure/${id}`)).data;
export const compactFimRegNode = async (host: string, note: string): Promise<FimRegPublishResult> =>
  (await api.post(`${R}/nodes/${encodeURIComponent(host)}/compact`, { note })).data;
export const getFimRegHygiene = async (host: string): Promise<{ items: FimRegHygieneFinding[] }> =>
  (await api.get(`${R}/nodes/${encodeURIComponent(host)}/hygiene`)).data;
export const ackFimRegHygiene = async (host: string, body: { itemPath: string; sha256: string; note: string }): Promise<void> => {
  await api.post(`${R}/nodes/${encodeURIComponent(host)}/hygiene/ack`, body);
};

export const getFimRegGroup = async (groupId: string): Promise<FimRegGroupCoverage> => (await api.get(`${R}/groups/${encodeURIComponent(groupId)}`)).data;

/**
 * Publish body: every interactive publish states what the user reviewed (409 when stale):
 * hosts -> `expected` (host -> resolvedHash), group -> `expectedGroupHash` (the group coverage's
 * resolvedHash), profile -> `expectedProfileDigest` (the profile list item's digest).
 */
export type FimRegPublishBody = { note: string; confirm?: boolean } & (
  /** `expected` must hold a NON-EMPTY resolvedHash for EVERY host (422 otherwise). */
  | { hosts: string[]; expected: Record<string, string> }
  | { group: string; expectedGroupHash: string }
);
export interface FimRegPublishResponse { results: FimRegPublishResult[]; published: number; failed: number }

/** Synchronous publish of hosts or a group. */
export const publishFimReg = async (body: FimRegPublishBody): Promise<FimRegPublishResponse> =>
  (await api.post(`${R}/publish`, body)).data;

export type FimRegJobStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled' | 'aborted';
export interface FimRegJob {
  id: number;
  kind: 'publish_profile' | string;
  status: FimRegJobStatus;
  total: number;
  done: number;
  failed: number;
  results: { host: string; status?: string; error: string | null }[];
  error: string | null;
  createdBy: string | null;
  createdAt: number;
  heartbeatAt: number | null;
  finishedAt: number | null;
}
export interface FimRegProfilePublishBody { profile: number; expectedProfileDigest: string; note: string; confirm?: boolean }

/**
 * Profile-wide publish runs as a background job: 202 {job}; poll getFimRegJob until it is
 * done / failed / cancelled. 409: the profile changed since it was reviewed, or a profile publish
 * is already running.
 */
export const startFimRegProfilePublish = async (body: FimRegProfilePublishBody): Promise<{ job: FimRegJob }> =>
  (await api.post(`${R}/publish`, body)).data;
/** Background job progress (Super Admin). */
export const getFimRegJob = async (id: number): Promise<FimRegJob> => (await api.get(`${R}/jobs/${id}`)).data;
/** Cancels a running job (Super Admin); it ends with status 'cancelled'. */
export const cancelFimRegJob = async (id: number): Promise<FimRegJob | { job: FimRegJob } | null> => (await api.post(`${R}/jobs/${id}/cancel`)).data ?? null;

export interface FimRegPolicyProblem { policyId: number; name: string; entries: { index: number; path: string; error: string }[] }
/** Stored policy entries that can no longer be built (republish blocked). Super Admin. */
export const listFimRegPolicyProblems = async (): Promise<{ items: FimRegPolicyProblem[] }> => (await api.get(`${R}/policy-problems`)).data;

export type FimRegChainStatus = 'ok' | 'unverifiable' | 'broken';
export interface FimRegHistoryPage extends FimPage<FimRegHistoryItem> {
  chainOk: boolean;
  chainBrokenAt: number | null;
  /** ok | unverifiable (cannot be checked right now, e.g. key missing) | broken (mismatch). Older servers omit it. */
  chainStatus?: FimRegChainStatus;
  chainReason?: string | null;
  /** The chain is HMAC-keyed (false = plain SHA-256, weaker tamper evidence). */
  chainKeyed?: boolean;
  chainAnchored?: boolean;
  /** Rows written without the key. */
  chainUnkeyedRows?: number;
}
export const listFimRegHistory = async (q: { scopeType: string; scopeValue: string; page?: number }): Promise<FimRegHistoryPage> =>
  (await api.get(`${R}/history`, { params: clean({ scope_type: q.scopeType, scope_value: q.scopeValue, page: q.page }) })).data;
export const rollbackFimReg = async (historyId: number, note: string): Promise<{ status: string; rules: number }> =>
  (await api.post(`${R}/rollback`, { historyId, note })).data;
export const listFimRegNeedsInit = async (): Promise<{ items: FimRegNeedsInit[] }> => (await api.get(`${R}/needs-init`)).data;

export const listFimRegLegacy = async (): Promise<{ items: FimRegLegacyPolicy[] }> => (await api.get(`${R}/migration/legacy`)).data;
export const applyFimRegLegacy = async (policyId: number, note: string): Promise<{ rules: number; skipped: number }> =>
  (await api.post(`${R}/migration/legacy/${policyId}/apply`, { note })).data;
export const removeFimRegLegacyEntries = async (policyId: number, note: string): Promise<{ removed: number; policy: FimPolicy }> =>
  (await api.post(`${R}/migration/legacy/${policyId}/remove-registry`, { note })).data;
/** Template v2 for policies created from 'windows-registry-persistence' (rev bump; Initialize afterwards). */
export const upgradeFimPolicyTemplate = async (policyId: number, note: string): Promise<FimPolicy> =>
  (await api.post(`/fim/policies/${policyId}/upgrade-template`, { note })).data;

/** Initialize only some entries (slots) of a policy, e.g. the new slots after an Apply. `force` is required to
 *  re-initialise a slot that has open critical drift on a managed policy (raises an alert). */
export const initializeFimBaselineEntries = async (id: number, note: string, hosts: string[], entries: number[], force = false): Promise<FimInitResult> =>
  (await api.post(`/fim/policies/${id}/initialize`, { note, hosts, entries, ...(force ? { force: true } : {}) })).data;
