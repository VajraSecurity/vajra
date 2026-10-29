/**
 * Deterministic resolution of a Windows node's registry coverage (docs/FIM_REGISTRY_DESIGN.md
 * §3.3-§3.7). Pure (no DB, no clock: `now` is an input), so the same inputs always give
 * byte-identical output and the unit tests can permute rule order freely.
 *
 *   L0 built-in catalog -> L1 profile -> L2 group -> L3 node
 *
 * Conflict policy: for add / disable / filter / severity the most specific layer wins;
 * exclusions accumulate; PROTECTION BEATS SPECIFICITY: a disable, narrowing filter,
 * intersecting exclusion or severity reduction on a protected entry applies only with an
 * approved, unexpired, two-person waiver for that exact entry, scope and action. Otherwise
 * the rule is reported in `blocked` and never silently applied.
 *
 * Deliberate deviation from §3.4 step 4 (merge of identical patterns): deny-lists and key
 * exclusions are INTERSECTED (the design says united). Uniting them would let a non-protected
 * duplicate entry silently narrow a protected one; intersecting only ever widens coverage.
 */
import { createHash } from 'crypto';
import { catalogVisibleByDesign,
  REG_CATALOG, REG_TIER_RANK, anchorBytes, type RegCatalogEntry, type RegTier,
} from './fimRegistryCatalog';
import {
  normalizeRegistryEntryV2, entryFingerprint, keysIntersect, patternMatchesKey, isWild, asciiLower,
  validateValueName, validateRegistryKeyV2, exclusionInside, canonicalRegistryKey, likeMatch, REG_LIMITS, type RegistryEntryV2,
} from './fimRegistrySql';

export { likeMatch };
import type { FimSeverity } from './fimLogic';

export const FIM_REG_CAPS = {
  entryBytesBlock: 768 * 1024,
  entryBytesWarn: 384 * 1024,
  entryRowsBlock: 4000,
  entryRowsWarn: 2000,
  // The design says 120, but its own Comprehensive tier is 136 entries (exact-key expansions);
  // 150 keeps every catalog tier selectable. Registry queries are cheap and osquery splays them.
  entriesPerNode: 150,
  totalRowsPerNode: 25000,
  pathsMax: 250,
  compactRetiredAbove: 64,
  compactPathsAbove: 200,
  rulesPerScope: 300,
  waiverMaxDays: 30,
  softRetireDays: 7,
  measurePerHostPer10Min: 5,
  publishBatchMax: 500,
  publishConfirmAbove: 200,
} as const;

export type RegLayer = 'profile' | 'group' | 'node';
export type RegOp = 'add' | 'disable' | 'exclude' | 'filter' | 'severity';
export type RegWaiverAction = 'disable' | 'narrow' | 'lower_severity' | 'opt_out';
export const REG_OPS: RegOp[] = ['add', 'disable', 'exclude', 'filter', 'severity'];
const OP_ORDER: Record<RegOp, number> = { add: 0, filter: 1, exclude: 2, severity: 3, disable: 4 };
const SEV_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export interface RegRule {
  id: number;
  layer: RegLayer;
  scopeValue: string;
  op: RegOp;
  target: string;
  spec: Record<string, any>;
  waiverId: number | null;
}

export interface RegWaiver {
  id: number;
  entryKey: string;
  scopeType: RegLayer;
  scopeValue: string;
  action: RegWaiverAction;
  requestedBy: string;
  approvedBy: string | null;
  status: string;
  expiresAt: number;
  /** Hash of the ONE rule this waiver was approved for (regRuleHash); null = legacy, never valid. */
  ruleHash: string | null;
}

/** Canonical hash of a rule's effect: a waiver is bound to exactly this (layer, scope, op, target, spec). */
export function regRuleHash(r: { layer: string; scopeValue: string; op: string; target: string; spec: Record<string, unknown> }): string {
  // The whole spec, measureOverride included: an approved change that skipped measurement is a
  // different change from one that did not.
  const spec = { ...(r.spec ?? {}) };
  return createHash('sha256').update(canonicalJson({ layer: r.layer, scopeValue: r.scopeValue, op: r.op, target: r.target, spec }), 'utf8').digest('hex');
}

export interface RegProfile {
  id: number;
  name: string;
  tier: RegTier;
  isDefault: boolean;
  scanIntervalSecs: number;
  mode: 'learn' | 'enforce';
}

export interface RegAssignment {
  scopeType: 'group' | 'node';
  scopeValue: string;
  profileId: number | null;
  tier: RegTier | null;
}

export interface ResolveInput {
  host: string;
  ownerGroupId: string | null;
  catalog?: readonly RegCatalogEntry[];
  profiles: RegProfile[];
  nodeAssignment?: RegAssignment | null;
  groupAssignment?: RegAssignment | null;
  /** Active rules (any scope; only those of this node's profile/group/host are applied). */
  rules: RegRule[];
  waivers: RegWaiver[];
  /** Measurements of custom entries by fingerprint. */
  measured?: Map<string, { rows: number; bytes: number }>;
  /** Force a tier (tier picker previews). */
  tierOverride?: RegTier;
  /** Leave out the node layer (group views). */
  skipNodeLayer?: boolean;
  now: number;
}

export type SourceBadge =
  | { layer: 'builtin'; tier: RegTier }
  | { layer: RegLayer; ruleId: number; op: RegOp; scopeValue: string }
  | { layer: 'merge'; from: string[] }
  | { layer: 'carve'; from: string };

export interface RegEstimate { rows: number; bytes: number; basis: 'measured' | 'estimated' | 'unknown' }

export interface EffectiveEntry extends RegistryEntryV2 {
  severity: FimSeverity;
  category: string;
  label: string;
  attack: string[];
  protected: boolean;
  verified: boolean;
  tier: RegTier | null;
  sources: SourceBadge[];
  estimate: RegEstimate;
  fingerprint: string;
}

export interface BlockedRule { ruleId: number; layer: RegLayer; op: RegOp; target: string; entryKey: string; reason: string }

export interface ResolveResult {
  ok: boolean;
  profile: { id: number; name: string; source: 'node' | 'group' | 'default' };
  tier: { value: RegTier; source: 'node' | 'group' | 'profile' };
  scanIntervalSecs: number;
  mode: 'learn' | 'enforce';
  entries: EffectiveEntry[];
  blocked: BlockedRule[];
  warnings: string[];
  errors: string[];
  hash: string;
  totals: { entries: number; rows: number; bytes: number };
  usedWaivers: number[];
}

type W = Omit<EffectiveEntry, 'fingerprint'> & { waivered?: boolean };

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const lowerSet = (l: string[]): Set<string> => new Set(l.map(asciiLower));
function unionNames(a: string[], b: string[]): string[] {
  const seen = lowerSet(a);
  const out = [...a];
  for (const n of b) if (!seen.has(asciiLower(n))) { seen.add(asciiLower(n)); out.push(n); }
  return out.sort((x, y) => cmp(asciiLower(x), asciiLower(y)));
}
function intersectNames(a: string[], b: string[]): string[] {
  const s = lowerSet(b);
  return a.filter((n) => s.has(asciiLower(n))).sort((x, y) => cmp(asciiLower(x), asciiLower(y)));
}
const sortedNames = (l: string[]): string[] => [...l].sort((x, y) => cmp(asciiLower(x), asciiLower(y)));
const sortedKeys = (l: string[]): string[] => [...new Map(l.map((k) => [k.toLowerCase(), k])).values()].sort((x, y) => cmp(x.toLowerCase(), y.toLowerCase()));
const maxSev = (a: FimSeverity, b: FimSeverity): FimSeverity => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

/** Canonical JSON (sorted keys) for hashing. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
}
export const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

export function fromCatalog(c: RegCatalogEntry): W {
  return {
    path: c.path, values: sortedNames(c.values), ignoreValues: sortedNames(c.ignoreValues), excludeKeys: [], includeSubkeys: c.values.length === 0,
    anchor: true, hiveScoped: c.path.toUpperCase().startsWith('HKEY_USERS\\%\\'), redactValues: sortedNames(c.redactValues), entryKey: c.id,
    realtimeRequired: c.realtimeRequired, severity: c.severity, category: c.category, label: c.label, attack: [...c.attack],
    protected: c.protected, verified: c.verified, tier: c.tier, sources: [{ layer: 'builtin', tier: c.tier }],
    visibleByDesign: catalogVisibleByDesign(c),
    estimate: { rows: c.est.rows + c.anchorRows, bytes: c.est.bytes + anchorBytes(c), basis: c.verified ? 'measured' : 'estimated' },
  };
}

/** Builds a custom entry from an `add custom:<hex16>` rule spec. Throws FimValidationError. */
export function customEntry(target: string, spec: Record<string, any>, measured?: Map<string, { rows: number; bytes: number }>): W {
  if (!/^custom:[0-9a-f]{16}$/.test(target)) throw new Error('custom entry ids are custom:<16 hex>');
  const v2 = normalizeRegistryEntryV2({ ...spec, entryKey: target }, { allowRecursive: true });
  const severity = typeof spec.severity === 'string' && SEVERITIES.includes(spec.severity) ? spec.severity as FimSeverity : 'high';
  const text = (x: unknown, dflt: string, max: number) =>
    // eslint-disable-next-line no-control-regex
    (typeof x === 'string' && x.trim() && x.length <= max && !/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(x) ? x.trim() : dflt);
  const fp = entryFingerprint(v2);
  const m = measured?.get(fp);
  return {
    ...v2, values: sortedNames(v2.values), ignoreValues: sortedNames(v2.ignoreValues), redactValues: sortedNames(v2.redactValues),
    severity, category: text(spec.category, 'custom', 64), label: text(spec.label, 'Custom registry key', 120), attack: [],
    protected: false, verified: false, tier: null, sources: [], visibleByDesign: false,
    estimate: m ? { rows: m.rows, bytes: m.bytes, basis: 'measured' } : { rows: 0, bytes: 0, basis: 'unknown' },
  };
}

/**
 * A waiver applies only when it is APPROVED (pending never counts), unexpired, approved by a
 * different person, for this entry, scope and action, AND bound to exactly this rule (spec hash).
 */
function waiverValid(w: RegWaiver | undefined, rule: RegRule, entryKey: string, actions: RegWaiverAction[], now: number): boolean {
  return !!w && w.status === 'approved' && w.expiresAt > now && !!w.approvedBy && w.approvedBy.toLowerCase() !== w.requestedBy.toLowerCase()
    && w.entryKey === entryKey && w.scopeType === rule.layer && w.scopeValue === rule.scopeValue && actions.includes(w.action)
    && !!w.ruleHash && w.ruleHash === regRuleHash(rule);
}

/** Can two entries (on intersecting keys) return a row with the same name? */
export function namesIntersect(a: Pick<W, 'values' | 'includeSubkeys' | 'ignoreValues'>, b: Pick<W, 'values' | 'includeSubkeys' | 'ignoreValues'>): boolean {
  const anyA = a.values.length === 0 || a.includeSubkeys, anyB = b.values.length === 0 || b.includeSubkeys;
  if (anyA && anyB) return true;
  if (anyA) { const d = lowerSet(a.ignoreValues); return b.values.some((n) => !d.has(asciiLower(n))); }
  if (anyB) { const d = lowerSet(b.ignoreValues); return a.values.some((n) => !d.has(asciiLower(n))); }
  const s = lowerSet(b.values);
  return a.values.some((n) => s.has(asciiLower(n)));
}

export const isExact = (p: string): boolean => !p.split('\\').some(isWild);
const excludes = (a: W, key: string): boolean => a.excludeKeys.some((x) => likeMatch(x, key));

export function resolveRegistry(input: ResolveInput): ResolveResult {
  const catalog = input.catalog ?? REG_CATALOG;
  const byId = new Map(catalog.map((c) => [c.id, c]));
  const warnings: string[] = [];
  const errors: string[] = [];
  const blocked: BlockedRule[] = [];
  const used = new Set<number>();
  const waivers = new Map(input.waivers.map((w) => [w.id, w]));
  // Single use: a waiver can back at most one rule (the lowest rule id that references it).
  const waiverOwner = new Map<number, number>();
  for (const r of [...input.rules].sort((a, b) => a.id - b.id)) if (r.waiverId != null && !waiverOwner.has(r.waiverId)) waiverOwner.set(r.waiverId, r.id);

  // 1. profile and tier
  const dflt = input.profiles.find((p) => p.isDefault) ?? null;
  const byPid = new Map(input.profiles.map((p) => [p.id, p]));
  let profile: RegProfile | null;
  let profileSource: 'node' | 'group' | 'default' = 'default';
  if (!input.skipNodeLayer && input.nodeAssignment?.profileId != null && byPid.has(input.nodeAssignment.profileId)) { profile = byPid.get(input.nodeAssignment.profileId)!; profileSource = 'node'; }
  else if (input.groupAssignment?.profileId != null && byPid.has(input.groupAssignment.profileId)) { profile = byPid.get(input.groupAssignment.profileId)!; profileSource = 'group'; }
  else profile = dflt;
  if (!profile) {
    // Fail closed: never resolve to "nothing"; the caller keeps the last published config.
    return {
      ok: false, profile: { id: 0, name: '', source: 'default' }, tier: { value: 'essential', source: 'profile' }, scanIntervalSecs: 3600, mode: 'enforce',
      entries: [], blocked: [], warnings: [], errors: ['no default registry profile exists'], hash: '', totals: { entries: 0, rows: 0, bytes: 0 }, usedWaivers: [],
    };
  }
  let tier: RegTier = profile.tier;
  let tierSource: 'node' | 'group' | 'profile' = 'profile';
  if (input.tierOverride) { tier = input.tierOverride; tierSource = input.skipNodeLayer ? 'group' : 'node'; }
  else if (!input.skipNodeLayer && input.nodeAssignment?.tier) { tier = input.nodeAssignment.tier; tierSource = 'node'; }
  else if (input.groupAssignment?.tier) { tier = input.groupAssignment.tier; tierSource = 'group'; }

  // 2. catalog entries of the tier
  const E = new Map<string, W>();
  for (const c of catalog) if (!c.optInOnly && REG_TIER_RANK[c.tier] <= REG_TIER_RANK[tier]) E.set(c.id, fromCatalog(c));

  // 3. layers, general -> specific
  const layers: { layer: RegLayer; scope: string | null }[] = [
    { layer: 'profile', scope: String(profile.id) },
    { layer: 'group', scope: input.ownerGroupId },
    { layer: 'node', scope: input.skipNodeLayer ? null : input.host },
  ];
  for (const { layer, scope } of layers) {
    if (scope === null || scope === '') continue;
    const R = input.rules.filter((r) => r.layer === layer && r.scopeValue === scope)
      .sort((a, b) => OP_ORDER[a.op] - OP_ORDER[b.op] || cmp(a.target, b.target) || a.id - b.id);
    for (const r of R) {
      const block = (entryKey: string, reason: string) => blocked.push({ ruleId: r.id, layer, op: r.op, target: r.target, entryKey, reason });
      const src: SourceBadge = { layer, ruleId: r.id, op: r.op, scopeValue: scope };
      const needWaiver = (entryKey: string, actions: RegWaiverAction[]): boolean => {
        const w = r.waiverId != null && waiverOwner.get(r.waiverId) === r.id ? waivers.get(r.waiverId) : undefined;
        if (waiverValid(w, r, entryKey, actions, input.now)) { used.add(w!.id); return true; }
        block(entryKey, w ? `protected coverage: ${entryKey} waiver #${w.id} is not an approved, unexpired, unused two-person waiver for exactly this change`
          : `protected coverage: ${entryKey} requires an approved waiver for exactly this change`);
        return false;
      };
      try {
        switch (r.op) {
          case 'add': {
            if (r.target.startsWith('custom:')) {
              const c = customEntry(r.target, r.spec ?? {}, input.measured);
              c.sources = [src];
              // A custom EXACT key inside a protected wildcard entry would carve that key out of the
              // protected coverage (see 5a): only with a waiver bound to this exact add.
              const prot = [...E.values()].filter((p) => p.protected && isExact(c.path) && !isExact(p.path) && patternMatchesKey(p.path, c.path) && namesIntersect(p, c));
              if (prot.length) {
                if (prot.length > 1 || !needWaiver(prot[0].entryKey, ['narrow'])) { if (prot.length > 1) block(prot[0].entryKey, 'protected coverage: overlaps several protected entries'); break; }
                c.waivered = true;
              }
              if (c.estimate.basis === 'unknown') warnings.push(`${r.target}: custom entry has not been measured; its size is unknown`);
              E.set(r.target, c);
            } else {
              const c = byId.get(r.target);
              if (!c) { block(r.target, 'unknown catalog id'); break; }
              const cur = E.get(r.target);
              if (cur) cur.sources.push(src);
              else { const w = fromCatalog(c); w.sources.push(src); E.set(r.target, w); }
            }
            break;
          }
          case 'filter': {
            const cur = E.get(r.target);
            if (!cur) { warnings.push(`rule #${r.id}: filter target ${r.target} is not effective here`); break; }
            const raw = Array.isArray(r.spec?.values) ? r.spec.values : null;
            if (!raw || raw.length > REG_LIMITS.valuesMax || raw.some((n: unknown) => validateValueName(n) !== null)) { block(r.target, 'invalid value list'); break; }
            const next = sortedNames([...new Map((raw as string[]).map((n) => [asciiLower(n), n])).values()]);
            const curL = lowerSet(cur.values), nextL = lowerSet(next);
            const narrowing = next.length > 0 && (cur.values.length === 0 || [...curL].some((n) => !nextL.has(n)));
            if (cur.protected && narrowing && !needWaiver(r.target, ['narrow'])) break;
            cur.values = next;
            cur.includeSubkeys = next.length === 0;
            cur.sources.push(src);
            break;
          }
          case 'exclude': {
            const targets = r.target === '*' ? [...E.keys()].sort() : [r.target];
            const ign: string[] = Array.isArray(r.spec?.ignoreValues) && r.target !== '*' ? r.spec.ignoreValues : [];
            const exkRaw: unknown[] = Array.isArray(r.spec?.excludeKeys) ? r.spec.excludeKeys : [];
            if (ign.some((n) => validateValueName(n) !== null) || exkRaw.some((x) => validateRegistryKeyV2(x, { exclusion: true }) !== null)) { block(r.target, 'invalid exclusion'); break; }
            const exk = (exkRaw as string[]).map(canonicalRegistryKey);
            for (const t of targets) {
              const cur = E.get(t);
              if (!cur) { if (r.target !== '*') warnings.push(`rule #${r.id}: exclude target ${t} is not effective here`); continue; }
              const keys = exk.filter((x) => exclusionInside(cur.path, x) && !likeMatch(x, cur.path));
              if (exk.some((x) => likeMatch(x, cur.path))) block(t, 'an exclusion may not exclude the entry\'s own key');
              const vals = lowerSet(cur.values);
              const hitsValues = ign.some((n) => cur.values.length === 0 || cur.includeSubkeys || vals.has(asciiLower(n)));
              if (keys.length === 0 && !hitsValues) continue;
              if (cur.protected && !needWaiver(t, ['narrow'])) continue;
              cur.ignoreValues = unionNames(cur.ignoreValues, ign);
              cur.excludeKeys = sortedKeys([...cur.excludeKeys, ...keys]);
              cur.sources.push(src);
            }
            break;
          }
          case 'severity': {
            const cur = E.get(r.target);
            if (!cur) { warnings.push(`rule #${r.id}: severity target ${r.target} is not effective here`); break; }
            const s = r.spec?.severity;
            if (typeof s !== 'string' || !SEVERITIES.includes(s)) { block(r.target, 'invalid severity'); break; }
            if (cur.protected && SEV_RANK[s] < SEV_RANK[cur.severity] && !needWaiver(r.target, ['lower_severity'])) break;
            cur.severity = s as FimSeverity;
            cur.sources.push(src);
            break;
          }
          case 'disable': {
            const cur = E.get(r.target);
            if (!cur) break;
            if (cur.protected && !needWaiver(r.target, ['disable', 'opt_out'])) break;
            E.delete(r.target);
            break;
          }
          default:
            block(r.target, 'unknown operation');
        }
      } catch (err) {
        block(r.target, (err as Error).message);
      }
    }
  }

  // 4. merge identical patterns (fim_baseline is unique per policy/host/path)
  const groups = new Map<string, W[]>();
  for (const w of E.values()) {
    const k = asciiLower(w.path);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(w);
  }
  const list: W[] = [];
  for (const members of groups.values()) {
    if (members.length === 1) { list.push(members[0]); continue; }
    members.sort((a, b) => Number(b.protected) - Number(a.protected)
      || (a.tier === null ? 9 : REG_TIER_RANK[a.tier]) - (b.tier === null ? 9 : REG_TIER_RANK[b.tier]) || cmp(a.entryKey, b.entryKey));
    const m: W = { ...members[0], sources: [...members[0].sources], attack: [...members[0].attack] };
    // With a protected member the merged definition (filters, flags, redaction) comes ONLY from
    // protected / catalog members: a custom duplicate can never change what is collected for a
    // protected entry (it would change the fingerprint, re-slot it, or switch off detections).
    const anyProtMember = members.some((x) => x.protected);
    for (const o of members.slice(1)) {
      if (anyProtMember && !o.protected && o.tier === null) {
        m.severity = maxSev(m.severity, o.severity);
        m.sources.push(...o.sources);
        warnings.push(`${o.entryKey} duplicates protected entry ${m.entryKey}; only its severity is used`);
        continue;
      }
      m.values = m.values.length === 0 || o.values.length === 0 ? [] : unionNames(m.values, o.values);
      m.ignoreValues = intersectNames(m.ignoreValues, o.ignoreValues);
      m.excludeKeys = sortedKeys(m.excludeKeys.filter((x) => o.excludeKeys.some((y) => y.toLowerCase() === x.toLowerCase())));
      m.includeSubkeys = m.includeSubkeys || o.includeSubkeys;
      m.anchor = m.anchor || o.anchor;
      m.hiveScoped = m.hiveScoped || o.hiveScoped;
      // Redaction of a protected entry is fixed: only protected / catalog members may add to it.
      const anyProt = members.some((x) => x.protected);
      if (!anyProt || o.protected || o.tier !== null) m.redactValues = unionNames(m.redactValues, o.redactValues);
      m.realtimeRequired = m.realtimeRequired || o.realtimeRequired;
      // Never fewer redactions than any member: a configuration-like member makes the merge redact names.
      m.visibleByDesign = m.visibleByDesign === true && o.visibleByDesign === true;
      m.severity = maxSev(m.severity, o.severity);
      m.protected = m.protected || o.protected;
      m.verified = m.verified && o.verified;
      m.attack = [...new Set([...m.attack, ...o.attack])];
      m.estimate = {
        rows: m.estimate.rows + o.estimate.rows, bytes: m.estimate.bytes + o.estimate.bytes,
        basis: m.estimate.basis === 'unknown' || o.estimate.basis === 'unknown' ? 'unknown' : m.estimate.basis === 'measured' && o.estimate.basis === 'measured' ? 'measured' : 'estimated',
      };
      m.sources.push(...o.sources);
    }
    if (m.values.length === 0) m.includeSubkeys = true;
    m.sources.push({ layer: 'merge', from: members.map((x) => x.entryKey).sort() });
    m.label = `${m.label} (+${members.length - 1} merged)`;
    list.push(m);
  }
  list.sort((a, b) => cmp(a.entryKey, b.entryKey));

  // 5a. carve-out: an exact key inside a wildcard entry with overlapping names is excluded from
  //     the wildcard entry and the exact-key entry absorbs its filter for that key (no coverage loss).
  //     Over a PROTECTED wildcard entry this is only allowed when the exact entry is itself catalog /
  //     protected or backed by a waiver for that add; otherwise the exact entry is blocked.
  const dropped = new Set<W>();
  for (const a of list) {
    if (isExact(a.path) || dropped.has(a)) continue;
    for (const b of list) {
      if (a === b || dropped.has(b) || !isExact(b.path) || !patternMatchesKey(a.path, b.path) || excludes(a, b.path) || !namesIntersect(a, b)) continue;
      const trusted = b.protected || b.tier !== null;
      if (a.protected && !trusted && !b.waivered) {
        dropped.add(b);
        blocked.push({ ruleId: 0, layer: 'node', op: 'add', target: b.entryKey, entryKey: a.entryKey, reason: `protected coverage: ${b.entryKey} would narrow ${a.entryKey}; a waiver for this add is required` });
        continue;
      }
      const aTrusted = a.protected || a.tier !== null;
      if (!aTrusted && trusted) {
        // An untrusted (custom) wildcard over a catalog/protected exact entry: the exact entry keeps
        // its catalog definition EXACTLY (values, filters, redaction, anchor, flags); the custom
        // wildcard only stops covering that key. A custom rule, exact or wildcard, can therefore
        // never redact, narrow or re-slot protected coverage without a waiver.
        a.excludeKeys = sortedKeys([...a.excludeKeys, b.path]);
        warnings.push(`${a.entryKey} no longer covers ${b.path}: that key is monitored by ${b.entryKey} with its own (catalog) definition`);
        continue;
      }
      a.excludeKeys = sortedKeys([...a.excludeKeys, b.path]);
      b.values = a.values.length === 0 || b.values.length === 0 ? [] : unionNames(b.values, a.values);
      b.ignoreValues = intersectNames(b.ignoreValues, a.ignoreValues);
      b.includeSubkeys = b.values.length === 0 || b.includeSubkeys || a.includeSubkeys;
      // The absorbing entry keeps the wildcard's coverage exactly: its redaction is the wildcard's
      // (plus catalog-defined redaction), it keeps an anchor and may not exclude its own key.
      b.redactValues = trusted ? unionNames(b.redactValues, a.redactValues) : [...a.redactValues];
      b.anchor = true;
      b.excludeKeys = b.excludeKeys.filter((x) => !likeMatch(x, b.path));
      b.severity = maxSev(b.severity, a.severity);
      b.protected = b.protected || a.protected;
      b.attack = [...new Set([...b.attack, ...a.attack])];
      b.sources.push({ layer: 'carve', from: a.entryKey });
    }
  }

  if (dropped.size) for (let i = list.length - 1; i >= 0; i--) if (dropped.has(list[i])) list.splice(i, 1);

  // 5b. overlap check: anything else that can return the same item is an error - except between
  //     two CUSTOM entries from different layers: the more specific layer wins (node > group >
  //     profile) and the other entry is dropped (blocked + warning), so a broader-scope rule can
  //     never make a node's own coverage unresolvable (and so trigger the fail-safe).
  const LAYER_RANK: Record<string, number> = { profile: 1, group: 2, node: 3 };
  const customRank = (w: W): number => (w.protected || w.tier !== null) ? 0
    : Math.max(0, ...w.sources.map((x: any) => LAYER_RANK[x?.layer] ?? 0));
  const overlapDropped = new Set<W>();
  const overlaps = (a: W, b: W): boolean => keysIntersect(a.path, b.path)
    && !((isExact(b.path) && excludes(a, b.path)) || (isExact(a.path) && excludes(b, a.path))) && namesIntersect(a, b);
  // Non-transitive: custom entries are visited from the most specific layer down; an entry is
  // dropped only if it overlaps an entry that is KEPT (a dropped entry never causes further drops).
  const customs = list.filter((w) => customRank(w) > 0).sort((a, b) => customRank(b) - customRank(a) || cmp(a.entryKey, b.entryKey));
  const kept: W[] = [];
  for (const e of customs) {
    const winner = kept.find((k) => customRank(k) > customRank(e) && overlaps(k, e));
    if (winner) {
      overlapDropped.add(e);
      blocked.push({ ruleId: 0, layer: 'node', op: 'add', target: e.entryKey, entryKey: winner.entryKey,
        reason: `overlap: ${e.entryKey} (${e.path}) overlaps ${winner.entryKey} (${winner.path}) from a more specific layer; the broader rule is not applied here` });
      warnings.push(`${e.entryKey} dropped on this node: overlaps ${winner.entryKey} from a more specific layer`);
    } else kept.push(e);
  }
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const a = list[i], b = list[j];
      if (overlapDropped.has(a) || overlapDropped.has(b)) continue;
      if (!overlaps(a, b)) continue;
      errors.push(`overlap: ${a.entryKey} (${a.path}) and ${b.entryKey} (${b.path}) can return the same values; narrow one of them or exclude the key`);
    }
  }
  if (overlapDropped.size) for (let i = list.length - 1; i >= 0; i--) if (overlapDropped.has(list[i])) list.splice(i, 1);

  // 6. caps
  let rows = 0, bytes = 0;
  for (const w of list) {
    if (w.values.length > REG_LIMITS.valuesMax) errors.push(`${w.entryKey}: more than ${REG_LIMITS.valuesMax} values after merging`);
    if (w.ignoreValues.length > REG_LIMITS.ignoreValuesMax) errors.push(`${w.entryKey}: more than ${REG_LIMITS.ignoreValuesMax} ignored values`);
    if (w.excludeKeys.length > REG_LIMITS.excludeKeysMax) errors.push(`${w.entryKey}: more than ${REG_LIMITS.excludeKeysMax} excluded keys`);
    if (w.estimate.bytes > FIM_REG_CAPS.entryBytesBlock) errors.push(`${w.entryKey}: estimated ${Math.round(w.estimate.bytes / 1024)} KiB per scan exceeds the ${FIM_REG_CAPS.entryBytesBlock / 1024} KiB limit (osquery drops result lines over ~1 MiB)`);
    else if (w.estimate.bytes > FIM_REG_CAPS.entryBytesWarn) warnings.push(`${w.entryKey}: estimated ${Math.round(w.estimate.bytes / 1024)} KiB per scan (warning above ${FIM_REG_CAPS.entryBytesWarn / 1024} KiB)`);
    if (w.estimate.rows > FIM_REG_CAPS.entryRowsBlock) errors.push(`${w.entryKey}: estimated ${w.estimate.rows} rows exceeds the ${FIM_REG_CAPS.entryRowsBlock} row limit`);
    else if (w.estimate.rows > FIM_REG_CAPS.entryRowsWarn) warnings.push(`${w.entryKey}: estimated ${w.estimate.rows} rows (warning above ${FIM_REG_CAPS.entryRowsWarn})`);
    if (w.realtimeRequired) warnings.push(`${w.entryKey}: needs real-time registry events (plgx agent) to catch create-then-delete within a scan interval`);
    rows += w.estimate.rows;
    bytes += w.estimate.bytes;
  }
  if (list.length > FIM_REG_CAPS.entriesPerNode) errors.push(`${list.length} entries exceed the ${FIM_REG_CAPS.entriesPerNode} entries per node limit`);
  if (rows > FIM_REG_CAPS.totalRowsPerNode) errors.push(`estimated ${rows} rows per node exceed the ${FIM_REG_CAPS.totalRowsPerNode} row limit`);
  if (list.length === 0) errors.push('the resolved coverage is empty; an empty registry policy is never published');

  // 7. fingerprints, hash
  const entries: EffectiveEntry[] = list.map((w) => ({ ...w, fingerprint: entryFingerprint(w) }));
  const hash = sha256Hex(canonicalJson({
    mode: profile.mode, scanIntervalSecs: profile.scanIntervalSecs,
    entries: entries.map((x) => ({ entryKey: x.entryKey, fingerprint: x.fingerprint, path: x.path, severity: x.severity, category: x.category, label: x.label })),
  }));
  return {
    ok: errors.length === 0,
    profile: { id: profile.id, name: profile.name, source: profileSource },
    tier: { value: tier, source: tierSource },
    scanIntervalSecs: profile.scanIntervalSecs,
    mode: profile.mode,
    entries, blocked, warnings: [...new Set(warnings)], errors, hash,
    totals: { entries: entries.length, rows, bytes },
    usedWaivers: [...used].sort((a, b) => a - b),
  };
}

// ---------------------------------------------------------------------------------------------
// Slots (§3.5): indices are allocated monotonically per host and never reused
// ---------------------------------------------------------------------------------------------

export interface SlotRow {
  slotIdx: number;
  entryKey: string;
  fingerprint: string;
  createdAt: number;
  retiredAt: number | null;
  purgeAfter: number | null;
  purgedAt: number | null;
}

export interface SlotPlan {
  slots: SlotRow[];
  changed: SlotRow[];
  paths: Record<string, unknown>[];
  needsInit: number[];
  retired: number[];
  revived: number[];
  kept: number[];
  entrySlot: Map<string, number>;
}

export const TOMBSTONE = Object.freeze({
  kind: 'registry', path: '', retired: true, prefix: 'registry', keyColumns: ['path'], valueColumns: ['type', 'data'],
  severity: 'low', category: 'retired', ignore: [], hash: false,
});

/** The JSON stored in fim_policies.paths[slot] for an effective entry (worker contract §3.12). */
export function policyEntryJson(e: EffectiveEntry): Record<string, unknown> {
  return {
    kind: 'registry', path: e.path, severity: e.severity, category: e.category, label: e.label,
    prefix: 'registry', keyColumns: ['path'], valueColumns: ['type', 'data'], ignore: [], hash: false,
    entryKey: e.entryKey, fingerprint: e.fingerprint, values: e.values, ignoreValues: e.ignoreValues, excludeKeys: e.excludeKeys,
    includeSubkeys: e.includeSubkeys, anchor: e.anchor, hiveScoped: e.hiveScoped, redactValues: e.redactValues,
    realtimeRequired: e.realtimeRequired, retired: false,
    // The worker applies the secret-like heuristic (digest marker) only where the scan SQL does.
    ...(e.entryKey.startsWith('custom:') ? { redactHeuristic: true } : {}),
    ...(e.visibleByDesign === true ? { visibleByDesign: true } : {}),
  };
}

export function allocateSlots(existing: SlotRow[], entries: EffectiveEntry[], now: number): SlotPlan {
  const slots = existing.map((s) => ({ ...s }));
  const changed = new Map<number, SlotRow>();
  const touch = (s: SlotRow) => changed.set(s.slotIdx, s);
  const live = new Map(slots.filter((s) => s.retiredAt === null).map((s) => [s.entryKey, s]));
  let next = slots.reduce((m, s) => Math.max(m, s.slotIdx + 1), 0);
  const needsInit: number[] = [], retired: number[] = [], revived: number[] = [], kept: number[] = [];
  const entrySlot = new Map<string, number>();
  const retire = (s: SlotRow) => { s.retiredAt = now; s.purgeAfter = now + FIM_REG_CAPS.softRetireDays * 86400; touch(s); retired.push(s.slotIdx); };
  const wanted = new Set(entries.map((e) => e.entryKey));
  for (const s of [...live.values()].sort((a, b) => a.slotIdx - b.slotIdx)) {
    if (!wanted.has(s.entryKey)) { retire(s); live.delete(s.entryKey); }
  }
  for (const e of [...entries].sort((a, b) => cmp(a.entryKey, b.entryKey))) {
    const l = live.get(e.entryKey);
    if (l && l.fingerprint === e.fingerprint) { kept.push(l.slotIdx); entrySlot.set(e.entryKey, l.slotIdx); continue; }
    if (l) { retire(l); live.delete(e.entryKey); }
    // Revive the most recently retired identical slot inside the soft-retire window: its
    // baseline rows are still there (any change in between shows as drift: the safe direction).
    const r = slots.filter((s) => s.entryKey === e.entryKey && s.fingerprint === e.fingerprint && s.retiredAt !== null
      && s.purgedAt === null && (s.purgeAfter ?? 0) > now && !retired.includes(s.slotIdx))
      .sort((a, b) => (b.retiredAt ?? 0) - (a.retiredAt ?? 0) || b.slotIdx - a.slotIdx)[0];
    if (r) {
      r.retiredAt = null; r.purgeAfter = null; touch(r); revived.push(r.slotIdx); entrySlot.set(e.entryKey, r.slotIdx);
      continue;
    }
    // Reuse a PURGED tombstone (its baseline rows are gone and its soft-retire window is over) before
    // growing the list: repeated rule flips can then never push a node to the slot cap.
    const reuse = slots.filter((x) => x.retiredAt !== null && x.purgedAt !== null && !retired.includes(x.slotIdx) && !changed.has(x.slotIdx))
      .sort((a, b) => a.slotIdx - b.slotIdx)[0];
    if (reuse) {
      Object.assign(reuse, { entryKey: e.entryKey, fingerprint: e.fingerprint, createdAt: now, retiredAt: null, purgeAfter: null, purgedAt: null });
      touch(reuse); needsInit.push(reuse.slotIdx); entrySlot.set(e.entryKey, reuse.slotIdx);
      continue;
    }
    const s: SlotRow = { slotIdx: next++, entryKey: e.entryKey, fingerprint: e.fingerprint, createdAt: now, retiredAt: null, purgeAfter: null, purgedAt: null };
    slots.push(s); touch(s); needsInit.push(s.slotIdx); entrySlot.set(e.entryKey, s.slotIdx);
  }
  const byKey = new Map(entries.map((e) => [e.entryKey, e]));
  const len = slots.reduce((m, s) => Math.max(m, s.slotIdx + 1), 0);
  const paths: Record<string, unknown>[] = [];
  const bySlot = new Map(slots.map((s) => [s.slotIdx, s]));
  for (let i = 0; i < len; i++) {
    const s = bySlot.get(i);
    const e = s && s.retiredAt === null ? byKey.get(s.entryKey) : undefined;
    paths.push(e ? policyEntryJson(e) : { ...TOMBSTONE });
  }
  return {
    slots: slots.sort((a, b) => a.slotIdx - b.slotIdx), changed: [...changed.values()].sort((a, b) => a.slotIdx - b.slotIdx),
    paths, needsInit, retired: retired.sort((a, b) => a - b), revived: revived.sort((a, b) => a - b), kept: kept.sort((a, b) => a - b), entrySlot,
  };
}

/** Compaction (§3.5): renumber live entries 0..n-1 in entryKey order (needs a full re-init). */
export function compactSlots(entries: EffectiveEntry[], now: number): SlotPlan {
  return allocateSlots([], entries, now);
}

// ---------------------------------------------------------------------------------------------
// Preview diff (published state vs a new resolution)
// ---------------------------------------------------------------------------------------------

export interface PublishedEntry { entryKey: string; fingerprint: string; path: string; severity: string; category: string; label: string; slot: number | null }

export function diffCoverage(published: PublishedEntry[], next: EffectiveEntry[]) {
  const pub = new Map(published.map((p) => [p.entryKey, p]));
  const nx = new Map(next.map((n) => [n.entryKey, n]));
  const added = next.filter((n) => !pub.has(n.entryKey));
  const changed = next.filter((n) => pub.has(n.entryKey) && pub.get(n.entryKey)!.fingerprint !== n.fingerprint);
  const severityOnly = next.filter((n) => {
    const p = pub.get(n.entryKey);
    return p && p.fingerprint === n.fingerprint && (p.severity !== n.severity || p.category !== n.category || p.label !== n.label);
  });
  const removed = published.filter((p) => !nx.has(p.entryKey)).map((p) => ({ slot: p.slot, entryKey: p.entryKey, path: p.path }));
  return { added, changed, severityOnly, removed };
}

export function sumEstimates(entries: { estimate: RegEstimate }[]): { entries: number; rows: number; bytes: number } {
  return entries.reduce((t, e) => ({ entries: t.entries + 1, rows: t.rows + e.estimate.rows, bytes: t.bytes + e.estimate.bytes }), { entries: 0, rows: 0, bytes: 0 });
}
