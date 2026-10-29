/**
 * Pure (DB-free) File Integrity Monitoring logic: path validation, policy
 * input validation, SCAN SQL + osquery config JSON generation, and
 * nodes.config_id comma-list arithmetic. Contract: docs/FIM_DESIGN.md in the
 * vajra_server repo. Kept free of imports so selftests never load index.ts.
 */

import { getCatalogSource } from './fimCatalog';
import { FimValidationError } from './fimErrors';
import {
  validateRegistryKeyV2, normalizeRegistryEntryV2, buildRegistryScanSqlV2, isRegistryV2, entryFingerprint,
  canonicalRegistryKey, asciiLower, buildLegacyRegistrySql, isCleanText, type RegKeyOpts,
} from './fimRegistrySql';
import { createHash } from 'crypto';

export { FimValidationError };

export type FimOsPlatform = 'linux' | 'windows';
export type FimSeverity = 'low' | 'medium' | 'high' | 'critical';
export type FimMode = 'learn' | 'enforce';
export type FimTargetType = 'all' | 'group' | 'node';

export type FimEntryKind = 'path' | 'xattr' | 'registry' | 'acl' | 'table';

/**
 * One policy entry = one scan query + one initialise query. `kind` defaults to 'path'
 * (older stored entries have none). Item kinds carry the metadata the worker needs
 * (prefix/keyColumns/valueColumns), always filled by the server, never by the client.
 */
export interface FimPathEntry {
  kind?: FimEntryKind;
  /** path/xattr/registry/acl only. */
  path?: string;
  severity: FimSeverity;
  category: string;
  ignore: string[];
  hash: boolean;
  /** table only: catalog source id. */
  source?: string;
  label?: string;
  prefix?: string;
  keyColumns?: string[];
  valueColumns?: string[];
  /** table sources that need an osquery extension must be enabled explicitly. */
  extensionEnabled?: boolean;
  // ---- registry v2 (docs/FIM_REGISTRY_DESIGN.md §3.6/§3.12). Absent on legacy registry entries,
  // which keep their legacy scan SQL so existing baselines stay valid.
  entryKey?: string;
  values?: string[];
  ignoreValues?: string[];
  excludeKeys?: string[];
  includeSubkeys?: boolean;
  anchor?: boolean;
  hiveScoped?: boolean;
  redactValues?: string[];
  realtimeRequired?: boolean;
  /** Set on custom entries (kept for compatibility; spec v3 decides by visibleByDesign). */
  redactHeuristic?: boolean;
  /** Catalog command entries: only their own redactValues are hidden (see fimRegistrySql). */
  visibleByDesign?: boolean;
  /** Tombstone slot of a managed per-node policy: keeps its index, never scanned. */
  retired?: boolean;
  fingerprint?: string;
}

export const entryKind = (e: { kind?: FimEntryKind }): FimEntryKind => e.kind ?? 'path';

export interface FimTarget {
  type: FimTargetType;
  value: string;
}

export interface FimPolicyInput {
  name: string;
  description: string;
  osPlatform: FimOsPlatform;
  paths: FimPathEntry[];
  scanIntervalSecs: number;
  realtime: boolean;
  mode: FimMode;
  /** Accepted and stored for compatibility; ignored (baselines are never learned automatically). */
  learnScans: number;
  enabled: boolean;
  template: string | null;
  targets: FimTarget[];
}

export const FIM_MAX_PATH_LEN = 1024;
export const FIM_MAX_PATHS = 500;
export const FIM_MAX_IGNORES = 100;
export const FIM_MIN_INTERVAL = 60;
export const FIM_MAX_INTERVAL = 7 * 24 * 3600;
export const FIM_MAX_TARGETS = 1000;
/** Upper bound (secs) of the file_events drain interval. */
export const FIM_FILE_EVENTS_MAX_INTERVAL = 300;

const SEVERITIES: readonly string[] = ['low', 'medium', 'high', 'critical'];

/** Name prefix reserved for the managed per-node registry policies. */
export const FIM_MANAGED_NAME_PREFIX = 'Registry coverage: ';

/** Returns an error message, or null when the path is acceptable. */
export function validateFimPath(path: unknown, platform: FimOsPlatform): string | null {
  if (typeof path !== 'string') return 'path must be a string';
  if (path.trim().length === 0) return 'path must not be empty';
  if (path.length > FIM_MAX_PATH_LEN) return `path must be at most ${FIM_MAX_PATH_LEN} characters`;
  if (path.includes("'")) return 'path must not contain single quotes';
  if (path.includes('\0')) return 'path must not contain NUL characters';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(path)) return 'path must not contain control characters';
  // Format/bidi/invisible characters and unpaired surrogates (osquery refuses a config document
  // containing a lone surrogate, which would also break every other query in it).
  if (!isCleanText(path)) return 'path must not contain format, bidi, invisible, private-use, unassigned or unpaired surrogate characters';
  if (platform === 'linux') {
    if (!path.startsWith('/')) return "Linux paths must start with '/'";
    if (/[*?]/.test(path)) return "Linux paths do not support '*' or '?'; use '%' (one level) or '%%' (recursive)";
  } else if (!/^[A-Za-z]:[\\/]/.test(path) && !path.startsWith('*')) {
    return "Windows paths must start with a drive letter (e.g. 'C:\\') or '*'";
  }
  if (!hasRealDirectoryPrefix(path, platform)) {
    return 'path must name a real directory before the first wildcard (e.g. /etc/%% or C:\\Windows\\*); a bare root or leading wildcard would scan the whole filesystem';
  }
  return null;
}

/** True when the literal prefix before the first wildcard has at least one non-root segment. */
export function hasRealDirectoryPrefix(path: string, platform: FimOsPlatform): boolean {
  const wild = platform === 'windows' ? /[%*]/ : /%/;
  const idx = path.search(wild);
  let prefix = idx === -1 ? path : path.slice(0, idx);
  if (platform === 'windows') prefix = prefix.replace(/^[A-Za-z]:[\\/]*/, '');
  return prefix.split(platform === 'windows' ? /[\\/]/ : '/').some((seg) => seg !== '');
}

function validateIgnore(g: unknown): string | null {
  if (typeof g !== 'string') return 'ignore entries must be strings';
  if (g.length === 0 || g.length > FIM_MAX_PATH_LEN) return `ignore entries must be 1-${FIM_MAX_PATH_LEN} characters`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(g)) return 'ignore entries must not contain control characters';
  if (!isCleanText(g)) return 'ignore entries must not contain format, bidi, invisible or unpaired surrogate characters';
  return null;
}

const isObj = (v: unknown): v is Record<string, any> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

function fail(msg: string): never {
  throw new FimValidationError(msg);
}

const REGISTRY_HIVE = /^HKEY_(LOCAL_MACHINE|USERS|CLASSES_ROOT|CURRENT_USER|CURRENT_CONFIG)(?:\\|$)/;

/**
 * Returns an error message or null. Registry key pattern rules v2 (FIM_REGISTRY_DESIGN §4.2):
 * HKEY_LOCAL_MACHINE / HKEY_USERS only, '%' as a whole segment (one level), '%%' recursive only
 * as the last segment and only when `allowRecursive` (catalog / Super Administrator), deny-list
 * of credential hives. See fimRegistrySql.ts.
 */
export function validateRegistryKey(key: unknown, opts: RegKeyOpts = {}): string | null {
  return validateRegistryKeyV2(key, opts);
}

/** NTFS ACL entries are read for EXACT paths only. */
export function validateAclPath(path: unknown): string | null {
  const e = validateFimPath(path, 'windows');
  if (e) return e;
  const p = path as string;
  if (!/^[A-Za-z]:[\\/]/.test(p)) return 'ACL paths must start with a drive letter (e.g. C:\\Windows)';
  if (/[%*?]/.test(p)) return 'ACL paths must be exact (no wildcards)';
  return null;
}

const ITEM_META: Record<'xattr' | 'registry' | 'acl', { label: string; prefix: string; keyColumns: string[]; valueColumns: string[]; severity: FimSeverity; category: string }> = {
  xattr: { label: 'Extended attributes & ACLs', prefix: 'xattr', keyColumns: ['path', 'key'], valueColumns: ['value'], severity: 'high', category: 'acl' },
  registry: { label: 'Registry values', prefix: 'registry', keyColumns: ['path'], valueColumns: ['type', 'data'], severity: 'high', category: 'registry' },
  acl: { label: 'NTFS ACL entries', prefix: 'acl', keyColumns: ['path', 'principal', 'type'], valueColumns: ['access', 'inherited_from'], severity: 'high', category: 'acl' },
};

export interface NormalizeOpts {
  /** Super Administrator: may use recursive '%%' registry patterns. */
  superAdmin?: boolean;
  /** Entries already stored for this policy: only those may stay LEGACY registry entries. */
  existing?: FimPathEntry[];
}

export function normalizePaths(raw: unknown, platform: FimOsPlatform, opts: NormalizeOpts = {}): FimPathEntry[] {
  if (!Array.isArray(raw)) fail('paths must be an array');
  if (raw.length === 0) fail('at least one path is required');
  if (raw.length > FIM_MAX_PATHS) fail(`at most ${FIM_MAX_PATHS} paths are allowed`);
  const seen = new Set<string>();
  const out: FimPathEntry[] = [];
  raw.forEach((p, i) => {
    const w = `paths[${i}]`;
    const entry: Record<string, any> = typeof p === 'string' ? { path: p } : isObj(p) ? p : fail(`${w} must be an object`);
    const kind = entry.kind === undefined || entry.kind === null ? 'path' : entry.kind;
    if (!['path', 'xattr', 'registry', 'acl', 'table'].includes(kind)) fail(`${w}: kind must be one of path, xattr, registry, acl, table`);
    if (entry.retired !== undefined && entry.retired !== null && entry.retired !== false) fail(`${w}: retired slots are managed by the server`);
    const sevGiven = entry.severity !== undefined && entry.severity !== null;
    if (sevGiven && (typeof entry.severity !== 'string' || !SEVERITIES.includes(entry.severity))) fail(`${w}: severity must be one of ${SEVERITIES.join(', ')}`);
    const catGiven = entry.category !== undefined && entry.category !== null;
    if (catGiven && (typeof entry.category !== 'string' || entry.category.length > 64)) fail(`${w}: category must be a string of at most 64 characters`);

    let dupKey: string;
    let result: FimPathEntry;
    if (kind === 'table') {
      if (typeof entry.source !== 'string') fail(`${w}: source is required for a system configuration entry`);
      const src = getCatalogSource(entry.source);
      if (!src) fail(`${w}: unknown source '${String(entry.source).slice(0, 60)}'`);
      if (src.platform !== platform) fail(`${w}: source '${src.id}' is for ${src.platform} hosts, but the policy platform is ${platform}`);
      if (src.requiresExtension && entry.extensionEnabled !== true) fail(`${w}: source '${src.id}' needs an osquery extension on the agent; set extensionEnabled=true to confirm it is deployed`);
      dupKey = `table\u0000${src.id}`;
      result = {
        kind: 'table', source: src.id, label: src.label, prefix: src.id, keyColumns: [...src.keyColumns], valueColumns: [...src.valueColumns],
        severity: (sevGiven ? entry.severity : src.severity) as FimSeverity, category: catGiven ? entry.category : src.category, ignore: [], hash: false,
        ...(src.requiresExtension ? { extensionEnabled: true } : {}),
      };
    } else {
      let err: string | null;
      if (kind === 'path') err = validateFimPath(entry.path, platform);
      else if (kind === 'xattr') err = platform !== 'linux' ? 'extended attribute entries are only available for Linux policies' : validateFimPath(entry.path, 'linux');
      else if (kind === 'registry') err = platform !== 'windows' ? 'registry entries are only available for Windows policies' : validateRegistryKey(entry.path, { allowRecursive: opts.superAdmin === true });
      else err = platform !== 'windows' ? 'NTFS ACL entries are only available for Windows policies' : validateAclPath(entry.path);
      if (err) fail(`${w}: ${err}`);
      dupKey = `${kind}\u0000${kind === 'registry' ? asciiLower(canonicalRegistryKey(entry.path)) : entry.path}`;
      if (kind === 'path') {
        const ignore = entry.ignore === undefined || entry.ignore === null ? [] : entry.ignore;
        if (!Array.isArray(ignore) || ignore.length > FIM_MAX_IGNORES) fail(`${w}: ignore must be an array of at most ${FIM_MAX_IGNORES} globs`);
        for (const g of ignore) {
          const ie = validateIgnore(g);
          if (ie) fail(`${w}: ${ie}`);
        }
        if (entry.hash !== undefined && typeof entry.hash !== 'boolean') fail(`${w}: hash must be a boolean`);
        result = { kind: 'path', path: entry.path, severity: (sevGiven ? entry.severity : 'medium') as FimSeverity, category: catGiven ? entry.category : '', ignore: [...ignore], hash: entry.hash !== false };
      } else {
        const m = ITEM_META[kind as 'xattr' | 'registry' | 'acl'];
        result = {
          kind, path: kind === 'registry' ? canonicalRegistryKey(entry.path) : entry.path, severity: (sevGiven ? entry.severity : m.severity) as FimSeverity, category: catGiven ? entry.category : m.category,
          ignore: [], hash: false, label: m.label, prefix: m.prefix, keyColumns: [...m.keyColumns], valueColumns: [...m.valueColumns],
        };
        // New registry entries are always v2 (mandatory filters, anchor, host-side redaction). Only
        // an entry that is already stored as legacy keeps the legacy form, so its baseline stays valid.
        const keepLegacy = kind === 'registry' && !isRegistryV2(entry) && (opts.existing ?? []).some((x) =>
          x.kind === 'registry' && !x.retired && !isRegistryV2(x as unknown as Record<string, unknown>) && x.path === entry.path);
        if (kind === 'registry' && !keepLegacy) {
          // v2: value allow/deny lists, exclusions, anchor, hive scoping, redaction (§3.6).
          const v2 = normalizeRegistryEntryV2(entry, { allowRecursive: opts.superAdmin === true });
          if (typeof entry.label === 'string' && entry.label.trim() && entry.label.length <= 120) result.label = entry.label.trim();
          Object.assign(result, v2);
          result.fingerprint = entryFingerprint(v2);
          // The worker mirrors the scan SQL: secret-like heuristic redaction only for custom entries.
          if (v2.entryKey.startsWith('custom:')) result.redactHeuristic = true;
        }
      }
    }
    if (seen.has(dupKey)) fail(`${w}: duplicate entry`);
    seen.add(dupKey);
    out.push(result);
  });
  return out;
}

export function normalizeTargets(raw: unknown): FimTarget[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) fail('targets must be an array');
  if (raw.length > FIM_MAX_TARGETS) fail(`at most ${FIM_MAX_TARGETS} targets are allowed`);
  const seen = new Set<string>();
  const out: FimTarget[] = [];
  raw.forEach((t, i) => {
    if (!isObj(t)) fail(`targets[${i}] must be an object`);
    if (t.type !== 'all' && t.type !== 'group' && t.type !== 'node') fail(`targets[${i}].type must be all, group or node`);
    let value = '';
    if (t.type === 'all') {
      // The client sends '*' (or ''); stored as '' in fim_policy_targets.
      if (t.value !== undefined && t.value !== null && t.value !== '' && t.value !== '*') fail(`targets[${i}]: an 'all' target must have value '*' or ''`);
    } else {
      if (typeof t.value !== 'string' || t.value.trim() === '' || t.value.length > 255) fail(`targets[${i}].value must be a non-empty string of at most 255 characters`);
      value = t.value.trim();
    }
    const k = `${t.type}\u0000${value}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ type: t.type, value });
  });
  if (out.some((t) => t.type === 'all') && out.length > 1) fail("an 'all' target cannot be combined with other targets");
  return out;
}

function intField(v: unknown, name: string, min: number, max: number): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < min || v > max) fail(`${name} must be an integer between ${min} and ${max}`);
  return v;
}

/**
 * Validates + normalizes a full policy body. With `existing` set (update), omitted
 * fields keep their current value. Throws FimValidationError.
 */
export function validatePolicyInput(body: unknown, existing?: FimPolicyInput, opts: NormalizeOpts & { managed?: boolean } = {}): FimPolicyInput {
  if (!isObj(body)) fail('request body must be an object');
  const base: FimPolicyInput = existing ?? {
    name: '', description: '', osPlatform: 'linux', paths: [], scanIntervalSecs: 3600,
    realtime: true, mode: 'learn', learnScans: 2, enabled: true, template: null, targets: [],
  };
  const osPlatform = body.osPlatform === undefined ? base.osPlatform : body.osPlatform;
  if (osPlatform !== 'linux' && osPlatform !== 'windows') fail("osPlatform must be 'linux' or 'windows'");

  const name = body.name === undefined ? base.name : body.name;
  if (typeof name !== 'string' || name.trim() === '' || name.trim().length > 120) fail('name is required (at most 120 characters)');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) fail('name must not contain control characters');
  if (!isCleanText(name)) fail('name must not contain format, bidi, invisible or unpaired surrogate characters');
  if (!opts.managed && name.trim().toLowerCase().startsWith(FIM_MANAGED_NAME_PREFIX.toLowerCase())) fail(`names starting with '${FIM_MANAGED_NAME_PREFIX.trim()}' are reserved for managed registry coverage`);

  const description = body.description === undefined ? base.description : body.description;
  if (typeof description !== 'string' || description.length > 2000) fail('description must be a string of at most 2000 characters');

  // Paths are always re-validated against the (possibly changed) platform.
  const paths = normalizePaths(body.paths === undefined ? base.paths : body.paths, osPlatform, { ...opts, existing: existing?.paths ?? [] });

  const scanIntervalSecs = intField(body.scanIntervalSecs === undefined ? base.scanIntervalSecs : body.scanIntervalSecs, 'scanIntervalSecs', FIM_MIN_INTERVAL, FIM_MAX_INTERVAL);
  const learnScans = intField(body.learnScans === undefined ? base.learnScans : body.learnScans, 'learnScans', 1, 100);

  const realtime = body.realtime === undefined ? base.realtime : body.realtime;
  const enabled = body.enabled === undefined ? base.enabled : body.enabled;
  if (typeof realtime !== 'boolean') fail('realtime must be a boolean');
  if (typeof enabled !== 'boolean') fail('enabled must be a boolean');

  const mode = body.mode === undefined ? base.mode : body.mode;
  if (mode !== 'learn' && mode !== 'enforce') fail("mode must be 'learn' or 'enforce'");

  const template = body.template === undefined ? base.template : body.template;
  if (template !== null && (typeof template !== 'string' || template.length > 100)) fail('template must be a string or null');

  const targets = body.targets === undefined ? base.targets : normalizeTargets(body.targets);

  return { name: name.trim(), description, osPlatform, paths, scanIntervalSecs, realtime, mode, learnScans, enabled, template: template || null, targets };
}

/**
 * Whether two entry lists differ in a way that must bump fim_policies.rev: the ORDERED
 * list of {kind, path, source, ignore[]} entries (order matters because each entry is scanned by an
 * index-keyed query). Severity/category/hash edits do not bump it.
 */
export function pathsChanged(a: FimPathEntry[], b: FimPathEntry[]): boolean {
  const key = (l: FimPathEntry[]) => JSON.stringify(l.map(entryRevKey));
  return key(a) !== key(b);
}

/**
 * What of an entry changes its scan (and so must bump rev): kind, path, source, ignore globs,
 * and for registry v2 entries everything in the fingerprint (lists, anchor, hive scoping,
 * redaction, entry key). Tombstones are distinct from live entries.
 */
export function entryRevKey(e: FimPathEntry): unknown[] {
  const k: unknown[] = [entryKind(e), e.path ?? '', e.source ?? '', e.extensionEnabled === true, [...new Set(e.ignore ?? [])].sort()];
  if (e.retired === true) k.push('retired');
  if (entryKind(e) === 'registry' && !e.retired && isRegistryV2(e as unknown as Record<string, unknown>)) {
    k.push('v2', entryFingerprint({
      path: e.path ?? '', values: e.values, ignoreValues: e.ignoreValues, excludeKeys: e.excludeKeys, includeSubkeys: e.includeSubkeys,
      anchor: e.anchor, hiveScoped: e.hiveScoped, redactValues: e.redactValues, entryKey: e.entryKey,
    }));
  }
  if (!e.retired && entryKind(e) !== 'table') {
    // Whatever the reason, a different generated query is a different scan.
    let sql = 'invalid';
    try { sql = buildScanSql(e as ScanEntry, entryKind(e) === 'registry' || entryKind(e) === 'acl' ? 'windows' : (e.path ?? '').startsWith('/') ? 'linux' : 'windows'); } catch { /* stays 'invalid' */ }
    k.push(createHash('sha256').update(sql).digest('hex'));
  }
  return k;
}

/** Soft warnings (never blocking) for patterns likely to exceed the osquery line limit. */
export const FIM_LARGE_PATTERN_NOTE =
  'A single pattern matching more than ~2,500 files exceeds the osquery result line limit and its scan results are dropped; narrow it.';
// Directories known to hold well over 2,500 files on typical hosts (measured: /usr/bin 4482,
// /usr/lib 14225, /lib/modules 146338 on a desktop Ubuntu).
const BIG_DIRS = new Set(['/usr', '/lib', '/lib64', '/var', '/opt', '/home', '/proc', '/sys', '/dev', '/bin', '/sbin',
  '/usr/bin', '/usr/lib', '/usr/lib64', '/usr/share', '/usr/include', '/usr/src', '/var/lib', '/var/cache', '/lib/modules']);
export function fimPathWarnings(paths: { kind?: FimEntryKind; path?: string }[], platform: FimOsPlatform): string[] {
  const out: string[] = [];
  for (const e of paths) {
    if (!e.path) continue;
    const path = e.path;
    if (entryKind(e) === 'registry') {
      // Broad registry subtree: a bare trailing % / %% a few keys below the hive (measured: CurrentControlSet\\Services\\% = 6,924 rows / 1 MiB).
      const m = REGISTRY_HIVE.exec(path);
      if (m && /%+$/.test(path)) {
        const lit = path.slice(m[0].length).split('\\').filter((x) => x !== '' && !x.includes('%'));
        if (lit.length <= 3 || path.endsWith('%%')) out.push(`${path}: broad registry subtree. ${FIM_LARGE_PATTERN_NOTE.replace('files', 'rows')}`);
      }
      continue;
    }
    if (entryKind(e) !== 'path') continue;
    if (platform === 'linux') {
      const rec = path.endsWith('%%');
      const dir = path.slice(0, path.lastIndexOf('/')) || '/';
      if (rec && BIG_DIRS.has(dir)) {
        out.push(`${path}: broad recursive pattern. ${FIM_LARGE_PATTERN_NOTE}`);
      }
    } else if (/^[A-Za-z]:[\\/]+(Windows|Program Files( \(x86\))?|Users)[\\/]*[%*]{1,2}$/i.test(path)) {
      out.push(`${path}: broad pattern. ${FIM_LARGE_PATTERN_NOTE}`);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// SCAN SQL + config JSON
// ---------------------------------------------------------------------------

function assertSafePath(p: string, platform: FimOsPlatform): void {
  const err = validateFimPath(p, platform);
  if (err) throw new FimValidationError(err);
}

/** Maps a policy path pattern to a SQL LIKE pattern (windows '*' -> '%'). */
export function toLikePattern(path: string, platform: FimOsPlatform): string {
  return platform === 'windows' ? path.replace(/\*/g, '%') : path;
}

/**
 * Hidden-file coverage (Linux). osquery's % / %% glob skips names starting with '.'
 * (and `.%%` / `.%/%%` would recurse through the '.' and '..' directory entries, i.e.
 * walk the PARENT tree, so they must never be used). Verified empirically with
 * osqueryd 5.0.1.1 on a temp tree (.hid, a/.dotfile, a/.cache/evil, .d/x/y,
 * b/c/.hc/deep/z): the single-level terms below return hidden entries safely:
 *   P.%       hidden files/dirs directly in P           (.hid, .d/)
 *   P%/.%     hidden entries one level down             (a/.dotfile, a/.cache/)
 *   P%/%/.%   hidden entries two levels down            (b/c/.hc/)
 *   P.%/%     files inside a top-level hidden dir       (.d/x/)
 *   P%/.%/%   files inside a hidden dir one level down  (a/.cache/evil)
 * They also return '.'/'..' relative entries (e.g. P/a/../vis), so '/./' and '/../'
 * paths are excluded. LIMITATION: hidden directories deeper than that
 * (e.g. b/c/.hc/deep/z, .d/x/y) are not covered; mid-path %% is not supported by
 * osquery. Windows has no dot-file convention, so no extra terms there.
 */
function hiddenTerms(path: string): string[] {
  const idx = path.lastIndexOf('/');
  const last = path.slice(idx + 1);
  if (last !== '%' && last !== '%%') return [];
  const P = path.slice(0, idx + 1);
  const terms = [`${P}.%`];
  if (last === '%%') terms.push(`${P}%/.%`, `${P}%/%/.%`, `${P}.%/%`, `${P}%/.%/%`);
  return terms;
}

function likeConds(col: string, path: string, platform: FimOsPlatform): { where: string; hidden: boolean } {
  const like = toLikePattern(path, platform);
  const hidden = platform === 'linux' ? hiddenTerms(path) : [];
  const conds = [like, ...hidden].map((t) => `${col} LIKE '${t}'`);
  const where = hidden.length
    ? `(${conds.join(' OR ')}) AND ${col} NOT LIKE '%/../%' AND ${col} NOT LIKE '%/./%'`
    : conds.join(' OR ');
  return { where, hidden: hidden.length > 0 };
}

export type ScanEntry = string | ({ kind?: FimEntryKind; path?: string; source?: string } & Partial<Pick<FimPathEntry,
  'values' | 'ignoreValues' | 'excludeKeys' | 'includeSubkeys' | 'anchor' | 'hiveScoped' | 'redactValues' | 'entryKey' | 'realtimeRequired' | 'retired' | 'visibleByDesign'>>);

/**
 * Builds the snapshot SCAN SQL for ONE entry (one osquery query per entry keeps each
 * result line under logger_tls_max_linesize). The same text is used for scheduled scans
 * and for Initialize. Everything embedded is validated (no quote, NUL or control
 * character can survive) or comes from the fixed catalog, so no literal can be broken
 * out of. Throws on any unsafe input. A bare string is a 'path' entry.
 *
 * path: files AND directories. The LEFT JOIN is guarded by f.type = 'regular' so FIFOs,
 *   devices and directories are never opened for hashing (verified with osqueryd 5.0.1:
 *   directories come back with type='directory' and a trailing slash).
 * xattr (linux): extended_attributes needs a path constraint; LIKE works (verified).
 * registry (windows, UNVERIFIED): registry.key LIKE '<pattern>' - '%' one level, '%%' recursive,
 *   as documented for the osquery registry table.
 * acl (windows, UNVERIFIED): ntfs_acl_permissions for one exact path.
 * table: the catalog's fixed SELECT.
 */
export function buildScanSql(entryIn: ScanEntry, platform: FimOsPlatform): string {
  const entry = typeof entryIn === 'string' ? { kind: 'path' as const, path: entryIn } : entryIn;
  const kind = entryKind(entry);
  if (kind === 'table') {
    const src = entry.source ? getCatalogSource(entry.source) : undefined;
    if (!src) throw new FimValidationError('unknown catalog source');
    if (src.platform !== platform) throw new FimValidationError(`source '${src.id}' is not available on ${platform}`);
    return src.sql;
  }
  const path = entry.path;
  if (typeof path !== 'string') throw new FimValidationError('path is required');
  if (kind === 'registry') {
    if (platform !== 'windows') throw new FimValidationError('registry entries are Windows-only');
    if ((entry as { retired?: boolean }).retired) throw new FimValidationError('retired slots are never scanned');
    if (isRegistryV2(entry as Record<string, unknown>)) {
      // Re-normalised here so SQL is never built from an unvalidated stored entry.
      return buildRegistryScanSqlV2(normalizeRegistryEntryV2(entry as Record<string, unknown>, { allowRecursive: true, maxWildcards: 4 }));
    }
    // Stored legacy entries keep their legacy filter (existing baselines stay valid) plus the
    // mandatory credential redaction.
    return buildLegacyRegistrySql(path);
  }
  if (kind === 'acl') {
    const err = platform !== 'windows' ? 'ACL entries are Windows-only' : validateAclPath(path);
    if (err) throw new FimValidationError(err);
    return `SELECT path, type, principal, access, inherited_from FROM ntfs_acl_permissions WHERE path = '${path}'`;
  }
  if (kind === 'xattr') {
    if (platform !== 'linux') throw new FimValidationError('extended attribute entries are Linux-only');
    assertSafePath(path, 'linux');
    return `SELECT path, key, value FROM extended_attributes WHERE ${likeConds('path', path, 'linux').where}`;
  }
  assertSafePath(path, platform);
  const { where } = likeConds('f.path', path, platform);
  const cols = platform === 'windows'
    ? 'f.path, f.type, f.size, f.mtime, h.sha256, h.md5'
    : 'f.path, f.type, f.size, f.mode, f.uid, f.gid, f.mtime, h.sha256, h.md5';
  return `SELECT ${cols} FROM file f LEFT JOIN hash h ON h.path = f.path AND f.type = 'regular' WHERE ${where}`;
}

export function scanQueryName(policyId: number | string, rev: number | string, entryIdx: number): string {
  return `fim_scan_${policyId}_${rev}_${entryIdx}`;
}

export function fimGroupKey(policyId: number | string): string {
  return `fim_${policyId}`;
}

export interface PublishablePolicy {
  id: number | string;
  rev: number | string;
  osPlatform: FimOsPlatform;
  paths: Exclude<ScanEntry, string>[];
  scanIntervalSecs: number;
  realtime: boolean;
}

/** The config_queries.query JSON document for a policy (see FIM_DESIGN.md). */
export function buildFimConfig(p: PublishablePolicy): Record<string, unknown> {
  // Real-time watching only makes sense for file/directory entries.
  const pathList = p.paths.filter((x) => entryKind(x) === 'path' && !x.retired).map((x) => x.path as string);
  const schedule: Record<string, any> = {};
  p.paths.forEach((entry, k) => {
    // Tombstone slots keep their index (the worker aligns entries by index) but are never scheduled.
    if (entry.retired) return;
    schedule[scanQueryName(p.id, p.rev, k)] = {
      query: buildScanSql(entry, p.osPlatform),
      interval: p.scanIntervalSecs,
      snapshot: true,
    };
  });
  const cfg: Record<string, any> = { schedule };
  if (p.osPlatform === 'linux') {
    if (p.realtime && pathList.length > 0) {
      cfg.file_paths = { [fimGroupKey(p.id)]: pathList };
      // Without a scheduled query on file_events the agent never reports inotify
      // events. The schedule key MUST be exactly 'file_events': vajra_server routes
      // /log results by schedule name. Several realtime policies emit an identical
      // body under this key; they live in separate config_queries rows that the
      // server merges, so publishing/unpublishing one never removes another's key.
      cfg.schedule.file_events = {
        query: 'SELECT * FROM file_events',
        interval: Math.min(p.scanIntervalSecs, FIM_FILE_EVENTS_MAX_INTERVAL),
        snapshot: false,
      };
    }
  } else if (p.realtime && pathList.length > 0) {
    // Windows: win_include_paths is emitted per the design but NOT yet verified
    // end-to-end against a real agent (no equivalent scheduled events query is
    // added here; the Windows event pipeline is routed differently).
    cfg.win_include_paths = { [fimGroupKey(p.id)]: pathList };
  }
  return cfg;
}

export function fimQueryName(policyName: string): string {
  return `fim:${policyName}`;
}

export function fimConfigOsName(platform: FimOsPlatform): string {
  return platform === 'windows' ? 'Windows' : 'Linux';
}

// ---------------------------------------------------------------------------
// nodes.config_id comma-list arithmetic (mirrors the SQL used in publish)
// ---------------------------------------------------------------------------

export function parseConfigIds(list: string | null | undefined): string[] {
  return (list ?? '').split(',').map((s) => s.trim()).filter((s) => s !== '');
}

/** Adds id (idempotent), preserving every other entry and its order. */
export function addConfigId(list: string | null | undefined, id: number | string): string {
  const ids = parseConfigIds(list);
  const s = String(id);
  if (!ids.includes(s)) ids.push(s);
  return ids.join(',');
}

/** Removes only id, preserving every other entry and its order. */
export function removeConfigId(list: string | null | undefined, id: number | string): string {
  const s = String(id);
  return parseConfigIds(list).filter((x) => x !== s).join(',');
}

/** SQL expression fragments (parameter-free; $n is supplied by the caller). */
export const SQL_CLEAN_IDS = `ARRAY(SELECT btrim(x) FROM unnest(string_to_array(COALESCE(config_id, ''), ',')) AS x WHERE btrim(x) <> '')`;

/** Escapes LIKE metacharacters for use with ESCAPE '\'. */
export function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (m) => `\\${m}`);
}

// ---------------------------------------------------------------------------
// Group Admin scoping (mirrors policy_management.ts isPolicyFullyInScope)
// ---------------------------------------------------------------------------

/**
 * True when every target lies inside the caller's groups/hosts. 'all' is never
 * in scope for a scoped caller. An empty target list is only manageable by its
 * creator (pass callerEmail for persisted policies; omit for a candidate).
 */
export function isFimPolicyInScope(
  policy: { targets: FimTarget[]; createdBy?: string | null },
  groupIds: Set<string>,
  hostIds: Iterable<string>,
  callerEmail?: string | null,
): boolean {
  const hosts = new Set(hostIds);
  if (policy.targets.some((t) => t.type === 'all')) return false;
  if (policy.targets.length === 0) {
    if (callerEmail === undefined) return true;
    return !!policy.createdBy && !!callerEmail && policy.createdBy.toLowerCase() === callerEmail.toLowerCase();
  }
  return policy.targets.every((t) => (t.type === 'group' ? groupIds.has(t.value) : hosts.has(t.value)));
}
