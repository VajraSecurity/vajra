/**
 * Registry v2 entries for FIM (docs/FIM_REGISTRY_DESIGN.md §3.6, §4.2): key-pattern and
 * value-name validation, the scan SQL, entry fingerprints and pattern intersection.
 * Pure and DB-free (no imports from index.ts) so selftests load it directly.
 *
 * Security model: every literal that reaches generated SQL passes validateRegistryKeyV2 /
 * validateValueName first and then sqlString(), which THROWS on anything the validator
 * refuses (defence in depth). The finished SQL is re-checked against a fixed token shape and
 * a 16 KiB cap (assertRegistrySqlShape). No caller concatenates SQL itself.
 *
 * UNVERIFIED on a Windows agent (no agent available here): the anchor UNION, `NOT LIKE ...
 * ESCAPE '^'`, `lower(name) IN (...)` pushed to SQLite, the HKEY_USERS\%\SOFTWARE\Classes link
 * traversal, and the "(Default)" value name. The SQL text itself is verified to parse and to
 * filter correctly in osquery's SQLite (osqueryd -S against a CTE stand-in for `registry`,
 * see src/test/utils/fimRegistry.selftest.ts).
 */
import redactionPolicyJson from './fimRedactionPolicy.json';
import { createHash } from 'crypto';
import { FimValidationError } from './fimErrors';
import { getRegCatalogEntry, catalogVisibleByDesign } from './fimRegistryCatalog';

export const REG_LIMITS = {
  keyMinLen: 3,
  keyMaxLen: 512,
  maxSegments: 32,
  maxWildcards: 3,
  valueNameMax: 255,
  valuesMax: 64,
  ignoreValuesMax: 64,
  excludeKeysMax: 32,
  redactValuesMax: 16,
  sqlMaxBytes: 16 * 1024,
} as const;

export const HKLM = 'HKEY_LOCAL_MACHINE';
/** Literal key names required after HKEY_USERS\% (see validateRegistryKeyV2). */
export const FIM_REG_HKU_MIN_LITERALS = 1;
export const HKU = 'HKEY_USERS';
/** `HKEY_USERS\S-1-5-18` is an alias of `.DEFAULT` (every per-user value appeared twice, B5). */
export const LOCAL_SYSTEM_EXCLUSION = 'HKEY_USERS\\S-1-5-18\\%';

/**
 * Registry identifiers (key patterns, exclusions, value names) are PRINTABLE ASCII ONLY.
 * Rationale (review findings): SQLite's lower()/LIKE in osquery fold ASCII only, so any
 * non-ASCII character makes the generated filter, the deny-list check, the fingerprint and the
 * real-time comparison disagree (Kelvin sign, long s 'ſAM', 'Ä' vs 'ä', lone surrogates that make
 * osquery reject the whole config, invisible format characters). Localized key or value names
 * cannot be configured as filters; they are still COLLECTED by wildcard patterns.
 */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
/** Characters refused anywhere in FIM text (file paths, globs, names): \p{C} (Cc Cf Cs Co Cn),
 *  line/paragraph separators, and invisible fillers. */
// (U+034F, a combining character, is matched as its own alternative so the class stays unambiguous.)
export const FIM_BAD_TEXT = /[\p{C}\u2028\u2029\u00ad\u115f\u1160\u180e\u3164\uffa0]|\u034f/u;
/** True when s is well-formed UTF-16 and free of FIM_BAD_TEXT characters. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export const isCleanText = (s: string): boolean => !LONE_SURROGATE.test(s) && !FIM_BAD_TEXT.test(s);

/**
 * Host-side redaction lists. Single source of truth: fimRedactionPolicy.json, a byte-identical copy
 * of the worker's engine_v2/fim/redaction_policy.json (embedded into vajra_fim at build time).
 * Both test suites pin the same canonical SHA-256, so the two copies cannot drift apart silently.
 *  - MANDATORY_REDACT_VALUES: credential-bearing names ALWAYS redacted, in every registry scan
 *    however the entry was created (legacy, custom, wildcard, catalog) and by the worker for
 *    real-time events. Presence and value length stay visible; a same-length change is not.
 *  - SECRET_LIKE_SUBSTRINGS: value names containing one of these (ASCII case-insensitive) are
 *    redacted too (custom keys can point at any application's settings: VNC, PuTTY, WinSCP, ...),
 *  - unless listed in FIM_REDACT_EXEMPT: non-secret security settings whose changes must stay
 *    visible (WDigest UseLogonCredential, Lsa LimitBlankPasswordUse, Winlogon PasswordExpiryWarning,
 *    password-policy numbers, ...). Subkey rows are never redacted.
 */
export const FIM_REDACTION_POLICY: { mandatory: string[]; secretLike: string[]; exempt: string[] } = redactionPolicyJson;
export const MANDATORY_REDACT_VALUES: string[] = [...redactionPolicyJson.mandatory];
export const SECRET_LIKE_SUBSTRINGS: string[] = [...redactionPolicyJson.secretLike];
export const FIM_REDACT_EXEMPT: string[] = [...redactionPolicyJson.exempt];
/** The name predicate applied to CUSTOM / legacy entries (catalog entries use only their redactValues). */
export function isSecretLikeName(name: string): boolean {
  const l = asciiLower(name);
  if (MANDATORY_REDACT_VALUES.includes(l)) return true;
  return (SECRET_LIKE_SUBSTRINGS.some((x) => l.includes(x)) || /[^\x20-\x7e]/.test(name)) && !FIM_REDACT_EXEMPT.includes(l);
}
const REFUSED_HIVES = new Set(['HKEY_CURRENT_USER', 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_CONFIG', 'HKCU', 'HKCR', 'HKCC']);
const ENTRY_KEY_RE = /^(reg\.[a-z0-9][a-z0-9._-]{0,99}|custom:[0-9a-f]{16})$/;

/**
 * Keys whose CONTENTS are never collected (§4.2): credential material (SAM, SECURITY, the LSA
 * boot-key neighbours) and volatile per-logon data. '%' = any one segment. A pattern may still
 * read the PARENT of a denied key (its subkey rows only carry names, never data).
 */
const DENY_ROOTS: string[][] = [
  [HKLM, 'SAM'],
  [HKLM, 'SECURITY'],
  ...['Data', 'JD', 'Skew1', 'GBG'].map((k) => [HKLM, 'SYSTEM', '%', 'Control', 'Lsa', k]),
  [HKU, '%', 'Volatile Environment'],
];

/** ASCII-only lower case: exactly what SQLite's lower() does inside osquery (verified: lower('ÉA') = 'Éa'). */
export const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

export const isWild = (seg: string): boolean => seg === '%' || seg === '%%';

/** Upper-cases the hive name (canonical stored form); the rest of the key keeps its spelling. */
export function canonicalRegistryKey(key: string): string {
  const up = (h: string) => asciiLower(h).toUpperCase();
  const i = key.indexOf('\\');
  return i < 0 ? up(key) : up(key.slice(0, i)) + key.slice(i);
}

/** SQL LIKE as SQLite evaluates the exclusions: '%' any run, rest literal, ASCII case-insensitive. */
export function likeMatch(pattern: string, text: string): boolean {
  const p = asciiLower(pattern), t = asciiLower(text);
  let dp: boolean[] = new Array(p.length + 1).fill(false);
  dp[0] = true;
  for (let j = 1; j <= p.length; j++) dp[j] = dp[j - 1] && p[j - 1] === '%';
  for (let i = 1; i <= t.length; i++) {
    const nx: boolean[] = new Array(p.length + 1).fill(false);
    for (let j = 1; j <= p.length; j++) nx[j] = p[j - 1] === '%' ? dp[j] || nx[j - 1] : dp[j - 1] && p[j - 1] === t[i - 1];
    dp = nx;
  }
  return dp[p.length];
}

export interface RegKeyOpts {
  /** '%%' (recursive) is allowed only in catalog entries or for a Super Administrator. */
  allowRecursive?: boolean;
  /** Catalog-only exemption (one entry needs four wildcard levels). */
  maxWildcards?: number;
  /** excludeKeys: same character/segment rules; no deny-list (nothing is read); no '%%'. */
  exclusion?: boolean;
}

/** One pattern segment vs one deny segment, with SQL LIKE semantics for '_' (any one character),
 *  because the agent filters with LIKE: 'S_M' must count as reaching into 'SAM'. */
function segMatch(p: string, d: string): boolean {
  if (p === '%' || d === '%') return true;
  if (!p.includes('_')) return asciiLower(p) === asciiLower(d);
  const re = new RegExp(`^${asciiLower(p).split('').map((c) => (c === '_' ? '.' : c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`);
  return re.test(asciiLower(d));
}

function reachesInto(pattern: string[], deny: string[]): boolean {
  for (let i = 0; i < deny.length; i++) {
    if (i >= pattern.length) return false; // pattern is an ancestor: only subkey NAMES are read
    const p = pattern[i];
    if (p === '%%') return true;
    if (!segMatch(p, deny[i])) return false;
  }
  return true;
}

/** Registry key pattern validation (v2, §4.2). Returns an error message or null. */
export function validateRegistryKeyV2(key: unknown, opts: RegKeyOpts = {}): string | null {
  if (typeof key !== 'string') return 'registry key must be a string';
  if (key.length < REG_LIMITS.keyMinLen || key.length > REG_LIMITS.keyMaxLen) return `registry key must be ${REG_LIMITS.keyMinLen}-${REG_LIMITS.keyMaxLen} characters`;
  if (key.includes("'")) return 'registry key must not contain single quotes';
  if (!PRINTABLE_ASCII.test(key)) return 'registry key patterns must be printable ASCII (no control, format, bidi, non-ASCII or unpaired surrogate characters)';
  if (/[*?/]/.test(key)) return "registry key must not contain '*', '?' or '/'; use '%' as a whole key segment";
  const segs = key.split('\\');
  const hive = asciiLower(segs[0]).toUpperCase();
  if (REFUSED_HIVES.has(hive)) {
    return `${segs[0]} is refused: osqueryd runs as SYSTEM, so HKEY_CURRENT_USER is not the logged-on user, and real-time events never report these names. Use HKEY_USERS\\%\\... (every loaded user) or HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\...`;
  }
  if (hive !== HKLM && hive !== HKU) return 'registry key must start with HKEY_LOCAL_MACHINE\\ or HKEY_USERS\\';
  if (segs.length < 2) return 'registry key must name a key below the hive';
  if (segs.length > REG_LIMITS.maxSegments) return `registry key must have at most ${REG_LIMITS.maxSegments} segments`;
  for (let i = 1; i < segs.length; i++) {
    const s = segs[i];
    if (s === '') return 'registry key must not contain an empty segment (\\\\) or end with \\';
    if (s !== s.trim()) return 'registry key segments must not start or end with spaces';
    if (s.includes('%') && !isWild(s)) {
      return "'%' must be a whole key segment (e.g. ...\\Services\\%\\Parameters). Partial patterns such as Run% are refused: they also match look-alike keys such as RunNotification";
    }
  }
  const body = segs.slice(1);
  const wild = body.filter(isWild).length;
  if (wild > (opts.maxWildcards ?? REG_LIMITS.maxWildcards)) return `registry key may contain at most ${opts.maxWildcards ?? REG_LIMITS.maxWildcards} '%' segments`;
  const rec = segs.indexOf('%%');
  if (rec !== -1) {
    if (opts.exclusion) return "'%%' is not used in exclusions: a trailing '%' already matches every level below";
    if (rec !== segs.length - 1) return "'%%' (recursive) is only allowed as the last segment";
    if (!opts.allowRecursive) return "'%%' (recursive) is only allowed in catalog entries or by a Super Administrator";
    if (segs.slice(1, rec).filter((s) => !isWild(s)).length < 3) return "'%%' needs at least three literal key names before it";
  }
  if (hive === HKLM && isWild(segs[1])) return 'the first key below HKEY_LOCAL_MACHINE must be a literal name';
  if (hive === HKU) {
    if (isWild(segs[1])) {
      // §4.2 says "at least 2 literal segments", but the same document's catalog (reg.env.user) and
      // test plan require HKEY_USERS\%\Environment to be accepted: one literal is the minimum
      // (HKEY_USERS\% alone stays refused).
      if (segs.slice(2).filter((s) => !isWild(s)).length < FIM_REG_HKU_MIN_LITERALS) return 'HKEY_USERS\\%\\... must be followed by a literal key name';
    } else if (segs.length < 3 && !opts.exclusion) {
      return 'HKEY_USERS\\<SID> alone is a whole user hive; name a key inside it';
    }
  }
  if (!opts.exclusion) {
    const canon = [hive, ...body];
    if (DENY_ROOTS.some((d) => reachesInto(canon, d))) {
      return 'this key is refused: credential material (SAM, SECURITY, LSA boot-key neighbours) and volatile per-logon data are never collected';
    }
  }
  return null;
}

/** Value names (values / ignoreValues / redactValues). '\' is allowed; '(Default)' is literal. */
export function validateValueName(name: unknown): string | null {
  if (typeof name !== 'string') return 'value names must be strings';
  if (name.length < 1 || name.length > REG_LIMITS.valueNameMax) return `value names must be 1-${REG_LIMITS.valueNameMax} characters`;
  if (name.includes("'")) return 'value names must not contain single quotes';
  if (!PRINTABLE_ASCII.test(name)) return 'value names must be printable ASCII (no control, format, bidi, non-ASCII or unpaired surrogate characters)';
  if (/[*?]/.test(name)) return "value names must not contain '*' or '?'";
  return null;
}

/** The ONLY way a literal enters generated registry SQL. Throws on anything unsafe. */
export function sqlString(s: unknown): string {
  if (typeof s !== 'string' || s.includes("'") || !PRINTABLE_ASCII.test(s) || s.length > 4096) {
    throw new FimValidationError('refusing to build SQL from an unsafe literal');
  }
  return `'${s}'`;
}

/** LIKE pattern for `NOT LIKE ... ESCAPE '^'`: '_' and '^' become literal, '%' stays a wildcard. */
export const escapeLikeCaret = (s: string): string => s.replace(/[\^_]/g, (m) => `^${m}`);

const sqlList = (names: string[]): string => names.map((n) => sqlString(n)).join(', ');

// ---------------------------------------------------------------------------------------------
// Entry model
// ---------------------------------------------------------------------------------------------

export interface RegistryEntryV2 {
  path: string;
  values: string[];
  ignoreValues: string[];
  excludeKeys: string[];
  includeSubkeys: boolean;
  anchor: boolean;
  hiveScoped: boolean;
  redactValues: string[];
  entryKey: string;
  realtimeRequired: boolean;
  /**
   * Catalog command/autostart entries whose values are commands (Run, IFEO, Services ImagePath,
   * Winlogon Shell/Userinit, ...): redact ONLY their own redactValues. Every other entry (custom,
   * legacy, configuration-like catalog entries such as RDP or environment variables) also redacts
   * credential-like names (spec v3).
   */
  visibleByDesign?: boolean;
}

const V2_FIELDS = ['values', 'ignoreValues', 'excludeKeys', 'includeSubkeys', 'anchor', 'hiveScoped', 'redactValues', 'entryKey', 'realtimeRequired'] as const;

/** A registry entry is "v2" when it carries any v2 field. Legacy entries keep their legacy SQL. */
export function isRegistryV2(e: Record<string, unknown>): boolean {
  return V2_FIELDS.some((k) => e[k] !== undefined && e[k] !== null);
}

export function isEntryKey(s: unknown): s is string {
  return typeof s === 'string' && ENTRY_KEY_RE.test(s);
}

/** Deterministic custom entry key from the (canonical) pattern. */
export function customEntryKey(path: string): string {
  return `custom:${createHash('sha256').update(asciiLower(canonicalRegistryKey(path)), 'utf8').digest('hex').slice(0, 16)}`;
}

type Tok = { t: 'lit'; v: string } | { t: 'one' } | { t: 'any' };
function toks(path: string, trailingPercentIsAny = false): Tok[] {
  const segs = path.split('\\');
  return segs.map((s, i) => {
    if (s === '%%') return { t: 'any' } as Tok;
    if (s === '%') return (trailingPercentIsAny && i === segs.length - 1 ? { t: 'any' } : { t: 'one' }) as Tok;
    return { t: 'lit', v: s.toLowerCase() } as Tok;
  });
}

function tokIntersect(a: Tok[], b: Tok[], i = 0, j = 0): boolean {
  if (i === a.length && j === b.length) return true;
  if ((i < a.length && a[i].t === 'any') || (j < b.length && b[j].t === 'any')) return true;
  if (i >= a.length || j >= b.length) return false;
  const x = a[i], y = b[j];
  if (x.t === 'lit' && y.t === 'lit' && x.v !== y.v) return false;
  return tokIntersect(a, b, i + 1, j + 1);
}

/** Can two key patterns match a common key? ('%' one segment, trailing '%%' any suffix.) */
export function keysIntersect(a: string, b: string): boolean {
  return tokIntersect(toks(a), toks(b));
}

/** Does pattern `p` match the exact (wildcard-free) key `k`? */
export function patternMatchesKey(p: string, k: string): boolean {
  return !k.split('\\').some(isWild) && keysIntersect(p, k);
}

/**
 * Exclusions are evaluated by SQLite LIKE, where '%' matches any run (including '\'), so a
 * trailing '%' covers every level below. An exclusion that can match no key of the entry is a
 * probable typo and is refused.
 */
export function exclusionInside(pattern: string, exclusion: string): boolean {
  return tokIntersect(toks(pattern), toks(exclusion, true));
}

function dedupeNames(list: unknown, max: number, what: string): string[] {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new FimValidationError(`${what} must be an array of value names`);
  if (list.length > max) throw new FimValidationError(`${what}: at most ${max} value names`);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const n of list) {
    const err = validateValueName(n);
    if (err) throw new FimValidationError(`${what}: ${err}`);
    const k = asciiLower(n as string);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(n as string);
  }
  return out;
}

/**
 * Validates and normalises a registry v2 entry body (custom entries, hand-made v2 entries and,
 * in the selftest, every catalog entry). Throws FimValidationError.
 */
export function normalizeRegistryEntryV2(raw: Record<string, unknown>, opts: RegKeyOpts = {}): RegistryEntryV2 {
  const err = validateRegistryKeyV2(raw.path, opts);
  if (err) throw new FimValidationError(err);
  const path = canonicalRegistryKey(raw.path as string);
  const values = dedupeNames(raw.values, REG_LIMITS.valuesMax, 'values');
  const ignoreValues = dedupeNames(raw.ignoreValues, REG_LIMITS.ignoreValuesMax, 'ignoreValues');
  const redactValues = dedupeNames(raw.redactValues, REG_LIMITS.redactValuesMax, 'redactValues');
  let excludeKeys: string[] = [];
  if (raw.excludeKeys !== undefined && raw.excludeKeys !== null) {
    if (!Array.isArray(raw.excludeKeys)) throw new FimValidationError('excludeKeys must be an array of key patterns');
    if (raw.excludeKeys.length > REG_LIMITS.excludeKeysMax) throw new FimValidationError(`excludeKeys: at most ${REG_LIMITS.excludeKeysMax} patterns`);
    const seen = new Set<string>();
    for (const x of raw.excludeKeys) {
      const e = validateRegistryKeyV2(x, { exclusion: true });
      if (e) throw new FimValidationError(`excludeKeys: ${e}`);
      const c = canonicalRegistryKey(x as string);
      if (!exclusionInside(path, c)) throw new FimValidationError(`excludeKeys: '${c}' matches no key of '${path}' (probable typo)`);
      // An exclusion may only narrow INSIDE the entry: one that matches the entry's own key (or
      // covers its whole pattern) would silently empty it.
      if (likeMatch(c, path)) throw new FimValidationError(`excludeKeys: '${c}' would exclude the entry's own key pattern '${path}'`);
      if (seen.has(asciiLower(c))) continue;
      seen.add(asciiLower(c));
      excludeKeys.push(c);
    }
    excludeKeys = excludeKeys.sort((a, b) => (asciiLower(a) < asciiLower(b) ? -1 : asciiLower(a) > asciiLower(b) ? 1 : 0));
  }
  const bool = (k: string, dflt: boolean): boolean => {
    const v = raw[k];
    if (v === undefined || v === null) return dflt;
    if (typeof v !== 'boolean') throw new FimValidationError(`${k} must be a boolean`);
    return v;
  };
  // Hive scoping (no 'removed' for unloaded user hives) only exists for HKEY_USERS\%\... patterns:
  // elsewhere it would only switch off removal / key-missing detection.
  const hkuWild = path.toUpperCase().startsWith('HKEY_USERS\\%\\');
  if (raw.hiveScoped === true && !hkuWild) throw new FimValidationError('hiveScoped is only valid for HKEY_USERS\\%\\... patterns');
  let entryKey: string;
  if (raw.entryKey === undefined || raw.entryKey === null || raw.entryKey === '') entryKey = customEntryKey(path);
  else if (isEntryKey(raw.entryKey)) entryKey = raw.entryKey;
  else throw new FimValidationError('entryKey must be a catalog id (reg.*) or custom:<16 hex>');
  // Visible-by-design only for catalog entries the catalog itself marks so (never elevatable by input).
  const cat = entryKey.startsWith('reg.') ? getRegCatalogEntry(entryKey) : undefined;
  const visibleByDesign = raw.visibleByDesign === true && !!cat && catalogVisibleByDesign(cat);
  return {
    ...(visibleByDesign ? { visibleByDesign: true } : {}),
    path,
    values,
    ignoreValues,
    excludeKeys,
    includeSubkeys: bool('includeSubkeys', values.length === 0),
    anchor: bool('anchor', true),
    hiveScoped: bool('hiveScoped', hkuWild),
    redactValues,
    entryKey,
    realtimeRequired: bool('realtimeRequired', false),
  };
}

const sortedLower = (l: string[] | undefined): string[] => [...new Set((l ?? []).map(asciiLower))].sort();

/**
 * Entry fingerprint (§3.5): everything that changes WHAT the scan returns. Severity, category
 * and label are not part of it, so changing them never needs a new slot or re-initialisation.
 * The entry key is included because it names the anchor rows, and the generated SQL itself is
 * hashed in, so any difference in the published query (whatever caused it) changes the
 * fingerprint.
 */
export function entryFingerprint(e: Partial<RegistryEntryV2> & { path: string }): string {
  let sql: string;
  try {
    sql = buildRegistryScanSqlV2({
      path: e.path, values: e.values ?? [], ignoreValues: e.ignoreValues ?? [], excludeKeys: e.excludeKeys ?? [], includeSubkeys: !!e.includeSubkeys,
      anchor: !!e.anchor, hiveScoped: !!e.hiveScoped, redactValues: e.redactValues ?? [], entryKey: e.entryKey ?? 'custom:0000000000000000', realtimeRequired: false, visibleByDesign: e.visibleByDesign === true,
    });
  } catch { sql = 'invalid'; }
  const parts = [sql,
    'registry',
    asciiLower(e.path),
    sortedLower(e.values).join('\u001f'),
    sortedLower(e.ignoreValues).join('\u001f'),
    [...new Set((e.excludeKeys ?? []).map(asciiLower))].sort().join('\u001f'),
    String(!!e.includeSubkeys),
    String(!!e.anchor),
    String(!!e.hiveScoped),
    sortedLower(e.redactValues).join('\u001f'),
    e.anchor ? String(e.entryKey ?? '') : '',
  ];
  return createHash('sha256').update(parts.join('\u001e'), 'utf8').digest('hex');
}

/** Item key the worker gives the anchor row of `key` for entry `entryKey`. */
export const anchorItemPath = (key: string, entryKey: string): string => `registry|${key}\\<anchor:${entryKey}>`;

/**
 * Scan SQL for a registry v2 entry (§3.6). Same text for scheduled scans and Initialize.
 *   main rows: values (allow-list / deny-list, ASCII-lower names) and, if includeSubkeys,
 *              subkey rows (direct children); HKEY_USERS entries skip the S-1-5-18 alias;
 *              redactValues are replaced ON THE HOST by 'REDACTED(len=N)';
 *   anchor:    one row per existing monitored key, named <key>\<anchor:<entryKey>>, so a key
 *              that becomes empty or is deleted is visible and an empty-but-existing key is
 *              not mistaken for a failed scan. Entry-specific names keep anchors of overlapping
 *              entries from colliding.
 * Exclusions use ESCAPE '^' (evaluated by SQLite) so '_' cannot widen them.
 */
export function buildRegistryScanSqlV2(entry: RegistryEntryV2): string {
  const err = validateRegistryKeyV2(entry.path, { allowRecursive: true, maxWildcards: REG_LIMITS.maxWildcards + 1 });
  if (err) throw new FimValidationError(err);
  if (!isEntryKey(entry.entryKey)) throw new FimValidationError('invalid entry key');
  const path = canonicalRegistryKey(entry.path);
  const isHku = path.toUpperCase().startsWith('HKEY_USERS\\');
  for (const lst of [entry.values, entry.ignoreValues, entry.redactValues]) {
    for (const n of lst) { const e = validateValueName(n); if (e) throw new FimValidationError(e); }
  }
  const excl = entry.excludeKeys.map((x) => {
    const e = validateRegistryKeyV2(x, { exclusion: true });
    if (e) throw new FimValidationError(e);
    return sqlString(escapeLikeCaret(x));
  });
  const values = [...new Set(entry.values.map(asciiLower))];
  const ignore = [...new Set(entry.ignoreValues.map(asciiLower))];
  // Spec v3: only visible-by-design catalog entries (commands) skip the credential-name rules.
  const untrusted = entry.visibleByDesign !== true;
  const redact = [...new Set([...entry.redactValues, ...(untrusted ? MANDATORY_REDACT_VALUES : [])].map(asciiLower))].sort();

  // Secret-like heuristic only for custom entries (they can point at any application's settings).
  const dataCol = redactedDataCol(redact, untrusted);
  const conds = [`key LIKE ${sqlString(path)}`];
  if (isHku) conds.push(`key NOT LIKE ${sqlString(LOCAL_SYSTEM_EXCLUSION)}`);
  for (const x of excl) conds.push(`key NOT LIKE ${x} ESCAPE '^'`);
  if (values.length) conds.push(`(lower(name) IN (${sqlList(values)})${entry.includeSubkeys ? " OR type = 'subkey'" : ''})`);
  else if (!entry.includeSubkeys) conds.push("type <> 'subkey'");
  if (ignore.length) conds.push(`lower(name) NOT IN (${sqlList(ignore)})`);
  let sql = `SELECT path, name, type, ${dataCol} FROM registry WHERE ${conds.join(' AND ')}`;

  if (entry.anchor) {
    const segs = path.split('\\');
    const last = segs[segs.length - 1];
    const parent = segs.slice(0, -1).join('\\');
    const a = [`key LIKE ${sqlString(parent)}`, "type = 'subkey'"];
    if (!isWild(last)) a.push(`lower(name) = ${sqlString(asciiLower(last))}`);
    if (isHku) a.push(`path NOT LIKE ${sqlString(LOCAL_SYSTEM_EXCLUSION)}`);
    for (const x of excl) a.push(`path NOT LIKE ${x} ESCAPE '^'`);
    sql += ` UNION ALL SELECT path || ${sqlString(`\\<anchor:${entry.entryKey}>`)} AS path, name, 'anchor' AS type, '' AS data FROM registry WHERE ${a.join(' AND ')}`;
  }
  if (isHku && entry.hiveScoped) {
    // Loaded user hives (presence markers, never stored as items): lets the worker tell "hive not
    // loaded" (no 'removed') from "hive loaded but the key/values were deleted" ('removed').
    // UNVERIFIED on a Windows agent: osquery enumerating the subkeys of the HKEY_USERS root.
    sql += ` UNION ALL SELECT ${sqlString('HKEY_USERS\\')} || name || ${sqlString('\\<hive>')} AS path, name, 'hive' AS type, '' AS data FROM registry WHERE key LIKE ${sqlString('HKEY_USERS')} AND type = 'subkey' AND name NOT LIKE ${sqlString('S-1-5-18')} AND name NOT LIKE ${sqlString('%^_Classes')} ESCAPE '^'`;
  }
  assertRegistrySqlShape(sql);
  return sql;
}

const SHAPE_TOKENS = /^(?:\s+|SELECT|FROM|WHERE|AND|OR|NOT|LIKE|ESCAPE|IN|UNION|ALL|CASE|WHEN|THEN|ELSE|END|AS|registry|path|name|type|data|key|lower|length|substr|sha256|1|16|GLOB|\?|\|\||[(),=]|<>)+$/;

/** Post-build check: fixed token shape (after removing literals) and a 16 KiB cap. */
export function assertRegistrySqlShape(sql: string): void {
  if (sql.length > REG_LIMITS.sqlMaxBytes) throw new FimValidationError(`generated registry SQL exceeds ${REG_LIMITS.sqlMaxBytes} bytes; narrow the entry`);
  if (!sql.startsWith('SELECT path, name, type, ') || !sql.includes(' FROM registry WHERE key LIKE ')) {
    throw new FimValidationError('generated registry SQL has an unexpected shape');
  }
  const stripped = sql.replace(/'[^']*'/g, '?');
  if (stripped.includes("'") || !SHAPE_TOKENS.test(stripped)) throw new FimValidationError('generated registry SQL has an unexpected shape');
}

/** data column with host-side redaction: listed names (mandatory + entry) and secret-like names. */
/**
 * Redacted data column (spec v2, identical in the worker: FimCore registry_redact).
 *  - Catalog / protected entries (`trusted`) redact ONLY their own redactValues (known credential
 *    locations such as Winlogon DefaultPassword). An attacker-chosen value name under Run, IFEO,
 *    Services ... ("Password", "Pwd", "Secret") is a command, never hidden.
 *  - Custom and legacy entries (untrusted: they can point at any application's settings) also
 *    redact the mandatory names, secret-like names (substrings) and every name containing a
 *    character outside printable ASCII (host-side lower() is ASCII-only, so localized names such
 *    as Kennwort-with-umlaut or Cyrillic/CJK cannot be matched by substring), minus `exempt`.
 * The marker always carries a short digest so an equal-length change stays visible:
 *   REDACTED(len=N,sha256=<first 16 hex of sha256(data)>) (characters / bytes up to the first NUL).
 * A short unsalted digest of a low-entropy secret can be brute-forced offline by someone who can
 * read the drift tables (documented trade-off for detecting same-length changes).
 */
function redactedDataCol(redact: string[], untrusted: boolean): string {
  const fixed = redact.length ? `lower(name) IN (${sqlList(redact)})` : '';
  const like = SECRET_LIKE_SUBSTRINGS.map((x) => `lower(name) LIKE ${sqlString(`%${x}%`)}`).join(' OR ');
  const heur = untrusted ? `((${like} OR name GLOB '*[^ -~]*') AND lower(name) NOT IN (${sqlList(FIM_REDACT_EXEMPT)}))` : '';
  const cond = [fixed, heur].filter(Boolean).join(' OR ');
  if (!cond) return 'data';
  return `CASE WHEN type <> 'subkey' AND (${cond}) THEN 'REDACTED(len=' || length(data) || ',sha256=' || substr(sha256(data), 1, 16) || ')' ELSE data END AS data`;
}

/**
 * Scan SQL for an already-stored LEGACY registry entry (no v2 fields). Its filter stays exactly
 * as before so existing baselines remain valid; only the mandatory credential redaction is added
 * (rows with those names change once, to their redacted form). New registry entries are always v2.
 */
export function buildLegacyRegistrySql(path: string): string {
  const err = validateRegistryKeyV2(path, { allowRecursive: true });
  if (err) throw new FimValidationError(err);
  const sql = `SELECT path, name, type, ${redactedDataCol([...new Set(MANDATORY_REDACT_VALUES.map(asciiLower))].sort(), true)} FROM registry WHERE key LIKE ${sqlString(path)}`;
  assertRegistrySqlShape(sql);
  return sql;
}
