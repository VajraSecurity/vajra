/**
 * Client-side mirror of the registry input rules (docs/FIM_REGISTRY_DESIGN.md §4.2). For UX only:
 * the server is authoritative and its 4xx message is always shown verbatim.
 */

import { INVISIBLE_CHAR_RX, codePointLabel } from './safeText';

const CONTROL_RX = /\p{Cc}/u;
/** Printable ASCII only (U+0020-U+007E) for key patterns and value names (server rule). */
const NON_PRINTABLE_ASCII_RX = /[^\u0020-\u007e]/u;

const REFUSED_HIVES: Record<string, string> = {
  HKEY_CURRENT_USER: 'HKEY_CURRENT_USER is refused: osqueryd runs as SYSTEM, so it is not the interactive user. Use HKEY_USERS\\%\\... instead.',
  HKEY_CLASSES_ROOT: 'HKEY_CLASSES_ROOT is refused (it is a merged view). Use HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\... or HKEY_USERS\\%\\SOFTWARE\\Classes\\...',
  HKEY_CURRENT_CONFIG: 'HKEY_CURRENT_CONFIG is refused (real-time never reports it).',
  HKCU: 'Abbreviations are not accepted. HKEY_CURRENT_USER is refused anyway: use HKEY_USERS\\%\\...',
  HKCR: 'Abbreviations are not accepted. HKEY_CLASSES_ROOT is refused anyway.',
  HKCC: 'Abbreviations are not accepted. HKEY_CURRENT_CONFIG is refused anyway.',
  HKLM: 'Write the hive in full: HKEY_LOCAL_MACHINE\\',
  HKU: 'Write the hive in full: HKEY_USERS\\',
};

const LSA_SECRETS = new Set(['DATA', 'JD', 'SKEW1', 'GBG']);

/** `isValueName`: value names may contain '/' (key patterns may not). */
function charError(s: string, what: string, isValueName: boolean): string | null {
  if (s.includes("'")) return `${what} must not contain a single quote (')`;
  const ctl = CONTROL_RX.exec(s);
  if (ctl) return `${what} must not contain NUL or control characters (found ${codePointLabel(ctl[0])})`;
  const inv = INVISIBLE_CHAR_RX.exec(s);
  if (inv) return `${what} must not contain bidi-control, zero-width, format, filler or tag characters (found ${codePointLabel(inv[0])})`;
  const na = NON_PRINTABLE_ASCII_RX.exec(s);
  if (na) return `${what} must be printable ASCII only (U+0020-U+007E; found ${codePointLabel(na[0])})`;
  if (isValueName ? /[*?]/.test(s) : /[*?/]/.test(s)) return `${what} must not contain '*', '?'${isValueName ? '' : " or '/'; use a whole % segment for one level"}`;
  return null;
}

export interface KeyRuleOptions {
  /** '%%' (recursive) is only allowed for Super Admins (and catalog entries). */
  allowRecursive: boolean;
  /** Label used in messages. */
  what?: string;
}

/** Validates a registry key pattern (entry path or excludeKey). Returns an error message or null. */
export function validateRegKeyPattern(raw: string, opts: KeyRuleOptions): string | null {
  const what = opts.what ?? 'Registry key';
  if (raw.length === 0) return `${what} is required`;
  if (raw.length < 3 || raw.length > 512) return `${what} must be 3-512 characters`;
  const ce = charError(raw, what, false);
  if (ce) return ce;
  const segs = raw.split('\\');
  const hive = segs[0].toUpperCase();
  if (REFUSED_HIVES[hive]) return REFUSED_HIVES[hive];
  if (hive !== 'HKEY_LOCAL_MACHINE' && hive !== 'HKEY_USERS') return `${what} must start with HKEY_LOCAL_MACHINE\\ or HKEY_USERS\\`;
  if (segs.length < 2 || raw.endsWith('\\')) return `${what} must not end with '\\' and must name a key below the hive`;
  if (segs.length > 32) return `${what} must have at most 32 segments`;
  for (const s of segs) {
    if (s === '') return `${what} must not contain an empty segment ('\\\\')`;
    if (s !== s.trim()) return `Segment "${s}" must not start or end with a space`;
    if (s.includes('%') && s !== '%' && s !== '%%') return `'%' must be a whole segment (found "${s}"); prefix patterns such as Run% are refused because they also match look-alike keys`;
  }
  const wild = segs.filter((s) => s === '%' || s === '%%').length;
  if (wild > 3) return `At most 3 '%' segments are allowed`;
  const rec = segs.indexOf('%%');
  if (rec !== -1) {
    if (rec !== segs.length - 1) return `'%%' is only allowed as the last segment`;
    if (!opts.allowRecursive) return `'%%' (recursive) is only allowed for Super Admins`;
    const literalsBefore = segs.slice(1, rec).filter((s) => s !== '%').length;
    if (literalsBefore < 3) return `'%%' needs at least 3 literal key names before it`;
  }
  const up = segs.map((s) => s.toUpperCase());
  if (hive === 'HKEY_LOCAL_MACHINE') {
    if (up[1] === '%') return 'The first key below HKEY_LOCAL_MACHINE must be literal (e.g. SOFTWARE or SYSTEM)';
    if (up[1] === 'SAM' || up[1] === 'SECURITY') return 'HKEY_LOCAL_MACHINE\\SAM and \\SECURITY hold credential material and are refused';
    if (up[1] === 'SYSTEM' && up[3] === 'CONTROL' && up[4] === 'LSA' && up[5] && LSA_SECRETS.has(up[5])) {
      return 'Lsa\\Data, JD, Skew1 and GBG (boot-key material) are refused';
    }
  } else {
    if (up[2] === 'VOLATILE ENVIRONMENT') return 'HKEY_USERS\\%\\Volatile Environment is refused (rewritten at every logon)';
    if (up[1] === '%') {
      const literalsAfter = segs.slice(2).filter((s) => s !== '%' && s !== '%%').length;
      if (literalsAfter < 2) return 'After HKEY_USERS\\% at least 2 literal key names are required';
    }
  }
  return null;
}

/** Validates one value name (values / ignoreValues). */
export function validateValueName(raw: string): string | null {
  if (raw.length < 1 || raw.length > 255) return 'Value names must be 1-255 characters';
  return charError(raw, 'Value name', true);
}

/** Validates a list of value names with a maximum count. */
export function validateValueList(list: string[], max: number, label: string): string | null {
  if (list.length > max) return `At most ${max} ${label}`;
  const seen = new Set<string>();
  for (const v of list) {
    const e = validateValueName(v);
    if (e) return `${label}: "${v}": ${e}`;
    const k = v.toLowerCase();
    if (seen.has(k)) return `${label}: "${v}" is listed twice (names are case-insensitive)`;
    seen.add(k);
  }
  return null;
}

/**
 * True when the exclusion pattern selects a strict subset of what the entry pattern covers: a key
 * below it, or a specific child where the entry has '%' (e.g. Services\% minus Services\Foo).
 * Segment-wise: '%' in the entry matches anything; '%' in the exclusion only matches '%'.
 */
export function excludeInside(entryPath: string, exclude: string): boolean {
  const a = entryPath.split('\\').map((s) => s.toLowerCase());
  const b = exclude.split('\\').map((s) => s.toLowerCase());
  const rec = a[a.length - 1] === '%%';
  const base = rec ? a.slice(0, -1) : a;
  if (b.length < base.length || (rec && b.length === base.length)) return false;
  const prefixOk = base.every((s, i) => s === '%' || s === b[i]);
  if (!prefixOk) return false;
  if (rec || b.length > base.length) return true;
  return base.some((s, i) => s === '%' && b[i] !== '%');
}

/** Validates excludeKeys for an entry. */
export function validateExcludeKeys(list: string[], entryPath: string, max: number, allowRecursive: boolean): string | null {
  if (list.length > max) return `At most ${max} excluded subkeys`;
  for (const k of list) {
    const e = validateRegKeyPattern(k, { allowRecursive, what: 'Excluded subkey' });
    if (e) return `"${k}": ${e}`;
    if (entryPath && !excludeInside(entryPath, k)) return `"${k}" is not inside the entry's key pattern (an exclusion that matches nothing is refused as a probable typo)`;
  }
  return null;
}

/**
 * Whether two key patterns can match a common key (segment by segment: '%' matches one segment, a
 * trailing '%%' any suffix, literals compare case-insensitively). Used for an overlap warning only;
 * the server's resolver decides (identical patterns are merged, other overlaps fail resolution).
 */
export function patternsIntersect(a: string, b: string): boolean {
  const x = a.split('\\').map((s) => s.toLowerCase());
  const y = b.split('\\').map((s) => s.toLowerCase());
  const xr = x[x.length - 1] === '%%';
  const yr = y[y.length - 1] === '%%';
  const xs = xr ? x.slice(0, -1) : x;
  const ys = yr ? y.slice(0, -1) : y;
  const n = Math.min(xs.length, ys.length);
  for (let i = 0; i < n; i++) if (xs[i] !== ys[i] && xs[i] !== '%' && ys[i] !== '%') return false;
  if (xs.length === ys.length) return true;
  return xs.length < ys.length ? xr : yr;
}
