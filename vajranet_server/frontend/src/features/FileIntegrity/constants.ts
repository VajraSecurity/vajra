import type { FimChangeType, FimOsPlatform, FimSeverity, FimMode } from '../../api/services/fimApi';
import { INVISIBLE_CHAR_RX } from './safeText';

export const SEVERITIES: FimSeverity[] = ['critical', 'high', 'medium', 'low'];
export const CHANGE_TYPES: FimChangeType[] = ['added', 'removed', 'modified', 'attributes'];

export const SEVERITY_COLOR: Record<FimSeverity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#64748b',
};

export const CHANGE_LABEL: Record<FimChangeType, { label: string; color: string; hint: string }> = {
  added: { label: 'Added', color: '#2563eb', hint: 'A new file appeared that is not in the baseline' },
  removed: { label: 'Removed', color: '#7c3aed', hint: 'A baselined file is gone' },
  modified: { label: 'Modified', color: '#dc2626', hint: 'File content (hash) changed' },
  attributes: { label: 'Attributes', color: '#0d9488', hint: 'Permissions, owner or timestamps changed; content unchanged' },
};

/**
 * Policy target types sent to the backend. FIM_DESIGN.md says targets are
 * [{type,value}] without naming the vocabulary; these are the values this UI
 * emits. Contract question for the backend owner.
 */
export const TARGET_TYPES = { all: 'all', group: 'group', node: 'node' } as const;

export const MODE_HELP: Record<FimMode, string> = {
  learn: 'Report only: changes from the baseline are listed as drift but never raise alerts. The baseline never changes by itself.',
  enforce: 'Alert on changes: any change from the baseline is listed as drift and raises an alert. The baseline never changes by itself.',
};

export const MODE_LABEL: Record<FimMode, string> = { learn: 'Report only (no alerts)', enforce: 'Alert on changes' };

/** Shown wherever baselines are explained: hosts are not monitored until initialised. */
export const BASELINE_RULE = "Baselines never change automatically - only when you click 'Initialize baseline' or approve a drift. A host with no baseline is not monitored.";

export const INTERVAL_OPTIONS: { value: number; label: string }[] = [
  { value: 300, label: 'Every 5 minutes' },
  { value: 900, label: 'Every 15 minutes' },
  { value: 1800, label: 'Every 30 minutes' },
  { value: 3600, label: 'Every hour' },
  { value: 21600, label: 'Every 6 hours' },
  { value: 43200, label: 'Every 12 hours' },
  { value: 86400, label: 'Every day' },
  { value: 604800, label: 'Every week' },
];

export function humanInterval(secs: number): string {
  const known = INTERVAL_OPTIONS.find((o) => o.value === secs);
  if (known) return known.label;
  if (secs % 86400 === 0) return `Every ${secs / 86400} days`;
  if (secs % 3600 === 0) return `Every ${secs / 3600} hours`;
  if (secs % 60 === 0) return `Every ${secs / 60} minutes`;
  return `Every ${secs}s`;
}

/** Mirrors the backend path rules in FIM_DESIGN.md. Returns an error message or null. */
export function validatePath(raw: string, os: FimOsPlatform): string | null {
  if (raw.trim() === '') return 'Path is required';
  if (raw.length > 1024) return 'Path must be at most 1024 characters';
  if (raw.includes("'")) return "Path must not contain a single quote (')";
  if (raw.includes('\0')) return 'Path must not contain NUL characters';
  if (INVISIBLE_CHAR_RX.test(raw)) return 'Path must not contain control, invisible, bidi-control or format characters';
  if (os === 'linux' && !raw.startsWith('/')) return "Linux paths must start with '/'";
  if (os === 'windows' && !/^([A-Za-z]:|\*)/.test(raw)) return "Windows paths must start with a drive letter (C:\\) or '*'";
  if (os === 'linux' && /[*?]/.test(raw)) return "Linux paths do not support '*' or '?'; use '%' (one level) or '%%' (recursive)";
  if (!hasRealDirectoryPrefix(raw, os)) return 'Path must name a real directory before the first wildcard (e.g. /etc/%% or C:\\Windows\\*)';
  return null;
}

/** True when the literal prefix before the first wildcard has at least one non-root segment. */
function hasRealDirectoryPrefix(raw: string, os: FimOsPlatform): boolean {
  const idx = raw.search(os === 'windows' ? /[%*]/ : /%/);
  let prefix = idx === -1 ? raw : raw.slice(0, idx);
  if (os === 'windows') prefix = prefix.replace(/^[A-Za-z]:[\\/]*/, '');
  return prefix.split(os === 'windows' ? /[\\/]/ : '/').some((seg) => seg !== '');
}

/** Mirrors the backend registry-key rules. */
export function validateRegistryKey(raw: string): string | null {
  if (raw.trim() === '') return 'Registry key is required';
  if (raw.length > 1024) return 'Registry key must be at most 1024 characters';
  if (raw.includes("'")) return 'Registry key must not contain a single quote';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(raw)) return 'Registry key must not contain control characters';
  if (INVISIBLE_CHAR_RX.test(raw)) return 'Registry key must not contain invisible, bidi-control or format characters';
  if (/[*?/]/.test(raw)) return "Registry key must not contain '*', '?' or '/'; use % (one level) or %% (recursive)";
  const m = /^HKEY_(LOCAL_MACHINE|USERS|CLASSES_ROOT|CURRENT_USER|CURRENT_CONFIG)(?:\\|$)/.exec(raw);
  if (!m) return 'Registry key must start with a hive such as HKEY_LOCAL_MACHINE\\ or HKEY_USERS\\';
  const rest = raw.slice(m[0].length);
  if (rest.includes('%%')) {
    if (!rest.slice(0, rest.search(/%/)).split('\\').some((s) => s !== '')) return "Name a real key below the hive before a '%%' wildcard";
  } else if (!rest.split('\\').some((s) => s !== '' && !s.includes('%'))) {
    return 'Registry key must contain at least one literal key name below the hive';
  }
  return null;
}

/** NTFS ACL entries are read for exact paths only. */
export function validateAclPath(raw: string): string | null {
  const e = validatePath(raw, 'windows');
  if (e) return e;
  if (!/^[A-Za-z]:[\\/]/.test(raw)) return 'ACL paths must start with a drive letter (e.g. C:\\Windows)';
  if (/[%*?]/.test(raw)) return 'ACL paths must be exact (no wildcards)';
  return null;
}

/** Validation of one policy entry, mirroring the backend per kind. */
export function entryError(e: { kind?: string; path?: string; source?: string }, os: FimOsPlatform): string | null {
  const kind = e.kind ?? 'path';
  if (kind === 'table') return e.source ? null : 'Choose a configuration source';
  if (kind === 'xattr') return os !== 'linux' ? 'Extended attributes are Linux-only' : validatePath(e.path ?? '', 'linux');
  if (kind === 'registry') return os !== 'windows' ? 'Registry entries are Windows-only' : validateRegistryKey(e.path ?? '');
  if (kind === 'acl') return os !== 'windows' ? 'NTFS ACL entries are Windows-only' : validateAclPath(e.path ?? '');
  return validatePath(e.path ?? '', os);
}

export const KIND_LABEL: Record<string, string> = {
  path: 'Files & directories', xattr: 'Extended attributes & ACLs', registry: 'Registry keys', acl: 'NTFS ACLs', table: 'System configuration',
  file: 'File', directory: 'Directory', item: 'Config item',
};

export function fmtTime(secs: number | null | undefined): string {
  if (!secs) return '-';
  return new Date(secs * 1000).toLocaleString();
}

export function shortHash(h: string | null | undefined): string {
  return h ? `${h.slice(0, 12)}...` : '-';
}

export function normalizeAttrs(a: Record<string, unknown> | string | null | undefined): Record<string, unknown> {
  if (!a) return {};
  if (typeof a === 'string') {
    try {
      const p = JSON.parse(a);
      return p && typeof p === 'object' ? (p as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }
  return a;
}

export function errStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } })?.response?.status;
}

export const HISTORY_KEY_MISSING_TEXT = 'Registry changes are disabled on the server: FIM_HISTORY_HMAC_KEY is missing or too short. Nothing was changed. An administrator must set the key (at least 32 characters) on the backend and restart it.';

/** The server's 503 for registry writes while the history key is missing: errors[0] === 'history_key_missing'. */
export function historyKeyMissing(err: unknown): boolean {
  const r = (err as { response?: { status?: number; data?: { errors?: unknown } } })?.response;
  return r?.status === 503 && Array.isArray(r.data?.errors) && r.data.errors[0] === 'history_key_missing';
}

export function errMsg(err: unknown, fallback: string): string {
  if (historyKeyMissing(err)) return HISTORY_KEY_MISSING_TEXT;
  const e = err as { response?: { data?: { message?: string; error?: string } }; message?: string };
  return e?.response?.data?.message ?? e?.response?.data?.error ?? e?.message ?? fallback;
}

export function blankEntry(kind: import('../../api/services/fimApi').FimEntryKind): import('../../api/services/fimApi').FimPolicyPath {
  return { kind, path: '', severity: kind === 'path' ? 'medium' : 'high', category: '', ignore: [], hash: kind === 'path' };
}

/**
 * Entry index named by a server error about a policy entry, e.g. "paths[3]: ..." (policy
 * validation) or "entry 3" / "entry #3"; null when the message names no entry.
 */
export function entryIndexFromError(message: unknown): number | null {
  if (typeof message !== 'string') return null;
  const m = /\bpaths\[(\d{1,4})\]/.exec(message) ?? /\bentry\s*#?\s*(\d{1,4})\b/i.exec(message);
  return m ? Number(m[1]) : null;
}

/** A problem reported for one policy entry (by index), with the entry's path when known. */
export interface EntryProblem { index: number; path?: string | null; error: string }

/** Policy-entry identity used to match a problem to an entry (path, or source for system configuration entries). */
export const entryKeyOf = (p: { path?: string; source?: string } | undefined) => (p ? String(p.path ?? p.source ?? '') : '');

/** The problem for entry `i`, if it still refers to the entry at that index (removing / editing the entry clears the mark). */
export const problemFor = (problems: EntryProblem[] | undefined, paths: { path?: string; source?: string }[], i: number) =>
  (problems ?? []).find((x) => x.index === i && i < paths.length && (!x.path || entryKeyOf(paths[i]).slice(0, 300) === x.path.slice(0, 300)));
