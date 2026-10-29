/**
 * Date formatting/parsing shared by the Sebi/CertIn/IRDAI compliance views —
 * was copy-pasted verbatim across all 3 files.
 */

export function fmtDateTime(unixtime: number) {
  return new Date(unixtime * 1000).toLocaleString('en-IN');
}

export function fmtDate(unixtime: number) {
  return new Date(unixtime * 1000).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' });
}

export function fmtTime(unixtime: number) {
  return new Date(unixtime * 1000).toLocaleTimeString('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
  });
}

// Parses the en-IN locale timestamp produced by backend (e.g. "15/5/2026, 10:30:00 am")
// Returns unix seconds, or null if the string cannot be parsed.
export function parseEnInTimestamp(s: string): number | null {
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),\s*(\d{1,2}):(\d{2}):(\d{2})(?:\s*(am|pm))?/i);
  if (!m) return null;
  const [, dd, mm, yyyy, hRaw, min, sec, ampm] = m;
  let h = parseInt(hRaw, 10);
  if (ampm) {
    if (ampm.toLowerCase() === 'pm' && h < 12) h += 12;
    if (ampm.toLowerCase() === 'am' && h === 12) h = 0;
  }
  const d = new Date(parseInt(yyyy, 10), parseInt(mm, 10) - 1, parseInt(dd, 10), h, parseInt(min, 10), parseInt(sec, 10));
  return Number.isFinite(d.getTime()) ? Math.floor(d.getTime() / 1000) : null;
}

/**
 * Age thresholds (in days) used to decide how loudly a stored compliance
 * snapshot should be flagged as stale. A month-old score must not render the
 * same way a fresh one does.
 */
export const SNAPSHOT_STALE_AFTER_DAYS = 7;
export const SNAPSHOT_EXPIRED_AFTER_DAYS = 30;

export type SnapshotAgeTone = 'fresh' | 'stale' | 'expired';

/**
 * Human-readable age of a unix-seconds timestamp, e.g. "30 days ago".
 * Returns null when the timestamp is missing or unusable — callers must render
 * an em dash for that case rather than an invented "just now".
 */
export function fmtRelative(unixtime: number | null | undefined, nowMs: number = Date.now()): string | null {
  if (unixtime == null || !Number.isFinite(Number(unixtime))) return null;
  const thenMs = Number(unixtime) * 1000;
  const diffMs = nowMs - thenMs;
  if (!Number.isFinite(diffMs)) return null;

  const future = diffMs < 0;
  const abs = Math.abs(diffMs);
  const minutes = Math.floor(abs / 60_000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  let phrase: string;
  if (minutes < 1) phrase = 'just now';
  else if (minutes < 60) phrase = `${minutes} minute${minutes === 1 ? '' : 's'}`;
  else if (hours < 24) phrase = `${hours} hour${hours === 1 ? '' : 's'}`;
  else if (days < 31) phrase = `${days} day${days === 1 ? '' : 's'}`;
  else {
    const months = Math.floor(days / 30);
    phrase = `${months} month${months === 1 ? '' : 's'}`;
  }

  if (phrase === 'just now') return phrase;
  return future ? `in ${phrase}` : `${phrase} ago`;
}

/** How stale a snapshot is, for colouring the recency pill. */
export function snapshotAgeTone(unixtime: number | null | undefined, nowMs: number = Date.now()): SnapshotAgeTone | null {
  if (unixtime == null || !Number.isFinite(Number(unixtime))) return null;
  const days = (nowMs - Number(unixtime) * 1000) / 86_400_000;
  if (days > SNAPSHOT_EXPIRED_AFTER_DAYS) return 'expired';
  if (days > SNAPSHOT_STALE_AFTER_DAYS) return 'stale';
  return 'fresh';
}

/** Tailwind classes for a recency pill at the given tone. */
export function snapshotAgeToneClasses(tone: SnapshotAgeTone | null): string {
  if (tone === 'expired') return 'bg-red-50 border-red-200 text-red-700';
  if (tone === 'stale') return 'bg-amber-50 border-amber-200 text-amber-800';
  if (tone === 'fresh') return 'bg-emerald-50 border-emerald-200 text-emerald-700';
  return 'bg-slate-50 border-slate-200 text-slate-600';
}
