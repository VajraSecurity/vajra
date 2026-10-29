/**
 * Parse comma-separated IPv4 specs: single hosts, CIDR, same-/24 ranges, or last-octet shortcuts (10.0.0.1-50).
 */

export type ParseIpInputResult =
  | { ok: true; tokens: string[] }
  | { ok: false; error: string };

/** Max IPv4 addresses produced from a single range token (same-/24 or last-octet shortcut). */
export const MAX_IP_RANGE_EXPAND_PER_SEGMENT = 1024;

function parseIPv4Quad(s: string): [number, number, number, number] | null {
  const parts = s.trim().split('.');
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = parseInt(p, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) return null;
    nums.push(n);
  }
  return [nums[0], nums[1], nums[2], nums[3]];
}

function formatIPv4(q: [number, number, number, number]): string {
  return `${q[0]}.${q[1]}.${q[2]}.${q[3]}`;
}

function parseOneToken(raw: string): { ok: true; tokens: string[] } | { ok: false; error: string } {
  const t = raw.trim();
  if (!t) return { ok: false, error: 'Empty entry.' };

  if (t.includes('/')) {
    const m = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,2})$/);
    if (!m) return { ok: false, error: `Invalid CIDR: "${raw}"` };
    const base = parseIPv4Quad(m[1]);
    if (!base) return { ok: false, error: `Invalid IP in CIDR: "${raw}"` };
    const pref = parseInt(m[2], 10);
    if (!Number.isFinite(pref) || pref < 0 || pref > 32) {
      return { ok: false, error: `Invalid prefix (0–32) in "${raw}"` };
    }
    return { ok: true, tokens: [`${formatIPv4(base)}/${pref}`] };
  }

  const fullRange = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (fullRange) {
    const a = parseIPv4Quad(fullRange[1]);
    const b = parseIPv4Quad(fullRange[2]);
    if (!a || !b) return { ok: false, error: `Invalid IP range: "${raw}"` };
    if (a[0] !== b[0] || a[1] !== b[1] || a[2] !== b[2]) {
      return {
        ok: false,
        error: `Range must share the same first three octets (e.g. 10.0.0.1-10.0.0.50): "${raw}"`,
      };
    }
    let lo = a[3];
    let hi = b[3];
    if (lo > hi) [lo, hi] = [hi, lo];
    const span = hi - lo + 1;
    if (span > MAX_IP_RANGE_EXPAND_PER_SEGMENT) {
      return {
        ok: false,
        error: `Range spans ${span} addresses (max ${MAX_IP_RANGE_EXPAND_PER_SEGMENT} per entry): "${raw}"`,
      };
    }
    const out: string[] = [];
    for (let x = lo; x <= hi; x++) out.push(formatIPv4([a[0], a[1], a[2], x]));
    return { ok: true, tokens: out };
  }

  const shortRange = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})\s*-\s*(\d{1,3})$/);
  if (shortRange) {
    const first = parseIPv4Quad(shortRange[1] + shortRange[2]);
    if (!first) return { ok: false, error: `Invalid IP in "${raw}"` };
    let lo = parseInt(shortRange[2], 10);
    let hi = parseInt(shortRange[3], 10);
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return { ok: false, error: `Invalid range: "${raw}"` };
    if (lo < 0 || lo > 255 || hi < 0 || hi > 255) {
      return { ok: false, error: `Octet out of range in "${raw}"` };
    }
    if (lo > hi) [lo, hi] = [hi, lo];
    const span = hi - lo + 1;
    if (span > MAX_IP_RANGE_EXPAND_PER_SEGMENT) {
      return {
        ok: false,
        error: `Range spans ${span} addresses (max ${MAX_IP_RANGE_EXPAND_PER_SEGMENT} per entry): "${raw}"`,
      };
    }
    const out: string[] = [];
    for (let x = lo; x <= hi; x++) out.push(formatIPv4([first[0], first[1], first[2], x]));
    return { ok: true, tokens: out };
  }

  const ip = parseIPv4Quad(t);
  if (!ip) {
    return {
      ok: false,
      error: `Unrecognized "${raw}". Examples: 192.168.1.1, 10.0.0.0/24, 10.0.0.1-10.0.0.50, 10.0.0.1-20`,
    };
  }
  return { ok: true, tokens: [formatIPv4(ip)] };
}

export function parseIpInput(raw: string): ParseIpInputResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: 'Enter at least one IP, range, or CIDR.' };
  }

  const parts = trimmed
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    return { ok: false, error: 'Enter at least one IP, range, or CIDR.' };
  }

  const tokens: string[] = [];
  const seen = new Set<string>();
  for (const part of parts) {
    const r = parseOneToken(part);
    if (!r.ok) return r;
    for (const tok of r.tokens) {
      if (!seen.has(tok)) {
        seen.add(tok);
        tokens.push(tok);
      }
    }
  }

  return { ok: true, tokens };
}
