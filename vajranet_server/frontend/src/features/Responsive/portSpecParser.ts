/**
 * Parse comma-separated port specs: single ports, ranges with "-" or ":" (e.g. 1-100, 10000:50000).
 * Returns normalized tokens using ":" for ranges (matches agent / single-node port control).
 */

export type ParsePortInputResult =
  | { ok: true; tokens: string[] }
  | { ok: false; error: string };

function normalizeToken(part: string): { ok: true; value: string } | { ok: false; error: string } {
  const p = part.trim();
  if (!p) return { ok: false, error: 'Empty port entry.' };

  const rangeMatch = p.match(/^(\d+)\s*[-:]\s*(\d+)$/);
  if (rangeMatch) {
    let a = parseInt(rangeMatch[1], 10);
    let b = parseInt(rangeMatch[2], 10);
    if (a > b) [a, b] = [b, a];
    if (!Number.isFinite(a) || !Number.isFinite(b) || a < 0 || b > 65535) {
      return { ok: false, error: `Port range out of bounds (0–65535): "${part}"` };
    }
    return { ok: true, value: `${a}:${b}` };
  }

  if (/^\d+$/.test(p)) {
    const n = parseInt(p, 10);
    if (!Number.isFinite(n) || n < 0 || n > 65535) {
      return { ok: false, error: `Invalid port "${part}" (use 0–65535).` };
    }
    return { ok: true, value: String(n) };
  }

  return {
    ok: false,
    error: `Unrecognized "${part}". Examples: 443, 1-100, 10000:50000, 256,8888`,
  };
}

export function parsePortInput(raw: string): ParsePortInputResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: 'Enter at least one port or range.' };
  }

  const parts = trimmed
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (parts.length === 0) {
    return { ok: false, error: 'Enter at least one port or range.' };
  }

  const tokens: string[] = [];
  const seen = new Set<string>();

  for (const part of parts) {
    const n = normalizeToken(part);
    if (!n.ok) return n;
    if (!seen.has(n.value)) {
      seen.add(n.value);
      tokens.push(n.value);
    }
  }

  return { ok: true, tokens };
}

/**
 * Expand port ranges (e.g., "5555:5560") into individual ports.
 * Single ports are returned as-is.
 */
export function expandPortRanges(tokens: string[]): string[] {
  const expanded: string[] = [];

  for (const token of tokens) {
    const rangeMatch = token.match(/^(\d+):(\d+)$/);
    if (rangeMatch) {
      const start = parseInt(rangeMatch[1], 10);
      const end = parseInt(rangeMatch[2], 10);
      for (let port = start; port <= end; port++) {
        expanded.push(String(port));
      }
    } else {
      // Single port
      expanded.push(token);
    }
  }

  return expanded;
}
