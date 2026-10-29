/**
 * Shared target validation for the network-scanning subsystem (nmap + nuclei).
 *
 * Scans are only ever allowed against private/CGNAT IPv4 space:
 *   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10.
 *
 * Hostnames are intentionally NOT accepted here — nmap/nuclei would resolve
 * them via DNS outside of this validation, making the private-range
 * restriction unenforceable for hostname targets. Only literal IPv4
 * addresses and CIDR blocks are allowed.
 *
 * CIDR validation checks the actual expanded network range (not just the
 * literal octets typed), so a request like "10.0.0.0/0" is rejected even
 * though its first octet is a private one — the /0 expands to the entire
 * IPv4 address space, which is not contained in any single allowed block.
 */

const MAX_EXPANDED_HOSTS = 4096;

function parseIPv4Octets(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== p) return null;
    octets.push(n);
  }
  return octets;
}

function ipToInt(octets: number[]): number {
  return (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0);
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function prefixToMask(prefix: number): number {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xFFFFFFFF >>> 0;
  return (0xFFFFFFFF << (32 - prefix)) >>> 0;
}

// [start, end] inclusive, as 32-bit unsigned integers.
const ALLOWED_BLOCKS: [number, number][] = [
  [ipToInt([10, 0, 0, 0]), ipToInt([10, 255, 255, 255])],
  [ipToInt([172, 16, 0, 0]), ipToInt([172, 31, 255, 255])],
  [ipToInt([192, 168, 0, 0]), ipToInt([192, 168, 255, 255])],
  [ipToInt([100, 64, 0, 0]), ipToInt([100, 127, 255, 255])],
];

function isRangeAllowed(startInt: number, endInt: number): boolean {
  return ALLOWED_BLOCKS.some(([blockStart, blockEnd]) => startInt >= blockStart && endInt <= blockEnd);
}

/** A single literal IPv4 address (no CIDR suffix), must fall inside an allowed block. */
export function isValidAndAllowedIP(ip: string): boolean {
  const octets = parseIPv4Octets(ip);
  if (!octets) return false;
  const n = ipToInt(octets);
  return isRangeAllowed(n, n);
}

/**
 * Validates a CIDR block by its actual expanded range, not just the literal
 * octets of the address given. Returns the canonical "network/prefix" form
 * (so a non-network address like "10.0.0.5/24" normalizes to "10.0.0.0/24")
 * or null if invalid/disallowed/too large.
 */
export function validateCIDR(cidr: string, maxHosts: number = MAX_EXPANDED_HOSTS): string | null {
  const [ip, prefixStr] = cidr.split('/');
  if (!ip || !prefixStr) return null;
  const octets = parseIPv4Octets(ip);
  if (!octets) return null;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32 || String(prefix) !== prefixStr.trim()) return null;

  const mask = prefixToMask(prefix);
  const ipInt = ipToInt(octets);
  const networkStart = (ipInt & mask) >>> 0;
  const networkEnd = (networkStart | (~mask >>> 0)) >>> 0;

  if (!isRangeAllowed(networkStart, networkEnd)) return null;

  const hostCount = Math.pow(2, 32 - prefix);
  if (hostCount > maxHosts) return null;

  return `${intToIp(networkStart)}/${prefix}`;
}

/**
 * Minimum-prefix floor for CIDRs used in recurring scheduled scans — a
 * tighter, opt-in-only policy layered on top of the range check above.
 * Kept separate from ad-hoc/one-off scan validation.
 */
export function isValidScheduleCidr(value: unknown, minPrefix = 16): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  const parts = trimmed.split('/');
  if (parts.length !== 2) return false;
  const prefix = parseInt(parts[1], 10);
  if (isNaN(prefix) || prefix < minPrefix || prefix > 32) return false;
  return validateCIDR(trimmed) !== null;
}

/**
 * Parses a comma/whitespace-separated list of targets (literal IPs and/or
 * CIDR blocks only — no hostnames) and validates every entry. Returns the
 * canonicalized target list, or null if anything in the list is invalid.
 */
export function parseAndValidateTargets(raw: string, maxHosts: number = MAX_EXPANDED_HOSTS): string[] | null {
  const normalized = raw.replace(/,/g, ' ').replace(/\s+/g, ' ').trim();
  const parts = normalized.split(' ').filter(Boolean);
  if (parts.length === 0) return null;

  const validated: string[] = [];
  for (const part of parts) {
    if (part.startsWith('-')) return null;
    if (part.includes('/')) {
      const canonical = validateCIDR(part, maxHosts);
      if (!canonical) return null;
      validated.push(canonical);
    } else {
      if (!isValidAndAllowedIP(part)) return null;
      validated.push(part);
    }
  }

  return validated;
}

export { MAX_EXPANDED_HOSTS };
