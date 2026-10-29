import { isValidAndAllowedIP } from '../nmapController';

/**
 * Validates the "known IPs" allowlist shared by create/update: devices (e.g.
 * routers/printers) that can never run the Vajra agent, so they'd otherwise
 * show up as "unmanaged" on every run. Deduped, trimmed, and each entry must
 * be a syntactically valid private IPv4 address.
 */
export function validateKnownIps(input: unknown): { knownIps: string[] } | { error: string } {
  if (input === undefined || input === null) return { knownIps: [] };
  if (!Array.isArray(input)) {
    return { error: 'knownIps must be an array of IP addresses.' };
  }

  const cleaned = Array.from(new Set(
    input.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean),
  ));

  for (const ip of cleaned) {
    if (!isValidAndAllowedIP(ip)) {
      return { error: `"${ip}" is not a valid private IPv4 address (10.x, 172.16-31.x, 192.168.x, 100.64-127.x).` };
    }
  }

  return { knownIps: cleaned };
}
