import * as net from 'net';

const HOSTNAME_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/**
 * Users routinely paste a full URL ("https://example.com/path") where a bare
 * domain is expected. Strips scheme, userinfo, path/query/fragment and port
 * before validating what's left looks like a hostname. Returns null if the
 * input doesn't reduce to a plausible domain.
 */
export function normalizeDomainInput(raw: string): string | null {
  let v = raw.trim().toLowerCase();
  if (!v) return null;

  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  v = v.split(/[/?#]/)[0];
  v = v.split('@').pop() as string;
  v = v.replace(/:\d+$/, '');
  v = v.replace(/\.$/, '');

  return HOSTNAME_RE.test(v) ? v : null;
}

export function normalizeIpInput(raw: string): string | null {
  const v = raw.trim();
  return v && net.isIP(v) !== 0 ? v : null;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

// Private-use, loopback, link-local and IANA special-purpose ranges: never
// legitimate lookup targets for a public reputation API.
//
// Kept in sync with the manual server's own reserved-range list in its
// internal/api/validate.go. That server rejects these outright, so a range
// missing here comes back as a generic upstream error instead of an immediate,
// clear client-side message. Add a range to both or neither.
const PRIVATE_V4_BLOCKS: [string, string][] = [
  ['0.0.0.0', '0.255.255.255'], // "this network"
  ['10.0.0.0', '10.255.255.255'], // RFC1918
  ['100.64.0.0', '100.127.255.255'], // carrier-grade NAT
  ['127.0.0.0', '127.255.255.255'], // loopback
  ['169.254.0.0', '169.254.255.255'], // link-local
  ['172.16.0.0', '172.31.255.255'], // RFC1918
  ['192.0.0.0', '192.0.0.255'], // IETF protocol assignments
  ['192.0.2.0', '192.0.2.255'], // TEST-NET-1
  ['192.88.99.0', '192.88.99.255'], // deprecated 6to4 relay anycast
  ['192.168.0.0', '192.168.255.255'], // RFC1918
  ['198.18.0.0', '198.19.255.255'], // benchmarking
  ['198.51.100.0', '198.51.100.255'], // TEST-NET-2
  ['203.0.113.0', '203.0.113.255'], // TEST-NET-3
  ['240.0.0.0', '255.255.255.255'], // reserved, includes broadcast
];

function isPrivateIPv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return PRIVATE_V4_BLOCKS.some(([start, end]) => n >= (ipv4ToInt(start) as number) && n <= (ipv4ToInt(end) as number));
}

// Expands any syntactically valid IPv6 address (as confirmed by net.isIP) into
// its 8 canonical zero-padded hex groups, resolving "::" compression and an
// embedded dotted-decimal IPv4 tail.
//
// The canonical form is what makes the SSRF guard sound: one address has many
// spellings, and Node's URL parser rewrites "[::ffff:169.254.169.254]" to
// "::ffff:a9fe:a9fe", so a spelling-specific check on the dotted-decimal form
// misses it entirely. Matching every embedded-IPv4 prefix below on its bit
// pattern instead means no re-patching for the next spelling.
function expandIPv6Groups(ip: string): string[] | null {
  let v = ip.toLowerCase();

  // Fold an embedded dotted-decimal IPv4 tail (e.g. "::ffff:169.254.169.254")
  // into two hex groups, so every group below is uniformly hex.
  const v4Tail = v.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Tail) {
    const n = ipv4ToInt(v4Tail[1]);
    if (n === null) return null;
    const hi = ((n >>> 16) & 0xffff).toString(16);
    const lo = (n & 0xffff).toString(16);
    v = v.slice(0, -v4Tail[1].length) + `${hi}:${lo}`;
  }

  const halves = v.split('::');
  if (halves.length > 2) return null; // more than one "::" is not valid IPv6

  if (halves.length === 1) {
    // Fully-written form with no "::" compression: must be exactly 8 groups.
    const groups = v.split(':');
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
    return groups.map((g) => g.padStart(4, '0'));
  }

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const elided = 8 - left.length - right.length;
  if (elided < 0) return null;
  const groups = [...left, ...Array(elided).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => g.padStart(4, '0'));
}

function isPrivateIPv6(ip: string): boolean {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  if (v.startsWith('fe80:')) return true; // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(v)) return true; // fc00::/7 unique local
  if (/^2001:0*db8:/.test(v)) return true; // 2001:db8::/32 documentation
  if (/^2002:/.test(v)) return true; // 6to4

  const groups = expandIPv6Groups(v);
  // net.isIP accepted it but this could not parse it. For an SSRF guard an
  // address we cannot reason about must fail closed, not open.
  if (!groups) return true;

  // Converts the last two hex groups (32 bits) into a dotted-decimal IPv4 address.
  const embeddedIPv4 = (): string => {
    const hi = parseInt(groups[6], 16);
    const lo = parseInt(groups[7], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  };

  // IPv4-mapped ::ffff:0:0/96 (RFC 4291): groups[0..4] = 0000, groups[5] = ffff.
  if (groups.slice(0, 5).every((g) => g === '0000') && groups[5] === 'ffff') {
    return isPrivateIPv4(embeddedIPv4());
  }
  // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) also embeds an IPv4 address
  // in the last 32 bits, so a caller can reach the same private target through it.
  if (groups[0] === '0064' && groups[1] === 'ff9b' && groups.slice(2, 6).every((g) => g === '0000')) {
    return isPrivateIPv4(embeddedIPv4());
  }

  return false;
}

/**
 * True for private, loopback, link-local and IANA special-purpose addresses
 * (documentation, CGNAT, benchmarking, reserved). No public reputation service
 * has data for these, and the manual server rejects them outright.
 */
export function isPrivateOrLoopbackIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return false;
}
