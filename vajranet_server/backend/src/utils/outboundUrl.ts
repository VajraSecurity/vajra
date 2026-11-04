import { lookup as dnsLookup, promises as dns } from 'dns';
import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import { isPrivateOrLoopbackIp } from '../services/domainReputation/validation';

export class OutboundUrlError extends Error {}

function encodeHostname(hostname: string): string {
  // new URL() keeps IPv6 literals bracketed. Encoding is a no-op for any hostname the
  // parser accepted, and guarantees no character from the input can end the authority.
  if (hostname.startsWith('[')) {
    return `[${hostname.slice(1, -1).split(':').map(encodeURIComponent).join(':')}]`;
  }
  return encodeURIComponent(hostname);
}

function encodePathname(pathname: string): string {
  return pathname
    .split('/')
    .map((segment) => encodeURIComponent(decodeURIComponent(segment)))
    .join('/')
    .replace(/\/+$/, '');
}

/**
 * Rebuilds an admin-supplied service base URL from its parsed parts, so the string a
 * request is sent to is exactly the one that was validated. A second URL parser (axios,
 * a proxy) can't read a different host out of it, and appending a path to it can't land
 * anywhere but under that host. Rejects what has no place in a base URL: other schemes,
 * embedded credentials, a query string and a fragment.
 */
export function canonicalizeHttpUrl(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new OutboundUrlError('URL must be a string');
  }

  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    throw new OutboundUrlError('URL is not valid');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OutboundUrlError('URL must start with http:// or https://');
  }
  if (parsed.username || parsed.password) {
    throw new OutboundUrlError('URL must not contain credentials');
  }
  if (parsed.search || parsed.hash) {
    throw new OutboundUrlError('URL must not contain a query string or fragment');
  }

  let path: string;
  try {
    path = encodePathname(parsed.pathname);
  } catch {
    throw new OutboundUrlError('URL path is not valid');
  }

  const scheme = parsed.protocol === 'https:' ? 'https' : 'http';
  const port = parsed.port ? `:${encodeURIComponent(parsed.port)}` : '';
  return `${scheme}://${encodeHostname(parsed.hostname)}${port}${path}`;
}

// Scanners and the reputation engine are normally on the customer's own network (the
// setup screens suggest https://192.168.1.50:8834), so these ranges have to stay reachable.
const INTERNAL_NETWORKS = new net.BlockList();
INTERNAL_NETWORKS.addSubnet('10.0.0.0', 8, 'ipv4');
INTERNAL_NETWORKS.addSubnet('172.16.0.0', 12, 'ipv4');
INTERNAL_NETWORKS.addSubnet('192.168.0.0', 16, 'ipv4');
INTERNAL_NETWORKS.addSubnet('100.64.0.0', 10, 'ipv4');
INTERNAL_NETWORKS.addSubnet('fc00::', 7, 'ipv6');

// Never a valid target, whatever the checks below say. Cloud metadata services that sit
// outside the ranges isPrivateOrLoopbackIp refuses, or inside the internal networks allowed
// above: Alibaba Cloud, Azure's wireserver and AWS over IPv6. Instance credentials are served
// from these. Also NAT64 prefixes, whose addresses are another spelling of any IPv4 address,
// so that a metadata address can't be reached through them.
const NEVER_ALLOWED = new net.BlockList();
NEVER_ALLOWED.addAddress('100.100.100.200', 'ipv4');
NEVER_ALLOWED.addAddress('168.63.129.16', 'ipv4');
NEVER_ALLOWED.addAddress('fd00:ec2::254', 'ipv6');
NEVER_ALLOWED.addSubnet('64:ff9b::', 96, 'ipv6');
NEVER_ALLOWED.addSubnet('64:ff9b:1::', 48, 'ipv6');

const LOOPBACK = new net.BlockList();
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK.addAddress('::1', 'ipv6');

/**
 * On-prem escape hatch for a service running on the same host as this server. Off by
 * default because loopback is where this server's own Redis, database and admin
 * endpoints are reachable without authentication.
 */
const allowLoopbackServiceUrl = (): boolean => process.env.ALLOW_LOOPBACK_SERVICE_URL === 'true';

function isAllowedServiceAddress(ip: string): boolean {
  const family = net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
  if (NEVER_ALLOWED.check(ip, family)) return false;
  if (!isPrivateOrLoopbackIp(ip)) return true;
  if (INTERNAL_NETWORKS.check(ip, family)) return true;
  return allowLoopbackServiceUrl() && LOOPBACK.check(ip, family);
}

/**
 * SSRF (CWE-918) gate for the admin-supplied URL of a service that normally lives on an
 * internal network. Public and internal-network addresses pass; loopback, link-local
 * (including the 169.254.169.254 cloud metadata address) and reserved ranges do not, for
 * any address the hostname resolves to. Returns the canonical URL to send requests to.
 */
export async function assertAllowedServiceUrl(raw: unknown): Promise<string> {
  const canonical = canonicalizeHttpUrl(raw);
  const hostname = new URL(canonical).hostname.replace(/^\[|\]$/g, '');

  let addresses: { address: string }[];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (err) {
    throw new OutboundUrlError(`Could not resolve host ${hostname}`, { cause: err });
  }

  const refused = addresses.find(({ address }) => !isAllowedServiceAddress(address));
  if (refused) {
    throw new OutboundUrlError(`Refusing to contact reserved address ${refused.address}`);
  }
  return canonical;
}

/**
 * Re-applies the address check at connect time. Without it a hostname could resolve to an
 * allowed address when assertAllowedServiceUrl runs and to a refused one when the request
 * connects (DNS rebinding). The socket uses the addresses checked here, not a second lookup.
 */
export const guardedServiceLookup: net.LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, '', 0);
      return;
    }
    const refused = addresses.find(({ address }) => !isAllowedServiceAddress(address));
    if (refused || addresses.length === 0) {
      const reason = refused ? `Refusing to contact reserved address ${refused.address}` : `Could not resolve host ${hostname}`;
      callback(new OutboundUrlError(reason), '', 0);
      return;
    }
    if (options.all) {
      callback(null, addresses);
    } else {
      callback(null, addresses[0].address, addresses[0].family);
    }
  });
};

type ConnectionFactory = (options: { host?: string | null }, callback: (err: Error | null, socket?: net.Socket) => void) => net.Socket | undefined;

/**
 * Node never calls `lookup` for an IP literal, so a stored URL such as http://127.0.0.1
 * saved before this validation existed would otherwise skip the check entirely.
 */
function guardLiteralHosts<T extends http.Agent>(agent: T): T {
  const target = agent as unknown as { createConnection: ConnectionFactory };
  const createConnection = target.createConnection.bind(agent);
  target.createConnection = (options, callback) => {
    const host = (options.host ?? '').replace(/^\[|\]$/g, '');
    if (net.isIP(host) !== 0 && !isAllowedServiceAddress(host)) {
      callback(new OutboundUrlError(`Refusing to contact reserved address ${host}`));
      return undefined;
    }
    return createConnection(options, callback);
  };
  return agent;
}

export const guardedServiceHttpAgent = guardLiteralHosts(new http.Agent({ lookup: guardedServiceLookup }));

export function createGuardedServiceHttpsAgent(options: https.AgentOptions = {}): https.Agent {
  return guardLiteralHosts(new https.Agent({ ...options, lookup: guardedServiceLookup }));
}
