/**
 * Pure normalization of a raw observation into scoreable identities.
 *
 * This module is where most of the correctness of asset identity resolution
 * actually lives, and it deliberately has NO database imports at all: it is a
 * single pure function so it can be exercised exhaustively by
 * src/test/utils/assetIdentityNormalize.selftest.ts without a Postgres
 * connection, and so a normalization bug can be re-run against the raw attrs
 * kept in asset_observations.attrs without re-scanning the network.
 *
 * The rule that matters most: a value that is not per-machine must never
 * become an identity. `00:00:00:00:00:00` is reported by interface_details for
 * 36 of the 57 live agents; if it survived normalization every one of those
 * hosts would score 80 (mac) against every other and the entire fleet would
 * collapse into a single asset on the first run. The same reasoning drives the
 * locally-administered MAC rule (Docker's 02:42:*, VMware/Hyper-V vNICs and
 * randomized Wi-Fi MACs are per-boot, not per-machine), the BIOS UUID
 * blocklist and the generic-hostname blocklist.
 *
 * EVERY rejection is recorded as a DroppedIdentity carrying the raw value and
 * a DropReason. An unexplained drop makes a later wrong match unauditable, so
 * dropping silently is never acceptable -- even for a value that is obviously
 * junk.
 *
 * @see backend/src/consts/assets.ts for the enumerable blocklists and weights.
 * @see backend/src/utils/assetIdentity/resolveAsset.ts for the matcher.
 */

import {
  BIOS_UUID_BLOCKLIST,
  HOSTNAME_BLOCKLIST,
  IDENTITY_WEIGHTS,
  MAC_BLOCKLIST,
} from '../../consts/assets';
import type {
  DroppedIdentity,
  DropReason,
  IdentityKind,
  NormalizedIdentity,
  NormalizedObservation,
  ObservedAttrs,
  OsFamily,
} from '../../types/assetIdentity';

/** Six colon-separated hex octets, after separator canonicalization. */
const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

/** Canonical 8-4-4-4-12 hex UUID, after uppercasing. */
const UUID_RE = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/;

/**
 * A DNS label per RFC 1123: alphanumeric with internal hyphens. Applied to the
 * FIRST label only, after the DNS suffix is stripped, so
 * "desktop-example.example.org" is validated as "desktop-example".
 */
const HOSTNAME_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** Dotted-quad IPv4 with each octet range-checked below. */
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Loose IPv6: hex groups and colons only. Structure is checked below. */
const IPV6_RE = /^[0-9a-f:]+$/;

const MAC_BLOCKLIST_SET = new Set(MAC_BLOCKLIST.map((m) => m.toLowerCase()));
const BIOS_UUID_BLOCKLIST_SET = new Set(BIOS_UUID_BLOCKLIST.map((u) => u.toUpperCase()));
const HOSTNAME_BLOCKLIST_SET = new Set(HOSTNAME_BLOCKLIST.map((h) => h.toLowerCase()));

/**
 * Substrings that identify a Windows OS string. Checked before the Linux list
 * because nothing in the Linux list is a substring of a Windows product name.
 */
const WINDOWS_OS_MARKERS = ['windows', 'win32', 'winnt', 'microsoft'];

/**
 * Substrings that identify a Linux OS string. Includes the `nodes.os_platform`
 * values the live fleet actually reports for Linux agents (ubuntu, pop, rhel,
 * kali), plus the distro/kernel names nmap's `OS details:` and OpenVAS's
 * `best_os_txt` emit. Anything matching neither list collapses to 'other'
 * rather than being dropped: "a machine whose OS we could not identify" is
 * still weak evidence, and at weight 10 it can never carry a match alone.
 */
const LINUX_OS_MARKERS = [
  'linux', 'ubuntu', 'debian', 'centos', 'rhel', 'red hat', 'redhat', 'fedora',
  'suse', 'arch', 'alpine', 'kali', 'pop', 'mint', 'rocky', 'alma', 'gentoo',
  'raspbian', 'oracle linux', 'amazon linux', 'busybox',
];

function weightOf(kind: IdentityKind): number {
  return IDENTITY_WEIGHTS[kind];
}

/**
 * Normalize one MAC to lowercase colon form, or explain why it cannot be an
 * identity.
 *
 * Accepts the separator styles scanners emit -- colon (osquery,
 * `interface_details.mac`), hyphen (Windows `getmac`, OpenVAS host details),
 * Cisco dotted-quad and bare hex -- and canonicalizes them all before any
 * test, so the blocklist and the locally-administered bit test are each
 * written once.
 */
export function normalizeMac(raw: string): { value: string } | { reason: DropReason } {
  const trimmed = (raw ?? '').trim();
  if (trimmed === '') return { reason: 'malformed_mac' };

  const hex = trimmed.toLowerCase().replace(/[:.\- ]/g, '');
  if (!/^[0-9a-f]{12}$/.test(hex)) return { reason: 'malformed_mac' };
  const value = (hex.match(/.{2}/g) as string[]).join(':');
  if (!MAC_RE.test(value)) return { reason: 'malformed_mac' };

  if (value === '00:00:00:00:00:00') return { reason: 'zero_mac' };
  if (value === 'ff:ff:ff:ff:ff:ff') return { reason: 'broadcast_mac' };
  // Any other enumerated blocklist entry keeps the closest available reason.
  if (MAC_BLOCKLIST_SET.has(value)) return { reason: 'zero_mac' };

  // Bit 1 of the first octet is the U/L flag: set means locally administered,
  // i.e. software-assigned rather than burned into a NIC by its vendor. That
  // makes the second hex nibble one of 2, 6, a or e. Docker bridges (02:42:*),
  // VMware/Hyper-V virtual NICs, libvirt taps and randomized Wi-Fi MACs all
  // land here, and none of them is stable per machine. The live fleet reports
  // thousands of distinct 02:* addresses in interface_details.
  const secondNibble = value[1];
  if (secondNibble === '2' || secondNibble === '6' || secondNibble === 'a' || secondNibble === 'e') {
    return { reason: 'locally_administered_mac' };
  }

  // A multicast MAC (low bit of the first octet set) is never a host address.
  const firstOctet = parseInt(value.slice(0, 2), 16);
  if ((firstOctet & 0x01) === 1) return { reason: 'malformed_mac' };

  return { value };
}

/**
 * Normalize a SMBIOS/BIOS UUID to canonical uppercase 8-4-4-4-12 form, or
 * explain why it cannot be an identity. Weight 100 means a false positive here
 * merges two unrelated machines outright, so the blocklist is checked strictly.
 */
export function normalizeBiosUuid(raw: string): { value: string } | { reason: DropReason } {
  const trimmed = (raw ?? '').trim();
  if (trimmed === '') return { reason: 'malformed_bios_uuid' };

  // Some sources wrap the value in braces or omit the hyphens.
  let value = trimmed.replace(/^\{|\}$/g, '').toUpperCase();
  if (/^[0-9A-F]{32}$/.test(value)) {
    value =
      value.slice(0, 8) + '-' + value.slice(8, 12) + '-' + value.slice(12, 16) +
      '-' + value.slice(16, 20) + '-' + value.slice(20);
  }
  if (!UUID_RE.test(value)) return { reason: 'malformed_bios_uuid' };

  const hexOnly = value.replace(/-/g, '');
  if (/^0+$/.test(hexOnly)) return { reason: 'zero_bios_uuid' };
  if (BIOS_UUID_BLOCKLIST_SET.has(value)) {
    return /^F+$/.test(hexOnly) ? { reason: 'zero_bios_uuid' } : { reason: 'junk_bios_uuid' };
  }
  return { value };
}

/**
 * Normalize a hostname to its lowercase first label, or explain why it cannot
 * be an identity.
 *
 * The DNS suffix is stripped because the same machine is reported as
 * "desktop-example" by the osquery agent and "desktop-example.example.org" by
 * nmap's reverse DNS; keeping the suffix would make those two observations
 * fail to match on a kind worth 40 points.
 */
export function normalizeHostname(raw: string): { value: string } | { reason: DropReason } {
  const trimmed = (raw ?? '').trim();
  if (trimmed === '') return { reason: 'empty_hostname' };

  const lower = trimmed.toLowerCase().replace(/\.$/, '');       // drop a FQDN's root dot
  if (HOSTNAME_BLOCKLIST_SET.has(lower)) return { reason: 'generic_hostname' };

  // A bare IP address is not a hostname. nmap and nuclei both echo the target
  // back when reverse DNS returns nothing, and accepting that would score the
  // ip evidence at 40 instead of 5.
  if (IPV4_RE.test(lower) || (lower.includes(':') && IPV6_RE.test(lower))) {
    return { reason: 'generic_hostname' };
  }

  const label = lower.split('.')[0];
  if (label === '') return { reason: 'empty_hostname' };
  if (HOSTNAME_BLOCKLIST_SET.has(label)) return { reason: 'generic_hostname' };
  if (!HOSTNAME_LABEL_RE.test(label)) return { reason: 'empty_hostname' };
  return { value: label };
}

/**
 * Normalize an IP literal, dropping the ranges that identify no machine:
 * loopback (127/8, ::1), link-local (169.254/16, fe80::/10), multicast, and
 * anything malformed. 0.0.0.0 is a placeholder, not an address.
 *
 * Private RFC1918 addresses are deliberately KEPT: this is an on-premise fleet
 * where essentially every asset has one, and ip is weight 5 precisely because
 * a DHCP lease is not a machine.
 */
export function normalizeIp(raw: string): { value: string } | { reason: DropReason } {
  const trimmed = (raw ?? '').trim();
  if (trimmed === '') return { reason: 'malformed_ip' };

  // Strip a CIDR suffix or zone id, and unwrap an IPv6 literal's brackets.
  const bare = trimmed.replace(/^\[|\]$/g, '').split('/')[0].split('%')[0];

  const v4 = bare.match(IPV4_RE);
  if (v4) {
    const parts = v4.slice(1, 5);
    if (parts.some((p) => p.length > 1 && p.startsWith('0'))) return { reason: 'malformed_ip' };
    const octets = parts.map((o) => Number(o));
    if (octets.some((o) => o > 255)) return { reason: 'malformed_ip' };
    if (octets[0] === 127) return { reason: 'loopback_ip' };
    if (octets[0] === 169 && octets[1] === 254) return { reason: 'link_local_ip' };
    if (octets[0] === 0) return { reason: 'malformed_ip' };          // 0.0.0.0 and 0/8
    if (octets[0] >= 224) return { reason: 'malformed_ip' };         // multicast / reserved
    return { value: octets.join('.') };
  }

  if (!bare.includes(':')) return { reason: 'malformed_ip' };
  const lower = bare.toLowerCase();
  if (!IPV6_RE.test(lower)) return { reason: 'malformed_ip' };
  if ((lower.match(/::/g) || []).length > 1) return { reason: 'malformed_ip' };
  if (lower === '::') return { reason: 'malformed_ip' };             // unspecified
  const groups = lower.split(':').filter((g) => g !== '');
  if (groups.length === 0 || groups.length > 8) return { reason: 'malformed_ip' };
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return { reason: 'malformed_ip' };
  if (!lower.includes('::') && groups.length !== 8) return { reason: 'malformed_ip' };
  if (lower === '::1') return { reason: 'loopback_ip' };
  // fe80::/10 -- the first group is fe80..febf.
  if (/^fe[89ab]/.test(lower)) return { reason: 'link_local_ip' };
  if (/^ff/.test(lower)) return { reason: 'malformed_ip' };          // ff00::/8 multicast
  return { value: lower };
}

/**
 * Collapse a raw OS string to a family. `Windows 11 Pro` and `Windows 11 Home`
 * are the same evidence about which machine this is, and keeping the full
 * string would make one host fail to match itself across two scanners that
 * word the version differently.
 *
 * Returns null only for an empty/absent string; anything unrecognized becomes
 * 'other' rather than being dropped.
 */
export function normalizeOsFamily(raw: string): OsFamily | null {
  const lower = (raw ?? '').trim().toLowerCase();
  if (lower === '') return null;
  if (WINDOWS_OS_MARKERS.some((m) => lower.includes(m))) return 'windows';
  if (LINUX_OS_MARKERS.some((m) => lower.includes(m))) return 'linux';
  return 'other';
}

/**
 * Turn raw observed attributes into the scoreable identity set plus a full
 * account of everything that was rejected and why.
 *
 * Pure: no DB, no clock, no randomness. `maxPossibleScore` is the score this
 * observation would achieve against an asset that shares every one of its
 * identities, which is what tells "scored 40 out of a possible 40" apart from
 * "scored 40 out of a possible 235".
 */
export function normalizeObservation(attrs: ObservedAttrs): NormalizedObservation {
  const identities: NormalizedIdentity[] = [];
  const dropped: DroppedIdentity[] = [];
  const seen = new Set<string>();

  const push = (kind: IdentityKind, value: string): void => {
    const key = kind + ' ' + value;
    if (seen.has(key)) return;
    seen.add(key);
    identities.push({ kind, value, weight: weightOf(kind) });
  };

  // bios_uuid (100)
  let biosUuid: string | null = null;
  if (attrs.biosUuid != null && String(attrs.biosUuid).trim() !== '') {
    const raw = String(attrs.biosUuid);
    const r = normalizeBiosUuid(raw);
    if ('value' in r) {
      biosUuid = r.value;
      push('bios_uuid', r.value);
    } else {
      dropped.push({ kind: 'bios_uuid', raw, reason: r.reason });
    }
  }

  // osquery_uuid (0) -- recorded as evidence for the audit trail and the UI
  // only. Scored 0 because on the 36 Linux agents nodes.host_identifier is an
  // osquery-generated UUID with no hardware meaning, so two hosts sharing one
  // (a cloned image, a restored /var/osquery) must never be pulled together.
  // Shape-validated, but NEVER blocklist-checked as a bios_uuid.
  if (attrs.osqueryUuid != null && String(attrs.osqueryUuid).trim() !== '') {
    const raw = String(attrs.osqueryUuid).trim();
    const upper = raw.replace(/^\{|\}$/g, '').toUpperCase();
    if (UUID_RE.test(upper)) {
      push('osquery_uuid', upper);
    } else {
      dropped.push({ kind: 'osquery_uuid', raw, reason: 'malformed_bios_uuid' });
    }
  }

  // mac (80)
  const macs: string[] = [];
  for (const rawMac of attrs.macs ?? []) {
    const raw = rawMac == null ? '' : String(rawMac);
    const r = normalizeMac(raw);
    if ('value' in r) {
      if (!macs.includes(r.value)) macs.push(r.value);
      push('mac', r.value);
    } else {
      dropped.push({ kind: 'mac', raw, reason: r.reason });
    }
  }

  // hostname (40)
  if (attrs.hostname != null) {
    const raw = String(attrs.hostname);
    const r = normalizeHostname(raw);
    if ('value' in r) push('hostname', r.value);
    else dropped.push({ kind: 'hostname', raw, reason: r.reason });
  }

  // os (10)
  let osFamily: OsFamily | null = null;
  if (attrs.os != null) {
    const raw = String(attrs.os);
    osFamily = normalizeOsFamily(raw);
    if (osFamily === null) dropped.push({ kind: 'os', raw, reason: 'unrecognized_os' });
    else push('os', osFamily);
  }

  // ip (5)
  for (const rawIp of attrs.ips ?? []) {
    const raw = rawIp == null ? '' : String(rawIp);
    const r = normalizeIp(raw);
    if ('value' in r) push('ip', r.value);
    else dropped.push({ kind: 'ip', raw, reason: r.reason });
  }

  // The best score this observation could possibly achieve: one contribution
  // per KIND present. A host with four NICs does not score 320 for mac --
  // scoring is per kind, see resolveAsset.ts.
  const kindsPresent = new Set(identities.map((i) => i.kind));
  let maxPossibleScore = 0;
  for (const kind of kindsPresent) maxPossibleScore += weightOf(kind);

  return { identities, biosUuid, macs, osFamily, dropped, maxPossibleScore };
}
