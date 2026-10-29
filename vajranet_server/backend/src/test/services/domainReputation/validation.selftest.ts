/**
 * Self-contained test for validation.ts's isPrivateOrLoopbackIp — the sole SSRF
 * guard used before every outbound request in the domain-reputation providers
 * (manualServer.ts, abuseipdb.ts, virustotal.ts) and in
 * controllers/burpsuite/burpsuiteController.ts's assertAllowedBurpUrl. No test
 * framework required:
 *
 *   node_modules/.bin/ts-node src/test/services/domainReputation/validation.selftest.ts
 *
 * The central case is IPv4-mapped IPv6. Recognising only the dotted-decimal
 * spelling "::ffff:d.d.d.d" is not enough: `new URL(...).hostname` normalizes a
 * bracketed literal such as "[::ffff:169.254.169.254]" to the compressed
 * hex-group form "::ffff:a9fe:a9fe", and every other spelling — fully expanded,
 * uppercase, dotted-decimal — normalizes there too, so a guard that misses it
 * misses the link-local metadata address entirely. The NAT64 well-known prefix
 * 64:ff9b::/96 embeds an IPv4 address in its last 32 bits the same way. Exits
 * non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { isPrivateOrLoopbackIp } from '../../../services/domainReputation/validation';

function main() {
  // Must be rejected (true = private/blocked).
  const mustBeBlocked = [
    '::ffff:a9fe:a9fe', // hex-group mapped 169.254.169.254 — what new URL().hostname actually produces
    '::ffff:169.254.169.254', // dotted-decimal mapped form (already worked pre-fix)
    '::FFFF:A9FE:A9FE', // uppercase
    '0:0:0:0:0:ffff:a9fe:a9fe', // fully-expanded, no "::" compression
    '64:ff9b::a9fe:a9fe', // NAT64-embedded 169.254.169.254
    '::ffff:7f00:1', // mapped 127.0.0.1, hex-group form
    '::ffff:127.0.0.1',
    '64:ff9b::7f00:1', // NAT64-embedded 127.0.0.1
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    '2001:db8::1',
    '2002::1',
    '169.254.169.254', // plain IPv4, sanity check
    '10.0.0.1',
    '127.0.0.1',
  ];
  for (const ip of mustBeBlocked) {
    assert.strictEqual(isPrivateOrLoopbackIp(ip), true, `must be treated as private/blocked: ${ip}`);
  }

  // ── Real public addresses — must remain allowed (false = not private) ───
  const mustBeAllowed = [
    '::ffff:8.8.8.8', // mapped public DNS, dotted form
    '::ffff:808:808', // mapped public DNS, hex-group form of 8.8.8.8
    '64:ff9b::808:808', // NAT64-embedded public IP
    '2001:4860:4860::8888', // Google public DNS
    '2606:4700:4700::1111', // Cloudflare public DNS
    '2400:cb00:2049:1::a29f:1804', // arbitrary public IPv6
    '8.8.8.8',
    '1.1.1.1',
  ];
  for (const ip of mustBeAllowed) {
    assert.strictEqual(isPrivateOrLoopbackIp(ip), false, `must remain allowed (public): ${ip}`);
  }

  // ── Non-IP input: net.isIP rejects it before isPrivateIPv6 ever runs, so this
  // ── returns false — not a guard bypass, since every caller only ever passes
  // ── something already confirmed to be an IP (a literal, or a dns.lookup() result).
  assert.strictEqual(isPrivateOrLoopbackIp('not-an-ip'), false, 'non-IP input is not this function\'s concern');

  console.log('validation.selftest: all checks passed');
}

main();
