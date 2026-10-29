/**
 * Self-contained test for utils/assetIdentity/normalize.ts — the pure,
 * DB-free half of asset identity resolution, where most of the feature's
 * correctness lives. No test framework required:
 *
 *   node_modules/.bin/ts-node src/test/utils/assetIdentityNormalize.selftest.ts
 *
 * Imports ONLY the pure module. normalize.ts has no database imports at all
 * (that is deliberate — see its header), so this file never risks pulling in
 * ../../index and its bootstrap IIFE the way a controller import would.
 *
 * Several fixtures are REAL values read out of the live fleet_prod database
 * rather than invented, and are marked as such:
 *
 *  - `00:00:00:00:00:00` is reported by interface_details for 36 distinct
 *    host_identifiers. It is the single most dangerous value in the fleet: if
 *    it survived normalization those 36 hosts would each score 80 against the
 *    other 35 and collapse into one asset.
 *  - The empty-string MAC is reported by 7 distinct hosts in the same table.
 *  - Locally-administered `02:*` addresses are pervasive (Docker bridges and
 *    veth pairs on the Linux agents); a sample of the real ones is asserted
 *    dropped.
 *  - A sweep of `interface_details` over a bounded id window found NO other
 *    MAC held by more than one host, so every real vendor MAC below is
 *    asserted to SURVIVE — dropping those would be just as broken as keeping
 *    the zero MAC.
 *  - The BIOS UUIDs are real `system_info.uuid` values (21 rows, all Windows,
 *    all distinct per host) and must survive; the AMI-style
 *    `03...00080009` family in particular is per-machine in this fleet even
 *    though one specific member of it is a known motherboard default and is
 *    blocklisted.
 *
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';

import {
  normalizeBiosUuid,
  normalizeHostname,
  normalizeIp,
  normalizeMac,
  normalizeObservation,
  normalizeOsFamily,
} from '../../utils/assetIdentity/normalize';
import type { DropReason } from '../../types/assetIdentity';

function macValue(raw: string): string {
  const r = normalizeMac(raw);
  assert.ok('value' in r, `expected ${raw} to normalize to a usable MAC, got ${JSON.stringify(r)}`);
  return (r as { value: string }).value;
}

function macDrop(raw: string, reason: DropReason): void {
  const r = normalizeMac(raw);
  assert.ok('reason' in r, `expected ${raw} to be DROPPED, but it normalized to ${JSON.stringify(r)}`);
  assert.strictEqual((r as { reason: DropReason }).reason, reason, `wrong drop reason for MAC ${raw}`);
}

function biosValue(raw: string): string {
  const r = normalizeBiosUuid(raw);
  assert.ok('value' in r, `expected BIOS UUID ${raw} to survive, got ${JSON.stringify(r)}`);
  return (r as { value: string }).value;
}

function biosDrop(raw: string, reason: DropReason): void {
  const r = normalizeBiosUuid(raw);
  assert.ok('reason' in r, `expected BIOS UUID ${raw} to be DROPPED, got ${JSON.stringify(r)}`);
  assert.strictEqual((r as { reason: DropReason }).reason, reason, `wrong drop reason for BIOS UUID ${raw}`);
}

function hostValue(raw: string): string {
  const r = normalizeHostname(raw);
  assert.ok('value' in r, `expected hostname ${JSON.stringify(raw)} to survive, got ${JSON.stringify(r)}`);
  return (r as { value: string }).value;
}

function hostDrop(raw: string, reason: DropReason): void {
  const r = normalizeHostname(raw);
  assert.ok('reason' in r, `expected hostname ${JSON.stringify(raw)} to be DROPPED, got ${JSON.stringify(r)}`);
  assert.strictEqual((r as { reason: DropReason }).reason, reason, `wrong drop reason for hostname ${raw}`);
}

function ipValue(raw: string): string {
  const r = normalizeIp(raw);
  assert.ok('value' in r, `expected IP ${raw} to survive, got ${JSON.stringify(r)}`);
  return (r as { value: string }).value;
}

function ipDrop(raw: string, reason: DropReason): void {
  const r = normalizeIp(raw);
  assert.ok('reason' in r, `expected IP ${raw} to be DROPPED, got ${JSON.stringify(r)}`);
  assert.strictEqual((r as { reason: DropReason }).reason, reason, `wrong drop reason for IP ${raw}`);
}

function main() {
  // ============================ MAC ====================================

  // THE load-bearing case. Real: 36 distinct host_identifiers in
  // interface_details report this exact value.
  macDrop('00:00:00:00:00:00', 'zero_mac');
  macDrop('00-00-00-00-00-00', 'zero_mac');
  macDrop('000000000000', 'zero_mac');
  macDrop('0000.0000.0000', 'zero_mac');

  macDrop('ff:ff:ff:ff:ff:ff', 'broadcast_mac');
  macDrop('FF:FF:FF:FF:FF:FF', 'broadcast_mac');

  // Real: the empty MAC is reported by 7 distinct hosts in interface_details.
  macDrop('', 'malformed_mac');
  macDrop('   ', 'malformed_mac');
  macDrop('not-a-mac', 'malformed_mac');
  macDrop('00:11:22:33:44', 'malformed_mac');
  macDrop('00:11:22:33:44:55:66', 'malformed_mac');
  macDrop('0g:11:22:33:44:55', 'malformed_mac');

  // Locally administered: second nibble 2/6/a/e. Docker's bridge prefix is the
  // headline case, and the four real 02:* values below were read out of
  // interface_details on the live fleet.
  macDrop('02:42:ac:11:00:02', 'locally_administered_mac');   // Docker container
  macDrop('02:42:1b:8e:44:9c', 'locally_administered_mac');   // docker0 bridge
  macDrop('02:00:d1:d7:66:98', 'locally_administered_mac');   // real, fleet_prod
  macDrop('02:1e:51:4e:e7:d9', 'locally_administered_mac');   // real, fleet_prod
  macDrop('02:e0:67:86:65:2a', 'locally_administered_mac');   // real, fleet_prod
  macDrop('02:fa:53:b9:26:a6', 'locally_administered_mac');   // real, fleet_prod
  macDrop('06:11:22:33:44:55', 'locally_administered_mac');
  macDrop('0a:00:27:00:00:0b', 'locally_administered_mac');   // VirtualBox host-only
  macDrop('0e:11:22:33:44:55', 'locally_administered_mac');
  macDrop('AA:BB:CC:DD:EE:FF', 'locally_administered_mac');   // 'a' nibble
  macDrop('9e:11:22:33:44:55', 'locally_administered_mac');

  // Multicast (low bit of the first octet) is a group address, never a host.
  macDrop('01:00:5e:00:00:fb', 'malformed_mac');
  macDrop('33:33:00:00:00:01', 'malformed_mac');

  // Real vendor MACs from the fleet's nmap output and vendor OUIs. The bounded
  // sweep of interface_details found no non-blocklisted MAC held by more than
  // one host, so every one of these MUST survive.
  assert.strictEqual(macValue('0C:38:3E:60:94:A7'), '0c:38:3e:60:94:a7');   // real, nmap output
  assert.strictEqual(macValue('0c-38-3e-60-94-a7'), '0c:38:3e:60:94:a7');
  assert.strictEqual(macValue('0c38.3e60.94a7'), '0c:38:3e:60:94:a7');
  assert.strictEqual(macValue('0c383e6094a7'), '0c:38:3e:60:94:a7');
  assert.strictEqual(macValue('  D8:BB:C1:2A:0F:31  '), 'd8:bb:c1:2a:0f:31');
  assert.strictEqual(macValue('00:1A:2B:3C:4D:5E'), '00:1a:2b:3c:4d:5e');
  assert.strictEqual(macValue('B8:85:84:AA:BB:CC'), 'b8:85:84:aa:bb:cc');
  assert.strictEqual(macValue('54:BF:64:11:22:33'), '54:bf:64:11:22:33');

  // Every separator style must land on the same normalized value, or the same
  // machine seen by osquery and by nmap fails to match itself at weight 80.
  const styles = ['0C:38:3E:60:94:A7', '0c-38-3e-60-94-a7', '0c38.3e60.94a7', '0C383E6094A7'];
  const normalizedStyles = new Set(styles.map(macValue));
  assert.strictEqual(normalizedStyles.size, 1, 'all MAC separator styles must normalize identically');

  // ============================ BIOS UUID ==============================

  // Real system_info.uuid values (21 rows, all Windows, all distinct per
  // host). These MUST survive — they are the weight-100 anchors.
  assert.strictEqual(
    biosValue('4C4C4544-0054-5A10-8052-B7C04F374A33'),
    '4C4C4544-0054-5A10-8052-B7C04F374A33',
  );                                                          // real, Dell
  assert.strictEqual(
    biosValue('dd0c5659-bd58-6655-30ac-581122900a0e'),
    'DD0C5659-BD58-6655-30AC-581122900A0E',
  );                                                          // real, lowercased input
  assert.strictEqual(
    biosValue('03560230-040F-051E-3206-930700080009'),
    '03560230-040F-051E-3206-930700080009',
  );                                                          // real, AMI-style but per-machine here
  assert.strictEqual(
    biosValue('03FF0210-04E0-05EB-C306-260700080009'),
    '03FF0210-04E0-05EB-C306-260700080009',
  );                                                          // real
  assert.strictEqual(
    biosValue('{30F15F48-EABE-4712-97CE-1A855A7D1482}'),
    '30F15F48-EABE-4712-97CE-1A855A7D1482',
  );                                                          // real, brace-wrapped input
  assert.strictEqual(
    biosValue('490d0578f1aa45edb6a68e46cad87fac'),
    '490D0578-F1AA-45ED-B6A6-8E46CAD87FAC',
  );                                                          // real, hyphenless input

  biosDrop('00000000-0000-0000-0000-000000000000', 'zero_bios_uuid');
  biosDrop('00000000000000000000000000000000', 'zero_bios_uuid');
  biosDrop('FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF', 'zero_bios_uuid');
  biosDrop('ffffffff-ffff-ffff-ffff-ffffffffffff', 'zero_bios_uuid');

  // Motherboard defaults / placeholders shipped verbatim by whole production
  // runs of consumer boards. One of these at weight 100 merges dozens of
  // unrelated machines — the most damaging false merge this feature can make.
  biosDrop('03000200-0400-0500-0006-000700080009', 'junk_bios_uuid');
  biosDrop('03000200-0400-0500-0006-000700080008', 'junk_bios_uuid');
  biosDrop('12345678-1234-5678-1234-567812345678', 'junk_bios_uuid');
  biosDrop('deadbeef-dead-beef-dead-beefdeadbeef', 'junk_bios_uuid');
  biosDrop('4c4c4544-0000-1020-8020-808c04f02033', 'junk_bios_uuid');

  biosDrop('', 'malformed_bios_uuid');
  biosDrop('   ', 'malformed_bios_uuid');
  biosDrop('not-a-uuid', 'malformed_bios_uuid');
  biosDrop('4C4C4544-0054-5A10-8052', 'malformed_bios_uuid');
  biosDrop('4C4C4544-0054-5A10-8052-B7C04F374A3Z', 'malformed_bios_uuid');
  biosDrop('To Be Filled By O.E.M.', 'malformed_bios_uuid');

  // ============================ HOSTNAME ===============================

  assert.strictEqual(hostValue('DESKTOP-EXAMPLE'), 'desktop-example');
  // The suffix strip is why the agent's short name and nmap's reverse-DNS FQDN
  // match at weight 40 instead of missing each other entirely.
  assert.strictEqual(hostValue('desktop-example.example.org'), 'desktop-example');
  assert.strictEqual(hostValue('DESKTOP-EXAMPLE.example.org.'), 'desktop-example');
  assert.strictEqual(hostValue('  vajra-uat  '), 'vajra-uat');
  assert.strictEqual(hostValue('node01'), 'node01');

  hostDrop('', 'empty_hostname');
  hostDrop('   ', 'empty_hostname');
  hostDrop('localhost', 'generic_hostname');
  hostDrop('LOCALHOST', 'generic_hostname');
  hostDrop('localhost.localdomain', 'generic_hostname');
  hostDrop('ubuntu', 'generic_hostname');
  hostDrop('ubuntu.local', 'generic_hostname');
  hostDrop('debian', 'generic_hostname');
  hostDrop('raspberrypi', 'generic_hostname');
  hostDrop('unknown', 'generic_hostname');
  hostDrop('-', 'generic_hostname');

  // nmap and nuclei echo the target back when reverse DNS returns nothing.
  // Accepting that would score an IP at 40 instead of 5.
  hostDrop('10.0.5.22', 'generic_hostname');
  hostDrop('192.168.1.1', 'generic_hostname');
  hostDrop('fe80::1', 'generic_hostname');
  hostDrop('-badstart', 'empty_hostname');
  hostDrop('bad_underscore', 'empty_hostname');

  // ============================ IP =====================================

  assert.strictEqual(ipValue('10.0.5.40'), '10.0.5.40');
  assert.strictEqual(ipValue(' 192.168.1.10 '), '192.168.1.10');
  assert.strictEqual(ipValue('10.0.5.40/24'), '10.0.5.40');
  assert.strictEqual(ipValue('2001:db8::1'), '2001:db8::1');
  assert.strictEqual(ipValue('[2001:DB8::1]'), '2001:db8::1');

  ipDrop('127.0.0.1', 'loopback_ip');
  ipDrop('127.1.2.3', 'loopback_ip');
  ipDrop('::1', 'loopback_ip');
  ipDrop('169.254.10.5', 'link_local_ip');
  ipDrop('fe80::1c2b:3d4e', 'link_local_ip');
  ipDrop('fe80::1%eth0', 'link_local_ip');
  ipDrop('0.0.0.0', 'malformed_ip');
  ipDrop('::', 'malformed_ip');
  ipDrop('224.0.0.251', 'malformed_ip');
  ipDrop('255.255.255.255', 'malformed_ip');
  ipDrop('', 'malformed_ip');
  ipDrop('999.1.1.1', 'malformed_ip');
  ipDrop('10.0.0', 'malformed_ip');
  ipDrop('10.0.0.01', 'malformed_ip');
  ipDrop('not an ip', 'malformed_ip');
  ipDrop('2001::db8::1', 'malformed_ip');

  // ============================ OS FAMILY ==============================

  // The whole point of collapsing to a family: two editions of one OS are the
  // same evidence about which machine this is.
  assert.strictEqual(normalizeOsFamily('Windows 11 Pro'), 'windows');
  assert.strictEqual(normalizeOsFamily('Windows 11 Home'), 'windows');
  assert.strictEqual(normalizeOsFamily('Microsoft Windows Server 2019'), 'windows');
  assert.strictEqual(normalizeOsFamily('windows'), 'windows');

  // Every non-Windows nodes.os_platform value the live fleet actually reports.
  for (const platform of ['ubuntu', 'pop', 'rhel', 'kali']) {
    assert.strictEqual(normalizeOsFamily(platform), 'linux', `os_platform ${platform} must be linux`);
  }
  assert.strictEqual(normalizeOsFamily('Linux 5.15 - 5.19'), 'linux');       // nmap OS details
  assert.strictEqual(normalizeOsFamily('Ubuntu 22.04.3 LTS'), 'linux');
  assert.strictEqual(normalizeOsFamily('Red Hat Enterprise Linux 9'), 'linux');

  assert.strictEqual(normalizeOsFamily('FreeBSD 13'), 'other');
  assert.strictEqual(normalizeOsFamily('Fanvil VoIP phone'), 'other');
  assert.strictEqual(normalizeOsFamily(''), null);
  assert.strictEqual(normalizeOsFamily('   '), null);

  // ============================ normalizeObservation ===================

  // A full Windows agent observation: every kind present and surviving.
  const agent = normalizeObservation({
    biosUuid: '4c4c4544-0054-5a10-8052-b7c04f374a33',
    osqueryUuid: 'c1d2e3f4-a5b6-4788-9900-aabbccddeeff',
    macs: ['0C:38:3E:60:94:A7', '00:00:00:00:00:00', '02:42:AC:11:00:02'],
    hostname: 'DESKTOP-EXAMPLE.example.org',
    os: 'Microsoft Windows 11 Pro',
    ips: ['10.0.5.40', '127.0.0.1', '169.254.3.4'],
  });
  assert.strictEqual(agent.biosUuid, '4C4C4544-0054-5A10-8052-B7C04F374A33');
  assert.deepStrictEqual(agent.macs, ['0c:38:3e:60:94:a7']);
  assert.strictEqual(agent.osFamily, 'windows');
  assert.deepStrictEqual(
    agent.identities.map((i) => i.kind + '=' + i.value).sort(),
    [
      'bios_uuid=4C4C4544-0054-5A10-8052-B7C04F374A33',
      'hostname=desktop-example',
      'ip=10.0.5.40',
      'mac=0c:38:3e:60:94:a7',
      'os=windows',
      'osquery_uuid=C1D2E3F4-A5B6-4788-9900-AABBCCDDEEFF',
    ],
  );
  // maxPossibleScore counts each KIND once (osquery_uuid contributes 0):
  // 100 + 80 + 40 + 10 + 5.
  assert.strictEqual(agent.maxPossibleScore, 235);

  // Every rejection is accounted for, with the raw value preserved.
  assert.deepStrictEqual(
    agent.dropped.map((d) => d.kind + '/' + d.reason + '/' + d.raw).sort(),
    [
      'ip/link_local_ip/169.254.3.4',
      'ip/loopback_ip/127.0.0.1',
      'mac/locally_administered_mac/02:42:AC:11:00:02',
      'mac/zero_mac/00:00:00:00:00:00',
    ],
  );

  // The osquery_uuid is evidence only: weight 0, and it must NEVER be recorded
  // as a bios_uuid. On the 36 Linux agents nodes.host_identifier is an
  // osquery-generated UUID with no hardware meaning.
  const osqueryOnly = normalizeObservation({
    osqueryUuid: '7f2b1c90-1111-4222-8333-444455556666',
    hostname: 'vajra-linux-01',
    os: 'ubuntu',
  });
  const osqueryIdentity = osqueryOnly.identities.find((i) => i.kind === 'osquery_uuid');
  assert.ok(osqueryIdentity, 'osquery_uuid must be recorded as evidence');
  assert.strictEqual(osqueryIdentity.weight, 0, 'osquery_uuid must never be scored');
  assert.strictEqual(osqueryOnly.biosUuid, null, 'osquery_uuid must never become a bios_uuid');
  assert.ok(
    !osqueryOnly.identities.some((i) => i.kind === 'bios_uuid'),
    'osquery_uuid must never be stored under kind bios_uuid',
  );
  assert.strictEqual(osqueryOnly.maxPossibleScore, 50, 'hostname 40 + os 10, osquery_uuid 0');

  // A machine reporting only the zero MAC — the 36-host case — must end up
  // with NO mac identity at all. If this ever regresses the whole fleet
  // collapses into one asset.
  const zeroMacHost = normalizeObservation({ macs: ['00:00:00:00:00:00'], hostname: 'somehost' });
  assert.ok(
    !zeroMacHost.identities.some((i) => i.kind === 'mac'),
    'the zero MAC must never produce a mac identity',
  );
  assert.deepStrictEqual(zeroMacHost.macs, []);

  // A Docker-only host: nothing but locally administered MACs and generic
  // names. EVERYTHING is dropped, and every drop is explained.
  const allDropped = normalizeObservation({
    biosUuid: '00000000-0000-0000-0000-000000000000',
    macs: ['00:00:00:00:00:00', '02:42:ac:11:00:02', 'garbage'],
    hostname: 'localhost',
    ips: ['127.0.0.1', '::1'],
    os: '',
  });
  assert.deepStrictEqual(allDropped.identities, [], 'nothing may survive this observation');
  assert.strictEqual(allDropped.maxPossibleScore, 0);
  assert.strictEqual(allDropped.biosUuid, null);
  assert.strictEqual(allDropped.osFamily, null);
  assert.strictEqual(allDropped.dropped.length, 8, 'every rejected value is recorded');
  assert.deepStrictEqual(
    allDropped.dropped.map((d) => d.reason).sort(),
    [
      'generic_hostname',
      'locally_administered_mac',
      'loopback_ip',
      'loopback_ip',
      'malformed_mac',
      'unrecognized_os',
      'zero_bios_uuid',
      'zero_mac',
    ].sort(),
  );
  for (const d of allDropped.dropped) {
    assert.ok(typeof d.raw === 'string', 'a drop must carry the raw value it rejected');
    assert.ok(typeof d.reason === 'string' && d.reason.length > 0, 'a drop must carry a reason');
  }

  // Repeated values across separator styles de-duplicate to one identity.
  const dupes = normalizeObservation({
    macs: ['0C:38:3E:60:94:A7', '0c-38-3e-60-94-a7', '0c38.3e60.94a7'],
    ips: ['10.0.5.40', '10.0.5.40'],
  });
  assert.strictEqual(dupes.identities.filter((i) => i.kind === 'mac').length, 1);
  assert.strictEqual(dupes.identities.filter((i) => i.kind === 'ip').length, 1);
  assert.strictEqual(dupes.maxPossibleScore, 85, 'per-kind: mac 80 + ip 5, not 3x80 + 2x5');

  // An unauthenticated nmap sweep: an IP and nothing else. This is the shape
  // that 1630 stored scans replay, and it must produce exactly one weak
  // identity — never a hostname or an os invented from the target string.
  const nmapOnly = normalizeObservation({ hostname: '10.0.5.22', ips: ['10.0.5.22'] });
  assert.deepStrictEqual(
    nmapOnly.identities.map((i) => i.kind + '=' + i.value),
    ['ip=10.0.5.22'],
  );
  assert.strictEqual(nmapOnly.maxPossibleScore, 5);

  // Absent attributes are not drops. Only a value that was actually present
  // and rejected is recorded, or match_reason fills with noise.
  const empty = normalizeObservation({});
  assert.deepStrictEqual(empty.identities, []);
  assert.deepStrictEqual(empty.dropped, []);
  assert.strictEqual(empty.maxPossibleScore, 0);

  console.log('assetIdentityNormalize.selftest: all checks passed');
}

main();
