/**
 * Self-contained test for openvasFeeder.ts's PARSING layer — extractHosts,
 * extractAuthenticatedIps, computeSeverityCountsByHost/ForHost,
 * extractAssetInventoryFacts and extractInnerReport. No test framework and NO
 * NETWORK/DATABASE required:
 *
 *   node_modules/.bin/ts-node src/test/services/assetIdentity/openvasFeeder.selftest.ts
 *
 * OpenVAS is the only asset-identity feeder actually wired into the
 * production cron tick (see assetResolutionService.ts), and this file is the
 * layer that turns a raw, already-XML-to-JSON-parsed GVM `get_report` body —
 * external, less-trusted input from whatever the scan target reported back —
 * into the structured facts `processOpenvasReportForAssets` hands to the
 * matcher. resolveAsset.ts/normalize.ts already have selftests of their own
 * for what happens AFTER this point; nothing previously exercised regex
 * extraction against report shapes directly, even though every field here
 * (hostname, MAC, bios_uuid candidate, machine-id) is a regex capture against
 * text a scanned host controls (see ATTRS_MAX_BYTES's comment in
 * consts/assets.ts for the same concern from the write side).
 *
 * Report shapes below mirror this codebase's actual fast-xml-parser
 * conventions used elsewhere (openvasController.ts's getReport,
 * resolveAsset's own selftest for the sibling layer): attributes prefixed
 * `@_`, mixed-content text nodes as `#text`, and GVM's own inconsistency
 * about whether a single vs. repeated element comes back as an object or an
 * array (handled by this module's own `ensureArray`, exercised implicitly by
 * every single-element case below never wrapping in `[...]`).
 *
 * IMPORT-SAFETY (see src/test/utils/openvasEditFlows.selftest.ts's header
 * comment for the fully-verified chain this repeats): openvasFeeder.ts
 * statically imports `executeGmpCommand` from utils/openvasClient.ts, which
 * statically imports utils/scannerScope.ts, which statically imports
 * utils/nodeScope.ts, which statically imports `dbSourceConnection` from
 * `../index` (src/index.ts) — and src/index.ts unconditionally runs the full
 * server-bootstrap IIFE at module load (DB connect, cron jobs, `server.listen`,
 * `process.exit` on port conflict). A plain top-level `import` of
 * openvasFeeder.ts therefore boots a second live server as a side effect of
 * running this test. This file neutralizes src/index.ts in `require.cache`
 * BEFORE requiring openvasFeeder.ts (via a runtime `require`, not a static
 * `import` — a static import is hoisted by the TS/CJS compiler ahead of the
 * stub-installation code below, defeating it), exactly like
 * openvasEditFlows.selftest.ts already does for openvasClient.ts directly.
 *
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import path from 'path';

// ---------------------------------------------------------------------------
// Step 1 (must happen before anything transitively requires openvasClient.ts):
// neutralize src/index.ts in require.cache. See header comment for why.
// ---------------------------------------------------------------------------
const SRC_DIR = path.join(__dirname, '..', '..', '..');
const INDEX_PATH = require.resolve(path.join(SRC_DIR, 'index'));
if (!require.cache[INDEX_PATH]) {
  require.cache[INDEX_PATH] = {
    id: INDEX_PATH,
    filename: INDEX_PATH,
    loaded: true,
    exports: {
      dbSourceConnection: () => {
        throw new Error(
          'STUB dbSourceConnection() was called. This selftest only exercises pure parsing ' +
          'functions (extractHosts/extractAuthenticatedIps/computeSeverityCountsByHost/' +
          'extractAssetInventoryFacts/extractInnerReport), none of which touch the DB — if you ' +
          'see this, something upstream changed. Stop and re-check the import-safety comment at ' +
          'the top of this file before proceeding.',
        );
      },
    },
  } as unknown as NodeModule;
}

// Required at call time (after the require.cache stub above is in place), not
// via a static top-level `import` — see the import-safety comment above.
const openvasFeeder = require(path.join(SRC_DIR, 'services', 'assetIdentity', 'openvasFeeder')) as {
  computeSeverityCountsByHost: (innerReport: any) => Map<string, import('../../../types/assetIdentity').SeverityCounts>;
  computeSeverityCountsForHost: (innerReport: any, ip: string) => import('../../../types/assetIdentity').SeverityCounts;
  extractAssetInventoryFacts: (innerReport: any) => Map<string, any>;
  extractAuthenticatedIps: (innerReport: any) => Set<string>;
  extractHosts: (innerReport: any) => any[];
  extractInnerReport: (getReportResult: any) => any | null;
};
const {
  computeSeverityCountsByHost,
  computeSeverityCountsForHost,
  extractAssetInventoryFacts,
  extractAuthenticatedIps,
  extractHosts,
  extractInnerReport,
} = openvasFeeder;

// ── extractHosts ────────────────────────────────────────────────────────────

function testExtractHosts() {
  // Baseline: MAC/fqdn/best_os_txt detail names, exactly as GVM names them
  // (not "hostname" -- see OpenvasReportHost's own doc comment on that bug).
  {
    const report = {
      host: {
        ip: '10.0.5.40',
        start: '2026-09-01T10:00:00Z',
        end: '2026-09-01T10:05:00Z',
        detail: [
          { name: 'MAC', value: 'AA:BB:CC:DD:EE:FF' },
          { name: 'fqdn', value: 'desktop-abc123.local' },
          { name: 'best_os_txt', value: 'Microsoft Windows 11 Pro' },
        ],
      },
    };
    const hosts = extractHosts(report);
    assert.strictEqual(hosts.length, 1);
    assert.strictEqual(hosts[0].ip, '10.0.5.40');
    assert.strictEqual(hosts[0].mac, 'AA:BB:CC:DD:EE:FF');
    assert.strictEqual(hosts[0].fqdn, 'desktop-abc123.local');
    assert.strictEqual(hosts[0].os, 'Microsoft Windows 11 Pro');
    assert.deepStrictEqual(hosts[0].netinfoMacs, []);
  }

  // best_os_cpe fallback when best_os_txt is absent.
  {
    const report = {
      host: { ip: '10.0.5.41', detail: [{ name: 'best_os_cpe', value: 'cpe:/o:linux:linux_kernel' }] },
    };
    assert.strictEqual(extractHosts(report)[0].os, 'cpe:/o:linux:linux_kernel');
  }

  // netinfo: raw `ip -o addr`-style text, every MAC-shaped token pulled out
  // regardless of surrounding text, exact-duplicate tokens deduplicated. This
  // layer deliberately does NOT filter broadcast/loopback/docker noise --
  // that is normalizeMac()'s job downstream, once this and the custom-VT MACs
  // are merged (see processOpenvasReportForAssets's own comment on why).
  {
    const netinfoText =
      '1: lo    inet 127.0.0.1/8 scope host lo\n' +
      '2: eth0    link/ether 0c:38:3e:60:94:a7 brd ff:ff:ff:ff:ff:ff\n' +
      '2: eth0    inet 10.0.5.42/24 brd 10.0.5.255 scope global eth0\n' +
      '3: docker0    link/ether 0c:38:3e:60:94:a7 brd ff:ff:ff:ff:ff:ff\n'; // repeated on purpose
    const report = { host: { ip: '10.0.5.42', detail: [{ name: 'netinfo', value: netinfoText }] } };
    const hosts = extractHosts(report);
    assert.deepStrictEqual(
      hosts[0].netinfoMacs,
      ['0c:38:3e:60:94:a7', 'ff:ff:ff:ff:ff:ff'],
      'every MAC-shaped token comes through (noise filtering is normalizeMac\'s job, not this layer\'s); the repeated eth0/docker0 tokens are deduplicated',
    );
  }

  // A host with no ip is dropped entirely rather than surfacing as ip: ''.
  {
    const report = { host: [{ ip: '10.0.5.43' }, { detail: [] }] };
    const hosts = extractHosts(report);
    assert.strictEqual(hosts.length, 1);
    assert.strictEqual(hosts[0].ip, '10.0.5.43');
  }

  // Multiple hosts (the ordinary subnet-scan shape) all come back, each with
  // only its own details.
  {
    const report = {
      host: [
        { ip: '10.0.5.50', detail: [{ name: 'fqdn', value: 'host-a.local' }] },
        { ip: '10.0.5.51', detail: [{ name: 'fqdn', value: 'host-b.local' }] },
      ],
    };
    const hosts = extractHosts(report);
    assert.strictEqual(hosts.length, 2);
    assert.strictEqual(hosts[0].fqdn, 'host-a.local');
    assert.strictEqual(hosts[1].fqdn, 'host-b.local');
  }

  // Absent/malformed report shapes must not throw -- a bad report is a report
  // with zero hosts, not a crashed feeder tick.
  assert.deepStrictEqual(extractHosts(null), []);
  assert.deepStrictEqual(extractHosts({}), []);
  assert.deepStrictEqual(extractHosts({ host: null }), []);
}

// ── extractAuthenticatedIps ─────────────────────────────────────────────────

function testExtractAuthenticatedIps() {
  // The exact verified-live string, case-insensitively, host as a plain string.
  {
    const report = {
      results: {
        result: [
          { nvt: { name: 'SSH Login Successful For Authenticated Checks' }, host: '10.0.5.60' },
          { nvt: { name: 'Some Unrelated NVT' }, host: '10.0.5.61' },
        ],
      },
    };
    const ips = extractAuthenticatedIps(report);
    assert.deepStrictEqual([...ips], ['10.0.5.60']);
  }

  // Lower/mixed case, and the substring-match design intent: any
  // "<Protocol> Login Successful For Authenticated Checks" variant (SMB/WMI/
  // ESXi), not only the one verified live (SSH), must be recognised.
  {
    const report = {
      results: {
        result: [
          { nvt: { name: 'smb login successful for authenticated checks' }, host: '10.0.5.62' },
        ],
      },
    };
    assert.ok(extractAuthenticatedIps(report).has('10.0.5.62'));
  }

  // host as a mixed-content object ({'#text': ip}), the shape GVM uses when a
  // result element carries attributes alongside its text.
  {
    const report = {
      results: {
        result: [
          { nvt: { name: 'SSH Login Successful For Authenticated Checks' }, host: { '#text': '10.0.5.63' } },
        ],
      },
    };
    assert.ok(extractAuthenticatedIps(report).has('10.0.5.63'));
  }

  // No results at all -- an unauthenticated-only scan -- comes back empty,
  // not thrown.
  assert.deepStrictEqual([...extractAuthenticatedIps({ results: {} })], []);
  assert.deepStrictEqual([...extractAuthenticatedIps(null)], []);
}

// ── computeSeverityCountsByHost / computeSeverityCountsForHost ─────────────

function testSeverityCounts() {
  const report = {
    results: {
      result: [
        { host: '10.0.5.70', severity: '9.8' }, // high
        { host: '10.0.5.70', severity: '7.0' }, // high (boundary, inclusive)
        { host: '10.0.5.70', severity: '6.9' }, // medium (just under high)
        { host: '10.0.5.70', severity: '4.0' }, // medium (boundary, inclusive)
        { host: '10.0.5.70', severity: '3.9' }, // low (just under medium)
        { host: '10.0.5.70', severity: '0.1' }, // low
        { host: '10.0.5.70', severity: '0.0' }, // log (boundary)
        { host: '10.0.5.70', severity: '' },    // log (unparseable -> NaN -> falls to else)
        { host: '10.0.5.71', severity: '10.0' }, // a different host entirely
      ],
    },
  };

  const byHost = computeSeverityCountsByHost(report);
  assert.deepStrictEqual(byHost.get('10.0.5.70'), { high: 2, medium: 2, low: 2, log: 2 });
  assert.deepStrictEqual(byHost.get('10.0.5.71'), { high: 1, medium: 0, low: 0, log: 0 });
  assert.strictEqual(byHost.get('10.0.5.99'), undefined, 'a host with no results is simply absent, not a zeroed entry');

  // The single-host lookup must agree with the bucket-once map for every host
  // -- this is the exact invariant the O(hosts x results) -> O(results)
  // refactor must not break.
  for (const ip of ['10.0.5.70', '10.0.5.71']) {
    assert.deepStrictEqual(computeSeverityCountsForHost(report, ip), byHost.get(ip));
  }
  assert.deepStrictEqual(computeSeverityCountsForHost(report, '10.0.5.99'), { high: 0, medium: 0, low: 0, log: 0 });
}

// ── extractAssetInventoryFacts ──────────────────────────────────────────────

function testExtractAssetInventoryFacts() {
  const NETWORK_OID = '1.3.6.1.4.1.25623.1.0.999905';
  const OS_OID = '1.3.6.1.4.1.25623.1.0.999901';
  const SERIAL_OID = '1.3.6.1.4.1.25623.1.0.999917';
  const MACS_OID = '1.3.6.1.4.1.25623.1.0.999920';

  const report = {
    results: {
      result: [
        {
          host: '10.0.5.80',
          nvt: { family: 'Asset Inventory', '@_oid': NETWORK_OID },
          description: 'Hostname\n--------\nreal-server-01\n\nsomething else after',
        },
        {
          host: '10.0.5.80',
          nvt: { family: 'Asset Inventory', '@_oid': MACS_OID },
          description: 'MAC Addresses\n-------------\n0c:38:3e:60:94:a7\n0c:38:3e:60:94:a7\naa:bb:cc:dd:ee:ff\n',
        },
        {
          host: '10.0.5.80',
          nvt: { family: 'Asset Inventory', '@_oid': SERIAL_OID },
          description:
            'Serial Numbers\n--------------\nUUID     : 4c4c4544-0054-5a10-8052-b7c04f374a33\n\n' +
            'OS Machine ID (not hardware serial/UUID - unique per OS install)\n' +
            '-------------------------------------------------------------------\n' +
            'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n',
        },
        {
          host: '10.0.5.80',
          nvt: { family: 'Asset Inventory', '@_oid': OS_OID },
          description: 'Operating System\n----------------\nUbuntu 22.04.3 LTS\n\n',
        },
        // A different host's Network VT result must not leak into 10.0.5.80's facts.
        {
          host: '10.0.5.81',
          nvt: { family: 'Asset Inventory', '@_oid': NETWORK_OID },
          description: 'Hostname\n--------\nother-host\n\n',
        },
        // Ignored on purpose: "Summary" (family matches, OID doesn't).
        {
          host: '10.0.5.80',
          nvt: { family: 'Asset Inventory', '@_oid': '1.3.6.1.4.1.25623.1.0.999999' },
          description: 'Summary\n-------\nlots of unrelated stuff\n',
        },
        // Ignored: not Asset Inventory at all.
        {
          host: '10.0.5.80',
          nvt: { family: 'General', '@_oid': '1.2.3.4' },
          description: 'irrelevant',
        },
      ],
    },
  };

  const byHost = extractAssetInventoryFacts(report);
  const facts = byHost.get('10.0.5.80')!;
  assert.strictEqual(facts.hostname, 'real-server-01');
  assert.deepStrictEqual(facts.macs, ['0c:38:3e:60:94:a7', 'aa:bb:cc:dd:ee:ff'], 'repeated MAC token deduplicated, order preserved');
  assert.strictEqual(facts.biosUuidCandidate, '4c4c4544-0054-5a10-8052-b7c04f374a33');
  assert.strictEqual(facts.machineId, 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6');
  assert.strictEqual(facts.osPretty, 'Ubuntu 22.04.3 LTS');

  assert.strictEqual(byHost.get('10.0.5.81')!.hostname, 'other-host');
  assert.strictEqual(byHost.get('10.0.5.81')!.macs.length, 0, 'a host with only a Network VT result has no MAC facts');

  // "unknown"/blank Serial Numbers output (the common real-world case per
  // SERIAL_UUID_RE's own doc comment -- most hosts lack passwordless sudo)
  // must not be captured as a real value.
  {
    const blankReport = {
      results: {
        result: [
          {
            host: '10.0.5.90',
            nvt: { family: 'Asset Inventory', '@_oid': SERIAL_OID },
            description:
              'Serial Numbers\n--------------\nUUID     : sudo: a password is required\n\n' +
              'OS Machine ID (not hardware serial/UUID - unique per OS install)\n' +
              '-------------------------------------------------------------------\n' +
              'unknown\n',
          },
        ],
      },
    };
    const blankFacts = extractAssetInventoryFacts(blankReport).get('10.0.5.90')!;
    assert.strictEqual(blankFacts.biosUuidCandidate, 'sudo: a password is required', 'not normalizeBiosUuid\'s job here -- capture is raw, rejection happens downstream');
    assert.strictEqual(blankFacts.machineId, null, '"unknown" is an isBlankInventoryValue and must not be captured');
  }

  // A result recognised by OID prefix even when family is something else
  // (the "OR OID prefix" half of the recognition rule).
  {
    const prefixReport = {
      results: {
        result: [
          {
            host: '10.0.5.91',
            nvt: { family: 'Some Other Family', '@_oid': NETWORK_OID },
            description: 'Hostname\n--------\nprefix-matched\n\n',
          },
        ],
      },
    };
    assert.strictEqual(extractAssetInventoryFacts(prefixReport).get('10.0.5.91')!.hostname, 'prefix-matched');
  }

  // No results at all comes back as an empty map, not thrown.
  assert.strictEqual(extractAssetInventoryFacts({ results: {} }).size, 0);
}

// ── extractInnerReport ───────────────────────────────────────────────────────

function testExtractInnerReport() {
  // report.report present (the ordinary shape).
  assert.deepStrictEqual(
    extractInnerReport({ get_report_response: { report: { report: { host: [] } } } }),
    { host: [] },
  );
  // report.report absent -- the report element itself IS the body (GVM's
  // documented inconsistency, per this module's own comment).
  assert.deepStrictEqual(
    extractInnerReport({ get_report_response: { report: { host: [] } } }),
    { host: [] },
  );
  // get_reports_response (plural) wrapper, and a report array instead of a
  // single object.
  assert.deepStrictEqual(
    extractInnerReport({ get_reports_response: { report: [{ report: { host: [] } }] } }),
    { host: [] },
  );
  // No report at all -> null, never thrown.
  assert.strictEqual(extractInnerReport({}), null);
  assert.strictEqual(extractInnerReport(null), null);
}

function main() {
  testExtractHosts();
  testExtractAuthenticatedIps();
  testSeverityCounts();
  testExtractAssetInventoryFacts();
  testExtractInnerReport();
  console.log('openvasFeeder.selftest: all checks passed');
}

main();
