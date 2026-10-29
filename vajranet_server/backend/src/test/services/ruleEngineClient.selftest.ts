/**
 * Regression test for a real, high-severity bug found by adversarial review
 * (docs/team/vajranet-sage.md, Finding 1): every path-parameterized function in
 * services/ruleEngineClient.ts built its outbound URL via
 * `encodeURIComponent(param)` spliced into a template literal. encodeURIComponent
 * does NOT escape `.`, so a param value of exactly ".." passed through unchanged,
 * sitting between two literal "/" characters from the template string. Express
 * captures ".." as an ordinary literal route param — but axios/Node's own URL
 * resolution against the axios baseURL DOES apply RFC 3986 dot-segment
 * collapsing to that literal "/../" sequence, landing the outbound request on a
 * completely different far-side path than the one the function's caller built
 * (e.g. GET /api/rules/../health actually reached /api/health on the engine
 * host). Reachable by ANY authenticated user on the checkAccessJwt-only GET
 * routes (GET /rules/:source/:id, GET /correlation-rules/:source/:id).
 *
 * Fix: checkSegments()/invalidPathSegment() in ruleEngineClient.ts reject any
 * segment that is exactly "." or ".." or contains a literal "/" or "\", BEFORE
 * a request is ever built — resolving a clean {status: 400, unreachable: false}
 * synchronously, with no axios call made at all.
 *
 * This test proves the "no axios call made at all" half directly: it replaces
 * axios.create with a spy BEFORE any ruleEngineClient function is called, then
 * asserts the spy is invoked zero times for every malicious path-parameterized
 * call, and only reaches 1 once a single legitimate call is made at the end
 * (proving the guard doesn't also break real, safe calls). This has to be a
 * fresh, isolated process (its own ts-node invocation) rather than sharing
 * ruleEngineTools.selftest.ts's process: that file's live check populates
 * ruleEngineClient's internal axios-instance cache before this file's checks
 * could run, which would make an axios.create() spy here observe 0 calls for
 * the wrong reason (cache hit) rather than the real one (guard short-circuit).
 *
 *   node_modules/.bin/ts-node src/test/services/ruleEngineClient.selftest.ts
 *
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';

// A guaranteed-non-routable test address (RFC 5737 TEST-NET-1) — belt-and-
// suspenders in case the axios.create spy below ever has a bug: a real call
// would hang/fail against a documented black-hole address, never reach a real
// host, regardless of what this env var is set to.
process.env.RULE_ENGINE_API_URL = 'http://192.0.2.1:8001';

import axios from 'axios';

let axiosCreateCalls = 0;
const originalCreate = axios.create.bind(axios);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(axios as any).create = (config: any) => {
  axiosCreateCalls++;
  const instance = originalCreate(config);
  // Never let a "happy path" call in this test actually hit the network either
  // — resolve a fake 200 immediately so the test can't hang or flake on a
  // real DNS/connect timeout.
  instance.request = (async () => ({ status: 200, data: { ok: true, fake: true } })) as typeof instance.request;
  return instance;
};

// Imported AFTER the spy is installed, so ruleEngineClient's lazily-created
// axios instance (built on first use inside client()) is always the spied one.
import * as ruleEngineClient from '../../services/ruleEngineClient';

async function assertRejectedWithoutNetworkCall(
  label: string,
  call: () => Promise<{ unreachable: boolean; status: number; data: unknown }>,
) {
  const before = axiosCreateCalls;
  const result = await call();
  assert.strictEqual(result.unreachable, false, `${label}: unreachable must be false (this is a guard rejection, not a network failure)`);
  assert.strictEqual(result.status, 400, `${label}: must resolve a clean 400`);
  assert.ok(
    typeof (result.data as any)?.error === 'string' && (result.data as any).error.length > 0,
    `${label}: must carry a specific error message, not a blank body`,
  );
  assert.strictEqual(axiosCreateCalls, before, `${label}: must NOT have called axios.create() / made any outbound network attempt`);
}

async function main() {
  // ── The exact repro from Sage's report: GET /rules/../health ────────────
  await assertRejectedWithoutNetworkCall('getRule(".." , "health")', () => ruleEngineClient.getRule('..', 'health'));
  // Fully-degenerate case from the report: collapses to the engine root "/".
  await assertRejectedWithoutNetworkCall('getRule("..", "..")', () => ruleEngineClient.getRule('..', '..'));
  // Single dot-segment is also rejected (not just "..").
  await assertRejectedWithoutNetworkCall('getRule(".", "health")', () => ruleEngineClient.getRule('.', 'health'));
  // Embedded literal slash/backslash (defense in depth, per Sage's exact ask).
  await assertRejectedWithoutNetworkCall('getRule("a/b", "id")', () => ruleEngineClient.getRule('a/b', 'id'));
  await assertRejectedWithoutNetworkCall('getRule("a\\\\b", "id")', () => ruleEngineClient.getRule('a\\b', 'id'));

  // ── Every other path-parameterized function in the module ───────────────
  await assertRejectedWithoutNetworkCall('patchRule', () => ruleEngineClient.patchRule('..', '1', { enabled: false }));
  await assertRejectedWithoutNetworkCall('deleteRule', () => ruleEngineClient.deleteRule('..', '1'));
  await assertRejectedWithoutNetworkCall('getCorrelationRule', () => ruleEngineClient.getCorrelationRule('..', '1'));
  await assertRejectedWithoutNetworkCall('patchCorrelationRule', () => ruleEngineClient.patchCorrelationRule('..', '1', { enabled: false }));
  await assertRejectedWithoutNetworkCall('patchIpWatchGroup', () => ruleEngineClient.patchIpWatchGroup('..', { enabled: false }));
  await assertRejectedWithoutNetworkCall('deleteIpWatchGroup', () => ruleEngineClient.deleteIpWatchGroup('..'));
  await assertRejectedWithoutNetworkCall('listIpWatchGroupIps', () => ruleEngineClient.listIpWatchGroupIps('..', {}));
  await assertRejectedWithoutNetworkCall('addIpWatchGroupIps', () => ruleEngineClient.addIpWatchGroupIps('..', { ips: ['1.2.3.4'] }));
  await assertRejectedWithoutNetworkCall('deleteIpWatchGroupIp (name)', () => ruleEngineClient.deleteIpWatchGroupIp('..', '1.2.3.4'));
  await assertRejectedWithoutNetworkCall('deleteIpWatchGroupIp (ip)', () => ruleEngineClient.deleteIpWatchGroupIp('finance_servers', '..'));
  await assertRejectedWithoutNetworkCall('importIpWatchGroupIpsCsv', () => ruleEngineClient.importIpWatchGroupIpsCsv('..', Buffer.from('1.2.3.4'), 'x.csv', 'text/csv'));
  await assertRejectedWithoutNetworkCall('patchThreatIntelFeed', () => ruleEngineClient.patchThreatIntelFeed('..', { enabled: false }));
  await assertRejectedWithoutNetworkCall('deleteThreatIntelFeed', () => ruleEngineClient.deleteThreatIntelFeed('..'));
  await assertRejectedWithoutNetworkCall('previewThreatIntelFeed', () => ruleEngineClient.previewThreatIntelFeed('..'));

  console.log(`ruleEngineClient.selftest: all ${18} malicious-segment calls rejected with a clean 400 and zero outbound network attempts`);

  // ── Negative control: a real, safe call must still go through ───────────
  assert.strictEqual(axiosCreateCalls, 0, 'sanity: no axios.create() call should have happened yet');
  const safeResult = await ruleEngineClient.getRule('sigma_windows_process_creation', '624');
  assert.strictEqual(axiosCreateCalls, 1, 'a legitimate call must still reach the network layer (axios.create() called exactly once)');
  assert.strictEqual(safeResult.unreachable, false);
  assert.strictEqual(safeResult.status, 200, 'the spied axios instance returns a fake 200 — proves the guard let a safe call all the way through to request()');

  console.log('ruleEngineClient.selftest: a legitimate (non-malicious) path segment still reaches the network layer normally — guard is not over-broad');
  console.log('ruleEngineClient.selftest: all checks passed');
}

main().then(() => process.exit(0)).catch((err) => {
  console.error('ruleEngineClient.selftest FAILED:', err);
  process.exit(1);
});
