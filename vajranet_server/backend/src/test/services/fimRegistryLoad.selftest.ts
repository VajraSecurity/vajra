/**
 * Synthetic scale check for the registry reconcile job against a THROWAWAY Postgres (never production):
 *   FIM_TEST_PG=127.0.0.1:55432 FIM_LOAD_NODES=15000 node_modules/.bin/ts-node src/test/services/fimRegistryLoad.selftest.ts
 * Seeds FIM_LOAD_NODES Windows nodes (prefix fimload-, 50 groups), then measures:
 *   - loadLayerData + resolveFor for every node (pure resolution cost),
 *   - a cold sweep (every node resolved, effective rows written; time-boxed by FIM_REG_SWEEP_BUDGET_MS),
 *   - a warm sweep (inputs cache: no resolution, no writes),
 *   - the publish rate (FIM_LOAD_PUBLISH nodes, default 200) and the set-based backout of them.
 * Asserts the warm sweep writes nothing and finishes well inside the 60 s reconcile interval.
 * Without FIM_TEST_PG it FAILS unless FIM_ALLOW_SKIP=1. Removes everything it created.
 */
import 'reflect-metadata';
import assert from 'assert';
// Pass 1 would otherwise onboard 200 nodes per sweep; the scale question is pass 2 (status of all).
process.env.FIM_REG_AUTO_PUBLISH_PER_SWEEP = process.env.FIM_REG_AUTO_PUBLISH_PER_SWEEP || '1';
import { openFimTestDb } from './fimTestDb';
import { monitorEventLoopDelay } from 'perf_hooks';
import * as svc from '../../services/fimService';
import * as reg from '../../services/fimRegistryService';
import { FIM_REG_SWEEP_BUDGET_MS } from '../../services/fimRegistryService';
import { FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL } from '../../utils/fim/fimRegistryDdl';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set; set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}
const N = Math.max(100, Number(process.env.FIM_LOAD_NODES) || 5000);
const PUB = Math.min(N, Math.max(10, Number(process.env.FIM_LOAD_PUBLISH) || 200));
const P = 'fimload';
/** FIM_LOAD_INVALID=1: every node's resolution is INVALID (one bad rule on the nodes' profile). */
const INVALID = process.env.FIM_LOAD_INVALID === '1';
/** Max acceptable event-loop stall during a sweep (ms). */
const MAX_STALL_MS = Number(process.env.FIM_LOAD_MAX_STALL_MS) || 150;
async function measured<T>(fn: () => Promise<T>): Promise<{ v: T; ms: number; maxStall: number }> {
  const h = monitorEventLoopDelay({ resolution: 5 });
  h.enable();
  const t = Date.now();
  const v = await fn();
  const ms = Date.now() - t;
  h.disable();
  return { v, ms, maxStall: Math.round(h.max / 1e6) };
}

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  const db = ds as unknown as svc.FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  await q(FIM_REGISTRY_DDL);
  await q(FIM_VERIFY_DDL);
  await q(FIM_WORKER_DDL);
  await q(FIM_PERF_DDL);
  await q('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_group_id text');
  const SA = { ...reg.systemActor(`${P}-req`), email: `${P}-sa@x`, userId: 9901 };
  const orig = (await q('SELECT managed_enabled FROM fim_reg_settings WHERE id'))[0]?.managed_enabled ?? false;
  const cleanup = async () => {
    await q('UPDATE fim_reg_settings SET managed_enabled = $1 WHERE id', [orig]);
    const pols = await q(`SELECT config_query_id FROM fim_policies WHERE managed_host LIKE $1 AND config_query_id IS NOT NULL`, [`${P}%`]);
    if (pols.length) await q('DELETE FROM config_queries WHERE id = ANY($1::bigint[])', [pols.map((p: any) => p.config_query_id)]);
    await q(`DELETE FROM fim_policies WHERE managed_host LIKE $1`, [`${P}%`]);
    for (const t of ['fim_reg_slots', 'fim_reg_effective']) await q(`DELETE FROM ${t} WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_rules WHERE scope_value LIKE $1 OR created_by LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_assignments WHERE scope_value LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_profiles WHERE name LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM alerts WHERE host_identifier LIKE $1 OR metadata LIKE $2`, [`${P}%`, `%${P}-%`]);
    await q(`DELETE FROM fim_audit WHERE actor LIKE $1 OR details->>'host' LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`]);
    await ds.transaction(async (m) => {
      await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
      await m.query(`DELETE FROM fim_reg_history WHERE actor LIKE $1 OR scope_value LIKE $1`, [`${P}%`]);
    });
  };
  await cleanup();
  const ms = (t: number) => `${Date.now() - t} ms`;
  try {
    let t = Date.now();
    await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname)
             SELECT $1 || lpad(g::text, 6, '0'), 'windows', $1 || '-g' || (g % 50), $1 || lpad(g::text, 6, '0'), $1 || lpad(g::text, 6, '0') FROM generate_series(1, $2::int) g`, [`${P}-`, N]);
    // some layer variety: 50 group rules
    for (let g = 0; g < 50; g++) {
      await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('group', $1, 'add', $2, '{}'::jsonb, 'load', $3, 1)`,
        [`${P}--g${g}`, g % 2 ? 'reg.netsh' : 'reg.aedebug', `${P}-seed`]);
    }
    if (INVALID) {
      // all load groups use one profile whose two custom rules overlap -> every node invalid
      const pid = (await q(`INSERT INTO fim_reg_profiles (name, tier, is_default, created_by, updated_by) VALUES ($1, 'essential', false, $1, $1) RETURNING id`, [`${P}-invalid`]))[0].id;
      for (const [i, path] of [`HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\%\\Cfg`, `HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\Prod\\%`].entries()) {
        const { customEntryKey } = await import('../../utils/fim/fimRegistrySql');
        await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('profile', $1, 'add', $2, $3::jsonb, 'load', $4, 1)`,
          [String(pid), customEntryKey(path), JSON.stringify({ path, severity: 'high', measureOverride: true }), `${P}-seed-${i}`]);
      }
      for (let g = 0; g < 50; g++) await q(`INSERT INTO fim_reg_assignments (scope_type, scope_value, profile_id, updated_by) VALUES ('group', $1, $2, $3)`, [`${P}--g${g}`, pid, `${P}-seed`]);
      // one HEALTHY new node queued behind all invalid ones (sorts last): it must not be starved
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [`${P}-zzz-healthy`, `${P}-healthy-group`, `${P}-zzz-healthy`, `${P}-zzz-healthy`]);
    }
    console.log(`seed: ${N} nodes in ${ms(t)}${INVALID ? ' (all INVALID)' : ''}`);
    await q(`UPDATE fim_reg_settings SET managed_enabled = true WHERE id`);
    const only = new Set<string>((await q(`SELECT host_identifier FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`])).map((r: any) => r.host_identifier));

    t = Date.now();
    const data = await reg.loadLayerData(db);
    const tLoad = Date.now() - t;
    const nodes = (await q(`SELECT host_identifier AS host, owner_group_id AS "ownerGroupId", os_platform FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`]));
    t = Date.now();
    let entries = 0;
    for (const nd of nodes) entries += reg.resolveFor({ host: nd.host, ownerGroupId: nd.ownerGroupId, hostname: nd.host }, data, {}).entries.length;
    const tResolve = Date.now() - t;
    console.log(`resolution: loadLayerData ${tLoad} ms; resolveFor x${N} ${tResolve} ms (${(tResolve / N).toFixed(2)} ms/node, ${(entries / N).toFixed(1)} entries/node)`);

    reg.resetReconcileTimers();
    const coldM = await measured(() => reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only }));
    const cold = coldM.v;
    console.log(`cold sweep: ${coldM.ms} ms, max event-loop stall ${coldM.maxStall} ms ${JSON.stringify(cold)}`);
    assert.ok(coldM.maxStall < MAX_STALL_MS, `cold sweep stalled the event loop ${coldM.maxStall} ms`);
    if (INVALID) {
      // Every invalid node is resolved at most once (its result is recorded by input digest), so a
      // healthy new node queued behind them is covered within the first sweep(s): the first for
      // 3,000 invalid nodes; at 15,000 the pre-checks span about 4 half-budget passes.
      const maxSweeps = Math.max(1, Math.ceil((N * 6) / (FIM_REG_SWEEP_BUDGET_MS / 2)));
      let sweeps = 1;
      let hp = (await q(`SELECT enabled FROM fim_policies WHERE managed_host = $1`, [`${P}-zzz-healthy`]))[0];
      while (!hp?.enabled && sweeps < maxSweeps + 1) {
        await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
        sweeps++;
        hp = (await q(`SELECT enabled FROM fim_policies WHERE managed_host = $1`, [`${P}-zzz-healthy`]))[0];
      }
      console.log(`healthy node behind ${N} invalid new nodes covered after ${sweeps} sweep(s) (bound ${maxSweeps})`);
      assert.ok(hp?.enabled, 'a healthy new node is never starved by invalid ones');
      if (N <= 3000) assert.strictEqual(sweeps, 1, 'covered in the FIRST sweep');
    }
    let resumed = 0;
    while ((await q(`SELECT count(*) AS c FROM fim_reg_effective WHERE host_identifier LIKE $1`, [`${P}%`]))[0].c < N && resumed < 10) {
      t = Date.now();
      const more = await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      resumed++;
      console.log(`  resumed sweep ${resumed}: ${ms(t)} nodes=${more.nodes} writes=${more.writes} timeBoxed=${!!more.timeBoxed}`);
    }
    const warmM = await measured(() => reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only }));
    const warm = warmM.v;
    const tWarm = warmM.ms;
    console.log(`warm sweep: ${tWarm} ms, max event-loop stall ${warmM.maxStall} ms ${JSON.stringify(warm)}`);
    assert.ok(warmM.maxStall < MAX_STALL_MS, `warm sweep stalled the event loop ${warmM.maxStall} ms`);
    if (INVALID) {
      assert.strictEqual(warm.resolved, 0, 'unchanged invalid nodes are never re-resolved');
      const alerts = (await q(`SELECT count(*)::int AS n FROM alerts WHERE alert_type = 'fim_config' AND event_code LIKE 'FIM registry coverage invalid for over an hour%' AND metadata LIKE $1`, [`%${P}-%`]))[0].n;
      console.log(`invalid-over-1h alerts (expected 0 now: nodes just became invalid): ${alerts}`);
      await q(`UPDATE fim_reg_effective SET invalid_since = 1 WHERE host_identifier LIKE $1`, [`${P}%`]);
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      const after = (await q(`SELECT count(*)::int AS n FROM alerts WHERE alert_type = 'fim_config' AND is_open AND event_code LIKE 'FIM registry coverage invalid for over an hour%' AND metadata LIKE $1`, [`%${P}-%`]))[0].n;
      console.log(`invalid-over-1h alerts for ${N} invalid nodes: ${after}`);
      assert.strictEqual(after, 1, 'one alert per cause, not one per node');
      await q(`DELETE FROM alerts WHERE alert_type = 'fim_config' AND event_code LIKE 'FIM registry coverage invalid for over an hour%' AND metadata LIKE $1`, [`%${P}-%`]);
    }
    assert.strictEqual(warm.writes, 0, `warm sweep wrote ${warm.writes} rows`);
    assert.ok(warm.cached >= warm.nodes - 2, 'warm sweep served from the inputs cache');
    assert.ok(tWarm < 30_000, 'warm sweep well inside the 60 s interval');

    if (INVALID) { console.log(`\nload check passed (N=${N}, invalid)`); return; }
    const hosts = [...only].sort().slice(0, PUB);
    t = Date.now();
    for (const h of hosts) await reg.publishNode(db, h, { actor: SA, note: 'load' });
    const tPub = Date.now() - t;
    console.log(`publish: ${PUB} nodes in ${tPub} ms (${(tPub / PUB).toFixed(1)} ms/node)`);
    t = Date.now();
    const off = await reg.setManagedEnabled(db, false, SA, 'load backout');
    console.log(`backout (set-based): ${off.disabledPolicies} policies in ${ms(t)}`);
    assert.ok(off.disabledPolicies >= PUB);
    console.log(`\nload check passed (N=${N})`);
  } finally {
    await cleanup();
    await tdb.drop();
  }
})().catch((err) => { console.error(err); process.exit(1); });
