/**
 * Final-round regression tests (DB-backed, throwaway Postgres; own database per process):
 *   FIM_TEST_PG=127.0.0.1:55432 node_modules/.bin/ts-node src/test/services/fimRound6.selftest.ts
 *  F5  job resume with mixed-case / punctuation host ids never skips nodes
 *  F6  no-op re-apply of 0005-0008 takes no exclusive lock (readers on every table)
 *  F1  a least-privilege app role boots without DDL privileges; missing schema -> 'migration required'
 *  F3  concurrent overlapping rule creation is serialised (one wins)
 *  F7  a dead-letter row tagged with another host does not fail a measurement
 *  key fingerprint rows are required for every key id; daily invariant check alerts
 */
import 'reflect-metadata';
import assert from 'assert';
import { DataSource } from 'typeorm';
import * as svc from '../../services/fimService';
import * as reg from '../../services/fimRegistryService';
import { FIM_BASE_DDL, FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL } from '../../utils/fim/fimRegistryDdl';
import { openFimTestDb } from './fimTestDb';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set; set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}
process.env.FIM_HISTORY_HMAC_KEY = process.env.FIM_HISTORY_HMAC_KEY || 'fimr6test-history-key-0123456789abcdef';
const P = 'fimr6';
const H = (s: string) => `${P}-${s}`;
const L = 'HKEY_LOCAL_MACHINE\\';
const APP_ROLE = `fimr6_app_${process.pid}`;
const SA: reg.RegActor = { email: `${P}-sa@x`, userId: 9201, superAdmin: true, actGroups: new Set(), actHosts: null, viewHosts: null, viewGroups: new Set(), requestId: `${P}-req` };
const BLOCKS: [string, string][] = [['0004_fim_base', FIM_BASE_DDL], ['0005_fim_registry', FIM_REGISTRY_DDL], ['0006_fim_verify', FIM_VERIFY_DDL], ['0007_fim_worker_schema', FIM_WORKER_DDL], ['0008_fim_perf', FIM_PERF_DDL]];

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  const db = ds as unknown as svc.FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  let n = 0;
  const ok = (m: string) => { n++; console.log(`ok - ${m}`); };
  let appDs: DataSource | null = null;
  try {
    for (const [name, b] of BLOCKS) await reg.applyFimDdl(db, name, b);
    await reg.setManagedEnabled(db, true, SA, 'enable');

    // --- F5: job resume ordering ------------------------------------------------------------------------
    {
      // mixed case / punctuation: DB collation order differs from code-unit order
      // The first chunk (in the DB collation, case-insensitive) ends on a LOWER-case id; the rest are
      // UPPER-case ids that sort BEFORE it in code-unit order (the old resume skipped exactly those).
      const ids = [...Array.from({ length: 19 }, (_, i) => `${P}a-${String(i).padStart(2, '0')}`), `${P}b_x`,
        ...Array.from({ length: 25 }, (_, i) => `${P}C.${String(i).padStart(2, '0')}`)];
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) SELECT h, 'windows', $2, h, h FROM unnest($1::text[]) h`, [ids, H('gJ')]);
      const pj = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-job`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      await reg.putAssignment(db, 'group', H('gJ'), { profileId: pj.profile.id, reason: 'x' }, SA);
      const job = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'resume order', (await reg.currentProfileDigest(db, pj.profile.id))!);
      const run1 = reg.runRegistryJob(db, job.id);
      // "crash" right after the first chunk's progress (and cursor) was committed
      for (let i = 0; i < 600 && (await reg.getJob(db, job.id, SA)).done < reg.FIM_REG_JOB_CHUNK; i++) await new Promise((r) => setTimeout(r, 10));
      await q(`UPDATE fim_reg_jobs SET lease_token = 'dead-runner', heartbeat_at = 1 WHERE id = $1`, [job.id]);
      await run1;
      await reg.resumeRegistryJobs(db);
      for (let i = 0; i < 600 && (await reg.getJob(db, job.id, SA)).status === 'running'; i++) await new Promise((r) => setTimeout(r, 50));
      const jd = await reg.getJob(db, job.id, SA);
      const published = (await q(`SELECT managed_host FROM fim_policies WHERE managed_host = ANY($1)`, [ids])).map((r: any) => r.managed_host).sort();
      assert.deepStrictEqual(ids.filter((x) => !published.includes(x)), [], 'nodes skipped by the resume');
      assert.strictEqual(jd.status, 'done');
    }
    ok('F5: a resumed profile job publishes every node (mixed case, punctuation; ordering and cursor use one comparator)');

    // --- F6: no-op re-apply of 0005-0008 never waits for readers -----------------------------------------
    {
      const runner = ds.createQueryRunner();
      await runner.connect();
      await runner.startTransaction();
      for (const t of ['fim_policies', 'fim_drift', 'fim_baseline', 'fim_host_state', 'fim_host_entry', 'fim_reg_settings', 'fim_reg_waivers', 'fim_reg_effective', 'fim_reg_history', 'fim_reg_measure', 'fim_reg_jobs', 'fim_reg_rules', 'fim_reg_history_keys', 'fim_reg_anchor_outbox', 'fim_reg_history_hwm', 'fim_audit', 'fim_verify_requests', 'fim_init_requests', 'fim_cursor_gaps', 'alerts']) {
        await runner.query(`SELECT count(*) FROM ${t}`);
      }
      for (const [name, ddl] of BLOCKS.filter(([n]) => /^000[5-8]/.test(n))) {
        await q(`DELETE FROM fim_schema_applied WHERE name = $1`, [name]);
        const t0 = Date.now();
        await reg.applyFimDdl(db, name, ddl);
        const ms = Date.now() - t0;
        assert.ok(ms < 3000, `${name}: the no-op re-apply waited ${ms} ms for a reader (exclusive lock)`);
      }
      // a worker-like writer is not blocked behind a forced no-op re-apply either
      const writer = (async () => { const t0 = Date.now(); await ds.transaction(async (m) => { await m.query(`SET LOCAL lock_timeout = '2s'`); await m.query(`UPDATE fim_reg_settings SET updated_at = updated_at WHERE id`); }); return Date.now() - t0; })();
      await q(`DELETE FROM fim_schema_applied WHERE name = '0005_fim_registry'`);
      await reg.applyFimDdl(db, '0005_fim_registry', FIM_REGISTRY_DDL);
      assert.ok((await writer) < 2000);
      await runner.rollbackTransaction();
      await runner.release();
    }
    ok('F6: a no-op re-apply of 0005-0008 takes no exclusive lock (open readers on every FIM table do not block it)');

    // --- F1: least-privilege app role -------------------------------------------------------------------
    {
      const dbName = tdb.name;
      await q(`DROP ROLE IF EXISTS ${APP_ROLE}`);
      await q(`CREATE ROLE ${APP_ROLE} LOGIN`);
      await q(`REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
      await q(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
      await q(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
      await q(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);
      const [host, port] = addr!.split(':');
      appDs = new DataSource({ type: 'postgres', host, port: Number(port), username: APP_ROLE, database: dbName });
      await appDs.initialize();
      const adb = appDs as unknown as svc.FimDb;
      reg.setRegistryDisabled(null);
      // first boot after a psql deploy: no stored hashes at all - the state check must decide
      await q('DELETE FROM fim_schema_applied');
      const boot = await reg.bootFimSchema(adb, BLOCKS);
      assert.ok(boot.ok, JSON.stringify(boot));
      assert.strictEqual(reg.registryDisabledReason(), null, 'an up-to-date schema boots without any DDL privilege');
      assert.strictEqual(Number((await q('SELECT count(*) AS c FROM fim_schema_applied'))[0].c), BLOCKS.length, 'block hashes recorded without running DDL');
      // the owner has not applied a migration yet: precise 'migration required', no exception, no retry loop
      await q('ALTER TABLE fim_drift DROP COLUMN last_realtime_at');
      const boot2 = await reg.bootFimSchema(adb, BLOCKS);
      assert.ok(boot2.ok, 'ok=true: no background retry loop for missing privileges');
      assert.ok(/FIM migration required: run sql\/migrations 0004-0008/.test(reg.registryDisabledReason() ?? ''), reg.registryDisabledReason() ?? 'null');
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND event_code LIKE 'FIM migration required%'`))[0].c), 1);
      // owner applies the migration -> the next boot (app role) is fine again
      await q(`DELETE FROM fim_schema_applied WHERE name = '0008_fim_perf'`);
      await reg.applyFimDdl(db, '0008_fim_perf', FIM_PERF_DDL);
      await q(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
      reg.setRegistryDisabled(null);
      assert.ok((await reg.bootFimSchema(adb, BLOCKS)).ok);
      assert.strictEqual(reg.registryDisabledReason(), null);
      await appDs.destroy();
      appDs = null;
    }
    ok('F1: a non-owner app role without CREATE boots an up-to-date schema; a missing migration gives a precise migration-required alert (no retry loop)');

    // --- F3: concurrent overlapping rule creation ---------------------------------------------------------
    {
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [H('w1'), H('gA'), H('w1'), H('w1')]);
      const a = { path: `${L}SOFTWARE\\Acme\\%\\Cfg`, severity: 'high', measureOverride: true };
      const b = { path: `${L}SOFTWARE\\Acme\\Prod\\%`, severity: 'high', measureOverride: true };
      const res = await Promise.allSettled([a, b].map((spec) => reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec, reason: 'race' }, SA)));
      assert.deepStrictEqual(res.map((r) => r.status).sort(), ['fulfilled', 'rejected'], JSON.stringify(res.map((r) => (r.status === 'rejected' ? String(r.reason) : 'ok'))));
      assert.notStrictEqual((await reg.publishNode(db, H('w1'), { actor: SA, note: 'race result' })).status, 'invalid');
    }
    ok('F3: two concurrent overlapping node rules: exactly one is accepted, the node stays valid');

    // --- F7: getMeasure host-scoped dead-letter rows ------------------------------------------------------
    {
      const m = (await reg.requestMeasure(db, H('w1'), ['reg.netsh'], SA))[0];
      const qid = (await q('SELECT queue_id FROM fim_reg_measure WHERE id = $1', [m.id]))[0].queue_id;
      await q(`INSERT INTO dead_letter_queue (table_name, error_message, event_data) VALUES ($1, $2, '{}')`, [String(qid), `distributed query failed on host ${H('other')} (status=1): forged`]);
      assert.strictEqual((await reg.getMeasure(db, m.id, SA)).status, 'pending', 'another host\'s failure row is ignored');
      await q(`INSERT INTO dead_letter_queue (table_name, error_message, event_data) VALUES ($1, $2, '{}')`, [String(qid), `distributed query failed on host ${H('w1')} (status=1): real`]);
      assert.strictEqual((await reg.getMeasure(db, m.id, SA)).status, 'failed');
    }
    ok('F7: a dead-letter row tagged with another host never fails a measurement; the own host\'s row does');

    // --- key fingerprint row required; daily invariant check alerts -----------------------------------------
    {
      await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.rdp', reason: 'history' }, SA);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      const keys = await q('SELECT * FROM fim_reg_history_keys');
      await ds.transaction(async (mq) => { await mq.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`); await mq.query('DELETE FROM fim_reg_history_keys'); });
      const v = await reg.verifyHistoryChain(db);
      assert.ok(!v.ok && !v.unverifiable && /fingerprint row of key id .* is missing/.test(v.reason!), JSON.stringify(v));
      for (const k of keys) await q('INSERT INTO fim_reg_history_keys (key_id, fingerprint, first_used_at) VALUES ($1,$2,$3)', [k.key_id, k.fingerprint, k.first_used_at]);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      await q('ALTER TABLE fim_reg_history DISABLE TRIGGER trg_fim_reg_history_no_truncate');
      reg.resetReconcileTimers();
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: new Set([H('w1')]) });
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND event_code LIKE 'FIM schema invariants broken%'`))[0].c), 1, 'daily invariant check alerts');
      await q('ALTER TABLE fim_reg_history ENABLE TRIGGER trg_fim_reg_history_no_truncate');
    }
    ok('key-fingerprint rows are required for every key id (deleting them is broken); the daily sweep checks the schema invariants');
  } finally {
    if (appDs?.isInitialized) await appDs.destroy();
    await tdb.drop();
    const [host, port] = addr!.split(':');
    const admin = new DataSource({ type: 'postgres', host, port: Number(port), username: process.env.FIM_TEST_USER || 'fimtest', database: process.env.FIM_TEST_ADMIN_DB || 'postgres' });
    await admin.initialize();
    await admin.query(`DROP ROLE IF EXISTS ${APP_ROLE}`).catch(() => undefined);
    await admin.destroy();
  }
  console.log(`\n${n} final-round groups passed`);
})().catch((err) => { console.error(err); process.exit(1); });
