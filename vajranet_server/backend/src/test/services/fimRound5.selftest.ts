/**
 * Round-5 regression tests (DB-backed, throwaway Postgres; own database per process):
 *   FIM_TEST_PG=127.0.0.1:55432 node_modules/.bin/ts-node src/test/services/fimRound5.selftest.ts
 * Each block fails on the behaviour before its fix (verified by mutation):
 *  N1  broader-scope rules vs member nodes' own rules; fail-safe never closes drift
 *  N2  high-water mark: TRUNCATE refused, missing row / disagreeing second marker = broken
 *  N3  boot DDL: hash skip, records the right hash, no exclusive lock on a no-op re-apply
 *  N4  perf indexes built CONCURRENTLY without blocking inserts
 *  N6  schema invariants repaired at boot (disabled trigger, downgraded version)
 *  S5  a failing boot DDL disables the registry with a critical alert (no exit)
 *  M-b2 key fingerprint rows append-only; key mismatch / anchor regression = broken
 *  mutation survivors: waiver single-use (service + DB index), expired waiver, job claim rules,
 *  per-node cancel latency
 */
import 'reflect-metadata';
import assert from 'assert';
import { createHash } from 'crypto';
import * as svc from '../../services/fimService';
import * as reg from '../../services/fimRegistryService';
import { FIM_BASE_DDL, FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL } from '../../utils/fim/fimRegistryDdl';
import { customEntryKey } from '../../utils/fim/fimRegistrySql';
import { openFimTestDb } from './fimTestDb';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set; set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}
process.env.FIM_HISTORY_HMAC_KEY = process.env.FIM_HISTORY_HMAC_KEY || 'fimr5test-history-key-0123456789abcdef';
const P = 'fimr5';
const H = (s: string) => `${P}-${s}`;
const L = 'HKEY_LOCAL_MACHINE\\';
const actor = (email: string, userId: number, superAdmin: boolean, groups: string[] = [], hosts: string[] = []): reg.RegActor => ({
  email, userId, superAdmin, actGroups: new Set(groups), actHosts: superAdmin ? null : new Set(hosts), viewHosts: superAdmin ? null : new Set(hosts), viewGroups: new Set(groups), requestId: `${P}-req`,
});

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  const db = ds as unknown as svc.FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  let n = 0;
  const ok = (m: string) => { n++; console.log(`ok - ${m}`); };
  const SA = actor(`${P}-sa@x`, 9101, true);
  const SA2 = actor(`${P}-sa2@x`, 9102, true);
  const maint = (sql: string, p: any[] = []) => ds.transaction(async (m) => { await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`); await m.query(sql, p); });
  const exp = () => Math.floor(Date.now() / 1000) + 86400;
  try {
    for (const b of [FIM_BASE_DDL, FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL]) await q(b);
    for (const h of ['w1', 'w2', 'w3'].map(H)) {
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [h, H('gA'), h, h]);
    }
    await reg.setManagedEnabled(db, true, SA, 'enable');

    // --- N1: a GA group rule overlapping a SA node rule is refused; forced via SQL the node rule wins -----
    {
      const nodeSpec = { path: `${L}SOFTWARE\\Acme\\%\\Cfg`, severity: 'high', measureOverride: true };
      const nr = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec: nodeSpec, reason: 'SA node coverage' }, SA);
      const p1 = await reg.publishNode(db, H('w1'), { actor: SA, note: 'with node rule' });
      const pol = (await q(`SELECT id, paths FROM fim_policies WHERE managed_host = $1`, [H('w1')]))[0];
      const slot = (pol.paths as any[]).findIndex((x) => x.entryKey === nr.rule.target);
      assert.ok(slot >= 0 && p1.status !== 'invalid');
      const d = (await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx)
        VALUES ($1,'x',$2,'registry|HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\Prod\\Cfg\\x','added','scan','critical',1,1,'item',$3) RETURNING id`, [pol.id, H('w1'), slot]))[0];
      // measured group rule that overlaps the node rule on w1: refused, naming the node
      const gSpec = { path: `${L}SOFTWARE\\Acme\\Prod\\%`, severity: 'high', measureOverride: true };
      await assert.rejects(reg.createRule(db, { layer: 'group', scopeValue: H('gA'), op: 'add', target: 'custom', spec: gSpec, reason: 'GA group rule' }, SA),
        new RegExp(`conflicts with the coverage of node ${H('w1')}|coverage of node ${H('w1')} invalid`));
      // forced via SQL: the node (more specific layer) keeps its coverage, the group entry is dropped there
      await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('group',$1,'add',$2,$3::jsonb,'forced',$4,1)`,
        [H('gA'), customEntryKey(gSpec.path), JSON.stringify({ path: gSpec.path, values: [], ignoreValues: [], excludeKeys: [], redactValues: [], includeSubkeys: true, anchor: true, hiveScoped: false, realtimeRequired: false, severity: 'high', category: 'custom', label: 'x', measureOverride: true }), `${P}-sql`]);
      const p2 = await reg.publishNode(db, H('w1'), { actor: reg.systemActor(), note: 'after forced group rule', auto: 'retry_invalid' });
      assert.notStrictEqual(p2.status, 'invalid', JSON.stringify(p2));
      const pol2 = (await q(`SELECT paths FROM fim_policies WHERE managed_host = $1`, [H('w1')]))[0];
      assert.ok((pol2.paths as any[]).some((x) => x.entryKey === nr.rule.target && !x.retired), 'node rule coverage kept');
      assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id = $1', [d.id]))[0].status, 'open', 'critical drift stays open');
      // fail-safe (same-layer overlap forced via SQL) never closes drift; it suspends coverage with a critical alert
      await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('node',$1,'add',$2,$3::jsonb,'forced',$4,1)`,
        [H('w1'), customEntryKey(gSpec.path), JSON.stringify({ path: gSpec.path, values: [], ignoreValues: [], excludeKeys: [], redactValues: [], includeSubkeys: true, anchor: true, hiveScoped: false, realtimeRequired: false, severity: 'high', category: 'custom', label: 'x', measureOverride: true }), `${P}-sql`]);
      const p3 = await reg.publishNode(db, H('w1'), { actor: reg.systemActor(), note: 'same-layer overlap', auto: 'retry_invalid' });
      assert.strictEqual(p3.status, 'invalid');
      assert.ok(p3.error!.startsWith('fail-safe'));
      const dr = (await q('SELECT status, note FROM fim_drift WHERE id = $1', [d.id]))[0];
      assert.strictEqual(dr.status, 'open', 'the fail-safe never closes drift (old code: ignored by system)');
      assert.ok(String(dr.note).includes('coverage suspended'));
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND host_identifier = $1 AND event_code LIKE 'FIM registry: coverage SUSPENDED%'`, [H('w1')]))[0].c), 1);
      // repaired: coverage returns on the same slot, drift still open
      await q(`DELETE FROM fim_reg_rules WHERE created_by = $1`, [`${P}-sql`]);
      const p4 = await reg.publishNode(db, H('w1'), { actor: SA, note: 'repaired' });
      assert.notStrictEqual(p4.status, 'invalid');
      assert.ok(p4.revived.includes(slot), 'same slot revived');
      assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id = $1', [d.id]))[0].status, 'open');
      await q(`DELETE FROM fim_drift WHERE id = $1`, [d.id]);
    }
    ok('N1: a group rule colliding with a node rule is refused at creation; forced, the node rule wins; the fail-safe suspends coverage without closing drift (critical alert)');

    // --- N2: high-water mark cannot be silently defeated -------------------------------------------
    {
      await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.netsh', reason: 'history row' }, SA);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      await assert.rejects(q('TRUNCATE fim_reg_history_hwm'), /only increase|append-only/);
      await assert.rejects(q('DELETE FROM fim_reg_history_hwm'), /only increase/);
      // a maintenance-role delete of the marker (or any loss of it) is broken, never ok
      const saved = (await q('SELECT * FROM fim_reg_history_hwm'))[0];
      await maint('DELETE FROM fim_reg_history_hwm');
      const v1 = await reg.verifyHistoryChain(db);
      assert.ok(!v1.ok && !v1.unverifiable && /high-water mark is missing/.test(v1.reason!), JSON.stringify(v1));
      await maint('INSERT INTO fim_reg_history_hwm (id, head_id, row_hash, row_count, updated_at) VALUES (true,$1,$2,$3,$4)', [saved.head_id, saved.row_hash, saved.row_count, saved.updated_at]);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      // the second, independent marker disagreeing (e.g. one table restored from an old backup)
      await maint('UPDATE fim_reg_settings SET history_head_id = history_head_id - 1 WHERE id');
      const v2 = await reg.verifyHistoryChain(db);
      assert.ok(!v2.ok && /two head markers disagree/.test(v2.reason!), JSON.stringify(v2));
      await assert.rejects(q('UPDATE fim_reg_settings SET history_head_id = 0 WHERE id'), /can only increase/);
      await maint('UPDATE fim_reg_settings SET history_head_id = $1 WHERE id', [saved.head_id]);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      // appendHistory re-creates (upserts) a missing marker row instead of silently skipping it
      await maint('DELETE FROM fim_reg_history_hwm');
      const r2 = await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.rdp', reason: 'upsert' }, SA);
      assert.strictEqual(Number((await q('SELECT head_id FROM fim_reg_history_hwm'))[0].head_id), r2.historyHead.id);
    }
    ok('N2: hwm TRUNCATE/DELETE refused; a missing marker or disagreeing second marker is broken; appendHistory upserts the marker');

    // --- M-b2: key fingerprints append-only; key mismatch and anchor regression are BROKEN -----------
    {
      await assert.rejects(q('DELETE FROM fim_reg_history_keys'), /append-only/);
      await assert.rejects(q(`UPDATE fim_reg_history_keys SET fingerprint = 'x'`), /append-only/);
      await assert.rejects(q('TRUNCATE fim_reg_history_keys'), /append-only/);
      const fp = (await q(`SELECT key_id, fingerprint FROM fim_reg_history_keys`))[0];
      await maint(`UPDATE fim_reg_history_keys SET fingerprint = 'forged' WHERE key_id = $1`, [fp.key_id]);
      const vk = await reg.verifyHistoryChain(db);
      assert.ok(!vk.ok && !vk.unverifiable && /key mismatch/.test(vk.reason!), JSON.stringify(vk));
      await maint(`UPDATE fim_reg_history_keys SET fingerprint = $2 WHERE key_id = $1`, [fp.key_id, fp.fingerprint]);
      const head = (await q('SELECT head_id, row_hash, row_count FROM fim_reg_history_hwm'))[0];
      await reg.flushHistoryAnchors(db, async () => undefined);
      const older = (await q('SELECT id, row_hash FROM fim_reg_history ORDER BY id DESC OFFSET 1 LIMIT 1'))[0];
      const vr = await reg.verifyHistoryChain(db, { anchor: async () => ({ id: Number(older.id), rowHash: older.row_hash, count: Number(head.row_count) - 1 }) });
      assert.ok(!vr.ok && !vr.unverifiable && /regressed/.test(vr.reason!), JSON.stringify(vr));
      const va = await reg.verifyHistoryChain(db, { anchor: async () => ({ id: Number(head.head_id), rowHash: 'forged', count: Number(head.row_count) }) });
      assert.ok(!va.ok && !va.unverifiable && va.brokenAt === Number(head.head_id), JSON.stringify(va));
      await maint(`UPDATE fim_reg_history SET actor = 'mallory' WHERE id = $1`, [head.head_id]);
      const vh = await reg.verifyHistoryChain(db);
      assert.ok(!vh.ok && !vh.unverifiable && /hash mismatch/.test(vh.reason!), JSON.stringify(vh));
      const orig = (await q(`SELECT actor FROM fim_reg_history WHERE id = $1`, [Number(head.head_id) - 1]))[0];
      await maint(`UPDATE fim_reg_history SET actor = $2 WHERE id = $1`, [head.head_id, orig.actor]);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
    }
    ok('M-b2: key-fingerprint rows append-only; key mismatch, anchor regression, anchor hash mismatch and chain hash mismatch are all BROKEN (not unverifiable)');

    // --- N3 / m16: boot DDL hash skip records the right hash and never takes exclusive locks on a no-op -----
    {
      const blk = `CREATE TABLE IF NOT EXISTS fimr5_probe (id int); SELECT 1`;
      assert.strictEqual(await reg.applyFimDdl(db, 'fimr5_probe', blk), 'applied');
      assert.strictEqual((await q(`SELECT sha256 FROM fim_schema_applied WHERE name = 'fimr5_probe'`))[0].sha256, createHash('sha256').update(blk).digest('hex'));
      assert.strictEqual(await reg.applyFimDdl(db, 'fimr5_probe', blk), 'skipped');
      assert.strictEqual(await reg.applyFimDdl(db, 'fimr5_probe', `${blk}; SELECT 2`), 'applied', 'a changed text is never skipped');
      assert.strictEqual((await q(`SELECT sha256 FROM fim_schema_applied WHERE name = 'fimr5_probe'`))[0].sha256, createHash('sha256').update(`${blk}; SELECT 2`).digest('hex'), 'the stored hash is refreshed on re-apply');
      assert.strictEqual(await reg.applyFimDdl(db, 'fimr5_probe', `${blk}; SELECT 2`), 'skipped', 'an unchanged second boot is skipped');
      await q('DROP TABLE fimr5_probe');
      await q(`DELETE FROM fim_schema_applied WHERE name = 'fimr5_probe'`);
      // re-applying the 0004 base DDL while a long reader holds fim_drift / fim_policies: no ACCESS EXCLUSIVE needed
      const runner = ds.createQueryRunner();
      await runner.connect();
      await runner.startTransaction();
      await runner.query('SELECT count(*) FROM fim_drift');
      await runner.query('SELECT count(*) FROM fim_policies');
      await runner.query('SELECT count(*) FROM fim_baseline');
      await runner.query('SELECT count(*) FROM fim_host_state');
      await q(`DELETE FROM fim_schema_applied WHERE name = '0004_fim_base'`);
      const t0 = Date.now();
      await reg.applyFimDdl(db, '0004_fim_base', FIM_BASE_DDL);
      const ms = Date.now() - t0;
      await runner.rollbackTransaction();
      await runner.release();
      assert.ok(ms < 4000, `the no-op 0004 re-apply waited ${ms} ms on the reader (exclusive lock)`);
    }
    ok('N3 / m16: DDL block hash skip (right hash recorded, changed text re-applied); a no-op 0004 re-apply takes no exclusive lock');

    // --- N6 / S5: invariants repaired at boot; a failing block disables the registry without exiting ---
    {
      const blocks: [string, string][] = [['0004_fim_base', FIM_BASE_DDL], ['0005_fim_registry', FIM_REGISTRY_DDL], ['0006_fim_verify', FIM_VERIFY_DDL], ['0007_fim_worker_schema', FIM_WORKER_DDL], ['0008_fim_perf', FIM_PERF_DDL]];
      for (const [name, b] of blocks) await reg.applyFimDdl(db, name, b); // hashes recorded: the next boot would skip them
      await q('ALTER TABLE fim_reg_history DISABLE TRIGGER trg_fim_reg_history_no_update');
      await q(`CREATE OR REPLACE FUNCTION fim_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS $$ SELECT 7 $$`);
      // DROPPED guards (not only disabled): history truncate, outbox, hwm and key-fingerprint guards
      for (const [tbl, trg] of [['fim_reg_history', 'trg_fim_reg_history_no_truncate'], ['fim_reg_anchor_outbox', 'trg_fim_reg_anchor_outbox_guard'],
        ['fim_reg_history_hwm', 'trg_fim_reg_history_hwm_guard'], ['fim_reg_history_keys', 'trg_fim_reg_history_keys_guard']]) await q(`DROP TRIGGER ${trg} ON ${tbl}`);
      const inv = await reg.fimSchemaInvariants(db);
      for (const t of ['trg_fim_reg_history_no_truncate', 'trg_fim_reg_anchor_outbox_guard', 'trg_fim_reg_history_hwm_guard', 'trg_fim_reg_history_keys_guard']) {
        assert.ok(inv.some((x) => x.includes(`trigger ${t}`) && x.includes('missing')), `dropped ${t} detected: ${JSON.stringify(inv)}`);
      }
      assert.ok(inv.some((x) => x.includes('trg_fim_reg_history_no_update') && x.includes('disabled')) && inv.some((x) => /fim_schema_version\(\) is 7/.test(x)));
      const boot = await reg.bootFimSchema(db, blocks);
      assert.ok(boot.ok && boot.repaired.length >= 6 && boot.problems.length === 0, JSON.stringify(boot));
      await assert.rejects(q('DELETE FROM fim_reg_history_keys'), /append-only/, 'dropped guard re-created');
      assert.deepStrictEqual(await reg.fimSchemaInvariants(db), []);
      assert.ok(reg.listHealthWarnings().some((w) => /re-applied/.test(w)));
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND event_code LIKE 'FIM schema invariants were broken and have been re-applied%'`))[0].c), 1);
      // Since the final round the boot runs DDL only when the schema is not current: make 0008 missing and broken.
      await q('ALTER TABLE fim_drift DROP COLUMN last_realtime_at');
      const bad = await reg.bootFimSchema(db, [...blocks.slice(0, 4), ['0008_fim_perf', 'SELECT * FROM table_that_does_not_exist']]);
      assert.ok(!bad.ok);
      assert.ok(/schema could not be applied/.test(reg.registryDisabledReason() ?? ''));
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.aedebug', reason: 'x' }, SA), reg.FimUnavailableError);
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND event_code LIKE 'FIM registry disabled: schema could not be applied%'`))[0].c), 1);
      assert.ok((await reg.bootFimSchema(db, blocks)).ok);
      assert.strictEqual(reg.registryDisabledReason(), null, 'a successful retry re-enables the registry');
    }
    ok('N6 / S5: a disabled trigger and a downgraded schema version are repaired at boot (critical alert, health warning); a failing block disables the registry with a critical alert and a retry re-enables it');

    // --- N4: perf indexes built CONCURRENTLY without blocking inserts --------------------------------
    {
      for (const ix of reg.FIM_PERF_INDEXES) await q(`DROP INDEX IF EXISTS ${ix.name}`);
      await q(`INSERT INTO query_result (host_identifier, unixtime, query_name, result) SELECT 'fimr5-qr', 1, (g % 5000)::text, '[]' FROM generate_series(1, 300000) g`);
      const runner = ds.createQueryRunner();
      await runner.connect();
      const build = reg.ensurePerfIndexes({ query: (s: string, p?: any[]) => runner.query(s, p) });
      const waits: number[] = [];
      for (let i = 0; i < 10; i++) {
        const t0 = Date.now();
        await ds.transaction(async (m) => { await m.query(`SET LOCAL lock_timeout = '2s'`); await m.query(`INSERT INTO query_result (host_identifier, unixtime, query_name, result) VALUES ('fimr5-qr', 1, 'x', '[]')`); });
        waits.push(Date.now() - t0);
      }
      const res = await build;
      await runner.release();
      assert.deepStrictEqual(res.missing, []);
      assert.ok(Math.max(...waits) < 1500, `inserts blocked during the build: ${waits.join(',')}`);
      const valid = await q(`SELECT c.relname, i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = ANY($1)`, [reg.FIM_PERF_INDEXES.map((x) => x.name)]);
      assert.ok(valid.length === 2 && valid.every((r: any) => r.indisvalid), JSON.stringify(valid));
      await q(`DELETE FROM query_result WHERE host_identifier = 'fimr5-qr'`);
    }
    ok('N4: the 0008a perf indexes are built CONCURRENTLY in the background while inserts keep flowing');

    // --- mutation survivors: waiver single use (service + DB index), expired waiver, job claim rules ----
    {
      const RUN = { op: 'disable', target: 'reg.run.hklm' };
      const w = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w3'), action: 'disable', reason: 'single use test host', expiresAt: exp(), rule: RUN }, SA);
      await reg.decideWaiver(db, w.id, 'approve', 'ok', SA2);
      const ap = await reg.applyWaiver(db, w.id, SA, 'apply');
      await reg.revokeRule(db, ap.rule.id, SA, 'free the rule slot');
      // service: the waiver was used once, a second use is refused even after the first rule is revoked
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w3'), ...RUN, reason: 'single use test host', waiverId: w.id }, SA), /already used/);
      // DB: the unique index refuses a second rule backed by the same waiver
      // two rows that differ in target and scope (only the waiver index can refuse the second one)
      await assert.rejects(q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, waiver_id, created_by, created_at) VALUES ('node',$1,'disable','reg.runonce.hklm','{}'::jsonb,'x',$3,'x',1), ('node',$2,'disable','reg.run.wow','{}'::jsonb,'x',$3,'x',1)`, [H('w3'), H('w2'), w.id]), /uq_fim_reg_rules_waiver|duplicate key/);
      // expired approved waiver refused by the service
      const w2 = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w3'), action: 'disable', reason: 'expiry test host', expiresAt: exp(), rule: RUN }, SA);
      await reg.decideWaiver(db, w2.id, 'approve', 'ok', SA2);
      await q(`UPDATE fim_reg_waivers SET requested_at = 1, approved_at = 2, expires_at = 3 WHERE id = $1`, [w2.id]);
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w3'), ...RUN, reason: 'expiry test host', waiverId: w2.id }, SA), /expired/);
      // job claim: never a RUNNING job with a fresh heartbeat, never a cancelled one
      const pid = Number((await q(`SELECT id FROM fim_reg_profiles WHERE is_default`))[0].id);
      const dg = (await reg.currentProfileDigest(db, pid))!;
      const j = await reg.startProfilePublishJob(db, pid, SA, 'claim', dg);
      await q(`UPDATE fim_reg_jobs SET status = 'running', heartbeat_at = $2, lease_token = 'other' WHERE id = $1`, [j.id, Math.floor(Date.now() / 1000)]);
      await reg.runRegistryJob(db, j.id);
      const jr = await reg.getJob(db, j.id, SA);
      assert.ok(jr.status === 'running' && jr.done === 0, 'a running job with a fresh heartbeat is not taken over');
      assert.strictEqual((await q('SELECT lease_token FROM fim_reg_jobs WHERE id = $1', [j.id]))[0].lease_token, 'other');
      await reg.cancelJob(db, j.id, SA, 'stop');
      await q(`UPDATE fim_reg_jobs SET heartbeat_at = 1 WHERE id = $1`, [j.id]);
      await reg.runRegistryJob(db, j.id);
      assert.strictEqual((await reg.getJob(db, j.id, SA)).status, 'cancelled', 'a cancelled job is never claimed');
    }
    ok('mutation survivors: waiver single use (service + DB index), expired waiver refused, job claim never takes running/cancelled jobs');

    // --- S3 / L-b5: cancel is honoured before the NEXT node, not at the end of a chunk ----------------
    {
      const bulk = Array.from({ length: 60 }, (_, i) => H(`b${String(i).padStart(2, '0')}`));
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) SELECT h, 'windows', $2, h, h FROM unnest($1::text[]) h`, [bulk, H('gB')]);
      const pj = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-job`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      await reg.putAssignment(db, 'group', H('gB'), { profileId: pj.profile.id, reason: 'x' }, SA);
      const j = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'cancel latency', (await reg.currentProfileDigest(db, pj.profile.id))!);
      const pubCount = async () => Number((await q(`SELECT count(*) AS c FROM fim_policies WHERE managed_host = ANY($1)`, [bulk]))[0].c);
      const run = reg.runRegistryJob(db, j.id);
      for (let i = 0; i < 400 && (await pubCount()) < 3; i++) await new Promise((r) => setTimeout(r, 10));
      await reg.cancelJob(db, j.id, SA, 'stop now');
      const atCancel = await pubCount();
      await run;
      const after = await pubCount();
      assert.ok(after - atCancel <= 1, `published ${after - atCancel} node(s) after the cancel (chunk-boundary cancel would publish up to ${reg.FIM_REG_JOB_CHUNK})`);
      // a profile change mid-chunk aborts before the next node
      const j2 = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'change latency', (await reg.currentProfileDigest(db, pj.profile.id))!);
      const before2 = await pubCount();
      const run2 = reg.runRegistryJob(db, j2.id);
      for (let i = 0; i < 400 && (await pubCount()) < before2 + 2; i++) await new Promise((r) => setTimeout(r, 10));
      await reg.createRule(db, { layer: 'profile', scopeValue: String(pj.profile.id), op: 'add', target: 'reg.netsh', reason: 'changed meanwhile' }, SA);
      const atChange = await pubCount();
      await run2;
      const j2r = await reg.getJob(db, j2.id, SA);
      assert.strictEqual(j2r.status, 'aborted');
      assert.ok((await pubCount()) - atChange <= 1, 'stopped before the next node after the profile change');
    }
    ok('S3 / L-b5: cancel and a profile change are honoured before the next node (per-node guard), not at the end of the chunk');
  } finally {
    await tdb.drop();
  }
  console.log(`\n${n} round-5 groups passed`);
})().catch((err) => { console.error(err); process.exit(1); });
