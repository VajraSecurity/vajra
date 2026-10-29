/**
 * DB-backed test for services/fimService.ts against a THROWAWAY Postgres:
 *   FIM_TEST_PG=127.0.0.1:55432 node_modules/.bin/ts-node src/test/services/fimDb.selftest.ts
 * (user fimtest, no password, database fimdb). Without FIM_TEST_PG it FAILS unless FIM_ALLOW_SKIP=1.
 * Seeds its own nodes/policies (prefix fimselftest) and removes them afterwards.
 */
import 'reflect-metadata';
import assert from 'assert';
import { openFimTestDb } from './fimTestDb';
import * as svc from '../../services/fimService';
import { validatePolicyInput, buildScanSql } from '../../utils/fim/fimLogic';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set (host:port of a throwaway Postgres); set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}

const P = 'fimselftest';
const rowsOfAny = (r: any): any[] => svc.rowsOf(r);
const nodeRow = (h: string, plat: string, cfg: string | null, grp: string | null) =>
  [h, plat, cfg, grp] as const;

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  // The suite seeds nodes with small fake config ids (7, 8, 18, 23, ...): on a FRESH database the
  // config_queries sequence would hand out the same numbers, so start it above them.
  await ds.query(`SELECT setval('config_queries_id_seq', GREATEST((SELECT COALESCE(max(id), 0) FROM config_queries), 1000))
                  WHERE (SELECT last_value FROM config_queries_id_seq) < 1000`);
  const db = ds as unknown as svc.FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  await q('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_group_id text');
  const cfgOf = async (h: string) => (await q('SELECT config_id FROM nodes WHERE host_identifier=$1', [h]))[0].config_id as string | null;
  let n = 0;
  const ok = (m: string) => { n++; console.log(`ok - ${m}`); };
  /** `expected` = what an analyst sees right now (approve requires it; review finding H1). */
  // What the UI sends: the contentHash of the drift rows it displayed.
  const EXP = async (ids: number[]) => Object.fromEntries((await q('SELECT * FROM fim_drift WHERE id = ANY($1::bigint[])', [ids]))
    .map((r: any) => [String(r.id), { contentHash: svc.driftContentHash(r) }]));
  const EXPA = async (alertIds: number[]) => EXP((await q(
    `SELECT d.id FROM fim_drift d JOIN alerts a ON a.id = ANY($1::bigint[])
     AND (d.alert_id = a.id OR substring(a.metadata from '"drift_id"\\s*:\\s*"?([0-9]{1,15})') = d.id::text)`, [alertIds])).map((r: any) => Number(r.id)));

  // fim_audit rows this run writes (policy names / hosts carry the prefix, or test actors / request ids).
  const auditStart = Number((await q('SELECT COALESCE(max(id), 0) AS m FROM fim_audit'))[0].m);
  const cleanup = async () => {
    await q(`DELETE FROM fim_audit WHERE id > $1 AND (details::text LIKE $2 OR request_id LIKE $2 OR actor LIKE $2 OR actor IN ('adm@x','a@x','ga@x','tester@x'))`, [auditStart, `%${P}%`]);
    const pols = await q(`SELECT id, config_query_id FROM fim_policies WHERE name LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM query_queue WHERE id IN (SELECT queue_id FROM fim_init_requests WHERE policy_id IN (SELECT id FROM fim_policies WHERE name LIKE $1))`, [`${P}%`]);
    for (const p of pols) {
      if (p.config_query_id) await q('DELETE FROM config_queries WHERE id=$1', [p.config_query_id]);
    }
    await q(`DELETE FROM fim_policies WHERE name LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM config_queries WHERE query_name LIKE 'fim:fimselftest%'`);
    await q(`DELETE FROM alerts WHERE event_code LIKE 'fimselftest%'`);
    await q(`DELETE FROM fim_drift WHERE policy_name LIKE $1 OR policy_id = 987654321`, [`${P}%`]); // drift has no FK: survives policy deletes
    await q(`DELETE FROM query_queue WHERE host_identifier LIKE $1`, [`${P}%`]); // incl. auto-init rows orphaned by policy deletes
    await q(`DELETE FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`]);
  };
  await cleanup();
  try {
    const seed = [
      nodeRow(`${P}-lin1`, 'ubuntu', '18,23,3', 'gA'),
      nodeRow(`${P}-lin2`, 'centos', null, 'gA'),
      nodeRow(`${P}-lin3`, 'ubuntu', '5', 'gB'),
      nodeRow(`${P}-win1`, 'windows', '23,35', 'gA'),
    ];
    for (const [h, pl, c, g] of seed) {
      await q(`INSERT INTO nodes (host_identifier, os_platform, config_id, owner_group_id, node_key) VALUES ($1,$2,$3,$4,$1)`, [h, pl, c, g]);
    }
    const other = (await q(`INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch) VALUES ('{}','fimselftest-unrelated','Linux','','') RETURNING id`))[0].id;
    await q(`DELETE FROM config_queries WHERE id=$1`, [other]);

    // create
    const pol = await svc.createPolicy(db, validatePolicyInput({
      name: `${P}-a`, osPlatform: 'linux', paths: [{ path: '/etc/%%', severity: 'high' }], realtime: true,
      targets: [{ type: 'group', value: 'gA' }, { type: 'node', value: `${P}-lin3` }],
    }), 'tester@x');
    assert.strictEqual(pol.rev, 1);
    assert.strictEqual(pol.targets.length, 2);
    await assert.rejects(svc.createPolicy(db, validatePolicyInput({ name: `${P}-a`, paths: [{ path: '/x' }] }), null), svc.FimConflictError);
    ok('create + unique-name conflict');

    // publish
    const r = await svc.publishPolicy(db, pol.id);
    assert.ok(r.published && r.configQueryId);
    assert.strictEqual((await svc.fetchPolicy(db, pol.id))!.publishedRev, 1);
    assert.strictEqual(r.nodesInScope, 3); // lin1, lin2 (gA), lin3 (node); not win1 (platform)
    const cid = String(r.configQueryId);
    assert.strictEqual(await cfgOf(`${P}-lin1`), `18,23,3,${cid}`);
    assert.strictEqual(await cfgOf(`${P}-lin2`), cid);
    assert.strictEqual(await cfgOf(`${P}-lin3`), `5,${cid}`);
    assert.strictEqual(await cfgOf(`${P}-win1`), '23,35');
    const cq = (await q('SELECT * FROM config_queries WHERE id=$1', [r.configQueryId]))[0];
    assert.strictEqual(cq.query_name, `fim:${P}-a`);
    assert.strictEqual(cq.os_name, 'Linux');
    const cfg = JSON.parse(cq.query);
    assert.ok(cfg.schedule[`fim_scan_${pol.id}_1_0`].snapshot); // key carries id, rev and entry index
    assert.strictEqual(cfg.file_accesses, undefined);
    assert.deepStrictEqual(cfg.file_paths, { [`fim_${pol.id}`]: ['/etc/%%'] });
    ok('publish inserts config_queries and adds id to in-scope nodes only');

    // republish idempotent, no duplicates
    const r2 = await svc.publishPolicy(db, pol.id);
    assert.strictEqual(r2.configQueryId, r.configQueryId);
    assert.strictEqual(r2.nodesAdded, 0);
    assert.strictEqual(await cfgOf(`${P}-lin1`), `18,23,3,${cid}`);
    ok('republish is idempotent (same row, no duplicate ids)');

    // shrink scope: only lin3 -> id removed from lin1/lin2, others untouched
    await svc.updatePolicy(db, pol.id, validatePolicyInput({ targets: [{ type: 'node', value: `${P}-lin3` }] }, {
      name: pol.name, description: pol.description, osPlatform: pol.osPlatform, paths: pol.paths, scanIntervalSecs: pol.scanIntervalSecs,
      realtime: pol.realtime, mode: pol.mode, learnScans: pol.learnScans, enabled: true, template: null, targets: pol.targets,
    }));
    const r3 = await svc.publishPolicy(db, pol.id);
    assert.strictEqual(r3.nodesRemoved, 2);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    assert.strictEqual(await cfgOf(`${P}-lin2`), '');
    assert.strictEqual(await cfgOf(`${P}-lin3`), `5,${cid}`);
    ok('narrowing scope removes only this id from nodes no longer in scope');

    // rev bump rules
    let cur = (await svc.fetchPolicy(db, pol.id))!;
    assert.strictEqual(cur.rev, 1);
    const asInput = (p: typeof cur) => ({ name: p.name, description: p.description, osPlatform: p.osPlatform, paths: p.paths, scanIntervalSecs: p.scanIntervalSecs, realtime: p.realtime, mode: p.mode, learnScans: p.learnScans, enabled: p.enabled, template: p.template, targets: p.targets });
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ description: 'd', mode: 'enforce', scanIntervalSecs: 120 }, asInput(cur)));
    assert.strictEqual(cur.rev, 1);
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ paths: [{ path: '/etc/%%', severity: 'critical', category: 'x', hash: false }] }, asInput(cur)));
    assert.strictEqual(cur.rev, 1); // severity/category/hash-only edit
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ paths: [{ path: '/etc/%%' }, { path: '/opt/%%' }] }, asInput(cur)));
    assert.strictEqual(cur.rev, 2);
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ osPlatform: 'windows', paths: [{ path: 'C:\\a\\*' }] }, asInput(cur)));
    assert.strictEqual(cur.rev, 3);
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ osPlatform: 'linux', paths: [{ path: '/etc/%%' }] }, asInput(cur)));
    assert.strictEqual(cur.rev, 4);
    cur = await svc.updatePolicy(db, pol.id, validatePolicyInput({ paths: [{ path: '/etc/%%', ignore: ['/etc/mtab'] }] }, asInput(cur)));
    assert.strictEqual(cur.rev, 5); // ignore-list change
    ok('rev bumps only on paths/os_platform change');

    // resolve
    const mk = async (host: string, path: string, type: string, attrs: any, sha: string | null) =>
      (await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, new_sha256, new_attrs, detected_at, last_seen_at)
                VALUES ($1,$8,$2,$3,$4,'scan',$5,$6::jsonb,$7,$7) RETURNING id`, [pol.id, host, path, type, sha, JSON.stringify(attrs), Math.floor(Date.now() / 1000), pol.name]))[0].id as string;
    const dAdd = await mk(`${P}-lin3`, '/etc/new', 'added', { size: 10, mode: '0644', uid: 0, gid: 0, mtime: 99, md5: 'm5' }, 'sha-new');
    const dMod = await mk(`${P}-lin3`, '/etc/mod', 'modified', { size: '7' }, 'sha-mod');
    const dRem = await mk(`${P}-lin3`, '/etc/gone', 'removed', {}, null);
    const dRej = await mk(`${P}-lin3`, '/etc/rej', 'modified', {}, 'sha-r');
    const dIgn = await mk(`${P}-lin3`, '/etc/ign', 'added', {}, 'sha-i');
    const dOther = await mk(`${P}-lin1`, '/etc/other', 'added', {}, 'sha-o');
    const dAttr = await mk(`${P}-lin3`, '/etc/attr', 'attributes', { mode: '0600' }, null);
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, sha256, md5, size, first_seen, last_seen) VALUES ($1,$2,'/etc/attr','old-attr','old-md5',3,1,1)`, [pol.id, `${P}-lin3`]);
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, sha256, size, first_seen, last_seen) VALUES ($1,$2,'/etc/mod','sha-old',5,1,1),($1,$2,'/etc/gone','g',1,1,1),($1,$2,'/etc/rej','keep',1,1,1)`, [pol.id, `${P}-lin3`]);
    // approving a hashless change is refused unless explicitly accepted, and nothing is changed
    await assert.rejects(svc.resolveDrift(db, [Number(dAdd), Number(dAttr)], 'approve', 'adm@x', 'ok', null, null, { expected: await EXP([Number(dAdd), Number(dAttr)]) }), svc.FimUnverifiedError);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dAdd]))[0].status, 'open');
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_baseline WHERE path='/etc/new'`))[0].n, 0);
    // removals never need a hash
    const ap = await svc.resolveDrift(db, [Number(dAdd), Number(dMod), Number(dRem), Number(dAttr), 999999999], 'approve', 'adm@x', 'ok', [`${P}-lin3`], null, { acceptUnverified: true, expected: await EXP([Number(dAdd), Number(dMod), Number(dRem), Number(dAttr)]) });
    assert.deepStrictEqual([ap.resolved, ap.skipped], [4, 1]);
    const bl = await q(`SELECT path, sha256, size, mode, md5, approved_by FROM fim_baseline WHERE policy_id=$1 ORDER BY path`, [pol.id]);
    const by = Object.fromEntries(bl.map((b: any) => [b.path, b]));
    assert.strictEqual(by['/etc/new'].sha256, 'sha-new'); assert.strictEqual(by['/etc/new'].mode, '0644'); assert.strictEqual(by['/etc/new'].approved_by, 'adm@x');
    assert.strictEqual(by['/etc/mod'].sha256, 'sha-mod'); assert.strictEqual(String(by['/etc/mod'].size), '7');
    assert.strictEqual(by['/etc/attr'].sha256, null); // exact new hash (NULL), not COALESCEd
    assert.strictEqual(by['/etc/attr'].md5, null);
    assert.strictEqual(by['/etc/attr'].mode, '0600');
    assert.strictEqual(by['/etc/attr'].size, null); // exact: absent attr -> NULL, not the old size 3
    assert.strictEqual(by['/etc/mod'].mode, null);
    assert.strictEqual(by['/etc/gone'], undefined);
    assert.strictEqual(by['/etc/rej'].sha256, 'keep');
    ok('approve upserts baseline (added/modified) and deletes it (removed)');
    // re-resolving already closed rows is a no-op
    const again = await svc.resolveDrift(db, [Number(dAdd)], 'reject', 'adm@x', null, null);
    assert.strictEqual(again.resolved, 0);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dAdd]))[0].status, 'approved');
    // reject / ignore leave baseline alone
    await svc.resolveDrift(db, [Number(dRej)], 'reject', 'adm@x', 'bad', null);
    await svc.resolveDrift(db, [Number(dIgn)], 'ignore', 'adm@x', null, null);
    assert.strictEqual((await q('SELECT status,resolved_by,note FROM fim_drift WHERE id=$1', [dRej]))[0].status, 'rejected');
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dIgn]))[0].status, 'ignored');
    assert.strictEqual((await q(`SELECT sha256 FROM fim_baseline WHERE path='/etc/rej' AND policy_id=$1`, [pol.id]))[0].sha256, 'keep');
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_baseline WHERE path='/etc/ign'`))[0].n, 0);
    // host filter: out-of-scope row untouched
    const sc = await svc.resolveDrift(db, [Number(dOther)], 'approve', 'adm@x', null, [`${P}-lin3`], null, { expected: await EXP([Number(dOther)]) });
    assert.strictEqual(sc.resolved, 0);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dOther]))[0].status, 'open');
    // policy filter: a caller who cannot manage this policy resolves nothing, even on visible hosts
    const pf = await svc.resolveDrift(db, [Number(dOther)], 'approve', 'adm@x', null, [`${P}-lin1`], [], { expected: await EXP([Number(dOther)]) });
    assert.strictEqual(pf.resolved, 0);
    const pf2 = await svc.resolveDrift(db, [Number(dOther)], 'approve', 'adm@x', null, [`${P}-lin1`], [pol.id + 1000], { expected: await EXP([Number(dOther)]) });
    assert.strictEqual(pf2.resolved, 0);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dOther]))[0].status, 'open');
    ok('closed rows untouched; reject/ignore keep baseline; host filter enforced');

    // reads
    const dl = await svc.listDrift(db, { q: '%_' }, null, 1, 10); // metachars must be escaped
    assert.strictEqual(dl.total, 0);
    const dl2 = await svc.listDrift(db, { status: 'open', policy: pol.id }, [`${P}-lin1`], 1, 10);
    assert.strictEqual(dl2.total, 1); assert.strictEqual(dl2.items[0].path, '/etc/other'); assert.strictEqual(dl2.items[0].policyName, `${P}-a`);
    assert.strictEqual((await svc.listDrift(db, {}, [], 1, 10)).total, 0);
    assert.ok(await svc.getDrift(db, Number(dOther), null));
    assert.strictEqual(await svc.getDrift(db, Number(dOther), [`${P}-lin3`]), null);
    const bq = await svc.listBaseline(db, { policy: pol.id, q: 'mod' }, null, 1, 10);
    assert.strictEqual(bq.total, 1);
    const sm = await svc.getSummary(db, null);
    assert.ok(sm.openDrift >= 1 && sm.trend.length === 14 && sm.bySeverity.medium >= 1);
    assert.ok(sm.driftLast24h >= 6);
    const sm2 = await svc.getSummary(db, []);
    assert.strictEqual(sm2.openDrift, 0);
    ok('list/get/baseline/summary incl. host scoping and LIKE escaping');

    // disable -> unpublish
    await svc.updatePolicy(db, pol.id, validatePolicyInput({ enabled: false }, asInput((await svc.fetchPolicy(db, pol.id))!)));
    const ru = await svc.publishPolicy(db, pol.id);
    assert.strictEqual(ru.published, false);
    assert.strictEqual(await cfgOf(`${P}-lin3`), '5');
    assert.strictEqual((await q('SELECT count(*)::int n FROM config_queries WHERE id=$1', [cid]))[0].n, 0);
    assert.strictEqual((await svc.fetchPolicy(db, pol.id))!.configQueryId, null);
    assert.strictEqual((await svc.fetchPolicy(db, pol.id))!.publishedRev, null);
    ok('disable removes config_queries row and id from all nodes');

    // windows publish + delete
    const wp = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-w`, osPlatform: 'windows', paths: [{ path: 'C:\\Windows\\System32\\drivers\\etc\\*' }], targets: [{ type: 'group', value: 'gA' }] }), null);
    const wr = await svc.publishPolicy(db, wp.id);
    assert.strictEqual(wr.nodesInScope, 1);
    assert.strictEqual(await cfgOf(`${P}-win1`), `23,35,${wr.configQueryId}`);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    const wcfg = JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [wr.configQueryId]))[0].query);
    assert.ok(wcfg.win_include_paths[`fim_${wp.id}`]);
    await svc.deletePolicy(db, wp.id);
    assert.strictEqual(await cfgOf(`${P}-win1`), '23,35');
    assert.strictEqual((await q('SELECT count(*)::int n FROM config_queries WHERE id=$1', [wr.configQueryId]))[0].n, 0);
    assert.strictEqual(await svc.fetchPolicy(db, wp.id), null);
    await assert.rejects(svc.deletePolicy(db, wp.id), svc.FimNotFoundError);
    ok('windows publish + delete cleans config_queries and node lists');

    // 'all' target: stored as '', presented as '*'; hostsInScope returned
    const alp = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-all`, paths: ['/etc/%%'], targets: [{ type: 'all', value: '*' }] }), null);
    assert.deepStrictEqual(alp.targets, [{ type: 'all', value: '*' }]);
    assert.strictEqual((await q('SELECT target_value v FROM fim_policy_targets WHERE policy_id=$1', [alp.id]))[0].v, '');
    const alr = await svc.publishPolicy(db, alp.id);
    assert.ok(alr.hostsInScope >= 3 && alr.configQueryId);
    const alu = await svc.updatePolicy(db, alp.id, validatePolicyInput({ enabled: false }, {
      name: alp.name, description: alp.description, osPlatform: alp.osPlatform, paths: alp.paths, scanIntervalSecs: alp.scanIntervalSecs,
      realtime: alp.realtime, mode: alp.mode, learnScans: alp.learnScans, enabled: true, template: null, targets: alp.targets }));
    assert.deepStrictEqual(alu.targets, [{ type: 'all', value: '*' }]);
    assert.strictEqual((await q('SELECT target_value v FROM fim_policy_targets WHERE policy_id=$1', [alp.id]))[0].v, '');
    await svc.deletePolicy(db, alp.id);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    ok("'all' target normalization + hostsInScope");

    // file_events schedule + independence of identical keys across policies
    const r1 = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-rt1`, paths: ['/etc/%%'], realtime: true, targets: [{ type: 'node', value: `${P}-lin1` }] }), null);
    const r2p = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-rt2`, paths: ['/opt/%%'], realtime: true, targets: [{ type: 'node', value: `${P}-lin1` }] }), null);
    const pr1 = await svc.publishPolicy(db, r1.id);
    const pr2 = await svc.publishPolicy(db, r2p.id);
    for (const pr of [pr1, pr2]) {
      const c = JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [pr.configQueryId]))[0].query);
      assert.deepStrictEqual(c.schedule.file_events, { query: 'SELECT * FROM file_events', interval: 300, snapshot: false });
    }
    await svc.deletePolicy(db, r1.id);
    const c2 = JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [pr2.configQueryId]))[0].query);
    assert.ok(c2.schedule.file_events);
    assert.strictEqual(await cfgOf(`${P}-lin1`), `18,23,3,${pr2.configQueryId}`);
    await svc.deletePolicy(db, r2p.id);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    ok('file_events schedule emitted; deleting one policy leaves the other intact');

    // reconcileAllPublishedPolicies
    const ap0 = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-rec`, paths: ['/etc/%%'], targets: [{ type: 'group', value: 'gA' }] }), null);
    const rp = await svc.publishPolicy(db, ap0.id);
    const rid = String(rp.configQueryId);
    await q(`INSERT INTO nodes (host_identifier, os_platform, config_id, owner_group_id, node_key) VALUES ($1,'ubuntu','18,3','gA',$1)`, [`${P}-late`]);
    await q(`UPDATE nodes SET config_id='18,23,36,3' WHERE host_identifier=$1`, [`${P}-lin2`]); // re-enroll reset
    await q(`UPDATE nodes SET config_id='18' WHERE host_identifier=$1`, [`${P}-win1`]); // out of scope (windows)
    await q(`INSERT INTO fim_policies (name, os_platform, paths, enabled, config_query_id) VALUES ($1,'linux','[]'::jsonb,false,999999)`, [`${P}-dis`]); // disabled: skipped
    await q(`INSERT INTO fim_policies (name, os_platform, paths) VALUES ($1,'linux','[]'::jsonb)`, [`${P}-unpub`]); // never published: skipped
    const rr = await svc.reconcileAllPublishedPolicies(db);
    assert.ok(rr.policies >= 1 && rr.added >= 2);
    assert.strictEqual(await cfgOf(`${P}-late`), `18,3,${rid}`);
    assert.strictEqual(await cfgOf(`${P}-lin2`), `18,23,36,3,${rid}`);
    assert.strictEqual(await cfgOf(`${P}-win1`), '18');
    assert.ok((await cfgOf(`${P}-lin1`))!.split(',').includes(rid));
    assert.strictEqual(await cfgOf(`${P}-lin3`), '5'); // gB: out of scope
    const rr2 = await svc.reconcileAllPublishedPolicies(db);
    assert.strictEqual(rr2.added + rr2.removed, 0); // idempotent
    assert.strictEqual(await cfgOf(`${P}-late`), `18,3,${rid}`);
    assert.strictEqual((await q(`SELECT count(*)::int n FROM config_queries WHERE id=999999`))[0].n, 0);
    await svc.deletePolicy(db, ap0.id);
    ok('reconcileAllPublishedPolicies re-adds ids for late/re-enrolled nodes, idempotent, skips disabled/unpublished');

    // delete keeps drift history; baseline/host_state/host_entry are removed
    const hp = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-hist`, mode: 'enforce', paths: ['/etc/%%'], targets: [{ type: 'node', value: `${P}-lin1` }] }), null);
    await svc.publishPolicy(db, hp.id);
    const hd = (await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, new_sha256, detected_at, last_seen_at)
        VALUES ($1,$2,$3,'/etc/h1','added','scan','sha-h',1,1),($1,$2,$3,'/etc/h2','added','scan','sha-h2',1,1) RETURNING id`, [hp.id, hp.name, `${P}-lin1`])).map((r: any) => Number(r.id));
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, first_seen, last_seen) VALUES ($1,$2,'/etc/h1',1,1)`, [hp.id, `${P}-lin1`]);
    await q(`INSERT INTO fim_host_state (policy_id, host_identifier, state, scan_count) VALUES ($1,$2,'locked',3)`, [hp.id, `${P}-lin1`]);
    await q(`INSERT INTO fim_host_entry (policy_id, host_identifier, entry_idx, rev) VALUES ($1,$2,0,1)`, [hp.id, `${P}-lin1`]);
    await svc.deletePolicy(db, hp.id);
    for (const t of ['fim_baseline', 'fim_host_state', 'fim_host_entry', 'fim_policy_targets']) {
      assert.strictEqual((await q(`SELECT count(*)::int n FROM ${t} WHERE policy_id=$1`, [hp.id]))[0].n, 0, t);
    }
    assert.strictEqual((await q('SELECT count(*)::int n FROM fim_drift WHERE policy_id=$1', [hp.id]))[0].n, 2);
    const hl = await svc.listDrift(db, { policy: hp.id }, null, 1, 10);
    assert.ok(hl.items.every((i) => i.policyDeleted && i.policyName === `${P}-hist`));
    assert.strictEqual((await svc.getDrift(db, hd[0], null))!.policyDeleted, true);
    // read-only except 'ignore'
    assert.strictEqual((await svc.resolveDrift(db, [hd[0]], 'approve', 'a@x', 'n', null, null, { acceptUnverified: true, expected: await EXP([hd[0]]) })).resolved, 0);
    assert.strictEqual((await svc.resolveDrift(db, [hd[0]], 'reject', 'a@x', 'n', null)).resolved, 0);
    assert.strictEqual((await svc.resolveDrift(db, [hd[0]], 'ignore', 'a@x', null, null)).resolved, 1);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    ok('delete keeps drift (policy_name + policyDeleted, ignore-only), cascades the rest');
    await q('DELETE FROM fim_drift WHERE policy_id=$1', [hp.id]);

    // affectsPublishedConfig (drives auto-publish on save)
    const base0 = (await svc.fetchPolicy(db, pol.id))!;
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, mode: 'learn', description: 'x', learnScans: 9 }), false);
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, paths: [...base0.paths, { path: '/q/%%', severity: 'low', category: '', ignore: [], hash: true }] }), true);
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, realtime: !base0.realtime }), true);
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, scanIntervalSecs: base0.scanIntervalSecs + 1 }), true);
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, enabled: !base0.enabled }), true);
    assert.strictEqual(svc.affectsPublishedConfig(base0, { ...base0, targets: [{ type: 'all', value: '*' }] }), true);
    // paths change: old schedule keys disappear on republish (row rewritten)
    const pp = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-keys`, paths: ['/etc/%%', '/opt/%%', '/srv/%%'], targets: [{ type: 'node', value: `${P}-lin1` }] }), null);
    const k1 = await svc.publishPolicy(db, pp.id);
    const keys1 = Object.keys(JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [k1.configQueryId]))[0].query).schedule).filter((k) => k.startsWith('fim_scan_'));
    assert.deepStrictEqual(keys1, [0, 1, 2].map((i) => `fim_scan_${pp.id}_1_${i}`));
    const pp2 = await svc.updatePolicy(db, pp.id, validatePolicyInput({ paths: ['/etc/%%', '/srv/%%'] }, { name: pp.name, description: '', osPlatform: 'linux', paths: pp.paths, scanIntervalSecs: 3600, realtime: true, mode: 'learn', learnScans: 2, enabled: true, template: null, targets: pp.targets }));
    assert.strictEqual(pp2.rev, 2);
    assert.strictEqual(pp2.publishedRev, 1); // changes not published yet
    await svc.publishPolicy(db, pp.id);
    const keys2 = Object.keys(JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [k1.configQueryId]))[0].query).schedule).filter((k) => k.startsWith('fim_scan_'));
    assert.deepStrictEqual(keys2, [`fim_scan_${pp.id}_2_0`, `fim_scan_${pp.id}_2_1`]);
    assert.strictEqual((await svc.fetchPolicy(db, pp.id))!.publishedRev, 2);
    await svc.deletePolicy(db, pp.id);
    ok('affectsPublishedConfig; republish after paths change drops old keys; publishedRev tracks rev');

    // ---- initialize baselines ----
    const ip = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-init`, paths: ['/etc/%%', '/opt/app/%'], targets: [{ type: 'node', value: `${P}-lin1` }, { type: 'node', value: `${P}-lin2` }, { type: 'node', value: `${P}-win1` }] }), null);
    await assert.rejects(svc.initializeBaseline(db, ip.id, { note: '  ', requestedBy: 'a@x' }), svc.FimBadRequestError);
    await assert.rejects(svc.initializeBaseline(db, 999999, { note: 'n', requestedBy: 'a@x' }), svc.FimNotFoundError);
    const maxRes = Number((await q('SELECT COALESCE(max(id),0) m FROM query_result'))[0].m);
    const i1 = await svc.initializeBaseline(db, ip.id, { note: 'first', requestedBy: 'a@x' });
    assert.strictEqual(i1.hosts, 2); // win1 filtered by OS
    assert.strictEqual(i1.requests, 4); // 2 hosts x 2 entries
    const reqs = await q(`SELECT r.*, qq.query, qq.sent, qq.send_time, qq.host_identifier AS qhost FROM fim_init_requests r JOIN query_queue qq ON qq.id = r.queue_id WHERE r.policy_id=$1 ORDER BY r.host_identifier, r.entry_idx`, [ip.id]);
    assert.strictEqual(reqs.length, 4);
    for (const r of reqs) {
      assert.strictEqual(r.query, buildScanSql(ip.paths[r.entry_idx].path, 'linux'));
      assert.strictEqual(r.qhost, r.host_identifier);
      assert.ok(r.sent === false && Number(r.send_time) === 0);
      assert.strictEqual(r.rev, ip.rev); assert.strictEqual(r.status, 'pending'); assert.strictEqual(r.batch_id, i1.batchId);
      assert.strictEqual(Number(r.after_result_id), maxRes); assert.strictEqual(r.requested_by, 'a@x'); assert.strictEqual(r.note, 'first');
    }
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_baseline WHERE policy_id=$1`, [ip.id]))[0].n, 0); // baseline untouched
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_host_state WHERE policy_id=$1`, [ip.id]))[0].n, 0);
    // a newer request SUPERSEDES the pending one: old rows expire, unsent queue rows vanish
    const oldQ = reqs.map((r: any) => Number(r.queue_id));
    await q(`UPDATE query_queue SET sent=true WHERE id=$1`, [oldQ[0]]); // already handed to an agent: must stay
    const i2 = await svc.initializeBaseline(db, ip.id, { note: 'again', requestedBy: 'a@x' });
    assert.strictEqual(i2.requests, 4); assert.strictEqual(i2.superseded, 4);
    assert.deepStrictEqual(i2.skipped, []);
    const exp = await q(`SELECT status, error, batch_id FROM fim_init_requests WHERE policy_id=$1 AND batch_id=$2`, [ip.id, i1.batchId]);
    assert.ok(exp.length === 4 && exp.every((r: any) => r.status === 'expired' && r.error === 'superseded by a newer request'));
    const left = await q(`SELECT id FROM query_queue WHERE id = ANY($1::bigint[])`, [oldQ]);
    assert.deepStrictEqual(left.map((r: any) => Number(r.id)), [oldQ[0]]); // only the sent one remains
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_init_requests WHERE policy_id=$1 AND status='pending'`, [ip.id]))[0].n, 4);
    // explicit host out of scope reported; scoped caller limited to visibleHosts
    await q(`UPDATE fim_init_requests SET status='done' WHERE policy_id=$1`, [ip.id]);
    const i3 = await svc.initializeBaseline(db, ip.id, { hosts: [`${P}-lin1`, `${P}-lin2`, `${P}-lin3`], note: 'scoped', requestedBy: 'ga@x', visibleHosts: [`${P}-lin1`] });
    assert.strictEqual(i3.hosts, 1);
    assert.deepStrictEqual(i3.skipped, [{ hostIdentifier: `${P}-lin3`, reason: 'out-of-scope' }]);
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_init_requests WHERE batch_id=$1 AND host_identifier<>$2`, [i3.batchId, `${P}-lin1`]))[0].n, 0);
    // system needs no note; disabled policy refused
    await q(`UPDATE fim_init_requests SET status='done' WHERE policy_id=$1`, [ip.id]);
    assert.strictEqual((await svc.initializeBaseline(db, ip.id, { hosts: [`${P}-lin2`], note: null, requestedBy: 'system' })).requests, 2);
    await q(`UPDATE fim_policies SET enabled=false WHERE id=$1`, [ip.id]);
    await assert.rejects(svc.initializeBaseline(db, ip.id, { note: 'n', requestedBy: 'a@x' }), svc.FimBadRequestError);
    await q(`UPDATE fim_policies SET enabled=true WHERE id=$1`, [ip.id]);
    ok('initialize: queue rows == scan SQL per entry, request metadata, supersede, OS/scope filters, note rules');

    // initialization status + versions from hand-seeded rows
    await q(`DELETE FROM fim_init_requests WHERE policy_id=$1`, [ip.id]);
    const nowS = Math.floor(Date.now() / 1000);
    const seedReq = (h: string, k: number, st: string, t: number, b: string) => q(`INSERT INTO fim_init_requests (batch_id, policy_id, host_identifier, entry_idx, rev, status, created_at) VALUES ($1,$2,$3,$4,1,$5,$6)`, [b, ip.id, h, k, st, t]);
    await seedReq(`${P}-lin1`, 0, 'failed', nowS - 500, 'old'); // old batch must be ignored
    await seedReq(`${P}-lin1`, 0, 'done', nowS - 10, 'new'); await seedReq(`${P}-lin1`, 1, 'done', nowS - 10, 'new');
    await seedReq(`${P}-lin2`, 0, 'done', nowS - 10, 'b2'); await seedReq(`${P}-lin2`, 1, 'pending', nowS - 10, 'b2');
    await q(`INSERT INTO fim_baseline_version (policy_id, host_identifier, version, reason, created_by, note, created_at, file_count, digest) VALUES ($1,$2,1,'init','a@x','n1',$3,10,'aaaa'),($1,$2,2,'init','a@x','n2',$4,12,'bbbb')`, [ip.id, `${P}-lin1`, nowS - 100, nowS - 5]);
    const ini = await svc.getInitialization(db, ip.id, null, {}, 1, 50);
    assert.deepStrictEqual(ini.totals, { none: 0, pending: 0, done: 1, partial: 1, failed: 0 });
    const byH = Object.fromEntries(ini.hosts.map((h) => [h.hostIdentifier, h]));
    assert.strictEqual(byH[`${P}-lin1`].status, 'done'); assert.strictEqual(byH[`${P}-lin1`].latestVersion, 2);
    assert.deepStrictEqual(byH[`${P}-lin1`].entries, { done: 2, pending: 0, failed: 0, expired: 0 });
    assert.strictEqual(byH[`${P}-lin2`].status, 'partial'); assert.strictEqual(byH[`${P}-lin2`].entries.pending, 1);
    assert.strictEqual(byH[`${P}-lin1`].lastInitAt, nowS - 10);
    assert.strictEqual(ini.total, 2); assert.strictEqual(ini.items.length, 2);
    assert.strictEqual((await svc.getInitialization(db, ip.id, null, { status: 'partial' }, 1, 50)).total, 1);
    assert.strictEqual((await svc.getInitialization(db, ip.id, [`${P}-lin1`], {}, 1, 50)).total, 1);
    await q(`UPDATE fim_init_requests SET status='failed' WHERE batch_id='b2'`);
    assert.strictEqual((await svc.getInitialization(db, ip.id, null, { q: 'lin2' }, 1, 50)).hosts[0].status, 'failed');
    await q(`DELETE FROM fim_init_requests WHERE policy_id=$1 AND host_identifier=$2`, [ip.id, `${P}-lin2`]);
    assert.strictEqual((await svc.getInitialization(db, ip.id, null, {}, 1, 50)).totals.none, 1);
    const vl = await svc.listBaselineVersions(db, { policy: ip.id }, null, 1, 10);
    assert.strictEqual(vl.total, 2); assert.strictEqual(vl.items[0].version, 2); assert.strictEqual(vl.items[0].digest, 'bbbb');
    assert.strictEqual(vl.items[0].policyName, `${P}-init`); assert.strictEqual(vl.items[0].fileCount, 12); assert.strictEqual(vl.items[0].createdBy, 'a@x');
    assert.strictEqual((await svc.listBaselineVersions(db, { policy: ip.id }, [`${P}-lin2`], 1, 10)).total, 0);
    ok('initialization status (latest batch per host) and baseline versions from seeded rows');

    // stats: hostsBaselined = locked host_state; hostsNotBaselined = in-scope hosts without one
    await q(`DELETE FROM fim_init_requests WHERE policy_id=$1`, [ip.id]);
    await q(`INSERT INTO fim_host_state (policy_id, host_identifier, state, scan_count) VALUES ($1,$2,'locked',3),($1,$3,'learning',9)`, [ip.id, `${P}-lin2`, `${P}-lin1`]);
    const sp = (await svc.fetchPolicy(db, ip.id))!;
    assert.deepStrictEqual([sp.stats.hosts, sp.stats.hostsBaselined, sp.stats.hostsNotBaselined, sp.stats.locked, sp.stats.learning], [2, 1, 1, 1, 1]);
    assert.strictEqual((await svc.getInitialization(db, ip.id, null, {}, 1, 50)).hostsNotBaselined, 1);
    await q(`UPDATE fim_policies SET config_query_id = 1 WHERE id=$1`, [ip.id]);
    const sm3 = await svc.getSummary(db, [`${P}-lin1`, `${P}-lin2`]);
    assert.ok(sm3.hostsNotBaselined >= 1 && sm3.hostsBaselined >= 1);
    assert.strictEqual(sm3.hostsLearning, sm3.hostsNotBaselined); assert.strictEqual(sm3.hostsLocked, sm3.hostsBaselined);
    await q(`UPDATE fim_policies SET config_query_id = NULL WHERE id=$1`, [ip.id]);
    // the 60 s reconcile never creates init requests or baselines on its own
    await svc.reconcileAllPublishedPolicies(db);
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_init_requests WHERE policy_id=$1`, [ip.id]))[0].n, 0);
    ok('stats (hostsBaselined/hostsNotBaselined + legacy aliases); reconcile does not auto-baseline');

    // ---- no N+1: policy list / summary use a constant number of queries ----
    let nq = 0;
    const counting: svc.FimQ = { query: (s2: string, p2?: any[]) => { nq++; return ds.query(s2, p2); } };
    const countQ = async (fn: () => Promise<unknown>) => { nq = 0; await fn(); return nq; };
    // extra policies of every target kind (group / node / all / none), one locked host
    const extra: number[] = [];
    for (const [k, targets] of [['g', [{ type: 'group', value: 'gA' }]], ['n', [{ type: 'node', value: `${P}-lin3` }]], ['al', [{ type: 'all', value: '*' }]], ['w', [{ type: 'group', value: 'gA' }]], ['none', []]] as const) {
      const ep = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-n1-${k}`, osPlatform: k === 'w' ? 'windows' : 'linux', paths: k === 'w' ? ['C:\\a\\*'] : ['/etc/%%', { kind: 'table', source: 'users' }], targets: targets as any }), null);
      extra.push(ep.id);
    }
    await q(`INSERT INTO fim_host_state (policy_id, host_identifier, state, scan_count) VALUES ($1,$2,'locked',1)`, [extra[0], `${P}-lin1`]);
    // set-based stats == the per-policy rule (resolveTargetHosts + locked host_state)
    const allP = await svc.fetchAllPolicies(counting);
    assert.ok(nq <= 2, `fetchAllPolicies issued ${nq} queries`);
    for (const pv of allP.filter((x) => x.name.startsWith(P))) {
      const cov = await svc.baselineCoverage(db, pv);
      assert.deepStrictEqual([pv.stats.hosts, pv.stats.hostsBaselined, pv.stats.hostsNotBaselined], [cov.inScope.length, cov.baselined.size, cov.inScope.length - cov.baselined.size], pv.name);
      const one = (await svc.fetchPolicy(db, pv.id))!;
      assert.deepStrictEqual(one.stats, pv.stats, pv.name);
    }
    assert.ok((await countQ(() => svc.fetchPolicy(counting, extra[0]))) <= 2);
    // summary: same numbers as the per-policy loop, query count independent of the policy count
    // compared inside ONE repeatable-read snapshot (other suites may write the shared DB concurrently)
    await ds.transaction('REPEATABLE READ', async (m) => {
      const sq = m as unknown as svc.FimQ;
      const loopNotBaselined = async (hf: string[] | null) => {
        const set = new Set<string>();
        for (const pv of await svc.fetchAllPolicies(sq, false)) {
          if (!pv.enabled) continue;
          const cov = await svc.baselineCoverage(sq, pv);
          for (const h of cov.inScope) if (!cov.baselined.has(h) && (!hf || hf.includes(h))) set.add(h);
        }
        return set.size;
      };
      const loopEntries = async () => {
        const out = { path: 0, xattr: 0, registry: 0, acl: 0, table: 0 } as Record<string, number>;
        for (const pv of await svc.fetchAllPolicies(sq, false)) if (pv.enabled) for (const e of pv.paths as any[]) if (!e.retired) out[e.kind ?? 'path'] = (out[e.kind ?? 'path'] ?? 0) + 1;
        return out;
      };
      const smN = await svc.getSummary(sq, null);
      assert.strictEqual(smN.hostsNotBaselined, await loopNotBaselined(null));
      assert.deepStrictEqual(smN.entriesByKind, await loopEntries());
      const smS = await svc.getSummary(sq, [`${P}-lin1`, `${P}-lin2`]);
      assert.strictEqual(smS.hostsNotBaselined, await loopNotBaselined([`${P}-lin1`, `${P}-lin2`]));
    });
    const qSummary1 = await countQ(() => svc.getSummary(counting, null));
    const qList1 = await countQ(() => svc.fetchAllPolicies(counting));
    for (let i = 0; i < 4; i++) {
      extra.push((await svc.createPolicy(db, validatePolicyInput({ name: `${P}-n1-more${i}`, paths: ['/etc/%%'], targets: [{ type: 'group', value: 'gA' }] }), null)).id);
    }
    assert.strictEqual(await countQ(() => svc.getSummary(counting, null)), qSummary1, 'getSummary query count grows with the policy count');
    assert.strictEqual(await countQ(() => svc.fetchAllPolicies(counting)), qList1, 'fetchAllPolicies query count grows with the policy count');
    for (const id of extra) await svc.deletePolicy(db, id);
    await svc.deletePolicy(db, ip.id);
    ok('no N+1: fetchAllPolicies / fetchPolicy / getSummary use a constant query count; set-based stats equal the per-policy rule');

    // ---- FIM alerts ----
    const ap1 = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-alr`, paths: ['/etc/%%'], targets: [{ type: 'node', value: `${P}-lin1` }, { type: 'node', value: `${P}-lin3` }] }), null);
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, sha256, first_seen, last_seen) VALUES ($1,$2,'/etc/a-mod','old',1,1)`, [ap1.id, `${P}-lin1`]);
    const now2 = Math.floor(Date.now() / 1000);
    const mkDrift = async (host: string, path: string, type: string, sha: string | null, alertId: number | null) =>
      Number((await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, hostname, path, change_type, source, new_sha256, new_attrs, detected_at, last_seen_at, alert_id)
         VALUES ($1,$2,$3,'h',$4,$5,'scan',$6,'{"size":5}'::jsonb,$7,$7,$8) RETURNING id`, [ap1.id, ap1.name, host, path, type, sha, now2, alertId]))[0].id);
    const mkAlert = async (host: string, type: string, sev: string, code: string, meta: string | null, open = true) =>
      Number((await q(`INSERT INTO alerts (host_identifier, hostname, unixtime, detection_time, event_code, metadata, is_open, severity, alert_type) VALUES ($1,'h',$2,$2,$3,$4,$5,$6,$7) RETURNING id`, [host, now2, `fimselftest ${code}`, meta, open, sev, type]))[0].id);
    const a1 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a1', null);
    const d1 = await mkDrift(`${P}-lin1`, '/etc/a-mod', 'modified', 'sha-new', a1); // linked via alert_id
    const a2 = await mkAlert(`${P}-lin1`, 'fim', 'Critical', 'a2', null);
    const d2 = await mkDrift(`${P}-lin1`, '/etc/a-hashless', 'modified', null, null);
    await q(`UPDATE alerts SET metadata=$2 WHERE id=$1`, [a2, JSON.stringify({ drift_id: d2, path: '/etc/a-hashless' })]); // linked via metadata only
    const a3 = await mkAlert(`${P}-lin1`, 'fim', 'Low', 'legacy', 'not json {{ "drift_id": nope');  // legacy metadata must not break anything
    const a4 = await mkAlert(`${P}-lin3`, 'fim_health', 'Medium', `scan overdue: h [${ap1.name}]`, null);
    const a5 = await mkAlert(`${P}-lin3`, 'fim', 'High', 'a5', null);
    const d5 = await mkDrift(`${P}-lin3`, '/etc/a5', 'added', 'sha5', a5);
    const a6 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a6', null);
    const d6 = await mkDrift(`${P}-lin1`, '/etc/a6', 'added', 'sha6', a6);
    const list = await svc.listAlerts(db, { q: 'fimselftest' }, null, 1, 50);
    assert.strictEqual(list.total, 6); assert.deepStrictEqual(list.counts, { open: list.counts.open, closed: list.counts.closed, truePositive: list.counts.truePositive, falsePositive: list.counts.falsePositive });
    const byId = Object.fromEntries(list.items.map((i) => [i.alertId, i]));
    assert.strictEqual(byId[a1].driftId, d1); assert.strictEqual(byId[a1].path, '/etc/a-mod'); assert.strictEqual(byId[a1].policyName, ap1.name);
    assert.strictEqual(byId[a2].driftId, d2); // via metadata drift_id
    assert.strictEqual(byId[a3].driftId, null); // legacy non-JSON metadata: no crash, no link
    assert.strictEqual(byId[a4].policyId, ap1.id); assert.strictEqual(byId[a4].driftId, null); // health alert -> policy by name
    assert.strictEqual(byId[a1].severity, 'high');
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', type: 'health' }, null, 1, 50)).total, 1);
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', type: 'drift', severity: 'critical' }, null, 1, 50)).total, 1);
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', policy: ap1.id }, null, 1, 50)).total, 5); // not the legacy one
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', verdict: 'unmarked' }, null, 1, 50)).total, 6);
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', host: `${P}-lin3` }, [`${P}-lin3`], 1, 50)).total, 2);
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest' }, [`${P}-lin3`], 1, 50)).total, 2); // host scoping
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest' }, [], 1, 50)).total, 0);
    assert.strictEqual((await svc.listAlerts(db, { q: 'fimselftest', status: 'closed' }, null, 1, 50)).total, 0);
    ok('alerts list: filters, drift linking (alert_id + metadata), legacy metadata safe, health->policy, host scoping');

    const actor = (hostFilter: string[] | null, policyFilter: number[] | null = null) => ({ hostFilter, groupIds: [] as string[], policyFilter, user: 'adm@x' });
    await assert.rejects(svc.closeAlerts(db, [a1], 'true_positive', '  ', actor(null)), svc.FimBadRequestError);
    await assert.rejects(svc.closeAlerts(db, [a1], 'true_positive', 'n', actor(null), { approveChange: true }), svc.FimBadRequestError);
    // out-of-scope host / policy not manageable -> skipped
    const sk = await svc.closeAlerts(db, [a1, a5], 'true_positive', 'tp', actor([`${P}-lin3`]));
    assert.deepStrictEqual([sk.closed, sk.skipped, sk.ids], [1, 1, [a5]]);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d5]))[0].status, 'rejected'); // TP -> rejected
    assert.strictEqual((await q('SELECT is_open FROM alerts WHERE id=$1', [a1]))[0].is_open, true);
    const pk = await svc.closeAlerts(db, [a1], 'true_positive', 'tp', actor(null, []));
    assert.strictEqual(pk.closed, 0); // drift's policy not manageable
    const tp = await svc.closeAlerts(db, [a1, a4, a3], 'true_positive', 'confirmed bad', actor(null));
    assert.strictEqual(tp.closed, 3);
    let ar = await q('SELECT id, is_open, mark_type, remarks FROM alerts WHERE id = ANY($1::bigint[]) ORDER BY id', [[a1, a3, a4]]);
    assert.ok(ar.every((r: any) => r.is_open === false && r.mark_type === 'true_positive' && r.remarks === 'confirmed bad'));
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d1]))[0].status, 'rejected');
    assert.strictEqual((await q(`SELECT sha256 FROM fim_baseline WHERE path='/etc/a-mod' AND policy_id=$1`, [ap1.id]))[0].sha256, 'old'); // baseline unchanged
    // already closed -> skipped; FP without approve -> ignored
    assert.strictEqual((await svc.closeAlerts(db, [a1], 'false_positive', 'x', actor(null))).closed, 0);
    const fp = await svc.closeAlerts(db, [a6], 'false_positive', 'benign', actor(null));
    assert.strictEqual(fp.closed, 1);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d6]))[0].status, 'ignored');
    assert.strictEqual((await q('SELECT mark_type FROM alerts WHERE id=$1', [a6]))[0].mark_type, 'false_positive');
    ok('close: TP rejects drift (baseline kept), FP ignores, health alert just closes, scope/policy skipped, note required');

    // approveChange with and without hash
    await assert.rejects(svc.closeAlerts(db, [a2], 'false_positive', 'legit', actor(null), { approveChange: true, expected: await EXPA([a2]) }), svc.FimUnverifiedError);
    assert.strictEqual((await q('SELECT is_open FROM alerts WHERE id=$1', [a2]))[0].is_open, true); // whole tx rolled back
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d2]))[0].status, 'open');
    const ap2 = await svc.closeAlerts(db, [a2], 'false_positive', 'legit', actor(null), { approveChange: true, acceptUnverified: true, expected: await EXPA([a2]) });
    assert.strictEqual(ap2.closed, 1);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d2]))[0].status, 'approved');
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_baseline WHERE policy_id=$1 AND path='/etc/a-hashless'`, [ap1.id]))[0].n, 1);
    const a7 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a7', null);
    const d7 = await mkDrift(`${P}-lin1`, '/etc/a7', 'added', 'sha7', a7);
    assert.strictEqual((await svc.closeAlerts(db, [a7], 'false_positive', 'ok', actor(null), { approveChange: true, expected: await EXPA([a7]) })).closed, 1);
    assert.strictEqual((await q(`SELECT sha256 FROM fim_baseline WHERE policy_id=$1 AND path='/etc/a7'`, [ap1.id]))[0].sha256, 'sha7');
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d7]))[0].status, 'approved');
    ok('approveChange: hashless needs acceptUnverified (rolls back otherwise); hashed approves into baseline');

    // reopen leaves drift untouched
    const ro = await svc.reopenAlerts(db, [a1, a2, a7], actor(null));
    assert.strictEqual(ro.reopened, 3);
    ar = await q('SELECT is_open, mark_type FROM alerts WHERE id = ANY($1::bigint[])', [[a1, a2, a7]]);
    assert.ok(ar.every((r: any) => r.is_open === true && r.mark_type === null));
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [d1]))[0].status, 'rejected');
    assert.strictEqual((await svc.reopenAlerts(db, [a1], actor(null))).reopened, 0); // already open
    assert.strictEqual((await svc.reopenAlerts(db, [a4], actor([`${P}-lin1`]))).reopened, 0); // out of scope
    ok('reopen: is_open true, mark cleared, drift untouched, scoped');

    // resolving drift from the Drift tab closes the linked alert
    const a8 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a8', null); const d8 = await mkDrift(`${P}-lin1`, '/etc/a8', 'added', 'sha8', a8);
    const a9 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a9', null); const d9 = await mkDrift(`${P}-lin1`, '/etc/a9', 'added', 'sha9', a9);
    const a10 = await mkAlert(`${P}-lin1`, 'fim', 'High', 'a10', null); const d10 = await mkDrift(`${P}-lin1`, '/etc/a10', 'added', 'sha10', a10);
    await svc.resolveDrift(db, [d8], 'approve', 'adm@x', 'ok', null, null, { expected: await EXP([d8]) });
    await svc.resolveDrift(db, [d9], 'reject', 'adm@x', 'bad', null);
    await svc.resolveDrift(db, [d10], 'ignore', 'adm@x', null, null);
    ar = await q('SELECT id, is_open, mark_type FROM alerts WHERE id = ANY($1::bigint[]) ORDER BY id', [[a8, a9, a10]]);
    assert.deepStrictEqual(ar.map((r: any) => [r.is_open, r.mark_type]), [[false, 'false_positive'], [false, 'true_positive'], [false, null]]);
    ok('resolveDrift closes the linked alert (approve->FP, reject->TP, ignore->closed)');

    // summary
    await q(`UPDATE alerts SET is_open=true WHERE id = ANY($1::bigint[])`, [[a8]]);
    const smA = await svc.getSummary(db, [`${P}-lin1`, `${P}-lin3`]);
    const myOpen = (await q(`SELECT lower(severity) s, count(*)::int n FROM alerts WHERE event_code LIKE 'fimselftest%' AND is_open GROUP BY 1`));
    assert.ok(smA.openAlerts >= myOpen.reduce((a: number, r: any) => a + r.n, 0));
    assert.ok(smA.openAlertsBySeverity.high >= 1);
    assert.strictEqual((await svc.getSummary(db, [])).openAlerts, 0);
    ok('summary openAlerts / openAlertsBySeverity (scoped)');

    // closeAlerts counts: an alert whose open drift was SKIPPED by resolveDriftTx is not closed
    // (a) drift of a deleted policy: reject/approve skip it
    const aDel = await mkAlert(`${P}-lin1`, 'fim', 'High', 'adel', null);
    const dDel = Number((await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, hostname, path, change_type, source, new_sha256, detected_at, last_seen_at, alert_id)
       VALUES (987654321,'gone',$1,'h','/etc/del','added','scan','shaD',$2,$2,$3) RETURNING id`, [`${P}-lin1`, now2, aDel]))[0].id);
    const cDel = await svc.closeAlerts(db, [aDel], 'true_positive', 'tp', actor(null));
    assert.deepStrictEqual([cDel.closed, cDel.skipped, cDel.ids, cDel.results[0].outcome], [0, 1, [], 'skipped']);
    assert.strictEqual((await q('SELECT is_open FROM alerts WHERE id=$1', [aDel]))[0].is_open, true);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dDel]))[0].status, 'open');
    // (b) approveChange: the alert is in the caller's act scope through its group, the drift host is not
    const aGrp = await mkAlert(`${P}-lin1`, 'fim', 'High', 'agrp', null);
    await q(`UPDATE alerts SET group_id = $2 WHERE id = $1`, [aGrp, `${P}-grp`]);
    const dGrp = await mkDrift(`${P}-lin1`, '/etc/agrp', 'added', 'shaG', aGrp);
    const cGrp = await svc.closeAlerts(db, [aGrp], 'false_positive', 'fp', { hostFilter: [`${P}-lin3`], groupIds: [`${P}-grp`], policyFilter: null, user: 'adm@x' },
      { approveChange: true, expected: await EXPA([aGrp]) });
    assert.deepStrictEqual([cGrp.closed, cGrp.skipped, cGrp.results[0].outcome], [0, 1, 'skipped']);
    assert.strictEqual((await q('SELECT is_open FROM alerts WHERE id=$1', [aGrp]))[0].is_open, true);
    assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id=$1', [dGrp]))[0].status, 'open');
    await q('DELETE FROM fim_drift WHERE id = $1', [dDel]);
    ok('closeAlerts: alert whose linked open drift was skipped (deleted policy / drift host out of scope, incl. approveChange) is not reported closed');

    // closeAlerts race: an open drift linked to the alert AFTER actableAlerts read it (committed on
    // another connection right before the close UPDATE) keeps the alert open; check-then-update closed it.
    const aRace = await mkAlert(`${P}-lin1`, 'fim', 'High', 'arace', null);
    let raced = false;
    const racyDb = {
      query: (s2: string, p2?: any[]) => ds.query(s2, p2),
      transaction: (fn: any) => ds.transaction((m) => fn({
        query: async (s2: string, p2?: any[]) => {
          if (!raced && /^\s*UPDATE alerts (a )?SET is_open = false/.test(s2)) { raced = true; await mkDrift(`${P}-lin1`, '/etc/arace', 'added', 'shaR', aRace); }
          return m.query(s2, p2);
        },
      })),
    } as unknown as svc.FimDb;
    const cRace = await svc.closeAlerts(racyDb, [aRace], 'true_positive', 'tp', actor(null));
    assert.ok(raced, 'hook ran');
    assert.deepStrictEqual([cRace.closed, cRace.skipped, cRace.ids, cRace.results[0].outcome], [0, 1, [], 'skipped']);
    assert.strictEqual((await q('SELECT is_open FROM alerts WHERE id=$1', [aRace]))[0].is_open, true);
    // the close route itself (no race) then resolves the drift together with the alert
    assert.strictEqual((await svc.closeAlerts(db, [aRace], 'true_positive', 'tp', actor(null))).closed, 1);
    assert.strictEqual((await q(`SELECT status FROM fim_drift WHERE alert_id=$1`, [aRace]))[0].status, 'rejected');
    ok('closeAlerts is race-safe: a drift linked between the check and the write keeps the alert open (skipped)');
    await svc.deletePolicy(db, ap1.id);
    await q('DELETE FROM fim_drift WHERE policy_id=$1', [ap1.id]);

    // ---- item / directory drift ----
    const kp = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-kinds`, paths: [{ kind: 'table', source: 'users' }, '/etc/ssh/%%', { kind: 'xattr', path: '/etc/%%' }], targets: [{ type: 'node', value: `${P}-lin1` }] }), null);
    assert.deepStrictEqual(kp.paths.map((e: any) => e.kind), ['table', 'path', 'xattr']);
    const kpub = await svc.publishPolicy(db, kp.id);
    const kcfg = JSON.parse((await q('SELECT query FROM config_queries WHERE id=$1', [kpub.configQueryId]))[0].query);
    assert.strictEqual(kcfg.schedule[`fim_scan_${kp.id}_1_0`].query, 'SELECT username, uid, gid, description, directory, shell FROM users');
    assert.ok(kcfg.schedule[`fim_scan_${kp.id}_1_1`].query.includes('LEFT JOIN hash'));
    assert.ok(kcfg.schedule[`fim_scan_${kp.id}_1_2`].query.startsWith('SELECT path, key, value FROM extended_attributes'));
    assert.deepStrictEqual(kcfg.file_paths, { [`fim_${kp.id}`]: ['/etc/ssh/%%'] });
    // initialize uses the very same SQL per entry
    const ki = await svc.initializeBaseline(db, kp.id, { note: 'k', requestedBy: 'a@x' });
    assert.strictEqual(ki.requests, 3);
    const kq = await q(`SELECT r.entry_idx, qq.query FROM fim_init_requests r JOIN query_queue qq ON qq.id=r.queue_id WHERE r.policy_id=$1 ORDER BY r.entry_idx`, [kp.id]);
    assert.deepStrictEqual(kq.map((r: any) => r.query), [0, 1, 2].map((i) => kcfg.schedule[`fim_scan_${kp.id}_1_${i}`].query));
    const mkK = async (kind: string, idx: number, path: string, type: string, sha: string | null, attrs: any) =>
      Number((await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, kind, entry_idx, path, change_type, source, new_sha256, new_attrs, detected_at, last_seen_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'scan',$8,$9::jsonb,1,1) RETURNING id`, [kp.id, kp.name, `${P}-lin1`, kind, idx, path, type, sha, JSON.stringify(attrs)]))[0].id);
    const di = await mkK('item', 0, 'users|alice', 'added', 'valhash', { username: 'alice', uid: '1001', shell: '/bin/bash' });
    const dd = await mkK('directory', 1, '/etc/ssh/newdir', 'added', null, { mode: '0755', uid: 0, gid: 0 });
    const df = await mkK('file', 1, '/etc/ssh/newfile', 'added', null, { size: 3 });
    // a hashless FILE still needs acceptUnverified; items and directories never do
    await assert.rejects(svc.resolveDrift(db, [df], 'approve', 'a@x', 'n', null, null, { expected: await EXP([df]) }), svc.FimUnverifiedError);
    const okk = await svc.resolveDrift(db, [di, dd], 'approve', 'a@x', 'n', null, null, { expected: await EXP([di, dd]) });
    assert.strictEqual(okk.resolved, 2);
    const bi = (await q(`SELECT * FROM fim_baseline WHERE policy_id=$1 AND path='users|alice'`, [kp.id]))[0];
    assert.deepStrictEqual([bi.kind, bi.entry_idx, bi.sha256, bi.size, bi.mode], ['item', 0, 'valhash', null, null]);
    assert.deepStrictEqual(bi.data, { username: 'alice', uid: '1001', shell: '/bin/bash' });
    const bd = (await q(`SELECT * FROM fim_baseline WHERE policy_id=$1 AND path='/etc/ssh/newdir'`, [kp.id]))[0];
    assert.deepStrictEqual([bd.kind, bd.entry_idx, bd.sha256, bd.mode, Number(bd.uid), Number(bd.gid), bd.size, bd.data], ['directory', 1, null, '0755', 0, 0, null, null]);
    // modify then remove the item
    const dm = await mkK('item', 0, 'users|alice', 'modified', 'valhash2', { username: 'alice', uid: '1001', shell: '/bin/zsh' });
    await svc.resolveDrift(db, [dm], 'approve', 'a@x', 'n', null, null, { expected: await EXP([dm]) });
    assert.deepStrictEqual((await q(`SELECT data, sha256 FROM fim_baseline WHERE policy_id=$1 AND path='users|alice'`, [kp.id]))[0], { data: { username: 'alice', uid: '1001', shell: '/bin/zsh' }, sha256: 'valhash2' });
    const dr = await mkK('item', 0, 'users|alice', 'removed', null, {});
    await svc.resolveDrift(db, [dr], 'approve', 'a@x', 'n', null, null, { expected: await EXP([dr]) });
    assert.strictEqual((await q(`SELECT count(*)::int n FROM fim_baseline WHERE policy_id=$1 AND path='users|alice'`, [kp.id]))[0].n, 0);
    // listings carry kind / entry_idx; baseline kind filter; summary by kind
    const dl3 = await svc.listDrift(db, { policy: kp.id }, null, 1, 50);
    assert.deepStrictEqual(Object.fromEntries(dl3.items.map((i) => [i.path + i.changeType, i.kind])), { 'users|aliceadded': 'item', '/etc/ssh/newdiradded': 'directory', '/etc/ssh/newfileadded': 'file', 'users|alicemodified': 'item', 'users|aliceremoved': 'item' });
    const bl2 = await svc.listBaseline(db, { policy: kp.id, kind: 'directory' }, null, 1, 10);
    assert.deepStrictEqual([bl2.total, bl2.items[0].kind, bl2.items[0].entryIdx], [1, 'directory', 1]);
    assert.strictEqual((await svc.listBaseline(db, { policy: kp.id, kind: 'item' }, null, 1, 10)).total, 0);
    const smk = await svc.getSummary(db, null);
    assert.ok(smk.baselineByKind.directory >= 1 && smk.openDriftByKind.file >= 1 && smk.entriesByKind.table >= 1 && smk.entriesByKind.xattr >= 1);
    await svc.deletePolicy(db, kp.id);
    await q('DELETE FROM fim_drift WHERE policy_id=$1', [kp.id]);
    ok('entry kinds: publish/initialize SQL per kind, item/directory approve semantics (no 409 for dirs/items), kind in listings, summary by kind');

    // ---- transactional audit (fim_audit in the SAME transaction as the change) ----
    const AUD = (rq: string) => ({ user: `${P}-aud@x`, userId: 77, requestId: `${P}-${rq}` });
    const auditRows = async (rq: string) => q(`SELECT action, actor, user_id, request_id, details FROM fim_audit WHERE request_id = $1 ORDER BY id`, [`${P}-${rq}`]);
    const pin = (p: svc.FimPolicyView) => ({ name: p.name, description: p.description, osPlatform: p.osPlatform, paths: p.paths, scanIntervalSecs: p.scanIntervalSecs, realtime: p.realtime, mode: p.mode, learnScans: p.learnScans, enabled: p.enabled, template: p.template, targets: p.targets });
    const ad = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-aud`, paths: ['/etc/%%'], targets: [{ type: 'node', value: `${P}-lin1` }] }), `${P}-aud@x`, AUD('c'));
    let ar0 = await auditRows('c');
    assert.deepStrictEqual(ar0.map((r: any) => [r.action, r.actor, Number(r.user_id), r.details.policyId]), [['FIM_POLICY_CREATE', `${P}-aud@x`, 77, ad.id]]);
    const adu = await svc.updatePolicy(db, ad.id, validatePolicyInput({ paths: ['/etc/%%', '/opt/%%'] }, pin(ad)), AUD('u'));
    ar0 = await auditRows('u');
    assert.deepStrictEqual(ar0.map((r: any) => [r.action, r.details.policyId, r.details.revBumped]), [['FIM_POLICY_UPDATE', ad.id, true]]);
    const adp = await svc.publishPolicy(db, ad.id, AUD('p'), { auto: true });
    ar0 = await auditRows('p');
    assert.deepStrictEqual(ar0.map((r: any) => [r.action, r.details.policyId, r.details.configQueryId, r.details.auto]), [['FIM_POLICY_PUBLISH', ad.id, adp.configQueryId, true]]);
    // alerts: close (incl. an oversight alert, by a Super Admin who is not its subject) and reopen
    const now3 = Math.floor(Date.now() / 1000);
    const mkA = async (type: string, meta: unknown) => Number((await q(`INSERT INTO alerts (host_identifier, hostname, unixtime, detection_time, event_code, metadata, is_open, severity, alert_type) VALUES ($1,'h',$2,$2,$3,$4,true,'High',$5) RETURNING id`,
      [`${P}-lin1`, now3, `fimselftest aud ${type}`, meta === null ? null : JSON.stringify(meta), type]))[0].id);
    const auA = await mkA('fim_health', null);
    const auO = await mkA('fim_config', { fim_config: 'critical_approved', by: 'someone-else@x', byUserId: 1 });
    const sa = (rq: string) => ({ hostFilter: null, groupIds: [] as string[], policyFilter: null, user: `${P}-aud@x`, userId: 77, requestId: `${P}-${rq}`, superAdmin: true });
    assert.strictEqual((await svc.closeAlerts(db, [auA, auO], 'true_positive', 'aud note', sa('ac'))).closed, 2);
    ar0 = await auditRows('ac');
    assert.strictEqual(ar0.length, 1);
    assert.strictEqual(ar0[0].action, 'FIM_ALERT_CLOSE');
    assert.deepStrictEqual([ar0[0].details.ids.slice().sort(), ar0[0].details.oversightIds, ar0[0].details.verdict, ar0[0].details.note, Number(ar0[0].user_id)],
      [[auA, auO].sort(), [auO], 'true_positive', 'aud note', 77]);
    assert.strictEqual((await svc.reopenAlerts(db, [auA, auO], sa('ar'), 'reopen why')).reopened, 2);
    ar0 = await auditRows('ar');
    assert.deepStrictEqual(ar0.map((r: any) => [r.action, r.details.ids.slice().sort(), r.details.oversightIds, r.details.note]), [['FIM_ALERT_REOPEN', [auA, auO].sort(), [auO], 'reopen why']]);
    ok('fim_audit rows (actor, user_id, request_id, details) for create/update/publish policy and close/reopen alerts incl. oversight');

    // Rollback: (a) failure after the body (audit already inserted) -> neither change nor audit row
    // survives; (b) the audit INSERT itself fails -> the change is rolled back (not fire-and-forget).
    const failAfter = { query: (s: string, p?: any[]) => ds.query(s, p), transaction: (fn: any) => ds.transaction(async (m) => { await fn(m); throw new Error('injected failure after body'); }) } as unknown as svc.FimDb;
    const failAudit = { query: (s: string, p?: any[]) => ds.query(s, p), transaction: (fn: any) => ds.transaction((m) => fn({ query: (s: string, p?: any[]) => (s.includes('INSERT INTO fim_audit') ? Promise.reject(new Error('injected audit failure')) : m.query(s, p)) })) } as unknown as svc.FimDb;
    for (const [fdb, tag] of [[failAfter, 'fa'], [failAudit, 'fb']] as const) {
      await assert.rejects(svc.createPolicy(fdb, validatePolicyInput({ name: `${P}-aud-${tag}`, paths: ['/x'] }), null, AUD(`${tag}c`)), /injected/);
      assert.strictEqual((await q('SELECT count(*)::int n FROM fim_policies WHERE name=$1', [`${P}-aud-${tag}`]))[0].n, 0);
      await assert.rejects(svc.updatePolicy(fdb, ad.id, validatePolicyInput({ description: `changed-${tag}` }, pin(adu)), AUD(`${tag}u`)), /injected/);
      assert.strictEqual((await svc.fetchPolicy(db, ad.id))!.description, adu.description);
      await assert.rejects(svc.publishPolicy(fdb, ad.id, AUD(`${tag}p`)), /injected/);
      await assert.rejects(svc.deletePolicy(fdb, ad.id, AUD(`${tag}d`)), /injected/);
      assert.ok(await svc.fetchPolicy(db, ad.id));
      assert.strictEqual(await cfgOf(`${P}-lin1`), `18,23,3,${adp.configQueryId}`);
      await assert.rejects(svc.closeAlerts(fdb, [auA, auO], 'false_positive', 'n', sa(`${tag}ac`)), /injected/);
      assert.deepStrictEqual((await q('SELECT is_open FROM alerts WHERE id = ANY($1::bigint[])', [[auA, auO]])).map((r: any) => r.is_open), [true, true]);
      await q('UPDATE alerts SET is_open=false WHERE id = ANY($1::bigint[])', [[auA, auO]]);
      await assert.rejects(svc.reopenAlerts(fdb, [auA, auO], sa(`${tag}ar`)), /injected/);
      assert.deepStrictEqual((await q('SELECT is_open FROM alerts WHERE id = ANY($1::bigint[])', [[auA, auO]])).map((r: any) => r.is_open), [false, false]);
      await q('UPDATE alerts SET is_open=true WHERE id = ANY($1::bigint[])', [[auA, auO]]);
      for (const k of ['c', 'u', 'p', 'd', 'ac', 'ar']) assert.strictEqual((await auditRows(`${tag}${k}`)).length, 0, `${tag}${k}`);
    }
    await svc.deletePolicy(db, ad.id, AUD('d'));
    ar0 = await auditRows('d');
    assert.deepStrictEqual(ar0.map((r: any) => [r.action, r.details.policyId, r.details.name, r.details.nodesRemoved]), [['FIM_POLICY_DELETE', ad.id, `${P}-aud`, 1]]);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    ok('audit is transactional: injected failure rolls back change + audit row; failing audit insert aborts the change');

    // ---- config_id order: other ids keep their exact order (last-writer-wins merge) ----
    // Run inside one transaction that is rolled back (reconcileManagedNodes is fleet-wide), with a
    // merge-join plan forced: that plan sorted the surviving ids before (e.g. '9,3,7' -> '3,7,9').
    const ORDER_DONE = new Error('order test done (rollback)');
    await assert.rejects(db.transaction(async (tq) => {
      await tq.query('SET LOCAL enable_hashjoin = off');
      await tq.query('SET LOCAL enable_nestloop = off');
      const mh = `${P}-ordw`; const oh = `${P}-ordo`;
      await tq.query(`INSERT INTO nodes (host_identifier, os_platform, config_id, owner_group_id, node_key) VALUES ($1,'windows','9,3,7',null,$1)`, [mh]);
      const cqm = Number(rowsOfAny(await tq.query(`INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch) VALUES ('{}','fim:fimselftest-ord','Windows','','') RETURNING id`))[0].id);
      await tq.query(`INSERT INTO nodes (host_identifier, os_platform, config_id, owner_group_id, node_key) VALUES ($1,'windows',$2,null,$1)`, [oh, `9,${cqm},3,7`]);
      await tq.query(`INSERT INTO fim_policies (name, os_platform, paths, enabled, managed_kind, managed_host, config_query_id) VALUES ($1,'windows','[]'::jsonb,true,'registry_node',$2,$3)`, [`${P}-ord`, mh, cqm]);
      await svc.reconcileManagedNodes(tq);
      const c = async (h: string) => rowsOfAny(await tq.query('SELECT config_id FROM nodes WHERE host_identifier=$1', [h]))[0].config_id;
      assert.strictEqual(await c(mh), `9,3,7,${cqm}`); // appended at the end, others untouched
      assert.strictEqual(await c(oh), '9,3,7'); // stripped, order kept
      // plain policy publish / unpublish under the same plan settings
      await tq.query(`UPDATE nodes SET config_id = '9,3,7' WHERE host_identifier = $1`, [`${P}-lin3`]);
      const op = rowsOfAny(await tq.query(`INSERT INTO fim_policies (name, os_platform, paths, enabled) VALUES ($1,'linux','["/etc/%%"]'::jsonb,true) RETURNING id`, [`${P}-ordp`]))[0];
      await tq.query(`INSERT INTO fim_policy_targets (policy_id, target_type, target_value) VALUES ($1,'node',$2)`, [op.id, `${P}-lin3`]);
      const pr = await svc.publishPolicyTx(tq, Number(op.id));
      assert.strictEqual(await c(`${P}-lin3`), `9,3,7,${pr.configQueryId}`);
      await tq.query(`UPDATE nodes SET config_id = $2 WHERE host_identifier = $1`, [`${P}-lin3`, `9,${pr.configQueryId},3,7`]);
      await tq.query(`UPDATE fim_policies SET enabled = false WHERE id = $1`, [op.id]);
      await svc.publishPolicyTx(tq, Number(op.id));
      assert.strictEqual(await c(`${P}-lin3`), '9,3,7');
      throw ORDER_DONE;
    }), (e: unknown) => e === ORDER_DONE);
    ok("config_id rewrites keep the other ids' order ('9,3,7' -> '9,3,7,<ours>'; removal keeps '9,3,7') even under a merge-join plan");

    // transaction atomicity: failure mid-publish rolls back everything. Isolated: the failure is
    // injected inside this test's own transaction (no ALTER of the shared table, no global counts).
    const apx2 = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-t`, paths: [{ path: '/etc/%%' }], targets: [{ type: 'group', value: 'gA' }] }), null);
    await assert.rejects(db.transaction(async (tq) => {
      await svc.publishPolicyTx(tq, apx2.id);
      throw new Error('injected failure after publish');
    }), /injected failure/);
    assert.strictEqual((await q(`SELECT count(*)::int n FROM config_queries WHERE query_name = $1`, [`fim:${P}-t`]))[0].n, 0);
    assert.strictEqual((await q('SELECT config_query_id FROM fim_policies WHERE id = $1', [apx2.id]))[0].config_query_id, null);
    assert.strictEqual(await cfgOf(`${P}-lin1`), '18,23,3');
    ok('publish is atomic (rollback leaves config_queries and nodes untouched)');
    console.log(`\n${n} DB groups passed`);
  } finally {
    await cleanup();
    await tdb.drop();
  }
})().catch((e) => { console.error(e); process.exit(1); });
