/**
 * FIM oversight-alert guard (alert_type 'fim_config') against a THROWAWAY Postgres:
 *   FIM_TEST_PG=127.0.0.1:55432 node_modules/.bin/ts-node src/test/services/fimAlertsGuard.selftest.ts
 * (user fimtest, no password, database fimdb). Without FIM_TEST_PG it FAILS unless FIM_ALLOW_SKIP=1.
 *
 * Covers:
 *  - guardGenericAlertUpdate (the rule the generic POST /api/alerts/update applies);
 *  - the generic express handler itself (src/index is stubbed so no server starts; the fleet DB is
 *    the throwaway database): a Group Admin can no longer close / reopen / mark a fim_config alert;
 *  - closeAlerts / reopenAlerts decide "own oversight alert" by USER ID when metadata has byUserId;
 *  - oversight alerts written by fimService carry byUserId.
 * Seeds rows with the prefix fimguardtest and removes them afterwards.
 */
import 'reflect-metadata';
import assert from 'assert';
import path from 'path';
import { openFimTestDb } from './fimTestDb';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set (host:port of a throwaway Postgres); set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}
const P = 'fimguardtest';

// Fake "primary" DB: vajra_users / memberships for getUserNodeScope, and a no-op audit_trail repo.
const USERS: Record<number, { role: string; groups: string[] }> = {
  9101: { role: 'Super Administrator', groups: [] }, // SA "other"
  9102: { role: 'Super Administrator', groups: [] }, // SA who is the subject of the alerts
  9103: { role: 'Admin', groups: [`${P}-g`] }, // Group Admin of the alert's group
};
const auditTrail: any[] = [];
const primary = {
  isInitialized: true,
  query: async (_sql: string, params: any[]) => {
    const u = USERS[Number(params[0])];
    if (!u) return [];
    if (!u.groups.length) return [{ role: u.role, group_id: null, membership_role: null }];
    return u.groups.map((g) => ({ role: u.role, group_id: g, membership_role: 'Group Admin' }));
  },
  getRepository: () => ({ create: (x: any) => x, save: async (x: any) => { auditTrail.push(x); return x; } }),
};
let fleet: { query: (sql: string, params?: any[]) => Promise<any> } | null = null;
/** Race hook: runs (committed, on another connection) right before the handler's next UPDATE of alerts. */
let beforeAlertUpdate: (() => Promise<void>) | null = null;
// Stub src/index BEFORE the controller is loaded (importing the real one would boot the server).
const indexPath = require.resolve(path.join(__dirname, '../../index'));
require.cache[indexPath] = { id: indexPath, filename: indexPath, loaded: true, exports: { dbSourceConnection: () => [primary, fleet] } } as any;

const svc = require('../../services/fimService') as typeof import('../../services/fimService');
const { alert_update } = require('../../controllers/alerts/alert_update') as typeof import('../../controllers/alerts/alert_update');

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  fleet = {
    query: async (sql: string, params?: any[]) => {
      if (beforeAlertUpdate && /^\s*UPDATE\s+alerts\b/i.test(sql)) { const h = beforeAlertUpdate; beforeAlertUpdate = null; await h(); }
      return ds.query(sql, params);
    },
  };
  const db = ds as unknown as import('../../services/fimService').FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  await q('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_group_id text');
  let n = 0;
  const ok = (m: string) => { n++; console.log(`ok - ${m}`); };
  const H = `${P}-h1`;

  const cleanup = async () => {
    const pols = await q(`SELECT id, config_query_id FROM fim_policies WHERE name LIKE $1`, [`${P}%`]);
    for (const p of pols) {
      await q('DELETE FROM fim_drift WHERE policy_id=$1', [p.id]);
      if (p.config_query_id) await q('DELETE FROM config_queries WHERE id=$1', [p.config_query_id]);
    }
    await q(`DELETE FROM fim_policies WHERE name LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_drift WHERE policy_name = $1`, [`${P}-pol`]);
    await q(`DELETE FROM alerts WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_audit WHERE actor LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`]);
  };
  await cleanup();
  try {
    await q(`INSERT INTO nodes (host_identifier, os_platform, config_id, owner_group_id, node_key) VALUES ($1,'windows','',$2,$1)`, [H, `${P}-g`]);
    const mkAlert = async (type: string, meta: unknown, open = true) => Number((await q(
      `INSERT INTO alerts (host_identifier, hostname, unixtime, detection_time, event_code, metadata, is_open, severity, alert_type)
       VALUES ($1,'h',1,1,$2,$3,$4,'High',$5) RETURNING id`,
      [H, `${P} ${type}`, meta === null ? null : typeof meta === 'string' ? meta : JSON.stringify(meta), open, type]))[0].id);
    const isOpen = async (id: number) => (await q('SELECT is_open FROM alerts WHERE id=$1', [id]))[0].is_open as boolean;
    const markOf = async (id: number) => (await q('SELECT mark_type FROM alerts WHERE id=$1', [id]))[0].mark_type as string | null;

    // ---- 1. guardGenericAlertUpdate (pure DB rule) ----
    const cfgById = await mkAlert('fim_config', { fim_config: 'critical_approved', by: 'renamed@x', byUserId: 9102 });
    const cfgByMail = await mkAlert('fim_config', { fim_config: 'forced_reinit', by: 'subject@x' });
    const cfgLegacy = await mkAlert('fim_config', 'not json {{');
    const health = await mkAlert('fim_health', null);
    const drift = await mkAlert('fim', null);
    const ga = { userId: 9103, email: 'ga@x', superAdmin: false };
    const g1 = await svc.guardGenericAlertUpdate(db, [cfgById, cfgByMail, cfgLegacy, health, drift], ga);
    assert.deepStrictEqual(g1.allowed, [String(health), String(drift)]);
    assert.deepStrictEqual(g1.blocked.map((b) => [b.id, b.reason]).sort(), [cfgById, cfgByMail, cfgLegacy].map((i) => [String(i), 'oversight_super_admin_only']).sort());
    // the subject (by user id, although metadata.by holds a different e-mail) is refused
    const g2 = await svc.guardGenericAlertUpdate(db, [cfgById, cfgByMail], { userId: 9102, email: 'subject@x', superAdmin: true });
    assert.deepStrictEqual(g2.blocked.map((b) => [b.id, b.reason]), [[String(cfgById), 'oversight_own_action'], [String(cfgByMail), 'oversight_own_action']]);
    // byUserId present: compared by id only (same e-mail, different id -> not the subject)
    const g3 = await svc.guardGenericAlertUpdate(db, [cfgById], { userId: 9101, email: 'renamed@x', superAdmin: true });
    assert.deepStrictEqual([g3.allowed, g3.blocked], [[String(cfgById)], []]);
    // another Super Admin may act on all of them
    const g4 = await svc.guardGenericAlertUpdate(db, [cfgById, cfgByMail, cfgLegacy, health], { userId: 9101, email: 'other@x', superAdmin: true });
    assert.strictEqual(g4.blocked.length, 0);
    assert.strictEqual(svc.isOwnOversightAlert(JSON.stringify({ by: 'A@X' }), { user: 'a@x', userId: null }), true);
    assert.strictEqual(svc.isOwnOversightAlert(JSON.stringify({ by: 'a@x', byUserId: 5 }), { user: 'a@x', userId: 6 }), false);
    assert.strictEqual(svc.isOwnOversightAlert(JSON.stringify({ by: 'b@x', byUserId: '6' }), { user: 'a@x', userId: 6 }), true);
    assert.strictEqual(svc.isOwnOversightAlert(JSON.stringify({ by: 'a@x', byUserId: 5 }), { user: 'a@x', userId: null }), true); // caller id unknown -> e-mail
    ok('guardGenericAlertUpdate: fim_config Super Admin only, never the subject (user id first, else e-mail); fim_health / fim untouched');

    // ---- 2. the generic express handler ----
    const call = async (userId: number, body: any) => {
      const out: { status: number; body: any } = { status: 0, body: null };
      const res: any = { status(c: number) { out.status = c; return res; }, json(b: any) { out.body = b; return res; } };
      const req: any = { body, jwtPayload: { id: userId, email: `${P}-u${userId}@x` }, ip: '127.0.0.1', socket: {}, get: () => 'selftest' };
      await alert_update(req, res, () => undefined);
      return out;
    };
    let r = await call(9103, { event_id: [cfgById], is_open: false });
    assert.strictEqual(r.status, 403, JSON.stringify(r.body));
    assert.strictEqual(await isOpen(cfgById), true);
    r = await call(9103, { event_id: [cfgByMail], action: 'false_positive' });
    assert.strictEqual(r.status, 403);
    assert.strictEqual(await markOf(cfgByMail), null);
    await q('UPDATE alerts SET is_open=false WHERE id=$1', [cfgLegacy]);
    r = await call(9103, { event_id: [cfgLegacy], is_open: true }); // reopen
    assert.strictEqual(r.status, 403);
    assert.strictEqual(await isOpen(cfgLegacy), false);
    // mixed request: the in-scope health alert is closed, the oversight alert is not
    r = await call(9103, { event_id: [cfgById, health], is_open: false });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.deepStrictEqual([await isOpen(cfgById), await isOpen(health)], [true, false]);
    assert.ok(auditTrail.some((a) => a.status === 'failure' && a.details?.blocked?.some((b: any) => b.id === String(cfgById))));
    // Super Admin who is the subject (by user id) is refused; another Super Admin may close it
    r = await call(9102, { event_id: [cfgById], is_open: false });
    assert.strictEqual(r.status, 403);
    assert.strictEqual(await isOpen(cfgById), true);
    r = await call(9101, { event_id: [cfgById], is_open: false });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(await isOpen(cfgById), false);
    ok('POST /api/alerts/update: Group Admin cannot close/reopen/mark fim_config (403), mixed lists drop only those, subject SA refused, other SA allowed');

    // ---- 2b. fim drift alerts through the generic endpoint ----
    const mkDrift = async (alertId: number | null, status: string, metaLink = false) => Number((await q(
      `INSERT INTO fim_drift (policy_id, policy_name, host_identifier, hostname, path, change_type, source, status, new_sha256, detected_at, last_seen_at, alert_id)
       VALUES (987650001, $1, $2, 'h', $3, 'added', 'scan', $4, 'sha', 1, 1, $5) RETURNING id`,
      [`${P}-pol`, H, `/g/${Math.random()}`, status, metaLink ? null : alertId]))[0].id);
    const fOpen = await mkAlert('fim', null); await mkDrift(fOpen, 'open');
    const fMeta = await mkAlert('fim', null); const dm = await mkDrift(null, 'open', true);
    await q('UPDATE alerts SET metadata = $2 WHERE id = $1', [fMeta, JSON.stringify({ drift_id: dm })]); // linked via metadata only
    const fDone = await mkAlert('fim', null); await mkDrift(fDone, 'rejected');
    const health2 = await mkAlert('fim_health', null);
    for (const uid of [9103, 9101]) { // Group Admin and Super Admin alike: the drift must be resolved with the alert
      r = await call(uid, { event_id: [fOpen, fMeta], is_open: false });
      assert.strictEqual(r.status, 403, JSON.stringify(r.body));
      assert.deepStrictEqual(r.body.blocked.map((b: any) => [b.id, b.reason]).sort(), [[String(fOpen), 'fim_drift_open_use_fim_routes'], [String(fMeta), 'fim_drift_open_use_fim_routes']].sort());
      r = await call(uid, { event_id: [fOpen], action: 'true_positive' });
      assert.strictEqual(r.status, 403);
    }
    assert.deepStrictEqual([await isOpen(fOpen), await isOpen(fMeta), await markOf(fOpen)], [true, true, null]);
    // partial block: 200 with the blocked ids + reasons; the rest is applied
    r = await call(9103, { event_id: [fOpen, health2, fDone], is_open: false });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.blocked, [{ id: String(fOpen), alert_type: 'fim', reason: 'fim_drift_open_use_fim_routes' }]);
    assert.deepStrictEqual(r.body.ids.slice().sort(), [String(health2), String(fDone)].sort());
    assert.deepStrictEqual([await isOpen(fOpen), await isOpen(health2), await isOpen(fDone)], [true, false, false]); // resolved drift: closable
    // reopen is allowed (the FIM reopen route does not touch drift either)
    await q('UPDATE alerts SET is_open = false WHERE id = $1', [fOpen]);
    r = await call(9103, { event_id: [fOpen], is_open: true });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(await isOpen(fOpen), true);
    // the oversight 403 also lists what was blocked
    r = await call(9103, { event_id: [cfgByMail], is_open: false });
    assert.deepStrictEqual([r.status, r.body.blocked], [403, [{ id: String(cfgByMail), alert_type: 'fim_config', reason: 'oversight_super_admin_only' }]]);
    ok('generic endpoint: fim alerts with an open linked drift (alert_id or metadata) cannot be closed/marked (403 + blocked list); partial 200 lists blocked; resolved-drift close and reopen allowed');

    // ---- 2c. race: a drift linked AFTER any check but BEFORE the write must still block the close ----
    // The hook commits the open drift on another connection right before the handler's UPDATE runs,
    // i.e. the condition only becomes true "inside" the update. A check-then-update closes the alert;
    // the single guarded UPDATE does not.
    for (const body of [{ is_open: false }, { action: 'false_positive' }]) {
      const fRace = await mkAlert('fim', null);
      beforeAlertUpdate = async () => { await mkDrift(fRace, 'open'); };
      r = await call(9103, { event_id: [fRace], ...body });
      assert.strictEqual(beforeAlertUpdate, null, 'hook ran');
      assert.strictEqual(r.status, 403, JSON.stringify(r.body));
      assert.deepStrictEqual(r.body.blocked, [{ id: String(fRace), alert_type: 'fim', reason: 'fim_drift_open_use_fim_routes' }]);
      assert.deepStrictEqual([await isOpen(fRace), await markOf(fRace)], [true, null]);
    }
    // same for an oversight alert that names the caller only by the time the UPDATE runs
    const cRace = await mkAlert('fim_config', { fim_config: 'x', by: 'nobody@x' });
    beforeAlertUpdate = async () => { await q('UPDATE alerts SET metadata = $2 WHERE id = $1', [cRace, JSON.stringify({ fim_config: 'x', by: 'nobody@x', byUserId: 9101 })]); };
    r = await call(9101, { event_id: [cRace], is_open: false });
    assert.deepStrictEqual([r.status, r.body.blocked], [403, [{ id: String(cRace), alert_type: 'fim_config', reason: 'oversight_own_action' }]]);
    assert.strictEqual(await isOpen(cRace), true);
    ok('generic endpoint is atomic: a drift linked / an oversight subject set between check and write still blocks the update');

    // ---- 3. FIM routes: "own alert" by user id ----
    const own = await mkAlert('fim_config', { fim_config: 'critical_approved', by: `${P}-old-mail@x`, byUserId: 9102 });
    const actor = (userId: number, user: string) => ({ hostFilter: null, groupIds: [] as string[], policyFilter: null, user: `${P}-${user}`, userId, superAdmin: true });
    let c = await svc.closeAlerts(db, [own], 'true_positive', 'n', actor(9102, 'new-mail@x')); // e-mail changed, id is the subject
    assert.strictEqual(c.closed, 0);
    c = await svc.closeAlerts(db, [own], 'true_positive', 'n', actor(9101, 'old-mail@x')); // same e-mail, other id
    assert.strictEqual(c.closed, 1);
    assert.strictEqual((await svc.reopenAlerts(db, [own], actor(9102, 'new-mail@x'))).reopened, 0);
    assert.strictEqual((await svc.reopenAlerts(db, [own], actor(9101, 'x'))).reopened, 1);
    ok('closeAlerts / reopenAlerts: own oversight alert decided by user id when metadata carries byUserId');

    // ---- 4. oversight alerts written by fimService carry byUserId ----
    const { REG_CATALOG } = await import('../../utils/fim/fimRegistryCatalog');
    const prot = REG_CATALOG.find((e: any) => e.protected);
    assert.ok(prot, 'a protected catalog entry exists');
    const pid = Number((await q(
      `INSERT INTO fim_policies (name, os_platform, paths, enabled, managed_kind, managed_host) VALUES ($1,'windows',$2::jsonb,true,'registry_node',$3) RETURNING id`,
      [`${P}-managed`, JSON.stringify([{ kind: 'registry', entryKey: prot!.id, path: 'HKEY_LOCAL_MACHINE\\x', severity: 'critical' }]), H]))[0].id);
    const did = Number((await q(
      `INSERT INTO fim_drift (policy_id, policy_name, host_identifier, kind, entry_idx, path, change_type, source, severity, new_sha256, new_attrs, detected_at, last_seen_at)
       VALUES ($1,$2,$3,'item',0,'registry|HKEY_LOCAL_MACHINE\\x|v','modified','scan','critical','h1','{"data":"1"}'::jsonb,1,1) RETURNING id`, [pid, `${P}-managed`, H]))[0].id);
    const exp = Object.fromEntries((await q('SELECT * FROM fim_drift WHERE id=$1', [did])).map((x: any) => [String(x.id), { contentHash: svc.driftContentHash(x) }]));
    await svc.resolveDrift(db, [did], 'approve', `${P}-sa@x`, 'n', null, null, { expected: exp, actorUserId: 9102 });
    const ca = (await q(`SELECT metadata FROM alerts WHERE host_identifier=$1 AND alert_type='fim_config' AND metadata LIKE '%critical_approved%' AND metadata LIKE $2`, [H, `%${P}-sa@x%`]));
    assert.strictEqual(ca.length, 1);
    assert.strictEqual(JSON.parse(ca[0].metadata).byUserId, 9102);
    // forced re-init of slots with open critical drift
    await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, kind, entry_idx, path, change_type, source, severity, new_sha256, detected_at, last_seen_at)
             VALUES ($1,$2,$3,'item',0,'registry|HKEY_LOCAL_MACHINE\\x|w','modified','scan','critical','h2',1,1)`, [pid, `${P}-managed`, H]);
    await q(`INSERT INTO fim_policy_targets (policy_id, target_type, target_value) VALUES ($1,'node',$2)`, [pid, H]);
    const ir = await svc.initializeBaseline(db, pid, { note: 'n', requestedBy: `${P}-sa@x`, requestedByUserId: 9102, force: true });
    assert.strictEqual(ir.hosts, 1);
    const fr = (await q(`SELECT metadata FROM alerts WHERE host_identifier=$1 AND alert_type='fim_config' AND metadata LIKE '%forced_reinit%' AND metadata LIKE $2`, [H, `%${P}-sa@x%`]));
    assert.strictEqual(fr.length, 1);
    assert.strictEqual(JSON.parse(fr[0].metadata).byUserId, 9102, fr[0].metadata);
    await q('DELETE FROM query_queue WHERE host_identifier=$1', [H]);
    await q('DELETE FROM fim_init_requests WHERE policy_id=$1', [pid]);
    ok('critical_approved / forced_reinit oversight alerts carry byUserId');

    console.log(`\n${n} guard groups passed`);
  } finally {
    await cleanup();
    await tdb.drop();
  }
})().catch((e) => { console.error(e); process.exit(1); });
