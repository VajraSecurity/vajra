/**
 * DB-backed integration test for services/fimRegistryService.ts against a THROWAWAY Postgres:
 *   FIM_TEST_PG=127.0.0.1:55432 node_modules/.bin/ts-node src/test/services/fimRegistryDb.selftest.ts
 * (user fimtest, no password, database fimdb). Without FIM_TEST_PG it FAILS unless FIM_ALLOW_SKIP=1
 * (a silently skipped DB suite is not a passing one).
 * Seeds its own rows (prefix fimregtest), restores fim_reg_settings and removes everything after.
 * Covers design §5.1 API/RBAC items and §5.3 integration items plus one regression test per
 * reviewer finding (names in the ok() lines): publish -> config_queries, slots/tombstones,
 * nodes.config_id, RBAC/IDOR, viewer-only actor, protected entries and two-person waivers bound to
 * one rule (user ids, designated approvers, the DB CHECK), stale-hash 409, preview writes nothing,
 * per-slot Initialize (scoped supersede), forced re-init alert, drift carried on a definition
 * change (A-HIGH1), approve guards (unconfirmed real-time drift, TOCTOU expected values,
 * case-insensitive baseline identity, critical protected approval alert), fim_config alerts closed
 * by other Super Admins only, measure + rate limit + implausible results, invalid resolution keeps
 * the last good config + auto-publish back-off + invalid alert, soft-retire + revival + purge, group
 * move, waiver expiry and revoke across > 200 nodes, kill-switch race, write-on-change sweep,
 * keyed/anchored hash chain (tamper, HMAC rewrite, tail truncation, role-gated trigger),
 * rules-vs-history divergence, rollback with the caller's permissions, compaction, profile
 * assignment guards, feature backout/restore, removed node, concurrent publishes, migration
 * assistant and template v2 upgrade.
 */
import 'reflect-metadata';
import assert from 'assert';
import { openFimTestDb } from './fimTestDb';
import * as svc from '../../services/fimService';
import * as reg from '../../services/fimRegistryService';
import { FimValidationError, validatePolicyInput } from '../../utils/fim/fimLogic';
import { FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL } from '../../utils/fim/fimRegistryDdl';
import { customEntryKey } from '../../utils/fim/fimRegistrySql';

const addr = process.env.FIM_TEST_PG;
if (!addr) {
  if (process.env.FIM_ALLOW_SKIP === '1') { console.log('SKIP (FIM_ALLOW_SKIP=1): FIM_TEST_PG not set'); process.exit(0); }
  console.error('FAIL: FIM_TEST_PG is not set (host:port of a throwaway Postgres); set FIM_ALLOW_SKIP=1 to skip explicitly');
  process.exit(1);
}
// The chain is keyed in this run (production refuses to start without a key).
process.env.FIM_HISTORY_HMAC_KEY = process.env.FIM_HISTORY_HMAC_KEY || 'fimregtest-history-key-0123456789abcdef';
const P = 'fimregtest';
const H = (s: string) => `${P}-${s}`;
const L = 'HKEY_LOCAL_MACHINE\\';
// Roles are cluster-wide: a per-run name so concurrent runs never touch each other's role.
const PROBE_ROLE = `fimregtest_probe_${process.pid}`;

const actor = (email: string, userId: number | null, superAdmin: boolean, groups: string[] = [], hosts: string[] = [], viewOnlyHosts: string[] = []): reg.RegActor => ({
  email, userId, superAdmin, actGroups: new Set(groups), actHosts: superAdmin ? null : new Set(hosts),
  viewHosts: superAdmin ? null : new Set([...hosts, ...viewOnlyHosts]), viewGroups: new Set(groups), requestId: `${P}-req`,
});
const RUN_KEY = 'registry|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\';

(async () => {
  const tdb = await openFimTestDb(addr!);
  const ds = tdb.ds;
  // The suite seeds nodes with small fake config ids (7, 8, 18, 23, ...): on a FRESH database the
  // config_queries sequence would hand out the same numbers, so start it above them.
  await ds.query(`SELECT setval('config_queries_id_seq', GREATEST((SELECT COALESCE(max(id), 0) FROM config_queries), 1000))
                  WHERE (SELECT last_value FROM config_queries_id_seq) < 1000`);
  const db = ds as unknown as svc.FimDb;
  const q = (s: string, p?: any[]) => ds.query(s, p);
  await q(FIM_REGISTRY_DDL); // idempotent: the same DDL the backend runs on boot
  await q(FIM_VERIFY_DDL);
  await q(FIM_WORKER_DDL);
  await q(FIM_PERF_DDL);
  await q('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_group_id text');
  let n = 0;
  const t0 = Date.now();
  const ok = (m: string) => { n++; console.log(`ok - ${m}`); };
  const hosts = ['w1', 'w2', 'w3', 'w4', 'w5', 'lin'].map(H);
  const bulk = Array.from({ length: 210 }, (_, i) => H(`h${String(i).padStart(3, '0')}`));
  const only = new Set([...hosts, ...bulk]);
  const SA = actor(`${P}-sa@x`, 9001, true);
  const SA2 = actor(`${P}-sa2@x`, 9002, true);
  const GA = actor(`${P}-ga@x`, 9003, false, [H('gA')], [H('w1'), H('w2'), H('w4'), H('w5'), H('lin')]);
  const GB = actor(`${P}-gb@x`, 9004, false, [H('gB')], [H('w3')]);
  const APR = actor(`${P}-approver@x`, 9005, false, [], [H('w1')]); // designated approver with act scope on w1 only
  const VIEW = actor(`${P}-viewer@x`, 9006, false, [], [], [H('w1')]);   // viewer only
  const SAasGA = { ...SA, email: `${P}-SA-alias@x`, userId: GA.userId }; // same user id, different e-mail
  const alertActor = (a: reg.RegActor): svc.AlertActor => ({ hostFilter: a.superAdmin ? null : [...(a.actHosts ?? [])], groupIds: [...a.actGroups], policyFilter: null, user: a.email, superAdmin: a.superAdmin });
  const origSettings = (await q('SELECT managed_enabled, approvers FROM fim_reg_settings WHERE id'))[0] ?? { managed_enabled: false, approvers: [] };

  const cleanup = async () => {
    await q(`UPDATE fim_reg_settings SET managed_enabled = $1, approvers = $2::jsonb WHERE id`, [origSettings.managed_enabled, JSON.stringify(origSettings.approvers ?? [])]);
    const pols = await q(`SELECT id, config_query_id FROM fim_policies WHERE managed_host LIKE $1 OR name LIKE $2`, [`${P}%`, `${P}%`]);
    for (const p of pols) if (p.config_query_id) await q('DELETE FROM config_queries WHERE id = $1', [p.config_query_id]);
    await q(`DELETE FROM query_queue WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM query_result WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_verify_requests WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_drift WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_policies WHERE managed_host LIKE $1 OR name LIKE $2`, [`${P}%`, `${P}%`]);
    await q(`DELETE FROM fim_reg_rules WHERE scope_value LIKE $1 OR created_by LIKE $1 OR scope_value IN (SELECT id::text FROM fim_reg_profiles WHERE name LIKE $1)`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_assignments WHERE scope_value LIKE $1 OR profile_id IN (SELECT id FROM fim_reg_profiles WHERE name LIKE $1)`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_rules WHERE waiver_id IN (SELECT id FROM fim_reg_waivers WHERE scope_value LIKE $1 OR requested_by LIKE $1)`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_waivers WHERE scope_value LIKE $1 OR requested_by LIKE $1 OR scope_value IN (SELECT id::text FROM fim_reg_profiles WHERE name LIKE $1)`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_jobs WHERE created_by LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM fim_reg_profiles WHERE name LIKE $1`, [`${P}%`]);
    for (const t of ['fim_reg_slots', 'fim_reg_effective', 'fim_reg_measure', 'fim_reg_hygiene_ack']) await q(`DELETE FROM ${t} WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM alerts WHERE host_identifier LIKE $1 OR event_code LIKE $2 OR metadata LIKE $3`, [`${P}%`, `%${P}%`, `%${P}%`]);
    await q(`DELETE FROM fim_audit WHERE actor LIKE $1 OR request_id LIKE $1 OR details::text LIKE $2`, [`${P}%`, `%${P}%`]);
    await q(`DELETE FROM nodes WHERE host_identifier LIKE $1`, [`${P}%`]);
    await q(`DELETE FROM dead_letter_queue WHERE table_name LIKE 'fimreg%'`);
    // history is append-only: test rows are removed under the explicit maintenance flag only
    await ds.transaction(async (m) => {
      await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
      await m.query(`DELETE FROM fim_reg_history WHERE scope_value LIKE $1 OR actor LIKE $1 OR scope_value IN (SELECT id::text FROM fim_reg_profiles WHERE name LIKE $1)`, [`${P}%`]);
      await m.query(`DELETE FROM fim_reg_anchor_outbox o WHERE NOT EXISTS (SELECT 1 FROM fim_reg_history h WHERE h.id = o.history_id)`);
      await m.query(`UPDATE fim_reg_history_hwm SET head_id = COALESCE((SELECT max(id) FROM fim_reg_history), 0),
        row_hash = (SELECT row_hash FROM fim_reg_history ORDER BY id DESC LIMIT 1), row_count = (SELECT count(*) FROM fim_reg_history) WHERE id`);
      await m.query(`UPDATE fim_reg_settings SET history_head_id = COALESCE((SELECT max(id) FROM fim_reg_history), 0) WHERE id`);
      if (!(await m.query('SELECT 1 FROM fim_reg_history LIMIT 1')).length) await m.query(`DELETE FROM fim_reg_history_keys WHERE key_id IN ('k1','k2')`);
    });
    if ((await q(`SELECT 1 FROM pg_roles WHERE rolname = $1`, [PROBE_ROLE])).length) {
      await q(`REVOKE ALL ON fim_reg_history FROM ${PROBE_ROLE}`);
      await q(`DROP ROLE ${PROBE_ROLE}`);
    }
  };
  await cleanup();
  const cfgOf = async (h: string) => (await q('SELECT config_id FROM nodes WHERE host_identifier = $1', [h]))[0].config_id as string | null;
  const pol = async (h: string) => (await q(`SELECT * FROM fim_policies WHERE managed_kind = 'registry_node' AND managed_host = $1`, [h]))[0];
  const exp = () => Math.floor(Date.now() / 1000) + 86400;
  const EXP = (d: any) => ({ [String(d.id)]: { contentHash: svc.driftContentHash(d) } });
  const drift = async (polId: number, h: string, path: string, slot: number, extra: Record<string, unknown> = {}) => {
    const v = { change_type: 'modified', source: 'scan', severity: 'high', kind: 'item', new_sha256: 'n1', last_seen_at: 100, confirmed_at: null as number | null, ...extra };
    return (await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx, new_sha256, new_attrs, confirmed_at)
       VALUES ($1,'x',$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11::jsonb,$12) RETURNING *`,
      [polId, h, path, v.change_type, v.source, v.severity, v.last_seen_at, v.kind, slot, v.new_sha256, JSON.stringify({ name: 'x', data: 'y' }), v.confirmed_at]))[0];
  };
  try {
    const nodeRows: [string, string, string, string | null][] = [[H('w1'), 'windows', H('gA'), '7,8'], [H('w2'), 'windows', H('gA'), null], [H('w3'), 'windows', H('gB'), '9'], [H('w4'), 'windows', H('gA'), null], [H('lin'), 'ubuntu', H('gA'), null]];
    for (const [h, plat, g, cfg] of nodeRows) {
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, config_id, node_key, hostname) VALUES ($1,$2,$3,$4,$5,$6)`, [h, plat, g, cfg, h, h]);
    }

    // --- feature switch ------------------------------------------------------------------------
    await q('UPDATE fim_reg_settings SET managed_enabled = false WHERE id');
    await assert.rejects(reg.publishNode(db, H('w1'), { actor: SA, note: 't' }), svc.FimBadRequestError);
    await assert.rejects(reg.setManagedEnabled(db, true, GA, 'x'), reg.FimForbiddenError);
    await reg.setManagedEnabled(db, true, SA, `${P} enable`);
    ok('feature switch: off refuses publish; only a Super Admin can turn it on');

    // --- first publish ------------------------------------------------------------------------
    const r1 = await reg.publishNode(db, H('w1'), { actor: SA, note: `${P} first` });
    assert.strictEqual(r1.status, 'needs_init');
    const p1 = await pol(H('w1'));
    assert.ok(p1 && p1.enabled && p1.realtime && p1.os_platform === 'windows');
    const cq = (await q('SELECT * FROM config_queries WHERE id = $1', [p1.config_query_id]))[0];
    const cfg = JSON.parse(cq.query);
    const schedKeys = Object.keys(cfg.schedule);
    assert.ok(p1.paths.length > 0 && schedKeys.length === p1.paths.length, 'non-empty schedule, one key per slot');
    assert.ok(schedKeys.every((k) => k.startsWith(`fim_scan_${p1.id}_${p1.rev}_`)));
    assert.ok(Object.values(cfg.schedule).every((s: any) => s.snapshot === true && s.query.includes('FROM registry')));
    assert.strictEqual(await cfgOf(H('w1')), `7,8,${p1.config_query_id}`);
    assert.strictEqual(await cfgOf(H('w3')), '9');
    const targets = await q('SELECT target_type, target_value FROM fim_policy_targets WHERE policy_id = $1', [p1.id]);
    assert.deepStrictEqual(targets, [{ target_type: 'node', target_value: H('w1') }]);
    assert.strictEqual(r1.needsInit.length, p1.paths.length);
    const r1b = await reg.publishNode(db, H('w1'), { actor: SA, note: 'again' });
    assert.ok(!r1b.revChanged && r1b.rev === r1.rev);
    await assert.rejects(reg.publishNode(db, H('lin'), { actor: SA, note: 'x' }), svc.FimBadRequestError);
    assert.ok(Number((await q(`SELECT count(*) AS c FROM fim_audit WHERE action = 'FIM_REG_PUBLISH' AND actor = $1 AND details->>'host' = $2`, [SA.email, H('w1')]))[0].c) >= 2, 'audit outbox row per publish (same transaction)');
    ok('publish: managed policy + node target, schedule keys per slot, config_id appended (others untouched), idempotent; Linux refused; audit outbox written');

    // pretend the whole host was initialised
    const initAll = async (h: string, polId: number) => {
      const slots = await q(`SELECT slot_idx FROM fim_reg_slots WHERE host_identifier = $1 AND retired_at IS NULL`, [h]);
      await q(`INSERT INTO fim_host_state (policy_id, host_identifier, state, rev, locked_at) VALUES ($1,$2,'locked',1,1) ON CONFLICT (policy_id, host_identifier) DO UPDATE SET state='locked'`, [polId, h]);
      for (const s of slots) {
        await q(`INSERT INTO fim_init_requests (batch_id, policy_id, host_identifier, entry_idx, rev, status, created_at, completed_at) VALUES ($1,$2,$3,$4,1,'done',$5,$5)`,
          [`${P}-b`, polId, h, s.slot_idx, Math.floor(Date.now() / 1000) + 1]);
      }
    };
    await initAll(H('w1'), p1.id);
    assert.strictEqual((await reg.getNodeCoverage(db, H('w1'), SA)).status, 'in_sync');

    // --- RBAC / IDOR ----------------------------------------------------------------------------------
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w3'), op: 'add', target: 'reg.netsh' }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.createRule(db, { layer: 'group', scopeValue: H('gB'), op: 'add', target: 'reg.netsh' }, GA), reg.FimForbiddenError);
    const defProfile = (await q('SELECT id FROM fim_reg_profiles WHERE is_default'))[0].id;
    await assert.rejects(reg.createRule(db, { layer: 'profile', scopeValue: String(defProfile), op: 'add', target: 'reg.netsh' }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-p`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce' }), GA), reg.FimForbiddenError);
    await assert.rejects(reg.getNodeCoverage(db, H('w3'), GA), svc.FimNotFoundError);
    await assert.rejects(reg.previewNode(db, H('w3'), { changes: [] }, GA), svc.FimNotFoundError);
    await assert.rejects(reg.publishTargets(db, { hosts: [H('w3')] }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.publishTargets(db, { group: H('gB') }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.publishTargets(db, { profile: Number(defProfile) }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.requestMeasure(db, H('w3'), ['reg.netsh'], GA), reg.FimForbiddenError);
    await assert.rejects(reg.listLegacy(db, GA), reg.FimForbiddenError);
    await assert.rejects(reg.putAssignment(db, 'group', H('gB'), { tier: 'recommended' }, GA), reg.FimForbiddenError);
    await assert.rejects(reg.setApprovers(db, [{ userId: GA.userId!, email: GA.email! }], GA, 'self'), reg.FimForbiddenError);
    ok('RBAC: Group Admin cannot touch another group, its nodes, profiles, settings, approvers or migration (IDOR -> 404/403)');

    // viewer-only actor: can see the node, cannot change anything about it
    assert.strictEqual((await reg.getNodeCoverage(db, H('w1'), VIEW)).host ?? H('w1'), H('w1'));
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.netsh', reason: 'viewer' }, VIEW), reg.FimForbiddenError);
    await assert.rejects(reg.publishTargets(db, { hosts: [H('w1')] }, VIEW), reg.FimForbiddenError);
    await assert.rejects(reg.requestMeasure(db, H('w1'), ['reg.netsh'], VIEW), reg.FimForbiddenError);
    await assert.rejects(reg.compactNode(db, H('w1'), VIEW, 'x'), reg.FimForbiddenError);
    await assert.rejects(reg.putAssignment(db, 'node', H('w1'), { tier: 'recommended' }, VIEW), reg.FimForbiddenError);
    ok('viewer-only actor: coverage visible; rules, publish, measure, compaction and assignments refused');

    // --- node rule, preview writes nothing, stale hash ------------------------------------------------
    const count = async () => (await q(`SELECT (SELECT count(*) FROM fim_reg_rules WHERE scope_value LIKE $1)::int + (SELECT count(*) FROM fim_reg_slots WHERE host_identifier LIKE $1)::int AS c`, [`${P}%`]))[0].c;
    const before = await count();
    const pv = await reg.previewNode(db, H('w1'), { changes: [{ action: 'add', rule: { op: 'add', target: 'reg.netsh', spec: {}, reason: '' } }] }, GA);
    assert.ok(pv.ok && pv.diff.added.some((e: any) => e.entryKey === 'reg.netsh') && pv.needsInit.includes('reg.netsh'));
    assert.strictEqual(pv.rev.next, pv.rev.current! + 1);
    assert.strictEqual(await count(), before);
    const staleHash = (await reg.getNodeCoverage(db, H('w1'), GA)).resolvedHash;
    const netshRule = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.netsh', reason: 'need netsh' }, GA);
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.netsh' }, GA), svc.FimConflictError);
    await assert.rejects(reg.publishNode(db, H('w1'), { actor: GA, expectedHash: staleHash, note: 'x' }), svc.FimConflictError);
    const cov = await reg.getNodeCoverage(db, H('w1'), GA);
    assert.strictEqual(cov.status, 'pending');
    const r2 = await reg.publishNode(db, H('w1'), { actor: GA, expectedHash: cov.resolvedHash, note: `${P} netsh` });
    assert.ok(r2.revChanged && r2.newSlots.length === 1 && r2.needsInit.length === 1, JSON.stringify(r2));
    // rule visibility across groups (non-vacuous: the w1 rule exists and SA sees it)
    assert.ok((await reg.listRules(db, {}, SA)).some((r) => r.id === netshRule.rule.id));
    const gbRules = await reg.listRules(db, {}, GB);
    assert.ok(!gbRules.some((r) => r.id === netshRule.rule.id), 'GB does not see the gA node rule');
    assert.ok(gbRules.every((r) => r.layer === 'profile' || r.scopeValue === H('w3') || r.scopeValue === H('gB')));
    ok('preview writes nothing; duplicate rule 409; stale expected hash 409; publish adds exactly one new slot needing init; rules of other groups invisible');

    // --- per-slot initialise; forced re-init with open critical drift; scoped supersede (A-MED4) ----
    const ir = await svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'slot', requestedBy: GA.email, entries: r2.needsInit });
    assert.strictEqual(ir.requests, 1);
    const slotNew = r2.needsInit[0];
    await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx)
             VALUES ($1,'x',$2,'registry|x','added','scan','critical',1,1,'item',$3)`, [r2.policyId, H('w1'), slotNew]);
    await assert.rejects(svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'again', requestedBy: GA.email, entries: [slotNew] }), svc.FimConflictError);
    await svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'forced', requestedBy: GA.email, entries: [slotNew], force: true });
    assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE 'FIM registry slot re-initialised%'`, [H('w1')]))[0].c), 1);
    await assert.rejects(svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'x', requestedBy: 'x', entries: [9999] }), svc.FimBadRequestError);
    await q(`DELETE FROM fim_drift WHERE host_identifier = $1`, [H('w1')]);
    await q(`UPDATE fim_init_requests SET status = 'done', completed_at = extract(epoch FROM now())::bigint + 2 WHERE policy_id = $1 AND status = 'pending'`, [r2.policyId]);
    {
      const [sa, sb] = [0, 1];
      await svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'a', requestedBy: GA.email, entries: [sa] });
      await svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'b', requestedBy: GA.email, entries: [sb] });
      const pend = async () => (await q(`SELECT entry_idx, status FROM fim_init_requests WHERE policy_id = $1 AND host_identifier = $2 AND status = 'pending' ORDER BY entry_idx`, [r2.policyId, H('w1')])).map((r: any) => Number(r.entry_idx));
      assert.deepStrictEqual(await pend(), [sa, sb], 'initialising slot b does not cancel the pending request of slot a');
      const again = await svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'a2', requestedBy: GA.email, entries: [sa] });
      assert.strictEqual(again.superseded, 1);
      assert.deepStrictEqual(await pend(), [sa, sb]);
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM fim_init_requests WHERE policy_id = $1 AND host_identifier = $2 AND entry_idx = $3 AND status = 'expired'`, [r2.policyId, H('w1'), sa]))[0].c), 1);
      await q(`UPDATE fim_init_requests SET status = 'done', completed_at = extract(epoch FROM now())::bigint + 2 WHERE policy_id = $1 AND status = 'pending'`, [r2.policyId]);
    }
    ok('Initialize entries:[slot] queues one request; open critical drift needs force (alerted); bad slot refused; A-MED4 interleaved per-slot inits supersede only the same slot');

    // --- A-HIGH1: a definition change carries open drift to the new slot (never closes it) ----------
    {
      const d = await drift(r2.policyId!, H('w1'), 'registry|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NetSh\\evil', slotNew, { severity: 'high' });
      const f = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'filter', target: 'reg.netsh', spec: { values: ['Helper1'] }, reason: 'narrow netsh' }, GA);
      const rf = await reg.publishNode(db, H('w1'), { actor: GA, note: 'netsh narrowed' });
      assert.deepStrictEqual(rf.retired, [slotNew]);
      assert.strictEqual(rf.newSlots.length, 1);
      const after1 = (await q('SELECT status, entry_idx, note FROM fim_drift WHERE id = $1', [d.id]))[0];
      assert.strictEqual(after1.status, 'open', 'drift stays open (the old code closed it as ignored)');
      assert.strictEqual(Number(after1.entry_idx), rf.newSlots[0]);
      assert.ok(String(after1.note).includes('carried from slot'));
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE '%closed on%because their coverage was removed%'`, [H('w1')]))[0].c), 0);
      await reg.revokeRule(db, f.rule.id, GA, 'undo');
      const rb2 = await reg.publishNode(db, H('w1'), { actor: GA, note: 'netsh restored' });
      assert.ok(rb2.revived.includes(slotNew));
      assert.strictEqual(Number((await q('SELECT entry_idx FROM fim_drift WHERE id = $1', [d.id]))[0].entry_idx), slotNew, 'carried back to the revived slot');
      assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id = $1', [d.id]))[0].status, 'open');
      await q('DELETE FROM fim_drift WHERE id = $1', [d.id]);
      await initAll(H('w1'), p1.id);
    }
    ok('A-HIGH1: open drift is carried to the new slot on a definition change and back on revival; nothing closed, no closure alert');

    // --- protected entry + two-person waiver bound to one rule --------------------------------------
    const RUN_RULE = { op: 'disable', target: 'reg.run.hklm' };
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), ...RUN_RULE, reason: 'decommission run key' }, GA), FimValidationError);
    const wb = (o: Record<string, unknown> = {}) => ({ entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w1'), action: 'disable', reason: 'lab host, see ticket 42', expiresAt: exp(), rule: RUN_RULE, ...o });
    await assert.rejects(reg.requestWaiver(db, wb({ expiresAt: exp() + 40 * 86400 }), GA), FimValidationError);
    await assert.rejects(reg.requestWaiver(db, wb({ entryKey: 'reg.netsh', rule: { op: 'disable', target: 'reg.netsh' } }), GA), FimValidationError);
    await assert.rejects(reg.requestWaiver(db, wb({ scopeValue: H('w3') }), GA), reg.FimForbiddenError);
    await assert.rejects(reg.requestWaiver(db, wb({ rule: undefined }), GA), /rule/);
    await assert.rejects(reg.requestWaiver(db, wb({ rule: { op: 'disable', target: 'reg.netsh' } }), GA), /does not reduce coverage/);
    await assert.rejects(reg.requestWaiver(db, wb({ action: 'lower_severity' }), GA), /does not match/);
    const w = await reg.requestWaiver(db, wb(), GA);
    assert.deepStrictEqual(w.rule, { op: 'disable', target: 'reg.run.hklm', spec: {} });
    // a pending waiver backs nothing
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), ...RUN_RULE, reason: 'lab host, see ticket 42', waiverId: w.id }, GA), /pending/);
    await assert.rejects(reg.applyWaiver(db, w.id, GA, 'x'), svc.FimConflictError);
    // approval: not the requester (compared by USER ID), only SA or a designated approver
    await assert.rejects(reg.decideWaiver(db, w.id, 'approve', '', GA), reg.FimForbiddenError);
    await assert.rejects(reg.decideWaiver(db, w.id, 'approve', '', SAasGA), /someone other than the requester/);
    await assert.rejects(reg.decideWaiver(db, w.id, 'approve', '', APR), reg.FimForbiddenError);
    await reg.setApprovers(db, [{ userId: APR.userId!, email: APR.email! }], SA, `${P} approver`);
    assert.ok(await reg.canApproveWaivers(db, APR));
    const w2 = await reg.requestWaiver(db, wb({ scopeValue: H('w2'), reason: 'self approval attempt' }), SA);
    await assert.rejects(reg.decideWaiver(db, w2.id, 'approve', '', SA), reg.FimForbiddenError);
    await assert.rejects(q(`UPDATE fim_reg_waivers SET status = 'approved', approved_by = 'someone-else', approved_by_user_id = requested_by_user_id, approved_at = 1 WHERE id = $1`, [w2.id]), /check|distinct_user_ids/i);
    await reg.decideWaiver(db, w.id, 'approve', 'ok', APR); // designated approver (not a Super Admin)
    // M3: an approved waiver backs exactly the approved change, once
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'exclude', target: 'reg.run.hklm', spec: { ignoreValues: ['X'] }, reason: 'lab host, see ticket 42', waiverId: w.id }, GA), /does not cover/);
    await assert.rejects(reg.applyWaiver(db, w.id, VIEW, 'x'), reg.FimForbiddenError);
    const applied = await reg.applyWaiver(db, w.id, GA, 'applying');
    assert.strictEqual(applied.rule.waiverId, w.id);
    await assert.rejects(reg.applyWaiver(db, w.id, GA, 'again'), /already used/);
    const covW = await reg.getNodeCoverage(db, H('w1'), GA);
    assert.ok(!covW.entries.some((e: any) => e.entryKey === 'reg.run.hklm') && covW.retiredPending.some((e: any) => e.entryKey === 'reg.run.hklm'));
    const runSlot = covW.retiredPending.find((e: any) => e.entryKey === 'reg.run.hklm')!.slot as number;
    await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx)
             VALUES ($1,'x',$2,'registry|run','added','scan','critical',1,1,'item',$3), ($1,'x',$2,'registry|other','added','scan','high',1,1,'item',0)`, [r2.policyId, H('w1'), runSlot]);
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, kind, entry_idx, first_seen, last_seen, sha256) VALUES ($1,$2,'registry|keep','item',$3,1,1,'x')`, [r2.policyId, H('w1'), runSlot]);
    const r3 = await reg.publishNode(db, H('w1'), { actor: GA, note: `${P} waiver applied` });
    assert.deepStrictEqual(r3.retired, [runSlot]);
    assert.deepStrictEqual(r3.usedWaivers, [w.id]);
    assert.strictEqual((await q(`SELECT status FROM fim_drift WHERE host_identifier = $1 AND entry_idx = $2`, [H('w1'), runSlot]))[0].status, 'ignored');
    assert.strictEqual((await q(`SELECT status FROM fim_drift WHERE host_identifier = $1 AND entry_idx = 0`, [H('w1')]))[0].status, 'open', 'other slots untouched');
    assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM fim_baseline WHERE host_identifier = $1 AND entry_idx = $2`, [H('w1'), runSlot]))[0].c), 1, 'baseline kept (soft retire)');
    assert.ok((await pol(H('w1'))).paths[runSlot].retired);
    assert.ok(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND event_code LIKE 'FIM registry: protected coverage reduced%' AND host_identifier = $1`, [H('w1')]))[0].c) >= 1);
    assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE 'FIM registry: 1 open critical/high drift closed on%'`, [H('w1')]))[0].c), 1, 'closing critical drift of removed coverage is alerted');
    assert.deepStrictEqual(await reg.hostsUsingWaiver(db, w.id), [H('w1')]);
    // the retired (tombstone) slot cannot be initialised - non-vacuous: runSlot IS retired here
    await assert.rejects(svc.initializeBaseline(db, r2.policyId!, { hosts: [H('w1')], note: 'x', requestedBy: 'x', entries: [runSlot] }), svc.FimBadRequestError);
    await q(`DELETE FROM fim_drift WHERE host_identifier = $1`, [H('w1')]);
    ok('protected disable: waiver bound to one rule; pending backs nothing; requester (by user id, any e-mail), GA and non-approvers refused; DB CHECK on user ids; designated approver approves; single use; soft-retired slot, only its drift closed (alerted), baseline kept; retired slot not initialisable');

    // --- MED-1: designated approvers are scoped; their approvals lapse when undesignated -----------
    {
      const pa = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-apr`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      const wp = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'profile', scopeValue: String(pa.profile.id), action: 'disable', reason: 'fleet-wide disable request', expiresAt: exp(), rule: RUN_RULE }, SA);
      await assert.rejects(reg.decideWaiver(db, wp.id, 'approve', 'x', { ...APR, viewHosts: null, actGroups: new Set([H('gA')]) }), /Profile-wide \(fleet\) waivers must be approved by a Super Administrator/);
      const w3w = await reg.requestWaiver(db, wb({ scopeValue: H('w3'), reason: 'other group host for approver' }), SA);
      await assert.rejects(reg.decideWaiver(db, w3w.id, 'approve', 'x', { ...APR, viewHosts: new Set([H('w3')]) }), reg.FimForbiddenError);
      await assert.rejects(reg.decideWaiver(db, w3w.id, 'approve', 'x', { ...APR, isApprover: false }), svc.FimNotFoundError);
      // (f2) designated and IN scope, but no longer an active approver (demoted / suspended): refused
      const w1w = await reg.requestWaiver(db, wb({ scopeValue: H('w1'), reason: 'in scope but demoted approver' }), SA);
      await assert.rejects(reg.decideWaiver(db, w1w.id, 'approve', 'x', { ...APR, isApprover: false }), reg.FimForbiddenError);
      // (g2) an approved waiver used for a DIFFERENT change than the approved one is refused by the service
      await reg.decideWaiver(db, w1w.id, 'approve', 'ok', SA2);
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'filter', target: 'reg.run.hklm', spec: { values: ['X'], dropsAllMonitored: true }, reason: 'lab host, see ticket 42', waiverId: w1w.id }, SA), /does not cover|different change/);
      await q(`UPDATE fim_reg_waivers SET rule_hash = 'f'||substr(rule_hash, 2) WHERE id = $1`, [w1w.id]);
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), ...RUN_RULE, reason: 'lab host, see ticket 42', waiverId: w1w.id }, SA), /approved for a different change/);
      await reg.decideWaiver(db, w1w.id, 'revoke', 'cleanup', SA);
      // approved by the designated approver, then undesignated -> the waiver no longer backs anything
      const w4w = await reg.requestWaiver(db, wb({ scopeValue: H('w1'), reason: 'approver lapse check', rule: { op: 'severity', target: 'reg.run.hklm', spec: { severity: 'low' } }, action: 'lower_severity' }), GA);
      await reg.decideWaiver(db, w4w.id, 'approve', 'ok', APR);
      assert.strictEqual((await q('SELECT approved_by_role FROM fim_reg_waivers WHERE id = $1', [w4w.id]))[0].approved_by_role, 'approver');
      const ld1 = await reg.loadLayerData(db, { host: H('w1'), group: H('gA') });
      assert.strictEqual(ld1.waivers.find((x) => x.id === w4w.id)!.status, 'approved');
      await reg.setApprovers(db, [], SA, `${P} undesignate`);
      const ld2 = await reg.loadLayerData(db, { host: H('w1'), group: H('gA') });
      assert.notStrictEqual(ld2.waivers.find((x) => x.id === w4w.id)!.status, 'approved', 'approval lapses with the designation');
      await reg.setApprovers(db, [{ userId: APR.userId!, email: APR.email! }], SA, `${P} redesignate`);
      for (const id of [wp.id, w3w.id, w4w.id]) await reg.decideWaiver(db, id, 'revoke', 'cleanup', SA);
    }
    ok('MED-1: profile-wide waivers need a Super Admin; approvers only inside their act scope and while active/designated (lapsed approvals stop backing coverage)');

    // --- waiver expiry restores coverage (revives the identical slot, no re-init) --------------------
    await q(`UPDATE fim_reg_waivers SET requested_at = extract(epoch FROM now())::bigint - 86400, expires_at = extract(epoch FROM now())::bigint - 1 WHERE id = $1`, [w.id]);
    const logs: string[] = [];
    reg.resetReconcileTimers();
    await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [H('w5'), H('gA'), H('w5'), H('w5')]);
    const st = await reg.reconcileRegistryNodes(db, (m, e) => logs.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only });
    assert.strictEqual((await q('SELECT status FROM fim_reg_waivers WHERE id = $1', [w.id]))[0].status, 'expired');
    assert.ok(logs.some((l) => l.includes('waiver_invalid') && l.includes(H('w1'))), logs.join('\n'));
    const revived = (await pol(H('w1'))).paths[runSlot];
    assert.ok(!revived.retired && revived.entryKey === 'reg.run.hklm', 'same slot revived');
    assert.ok(st.autoPublished >= 1);
    assert.ok(await pol(H('w2')) && await pol(H('w3')) && await pol(H('w5')));
    assert.deepStrictEqual(await reg.hostsUsingWaiver(db, w.id), []);
    ok('waiver expiry: status expired, alert, automatic republish (waiver_invalid) revives the identical slot (baseline still valid)');

    // --- R12-1 / R12-4: protected entries cannot be re-slotted or emptied without waiver + alert ------
    {
      const lsaVals = (await import('../../utils/fim/fimRegistryCatalog')).getRegCatalogEntry('reg.lsa')!.values;
      // widening (all values + one) changes the fingerprint: a waiver is needed now (old code: accepted)
      await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'filter', target: 'reg.lsa', spec: { values: [...lsaVals, 'zzz'] }, reason: 'widen lsa values' }, GA), /protected coverage/);
      // the unchanged value set needs nothing (no fingerprint change)
      assert.deepStrictEqual(reg.touchesProtected({ op: 'filter', target: 'reg.lsa', spec: { values: [...lsaVals] } }), []);
      // a re-slot of a protected entry (here via an approved waiver) raises an alert and needs Initialize
      const wr = await reg.requestWaiver(db, { entryKey: 'reg.lsa', scopeType: 'node', scopeValue: H('w2'), action: 'narrow', reason: 'add one more lsa value', expiresAt: exp(), rule: { op: 'filter', target: 'reg.lsa', spec: { values: [...lsaVals, 'zzz'] } } }, SA);
      await reg.decideWaiver(db, wr.id, 'approve', 'ok', SA2);
      await reg.applyWaiver(db, wr.id, SA, 'apply');
      const rw = await reg.publishNode(db, H('w2'), { actor: SA, note: 'reslot' });
      assert.ok(rw.retired.length >= 1 && rw.needsInit.length >= 1);
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE 'FIM registry: protected entr% re-slotted%reg.lsa%'`, [H('w2')]))[0].c), 1);
      await reg.decideWaiver(db, wr.id, 'revoke', 'cleanup', SA);
      for (const r of await reg.listRules(db, { layer: 'node', scopeValue: H('w2') }, SA)) if (r.waiverId === wr.id) await reg.revokeRule(db, r.id, SA, 'cleanup');
      // R12-4: any named filter on a protected ALL-values entry (Run) drops what it watches: explicit + Super Admin only
      await assert.rejects(reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w1'), action: 'narrow', reason: 'only watch a nonexistent value', expiresAt: exp(), rule: { op: 'filter', target: 'reg.run.hklm', spec: { values: ['DoesNotExist'] } } }, SA), /dropsAllMonitored/);
      await assert.rejects(reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w1'), action: 'narrow', reason: 'only watch a nonexistent value', expiresAt: exp(), rule: { op: 'filter', target: 'reg.run.hklm', spec: { values: ['DoesNotExist'], dropsAllMonitored: true } } }, GA), reg.FimForbiddenError);
      const wd = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: H('w1'), action: 'narrow', reason: 'only watch a nonexistent value', expiresAt: exp(), rule: { op: 'filter', target: 'reg.run.hklm', spec: { values: ['DoesNotExist'], dropsAllMonitored: true } } }, SA);
      await reg.decideWaiver(db, wd.id, 'approve', 'ok', SA2);
      const ad = await reg.applyWaiver(db, wd.id, SA, 'apply');
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND severity = 'critical' AND event_code LIKE $1`, [`%waiver #${wd.id} applied a filter that drops ALL monitored values%`]))[0].c), 1);
      await reg.revokeRule(db, ad.rule.id, SA, 'cleanup');
      await reg.decideWaiver(db, wd.id, 'revoke', 'cleanup', SA);
      await reg.publishNode(db, H('w2'), { actor: SA, note: 'restore' });
    }
    ok('R12-1/R12-4: widening a protected entry needs a waiver; a protected re-slot is alerted; a filter emptying a protected all-values entry is explicit, Super-Admin-only and critically alerted');

    // --- M7: the registry can be disabled at runtime (history key missing) without exiting ------------
    {
      reg.setRegistryDisabled('FIM_HISTORY_HMAC_KEY is missing or too short', 'history_key_missing');
      try {
        const e = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.netsh', reason: 'x' }, GA).then(() => null, (x) => x);
        assert.ok(e instanceof reg.FimUnavailableError && e.code === 'history_key_missing', String(e));
        await assert.rejects(reg.publishNode(db, H('w1'), { actor: SA, note: 'x' }), reg.FimUnavailableError);
        assert.strictEqual((await reg.getSettings(db)).registryDisabledReason, 'FIM_HISTORY_HMAC_KEY is missing or too short');
        assert.ok((await reg.getNodeCoverage(db, H('w1'), SA)).host ?? true, 'reads still work');
      } finally { reg.setRegistryDisabled(null); }
      assert.strictEqual((await reg.getSettings(db)).registryDisabledReason, null);
      assert.throws(() => reg.assertHistoryKeyRingCovers([{ key_id: 'k9', fingerprint: null }]), /not configured/);
      assert.throws(() => reg.assertHistoryKeyRingCovers([{ key_id: 'k1', fingerprint: 'deadbeef' }]), /key mismatch/);
      // PREVIOUS_KEYS is JSON (keys may contain commas/colons); the old "id:key,id:key" format is refused
      const savedPrev = process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS;
      process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS = 'k0:a,b';
      assert.throws(() => reg.historyKeyed(), /JSON object/);
      process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS = JSON.stringify({ k0: 'a,b:c' });
      assert.ok(reg.historyRowHash(null, { at: 1, actor: 'a', reason: null, scope_type: 'node', scope_value: 'x', snapshot: {} }, 'k0').length === 64);
      if (savedPrev === undefined) delete process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS; else process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS = savedPrev;
    }
    ok('M7 / L6: registry disabled (503 code history_key_missing) instead of a process exit; key-ring coverage and key mismatch reported distinctly');

    // --- approve guards on registry drift ------------------------------------------------------------
    {
      const pid = r2.policyId!;
      const SAa = alertActor(SA);
      // T5: unconfirmed real-time drift cannot be approved
      const rt = await drift(pid, H('w1'), `${RUN_KEY}evil`, runSlot, { source: 'realtime', severity: 'critical', last_seen_at: 100 });
      await assert.rejects(svc.resolveDrift(db, [rt.id], 'approve', SA.email, 'n', null, null, { expected: EXP(rt) }), svc.FimUnconfirmedError);
      const rq = await svc.recheckDrift(db, rt.id, null);
      assert.ok(rq.queued);
      assert.strictEqual(Number((await q('SELECT count(*) AS c FROM fim_verify_requests WHERE drift_id = $1', [rt.id]))[0].c), 1);
      const rq2 = await svc.recheckDrift(db, rt.id, null);
      assert.ok(!rq2.queued && rq2.retryAfterSecs > 0, 'recheck rate-limited');
      await assert.rejects(svc.recheckDrift(db, rt.id, [H('w2')]), svc.FimNotFoundError);
      // the worker's check scan confirmed it (and updated it again)
      await q('UPDATE fim_drift SET confirmed_at = 150, last_seen_at = 150 WHERE id = $1', [rt.id]);
      await assert.rejects(svc.resolveDrift(db, [rt.id], 'approve', SA.email, 'n', null, null, {}), /expected values/);
      // the content changed after the review (new value): refused with the current values
      await q(`UPDATE fim_drift SET new_sha256 = 'n2', new_attrs = '{"name":"x","data":"z"}'::jsonb WHERE id = $1`, [rt.id]);
      const ch = await svc.resolveDrift(db, [rt.id], 'approve', SA.email, 'n', null, null, { expected: EXP(rt) }).then(() => null, (e) => e);
      assert.ok(ch instanceof svc.FimDriftChangedError, String(ch));
      const nowRow = (await q('SELECT * FROM fim_drift WHERE id = $1', [rt.id]))[0];
      assert.deepStrictEqual([ch.current[0].contentHash, ch.current[0].newSha256], [svc.driftContentHash(nowRow), 'n2'], '409 carries the current values');
      // closeAlerts(approveChange) applies the same TOCTOU guard
      const al = (await q(`INSERT INTO alerts (host_identifier, hostname, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, os_name, detection_time)
         VALUES ($1,$4,1,$2,$3,true,true,'critical','fim','File Integrity','','','windows',1) RETURNING id`, [H('w1'), `${P} drift alert`, JSON.stringify({ drift_id: Number(rt.id) }), H('w1')]))[0];
      await q('UPDATE fim_drift SET alert_id = $2 WHERE id = $1', [rt.id, al.id]);
      await assert.rejects(svc.closeAlerts(db, [Number(al.id)], 'false_positive', 'fp', SAa, { approveChange: true, expected: EXP(rt) }), svc.FimDriftChangedError);
      assert.strictEqual((await q('SELECT status FROM fim_drift WHERE id = $1', [rt.id]))[0].status, 'open', 'nothing changed (rolled back)');
      // case-insensitive identity: approval updates the baseline row spelled differently
      await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, kind, entry_idx, first_seen, last_seen, sha256) VALUES ($1,$2,$3,'item',$4,1,1,'old')`, [pid, H('w1'), `${RUN_KEY}EVIL`, runSlot]);
      const cur = (await q('SELECT * FROM fim_drift WHERE id = $1', [rt.id]))[0];
      // a further rescan with UNCHANGED content (last_seen + occurrences bumped) does not invalidate the review
      await q('UPDATE fim_drift SET last_seen_at = 999, occurrences = occurrences + 3 WHERE id = $1', [rt.id]);
      const res = await svc.closeAlerts(db, [Number(al.id)], 'false_positive', 'fp', SAa, { approveChange: true, expected: EXP(cur) });
      assert.strictEqual(res.closed, 1);
      const bl = await q(`SELECT path, sha256 FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 AND lower(path) = lower($3)`, [pid, H('w1'), `${RUN_KEY}evil`]);
      assert.deepStrictEqual(bl, [{ path: `${RUN_KEY}EVIL`, sha256: 'n2' }], 'one baseline row, original spelling, new value');
      assert.strictEqual((await q('SELECT path FROM fim_drift WHERE id = $1', [rt.id]))[0].path, `${RUN_KEY}EVIL`);
      // M4: approving critical drift of a protected entry raises an oversight alert ...
      const crit = await q(`SELECT id, metadata FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE 'FIM critical drift on a protected registry entry approved%'`, [H('w1')]);
      assert.strictEqual(crit.length, 1);
      assert.strictEqual(JSON.parse(crit[0].metadata).by, SA.email);
      // ... which only a DIFFERENT Super Admin can close; Group Admins never close fim_config alerts
      const critId = Number(crit[0].id);
      assert.strictEqual((await svc.closeAlerts(db, [critId], 'true_positive', 'x', SAa)).closed, 0, 'not by the approver');
      const lstSA = await svc.listAlerts(db, { type: 'config' }, null, 1, 200, true, { user: SA.email, userId: SA.userId });
      assert.strictEqual(lstSA.items.find((a: any) => a.alertId === critId)!.canClose, false, 'the approver sees no Close for the alert about itself');
      const lstSA2 = await svc.listAlerts(db, { type: 'config' }, null, 1, 200, true, { user: SA2.email, userId: SA2.userId });
      assert.strictEqual(lstSA2.items.find((a: any) => a.alertId === critId)!.canClose, true);
      assert.strictEqual((await svc.closeAlerts(db, [critId], 'true_positive', 'x', alertActor(GA))).closed, 0, 'not by a Group Admin');
      const lstGA = await svc.listAlerts(db, { type: 'config' }, [...GA.actHosts!], 1, 50, false);
      assert.ok(lstGA.items.length > 0 && lstGA.items.every((a: any) => a.canClose === false));
      const gaCfg = (await q(`SELECT id FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND is_open AND metadata LIKE $2 LIMIT 1`, [H('w1'), `%"by":"${GA.email}"%`]))[0];
      assert.ok(gaCfg, 'an oversight alert about a GA action exists');
      assert.strictEqual((await svc.closeAlerts(db, [Number(gaCfg.id)], 'true_positive', 'x', alertActor(GA))).closed, 0, 'the GA cannot close the alert about itself');
      assert.strictEqual((await svc.closeAlerts(db, [critId], 'true_positive', 'reviewed', alertActor(SA2))).closed, 1);
      // Content-only guard: rescans approve; changed content / unconfirmed items are reported per item
      {
        const mk = (n: string, extra: Record<string, unknown> = {}) => drift(pid, H('w1'), `${RUN_KEY}batch-${n}`, runSlot, extra);
        const rescan = (ids: number[]) => q('UPDATE fim_drift SET last_seen_at = last_seen_at + 500, occurrences = occurrences + 1 WHERE id = ANY($1::bigint[])', [ids]);
        const exps = (rows: any[]) => Object.assign({}, ...rows.map(EXP));
        const st = async (id: number) => (await q('SELECT status FROM fim_drift WHERE id = $1', [id]))[0].status;
        // single item: unchanged rescan still approves (the old lastSeenAt guard refused this)
        const s1 = await mk('single');
        await rescan([s1.id]);
        assert.strictEqual((await svc.resolveDrift(db, [s1.id], 'approve', SA.email, 'n', null, null, { expected: EXP(s1) })).resolved, 1);
        // bulk: all rescanned, content unchanged -> all approved
        const b = [await mk('b1'), await mk('b2'), await mk('b3')];
        await rescan(b.map((r) => r.id));
        const rb = await svc.resolveDrift(db, b.map((r) => r.id), 'approve', SA.email, 'n', null, null, { expected: exps(b) });
        assert.strictEqual(rb.resolved, 3);
        // mixed batch (default per item): unchanged -> approved, changed -> drift_changed, unconfirmed -> awaiting
        const m1 = await mk('m1'); const m2 = await mk('m2'); const m3 = await mk('m3', { source: 'realtime' });
        await rescan([m1.id, m2.id, m3.id]);
        await q(`UPDATE fim_drift SET new_sha256 = 'other' WHERE id = $1`, [m2.id]);
        const ids3 = [m1.id, m2.id, m3.id].map(Number);
        // all-or-nothing on request: nothing approved
        await assert.rejects(svc.resolveDrift(db, ids3, 'approve', SA.email, 'n', null, null, { expected: exps([m1, m2, m3]), atomic: true }), svc.FimUnconfirmedError);
        assert.strictEqual(await st(m1.id), 'open');
        const rm = await svc.resolveDrift(db, ids3, 'approve', SA.email, 'n', null, null, { expected: exps([m1, m2, m3]) });
        assert.strictEqual(rm.resolved, 1);
        assert.deepStrictEqual(rm.results.map((r) => [r.id, r.outcome]), [[ids3[0], 'resolved'], [ids3[1], 'drift_changed'], [ids3[2], 'awaiting_confirmation']]);
        assert.strictEqual(rm.results[1].current!.newSha256, 'other');
        assert.deepStrictEqual([await st(m1.id), await st(m2.id), await st(m3.id)], ['approved', 'open', 'open']);
        // mixed alert close: the alert of the changed drift stays open for re-review
        const a1d = await mk('a1'); const a2d = await mk('a2');
        const mkAlert = async (d: any) => {
          const a = (await q(`INSERT INTO alerts (host_identifier, hostname, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type, technique, technique_id, action, os_name, detection_time)
            VALUES ($1,$4,1,$2,$3,true,true,'high','fim','File Integrity','','','windows',1) RETURNING id`, [H('w1'), `${P} batch alert`, JSON.stringify({ drift_id: Number(d.id) }), H('w1')]))[0];
          await q('UPDATE fim_drift SET alert_id = $2 WHERE id = $1', [d.id, a.id]);
          return Number(a.id);
        };
        const al1 = await mkAlert(a1d); const al2 = await mkAlert(a2d);
        await rescan([a1d.id, a2d.id]);
        await q(`UPDATE fim_drift SET change_type = 'removed' WHERE id = $1`, [a2d.id]);
        const rc = await svc.closeAlerts(db, [al1, al2], 'false_positive', 'fp', SAa, { approveChange: true, expected: exps([a1d, a2d]) });
        assert.strictEqual(rc.closed, 1);
        assert.deepStrictEqual(rc.results.map((r) => [r.id, r.outcome]), [[al1, 'closed'], [al2, 'drift_changed']]);
        const open2 = (await q('SELECT is_open FROM alerts WHERE id = $1', [al2]))[0].is_open;
        assert.strictEqual(open2, true, 'alert of the changed drift stays open');
        assert.deepStrictEqual([await st(a1d.id), await st(a2d.id)], ['approved', 'open']);
        // single alert close with changed content: 409
        await assert.rejects(svc.closeAlerts(db, [al2], 'false_positive', 'fp', SAa, { approveChange: true, expected: EXP(a2d) }), svc.FimDriftChangedError);
        // the listing exposes the same contentHash the guard checks
        const lst = await svc.listDrift(db, { status: 'open' }, [H('w1')], 1, 200);
        const row = lst.items.find((d: any) => d.id === Number(a2d.id))!;
        assert.strictEqual(row.contentHash, svc.driftContentHash((await q('SELECT * FROM fim_drift WHERE id = $1', [a2d.id]))[0]));
        const la = await svc.listAlerts(db, { status: 'open', type: 'drift' }, [H('w1')], 1, 200);
        assert.strictEqual(la.items.find((a: any) => a.alertId === al2)!.contentHash, row.contentHash);
        assert.strictEqual((await svc.closeAlerts(db, [al2], 'false_positive', 'fp', SAa, { approveChange: true, expected: { [String(a2d.id)]: { contentHash: row.contentHash } } })).closed, 1);
      }
      // a scan drift with matching expected values approves normally
      const sd = await drift(pid, H('w1'), `${RUN_KEY}fine`, runSlot, { severity: 'high' });
      assert.strictEqual((await svc.resolveDrift(db, [sd.id], 'approve', SA.email, 'n', null, null, { expected: EXP(sd) })).resolved, 1);
      await q(`DELETE FROM fim_drift WHERE host_identifier = $1`, [H('w1')]);
      await q(`DELETE FROM fim_baseline WHERE host_identifier = $1 AND path LIKE $2`, [H('w1'), `${RUN_KEY}%`]);
    }
    ok('approve guards: unconfirmed real-time drift 409, recheck queued + rate-limited, expected mandatory, TOCTOU drift_changed (resolve + closeAlerts), case-insensitive baseline row updated in place, critical protected approval alerted and closable only by another Super Admin (M4)');

    // --- one case-folding rule (ASCII only, COLLATE "C") + case-duplicate merge in 0006 -------------
    {
      const pid = r2.policyId!;
      // non-ASCII letters differing in case are DIFFERENT items (as for the worker's ascii_lower)
      const e1 = await drift(pid, H('w1'), `${RUN_KEY}Été`, runSlot);
      const e2 = await drift(pid, H('w1'), `${RUN_KEY}été`, runSlot);
      assert.ok(e1.id && e2.id && e1.id !== e2.id, 'both open (a collation lower() folded them into one)');
      // ASCII letters differing in case are the SAME item
      await drift(pid, H('w1'), `${RUN_KEY}CaseKey`, runSlot);
      await assert.rejects(drift(pid, H('w1'), `${RUN_KEY}casekey`, runSlot), /uq_fim_drift_open_ci|duplicate key/);
      // Kelvin sign (U+212A) is not ASCII: 'S\u212Aype' and 'Skype' are different items on both sides
      const kv = await drift(pid, H('w1'), `${RUN_KEY}S\u212Aype`, runSlot);
      const sk = await drift(pid, H('w1'), `${RUN_KEY}Skype`, runSlot);
      assert.ok(kv.id !== sk.id);
      // approve adopts a baseline spelling only for an ASCII-case match
      await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, kind, entry_idx, first_seen, last_seen, sha256) VALUES ($1,$2,$3,'item',$4,1,1,'old')`, [pid, H('w1'), `${RUN_KEY}Été`, runSlot]);
      await svc.resolveDrift(db, [e2.id], 'approve', SA.email, 'n', null, null, { expected: EXP(e2) });
      const bl = await q(`SELECT path FROM fim_baseline WHERE policy_id = $1 AND host_identifier = $2 AND path IN ($3, $4) ORDER BY path`, [pid, H('w1'), `${RUN_KEY}Été`, `${RUN_KEY}été`]);
      assert.strictEqual(bl.length, 2, 'the non-ASCII case variant is its own baseline row');
      assert.strictEqual((await q('SELECT path FROM fim_drift WHERE id = $1', [e2.id]))[0].path, `${RUN_KEY}été`, 'path not rewritten to a non-ASCII case variant');
      // 0006 duplicate merge: survivor = latest evidence; alerts of merged rows closed
      const sentinel = new Error('rollback merge test');
      const err = await ds.transaction(async (m) => {
        await m.query('DROP INDEX uq_fim_drift_open_ci');
        await m.query('DROP INDEX IF EXISTS uq_fim_drift_open_v7'); // 0007 (worker schema) index, if applied
        const ins = async (path: string, last: number, occ: number, sev: string, det: number, sha: string) => (await m.query(
          `INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx, new_sha256, occurrences)
           VALUES ($1,'x',$2,$3,'modified','scan',$4,$5,$6,'item',$7,$8,$9) RETURNING id`, [pid, H('w1'), path, sev, det, last, runSlot, sha, occ]))[0].id;
        const dA = await ins(`${RUN_KEY}Dup`, 10, 1, 'high', 5, 'old-a');
        const dB = await ins(`${RUN_KEY}DUP`, 30, 2, 'low', 7, 'newest');
        const dC = await ins(`${RUN_KEY}dup`, 20, 3, 'critical', 6, 'mid');
        const alA = (await m.query(`INSERT INTO alerts (host_identifier, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type) VALUES ($1,1,'x',$2,true,true,'high','fim') RETURNING id`, [H('w1'), '{}']))[0].id;
        await m.query('UPDATE fim_drift SET alert_id = $2 WHERE id = $1', [dA, alA]);
        const alC = (await m.query(`INSERT INTO alerts (host_identifier, unixtime, event_code, metadata, is_alert, is_open, severity, alert_type) VALUES ($1,1,'x',$2,true,true,'high','fim') RETURNING id`, [H('w1'), JSON.stringify({ drift_id: Number(dC) })]))[0].id;
        await m.query(FIM_VERIFY_DDL);
        const rows = await m.query('SELECT id, status, occurrences, severity, detected_at, new_sha256, note FROM fim_drift WHERE id = ANY($1::bigint[]) ORDER BY id', [[dA, dB, dC]]);
        const by = new Map(rows.map((r: any) => [String(r.id), r]));
        const sv: any = by.get(String(dB));
        assert.deepStrictEqual([sv.status, Number(sv.occurrences), sv.severity, Number(sv.detected_at), sv.new_sha256], ['open', 6, 'critical', 5, 'newest'], 'survivor = most recent evidence, merged counters, highest severity');
        for (const d of [dA, dC]) {
          const r: any = by.get(String(d));
          assert.strictEqual(r.status, 'ignored');
          assert.ok(String(r.note).includes(`Merged into drift #${dB}`));
        }
        const al = await m.query('SELECT id, is_open, remarks FROM alerts WHERE id = ANY($1::bigint[])', [[alA, alC]]);
        assert.ok(al.length === 2 && al.every((a: any) => a.is_open === false && String(a.remarks).includes(`merged into drift #${dB}`)), JSON.stringify(al));
        assert.strictEqual((await m.query(`SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_ci'`))[0].indexdef.includes('COLLATE'), true);
        throw sentinel;
      }).then(() => null, (e) => e);
      assert.strictEqual(err, sentinel, String(err?.stack ?? err));
      assert.ok((await q(`SELECT 1 FROM pg_indexes WHERE indexname = 'uq_fim_drift_open_ci'`)).length === 1, 'index restored by the rollback');
      await q(`DELETE FROM fim_drift WHERE host_identifier = $1`, [H('w1')]);
      await q(`DELETE FROM fim_baseline WHERE host_identifier = $1 AND path LIKE $2`, [H('w1'), `${RUN_KEY}%`]);
    }
    ok('registry identity folds ASCII letters only (COLLATE "C"): non-ASCII case variants stay distinct (drift + baseline), ASCII variants collide; 0006 merge keeps the most recent evidence, merges counters/severity and closes the merged rows\' alerts');


    // --- group move ---------------------------------------------------------------------------------------
    await q(`UPDATE nodes SET owner_group_id = $2 WHERE host_identifier = $1`, [H('w2'), H('gB')]);
    logs.length = 0;
    await reg.reconcileRegistryNodes(db, (m, e) => logs.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only });
    assert.ok(logs.some((l) => l.startsWith('FIM_REG_AUTO_REPUBLISH') && l.includes('group_change') && l.includes(H('w2'))));
    assert.strictEqual((await q('SELECT owner_group_id FROM fim_reg_effective WHERE host_identifier = $1', [H('w2')]))[0].owner_group_id, H('gB'));
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.netsh' }, { ...GA, actHosts: new Set([H('w1')]) }), reg.FimForbiddenError);
    ok('group move: automatic republish (group_change); the old group admin loses write access');

    // --- M7: a steady-state sweep writes nothing ------------------------------------------------------
    const s1 = await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    const s2 = await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    assert.ok(s1.nodes > 0 && s2.nodes === s1.nodes);
    assert.strictEqual(s2.writes, 0, JSON.stringify(s2));
    assert.ok(s2.cached === s2.nodes, 'every node served from the inputs cache');
    ok('M7/A-LOW8: a second sweep with unchanged inputs resolves nothing and writes nothing');

    // --- custom key needs a measurement; measure + rate limit; implausible results ------------------
    const spec = { path: `${L}SOFTWARE\\Acme\\Agent`, values: ['Path'], severity: 'medium', label: 'Acme' };
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec, reason: 'acme' }, GA), /measure/);
    const m1 = (await reg.requestMeasure(db, H('w1'), [spec], GA))[0];
    const mq = (await q('SELECT query FROM query_queue WHERE id = (SELECT queue_id FROM fim_reg_measure WHERE id = $1)', [m1.id]))[0].query;
    assert.ok(mq.startsWith('SELECT count(*) AS rows, COALESCE(sum(') && mq.includes('FROM registry'));
    await q(`INSERT INTO query_result (host_identifier, unixtime, query_name, result) SELECT $1, 1, queue_id::text, '[{"rows":"3","bytes":"420"}]' FROM fim_reg_measure WHERE id = $2`, [H('w1'), m1.id]);
    const m1b = await reg.getMeasure(db, m1.id, GA);
    assert.deepStrictEqual([m1b.status, m1b.rows, m1b.bytes], ['done', 3, 420]);
    await reg.requestMeasure(db, H('w1'), ['reg.netsh', 'reg.rdp', 'reg.rdp.tcp', 'reg.aedebug'], GA);
    await assert.rejects(reg.requestMeasure(db, H('w1'), ['reg.netsh'], GA), reg.FimRateLimitError);
    const cr = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec, reason: 'acme' }, GA);
    assert.strictEqual(cr.rule.target, customEntryKey(spec.path));
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec: { path: `${L}SOFTWARE\\A\\B\\C\\%%` }, reason: 'x' }, GA), FimValidationError);
    for (const [rows, bytes] of [['3', '10'], ['0', '500'], ['-1', '0'], ['99999999', '999999999999']]) {
      const mx = (await reg.requestMeasure(db, H('w2'), [{ path: `${L}SOFTWARE\\Acme\\Other${rows}` }], SA))[0];
      await q(`INSERT INTO query_result (host_identifier, unixtime, query_name, result) SELECT $1, 1, queue_id::text, $3 FROM fim_reg_measure WHERE id = $2`, [H('w2'), mx.id, JSON.stringify([{ rows, bytes }])]);
      const g = await reg.getMeasure(db, mx.id, SA);
      assert.strictEqual(g.status, 'failed', `implausible ${rows}/${bytes} rejected`);
    }
    ok('custom keys: refused until measured; count-only measure query + result; 5/node/10 min rate limit; GA cannot use %%; A-LOW10 implausible agent numbers rejected');

    // --- invalid resolution: rule refused up front; otherwise fail-safe catalog-only coverage (M1, R12-2) ----
    const ov1 = { path: `${L}SOFTWARE\\Acme\\%\\Cfg`, severity: 'high', measureOverride: true };
    const ov2 = { path: `${L}SOFTWARE\\Acme\\Prod\\%`, severity: 'high', measureOverride: true };
    // A rule that would make the scope unresolvable is refused at creation (R12-2) ...
    const sqlRule = async (scope: string, spec: any) => (await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('node',$1,'add',$2,$3::jsonb,'outside the API',$4,1) RETURNING id`,
      [scope, customEntryKey(spec.path), JSON.stringify({ path: spec.path, values: [], ignoreValues: [], excludeKeys: [], redactValues: [], includeSubkeys: true, anchor: true, hiveScoped: false, realtimeRequired: false, severity: 'high', category: 'custom', label: 'x', measureOverride: true }), `${P}-sql`]))[0].id;
    await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec: ov1, reason: 'overlap a' }, SA);
    await assert.rejects(reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'custom', spec: ov2, reason: 'overlap b' }, SA), /would make the registry coverage of node .* invalid: .*overlap/);
    await assert.rejects(reg.createRule(db, { layer: 'group', scopeValue: H('gA'), op: 'add', target: 'custom', spec: { path: `${L}SYSTEM\\%\\Services\\%`, values: ['ImagePath'], measureOverride: true }, reason: 'freeze attempt' }, SA), /invalid/);
    // ... and if it still happens (rule written outside the API, catalog change), a fail-safe
    // catalog-only config is published instead of freezing the stale one.
    await sqlRule(H('w1'), ov2);
    const bad = await reg.publishNode(db, H('w1'), { actor: SA, note: 'bad' });
    assert.strictEqual(bad.status, 'invalid');
    assert.ok(bad.error!.startsWith('fail-safe') && bad.error!.includes('overlap'), bad.error!);
    const livePaths = ((await pol(H('w1'))).paths as any[]).filter((p) => !p.retired);
    assert.ok(livePaths.length > 0 && livePaths.every((p) => String(p.entryKey).startsWith('reg.')), 'only catalog entries live (fail-safe)');
    assert.ok(livePaths.some((p) => p.entryKey === 'reg.run.hklm'));
    assert.ok((await pol(H('w1'))).enabled);
    assert.strictEqual((await q('SELECT status FROM fim_reg_effective WHERE host_identifier = $1', [H('w1')]))[0].status, 'invalid');
    {
      // a NEW node whose resolution is invalid: one automatic attempt, then back-off until it changes
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [H('w6'), H('gA'), H('w6'), H('w6')]);
      only.add(H('w6'));
      const o1 = await reg.createRule(db, { layer: 'node', scopeValue: H('w6'), op: 'add', target: 'custom', spec: ov1, reason: 'overlap a' }, SA);
      await sqlRule(H('w6'), ov2);
      const attempts = async () => { const lg: string[] = []; await reg.reconcileRegistryNodes(db, (m, e) => lg.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only }); return lg.filter((l) => l.startsWith('FIM_REG_AUTO_REPUBLISH') && l.includes(H('w6'))).length; };
      assert.strictEqual(await attempts(), 1);
      assert.strictEqual((await q('SELECT status FROM fim_reg_effective WHERE host_identifier = $1', [H('w6')]))[0].status, 'invalid');
      assert.strictEqual(await attempts(), 0, 'no retry while the resolution is unchanged (back-off)');
      assert.strictEqual(await attempts(), 0);
      await q(`UPDATE fim_reg_effective SET invalid_since = extract(epoch FROM now())::bigint - 7200 WHERE host_identifier = $1`, [H('w6')]);
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      // ONE alert per cause (not per node), updated in place on the next sweep
      const inv = async () => q(`SELECT id, host_identifier, metadata FROM alerts WHERE alert_type = 'fim_config' AND is_open AND event_code LIKE 'FIM registry coverage invalid for over an hour%' AND metadata LIKE $1`, [`%${H('w6')}%`]);
      const a1 = await inv();
      assert.ok(a1.length === 1 && a1[0].host_identifier === null && JSON.parse(a1[0].metadata).examples.includes(H('w6')), JSON.stringify(a1));
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      assert.deepStrictEqual((await inv()).map((a: any) => a.id), [a1[0].id], 'no second alert for the same cause');
      // the back-off never re-resolves an unchanged invalid node
      const stB = await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      assert.strictEqual(stB.resolved, 0, JSON.stringify(stB));
      await reg.revokeRule(db, o1.rule.id, SA, 'fix overlap');
      assert.strictEqual(await attempts(), 1, 'retried once the resolution changed');
      assert.ok(await pol(H('w6')));
    }
    for (const r of await reg.listRules(db, { layer: 'node', scopeValue: H('w1') }, SA)) if (r.target.startsWith('custom:') && r.target !== cr.rule.target) await reg.revokeRule(db, r.id, SA, 'undo overlap');
    ok('invalid resolution (overlap): nothing published, last good config kept; M1 automatic publish backs off until the resolution changes, alert after 1 h invalid');

    // --- round 4 M3: a dead waiver never stays in force on a node whose coverage is invalid --------------
    {
      const h7 = H('w7');
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [h7, H('gA'), h7, h7]);
      only.add(h7);
      const w7 = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: h7, action: 'disable', reason: 'fail-safe test host', expiresAt: exp(), rule: RUN_RULE }, SA);
      await reg.decideWaiver(db, w7.id, 'approve', 'ok', SA2);
      await reg.applyWaiver(db, w7.id, SA, 'apply');
      const p7 = await reg.publishNode(db, h7, { actor: SA, note: 'with waiver' });
      assert.deepStrictEqual(p7.usedWaivers, [w7.id]);
      const runLive = async () => ((await pol(h7)).paths as any[]).some((p) => p.entryKey === 'reg.run.hklm' && !p.retired);
      assert.strictEqual(await runLive(), false);
      // the node's coverage becomes invalid (overlap) ...
      await reg.createRule(db, { layer: 'node', scopeValue: h7, op: 'add', target: 'custom', spec: ov1, reason: 'overlap a' }, SA);
      await sqlRule(h7, ov2);
      // ... and the waiver is revoked: the old behaviour kept the waiver-reduced config forever
      await reg.decideWaiver(db, w7.id, 'revoke', 'no longer needed', SA);
      const r7 = await reg.publishNode(db, h7, { actor: reg.systemActor(), note: 'revoked', auto: 'waiver_revoked' });
      assert.strictEqual(r7.status, 'invalid');
      assert.ok(r7.error!.startsWith('fail-safe'), r7.error!);
      assert.strictEqual(await runLive(), true, 'protected Run coverage is back (catalog-only fail-safe)');
      assert.deepStrictEqual(await reg.hostsUsingWaiver(db, w7.id), []);
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND severity = 'critical' AND event_code LIKE '%fail-safe catalog-only coverage published%'`, [h7]))[0].c), 1);
      // the sweep does not loop on it (no waiver_invalid any more)
      const lg: string[] = [];
      await reg.reconcileRegistryNodes(db, (m, e) => lg.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only });
      assert.ok(!lg.some((l) => l.includes('waiver_invalid') && l.includes(h7)));      for (const r of await reg.listRules(db, { layer: 'node', scopeValue: h7 }, SA)) await reg.revokeRule(db, r.id, SA, 'cleanup');
    }
    ok('round 4 M3: an expired/revoked waiver on a node with INVALID coverage -> fail-safe catalog-only coverage published, critical alert, no retry loop');

    // --- M4 + tombstone reuse: a node invalid because of the slot cap recovers after the purge ---------
    {
      const { FIM_REG_CAPS: caps } = await import('../../utils/fim/fimRegistryResolver');
      const h8 = H('w8');
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) VALUES ($1,'windows',$2,$3,$4)`, [h8, H('gA'), h8, h8]);
      only.add(h8);
      await reg.publishNode(db, h8, { actor: SA, note: 'base' });
      const maxIdx = Number((await q('SELECT max(slot_idx) AS m FROM fim_reg_slots WHERE host_identifier = $1', [h8]))[0].m);
      // fill the slot list with retired tombstones up to the cap (purge window already over)
      await q(`INSERT INTO fim_reg_slots (host_identifier, slot_idx, entry_key, fingerprint, created_at, retired_at, purge_after)
               SELECT $1, g, 'custom:' || lpad(to_hex(g), 16, '0'), 'fp', 1, 2, 3 FROM generate_series($2::int, $3::int) g`, [h8, maxIdx + 1, caps.pathsMax - 1]);
      const add = await reg.createRule(db, { layer: 'node', scopeValue: h8, op: 'add', target: 'reg.netsh', reason: 'needs a slot' }, SA);
      const full = await reg.publishNode(db, h8, { actor: SA, note: 'cap' });
      assert.strictEqual(full.status, 'invalid');
      assert.ok(/exceed/.test(full.error!), full.error!);
      // the purge runs in the next sweep, invalidates the cached inputs and the node is retried
      const lg: string[] = [];
      await reg.reconcileRegistryNodes(db, (m, e) => lg.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only });
      const eff8 = (await q('SELECT status FROM fim_reg_effective WHERE host_identifier = $1', [h8]))[0];
      assert.notStrictEqual(eff8.status, 'invalid', `recovered after the purge: ${lg.filter((l) => l.includes(h8)).join(' | ')}`);
      const netshSlot = (await q(`SELECT slot_idx FROM fim_reg_slots WHERE host_identifier = $1 AND entry_key = 'reg.netsh' AND retired_at IS NULL`, [h8]))[0].slot_idx;
      assert.ok(Number(netshSlot) <= caps.pathsMax - 1 && Number(netshSlot) > maxIdx, 'a purged tombstone slot was reused (no growth past the cap)');
      assert.strictEqual(((await pol(h8)).paths as any[]).length, caps.pathsMax);
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND host_identifier = $1 AND event_code LIKE '%slots (incl. retired); compact its coverage soon%'`, [h8]))[0].c), 1, '90% slot-cap warning');
      await reg.revokeRule(db, add.rule.id, SA, 'cleanup');
    }
    ok('M4: slot purge invalidates the cached inputs, the invalid node is retried and reuses a purged tombstone; 90% slot-cap warning raised');

    // --- M2: kill switch vs. concurrent publishes --------------------------------------------------------
    for (let i = 0; i < 4; i++) {
      await reg.createRule(db, { layer: 'node', scopeValue: H('w4'), op: 'add', target: i % 2 ? 'reg.rdp' : 'reg.aedebug', reason: 'race' }, SA).catch(() => undefined);
      const res = await Promise.allSettled([reg.publishNode(db, H('w4'), { actor: SA, note: 'race' }), reg.setManagedEnabled(db, false, SA, `${P} race off`)]);
      assert.strictEqual(res[1].status, 'fulfilled');
      const p4 = await pol(H('w4'));
      if (p4) {
        assert.ok(!p4.enabled && !p4.config_query_id, `iteration ${i}: managed policy left enabled after the kill switch`);
        assert.ok(!(await cfgOf(H('w4')) ?? '').split(',').includes(String(p4.id)));
      }
      await reg.setManagedEnabled(db, true, SA, `${P} race on`);
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    }
    ok('M2: publish racing the kill switch never leaves a managed policy enabled (FOR SHARE on the settings row)');

    // --- history chain: keyed, tamper detection, HMAC rewrite, tail truncation, role gate -----------
    assert.ok((await reg.verifyHistoryChain(db)).ok);
    assert.ok((await reg.verifyHistoryChain(db)).keyed);
    const hist = await reg.listHistory(db, 'node', H('w1'), 1, 100, { full: true });
    assert.ok(hist.items.length >= 4 && hist.chainOk);
    const victim = hist.items[hist.items.length - 1];
    const maint = (sql: string, p: any[]) => ds.transaction(async (m) => { await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`); await m.query(sql, p); });
    await maint(`UPDATE fim_reg_history SET actor = 'mallory' WHERE id = $1`, [victim.id]);
    const broken = await reg.verifyHistoryChain(db);
    assert.ok(!broken.ok && broken.brokenAt === victim.id, JSON.stringify({ broken, victim: victim.id }));
    await assert.rejects(q(`UPDATE fim_reg_history SET actor = 'x' WHERE id = $1`, [victim.id]), /append-only/);
    await maint(`UPDATE fim_reg_history SET actor = $2 WHERE id = $1`, [victim.id, victim.actor]);
    assert.ok((await reg.verifyHistoryChain(db)).ok);
    {
      // An attacker without the key rewrites a row AND recomputes its hash (plain SHA-256): detected.
      const row = (await q('SELECT * FROM fim_reg_history WHERE id = $1', [victim.id]))[0];
      const key = process.env.FIM_HISTORY_HMAC_KEY;
      delete process.env.FIM_HISTORY_HMAC_KEY;
      const forged = reg.historyRowHash(row.prev_hash, { at: Number(row.at), actor: 'mallory', reason: row.reason, scope_type: row.scope_type, scope_value: row.scope_value, snapshot: row.snapshot });
      process.env.FIM_HISTORY_HMAC_KEY = key;
      await maint(`UPDATE fim_reg_history SET actor = 'mallory', row_hash = $2 WHERE id = $1`, [victim.id, forged]);
      const v = await reg.verifyHistoryChain(db);
      assert.ok(!v.ok && v.brokenAt === victim.id, 'an unkeyed recomputation does not verify');
      await maint(`UPDATE fim_reg_history SET actor = $2, row_hash = $3 WHERE id = $1`, [victim.id, row.actor, row.row_hash]);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
    }
    {
      // Tail truncation: invisible to the chain alone, caught by the anchored head.
      const tmp = await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.aedebug', reason: 'tail' }, SA);
      const head = tmp.historyHead;
      await maint('DELETE FROM fim_reg_history WHERE id = $1', [head.id]);
      // The in-database outbox still records the deleted head: detected even without the anchor.
      const vo = await reg.verifyHistoryChain(db);
      assert.ok(!vo.ok && vo.brokenAt === head.id && /recorded chain head|high-water mark/.test(vo.reason!), JSON.stringify(vo));
      // The outbox is append-only now: deleting its row needs the maintenance role too.
      await assert.rejects(q('DELETE FROM fim_reg_anchor_outbox WHERE history_id = $1', [head.id]), /append-only/);
      await assert.rejects(q(`UPDATE fim_reg_anchor_outbox SET row_hash = 'x' WHERE history_id = $1`, [head.id]), /append-only/);
      // An attacker who deletes the newest history row AND its outbox row (and whose anchor store
      // returns an older head) is caught by the local monotonic high-water mark.
      await maint('DELETE FROM fim_reg_anchor_outbox WHERE history_id = $1', [head.id]);
      const vh = await reg.verifyHistoryChain(db, { anchor: async () => ({ id: head.id - 1, rowHash: (await q('SELECT row_hash FROM fim_reg_history WHERE id = $1', [head.id - 1]))[0]?.row_hash ?? '', count: head.count - 1 }) });
      assert.ok(!vh.ok && !vh.unverifiable && /high-water mark/.test(vh.reason!), JSON.stringify(vh));
      await assert.rejects(q('UPDATE fim_reg_history_hwm SET head_id = head_id - 1 WHERE id'), /only increase/);
      // ... and by the external anchor when it holds the deleted head
      const va = await reg.verifyHistoryChain(db, { anchor: async () => head });
      assert.ok(!va.ok && (/deleted or altered/.test(va.reason!) || /high-water/.test(va.reason!)), JSON.stringify(va));
      // repair (maintenance): move the high-water mark back to the real head
      await maint(`UPDATE fim_reg_history_hwm SET head_id = (SELECT max(id) FROM fim_reg_history), row_hash = (SELECT row_hash FROM fim_reg_history ORDER BY id DESC LIMIT 1), row_count = (SELECT count(*) FROM fim_reg_history) WHERE id`, []);
      await maint(`UPDATE fim_reg_settings SET history_head_id = (SELECT max(id) FROM fim_reg_history) WHERE id`, []);
      assert.ok((await reg.verifyHistoryChain(db)).ok, 'the remaining chain itself is consistent after repair');
      const rv = await reg.revokeRule(db, tmp.rule.id, SA, 'tail cleanup');
      assert.ok((await reg.verifyHistoryChain(db, { anchor: async () => rv.historyHead })).ok);
      const fewer = await reg.verifyHistoryChain(db, { anchor: async () => ({ ...rv.historyHead, count: rv.historyHead.count + 5 }) });
      assert.ok(!fewer.ok && /fewer rows/.test(fewer.reason!));
      // (d2) an anchored head whose hash differs from the stored row -> broken at that row
      const forgedA = await reg.verifyHistoryChain(db, { anchor: async () => ({ ...rv.historyHead, rowHash: 'forged' }) });
      assert.ok(!forgedA.ok && forgedA.brokenAt === rv.historyHead.id && /rewritten/.test(forgedA.reason!), JSON.stringify(forgedA));
      // MED-2: an anchor store that cannot be read is UNVERIFIABLE (not ok), never silently ok
      const un = await reg.verifyHistoryChain(db, { anchor: async () => { throw new Error('audit_trail unavailable'); } });
      assert.ok(!un.ok && un.unverifiable && /anchor store unavailable/.test(un.reason!), JSON.stringify(un));
      // outbox flush: the newest head is written to the anchor store and stamped
      const written: reg.HistoryHead[] = [];
      const fl = await reg.flushHistoryAnchors(db, async (h) => { written.push(h); });
      assert.strictEqual(fl.anchored, rv.historyHead.id);
      assert.deepStrictEqual(written, [rv.historyHead]);
      assert.strictEqual(Number((await q('SELECT count(*) AS c FROM fim_reg_anchor_outbox WHERE anchored_at IS NULL'))[0].c), 0);
      // a failing anchor write keeps the head pending (retried later)
      const t2 = await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.aedebug', reason: 'pending' }, SA);
      await assert.rejects(reg.flushHistoryAnchors(db, async () => { throw new Error('down'); }), /down/);
      assert.strictEqual(Number((await q('SELECT count(*) AS c FROM fim_reg_anchor_outbox WHERE anchored_at IS NULL AND history_id = $1', [t2.historyHead.id]))[0].c), 1);
      // an overdue anchor write -> unverifiable
      await maint('UPDATE fim_reg_anchor_outbox SET created_at = created_at - 3600 WHERE anchored_at IS NULL', []);
      const od = await reg.verifyHistoryChain(db, { anchor: async () => rv.historyHead });
      assert.ok(!od.ok && od.unverifiable && /overdue/.test(od.reason!), JSON.stringify(od));
      await reg.flushHistoryAnchors(db, async () => undefined);
      // MED-3: the anchor store regressing to an older head than recorded as anchored -> unverifiable
      const rg = await reg.verifyHistoryChain(db, { anchor: async () => rv.historyHead });
      assert.ok(!rg.ok && !rg.unverifiable && /regressed/.test(rg.reason!), JSON.stringify(rg));
      assert.ok((await reg.verifyHistoryChain(db, { anchor: async () => t2.historyHead })).ok);
      await reg.revokeRule(db, t2.rule.id, SA, 'pending cleanup');
      await reg.flushHistoryAnchors(db, async () => undefined);
    }
    {
      // MED-4: key rotation keeps old rows verifiable (key ring); dropping a needed key is reported
      const oldKey = process.env.FIM_HISTORY_HMAC_KEY!;
      process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS = JSON.stringify({ k1: oldKey });
      process.env.FIM_HISTORY_HMAC_KEY = 'fimregtest-rotated-key-abcdefghijklmnopqrstuvwxyz';
      process.env.FIM_HISTORY_HMAC_KEY_ID = 'k2';
      const k2 = await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.aedebug', reason: 'rotated' }, SA);
      assert.strictEqual((await q('SELECT key_id FROM fim_reg_history WHERE id = $1', [k2.historyHead.id]))[0].key_id, 'k2');
      assert.ok((await reg.verifyHistoryChain(db)).ok, 'rows of k1 and k2 verify');
      delete process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS;
      const lostKey = await reg.verifyHistoryChain(db);
      assert.ok(!lostKey.ok && lostKey.unverifiable && /unknown history key id k1/.test(lostKey.reason!), JSON.stringify(lostKey));
      process.env.FIM_HISTORY_HMAC_PREVIOUS_KEYS = JSON.stringify({ k1: oldKey });
      await reg.revokeRule(db, k2.rule.id, SA, 'rotated cleanup');
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      // an unkeyed row after keyed rows is refused by verification
      assert.throws(() => reg.assertHistoryKeyForProduction({ ...process.env, FIM_HISTORY_HMAC_KEY: '', NODE_ENV: 'development' } as NodeJS.ProcessEnv, true), /required/);
      reg.assertHistoryKeyForProduction({ ...process.env, FIM_HISTORY_HMAC_KEY: '', NODE_ENV: 'development' } as NodeJS.ProcessEnv, false);
      const saved = { k: process.env.FIM_HISTORY_HMAC_KEY, id: process.env.FIM_HISTORY_HMAC_KEY_ID };
      delete process.env.FIM_HISTORY_HMAC_KEY;
      await assert.rejects(reg.setManagedEnabled(db, true, SA, 'no key'), /FIM_HISTORY_HMAC_KEY/);
      process.env.FIM_HISTORY_ALLOW_UNKEYED = '1';
      const nk = await reg.createRule(db, { layer: 'node', scopeValue: H('w2'), op: 'add', target: 'reg.aedebug', reason: 'unkeyed' }, SA);
      delete process.env.FIM_HISTORY_ALLOW_UNKEYED;
      process.env.FIM_HISTORY_HMAC_KEY = saved.k; process.env.FIM_HISTORY_HMAC_KEY_ID = saved.id;
      const uv = await reg.verifyHistoryChain(db);
      assert.ok(!uv.ok && uv.brokenAt === nk.historyHead.id && /without a key/.test(uv.reason!), JSON.stringify(uv));
      // restore: remove the unkeyed row (maintenance) and its outbox head, then revoke the rule
      await maint('DELETE FROM fim_reg_history WHERE id = $1', [nk.historyHead.id]);
      await maint('DELETE FROM fim_reg_anchor_outbox WHERE history_id = $1', [nk.historyHead.id]);
      await maint(`UPDATE fim_reg_history_hwm SET head_id = (SELECT max(id) FROM fim_reg_history), row_hash = (SELECT row_hash FROM fim_reg_history ORDER BY id DESC LIMIT 1), row_count = (SELECT count(*) FROM fim_reg_history) WHERE id`, []);
      await maint(`UPDATE fim_reg_settings SET history_head_id = (SELECT max(id) FROM fim_reg_history) WHERE id`, []);
      await reg.revokeRule(db, nk.rule.id, SA, 'unkeyed cleanup');
      assert.ok((await reg.verifyHistoryChain(db)).ok);
    }
    {
      // R12-3: a fully UNKEYED rewrite of the whole chain (key_id NULL, hashes, outbox and high-water
      // mark recomputed) is broken while a key is configured; no anchor at all is unverifiable.
      const orig = await q('SELECT id, prev_hash, row_hash, key_id, scope_type, scope_value, snapshot, actor, at, reason FROM fim_reg_history ORDER BY id');
      const saveKey = process.env.FIM_HISTORY_HMAC_KEY;
      let prev: string | null = null;
      const forged: { id: number; prev: string | null; hash: string }[] = [];
      delete process.env.FIM_HISTORY_HMAC_KEY;
      for (const r of orig) { const h = reg.historyRowHash(prev, { at: Number(r.at), actor: r.actor, reason: r.reason, scope_type: r.scope_type, scope_value: r.scope_value, snapshot: r.snapshot }, null); forged.push({ id: Number(r.id), prev, hash: h }); prev = h; }
      process.env.FIM_HISTORY_HMAC_KEY = saveKey;
      await ds.transaction(async (m) => {
        await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
        for (const f of forged) {
          await m.query('UPDATE fim_reg_history SET key_id = NULL, prev_hash = $2, row_hash = $3 WHERE id = $1', [f.id, f.prev, f.hash]);
          await m.query('UPDATE fim_reg_anchor_outbox SET row_hash = $2, key_id = NULL WHERE history_id = $1', [f.id, f.hash]);
        }
        await m.query('UPDATE fim_reg_history_hwm SET row_hash = $1 WHERE id', [forged[forged.length - 1].hash]);
      });
      const uv = await reg.verifyHistoryChain(db);
      assert.ok(!uv.ok && /without a key written after a history key was in use/.test(uv.reason!), JSON.stringify(uv));
      await ds.transaction(async (m) => {
        await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
        for (const r of orig) {
          await m.query('UPDATE fim_reg_history SET key_id = $2, prev_hash = $3, row_hash = $4 WHERE id = $1', [r.id, r.key_id, r.prev_hash, r.row_hash]);
          await m.query('UPDATE fim_reg_anchor_outbox SET row_hash = $2, key_id = $3 WHERE history_id = $1', [r.id, r.row_hash, r.key_id]);
        }
        await m.query('UPDATE fim_reg_history_hwm SET row_hash = $1 WHERE id', [orig[orig.length - 1].row_hash]);
      });
      assert.ok((await reg.verifyHistoryChain(db)).ok);
      const na = await reg.verifyHistoryChain(db, { anchor: async () => null });
      assert.ok(!na.ok && na.unverifiable && /no anchor|no head/.test(na.reason!), JSON.stringify(na));
      // ... also when nothing was ever anchored (fresh outbox) while a key is configured
      const anch = await q('SELECT history_id, anchored_at FROM fim_reg_anchor_outbox WHERE anchored_at IS NOT NULL');
      await maint(`UPDATE fim_reg_anchor_outbox SET anchored_at = NULL, created_at = extract(epoch FROM now())::bigint WHERE anchored_at IS NOT NULL`, []);
      const na2 = await reg.verifyHistoryChain(db, { anchor: async () => null });
      assert.ok(!na2.ok && na2.unverifiable && /no anchor is available/.test(na2.reason!), JSON.stringify(na2));
      await ds.transaction(async (m) => {
        await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
        for (const a of anch) await m.query('UPDATE fim_reg_anchor_outbox SET anchored_at = $2 WHERE history_id = $1', [a.history_id, a.anchored_at]);
      });
      // incremental mode: a rewrite inside the recent window is caught (not only by the nightly full check)
      assert.ok((await reg.verifyHistoryChain(db, { fromCache: true })).ok);
      const mid = orig[Math.max(0, orig.length - 3)];
      await maint(`UPDATE fim_reg_history SET actor = 'mallory' WHERE id = $1`, [mid.id]);
      const vw = await reg.verifyHistoryChain(db, { fromCache: true });
      assert.ok(!vw.ok && vw.brokenAt === Number(mid.id), JSON.stringify(vw));
      await maint(`UPDATE fim_reg_history SET actor = $2 WHERE id = $1`, [mid.id, mid.actor]);
      assert.ok((await reg.verifyHistoryChain(db, { fromCache: true })).ok);
    }
    {
      // Role gate: the maintenance flag alone does not open the table to a non-member role.
      await q(`CREATE ROLE ${PROBE_ROLE} NOLOGIN`);
      await q(`GRANT SELECT, UPDATE, DELETE ON fim_reg_history TO ${PROBE_ROLE}`);
      const asProbe = (sql: string) => ds.transaction(async (m) => {
        await m.query(`SET LOCAL ROLE ${PROBE_ROLE}`);
        await m.query(`SET LOCAL vajra.fim_history_maintenance = 'on'`);
        await m.query(sql, [victim.id]);
      });
      await assert.rejects(asProbe('UPDATE fim_reg_history SET actor = actor WHERE id = $1'), /append-only/);
      await assert.rejects(asProbe('DELETE FROM fim_reg_history WHERE id = $1'), /append-only/);
      await q(`GRANT fim_history_admin TO ${PROBE_ROLE}`);
      await asProbe('UPDATE fim_reg_history SET actor = actor WHERE id = $1'); // member + flag: allowed
      await q(`REVOKE fim_history_admin FROM ${PROBE_ROLE}`);
      assert.ok((await reg.verifyHistoryChain(db)).ok);
    }
    ok('history: keyed chain verifies; tampered row pinpointed; UPDATE refused; unkeyed rewrite detected; tail truncation caught by the anchor (row count too); trigger needs fim_history_admin membership AND the flag (M5/A-MED5)');

    // --- rules vs. history divergence (direct SQL write) -------------------------------------------------
    {
      const ins = (await q(`INSERT INTO fim_reg_rules (layer, scope_value, op, target, spec, reason, created_by, created_at) VALUES ('node',$1,'add','reg.rdp','{}'::jsonb,'sneaky',$2,1) RETURNING id`, [H('w2'), `${P}-sql`]))[0];
      assert.ok((await reg.rulesDivergence(db)).some((d) => d.scopeType === 'node' && d.scopeValue === H('w2')));
      reg.resetReconcileTimers();
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM alerts WHERE alert_type = 'fim_config' AND is_open AND event_code LIKE 'FIM registry rules differ from the last recorded history snapshot%'`))[0].c) >= 1, true);
      await q('DELETE FROM fim_reg_rules WHERE id = $1', [ins.id]);
      const divLeft = (await reg.rulesDivergence(db)).filter((d) => d.scopeValue.startsWith(P));
      // non-vacuous: w1 still has an active waiver-backed rule (bigint waiver_id vs number in the snapshot)
      assert.ok((await q(`SELECT 1 FROM fim_reg_rules WHERE status = 'active' AND scope_value = $1 AND waiver_id IS NOT NULL`, [H('w1')])).length === 1);
      assert.deepStrictEqual(divLeft, []);
      await q(`DELETE FROM alerts WHERE alert_type = 'fim_config' AND event_code LIKE 'FIM registry rules differ from the last recorded history snapshot%' AND metadata LIKE $1`, [`%${P}%`]);
    }
    ok('A-MED5: a rule written outside the API is reported by the daily rules-vs-snapshot check (critical alert)');

    // --- rollback with the caller's real permissions (L1) -------------------------------------------------
    {
      const ovKey = customEntryKey(ov1.path);
      const snapOv = hist.items.find((h: any) => (h.snapshot.rules ?? []).some((r: any) => r.target === ovKey) && (h.snapshot.rules ?? []).some((r: any) => r.waiverId))!;
      assert.ok(snapOv, 'a snapshot with an SA-only rule and a waiver-backed rule exists');
      const rbo = await reg.rollback(db, snapOv.id, GA, 'GA rollback');
      assert.ok(rbo.skipped.some((s: string) => s.includes(ovKey) && /measure/i.test(s)), JSON.stringify(rbo.skipped));
      assert.ok(rbo.skipped.some((s: string) => s.includes('reg.run.hklm') && /waiver/.test(s)));
      const act = (await reg.listRules(db, { layer: 'node', scopeValue: H('w1') }, SA)).map((r) => r.target);
      assert.ok(!act.includes(ovKey) && !act.some((t) => t === 'reg.run.hklm'), 'no SA-only or waiver-backed rule recreated by a GA');
      const profHist = (await q(`SELECT id FROM fim_reg_history WHERE scope_type = 'profile' ORDER BY id DESC LIMIT 1`))[0];
      if (profHist) await assert.rejects(reg.rollback(db, Number(profHist.id), GA, 'x'), reg.FimForbiddenError);
      await assert.rejects(reg.rollback(db, snapOv.id, GB, 'x'), svc.FimNotFoundError);
    }
    const firstSnap = hist.items.find((h: any) => (h.snapshot.rules ?? []).length === 1 && h.snapshot.rules[0].target === 'reg.netsh')!;
    const rb = await reg.rollback(db, firstSnap.id, GA, 'back to netsh only');
    assert.strictEqual(rb.rules, 1);
    const after = await reg.listRules(db, { layer: 'node', scopeValue: H('w1') }, SA);
    assert.deepStrictEqual(after.map((r) => r.target), ['reg.netsh']);
    ok('rollback: forward-only, with the caller\'s permissions (L1): SA-only and waiver-backed rules are not recreated by a GA; profile rollback SA-only; other group 404');

    // --- soft-retire purge ---------------------------------------------------------------------------------
    await reg.publishNode(db, H('w1'), { actor: SA, note: 'after rollback' });
    const rdp = await reg.createRule(db, { layer: 'node', scopeValue: H('w1'), op: 'add', target: 'reg.rdp', reason: 'temp' }, SA);
    await reg.publishNode(db, H('w1'), { actor: SA, note: 'add rdp' });
    await reg.revokeRule(db, rdp.rule.id, SA, 'remove rdp');
    const rr = await reg.publishNode(db, H('w1'), { actor: SA, note: 'remove rdp' });
    assert.strictEqual(rr.retired.length, 1);
    const retiredSlot = rr.retired[0];
    await q(`INSERT INTO fim_baseline (policy_id, host_identifier, path, kind, entry_idx, first_seen, last_seen) VALUES ($1,$2,'registry|old','item',$3,1,1)`, [r2.policyId, H('w1'), retiredSlot]);
    await q(`UPDATE fim_reg_slots SET purge_after = 1 WHERE host_identifier = $1 AND slot_idx = $2`, [H('w1'), retiredSlot]);
    await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM fim_baseline WHERE host_identifier = $1 AND entry_idx = $2`, [H('w1'), retiredSlot]))[0].c), 0);
    assert.ok((await q(`SELECT purged_at FROM fim_reg_slots WHERE host_identifier = $1 AND slot_idx = $2`, [H('w1'), retiredSlot]))[0].purged_at);
    ok('soft-retire: baseline rows of a slot retired > 7 days ago are purged by the reconcile job');

    // --- concurrent publishes of one node serialize cleanly ------------------------------------------------
    await reg.createRule(db, { layer: 'node', scopeValue: H('w4'), op: 'add', target: 'reg.rdp.tcp', reason: 'rdp' }, GA);
    const conc = await Promise.allSettled(Array.from({ length: 6 }, () => reg.publishNode(db, H('w4'), { actor: GA, note: 'race' })));
    assert.strictEqual(conc.length, 6);
    assert.ok(conc.every((c) => c.status === 'fulfilled'), JSON.stringify(conc.filter((c) => c.status === 'rejected')));
    assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM fim_policies WHERE managed_host = $1`, [H('w4')]))[0].c), 1);
    const dup = await q(`SELECT entry_key, count(*) FROM fim_reg_slots WHERE host_identifier = $1 AND retired_at IS NULL GROUP BY entry_key HAVING count(*) > 1`, [H('w4')]);
    assert.strictEqual(dup.length, 0);
    ok('six concurrent publishes of the same node: one policy, unique live slots');

    // --- compaction --------------------------------------------------------------------------------------
    const pc = await pol(H('w1'));
    assert.ok(pc.paths.some((p: any) => p.retired), 'there are tombstones to compact');
    const cp = await reg.compactNode(db, H('w1'), GA, 'compact test');
    const pc2 = await pol(H('w1'));
    assert.ok(pc2.rev === pc.rev + 1 && !pc2.paths.some((p: any) => p.retired));
    assert.strictEqual(Number((await q('SELECT count(*) AS c FROM fim_baseline WHERE policy_id = $1', [pc.id]))[0].c), 0);
    assert.strictEqual((await q('SELECT state FROM fim_host_state WHERE policy_id = $1 AND host_identifier = $2', [pc.id, H('w1')]))[0].state, 'learning');
    assert.strictEqual(cp.needsInit.length, pc2.paths.length);
    ok('compaction: slots renumbered (no tombstones), rev bump, baseline removed, monitoring paused until Initialize');

    // --- profiles: optimistic concurrency, assignment version, waiver-backed profiles (A-MED2) -------
    const pr = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-prof`, tier: 'comprehensive', isDefault: false, scanIntervalSecs: 1800, mode: 'learn', reason: 'x' }), SA);
    await assert.rejects(reg.saveProfile(db, pr.profile.id, reg.validateProfileInput({ name: `${P}-prof`, tier: 'essential', isDefault: false, scanIntervalSecs: 1800, mode: 'learn', version: 99 }), SA), svc.FimConflictError);
    const as1 = await reg.putAssignment(db, 'group', H('gA'), { profileId: pr.profile.id, reason: 'x' }, GA);
    await assert.rejects(reg.deleteProfile(db, pr.profile.id, SA, 'x'), svc.FimConflictError);
    const covP = await reg.getNodeCoverage(db, H('w4'), GA);
    assert.ok(covP.profile.id === pr.profile.id && covP.profile.source === 'group' && covP.tier.value === 'comprehensive' && covP.mode === 'learn');
    await assert.rejects(reg.putAssignment(db, 'group', H('gA'), { profileId: null, tier: null, reason: 'x' }, GA), /version is required/);
    await assert.rejects(reg.putAssignment(db, 'group', H('gA'), { profileId: null, tier: null, reason: 'x', version: 99 }, GA), svc.FimConflictError);
    await reg.putAssignment(db, 'group', H('gA'), { profileId: null, tier: null, reason: 'x', version: as1.after!.version }, GA);
    await reg.deleteProfile(db, pr.profile.id, SA, 'cleanup');
    {
      // group / profile publish stale check inputs (the controller compares them before publishing)
      const gc = await reg.getGroupCoverage(db, H('gA'), GA);
      assert.strictEqual(gc.resolvedHash, await reg.currentGroupHash(db, H('gA')));
      const gr = await reg.createRule(db, { layer: 'group', scopeValue: H('gA'), op: 'add', target: 'reg.printmonitors', reason: 'stale check' }, GA);
      assert.notStrictEqual(await reg.currentGroupHash(db, H('gA')), gc.resolvedHash, 'group hash changes with the group rules');
      await reg.revokeRule(db, gr.rule.id, GA, 'undo');
      assert.strictEqual(await reg.currentGroupHash(db, H('gA')), gc.resolvedHash);
      const pd = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-digest`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      const d0 = (await reg.listProfiles(db, SA)).find((x: any) => x.id === pd.profile.id)!.digest;
      assert.ok(d0 && d0 === await reg.currentProfileDigest(db, pd.profile.id));
      await reg.createRule(db, { layer: 'profile', scopeValue: String(pd.profile.id), op: 'add', target: 'reg.netsh', reason: 'digest' }, SA);
      assert.notStrictEqual(await reg.currentProfileDigest(db, pd.profile.id), d0, 'profile digest changes with its rules');
    }
    {
      const pw = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-waived`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      const wp = await reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'profile', scopeValue: String(pw.profile.id), action: 'disable', reason: 'kiosk profile, ticket 7', expiresAt: exp(), rule: RUN_RULE }, SA);
      await reg.decideWaiver(db, wp.id, 'approve', 'ok', SA2);
      await reg.applyWaiver(db, wp.id, SA, 'apply');
      await assert.rejects(reg.putAssignment(db, 'group', H('gA'), { profileId: pw.profile.id, reason: 'inherit waiver' }, GA), reg.FimForbiddenError);
      await assert.rejects(reg.putAssignment(db, 'node', H('w4'), { profileId: pw.profile.id, reason: 'inherit waiver' }, GA), reg.FimForbiddenError);
      const sa1 = await reg.putAssignment(db, 'node', H('w4'), { profileId: pw.profile.id, reason: 'SA decides' }, SA);
      await reg.putAssignment(db, 'node', H('w4'), { profileId: null, tier: null, reason: 'undo', version: sa1.after!.version }, SA);
    }
    {
      // LOW-1: an empty review hash is a stale review, never "no check"
      await assert.rejects(reg.publishNode(db, H('w4'), { actor: GA, expectedHash: '', note: 'empty hash' }), svc.FimConflictError);
      // LOW-2: profile version must be a safe integer; two concurrent assignment creates -> one 409
      assert.throws(() => reg.validateProfileInput({ name: `${P}-v`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', version: 1e21 }), FimValidationError);
      const race = await Promise.allSettled([1, 2].map(() => reg.putAssignment(db, 'node', H('w4'), { tier: 'recommended', reason: 'race' }, GA)));
      assert.deepStrictEqual(race.map((r) => r.status).sort(), ['fulfilled', 'rejected']);
      assert.ok((race.find((r) => r.status === 'rejected') as PromiseRejectedResult).reason instanceof svc.FimConflictError);
      const cur = (await q(`SELECT version FROM fim_reg_assignments WHERE scope_type = 'node' AND scope_value = $1`, [H('w4')]))[0];
      await reg.putAssignment(db, 'node', H('w4'), { profileId: null, tier: null, reason: 'undo', version: Number(cur.version) }, GA);
    }
    ok('profiles: version 409; A-LOW11 assignment version mandatory + stale 409; group profile/tier/mode inherited; A-MED2 a waiver-backed profile can only be assigned by a Super Admin');

    // --- H2: waiver revoke / expiry across > 200 nodes (budget-exempt republish) --------------------
    {
      const tB = Date.now();
      await q(`INSERT INTO nodes (host_identifier, os_platform, owner_group_id, node_key, hostname) SELECT h, 'windows', $2, h, h FROM unnest($1::text[]) AS h`, [bulk, H('gH')]);
      const gw = (reason: string) => reg.requestWaiver(db, { entryKey: 'reg.run.hklm', scopeType: 'group', scopeValue: H('gH'), action: 'disable', reason, expiresAt: exp(), rule: RUN_RULE }, SA);
      const w1g = await gw('bulk group waiver one');
      await reg.decideWaiver(db, w1g.id, 'approve', 'ok', SA2);
      const ruleG = await reg.applyWaiver(db, w1g.id, SA, 'apply');
      // new nodes are onboarded at FIM_REG_AUTO_PUBLISH_PER_SWEEP per sweep
      for (let i = 0; i < 3; i++) await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      assert.strictEqual((await reg.hostsUsingWaiver(db, w1g.id)).length, bulk.length);
      const revoked = await reg.decideWaiver(db, w1g.id, 'revoke', 'no longer needed', SA);
      assert.strictEqual(revoked.status, 'revoked');
      const lg: string[] = [];
      const sr = await reg.reconcileRegistryNodes(db, (m, e) => lg.push(`${m}:${JSON.stringify(e)}`), { onlyHosts: only });
      assert.strictEqual(lg.filter((l) => l.includes('waiver_invalid')).length, bulk.length, 'all 210 republished in ONE sweep (budget-exempt)');
      assert.strictEqual((await reg.hostsUsingWaiver(db, w1g.id)).length, 0);
      assert.ok((await reg.getNodeCoverage(db, bulk[205], SA)).entries.some((e: any) => e.entryKey === 'reg.run.hklm'), 'protected coverage restored on the 206th node');
      // expiry of a second waiver, same scale
      await reg.revokeRule(db, ruleG.rule.id, SA, 'old waiver rule');
      const w2g = await gw('bulk group waiver two');
      await reg.decideWaiver(db, w2g.id, 'approve', 'ok', SA2);
      await reg.applyWaiver(db, w2g.id, SA, 'apply');
      for (const h of bulk) await reg.publishNode(db, h, { actor: SA, note: 'apply waiver two' });
      assert.strictEqual((await reg.hostsUsingWaiver(db, w2g.id)).length, bulk.length);
      await q(`UPDATE fim_reg_waivers SET requested_at = extract(epoch FROM now())::bigint - 86400, expires_at = extract(epoch FROM now())::bigint - 1 WHERE id = $1`, [w2g.id]);
      await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
      assert.strictEqual((await reg.hostsUsingWaiver(db, w2g.id)).length, 0, 'every node lost the expired waiver in one sweep');
      console.log(`   (H2 block: ${bulk.length} nodes, sweep after revoke ${sr.ms} ms, block total ${Date.now() - tB} ms)`);
    }
    ok('H2: revoking or expiring a group waiver used by 210 nodes republishes all of them in one sweep (not limited by the 200/sweep onboarding budget)');

    // --- HIGH-2: profile-wide publish runs as a chunked, resumable, single background job -------------
    {
      const pj = await reg.saveProfile(db, null, reg.validateProfileInput({ name: `${P}-job`, tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', reason: 'x' }), SA);
      await reg.putAssignment(db, 'group', H('gH'), { profileId: pj.profile.id, reason: 'job test' }, SA);
      const targets = await reg.profileTargets(db, pj.profile.id);
      assert.deepStrictEqual(targets, [...bulk].sort(), 'cheap target computation = the group members');
      const pd0 = (await reg.currentProfileDigest(db, pj.profile.id))!;
      await assert.rejects(reg.startProfilePublishJob(db, pj.profile.id, SA, 'stale', 'f'.repeat(64)), svc.FimConflictError);
      await assert.rejects(reg.startProfilePublishJob(db, pj.profile.id, GA, 'x', pd0), reg.FimForbiddenError);
      const job = await reg.startProfilePublishJob(db, pj.profile.id, SA, `${P} job`, pd0);
      await assert.rejects(reg.startProfilePublishJob(db, pj.profile.id, SA, 'second', pd0), svc.FimConflictError);
      // simulate a runner that died after the first chunk: claim, stop, then resume via stale heartbeat
      await q(`UPDATE fim_reg_jobs SET status = 'running', heartbeat_at = 1, cursor = $2, done = 5 WHERE id = $1`, [job.id, [...bulk].sort()[4]]);
      const loopDelays: number[] = [];
      let last = Date.now();
      const tick = setInterval(() => { const n2 = Date.now(); loopDelays.push(n2 - last - 5); last = n2; }, 5);
      assert.strictEqual(await reg.resumeRegistryJobs(db), 1);
      for (let i = 0; i < 600; i++) { const j = await reg.getJob(db, job.id, SA); if (j.status === 'done') break; await new Promise((r) => setTimeout(r, 100)); }
      clearInterval(tick);
      const jd = await reg.getJob(db, job.id, SA);
      assert.deepStrictEqual([jd.status, jd.total, jd.done + jd.failed], ['done', bulk.length, bulk.length], JSON.stringify(jd));
      const maxDelay = Math.max(...loopDelays);
      console.log(`   (profile job: ${bulk.length} nodes, max event-loop delay while running ${maxDelay} ms)`);
      assert.ok(maxDelay < 250, `event loop blocked ${maxDelay} ms`);
      // M2: the profile changes after the review -> the job aborts before publishing anything more
      const before = Number((await q(`SELECT count(*) AS c FROM fim_audit WHERE action = 'FIM_REG_PUBLISH' AND details->>'host' LIKE $1`, [`${P}-h%`]))[0].c);
      const j2 = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'again', pd0);
      const pr2 = await reg.createRule(db, { layer: 'profile', scopeValue: String(pj.profile.id), op: 'add', target: 'reg.netsh', reason: 'changed meanwhile' }, SA);
      await reg.runRegistryJob(db, j2.id);
      const ja = await reg.getJob(db, j2.id, SA);
      assert.deepStrictEqual([ja.status, ja.error, ja.done], ['aborted', 'profile changed during publish', 0], JSON.stringify(ja));
      assert.strictEqual(Number((await q(`SELECT count(*) AS c FROM fim_audit WHERE action = 'FIM_REG_PUBLISH' AND details->>'host' LIKE $1`, [`${P}-h%`]))[0].c), before, 'no node published from unreviewed content');
      await reg.revokeRule(db, pr2.rule.id, SA, 'undo');
      // L4: two runners racing on one job never process more than the total (lease ownership)
      const pd1 = (await reg.currentProfileDigest(db, pj.profile.id))!;
      const j3 = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'race', pd1);
      await Promise.all([reg.runRegistryJob(db, j3.id), reg.runRegistryJob(db, j3.id)]);
      const jr = await reg.getJob(db, j3.id, SA);
      assert.ok(jr.status === 'done' && jr.done + jr.failed === jr.total && jr.total === bulk.length, JSON.stringify({ ...jr, results: undefined }));
      // a stale runner that lost its lease stops writing progress
      const j4 = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'lease', pd1);
      const run4 = reg.runRegistryJob(db, j4.id);
      // deterministic: wait (bounded) until the runner has committed its first chunk, then take the lease
      for (let i = 0; i < 200; i++) { if ((await reg.getJob(db, j4.id, SA)).done > 0) break; await new Promise((r) => setTimeout(r, 25)); }
      assert.ok((await reg.getJob(db, j4.id, SA)).done > 0, 'first chunk committed');
      const pubOf = async () => Number((await q(`SELECT count(*) AS c FROM fim_audit WHERE action = 'FIM_REG_PUBLISH' AND details->>'note' LIKE $1`, [`profile publish job #${j4.id}%`]))[0].c);
      await q(`UPDATE fim_reg_jobs SET lease_token = 'taken-over', heartbeat_at = $2 WHERE id = $1`, [j4.id, Math.floor(Date.now() / 1000)]);
      const atTakeover = await pubOf();
      await run4;
      // the per-node lease check: at most the publish already in flight completes after the takeover
      assert.ok((await pubOf()) - atTakeover <= 1, `old runner published ${(await pubOf()) - atTakeover} node(s) after losing its lease`);
      const jl = await reg.getJob(db, j4.id, SA);
      assert.ok(jl.status === 'running' && jl.done + jl.failed < bulk.length, `the old runner stopped after losing its lease: ${JSON.stringify({ ...jl, results: undefined })}`);
      // cancel endpoint
      await assert.rejects(reg.cancelJob(db, j4.id, GA, null), reg.FimForbiddenError);
      assert.strictEqual((await reg.cancelJob(db, j4.id, SA, 'stop')).status, 'cancelled');
      await assert.rejects(reg.cancelJob(db, j4.id, SA, 'again'), svc.FimConflictError);
      // max age: a stuck job is failed and alerted by the resume pass
      const j5 = await reg.startProfilePublishJob(db, pj.profile.id, SA, 'stuck', pd1);
      await q(`UPDATE fim_reg_jobs SET created_at = created_at - 7 * 3600 WHERE id = $1`, [j5.id]);
      await reg.resumeRegistryJobs(db);
      assert.strictEqual((await reg.getJob(db, j5.id, SA)).status, 'failed');
      await q(`DELETE FROM alerts WHERE alert_type = 'fim_config' AND event_code LIKE 'FIM registry job #%'`);
      const cur = (await q(`SELECT version FROM fim_reg_assignments WHERE scope_type = 'group' AND scope_value = $1`, [H('gH')]))[0];
      await reg.putAssignment(db, 'group', H('gH'), { profileId: null, tier: null, reason: 'undo', version: Number(cur.version) }, SA);
      await q(`DELETE FROM fim_reg_jobs WHERE created_by LIKE $1`, [`${P}%`]);
    }
    ok('HIGH-2: profile publish = background job (Super Admin, one at a time, resumable after a dead runner, progress, event loop stays responsive)');

    // --- migration assistant + template v2 --------------------------------------------------------------
    const legacy = await svc.createPolicy(db, validatePolicyInput({
      name: `${P}-legacy`, osPlatform: 'windows', template: 'windows-registry-persistence',
      paths: [{ kind: 'registry', path: `${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run` }, { kind: 'registry', path: `${L}SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\%` }, { kind: 'registry', path: `${L}SOFTWARE\\Acme\\Thing` }, { path: 'C:\\Windows\\x.dll' }],
      targets: [{ type: 'group', value: H('gA') }],
    }), SA.email);
    const lst = (await reg.listLegacy(db, SA)).find((x: any) => x.id === legacy.id);
    assert.deepStrictEqual(lst.entries.map((e: any) => e.mapping.type), ['catalog', 'catalog', 'custom']);
    assert.ok(lst.templateUpgradeAvailable && lst.overlapHosts >= 1);
    const ap = await reg.applyLegacy(db, legacy.id, SA, 'migrate');
    assert.strictEqual(ap.rules, 2); // Active Setup (recommended) + custom; Run is Essential (always on)
    const rm = await reg.removeLegacyRegistry(db, legacy.id, SA);
    assert.strictEqual(rm.removed, 3);
    assert.strictEqual(rm.policy!.paths.length, 1);
    const legacy2 = await svc.createPolicy(db, validatePolicyInput({ name: `${P}-legacy2`, osPlatform: 'windows', template: 'windows-registry-persistence',
      paths: [{ kind: 'registry', path: `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa` }], targets: [] }), SA.email);
    const up = await svc.upgradePolicyTemplate(db, legacy2.id);
    assert.ok(up.policy.rev === 2 && up.policy.realtime && up.policy.paths.length === 15);
    await assert.rejects(svc.upgradePolicyTemplate(db, legacy2.id), svc.FimBadRequestError);
    ok('migration assistant: catalog/custom mapping, rules created at the target group, legacy registry entries removed; template v2 upgrade bumps rev once');

    // --- feature backout and restore; removed node -----------------------------------------------------
    await q(`INSERT INTO fim_drift (policy_id, policy_name, host_identifier, path, change_type, source, severity, detected_at, last_seen_at, kind, entry_idx)
             VALUES ($1,'x',$2,'registry|kept','added','scan','high',1,1,'item',0)`, [r2.policyId, H('w1')]);
    const off = await reg.setManagedEnabled(db, false, SA, 'backout');
    assert.ok(off.disabledPolicies >= 4 + bulk.length);
    for (const h of [H('w1'), H('w3'), bulk[0]]) {
      const p = await pol(h);
      assert.ok(!p.enabled && !p.config_query_id);
      assert.ok(!(await cfgOf(h) ?? '').split(',').includes(String(p.id)));
    }
    assert.strictEqual(await cfgOf(H('w1')), '7,8');
    assert.ok(Number((await q(`SELECT count(*) AS c FROM fim_drift WHERE host_identifier = $1`, [H('w1')]))[0].c) > 0, 'drift kept');
    await reg.setManagedEnabled(db, true, SA, 'restore');
    for (let i = 0; i < 3; i++) await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    assert.ok((await pol(H('w1'))).enabled && (await pol(H('w1'))).config_query_id);
    await q(`DELETE FROM nodes WHERE host_identifier = $1`, [H('w3')]);
    await reg.reconcileRegistryNodes(db, undefined, { onlyHosts: only });
    assert.ok(!(await pol(H('w3'))).enabled);
    ok('backout: all managed policies disabled set-based in one go, config ids removed, other ids and drift kept; restore republishes; removed node -> policy disabled');

    // --- generic API guards on managed policies ------------------------------------------------------
    const ga = await svc.fetchPolicy(db, (await pol(H('w1'))).id);
    assert.strictEqual(ga!.managedKind, 'registry_node');
    assert.throws(() => validatePolicyInput({ name: 'Registry coverage: x', osPlatform: 'windows', paths: [{ path: 'C:\\x\\y' }] }), FimValidationError);
    ok('managed policies are flagged; the reserved name prefix is refused for hand-made policies');
  } finally {
    await cleanup();
    await tdb.drop();
  }
  console.log(`\n${n} groups passed (${Date.now() - t0} ms)`);
})().catch((err) => { console.error(err); process.exit(1); });
