/**
 * Self-contained test for utils/fim/fimLogic.ts (pure, DB-free):
 *   node_modules/.bin/ts-node src/test/utils/fimLogic.selftest.ts
 */
import assert from 'assert';
import {
  validateFimPath, validatePolicyInput, normalizePaths, buildScanSql, buildFimConfig,
  addConfigId, removeConfigId, fimPathWarnings, parseConfigIds, isFimPolicyInScope, escapeLike, pathsChanged,
  FimValidationError,
} from '../../utils/fim/fimLogic';
type FimOsPlatformT = 'linux' | 'windows';
import { FIM_TEMPLATES } from '../../utils/fim/fimTemplates';

let n = 0;
const t = (name: string, fn: () => void) => { fn(); n++; console.log(`ok - ${name}`); };

t('path validation: linux', () => {
  assert.strictEqual(validateFimPath('/etc/%%', 'linux'), null);
  assert.strictEqual(validateFimPath('/home/%/.ssh/%%', 'linux'), null);
  for (const bad of ['', '   ', 'etc/passwd', "/etc/' OR 1=1 --", '/etc/a\0b', '/etc/a\nb', '/' + 'a'.repeat(1024), 'C:\\x']) {
    assert.notStrictEqual(validateFimPath(bad, 'linux'), null, JSON.stringify(bad));
  }
  assert.strictEqual(validateFimPath('/' + 'a'.repeat(1023), 'linux'), null); // exactly 1024
  assert.notStrictEqual(validateFimPath(42, 'linux'), null);
});

t('path validation: windows', () => {
  assert.strictEqual(validateFimPath('C:\\Windows\\System32\\drivers\\etc\\*', 'windows'), null);
  assert.notStrictEqual(validateFimPath('*\\Startup\\*', 'windows'), null); // no real directory prefix
  for (const bad of ['/etc/passwd', 'Windows\\x', "C:\\a'b", 'C:\\a\0']) {
    assert.notStrictEqual(validateFimPath(bad, 'windows'), null, JSON.stringify(bad));
  }
});

t('SCAN SQL: one query per entry, with hidden-file terms (empirically verified, see fimLogic.ts)', () => {
  const sql = buildScanSql('/etc/%%', 'linux');
  assert.strictEqual(
    sql,
    "SELECT f.path, f.type, f.size, f.mode, f.uid, f.gid, f.mtime, h.sha256, h.md5 FROM file f LEFT JOIN hash h ON h.path = f.path AND f.type = 'regular' WHERE " +
    "(f.path LIKE '/etc/%%' OR f.path LIKE '/etc/.%' OR f.path LIKE '/etc/%/.%' OR f.path LIKE '/etc/%/%/.%' OR f.path LIKE '/etc/.%/%' OR f.path LIKE '/etc/%/.%/%') " +
    "AND f.path NOT LIKE '%/../%' AND f.path NOT LIKE '%/./%'",
  );
  // never the recursive dot terms that would walk the parent tree via '.'/'..'
  assert.ok(!sql.includes(".%%'") && !sql.includes(".%/%%"));
  // one-level entry: only the top-level hidden term
  assert.ok(buildScanSql('/etc/%', 'linux').includes("f.path LIKE '/etc/.%'"));
  assert.ok(!buildScanSql('/etc/%', 'linux').includes("/etc/%/.%"));
  // exact file / partial name: no hidden terms
  assert.strictEqual(buildScanSql('/etc/passwd', 'linux'), "SELECT f.path, f.type, f.size, f.mode, f.uid, f.gid, f.mtime, h.sha256, h.md5 FROM file f LEFT JOIN hash h ON h.path = f.path AND f.type = 'regular' WHERE f.path LIKE '/etc/passwd'");
  assert.ok(buildScanSql('/home/%/.ssh/%%', 'linux').includes("f.path LIKE '/home/%/.ssh/.%'"));
  const w = buildScanSql('C:\\Windows\\System32\\drivers\\etc\\*', 'windows');
  assert.ok(w.includes("f.path LIKE 'C:\\Windows\\System32\\drivers\\etc\\%'"));
  assert.ok(!/f\.(uid|gid|mode)/.test(w));
  assert.ok(!w.includes('NOT LIKE')); // no hidden terms on Windows
});

t('SCAN SQL: injection attempts are rejected, never embedded', () => {
  for (const evil of ["/etc/%%' OR 1=1 --", "/etc/%' OR 1=1 --", "/etc/%%'; DROP TABLE nodes; --", "/a'", "/a\0' OR 1=1"]) {
    assert.throws(() => buildScanSql(evil, 'linux'), FimValidationError, evil);
    assert.throws(() => normalizePaths([{ path: evil }], 'linux'), FimValidationError, evil);
    assert.throws(() => buildFimConfig({ id: 1, rev: 1, osPlatform: 'linux', paths: [{ path: '/ok/x' }, { path: evil }], scanIntervalSecs: 60, realtime: false }), FimValidationError, evil);
  }
  // every accepted statement has exactly 2 quotes per literal
  for (const ok of ['/var/log/--x', '/tmp/a;b', '/etc/%%']) {
    const sql = buildScanSql(ok, 'linux');
    const lits = (sql.match(/LIKE '/g) ?? []).length;
    assert.strictEqual((sql.match(/'/g) ?? []).length, lits * 2 + 2, ok); // LIKE and NOT LIKE literals + the 'regular' type guard
  }
});

t('config JSON: linux realtime / non-realtime', () => {
  const p = { id: 7, rev: 4, osPlatform: 'linux' as const, paths: [{ path: '/etc/%%' }, { path: '/usr/bin/%%' }], scanIntervalSecs: 3600, realtime: true };
  const c: any = buildFimConfig(p);
  assert.deepStrictEqual(Object.keys(c.schedule).sort(), ['file_events', 'fim_scan_7_4_0', 'fim_scan_7_4_1']);
  assert.ok(c.schedule['fim_scan_7_4_0'].query.includes("LIKE '/etc/%%'") && !c.schedule['fim_scan_7_4_0'].query.includes('/usr/bin'));
  assert.ok(c.schedule['fim_scan_7_4_1'].query.includes("LIKE '/usr/bin/%%'") && !c.schedule['fim_scan_7_4_1'].query.includes('/etc/'));
  assert.deepStrictEqual(c.schedule.file_events, { query: 'SELECT * FROM file_events', interval: 300, snapshot: false });
  assert.strictEqual((buildFimConfig({ ...p, scanIntervalSecs: 120 }) as any).schedule.file_events.interval, 120);
  assert.strictEqual(c.schedule['fim_scan_7_4_0'].interval, 3600);
  assert.strictEqual(c.schedule['fim_scan_7_4_1'].snapshot, true);
  assert.deepStrictEqual(c.file_paths, { fim_7: ['/etc/%%', '/usr/bin/%%'] });
  assert.strictEqual(c.file_accesses, undefined); // reads are noise
  assert.strictEqual(c.win_include_paths, undefined);
  const c2: any = buildFimConfig({ ...p, realtime: false });
  assert.strictEqual(c2.file_paths, undefined);
  assert.strictEqual(c2.file_accesses, undefined);
  assert.ok(c2.schedule['fim_scan_7_4_0']);
  assert.strictEqual(c2.schedule.file_events, undefined); // only when realtime
  JSON.parse(JSON.stringify(c)); // serialisable
});

t('config JSON: windows', () => {
  const c: any = buildFimConfig({ id: 3, rev: 2, osPlatform: 'windows', paths: [{ path: 'C:\\Windows\\System32\\drivers\\etc\\*' }], scanIntervalSecs: 600, realtime: true });
  assert.deepStrictEqual(c.win_include_paths, { fim_3: ['C:\\Windows\\System32\\drivers\\etc\\*'] });
  assert.strictEqual(c.file_paths, undefined);
  assert.strictEqual(c.schedule.file_events, undefined); // windows: not emitted (unverified)
  const round = JSON.parse(JSON.stringify(c));
  assert.strictEqual(round.win_include_paths.fim_3[0], 'C:\\Windows\\System32\\drivers\\etc\\*');
  assert.strictEqual(Object.prototype.hasOwnProperty.call(buildFimConfig({ id: 3, rev: 2, osPlatform: 'windows', paths: [{ path: 'C:\\a\\*' }], scanIntervalSecs: 600, realtime: false }), 'win_include_paths'), false);
});

t('config_id list arithmetic', () => {
  assert.strictEqual(addConfigId(null, 5), '5');
  assert.strictEqual(addConfigId('', 5), '5');
  assert.strictEqual(addConfigId('18,23,3', 5), '18,23,3,5');
  assert.strictEqual(addConfigId('18,5,3', 5), '18,5,3'); // idempotent
  assert.strictEqual(addConfigId(' 18 , ,23,', 5), '18,23,5'); // cleans blanks
  assert.strictEqual(removeConfigId('18,5,3', 5), '18,3');
  assert.strictEqual(removeConfigId('5', 5), '');
  assert.strictEqual(removeConfigId(null, 5), '');
  assert.strictEqual(removeConfigId('15,50,5,55', 5), '15,50,55'); // never a substring match
  assert.deepStrictEqual(parseConfigIds('1, 2,,3'), ['1', '2', '3']);
});

t('policy input validation', () => {
  const ok = validatePolicyInput({ name: ' P1 ', osPlatform: 'linux', paths: [{ path: '/etc/%%' }, '/var/%'], targets: [{ type: 'node', value: 'h1' }, { type: 'node', value: 'h1' }] });
  assert.strictEqual(ok.name, 'P1');
  assert.strictEqual(ok.paths[0].severity, 'medium');
  assert.strictEqual(ok.paths[1].path, '/var/%');
  assert.strictEqual(ok.targets.length, 1);
  assert.strictEqual(ok.mode, 'learn');
  const bad: any[] = [
    {}, { name: 'x', paths: [] }, { name: 'x', paths: [{ path: "/a'" }] }, { name: 'x', paths: [{ path: '/a' }, { path: '/a' }] },
    { name: 'x', paths: [{ path: '/a', severity: 'urgent' }] }, { name: 'x', paths: [{ path: '/a' }], scanIntervalSecs: 5 },
    { name: 'x', paths: [{ path: '/a' }], mode: 'x' }, { name: 'x', paths: [{ path: 'C:\\a' }] },
    { name: 'x', osPlatform: 'mac', paths: [{ path: '/a' }] },
    { name: 'x', paths: [{ path: '/a' }], targets: [{ type: 'all' }, { type: 'node', value: 'h' }] },
    { name: 'x', paths: [{ path: '/a' }], targets: [{ type: 'node', value: '' }] },
    { name: 'x', paths: [{ path: '/a', ignore: ['a\0b'] }] }, { name: 'x'.repeat(121), paths: [{ path: '/a' }] },
  ];
  for (const b of bad) assert.throws(() => validatePolicyInput(b), FimValidationError, JSON.stringify(b));
  // update: switching platform re-validates existing paths
  assert.throws(() => validatePolicyInput({ osPlatform: 'windows' }, ok), FimValidationError);
  assert.strictEqual(validatePolicyInput({ enabled: false }, ok).paths.length, 2);
  assert.strictEqual(pathsChanged(ok.paths, ok.paths), false);
  const reordered = ok.paths.map((p) => ({ hash: p.hash, ignore: p.ignore, category: p.category, severity: p.severity, path: p.path }));
  assert.strictEqual(pathsChanged(ok.paths, reordered), false); // jsonb key order must not bump rev
  assert.strictEqual(pathsChanged(ok.paths, ok.paths.slice(1)), true);
});

t('learnScans is accepted and stored as-is; autoInit no longer exists', () => {
  const v: any = validatePolicyInput({ name: 'x', paths: ['/a/b'], learnScans: 7, autoInit: true });
  assert.strictEqual(v.learnScans, 7);
  assert.strictEqual('autoInit' in v, false);
});

t('all-target normalization', () => {
  assert.deepStrictEqual(validatePolicyInput({ name: 'x', paths: ['/a'], targets: [{ type: 'all', value: '*' }] }).targets, [{ type: 'all', value: '' }]);
  assert.deepStrictEqual(validatePolicyInput({ name: 'x', paths: ['/a'], targets: [{ type: 'all' }] }).targets, [{ type: 'all', value: '' }]);
  assert.throws(() => validatePolicyInput({ name: 'x', paths: ['/a'], targets: [{ type: 'all', value: 'foo' }] }), FimValidationError);
});

t('all templates are valid for their platform', () => {
  assert.strictEqual(FIM_TEMPLATES.length, 18);
  assert.strictEqual(new Set(FIM_TEMPLATES.map((x) => x.id)).size, 18);
  for (const tpl of FIM_TEMPLATES) {
    const paths = normalizePaths(tpl.paths, tpl.osPlatform);
    assert.strictEqual(paths.length, tpl.paths.length);
    for (const x of paths) buildScanSql(x, tpl.osPlatform);
    assert.ok(!tpl.paths.some((x) => /SAM$/.test(x.path ?? '')));
    assert.deepStrictEqual(fimPathWarnings(paths, tpl.osPlatform), [], tpl.id); // templates must not trigger the broad-pattern warning
    assert.ok(tpl.scanIntervalSecs >= 60);
  }
});

t('group-admin scoping', () => {
  const groups = new Set(['g1']);
  const hosts = ['h1', 'h2'];
  assert.strictEqual(isFimPolicyInScope({ targets: [{ type: 'group', value: 'g1' }, { type: 'node', value: 'h2' }] }, groups, hosts, 'a@x'), true);
  assert.strictEqual(isFimPolicyInScope({ targets: [{ type: 'group', value: 'g2' }] }, groups, hosts, 'a@x'), false);
  assert.strictEqual(isFimPolicyInScope({ targets: [{ type: 'node', value: 'h3' }] }, groups, hosts, 'a@x'), false);
  assert.strictEqual(isFimPolicyInScope({ targets: [{ type: 'group', value: 'g1' }, { type: 'node', value: 'h3' }] }, groups, hosts, 'a@x'), false);
  assert.strictEqual(isFimPolicyInScope({ targets: [{ type: 'all', value: '' }] }, groups, hosts, 'a@x'), false);
  assert.strictEqual(isFimPolicyInScope({ targets: [], createdBy: 'B@x' }, groups, hosts, 'a@x'), false);
  assert.strictEqual(isFimPolicyInScope({ targets: [], createdBy: 'A@x' }, groups, hosts, 'a@x'), true);
  assert.strictEqual(isFimPolicyInScope({ targets: [] }, groups, hosts), true); // candidate
});

t('rev bump only on path-set / ignore changes', () => {
  const base = [{ path: '/etc/%%', severity: 'low' as const, category: 'a', ignore: ['/etc/x', '/etc/y'], hash: true }];
  assert.strictEqual(pathsChanged(base, [{ ...base[0], severity: 'critical', category: 'zz', hash: false }]), false);
  assert.strictEqual(pathsChanged(base, [{ ...base[0], ignore: ['/etc/y', '/etc/x'] }]), false);
  assert.strictEqual(pathsChanged(base, [{ ...base[0], hash: false }]), false);
  assert.strictEqual(pathsChanged(base, [{ ...base[0], ignore: ['/etc/x'] }]), true);
  assert.strictEqual(pathsChanged(base, [{ ...base[0], path: '/etc/%' }]), true);
  assert.strictEqual(pathsChanged(base, [...base, { ...base[0], path: '/opt/%%' }]), true);
  // order matters: scan queries are keyed by entry index
  assert.strictEqual(pathsChanged([...base, { ...base[0], path: '/opt/%%' }], [{ ...base[0], path: '/opt/%%' }, ...base]), true);
});

t('linux wildcard + directory-prefix rules', () => {
  for (const bad of ['/etc/*', '/etc/a?', '/*', '/%%', '/%', '//%%', '/etc/*/x']) {
    assert.notStrictEqual(validateFimPath(bad, 'linux'), null, bad);
  }
  assert.ok(validateFimPath('/etc/*', 'linux')!.includes('%'));
  for (const good of ['/etc/%%', '/etc/%', '/etc', '/etc/passwd', '/home/%/.ssh/%%', '/etc%']) {
    assert.strictEqual(validateFimPath(good, 'linux'), null, good);
  }
  for (const bad of ['C:\\%%', 'C:\\*', 'C:\\', 'C:/%', '*', '*\\Startup\\*', '%']) {
    assert.notStrictEqual(validateFimPath(bad, 'windows'), null, bad);
  }
  for (const good of ['C:\\Windows\\*', 'C:\\Windows\\System32\\%%', 'C:\\Users\\%\\AppData\\%']) {
    assert.strictEqual(validateFimPath(good, 'windows'), null, good);
  }
});

t('soft warnings for broad patterns', () => {
  assert.strictEqual(fimPathWarnings([{ path: '/usr/lib/%%' }, { path: '/usr/bin/%%' }, { path: '/var/%%' }], 'linux').length, 3);
  assert.strictEqual(fimPathWarnings([{ path: '/etc/%%' }, { path: '/usr/sbin/%%' }, { path: '/usr/lib/systemd/%%' }, { path: '/usr/bin/sudo' }], 'linux').length, 0);
  assert.strictEqual(fimPathWarnings([{ path: 'C:\\Windows\\*' }], 'windows').length, 1);
  assert.strictEqual(fimPathWarnings([{ path: 'C:\\Windows\\System32\\drivers\\etc\\*' }], 'windows').length, 0);
});

t('entry kinds: normalisation fills server-side metadata and rejects bad input', () => {
  const e = normalizePaths([
    '/etc/%%', { path: '/etc/%%', kind: 'xattr' }, { kind: 'table', source: 'listening_ports', keyColumns: ['evil'], valueColumns: ['x'], label: 'x', prefix: 'x' },
  ], 'linux');
  assert.strictEqual(e[0].kind, 'path');
  assert.deepStrictEqual([e[1].kind, e[1].prefix, e[1].keyColumns, e[1].valueColumns], ['xattr', 'xattr', ['path', 'key'], ['value']]);
  // client-supplied columns/label/prefix are ignored: the catalog decides
  assert.deepStrictEqual([e[2].source, e[2].prefix, e[2].keyColumns, e[2].valueColumns, e[2].label, e[2].severity], ['listening_ports', 'listening_ports', ['protocol', 'port', 'address'], ['process', 'process_path'], 'Listening ports', 'high']);
  assert.strictEqual(e[2].path, undefined);
  // table severity override honoured
  assert.strictEqual(normalizePaths([{ kind: 'table', source: 'users', severity: 'low' }], 'linux')[0].severity, 'low');
  const w = normalizePaths([
    { kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { kind: 'registry', path: 'HKEY_USERS\\%\\Environment' },
    { kind: 'acl', path: 'C:\\Windows\\System32' },
    { kind: 'table', source: 'services' },
  ], 'windows');
  assert.deepStrictEqual(w.map((x) => x.kind), ['registry', 'registry', 'acl', 'table']);
  assert.deepStrictEqual(w[2].keyColumns, ['path', 'principal', 'type']);
  const bad: [any, FimOsPlatformT][] = [
    [{ kind: 'bogus', path: '/a/b' }, 'linux'],
    [{ kind: 'xattr', path: 'C:\\a' }, 'windows'], [{ kind: 'xattr', path: '/etc/*' }, 'linux'], [{ kind: 'xattr', path: "/etc/' OR 1=1 --" }, 'linux'], [{ kind: 'xattr', path: '/%%' }, 'linux'],
    [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Run' }, 'linux'], [{ kind: 'registry', path: 'SOFTWARE\\Run' }, 'windows'],
    [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\%%' }, 'windows'], [{ kind: 'registry', path: 'HKEY_USERS\\%' }, 'windows'], [{ kind: 'registry', path: 'HKEY_USERS\\%\\%%\\Run' }, 'windows'], [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE' }, 'windows'], [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\' }, 'windows'],
    [{ kind: 'registry', path: "HKEY_LOCAL_MACHINE\\SOFTWARE\\x' OR 1=1 --" }, 'windows'], [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\a\0b' }, 'windows'],
    [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\*' }, 'windows'], [{ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\a\nb' }, 'windows'],
    [{ kind: 'acl', path: '/etc' }, 'linux'], [{ kind: 'acl', path: 'C:\\Windows\\*' }, 'windows'], [{ kind: 'acl', path: 'C:\\Win%dows' }, 'windows'], [{ kind: 'acl', path: "C:\\a' OR 1=1" }, 'windows'],
    [{ kind: 'acl', path: 'C:\\' }, 'windows'], [{ kind: 'acl', path: '*\\x' }, 'windows'],
    [{ kind: 'table', source: 'nope' }, 'linux'], [{ kind: 'table', source: "users'; DROP TABLE x;--" }, 'linux'], [{ kind: 'table', source: 'services' }, 'linux'], [{ kind: 'table', source: 'users' }, 'windows'],
    [{ kind: 'table' }, 'linux'], [{ kind: 'table', source: 'registry_acl_ext' }, 'windows'],
    [{ kind: 'path', path: '/a/b', severity: "high'" }, 'linux'], [{ kind: 'table', source: 'users', category: 'x'.repeat(65) }, 'linux'],
  ];
  for (const [b, plat] of bad) assert.throws(() => normalizePaths([b], plat), FimValidationError, JSON.stringify(b) + ' on ' + plat);
  assert.strictEqual(normalizePaths([{ kind: 'table', source: 'registry_acl_ext', extensionEnabled: true }], 'windows')[0].extensionEnabled, true);
  assert.throws(() => normalizePaths([{ kind: 'table', source: 'users' }, { kind: 'table', source: 'users' }], 'linux'), FimValidationError); // duplicate
  assert.strictEqual(normalizePaths(Array.from({ length: 500 }, (_, i) => `/opt/d${i}/x`), 'linux').length, 500);
  assert.throws(() => normalizePaths(Array.from({ length: 501 }, (_, i) => `/opt/d${i}/x`), 'linux'), FimValidationError);
});

t('scan SQL per kind (exact text)', () => {
  const run = "SELECT path, key, value FROM extended_attributes WHERE ";
  assert.strictEqual(buildScanSql({ kind: 'xattr', path: '/etc/ssh/passwd' }, 'linux'), run + "path LIKE '/etc/ssh/passwd'");
  const xr = buildScanSql({ kind: 'xattr', path: '/etc/%%' }, 'linux');
  assert.ok(xr.startsWith(run + "(path LIKE '/etc/%%' OR path LIKE '/etc/.%'") && xr.endsWith("AND path NOT LIKE '%/../%' AND path NOT LIKE '%/./%'"));
  // Stored legacy registry entries keep their legacy filter; the mandatory credential redaction is always added.
  const legacy = buildScanSql({ kind: 'registry', path: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%' }, 'windows');
  assert.ok(legacy.startsWith("SELECT path, name, type, CASE WHEN type <> 'subkey' AND (lower(name) IN ('altdefaultpassword'"), legacy);
  assert.ok(legacy.includes("LIKE '%password%'") && legacy.includes(',sha256='), 'legacy entries are untrusted: mandatory + heuristic with digest');
  assert.ok(legacy.endsWith(" FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%'"), legacy);
  assert.strictEqual(buildScanSql({ kind: 'acl', path: 'C:\\Windows\\System32' }, 'windows'),
    "SELECT path, type, principal, access, inherited_from FROM ntfs_acl_permissions WHERE path = 'C:\\Windows\\System32'");
  assert.strictEqual(buildScanSql({ kind: 'table', source: 'groups' }, 'linux'), 'SELECT groupname, gid FROM groups');
  assert.throws(() => buildScanSql({ kind: 'table', source: 'groups' }, 'windows'), FimValidationError);
  assert.throws(() => buildScanSql({ kind: 'registry', path: 'HKEY_USERS\\x\' OR 1=1' }, 'windows'), FimValidationError);
  assert.throws(() => buildScanSql({ kind: 'acl', path: "C:\\x' --" }, 'windows'), FimValidationError);
  assert.throws(() => buildScanSql({ kind: 'xattr', path: "/x' --" }, 'linux'), FimValidationError);
  assert.throws(() => buildScanSql({ kind: 'xattr', path: '/etc/a' }, 'windows'), FimValidationError);
  // config: per-entry keys for every kind; realtime paths only for 'path' entries; no file_paths when none
  const cfg: any = buildFimConfig({ id: 9, rev: 3, osPlatform: 'linux', scanIntervalSecs: 600, realtime: true, paths: [
    { kind: 'table', source: 'users' }, { kind: 'path', path: '/etc/ssh/%%' }, { kind: 'xattr', path: '/etc/ssh/%%' }] });
  assert.deepStrictEqual(Object.keys(cfg.schedule).sort(), ['file_events', 'fim_scan_9_3_0', 'fim_scan_9_3_1', 'fim_scan_9_3_2']);
  assert.deepStrictEqual(cfg.file_paths, { fim_9: ['/etc/ssh/%%'] });
  const cfg2: any = buildFimConfig({ id: 9, rev: 1, osPlatform: 'linux', scanIntervalSecs: 600, realtime: true, paths: [{ kind: 'table', source: 'users' }] });
  assert.strictEqual(cfg2.file_paths, undefined);
  // rev bump covers kind/source/path/ignore
  const a = normalizePaths([{ kind: 'table', source: 'users' }], 'linux');
  assert.strictEqual(pathsChanged(a, normalizePaths([{ kind: 'table', source: 'groups' }], 'linux')), true);
  assert.strictEqual(pathsChanged(a, normalizePaths([{ kind: 'table', source: 'users', severity: 'low' }], 'linux')), false);
  assert.strictEqual(pathsChanged(normalizePaths(['/a/b'], 'linux'), normalizePaths([{ kind: 'xattr', path: '/a/b' }], 'linux')), true);
  assert.strictEqual(pathsChanged(normalizePaths(['/a/b'], 'linux'), [{ path: '/a/b', severity: 'medium', category: '', ignore: [], hash: true }]), false); // old stored entry (no kind) == path
});

t('registry broad-subtree warnings; templates avoid them; services key not in template', () => {
  const w = (k: string) => fimPathWarnings([{ kind: 'registry', path: k }], 'windows').length;
  assert.strictEqual(w('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%'), 1);
  assert.strictEqual(w('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%%'), 1);
  assert.strictEqual(w('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%'), 0);
  assert.strictEqual(w('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'), 0);
  const reg = FIM_TEMPLATES.find((x) => x.id === 'windows-registry-persistence')!;
  assert.ok(!reg.paths.some((x) => /CurrentControlSet\\Services/.test(x.path ?? '')));
  const all = JSON.stringify(FIM_TEMPLATES);
  assert.ok(!all.includes('System32\\\\powershell.exe'), 'powershell.exe lives under WindowsPowerShell\\v1.0');
});

t('path entries ending in a separator track the directory itself (no hidden-file expansion)', () => {
  assert.strictEqual(validateFimPath('/etc/ssh/', 'linux'), null);
  assert.strictEqual(validateFimPath('C:\\Windows\\System32\\', 'windows'), null);
  assert.notStrictEqual(validateFimPath('/', 'linux'), null);
  assert.notStrictEqual(validateFimPath('C:\\', 'windows'), null);
  assert.strictEqual(buildScanSql('/etc/ssh/', 'linux'),
    "SELECT f.path, f.type, f.size, f.mode, f.uid, f.gid, f.mtime, h.sha256, h.md5 FROM file f LEFT JOIN hash h ON h.path = f.path AND f.type = 'regular' WHERE f.path LIKE '/etc/ssh/'");
  assert.ok(!buildScanSql('/etc/ssh/', 'linux').includes('NOT LIKE'));
  const tpl = FIM_TEMPLATES.find((x) => x.id === 'linux-directories-permissions')!;
  assert.ok(['/etc/ssh/', '/etc/sudoers.d/', '/root/.ssh/'].every((d) => tpl.paths.some((x) => x.path === d)));
  assert.strictEqual(normalizePaths(['/etc/ssh/'], 'linux')[0].path, '/etc/ssh/');
});

t('escapeLike', () => assert.strictEqual(escapeLike('a%b_c\\d'), 'a\\%b\\_c\\\\d'));

console.log(`\n${n} groups passed`);
