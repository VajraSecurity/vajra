/**
 * Self-contained tests for per-node registry coverage (pure, DB-free):
 *   node_modules/.bin/ts-node src/test/utils/fimRegistry.selftest.ts
 * Test plan: docs/FIM_REGISTRY_DESIGN.md §5.1 (vajra_server repo).
 *  - adversarial validation inputs, exact SQL goldens, every catalog entry validated + built
 *  - the generated SQL is executed by REAL osqueryd (when installed) against a CTE stand-in for
 *    the Windows-only `registry` table: syntax, LIKE/ESCAPE/lower()/UNION semantics
 *  - property test: 10,000 random strings are refused or produce parseable SQL with the literal once
 *  - resolver: determinism over 1,000 permutations, precedence, protection + waivers, merge,
 *    carve-out, overlap, caps, slots, preview diff, hash chain, hygiene
 *  - optional replay of real exported Windows rows: FIM_REG_LIVEDATA=<dir with registry_*.json>
 */
import assert from 'assert';
import { execFileSync, spawnSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import {
  validateRegistryKeyV2, validateValueName, buildRegistryScanSqlV2, normalizeRegistryEntryV2, entryFingerprint, sqlString,
  keysIntersect, exclusionInside, assertRegistrySqlShape, customEntryKey, asciiLower,
} from '../../utils/fim/fimRegistrySql';
import { FimValidationError, buildScanSql, normalizePaths, pathsChanged, buildFimConfig, validatePolicyInput, validateFimPath } from '../../utils/fim/fimLogic';
import { REG_CATALOG, regTierEntries, getRegCatalogEntry, catalogVisibleByDesign } from '../../utils/fim/fimRegistryCatalog';
import {
  resolveRegistry, allocateSlots, policyEntryJson, diffCoverage, FIM_REG_CAPS, likeMatch, canonicalJson, regRuleHash,
  type RegRule, type RegWaiver, type RegProfile, type ResolveInput,
} from '../../utils/fim/fimRegistryResolver';
import { MANDATORY_REDACT_VALUES, FIM_REDACT_EXEMPT, FIM_REDACTION_POLICY, isSecretLikeName, isCleanText } from '../../utils/fim/fimRegistrySql';
import { createHash } from 'crypto';
import { FIM_TEMPLATES } from '../../utils/fim/fimTemplates';
import { FIM_REGISTRY_DDL, FIM_VERIFY_DDL, FIM_WORKER_DDL, FIM_PERF_DDL } from '../../utils/fim/fimRegistryDdl';
import { hygieneFindings, historyRowHash, touchesProtected, validateRuleInput, systemActor, isActiveApprover, FIM_PERF_INDEXES } from '../../services/fimRegistryService';

let n = 0;
const t = (name: string, fn: () => void) => { fn(); n++; console.log(`ok - ${name}`); };
// Gated parts (osqueryd, real exported rows) never pass silently: a skip is LOUD and fails the run
// unless FIM_ALLOW_SKIP=1 (CI's FIM job installs osquery and provides the fixtures).
const skips: string[] = [];
const skip = (what: string, why: string) => { skips.push(`${what}: ${why}`); console.log(`SKIPPED - ${what}: ${why}`); };
const L = 'HKEY_LOCAL_MACHINE\\';

const osq = (() => {
  try { execFileSync('osqueryd', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; }
})();
function runOsq(sql: string): any[] {
  // Large statements go through stdin (a single argv string is limited to 128 KiB on Linux).
  if (sql.length > 100_000) {
    const r = spawnSync('osqueryd', ['-S', '--json'], { input: `${sql};\n`, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
    const out = r.stdout ?? '';
    return JSON.parse(out.slice(out.indexOf('['), out.lastIndexOf(']') + 1));
  }
  const out = execFileSync('osqueryd', ['-S', '--json', sql], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out);
}
const lit = (s: string) => `'${s.replace(/'/g, "''")}'`;
/** CTE stand-in for osquery's Windows `registry` table. */
function regCte(rows: { key: string; path: string; name: string; type: string; data: string }[]): string {
  if (!rows.length) rows = [{ key: 'x', path: 'x', name: 'x', type: 'x', data: '' }];
  return `WITH registry(key, path, name, type, data) AS (VALUES ${rows.map((r) => `(${lit(r.key)},${lit(r.path)},${lit(r.name)},${lit(r.type)},${lit(r.data)})`).join(',')}) `;
}

const PROFILES: RegProfile[] = [
  { id: 1, name: 'Workstation default', tier: 'essential', isDefault: true, scanIntervalSecs: 3600, mode: 'enforce' },
  { id: 2, name: 'Server', tier: 'recommended', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce' },
];
function baseInput(over: Partial<ResolveInput> = {}): ResolveInput {
  return { host: 'H1', ownerGroupId: 'G1', profiles: PROFILES, rules: [], waivers: [], now: 1_000_000, ...over };
}
const rule = (id: number, layer: RegRule['layer'], op: RegRule['op'], target: string, spec: Record<string, any> = {}, waiverId: number | null = null): RegRule =>
  ({ id, layer, scopeValue: layer === 'profile' ? '1' : layer === 'group' ? 'G1' : 'H1', op, target, spec, waiverId });
const waiver = (id: number, over: Partial<RegWaiver> = {}, forRule?: RegRule): RegWaiver => ({
  id, entryKey: 'reg.run.hklm', scopeType: 'node', scopeValue: 'H1', action: 'disable', requestedBy: 'ga@x', approvedBy: 'sa@x', status: 'approved', expiresAt: 2_000_000,
  ruleHash: forRule ? regRuleHash(forRule) : null, ...over,
});
const keys = (r: ReturnType<typeof resolveRegistry>) => r.entries.map((e) => e.entryKey);
const CUSTOM = { path: `${L}SOFTWARE\\Acme\\Agent`, values: ['Path'], severity: 'medium' };
const CK = customEntryKey(CUSTOM.path);

// ---------------------------------------------------------------------------------------------
t('adversarial registry keys are refused (§5.1)', () => {
  const bad = [
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\x' OR 1=1 --", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Run'; SELECT * FROM users; --",
    'HKEY_LOCAL_MACHINE\\%%', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\%%', 'HKEY_LOCAL_MACHINE\\%\\Run', 'HKEY_USERS\\%',
    'HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains', 'hkey_local_machine\\security\\policy', 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_CLASSES_ROOT\\CLSID', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\\\Microsoft',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\a\u0000b', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\\u0001x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\\u202Etxt.exe',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\a\u200Bb', `${L}${'A'.repeat(495)}`, L + Array.from({ length: 32 }, (_, i) => `k${i}`).join('\\'),
    `${L}SOFTWARE\\%\\%\\%\\%`, 'HKEY_USERS\\%\\Volatile Environment', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD',
    'HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa\\Skew1\\x', 'HKEY_LOCAL_MACHINE\\SYSTEM\\%\\Control\\Lsa\\%', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\%Run',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\S-1-5-%', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\*', 'HKEY_LOCAL_MACHINE\\SOFTWARE/x', 'HKEY_LOCAL_MACHINE\\ SOFTWARE',
    'HKLM\\SOFTWARE\\Run', '\\REGISTRY\\A\\{x}\\y', 'HKEY_USERS\\S-1-5-21-1', 'HKEY_LOCAL_MACHINE', 42,
  ];
  for (const k of bad) assert.notStrictEqual(validateRegistryKeyV2(k), null, JSON.stringify(k));
  // 513 characters
  assert.notStrictEqual(validateRegistryKeyV2(L + 'a'.repeat(513 - L.length)), null);
  // '%%' needs the recursive privilege and 3 literals
  assert.strictEqual(validateRegistryKeyV2(`${L}SOFTWARE\\Microsoft\\Windows\\%%`, { allowRecursive: true }), null);
  assert.notStrictEqual(validateRegistryKeyV2(`${L}SOFTWARE\\Microsoft\\Windows\\%%`), null);
  assert.notStrictEqual(validateRegistryKeyV2(`${L}SOFTWARE\\Microsoft\\%%`, { allowRecursive: true }), null);
});

t('good registry keys are accepted', () => {
  for (const k of ['HKEY_USERS\\%\\Environment', `${L}SYSTEM\\CurrentControlSet\\Services\\%`, `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa`,
    'hkey_local_machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKEY_USERS\\.DEFAULT\\Environment', `${L}SOFTWARE\\Foo_Bar\\%\\x`]) {
    assert.strictEqual(validateRegistryKeyV2(k), null, k);
  }
  assert.strictEqual(validateRegistryKeyV2(L + 'a'.repeat(512 - L.length)), null); // exactly 512
});

t('value names: quotes, controls, bidi, 256 chars, 65 values are refused', () => {
  for (const v of ["a'b", 'a\u0001', 'a\u202Eb', 'a'.repeat(256), '', 'x*y']) assert.notStrictEqual(validateValueName(v), null, JSON.stringify(v));
  assert.strictEqual(validateValueName('(Default)'), null);
  assert.strictEqual(validateValueName('Foo\\Bar'), null);
  assert.throws(() => normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\X`, values: Array.from({ length: 65 }, (_, i) => `v${i}`) }), FimValidationError);
  assert.throws(() => normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\X`, values: ["it's"] }), FimValidationError);
  assert.throws(() => normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\X`, excludeKeys: [`${L}SOFTWARE\\Other`] }), /matches no key/);
  assert.throws(() => sqlString("x'y"), FimValidationError);
  assert.throws(() => sqlString('x\u0000'), FimValidationError);
});

t('SQL golden: exact text for representative entries (redaction always on; hive presence for per-user entries)', () => {
  const env = normalizeRegistryEntryV2({ path: 'HKEY_USERS\\%\\Environment', entryKey: 'reg.env.user' });
  const sql = buildRegistryScanSqlV2(env);
  // reg.env.user holds arbitrary data (environment variables): NOT visible by design (spec v3), so it
  // gets the credential-name rules; command entries (Run, IFEO ...) do not (asserted below).
  // Custom entry: mandatory names + secret-like / non-ASCII names, always with the digest marker.
  const cust = buildRegistryScanSqlV2(normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\Acme\\Agent` }));
  const like = FIM_REDACTION_POLICY.secretLike.map((x) => `lower(name) LIKE '%${x}%'`).join(' OR ');
  const red = `CASE WHEN type <> 'subkey' AND (lower(name) IN (${[...new Set(MANDATORY_REDACT_VALUES.map((v) => v.toLowerCase()))].sort().map((v) => `'${v}'`).join(', ')}) OR ((${like} OR name GLOB '*[^ -~]*') AND lower(name) NOT IN (${FIM_REDACT_EXEMPT.map((v) => `'${v}'`).join(', ')}))) THEN 'REDACTED(len=' || length(data) || ',sha256=' || substr(sha256(data), 1, 16) || ')' ELSE data END AS data`;
  assert.ok(cust.includes(red), cust);
  assert.strictEqual(sql,
    `SELECT path, name, type, ${red} FROM registry WHERE key LIKE 'HKEY_USERS\\%\\Environment' AND key NOT LIKE 'HKEY_USERS\\S-1-5-18\\%' ` +
    "UNION ALL SELECT path || '\\<anchor:reg.env.user>' AS path, name, 'anchor' AS type, '' AS data FROM registry WHERE key LIKE 'HKEY_USERS\\%' AND type = 'subkey' AND lower(name) = 'environment' AND path NOT LIKE 'HKEY_USERS\\S-1-5-18\\%' " +
    "UNION ALL SELECT 'HKEY_USERS\\' || name || '\\<hive>' AS path, name, 'hive' AS type, '' AS data FROM registry WHERE key LIKE 'HKEY_USERS' AND type = 'subkey' AND name NOT LIKE 'S-1-5-18' AND name NOT LIKE '%^_Classes' ESCAPE '^'");
  const svc = normalizeRegistryEntryV2({ path: `${L}SYSTEM\\CurrentControlSet\\Services\\%`, values: ['ImagePath', '(Default)'], excludeKeys: [`${L}SYSTEM\\CurrentControlSet\\Services\\Foo_Svc`], entryKey: 'reg.svc.image' });
  const s2 = buildRegistryScanSqlV2(svc);
  assert.ok(s2.includes("key NOT LIKE 'HKEY^_LOCAL^_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Foo^_Svc' ESCAPE '^'"), s2);
  assert.ok(s2.includes("(lower(name) IN ('imagepath', '(default)'))"), s2);
  assert.ok(!s2.includes('<hive>'), 'no hive rows for machine entries');
  const wl = normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`, values: ['Shell', 'DefaultPassword'], redactValues: ['Shell2'], ignoreValues: ['LastUsedUsername'] });
  const s3 = buildRegistryScanSqlV2(wl);
  assert.ok(s3.includes("'shell2'") && s3.includes("lower(name) NOT IN ('lastusedusername')"));
  assert.throws(() => assertRegistrySqlShape("SELECT path, name, type, data FROM registry WHERE key LIKE 'x'; DROP TABLE x"), FimValidationError);
  assert.throws(() => buildScanSql({ kind: 'registry', path: `${L}SOFTWARE\\X`, retired: true } as never, 'windows'), FimValidationError);
});

t('golden SQL file: every catalog entry (as resolved in each tier) produces exactly the reviewed SQL', () => {
  const file = join(__dirname, '../fixtures/fim_registry_golden_sql.json');
  const now: Record<string, string> = {};
  for (const c of REG_CATALOG) {
    now[c.id] = buildRegistryScanSqlV2(normalizeRegistryEntryV2({ path: c.path, values: c.values, ignoreValues: c.ignoreValues, redactValues: c.redactValues, entryKey: c.id }, { allowRecursive: c.allowRecursive, maxWildcards: c.maxWildcards }));
  }
  if (process.env.FIM_UPDATE_GOLDEN === '1' || !existsSync(file)) {
    writeFileSync(file, `${JSON.stringify(now, null, 1)}\n`);
    console.log(`   golden file ${process.env.FIM_UPDATE_GOLDEN === '1' ? 'updated' : 'created'}: ${file}`);
  }
  const golden = JSON.parse(readFileSync(file, 'utf8'));
  assert.deepStrictEqual(Object.keys(golden).sort(), Object.keys(now).sort(), 'catalog ids changed: review and regenerate with FIM_UPDATE_GOLDEN=1');
  for (const id of Object.keys(now)) assert.strictEqual(now[id], golden[id], `SQL of ${id} changed: review the diff and regenerate with FIM_UPDATE_GOLDEN=1`);
});

t('every catalog entry validates, has a unique id and builds shaped SQL', () => {
  const ids = new Set<string>();
  for (const c of REG_CATALOG) {
    assert.ok(!ids.has(c.id), c.id); ids.add(c.id);
    assert.ok(/^reg\.[a-z0-9][a-z0-9._-]*$/.test(c.id), c.id);
    const v2 = normalizeRegistryEntryV2({ path: c.path, values: c.values, ignoreValues: c.ignoreValues, redactValues: c.redactValues, entryKey: c.id }, { allowRecursive: c.allowRecursive, maxWildcards: c.maxWildcards });
    assert.strictEqual(v2.path, c.path, `${c.id} not canonical`);
    assertRegistrySqlShape(buildRegistryScanSqlV2(v2));
    assert.ok(c.est.bytes <= FIM_REG_CAPS.entryBytesBlock, c.id);
    if (c.tier === 'essential') assert.ok(c.protected, `${c.id} must be protected`);
  }
  assert.ok(regTierEntries('essential').length >= 40, 'essential has the ~40 design entries');
  assert.ok(getRegCatalogEntry('reg.self.osqueryd')?.protected);
});

t('template v2: allow-lists, realtime, anchors, catalog-backed, no LsaPid / S-1-5-18', () => {
  const tpl = FIM_TEMPLATES.find((x) => x.id === 'windows-registry-persistence')!;
  assert.strictEqual(tpl.version, 2);
  assert.strictEqual(tpl.realtime, true);
  const paths = normalizePaths(tpl.paths, 'windows', { superAdmin: true });
  const lsa = paths.find((p) => p.entryKey === 'reg.lsa')!;
  assert.ok(lsa.values!.length > 0 && !lsa.values!.some((v) => v.toLowerCase() === 'lsapid'));
  for (const p of paths) {
    const sql = buildScanSql(p, 'windows');
    if (p.path!.startsWith('HKEY_USERS')) assert.ok(sql.includes("NOT LIKE 'HKEY_USERS\\S-1-5-18\\%'"));
    assert.ok(sql.includes('<anchor:'));
  }
  assert.ok(!paths.some((p) => /\\Services\\%$/.test(p.path!)));
  // v1 -> v2 is a rev bump
  assert.ok(pathsChanged([{ kind: 'registry', path: `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa`, severity: 'critical', category: 'auth', ignore: [], hash: false }], [lsa]));
});

t('buildFimConfig skips tombstones but keeps indices', () => {
  const live = policyEntryJson({ ...resolveRegistry(baseInput()).entries[0] });
  const cfg = buildFimConfig({ id: 7, rev: 3, osPlatform: 'windows', scanIntervalSecs: 3600, realtime: true,
    paths: [live as never, { kind: 'registry', path: '', retired: true } as never, live as never] });
  assert.deepStrictEqual(Object.keys(cfg.schedule as object).sort(), ['fim_scan_7_3_0', 'fim_scan_7_3_2']);
});

t('pattern intersection and exclusion containment', () => {
  assert.ok(keysIntersect(`${L}S\\Services\\%`, `${L}S\\Services\\WinDefend`));
  assert.ok(!keysIntersect(`${L}S\\Services\\%`, `${L}S\\Services\\%\\Parameters`));
  assert.ok(keysIntersect('HKEY_USERS\\%\\Environment', 'HKEY_USERS\\S-1-5-21-1\\Environment'));
  assert.ok(keysIntersect(`${L}A\\B\\C\\%%`, `${L}A\\B\\C\\D\\E`));
  assert.ok(exclusionInside(`${L}S\\Services\\%`, `${L}S\\Services\\Foo`));
  assert.ok(exclusionInside('HKEY_USERS\\%\\X\\Y', 'HKEY_USERS\\S-1-5-18\\%'));
  assert.ok(!exclusionInside(`${L}S\\Services\\%`, `${L}S\\Other`));
  assert.ok(likeMatch('HKEY_USERS\\S-1-5-18\\%', 'hkey_users\\s-1-5-18\\a\\b'));
  assert.ok(!likeMatch('Foo_Svc', 'FooXSvc'));
});

t('osqueryd executes the generated SQL with the intended semantics (CTE stand-in)', () => {
  if (!osq) { skip('osqueryd semantics', 'osqueryd not installed'); return; }
  const e = normalizeRegistryEntryV2({ path: 'HKEY_USERS\\%\\SOFTWARE\\Run', values: ['Shell', 'OneDrive'], ignoreValues: ['LsaPid'], excludeKeys: ['HKEY_USERS\\S-1-5-21-9_x\\%'], entryKey: 'reg.run.hku' });
  const rows = runOsq(regCte([
    { key: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run', path: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run\\OneDrive', name: 'OneDrive', type: 'REG_SZ', data: 'od' },
    { key: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run', path: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run\\Other', name: 'Other', type: 'REG_SZ', data: 'x' },
    { key: 'HKEY_USERS\\S-1-5-18\\SOFTWARE\\Run', path: 'HKEY_USERS\\S-1-5-18\\SOFTWARE\\Run\\OneDrive', name: 'OneDrive', type: 'REG_SZ', data: 'dup' },
    { key: 'HKEY_USERS\\S-1-5-21-9_x\\SOFTWARE\\Run', path: 'HKEY_USERS\\S-1-5-21-9_x\\SOFTWARE\\Run\\Shell', name: 'Shell', type: 'REG_SZ', data: 'excluded' },
    { key: 'HKEY_USERS\\S-1-5-21-9Xx\\SOFTWARE\\Run', path: 'HKEY_USERS\\S-1-5-21-9Xx\\SOFTWARE\\Run\\Shell', name: 'SHELL', type: 'REG_SZ', data: 'kept' },
    { key: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE', path: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run', name: 'Run', type: 'subkey', data: '' },
    { key: 'HKEY_USERS\\S-1-5-18\\SOFTWARE', path: 'HKEY_USERS\\S-1-5-18\\SOFTWARE\\Run', name: 'Run', type: 'subkey', data: '' },
    { key: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE', path: 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\RunNotification', name: 'RunNotification', type: 'subkey', data: '' },
  ]) + buildRegistryScanSqlV2(e));
  assert.deepStrictEqual(rows.map((r) => r.data).sort(), ['', 'kept', 'od']);
  assert.ok(rows.some((r) => r.type === 'anchor' && r.path === 'HKEY_USERS\\S-1-5-21-1\\SOFTWARE\\Run\\<anchor:reg.run.hku>'));
  // redaction happens in SQL (on the host)
  const w = normalizeRegistryEntryV2({ path: `${L}W`, values: ['DefaultPassword'], redactValues: ['DefaultPassword'], anchor: false });
  const r2 = runOsq(regCte([{ key: `${L}W`, path: `${L}W\\DefaultPassword`, name: 'DefaultPassword', type: 'REG_SZ', data: 'hunter2' }]) + buildRegistryScanSqlV2(w));
  assert.strictEqual(r2[0].data, 'REDACTED(len=7,sha256=f52fbd32b2b3b86f)');
  // count-only Measure query parses and returns only two numbers
  const m = runOsq(regCte([{ key: `${L}W`, path: `${L}W\\A`, name: 'A', type: 'REG_SZ', data: 'xyz' }]) +
    `SELECT count(*) AS rows, COALESCE(sum(length(path) + length(name) + length(type) + length(data) + 48), 0) AS bytes FROM (${buildRegistryScanSqlV2(normalizeRegistryEntryV2({ path: `${L}W`, entryKey: 'reg.w' }))})`);
  assert.deepStrictEqual(Object.keys(m[0]).sort(), ['bytes', 'rows']);
});

t('property: 10,000 random strings are refused or yield parseable SQL containing the literal once', () => {
  let seed = 1234567;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const alphabet = ["'", '\\', '%', '_', '^', ' ', '\u0000', '\u0001', '\u202E', '\u200B', '\u00AD', '\u180E', '\uFEFF', '\u2028', '\uD800', '\uDC00', '\u017F', '\u212A', 'é', 'Ä', '漢', ';', '-', '"', '*', '/', 'A', 'z', '0', '(', ')', 'S', 'M'];
  const roots = [`${L}SOFTWARE\\`, `${L}`, `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\`, 'HKEY_USERS\\%\\', `${L}SYSTEM\\%\\Control\\`];
  const denied = (x: string) => /^HKEY_LOCAL_MACHINE\\(SAM|SECURITY)(\\|$)/i.test(x) || /\\Lsa\\(Data|JD|Skew1|GBG)(\\|$)/i.test(x) || /^HKEY_USERS\\[^\\]+\\Volatile Environment/i.test(x);
  const accepted: { s: string; sql: string }[] = [];
  for (let i = 0; i < 10000; i++) {
    const len = 1 + Math.floor(rnd() * 12);
    let tail = '';
    // full Unicode: random BMP code points (incl. surrogates/format chars) plus astral ones
    for (let j = 0; j < len; j++) {
      const r = rnd();
      tail += r < 0.4 ? String.fromCharCode(0x20 + Math.floor(rnd() * 0x5f)) : r < 0.6 ? String.fromCharCode(Math.floor(rnd() * 0x10000)) : r < 0.65 ? String.fromCodePoint(0x10000 + Math.floor(rnd() * 0xFFFFF)) : alphabet[Math.floor(rnd() * alphabet.length)];
    }
    if (rnd() < 0.2) tail = ['SAM', 'sam', 'S_M', 'SECURITY', 'JD', 'Skew1', 'Volatile Environment'][Math.floor(rnd() * 7)] + (rnd() < 0.5 ? '' : `\\${tail}`);
    const s = roots[Math.floor(rnd() * roots.length)] + tail;
    if (validateRegistryKeyV2(s) !== null) continue;
    assert.ok(/^[\x20-\x7e]*$/.test(s), `non-ASCII accepted: ${JSON.stringify(s)}`);
    assert.ok(!denied(s) && !/^HKEY_LOCAL_MACHINE\\(S_M|SA_|_AM|S__|SECURIT_)(\\|$)/i.test(s), `deny-listed key accepted: ${JSON.stringify(s)}`);
    const sql = buildRegistryScanSqlV2(normalizeRegistryEntryV2({ path: s, anchor: false }));
    const quoted = `'${s}'`;
    assert.strictEqual(sql.split(quoted).length - 1, 1, s);
    assert.ok(!s.includes("'"));
    accepted.push({ s, sql });
  }
  assert.ok(accepted.length > 500, `only ${accepted.length} accepted`);
  if (!osq) { skip('property test SQL parse', 'osqueryd not installed'); return; }
  for (let i = 0; i < accepted.length; i += 400) {
    const batch = accepted.slice(i, i + 400);
    const union = batch.map((a) => `SELECT count(*) AS c FROM (${a.sql})`).join(' UNION ALL ');
    const rows = runOsq(regCte([]) + union);
    assert.ok(Array.isArray(rows) && rows.length >= 1, 'osqueryd parsed the batch');
  }
  console.log(`   ${accepted.length} accepted strings parsed by osqueryd`);
});

// ---------------------------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------------------------
t('resolver: tiers resolve cleanly; Essential within the ~400 KB budget', () => {
  for (const tier of ['essential', 'recommended', 'comprehensive'] as const) {
    const r = resolveRegistry(baseInput({ tierOverride: tier }));
    assert.ok(r.ok, `${tier}: ${r.errors.join('; ')}`);
  }
  const ess = resolveRegistry(baseInput());
  assert.ok(ess.totals.bytes <= 400 * 1024, `essential ${ess.totals.bytes} B`);
  // carve-out: the self-protection key is excluded from Services\% and absorbs its value filter
  const svc = ess.entries.find((e) => e.entryKey === 'reg.svc.image')!;
  assert.ok(svc.excludeKeys.some((x) => x.endsWith('\\Services\\osqueryd')));
  const self = ess.entries.find((e) => e.entryKey === 'reg.self.osqueryd')!;
  assert.ok(self.values.includes('ServiceDll') && self.protected);
  // Recommended merges the identical Services\% pattern (ObjectName)
  const rec = resolveRegistry(baseInput({ tierOverride: 'recommended' }));
  assert.ok(rec.entries.find((e) => e.entryKey === 'reg.svc.image')!.values.includes('ObjectName'));
  assert.ok(!keys(rec).includes('reg.svc.objectname'));
});

t('resolver determinism: 1,000 permutations of the rule set give identical output and hash', () => {
  const rules = [
    rule(1, 'profile', 'add', 'reg.activesetup'), rule(2, 'group', 'severity', 'reg.activesetup', { severity: 'critical' }),
    rule(3, 'node', 'exclude', 'reg.activesetup', { ignoreValues: ['Version'] }), rule(4, 'group', 'add', 'custom', {}),
    rule(5, 'node', 'add', CK, CUSTOM), rule(6, 'group', 'exclude', '*', { excludeKeys: [`${L}SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{x}`] }),
    rule(7, 'node', 'filter', 'reg.activesetup', { values: ['StubPath', 'Version'] }), rule(8, 'profile', 'disable', 'reg.netsh'),
  ].filter((r) => r.target !== 'custom');
  const ref = resolveRegistry(baseInput({ rules }));
  const refJson = canonicalJson(ref);
  let seed = 42;
  const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
  for (let i = 0; i < 1000; i++) {
    const p = [...rules].sort(() => rnd() - 0.5);
    const r = resolveRegistry(baseInput({ rules: p }));
    assert.strictEqual(r.hash, ref.hash);
    if (i % 100 === 0) assert.strictEqual(canonicalJson(r), refJson);
  }
  // removing a layer's rules gives exactly the lower layers' result
  const noNode = resolveRegistry(baseInput({ rules: rules.filter((r) => r.layer !== 'node') }));
  const viaSkip = resolveRegistry(baseInput({ rules, skipNodeLayer: true, host: 'ignored' }));
  assert.strictEqual(noNode.hash, viaSkip.hash);
});

t('precedence: node add beats group disable; group severity beats profile; exclusions unite; specific filter wins', () => {
  const r = resolveRegistry(baseInput({
    rules: [
      rule(1, 'group', 'disable', 'reg.activesetup'), rule(2, 'node', 'add', 'reg.activesetup'),
      rule(3, 'profile', 'add', 'reg.netsh'), rule(4, 'profile', 'severity', 'reg.netsh', { severity: 'low' }), rule(5, 'group', 'severity', 'reg.netsh', { severity: 'critical' }),
      rule(6, 'profile', 'add', 'reg.rdp'), rule(7, 'group', 'exclude', 'reg.rdp', { ignoreValues: ['AllowRemoteRPC'] }), rule(8, 'node', 'exclude', 'reg.rdp', { ignoreValues: ['fSingleSessionPerUser'] }),
      rule(9, 'profile', 'add', 'reg.rdp.tcp'), rule(10, 'group', 'filter', 'reg.rdp.tcp', { values: ['PortNumber'] }), rule(11, 'node', 'filter', 'reg.rdp.tcp', { values: ['PortNumber', 'UserAuthentication'] }),
    ],
  }));
  assert.ok(r.ok, r.errors.join(';'));
  assert.ok(keys(r).includes('reg.activesetup'));
  assert.strictEqual(r.entries.find((e) => e.entryKey === 'reg.netsh')!.severity, 'critical');
  assert.deepStrictEqual(r.entries.find((e) => e.entryKey === 'reg.rdp')!.ignoreValues, ['AllowRemoteRPC', 'fSingleSessionPerUser']);
  assert.deepStrictEqual(r.entries.find((e) => e.entryKey === 'reg.rdp.tcp')!.values, ['PortNumber', 'UserAuthentication']);
  assert.ok(r.entries.find((e) => e.entryKey === 'reg.activesetup')!.sources.some((s) => s.layer === 'node'));
});

t('protected entries: no waiver / pending / rejected / expired / self-approved / wrong scope -> blocked; valid -> applied; expiry restores', () => {
  const dis = (w: number | null) => rule(1, 'node', 'disable', 'reg.run.hklm', {}, w);
  const W = (id: number, over: Partial<RegWaiver> = {}) => waiver(id, over, dis(id));
  const blockedWith = (wv: RegWaiver[] | [], wid: number | null) => {
    const r = resolveRegistry(baseInput({ rules: [dis(wid)], waivers: wv as RegWaiver[] }));
    return { kept: keys(r).includes('reg.run.hklm'), blocked: r.blocked.length };
  };
  assert.deepStrictEqual(blockedWith([], null), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { status: 'pending', approvedBy: null })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { status: 'rejected' })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { expiresAt: 999_999 })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { approvedBy: 'GA@x' })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { scopeType: 'group', scopeValue: 'G1' })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { entryKey: 'reg.lsa' })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { action: 'narrow' })], 9), { kept: true, blocked: 1 });
  assert.deepStrictEqual(blockedWith([W(9, { ruleHash: null })], 9), { kept: true, blocked: 1 }, 'unbound waiver never counts');
  assert.deepStrictEqual(blockedWith([W(9)], 9), { kept: false, blocked: 0 });
  // expiry exactly at `now` restores coverage
  assert.deepStrictEqual(blockedWith([W(9, { expiresAt: 1_000_000 })], 9), { kept: true, blocked: 1 });
  // narrowing filter, intersecting exclusion, lowering severity on a protected entry
  const lsaVals = getRegCatalogEntry('reg.lsa')!.values;
  for (const r of [
    rule(2, 'group', 'filter', 'reg.lsa', { values: ['RunAsPPL'] }), rule(3, 'group', 'exclude', 'reg.lsa', { ignoreValues: ['RunAsPPL'] }),
    rule(4, 'group', 'severity', 'reg.lsa', { severity: 'low' }), rule(5, 'group', 'exclude', '*', { excludeKeys: [`${L}SYSTEM\\CurrentControlSet\\Services\\WinDefend`] }),
  ]) {
    const res = resolveRegistry(baseInput({ rules: [r] }));
    assert.strictEqual(res.blocked.length >= 1, true, `rule ${r.id} must be blocked`);
    const lsa = res.entries.find((e) => e.entryKey === 'reg.lsa')!;
    assert.deepStrictEqual(lsa.values, [...lsaVals].sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1)));
    assert.strictEqual(lsa.severity, 'critical');
    assert.deepStrictEqual(lsa.ignoreValues, []);
  }
  // widening a protected allow-list and raising severity are free
  const wide = resolveRegistry(baseInput({ rules: [rule(6, 'node', 'filter', 'reg.lsa', { values: [...lsaVals, 'Extra'] }), rule(7, 'node', 'severity', 'reg.knowndlls', { severity: 'critical' })] }));
  assert.strictEqual(wide.blocked.length, 0);
  // a non-protected duplicate entry can never narrow a protected one through merging
  const dupe = resolveRegistry(baseInput({ rules: [rule(8, 'node', 'add', customEntryKey(`${L}SYSTEM\\CurrentControlSet\\Control\\Lsa`), { path: `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa`, ignoreValues: ['RunAsPPL'], severity: 'low' })] }));
  const merged = dupe.entries.find((e) => e.path.endsWith('\\Control\\Lsa'))!;
  // (A-MED3) the protected definition is kept exactly: a custom duplicate neither narrows nor widens it
  assert.ok(merged.protected && merged.severity === 'critical' && merged.ignoreValues.length === 0 && merged.values.length === lsaVals.length);
});

t('overlap: two wildcard patterns that can return the same rows -> error; nothing is published', () => {
  const a = { path: `${L}SOFTWARE\\Acme\\%\\Cfg`, severity: 'high' };
  const b = { path: `${L}SOFTWARE\\Acme\\Prod\\%`, severity: 'high' };
  const r = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', customEntryKey(a.path), a), rule(2, 'node', 'add', customEntryKey(b.path), b)] }));
  assert.ok(!r.ok && r.errors.some((e) => e.startsWith('overlap')), r.errors.join(';'));
  // disjoint value filters on overlapping keys are fine; two exact keys never overlap
  const c = { path: `${L}SOFTWARE\\Acme\\%\\Cfg`, values: ['A'], severity: 'high' };
  const d = { path: `${L}SOFTWARE\\Acme\\Prod\\%`, values: ['B'], severity: 'high' };
  assert.ok(resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', customEntryKey(c.path), c), rule(2, 'node', 'add', customEntryKey(d.path), d)] })).ok);
});

t('caps: entries, per-entry size and total rows', () => {
  const many = Array.from({ length: 100 }, (_, i) => rule(100 + i, 'node', 'add', customEntryKey(`${L}SOFTWARE\\Acme\\K${i}`), { path: `${L}SOFTWARE\\Acme\\K${i}`, severity: 'low' }));
  const r1 = resolveRegistry(baseInput({ rules: many }));
  assert.ok(!r1.ok && r1.errors.some((e) => e.includes('entries per node')));
  const big = { path: `${L}SOFTWARE\\Big`, severity: 'low' };
  const fp = (s: object) => entryFingerprint(normalizeRegistryEntryV2({ ...s, entryKey: customEntryKey(big.path) }));
  const r2 = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', customEntryKey(big.path), big)], measured: new Map([[fp(big), { rows: 100, bytes: 800 * 1024 }]]) }));
  assert.ok(!r2.ok && r2.errors.some((e) => e.includes('KiB')));
  const r3 = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', customEntryKey(big.path), big)], measured: new Map([[fp(big), { rows: 25001, bytes: 1000 }]]) }));
  assert.ok(!r3.ok && r3.errors.some((e) => e.includes('rows')));
  // unmeasured custom entries warn (rule creation requires a measurement)
  assert.ok(resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', CK, CUSTOM)] })).warnings.some((w) => w.includes('not been measured')));
});

t('slots: stable across unrelated edits, new slot on fingerprint change, revival within 7 days, severity-only keeps slot and rev', () => {
  const r0 = resolveRegistry(baseInput());
  const p0 = allocateSlots([], r0.entries, 1000);
  assert.strictEqual(p0.needsInit.length, r0.entries.length);
  assert.deepStrictEqual(p0.needsInit, [...p0.needsInit].sort((a, b) => a - b));
  // unrelated edit: add an entry -> every old slot kept, one new slot at the end
  const r1 = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', 'reg.netsh')] }));
  const p1 = allocateSlots(p0.slots, r1.entries, 2000);
  assert.strictEqual(p1.needsInit.length, 1);
  assert.strictEqual(p1.kept.length, r0.entries.length);
  assert.strictEqual(p1.needsInit[0], p0.slots.length);
  // fingerprint change -> old slot retired, new slot; never reused
  const r2 = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', 'reg.netsh'), rule(2, 'node', 'exclude', 'reg.netsh', { ignoreValues: ['x'] })] }));
  const p2 = allocateSlots(p1.slots, r2.entries, 3000);
  assert.strictEqual(p2.retired.length, 1);
  assert.strictEqual(p2.needsInit[0], p1.slots.length);
  assert.ok(p2.paths[p2.retired[0]].retired === true);
  // revert within 7 days -> the retired identical slot is revived (no init)
  const p3 = allocateSlots(p2.slots, r1.entries, 4000);
  assert.deepStrictEqual(p3.revived, [p1.needsInit[0]]);
  assert.strictEqual(p3.needsInit.length, 0);
  // after the window -> new slot
  const p4 = allocateSlots(p2.slots, r1.entries, 3000 + 8 * 86400);
  assert.strictEqual(p4.revived.length, 0);
  assert.strictEqual(p4.needsInit.length, 1);
  // severity-only change: same slots, no rev bump (pathsChanged ignores severity)
  const r5 = resolveRegistry(baseInput({ rules: [rule(1, 'node', 'add', 'reg.netsh'), rule(3, 'node', 'severity', 'reg.netsh', { severity: 'critical' })] }));
  const p5 = allocateSlots(p1.slots, r5.entries, 5000);
  assert.strictEqual(p5.needsInit.length + p5.retired.length, 0);
  assert.ok(!pathsChanged(p1.paths as never, p5.paths as never));
  assert.notStrictEqual(r5.hash, r1.hash, 'severity changes still need a publish');
  // preview diff classification
  const pub = p1.paths.map((p: any, i) => ({ entryKey: p.entryKey, fingerprint: p.fingerprint, path: p.path, severity: p.severity, category: p.category, label: p.label, slot: i })).filter((x) => x.entryKey);
  const d = diffCoverage(pub, r5.entries);
  assert.deepStrictEqual(d.severityOnly.map((e) => e.entryKey), ['reg.netsh']);
  const d2 = diffCoverage(pub, r2.entries);
  assert.deepStrictEqual(d2.changed.map((e) => e.entryKey), ['reg.netsh']);
});

t('rule input validation + protected detection (server side)', () => {
  const sa = systemActor();
  const ga = { ...sa, superAdmin: false, email: 'ga@x' };
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'add', target: 'custom', spec: { path: `${L}SOFTWARE\\A\\B\\C\\%%` } }, ga), /Super Administrator/);
  assert.ok(validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'add', target: 'custom', spec: { path: `${L}SOFTWARE\\A\\B\\C\\%%` } }, sa).target.startsWith('custom:'));
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'disable', target: '*' }, sa), FimValidationError);
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'exclude', target: '*', spec: { ignoreValues: ['x'] } }, sa), FimValidationError);
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'exclude', target: 'reg.lsa', spec: { excludeKeys: [`${L}SOFTWARE\\Elsewhere`] } }, sa), /matches no key/);
  assert.throws(() => validateRuleInput({ layer: 'evil', scopeValue: 'H1', op: 'add', target: 'reg.lsa' }, sa), FimValidationError);
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'add', target: "reg.x'; drop" }, sa), FimValidationError);
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'add', target: 'custom', spec: { path: `${L}SOFTWARE\\X`, measureOverride: true } }, ga), /Super Administrator/);
  assert.strictEqual(touchesProtected({ op: 'severity', target: 'reg.lsa', spec: { severity: 'critical' } }).length, 0);
  assert.strictEqual(touchesProtected({ op: 'severity', target: 'reg.lsa', spec: { severity: 'high' } }).length, 1);
  // R12-1: widening a protected entry (all values) also changes its fingerprint (re-slot): waiver needed
  assert.strictEqual(touchesProtected({ op: 'filter', target: 'reg.lsa', spec: { values: [] } }).length, 1);
  assert.strictEqual(touchesProtected({ op: 'filter', target: 'reg.lsa', spec: { values: ['RunAsPPL'] } }).length, 1);
  assert.strictEqual(touchesProtected({ op: 'disable', target: 'reg.netsh', spec: {} }).length, 0);
  assert.ok(touchesProtected({ op: 'exclude', target: '*', spec: { excludeKeys: [`${L}SYSTEM\\CurrentControlSet\\Services\\%`] } }).length > 1);
});

t('history hash chain: any field change breaks the row hash', () => {
  const row = { at: 1, actor: 'sa@x', reason: 'r', scope_type: 'node', scope_value: 'H1', snapshot: { rules: [{ id: 1, op: 'disable', target: 'reg.netsh' }] } };
  const h1 = historyRowHash(null, row);
  const h2 = historyRowHash(h1, { ...row, at: 2 });
  assert.notStrictEqual(historyRowHash(null, { ...row, actor: 'evil' }), h1);
  assert.notStrictEqual(historyRowHash(null, { ...row, snapshot: { rules: [] } }), h1);
  assert.notStrictEqual(historyRowHash('x', { ...row, at: 2 }), h2);
  assert.strictEqual(historyRowHash(null, JSON.parse(JSON.stringify(row))), h1, 'key order does not matter');
});

t('baseline hygiene heuristics', () => {
  const f = hygieneFindings([
    { path: `registry|${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd`, sha256: 'a', data: { type: 'REG_SZ', data: 'C:\\Users\\bob\\AppData\\Local\\upd.exe' } },
    { path: `registry|${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Defender`, sha256: 'b', data: { type: 'REG_SZ', data: 'C:\\ProgramData\\Microsoft\\Windows Defender\\x.exe' } },
    { path: `registry|${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger`, sha256: 'c', data: { type: 'REG_SZ', data: 'cmd.exe' } },
    { path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages`, sha256: 'd', data: { type: 'REG_MULTI_SZ', data: 'kerberos,msv1_0,evilssp' } },
    { path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages`, sha256: 'e', data: { type: 'REG_MULTI_SZ', data: 'scecli' } },
    { path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential`, sha256: 'f', data: { type: 'REG_DWORD', data: '1' } },
    { path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\MiniNt`, sha256: 'g', data: { type: 'subkey', data: '' } },
    { path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\<anchor:reg.lsa>`, sha256: 'h', data: { type: 'anchor', data: '' } },
  ]);
  const rules = f.map((x) => x.rule).sort();
  assert.deepStrictEqual(rules, ['autostart-user-writable', 'ifeo-debugger', 'lsa-packages', 'minint', 'wdigest-cleartext']);
});

t('DDL module is identical to the backend migration mirror', () => {
  const mirror = readFileSync(join(__dirname, '../../../migrations/031_add_fim_registry.sql'), 'utf8');
  const strip = (s: string) => s.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n').replace(/\s+/g, ' ').trim();
  assert.strictEqual(strip(mirror), strip(FIM_REGISTRY_DDL));
  assert.strictEqual(strip(readFileSync(join(__dirname, '../../../migrations/032_add_fim_verify.sql'), 'utf8')), strip(FIM_VERIFY_DDL));
  assert.strictEqual(strip(readFileSync(join(__dirname, '../../../migrations/033_add_fim_worker_schema.sql'), 'utf8')), strip(FIM_WORKER_DDL));
  assert.strictEqual(strip(readFileSync(join(__dirname, '../../../migrations/034_add_fim_perf.sql'), 'utf8')), strip(FIM_PERF_DDL));
  // the background-built perf indexes are exactly the 0008a statements
  const perfSql = readFileSync(join(__dirname, '../../../migrations/034a_add_fim_perf_indexes.sql'), 'utf8');
  for (const ix of FIM_PERF_INDEXES) assert.ok(perfSql.includes(`${ix.ddl};`), ix.ddl);
});

t('replay of real exported Windows rows through the v2 SQL in osqueryd (committed sample, or FIM_REG_LIVEDATA)', () => {
  // Default: a small SANITIZED subset of a real Windows 11 export committed under
  // src/test/fixtures/fim_registry_live_sample (SIDs, user, domain and host names, IPs replaced;
  // key names, value names, types and data shapes kept; Services limited to stock services).
  // FIM_REG_LIVEDATA=<dir> replays a full private export instead (not committed).
  const full = !!process.env.FIM_REG_LIVEDATA;
  const dir = process.env.FIM_REG_LIVEDATA || join(__dirname, '../fixtures/fim_registry_live_sample');
  if (!osq) { skip('replay of real Windows rows', 'osqueryd not installed'); return; }
  if (!existsSync(dir)) { skip('replay of real Windows rows', `${dir} not found`); return; }
  const keyOf = (p: string) => (p.endsWith('\\') ? p.slice(0, -1) : p.slice(0, p.lastIndexOf('\\')));
  const counts: Record<string, number> = {};
  const essential = resolveRegistry(baseInput({ tierOverride: 'recommended' })).entries;
  for (let i = 0; i <= 15; i++) {
    const f = join(dir, `registry_windows-registry-persistence_${i}.json`);
    if (!existsSync(f)) continue;
    const rows = (JSON.parse(readFileSync(f, 'utf8')) as any[]).map((r) => ({ key: keyOf(r.path), path: r.path, name: r.name, type: r.type, data: r.data ?? '' }));
    if (!rows.length) continue;
    for (const e of essential) {
      const k0 = asciiLower(rows[0].key);
      const hit = rows.some((r) => keysIntersect(e.path, r.key)) && (asciiLower(e.path) === k0 || e.path.endsWith('\\%'));
      if (!hit) continue;
      // anchor needs the monitored key's own subkey row (not in the export): add it.
      const parentRows = [...new Set(rows.map((r) => r.key))].map((k) => ({ key: keyOf(k + 'x'), path: k, name: k.slice(k.lastIndexOf('\\') + 1), type: 'subkey', data: '' }));
      const out = runOsq(regCte([...rows, ...parentRows]) + buildRegistryScanSqlV2(e));
      counts[e.entryKey] = out.filter((r) => r.type !== 'anchor').length;
      if (e.entryKey === 'reg.lsa') {
        assert.ok(!out.some((r) => /lsapid$/i.test(r.name)), 'LsaPid filtered');
        assert.ok(!out.some((r) => ['Data', 'JD', 'Skew1', 'GBG'].includes(r.name)), 'boot-key subkeys filtered');
        assert.ok(out.some((r) => r.type === 'anchor'));
      }
      if (e.entryKey === 'reg.winlogon') assert.ok(!out.some((r) => /lastlogoffendtimeperfcounter|shutdownflags/i.test(r.name)));
      if (e.entryKey === 'reg.sessmgr') assert.ok(!out.some((r) => /pendingfilerenameoperations/i.test(r.name)));
      if (e.entryKey === 'reg.run.hku' || e.entryKey === 'reg.env.user') assert.ok(!out.some((r) => r.path.includes('S-1-5-18')));
    }
  }
  console.log(`   filtered value rows per entry: ${JSON.stringify(counts)}`);
  assert.ok(Object.keys(counts).length >= 8);
  if (full) assert.ok((counts['reg.svc.image'] ?? 0) > 500, 'the unfiltered Services export (6,924 rows) is replayed too');
  else assert.ok((counts['reg.svc.image'] ?? 0) >= 20, `Services sample replayed (${counts['reg.svc.image'] ?? 0} rows)`);
});

// =============================================================================================
// Review findings (pure logic): each test fails on the behaviour before the fix
// =============================================================================================
const IFEO = `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`;
const SVCK = `${L}SYSTEM\\CurrentControlSet\\Services`;
const WLK = `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`;
const add = (id: number, spec: any, waiverId: number | null = null): RegRule => ({ id, layer: 'node', scopeValue: 'H1', op: 'add', target: customEntryKey(spec.path), spec, waiverId });
const planted = [
  { key: IFEO, path: `${IFEO}\\sethc.exe`, name: 'sethc.exe', type: 'subkey', data: '' },
  { key: `${IFEO}\\sethc.exe`, path: `${IFEO}\\sethc.exe\\Debugger`, name: 'Debugger', type: 'REG_SZ', data: 'C:\\Windows\\System32\\cmd.exe' },
  { key: SVCK, path: `${SVCK}\\EvilSvc`, name: 'EvilSvc', type: 'subkey', data: '' },
  { key: `${SVCK}\\EvilSvc`, path: `${SVCK}\\EvilSvc\\ImagePath`, name: 'ImagePath', type: 'REG_EXPAND_SZ', data: 'C:\\evil\\implant.exe' },
  { key: `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`, path: WLK, name: 'Winlogon', type: 'subkey', data: '' },
  { key: WLK, path: `${WLK}\\Shell`, name: 'Shell', type: 'REG_SZ', data: 'explorer.exe, C:\\x\\evil.exe' },
];
const attackRules = [
  add(1, { path: `${IFEO}\\sethc.exe`, anchor: false, severity: 'low' }),
  add(2, { path: `${SVCK}\\EvilSvc`, values: ['ImagePath'], redactValues: ['ImagePath'], severity: 'low' }),
  add(3, { path: WLK, values: ['Shell'], redactValues: ['Shell', 'Userinit'], anchor: false, severity: 'low' }),
];

t('H1: a custom key can never carve, redact or blind protected coverage without a waiver (resolver)', () => {
  const r = resolveRegistry(baseInput({ rules: attackRules }));
  const ifeo = r.entries.find((e) => e.entryKey === 'reg.ifeo')!;
  const svc = r.entries.find((e) => e.entryKey === 'reg.svc.image')!;
  const wl = r.entries.find((e) => e.entryKey === 'reg.winlogon')!;
  assert.ok(!ifeo.excludeKeys.some((x) => /sethc/i.test(x)), 'sethc must not be carved out of reg.ifeo');
  assert.ok(!svc.excludeKeys.some((x) => /EvilSvc/i.test(x)), 'EvilSvc must not be carved out of reg.svc.image');
  assert.deepStrictEqual(wl.redactValues, getRegCatalogEntry('reg.winlogon')!.redactValues.slice().sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1)));
  assert.strictEqual(wl.anchor, true);
  assert.ok(!r.entries.some((e) => e.entryKey === customEntryKey(`${IFEO}\\sethc.exe`)), 'carving custom entry is blocked');
  assert.ok(!r.entries.some((e) => e.entryKey === customEntryKey(`${SVCK}\\EvilSvc`)));
  assert.ok(r.blocked.some((b) => b.reason.startsWith('protected coverage:')), JSON.stringify(r.blocked));
  // variant E: self-exclusion through a separate exclude rule on the custom id
  const ex: RegRule = { id: 6, layer: 'node', scopeValue: 'H1', op: 'exclude', target: customEntryKey(`${IFEO}\\utilman.exe`), spec: { excludeKeys: [`${IFEO}\\utilman.exe`] }, waiverId: null };
  const rE = resolveRegistry(baseInput({ rules: [add(5, { path: `${IFEO}\\utilman.exe`, severity: 'low' }), ex] }));
  assert.ok(!rE.entries.find((e) => e.entryKey === 'reg.ifeo')!.excludeKeys.some((x) => /utilman/i.test(x)));
  // variant F: exact HKU SID key under protected reg.run.hku
  const hku = { path: 'HKEY_USERS\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', severity: 'low' };
  const rF = resolveRegistry(baseInput({ rules: [add(7, hku)] }));
  assert.ok(!rF.entries.find((e) => e.entryKey === 'reg.run.hku')!.excludeKeys.length);
  // self-exclusion is refused at validation, and a covering exclusion too
  assert.throws(() => normalizeRegistryEntryV2({ path: `${IFEO}\\sethc.exe`, excludeKeys: [`${IFEO}\\sethc.exe`] }), /own key/);
  assert.throws(() => normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\X\\%`, excludeKeys: [`${L}SOFTWARE\\X\\%`] }), /own key/);
  // touchesProtected: such an add needs a waiver (server refuses the rule without one)
  const v = validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'add', target: 'custom', spec: { path: `${IFEO}\\sethc.exe`, severity: 'low' } }, systemActor());
  assert.deepStrictEqual(touchesProtected(v).map((c) => c.id), ['reg.ifeo']);
});

t('H1: with a waiver bound to that exact add, carving keeps the protected coverage of the key', () => {
  const r1 = add(1, { path: `${IFEO}\\sethc.exe`, values: ['Debugger'], redactValues: ['Debugger'], anchor: false, severity: 'low' }, 9);
  const w = waiver(9, { entryKey: 'reg.ifeo', action: 'narrow' }, r1);
  const r = resolveRegistry(baseInput({ rules: [r1], waivers: [w] }));
  const c = r.entries.find((e) => e.entryKey === r1.target)!;
  assert.ok(c, JSON.stringify(r.blocked));
  assert.ok(c.protected && c.anchor, 'absorbing entry is protected and anchored');
  assert.deepStrictEqual(c.redactValues, [], 'redaction of the absorbing entry is the protected entry\'s (none), not the custom one');
  assert.ok(['debugger', 'globalflag', 'verifierdlls', 'verifierflags'].every((x) => c.values.map((v) => v.toLowerCase()).includes(x)));
});

t('H1 (osqueryd): the REAL generated SQL still returns the planted malicious rows after the attack rules', () => {
  if (!osq) { skip('H1 osqueryd carve-out execution', 'osqueryd not installed'); return; }
  const collect = (rules: RegRule[]) => {
    const r = resolveRegistry(baseInput({ rules }));
    const out: string[] = [];
    for (const e of r.entries) for (const x of runOsq(regCte(planted) + buildRegistryScanSqlV2(e))) if (x.type !== 'anchor' && x.type !== 'subkey') out.push(`${x.path}=${x.data}`);
    return out;
  };
  for (const rows of [collect([]), collect(attackRules)]) {
    assert.ok(rows.some((x) => /sethc\.exe\\Debugger=C:\\Windows\\System32\\cmd\.exe$/.test(x)), rows.join('\n'));
    assert.ok(rows.some((x) => /EvilSvc\\ImagePath=C:\\evil\\implant\.exe$/.test(x)), rows.join('\n'));
    assert.ok(rows.some((x) => /Winlogon\\Shell=explorer\.exe, C:\\x\\evil\.exe$/.test(x)), rows.join('\n'));
  }
});

t('H1b / A-MED3: a custom duplicate of a protected entry changes nothing but severity (redact, anchor, filters, hive scoping)', () => {
  const dupWl = add(3, { path: WLK, values: ['Shell'], redactValues: ['Shell', 'Userinit', 'Taskman', 'AppSetup'], anchor: false, severity: 'critical' });
  const dupRun = add(4, { path: `${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`, redactValues: ['SecurityHealth'], severity: 'low' });
  const base = resolveRegistry(baseInput());
  const r = resolveRegistry(baseInput({ rules: [dupWl, dupRun] }));
  for (const k of ['reg.winlogon', 'reg.run.hklm']) {
    const a = base.entries.find((e) => e.entryKey === k)!, b = r.entries.find((e) => e.entryKey === k)!;
    assert.strictEqual(b.fingerprint, a.fingerprint, `${k}: fingerprint (what is collected) must not change`);
    assert.deepStrictEqual([b.redactValues, b.anchor, b.values, b.excludeKeys, b.hiveScoped], [a.redactValues, a.anchor, a.values, a.excludeKeys, a.hiveScoped]);
  }
  assert.ok(r.warnings.some((w) => w.includes('duplicates protected entry')));
  // hiveScoped is refused outside HKEY_USERS\%\...
  assert.throws(() => normalizeRegistryEntryV2({ path: WLK, hiveScoped: true }), /hiveScoped/);
});

t('M1: credential values are redacted in EVERY registry query; new registry entries are always v2', () => {
  const p = validatePolicyInput({ name: 'p', osPlatform: 'windows', paths: [{ kind: 'registry', path: WLK }], targets: [] });
  assert.ok(p.paths[0].entryKey?.startsWith('custom:') && p.paths[0].anchor === true, 'a new registry entry becomes v2');
  for (const sql of [buildScanSql(p.paths[0], 'windows'), buildScanSql({ kind: 'registry', path: WLK }, 'windows')]) {
    assert.ok(sql.includes("'defaultpassword'") && sql.includes("'altdefaultpassword'"), sql);
  }
  // the secret-like heuristic (with digest) is part of custom v2 entries only, and flagged for the worker
  assert.ok(buildScanSql(p.paths[0], 'windows').includes("LIKE '%password%'") && p.paths[0].redactHeuristic === true);
  assert.ok(buildScanSql({ kind: 'registry', path: WLK }, 'windows').includes("LIKE '%password%'"), 'legacy entries are untrusted too');
  // an already-stored legacy entry stays legacy (its filter is unchanged) but redacted
  const kept = validatePolicyInput({ paths: [{ kind: 'registry', path: WLK }] }, { name: 'p', description: '', osPlatform: 'windows', paths: [{ kind: 'registry', path: WLK, severity: 'high', category: 'registry', ignore: [], hash: false }], scanIntervalSecs: 3600, realtime: true, mode: 'enforce', learnScans: 2, enabled: true, template: null, targets: [] });
  assert.strictEqual(kept.paths[0].entryKey, undefined);
  if (osq) {
    const planted = [{ key: WLK, path: `${WLK}\\DefaultPassword`, name: 'DefaultPassword', type: 'REG_SZ', data: 'hunter2' }, { key: WLK, path: `${WLK}\\VNCPassword`, name: 'VNCPassword', type: 'REG_BINARY', data: 'AABB' }, { key: WLK, path: `${WLK}\\UseLogonCredential`, name: 'UseLogonCredential', type: 'REG_DWORD', data: '1' }];
    const rows = runOsq(regCte(planted) + buildScanSql(p.paths[0], 'windows')).filter((x: any) => x.type !== 'anchor');
    assert.deepStrictEqual(rows.map((x: any) => x.data).sort(), ['1', 'REDACTED(len=4,sha256=2f8ea0f6e95594bb)', 'REDACTED(len=7,sha256=f52fbd32b2b3b86f)']);
    const legacyRows = runOsq(regCte(planted) + buildScanSql({ kind: 'registry', path: WLK }, 'windows'));
    assert.deepStrictEqual(legacyRows.map((x: any) => x.data).sort(), ['1', 'REDACTED(len=4,sha256=2f8ea0f6e95594bb)', 'REDACTED(len=7,sha256=f52fbd32b2b3b86f)'], 'legacy entries are untrusted: mandatory + heuristic, digest marker');
  } else skip('M1 osqueryd redaction', 'osqueryd not installed');
});

t('M2: a waiver backs exactly ONE rule with exactly the approved spec (no reuse, pending never counts)', () => {
  const approved = rule(1, 'node', 'exclude', 'reg.lsa', { ignoreValues: ['LmCompatibilityLevel'] }, 9);
  const reuse = rule(2, 'node', 'filter', 'reg.lsa', { values: ['DoesNotExist'] }, 9);
  const w = waiver(9, { entryKey: 'reg.lsa', action: 'narrow' }, approved);
  const r = resolveRegistry(baseInput({ rules: [approved, reuse], waivers: [w] }));
  const lsa = r.entries.find((e) => e.entryKey === 'reg.lsa')!;
  assert.deepStrictEqual(lsa.ignoreValues, ['LmCompatibilityLevel']);
  assert.ok(!lsa.values.includes('DoesNotExist') && lsa.values.length > 1);
  assert.deepStrictEqual(r.usedWaivers, [9]);
  assert.ok(r.blocked.some((b) => b.ruleId === 2));
  // the approved spec must match: same rule id but a different spec is blocked
  const tampered = rule(1, 'node', 'exclude', 'reg.lsa', { ignoreValues: ['RunAsPPL'] }, 9);
  assert.ok(resolveRegistry(baseInput({ rules: [tampered], waivers: [w] })).blocked.length === 1);
  assert.ok(resolveRegistry(baseInput({ rules: [approved], waivers: [{ ...w, status: 'pending' }] })).blocked.length === 1);
  // dropping all monitored values needs an explicit flag (part of what the approver approves)
  assert.throws(() => validateRuleInput({ layer: 'node', scopeValue: 'H1', op: 'filter', target: 'reg.lsa', spec: { values: ['DoesNotExist'] } }, systemActor()), /dropsAllMonitored/);
});

t('L1 / L2 / L3 / A-LOW9 / Unicode folds: ASCII-only identifiers; deny-list with LIKE semantics', () => {
  const refuse = [
    `${L}\u017FAM\\SAM\\Domains\\Account`, `${L}SOFTWARE\\\uD800`, `${L}SOFTWARE\\a\u00ADb`, `${L}SOFTWARE\\Acme\\\u212Aey`, `${L}SOFTWARE\\\u00C4rger`,
    `${L}S_M`, `${L}SA_`, `${L}_AM\\x`, `${L}SECURIT_\\Policy\\Secrets`, `${L}SYSTEM\\CurrentControlSet\\Control\\Ls_\\JD`, `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\J_`,
    `${L}SAM\u180E`, `${L}SAM\uFFF9`, `${L}SAM${String.fromCodePoint(0xE0041)}`, `${L}SOFTWARE\\a\u0085b`,
  ];
  for (const k of refuse) assert.notStrictEqual(validateRegistryKeyV2(k, { allowRecursive: true }), null, JSON.stringify(k));
  for (const n2 of ['KENNW\u00D6RT', 'Defaultpa\u017Fsword', 'a\uD800']) assert.notStrictEqual(validateValueName(n2), null, n2);
  assert.strictEqual(validateValueName('Path/With/Slash'), null, "'/' is legal in value names");
  assert.notStrictEqual(validateFimPath('/etc/\uD800x', 'linux'), null);
  assert.notStrictEqual(validateFimPath('/etc/a\u200Bb', 'linux'), null);
  assert.ok(isCleanText('/etc/caf\u00E9') && !isCleanText('/etc/\uDC00'));
  // fingerprint follows the generated SQL: exclusion spellings that differ in the SQL differ here
  const P = `${L}SOFTWARE\\Acme\\%`;
  const a = normalizeRegistryEntryV2({ path: P, excludeKeys: [`${L}SOFTWARE\\Acme\\Key`], entryKey: 'custom:0000000000000001' });
  const b = normalizeRegistryEntryV2({ path: P, excludeKeys: [`${L}SOFTWARE\\Acme\\key`], entryKey: 'custom:0000000000000001' });
  assert.notStrictEqual(buildRegistryScanSqlV2(a), buildRegistryScanSqlV2(b));
  assert.notStrictEqual(entryFingerprint(a), entryFingerprint(b));
});

t('design §5.1 deviations (documented): exact keys are carved out only for catalog/protected or waived entries', () => {
  // Services\% vs Services\WinDefend (both catalog): no overlap error, carved (the design's Essential tier needs it)
  const ess = resolveRegistry(baseInput());
  assert.ok(ess.ok);
  // custom exact key under a protected wildcard: blocked (not an overlap error that would freeze the node)
  const r = resolveRegistry(baseInput({ rules: [add(1, { path: 'HKEY_USERS\\S-1-5-21-1\\Environment', severity: 'high' })] }));
  assert.ok(r.ok && r.blocked.some((b) => b.entryKey === 'reg.env.user'));
});

// =============================================================================================
// Review 3
// =============================================================================================
/** Canonical SHA-256 of the shared redaction policy; the worker's unit test pins the SAME value. */
const REDACTION_POLICY_PIN = 'ebcea78992fedb4292324e7bca0b384edf9226814e84b95180ae5e2975530fe6';
t('HIGH-2: redaction policy is shared with the worker (pinned) and never hides catalog-monitored non-secret settings', () => {
  const canon = canonicalJson({ mandatory: FIM_REDACTION_POLICY.mandatory, secretLike: FIM_REDACTION_POLICY.secretLike, exempt: FIM_REDACTION_POLICY.exempt });
  assert.strictEqual(createHash('sha256').update(canon).digest('hex'), REDACTION_POLICY_PIN,
    'fimRedactionPolicy.json changed: copy it byte-for-byte to engine_v2/fim/redaction_policy.json and update the pin in BOTH test suites');
  for (const x of [...FIM_REDACTION_POLICY.mandatory, ...FIM_REDACTION_POLICY.secretLike, ...FIM_REDACTION_POLICY.exempt]) assert.strictEqual(x, asciiLower(x), `${x} must be lower-case`);
  // Catalog entries never apply the name heuristic (spec v2): no catalog-monitored value can be hidden by name.
  const allCat = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }] })).entries.filter((e) => e.entryKey.startsWith('reg.'));
  assert.ok(allCat.length > 50);
  const visibleIds = new Set(REG_CATALOG.filter((c) => catalogVisibleByDesign(c)).map((c) => c.id));
  // The visible-by-design list (commands) is fixed: changing it is a reviewed decision.
  assert.ok(['reg.run.hklm', 'reg.runonce.hklm', 'reg.ifeo', 'reg.svc.image', 'reg.winlogon', 'reg.appinit', 'reg.lsa'].every((id) => visibleIds.has(id)));
  assert.ok(['reg.env.machine', 'reg.env.user', 'reg.rdp', 'reg.rdp.tcp', 'reg.winrm'].every((id) => !visibleIds.has(id)));
  for (const e of allCat) {
    const sql = buildRegistryScanSqlV2(e);
    if (visibleIds.has(e.entryKey)) assert.ok(!sql.includes("LIKE '%password%'") && !sql.includes('GLOB'), `${e.entryKey}: visible-by-design SQL must not redact by heuristic`);
    else assert.ok(sql.includes("LIKE '%password%'") && sql.includes('GLOB'), `${e.entryKey}: data-bearing catalog entry must redact credential-like names`);
  }
  for (const v of ['LimitBlankPasswordUse', 'PasswordExpiryWarning', 'UseLogonCredential', 'DisablePasswordChange', 'MaximumPasswordAge']) assert.ok(!isSecretLikeName(v), v);
  for (const v of ['DefaultPassword', 'VncPassword', 'ClientSecret', 'DbConnectionString', 'MyApiKey']) assert.ok(isSecretLikeName(v), v);
  if (!osq) { skip('HIGH-2 osqueryd LimitBlankPasswordUse', 'osqueryd not installed'); return; }
  const lsa = resolveRegistry(baseInput()).entries.find((e) => e.entryKey === 'reg.lsa')!;
  const LSA = `${L}SYSTEM\\CurrentControlSet\\Control\\Lsa`;
  const run = (v: string) => runOsq(regCte([{ key: LSA, path: `${LSA}\\LimitBlankPasswordUse`, name: 'LimitBlankPasswordUse', type: 'REG_DWORD', data: v }]) + buildRegistryScanSqlV2(lsa))
    .filter((r) => r.type !== 'anchor').map((r) => r.data);
  assert.deepStrictEqual([run('1'), run('0')], [['1'], ['0']], 'a 1 -> 0 change of LimitBlankPasswordUse is visible (was REDACTED(len=1) both times)');
});

t('review 3 LOWs: escaped LSA package lists, waiver hash covers measureOverride, purged tombstones are reused', () => {
  // (4) the worker stores REG_MULTI_SZ separators escaped (<U+0000>, <U+000A>)
  const lsa = (data: string) => hygieneFindings([{ path: `registry|${L}SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages`, sha256: 'x', data: { type: 'REG_MULTI_SZ', data } }]);
  assert.strictEqual(lsa('kerberos<U+0000>msv1_0<U+0000>evilssp').length, 1, 'escaped NUL separators are split');
  assert.ok(lsa('kerberos<U+000A>evilssp')[0].detail.includes('evilssp'));
  assert.strictEqual(lsa('kerberos<U+0000>msv1_0').length, 0, 'no false positive for the defaults');
  // (7) an approved change that skipped measurement is a different change
  const base = { layer: 'node', scopeValue: 'H1', op: 'add', target: 'custom:0123456789abcdef', spec: { path: `${L}SOFTWARE\\X` } };
  assert.notStrictEqual(regRuleHash(base), regRuleHash({ ...base, spec: { ...base.spec, measureOverride: true } }));
  // tombstone reclaim: a purged slot is reused before the list grows (no slot-cap creep from rule flips)
  const e = (k: string): any => ({ ...normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\${k}`, entryKey: customEntryKey(`${L}SOFTWARE\\${k}`) }), fingerprint: `fp-${k}`, severity: 'low', category: 'c', label: k });
  const slots = [
    { slotIdx: 0, entryKey: e('A').entryKey, fingerprint: 'fp-A', createdAt: 1, retiredAt: null, purgeAfter: null, purgedAt: null },
    { slotIdx: 1, entryKey: e('B').entryKey, fingerprint: 'fp-B', createdAt: 1, retiredAt: 5, purgeAfter: 6, purgedAt: 7 },
    { slotIdx: 2, entryKey: e('C').entryKey, fingerprint: 'fp-C', createdAt: 1, retiredAt: 5, purgeAfter: 9e9, purgedAt: null },
  ];
  const plan = allocateSlots(slots, [e('A'), e('D')], 100);
  assert.strictEqual(plan.paths.length, 3, 'no new index');
  assert.strictEqual(plan.entrySlot.get(e('D').entryKey), 1, 'the purged slot 1 is reused (not the retired-but-unpurged slot 2)');
  assert.deepStrictEqual(plan.needsInit, [1]);
});

t('review 3 H: attacker-chosen value names never hide data in catalog entries; custom heuristic redaction detects equal-length changes', () => {
  const run = resolveRegistry(baseInput()).entries.find((e) => e.entryKey === 'reg.run.hklm')!;
  const RUNK = `${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`;
  const cust = normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\Acme\\Agent` });
  if (!osq) { skip('review 3 H osqueryd', 'osqueryd not installed'); return; }
  const q = (e: any, key: string, name: string, data: string) => runOsq(regCte([{ key, path: `${key}\\${name}`, name, type: 'REG_SZ', data }]) + buildRegistryScanSqlV2(e)).filter((r) => r.type !== 'anchor').map((r) => r.data);
  assert.deepStrictEqual(q(run, RUNK, 'PwdHelper', 'C:\\a\\x.exe'), ['C:\\a\\x.exe'], 'a Run value named PwdHelper is collected in clear');
  const a = q(cust, `${L}SOFTWARE\\Acme\\Agent`, 'DbPassword', 'aaaa1111')[0];
  const b = q(cust, `${L}SOFTWARE\\Acme\\Agent`, 'DbPassword', 'bbbb2222')[0];
  assert.ok(a.startsWith('REDACTED(len=8,sha256=') && b.startsWith('REDACTED(len=8,sha256=') && a !== b, `${a} vs ${b}`);
  assert.strictEqual(a, `REDACTED(len=8,sha256=${createHash('sha256').update('aaaa1111').digest('hex').slice(0, 16)})`, 'same digest as the worker computes');
});

t('round 4: catalog autoruns never hide values (Password/Pwd/Secret/ApiKey names), Winlogon DefaultPassword gets a digest, localized secret names in custom entries are redacted', () => {
  if (!osq) { skip('round 4 redaction osqueryd', 'osqueryd not installed'); return; }
  const ent = (k: string) => resolveRegistry(baseInput()).entries.find((e) => e.entryKey === k)!;
  const RUNK = `${L}SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`;
  const WL = `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`;
  const rows = (e: any, key: string, vals: [string, string][]) => runOsq(regCte(vals.map(([name, data]) => ({ key, path: `${key}\\${name}`, name, type: 'REG_SZ', data }))) + buildRegistryScanSqlV2(e))
    .filter((r) => r.type !== 'anchor' && r.type !== 'hive').map((r) => [r.name, r.data]).sort();
  const names: [string, string][] = [['Password', 'C:\\x\\a.exe'], ['Pwd', 'C:\\x\\b.exe'], ['Secret', 'C:\\x\\c.exe'], ['ApiKey', 'C:\\x\\d.exe']];
  assert.deepStrictEqual(rows(ent('reg.run.hklm'), RUNK, names), [...names].sort(), 'Run values are commands: never redacted by name');
  const d = (x: string) => createHash('sha256').update(x).digest('hex').slice(0, 16);
  assert.deepStrictEqual(rows(ent('reg.winlogon'), WL, [['DefaultPassword', 'hunter2']]), [['DefaultPassword', `REDACTED(len=7,sha256=${d('hunter2')})`]]);
  // equal-length swap of the credential is visible
  assert.notDeepStrictEqual(rows(ent('reg.winlogon'), WL, [['DefaultPassword', 'hunter3']]), rows(ent('reg.winlogon'), WL, [['DefaultPassword', 'hunter2']]));
  const cust = normalizeRegistryEntryV2({ path: `${L}SOFTWARE\\Acme\\Agent` });
  const ACME = `${L}SOFTWARE\\Acme\\Agent`;
  assert.deepStrictEqual(rows(cust, ACME, [['Kennw\u00f6rt', 'hunter2'], ['\u041f\u0430\u0440\u043e\u043b\u044c', 'hunter2'], ['Passwort', 'hunter2'], ['Path', 'C:\\acme']]),
    [['Kennw\u00f6rt', `REDACTED(len=7,sha256=${d('hunter2')})`], ['Passwort', `REDACTED(len=7,sha256=${d('hunter2')})`], ['Path', 'C:\\acme'], ['\u041f\u0430\u0440\u043e\u043b\u044c', `REDACTED(len=7,sha256=${d('hunter2')})`]]);
});

t('mutation gaps: approver status, custom wildcard redaction over catalog keys, catalog autoruns unredacted (no osqueryd needed)', () => {
  // (f1) approver status = designated AND active AND admin role
  const ap = [{ userId: 7 }];
  assert.strictEqual(isActiveApprover(7, ap, { role: 'Group Admin', suspended: false }), true);
  assert.strictEqual(isActiveApprover(7, ap, { role: 'Group Admin', suspended: true }), false, 'suspended');
  assert.strictEqual(isActiveApprover(7, ap, { role: 'Viewer', suspended: false }), false, 'demoted');
  assert.strictEqual(isActiveApprover(8, ap, { role: 'Super Administrator', suspended: false }), false, 'never designated');
  assert.strictEqual(isActiveApprover(7, ap, null), false, 'unknown user');
  assert.strictEqual(isActiveApprover(null, ap, { role: 'Group Admin' }), false);
  // (b) a custom WILDCARD carrying redactValues over a catalog exact key never changes the catalog entry
  const CV = `${L}SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`;
  const spec = { path: `${CV}\\%`, values: ['Shell', 'Userinit'], redactValues: ['Shell', 'Userinit'], severity: 'low' };
  const base = resolveRegistry(baseInput()).entries.find((e) => e.entryKey === 'reg.winlogon')!;
  const withRule = resolveRegistry(baseInput({ rules: [{ id: 1, layer: 'node', scopeValue: 'H1', op: 'add', target: customEntryKey(spec.path), spec, waiverId: null }] }));
  const wl = withRule.entries.find((e) => e.entryKey === 'reg.winlogon')!;
  assert.deepStrictEqual([wl.redactValues, wl.values, wl.fingerprint], [base.redactValues, base.values, base.fingerprint], 'catalog entry unchanged by the custom wildcard');
  const cust = withRule.entries.find((e) => e.entryKey === customEntryKey(spec.path))!;
  assert.ok(cust.excludeKeys.some((x) => /Winlogon$/i.test(x)), 'the custom wildcard stops covering the catalog key');
  // (c) catalog entries without their own redactValues have a plain data column (nothing hidden by name)
  for (const id of ['reg.run.hklm', 'reg.runonce.hklm', 'reg.ifeo', 'reg.svc.image']) {
    const e = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }] })).entries.find((x) => x.entryKey === id)!;
    const sql = buildRegistryScanSqlV2(e);
    assert.ok(sql.startsWith('SELECT path, name, type, data FROM registry'), `${id}: ${sql.slice(0, 120)}`);
  }
  const wsql = buildRegistryScanSqlV2(base);
  assert.ok(wsql.includes("lower(name) IN ('altdefaultpassword', 'defaultpassword')") && !wsql.includes("'pwd'") && !wsql.includes("'secret'"), wsql.slice(0, 300));
});

t('round 5: spec v3 - data-bearing catalog entries (env, RDP) and custom keys merged into them redact credential names; revoked waivers never count', () => {
  // NEW-1: a custom key on a NON-protected catalog path merges into the catalog entry and keeps redacting
  const rdp = REG_CATALOG.find((c) => c.id === 'reg.rdp.tcp')!;
  const spec = { path: rdp.path, values: ['Password', 'PortNumber'], redactValues: ['Password'], severity: 'low' };
  const r = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }], rules: [rule(1, 'node', 'add', customEntryKey(rdp.path), spec)] }));
  const merged = r.entries.find((e) => e.entryKey === 'reg.rdp.tcp')!;
  assert.ok(merged, JSON.stringify(r.errors));
  assert.notStrictEqual(merged.visibleByDesign, true);
  const msql = buildRegistryScanSqlV2(merged);
  assert.ok(msql.includes("LIKE '%password%'") && msql.includes("'password'"), 'merged entry redacts credential names');
  // a custom duplicate of a NON-protected visible-by-design entry (netsh) makes the merge redact names too
  const ns = REG_CATALOG.find((c) => c.id === 'reg.netsh')!;
  const rn = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }], rules: [rule(4, 'node', 'add', customEntryKey(ns.path), { path: ns.path, redactValues: ['Password'], severity: 'low' })] }));
  const mn = rn.entries.find((e) => e.entryKey === 'reg.netsh')!;
  assert.notStrictEqual(mn.visibleByDesign, true, 'never fewer redactions than any member');
  // m02d: the custom member's explicit redactValues survive the merge, also for a name the heuristic misses
  const rl = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }], rules: [rule(5, 'node', 'add', customEntryKey(rdp.path), { path: rdp.path, redactValues: ['LicenseKey'], severity: 'low' })] }));
  const ml = rl.entries.find((e) => e.entryKey === 'reg.rdp.tcp')!;
  assert.ok(ml.redactValues.includes('LicenseKey'), JSON.stringify(ml.redactValues));
  for (const v of rdp.redactValues) assert.ok(ml.redactValues.includes(v), `catalog redactValue ${v} kept`);
  assert.ok(buildRegistryScanSqlV2(ml).includes("'licensekey'"));
  // m02a guard: no catalog WILDCARD entry carries its own redactValues (the carve-out would not keep them);
  // adding one requires extending the carve-out first
  const isExactPath = (p: string) => !p.split('\\').some((x) => x.includes('%'));
  assert.deepStrictEqual(REG_CATALOG.filter((c) => !isExactPath(c.path) && c.redactValues.length).map((c) => c.id), []);
  assert.ok(buildRegistryScanSqlV2(mn).includes("LIKE '%password%'"));
  // a merge with a visible-by-design catalog entry never makes it visible-by-design unless every member is
  const run = REG_CATALOG.find((c) => c.id === 'reg.run.hklm')!;
  const rr = resolveRegistry(baseInput({ rules: [rule(2, 'node', 'add', customEntryKey(run.path), { path: run.path, severity: 'low' })] }));
  assert.strictEqual(rr.entries.find((e) => e.entryKey === 'reg.run.hklm')!.visibleByDesign, true, 'protected Run ignores the custom duplicate (commands stay visible)');
  // m15c: a REVOKED (or expired) waiver never backs a protected reduction in the resolver
  const dis = rule(3, 'node', 'disable', 'reg.run.hklm', {}, 77);
  for (const status of ['revoked', 'expired', 'pending', 'rejected'] as const) {
    const res = resolveRegistry(baseInput({ rules: [dis], waivers: [waiver(77, { status }, dis)] }));
    assert.ok(res.entries.some((e) => e.entryKey === 'reg.run.hklm'), `a ${status} waiver must not disable reg.run.hklm`);
  }
  assert.ok(!resolveRegistry(baseInput({ rules: [dis], waivers: [waiver(77, {}, dis)] })).entries.some((e) => e.entryKey === 'reg.run.hklm'), 'an approved bound waiver does');
  if (!osq) { skip('round 5 env redaction osqueryd', 'osqueryd not installed'); return; }
  // N5: environment variables: secrets redacted (digest), PATH/TEMP visible
  const env = resolveRegistry(baseInput()).entries.find((e) => e.entryKey === 'reg.env.machine')!;
  const ENVK = `${L}SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`;
  const rows = runOsq(regCte([['Path', 'C:\\Windows'], ['TEMP', 'C:\\Temp'], ['DB_PASSWORD', 'hunter22'], ['API_TOKEN', 'abcd']].map(([name, data]) => ({ key: ENVK, path: `${ENVK}\\${name}`, name, type: 'REG_SZ', data }))) + buildRegistryScanSqlV2(env))
    .filter((x) => x.type !== 'anchor').map((x) => [x.name, x.data]).sort();
  const d = (x: string) => createHash('sha256').update(x).digest('hex').slice(0, 16);
  assert.deepStrictEqual(rows, [['API_TOKEN', `REDACTED(len=4,sha256=${d('abcd')})`], ['DB_PASSWORD', `REDACTED(len=8,sha256=${d('hunter22')})`], ['Path', 'C:\\Windows'], ['TEMP', 'C:\\Temp']]);
  // RDP-Tcp merged entry in osqueryd: Password redacted
  const rrows = runOsq(regCte([{ key: rdp.path, path: `${rdp.path}\\Password`, name: 'Password', type: 'REG_SZ', data: 'hunter22' }]) + msql).filter((x) => x.type !== 'anchor');
  assert.deepStrictEqual(rrows.map((x) => x.data), [`REDACTED(len=8,sha256=${d('hunter22')})`]);
});

t('final round F2: layer precedence is non-transitive (a dropped entry never causes further drops)', () => {
  const mk = (id: number, layer: RegRule['layer'], path: string) => rule(id, layer, 'add', customEntryKey(path), { path, severity: 'low', measureOverride: true });
  const A = `${L}SOFTWARE\\Acme\\Apps`;
  // profile Zeta\%, group SOFTWARE\%\% (overlaps both), node Beta\%: only the group entry is dropped
  const r = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'essential' }], rules: [
    mk(1, 'profile', `${A}\\Zeta\\%`), mk(2, 'group', `${A}\\%%`), mk(3, 'node', `${A}\\Beta\\%`)] }));
  assert.ok(r.ok, JSON.stringify(r.errors));
  assert.ok(!r.blocked.some((b) => !b.reason.startsWith('overlap:')), JSON.stringify(r.blocked));
  const ks = keys(r);
  assert.ok(ks.includes(customEntryKey(`${A}\\Beta\\%`)), 'node entry kept');
  assert.ok(!ks.includes(customEntryKey(`${A}\\%%`)), 'group entry dropped (overlaps the node entry)');
  assert.ok(ks.includes(customEntryKey(`${A}\\Zeta\\%`)), 'profile entry kept: it only overlapped the DROPPED group entry');
});

t('HIGH-1 property (real osqueryd): random NON-waived custom rule sets never change what protected entries return', () => {
  if (!osq) { skip('HIGH-1 property test', 'osqueryd not installed'); return; }
  let seed = 20261013;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const pick = <T>(a: T[]): T => a[Math.floor(rnd() * a.length)];
  const prot = REG_CATALOG.filter((c) => c.protected && !c.optInOnly);
  const sampleKey = (p: string) => p.split('\\').map((x) => (x === '%' ? 'Xk' : x === '%%' ? 'Xk\\Yk' : x)).join('\\');
  const parent = (p: string) => p.split('\\').slice(0, -1).join('\\');
  const samples = prot.flatMap((c) => (c.values.length ? c.values : ['EvilVal'])
    .filter((v) => !c.ignoreValues.includes(v) && !c.redactValues.includes(v) && !isSecretLikeName(v))
    .map((v) => ({ id: c.id, key: sampleKey(c.path), name: v })));
  const planted = new Map<string, { key: string; path: string; name: string; type: string; data: string }>();
  for (const x of samples) {
    planted.set(`${x.key}\\${x.name}`, { key: x.key, path: `${x.key}\\${x.name}`, name: x.name, type: 'REG_SZ', data: `MARK|${x.id}` });
    planted.set(x.key, { key: parent(x.key), path: x.key, name: x.key.split('\\').pop()!, type: 'subkey', data: '' });
  }
  const cte = regCte([...planted.values()]);
  const randomCustom = (id: number): RegRule => {
    const c = pick([...REG_CATALOG]);
    const vals = c.values.length ? c.values : ['EvilVal'];
    const sk = sampleKey(c.path);
    const path = pick([c.path, sk, `${parent(c.path)}\\%`, `${parent(sk)}\\%`, `${parent(parent(sk))}\\%\\${sk.split('\\').pop()}`]);
    const spec: any = { path, severity: 'low', redactValues: rnd() < 0.8 ? vals.slice(0, 16) : [] };
    if (rnd() < 0.5) spec.values = rnd() < 0.5 ? vals : [pick(vals)];
    if (rnd() < 0.3) spec.ignoreValues = [pick(vals)];
    if (rnd() < 0.2) spec.anchor = false;
    if (rnd() < 0.2) spec.includeSubkeys = rnd() < 0.5;
    let target = 'custom:0000000000000000';
    try { target = customEntryKey(path); } catch { /* invalid path: the resolver blocks it */ }
    return { id, layer: pick(['node', 'group', 'profile'] as const), scopeValue: '', op: 'add', target, spec, waiverId: null };
  };
  const cases: { rules: RegRule[]; sql: string[] }[] = [];
  let notOk = 0;
  for (let i = 0; cases.length < 300 && i < 2000; i++) {
    const rules = Array.from({ length: 1 + Math.floor(rnd() * 3) }, (_, j) => randomCustom(j + 1))
      .map((r) => ({ ...r, scopeValue: r.layer === 'node' ? 'H1' : r.layer === 'group' ? 'G1' : '1' }));
    const res = resolveRegistry(baseInput({ profiles: [{ ...PROFILES[0], tier: 'comprehensive' }], rules }));
    if (!res.ok) { notOk++; continue; }
    cases.push({ rules, sql: res.entries.map((e) => buildRegistryScanSqlV2(e)) });
  }
  const want = samples.map((x) => asciiLower(`${x.key}\\${x.name}`));
  const lost: string[] = [];
  // Batches stay under SQLite's 500-term compound SELECT limit (each entry query is one term).
  const batches: number[][] = [];
  for (let i = 0, cur: number[] = [], terms = 0; i < cases.length; i++) {
    if (terms + cases[i].sql.length > 450 && cur.length) { batches.push(cur); cur = []; terms = 0; }
    cur.push(i); terms += cases[i].sql.length;
    if (i === cases.length - 1) batches.push(cur);
  }
  for (const batch of batches) {
    const sql = cte + batch.flatMap((ci) => cases[ci].sql.map((q) => `SELECT ${ci} AS c, path, data FROM (${q})`)).join(' UNION ALL ');
    const rows = runOsq(sql.length > 100_000 ? sql : sql + ' '.repeat(100_001 - sql.length));
    assert.ok(rows.length > 0, 'osqueryd returned rows for the batch');
    const clear = new Map<number, Set<string>>();
    for (const r of rows) if (String(r.data).startsWith('MARK|')) {
      const k = Number(r.c);
      if (!clear.has(k)) clear.set(k, new Set());
      clear.get(k)!.add(asciiLower(r.path));
    }
    for (const ci of batch) {
      const got = clear.get(ci) ?? new Set();
      for (const w of want) if (!got.has(w)) lost.push(`${w} lost with rules ${JSON.stringify(cases[ci].rules.map((r) => r.spec))}`);
    }
  }
  console.log(`   ${cases.length} valid random custom rule sets (${notOk} invalid resolutions skipped) x ${samples.length} protected values`);
  assert.ok(cases.length >= 300 && samples.length > 50);
  assert.deepStrictEqual(lost.slice(0, 5), [], `${lost.length} protected value(s) lost or redacted`);
});

if (skips.length) {
  console.log(`${skips.length} gated test(s) SKIPPED:\n  ${skips.join('\n  ')}`);
  if (process.env.FIM_ALLOW_SKIP !== '1') { console.error('FAILING: gated tests did not run (set FIM_ALLOW_SKIP=1 to accept)'); process.exit(1); }
}
console.log(`\n${n} groups passed`);
