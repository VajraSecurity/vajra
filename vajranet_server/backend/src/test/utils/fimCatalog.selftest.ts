/**
 * Catalog invariants + (when osqueryd is installed) real-osquery verification of every
 * Linux source:  node_modules/.bin/ts-node src/test/utils/fimCatalog.selftest.ts
 */
import assert from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { buildScanSql } from '../../utils/fim/fimLogic';
import { FIM_CATALOG, catalogMetadata, getCatalogSource } from '../../utils/fim/fimCatalog';

let n = 0;
const t = (name: string, fn: () => void) => { fn(); n++; console.log(`ok - ${name}`); };
const VOLATILE = /(^|_)(pid|ppid|pgroup|time|timestamp|count|counter|bytes|packets|memory|resident|total_size|wired|used_by|address_hex|active_state|sub_state|percentage_encrypted|state_timestamp)($|_)/i;

t('catalog ids are unique and metadata hides SQL', () => {
  assert.strictEqual(new Set(FIM_CATALOG.map((s) => s.id)).size, FIM_CATALOG.length);
  const meta = catalogMetadata();
  assert.ok(meta.every((m) => !('sql' in m)));
  assert.strictEqual(catalogMetadata('windows').every((m) => m.platform === 'windows'), true);
  assert.ok(getCatalogSource('users') && !getCatalogSource('nope'));
});

t('every SELECT list is exactly key + value columns; no volatile columns', () => {
  for (const s of FIM_CATALOG) {
    assert.ok(s.keyColumns.length > 0, s.id);
    const cols = [...s.keyColumns, ...s.valueColumns];
    assert.strictEqual(new Set(cols).size, cols.length, `${s.id}: duplicate column`);
    const m = /^SELECT\s+([\s\S]+?)\s+FROM\s/i.exec(s.sql);
    assert.ok(m, `${s.id}: not a SELECT`);
    const sel = m![1].split(',').map((x) => {
      const a = /\sAS\s+([A-Za-z_]+)\s*$/i.exec(x.trim());
      return a ? a[1] : x.trim().replace(/^.*\./, '');
    });
    // string-literal selects ('secureboot' AS setting) are handled by the AS branch
    assert.deepStrictEqual(sel, cols, `${s.id}: select list != key+value columns`);
    for (const c of cols) assert.ok(!VOLATILE.test(c), `${s.id}: volatile column ${c}`);
    assert.ok(!s.sql.includes(';') && !/--/.test(s.sql), `${s.id}: unsafe SQL`);
    assert.ok(s.intervalHint >= 60);
  }
});

t('Windows sources are flagged unverified; extension sources are flagged', () => {
  for (const s of FIM_CATALOG.filter((x) => x.platform === 'windows')) assert.strictEqual(s.verified, 'unverified', s.id);
  assert.ok(FIM_CATALOG.some((s) => s.requiresExtension));
});

const have = spawnSync('osqueryd', ['--version']).status === 0;
const skipped: string[] = [];
if (!have) { skipped.push('osqueryd execution of the Linux catalog SQL'); console.log('SKIPPED - osqueryd not installed: Linux catalog SQL not executed'); }
else {
  t('Linux sources run on real osqueryd and return exactly the declared columns', () => {
    for (const s of FIM_CATALOG.filter((x) => x.platform === 'linux')) {
      const out = execFileSync('osqueryd', ['-S', '--json', s.sql], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 180000 });
      const rows = JSON.parse(out.slice(out.indexOf('[')));
      if (rows.length) assert.deepStrictEqual(Object.keys(rows[0]).sort(), [...s.keyColumns, ...s.valueColumns].sort(), s.id);
      else {
        // Empty table here: still prove every declared column name exists in the result.
        const cols = [...s.keyColumns, ...s.valueColumns].map((c) => `"${c}"`).join(', ');
        execFileSync('osqueryd', ['-S', '--json', `SELECT ${cols} FROM (${s.sql}) LIMIT 0`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 180000 });
      }
      console.log(`   ${s.id}: ${rows.length} rows${rows.length ? '' : ' (empty here: declared column names verified with a LIMIT 0 projection)'}`);
    }
  });
}
if (have) {
  t('generated path/xattr SQL on real osqueryd: hidden files, directories, FIFO never hashed', () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'fimsql-'));
    try {
      for (const dir of ['a/.cache', '.d/x', 'b/c/d']) fs.mkdirSync(path.join(d, dir), { recursive: true });
      for (const f of ['.hid', 'vis', 'a/.dotfile', 'a/vis2', 'a/.cache/evil', 'b/.top']) fs.writeFileSync(path.join(d, f), f);
      spawnSync('mkfifo', [path.join(d, 'pipe')]);
      const q = (sql: string) => { const o = execFileSync('osqueryd', ['-S', '--json', sql], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 120000 }); return JSON.parse(o.slice(o.indexOf('['))) as any[]; };
      const rows = q(buildScanSql({ kind: 'path', path: `${d}/%%` }, 'linux'));
      const rel = new Map(rows.map((r) => [r.path.replace(d, ''), r]));
      for (const want of ['/.hid', '/a/.dotfile', '/a/.cache/evil', '/b/.top', '/vis', '/a/vis2']) {
        assert.ok(rel.has(want), `missing ${want}`);
        assert.strictEqual(rel.get(want).type, 'regular');
        assert.ok(rel.get(want).sha256, `${want} should be hashed`);
      }
      assert.strictEqual(rel.get('/a/').type, 'directory');
      assert.ok(!rel.get('/a/').sha256, 'directories are not hashed');
      if (rel.has('/pipe')) assert.ok(!rel.get('/pipe').sha256, 'FIFO must never be read');
      assert.ok([...rel.keys()].every((k) => !k.includes('/../') && !k.includes('/./')), 'relative entries are filtered');
      const self = q(buildScanSql({ kind: 'path', path: `${d}/a/` }, 'linux'));
      assert.deepStrictEqual(self.map((r) => [r.path.replace(d, ''), r.type]), [['/a/', 'directory']], 'trailing-separator entry returns the directory itself');
      if (spawnSync('setfacl', ['-m', 'u:nobody:r', path.join(d, 'a/.cache/evil')]).status === 0) {
        const x = q(buildScanSql({ kind: 'xattr', path: `${d}/%%` }, 'linux'));
        assert.ok(x.some((r) => r.path.endsWith('/a/.cache/evil') && r.key === 'system.posix_acl_access'), 'POSIX ACL (hidden dir) not reported');
        assert.deepStrictEqual(Object.keys(x[0]).sort(), ['key', 'path', 'value']);
      } else q(buildScanSql({ kind: 'xattr', path: `${d}/%%` }, 'linux')); // at least must execute
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });
}
console.log(`\n${n} groups passed`);
if (skipped.length && process.env.FIM_ALLOW_SKIP !== '1') { console.error(`FAILING: ${skipped.length} gated test(s) did not run (set FIM_ALLOW_SKIP=1 to accept)`); process.exit(1); }
