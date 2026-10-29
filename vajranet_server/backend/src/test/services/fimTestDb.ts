/**
 * Database for the FIM DB selftests. With FIM_TEST_DB set the suites use that database (shared,
 * prepared by the caller). Otherwise every process gets its OWN throwaway database on the
 * FIM_TEST_PG server (fimt_<pid>_<random>): created from the minimal base schema fixture plus the
 * FIM migrations, and dropped again at the end - concurrent runs (several verifiers, CI shards)
 * can never corrupt each other's results.
 */
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { DataSource } from 'typeorm';

export interface FimTestDb { ds: DataSource; name: string; drop: () => Promise<void> }

export async function openFimTestDb(addr: string): Promise<FimTestDb> {
  const [host, port] = addr.split(':');
  const username = process.env.FIM_TEST_USER || 'fimtest';
  const mk = (database: string) => new DataSource({ type: 'postgres', host, port: Number(port), username, database });
  if (process.env.FIM_TEST_DB) {
    const ds = mk(process.env.FIM_TEST_DB);
    await ds.initialize();
    return { ds, name: process.env.FIM_TEST_DB, drop: async () => { await ds.destroy(); } };
  }
  const name = `fimt_${process.pid}_${randomBytes(4).toString('hex')}`;
  const admin = mk(process.env.FIM_TEST_ADMIN_DB || 'postgres');
  await admin.initialize();
  await admin.query(`CREATE DATABASE ${name}`);
  const ds = mk(name);
  try {
    await ds.initialize();
    const root = join(__dirname, '../../..');
    // psql meta-commands (pg_dump may emit e.g. \restrict) are not SQL: drop those lines.
    const sql = (f: string) => readFileSync(f, 'utf8').split('\n').filter((l) => !l.startsWith('\\')).join('\n');
    await ds.query(sql(join(root, 'src/test/fixtures/fim_ci_base_schema.sql')));
    for (const f of readdirSync(join(root, 'migrations')).filter((x) => /^03[0-9]_add_fim_.*\.sql$/.test(x)).sort()) {
      await ds.query(sql(join(root, 'migrations', f)));
    }
  } catch (err) {
    if (ds.isInitialized) await ds.destroy();
    await admin.query(`DROP DATABASE IF EXISTS ${name}`).catch(() => undefined);
    await admin.destroy();
    throw err;
  }
  return {
    ds, name,
    drop: async () => {
      await ds.destroy();
      try { await admin.query(`DROP DATABASE IF EXISTS ${name}`); } finally { await admin.destroy(); }
    },
  };
}
