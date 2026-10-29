/**
 * Live end-to-end selftest for the OpenVAS edit-scan / edit-target /
 * edit-credential request-handling logic in
 * controllers/openvas/openvasController.ts (updateTarget, updateTask,
 * updateCredential), run against a REAL, live GVM backend through the real
 * utils/openvasClient.ts executeGmpCommand/executeGmpPost implementations —
 * the exact same functions the live Express backend uses.
 *
 * WHY THIS FILE EXISTS
 * ---------------------
 * No legitimate seeded/documented dev account with a known password exists
 * anywhere in this repo (checked: no seed script, no createDefaultAdmin, no
 * DEV_ADMIN/TEST_ADMIN, .env.example ships only placeholder secrets, and
 * ormconfig-setup.ts's DATABASE_SETUP_QUERIES only creates indexes/DDL, never
 * a user row). The only "bootstrap" path in the app is user_register.ts
 * promoting the FIRST-EVER registered user to Super Administrator — moot here
 * because this deployment's users table is already populated with real
 * people's accounts (2 existing Super Administrators), and creating a new
 * account or touching an existing one is explicitly out of scope for this
 * kind of verification work. So there is no way to obtain a real Super
 * Administrator JWT without touching a real account — this file is the
 * documented fallback: the fullest LIVE-GVM coverage achievable at the code
 * level without one.
 *
 * WHY IT'S SHAPED THIS WAY (import-safety)
 * ------------------------------------------
 * controllers/openvas/openvasController.ts cannot be imported directly from a
 * standalone script: it statically imports utils/auditTrailLogger.ts, which
 * statically imports `dbSourceConnection` from `../index` (src/index.ts) —
 * and src/index.ts unconditionally runs a full server-bootstrap IIFE at
 * module load (Redis connect, DB connect, `server.listen(PORT)`,
 * `process.exit(1)` on any startup error including EADDRINUSE). Importing it
 * from a script running alongside the live backend would race that same port
 * and could kill this process, or worse, the shared DB connection pool.
 *
 * Less obviously — and verified explicitly here on 2026-09-10, do NOT assume
 * this stays true after future edits; re-verify before reusing this pattern —
 * utils/openvasClient.ts is ALSO not safe to import directly on its own: it
 * has a static import of `{ groupIdWhereValue, scannerCacheKey } from
 * './scannerScope'`, and scannerScope.ts statically imports `./nodeScope`,
 * which statically imports `dbSourceConnection` from `../index`. So a plain
 * `require`/`import` of openvasClient.ts transitively executes src/index.ts's
 * bootstrap IIFE too, via that chain — even though openvasClient.ts's own
 * code never calls anything from nodeScope.ts.
 *
 * The fix is a standard Node.js require-cache stub: before anything requires
 * openvasClient.ts, this file pre-populates `require.cache` for index.ts's
 * resolved path with a fake module exporting a `dbSourceConnection` stub that
 * throws if actually invoked. Node's CommonJS loader checks `require.cache`
 * before ever reading a file from disk, so the real index.ts is never opened
 * or executed. That stub should in fact never run at all here: every GVM call
 * below passes its own explicit `config` argument to
 * executeGmpCommand/executeGmpPost, which short-circuits openvasClient.ts's
 * only OTHER path to index.ts — a *dynamic* `await import('../index')` inside
 * its own getOpenVASConfig(), reached only when no config is supplied.
 *
 * WHAT THIS COVERS vs. WHAT STILL ONLY HAS GVM-DIRECT (curl) COVERAGE
 * ----------------------------------------------------------------------
 * Covered here, against a real live GVM instance, through the real shipped
 * executeGmpCommand/executeGmpPost:
 *   - updateTarget's save_target field-carryover logic (in_use guard, host
 *     re-validation, credential-id '0'-vs-clear convention)
 *   - updateTask's save_task field-carryover + isNew/target-config-scanner
 *     lock logic
 *   - updateCredential's save_credential field-carryover + type-is-fixed
 *     convention, including the "no password supplied = leave unchanged"
 *     branch
 *   - create_target / create_credential / create_task and their delete_*
 *     counterparts, needed to set up/tear down the above
 *   - GVM's real response shapes (action_result / *_response envelopes) via
 *     the same parseGmpResponse used in production
 *
 * NOT covered here (still only verified this session via raw curl against
 * the live backend, never through actual code): checkJwt/requireAdmin
 * middleware, CSRF (checkCsrf), rate limiting, resolveScannerGroupContext's
 * real group-membership resolution (this script always acts in the
 * null/"Super Administrator's own scope" group directly), Express
 * routing/param parsing/serialization, and logAuditTrail's actual DB write
 * (openvasController.ts's create/updateTask paths call it; this script
 * doesn't, since importing it would reach index.ts the same way
 * auditTrailLogger.ts does).
 *
 * Creates and deletes its own throwaway credential/target/task in the
 * configured GVM instance (named SELFTEST_OPENVAS_EDIT_FLOWS_<timestamp>_*),
 * cleaned up in a finally block regardless of pass/fail.
 *
 * NOT wired into `npm test` — this hits a real, live external GVM server and
 * mutates its state (even though it cleans up after itself), which is not
 * safe to run unattended/concurrently in CI. Run manually:
 *
 *   node_modules/.bin/ts-node src/test/utils/openvasEditFlows.selftest.ts
 *
 * Requires: a reachable GVM instance with an active `openvas_configs` row for
 * the Super Administrator's own scope (group_id IS NULL, is_active = true) —
 * the same one the running backend itself uses — the fleet DB
 * (PG_HOST1/PG_PORT1/POSTGRES_USER1/POSTGRES_PASSWORD1/POSTGRES_DB1) and
 * NESSUS_ENCRYPTION_KEY reachable/set via the normal .env.
 */

import 'dotenv/config';
import assert from 'assert';
import path from 'path';
import { Client } from 'pg';
import { decrypt } from '../../utils/encryption';
import { parseAndValidateTargets } from '../../controllers/network/targetValidation';
import { EXTERNAL_API_TIMEOUT_MS } from '../../consts/timeout';
import {
  OPENVAS_DEFAULT_PORT_LIST_ID,
  OPENVAS_DEFAULT_SCANNER_ID,
  OPENVAS_DEFAULT_TARGET_PARAMS,
  OPENVAS_DEFAULT_TASK_PARAMS,
} from '../../consts/scanning';

// ---------------------------------------------------------------------------
// Step 1 (must happen before anything transitively requires openvasClient.ts):
// neutralize src/index.ts in require.cache. See header comment for why.
// ---------------------------------------------------------------------------
const SRC_DIR = path.join(__dirname, '..', '..');
const INDEX_PATH = require.resolve(path.join(SRC_DIR, 'index'));
if (!require.cache[INDEX_PATH]) {
  require.cache[INDEX_PATH] = {
    id: INDEX_PATH,
    filename: INDEX_PATH,
    loaded: true,
    exports: {
      dbSourceConnection: () => {
        throw new Error(
          'STUB dbSourceConnection() was called. This selftest always passes an explicit ' +
          '`config` to executeGmpCommand/executeGmpPost specifically so this stub is never ' +
          'exercised — if you see this, something upstream changed. Stop and re-check the ' +
          'import-safety comment at the top of this file before proceeding.',
        );
      },
    },
  } as unknown as NodeModule;
}

interface LiveGvmConfig {
  gsaUrl: string;
  gmpUsername: string;
  gmpPassword: string;
}

interface OpenvasClientModule {
  executeGmpCommand: (
    groupId: string | null,
    cmd: string,
    config?: LiveGvmConfig,
    timeoutMs?: number,
    extraParams?: Record<string, string>,
  ) => Promise<any>;
  executeGmpPost: (
    groupId: string | null,
    cmd: string,
    formParams: Record<string, string>,
    config?: LiveGvmConfig,
    timeoutMs?: number,
  ) => Promise<any>;
}

// Required at call time (after the require.cache stub above is in place),
// not via a static top-level `import` — a static import would be hoisted by
// the TS/CJS compiler ahead of the stub-installation code above, defeating it.
const openvasClientMod = require(path.join(SRC_DIR, 'utils', 'openvasClient')) as OpenvasClientModule;
const { executeGmpCommand, executeGmpPost } = openvasClientMod;

function ensureArray<T>(val: T | T[] | undefined | null): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

/** Loads the live GVM connection config directly from the fleet DB via a raw
 *  `pg` client — deliberately NOT via TypeORM/dbSourceConnection (that would
 *  need index.ts) and NOT via openvasClient.ts's own getOpenVASConfig (that
 *  would take its dynamic `import('../index')` path). Mirrors exactly what
 *  getOpenVASConfig does: read the active openvas_configs row for this scope,
 *  decrypt the stored GMP password with the same utils/encryption.ts. */
async function loadLiveGvmConfig(): Promise<LiveGvmConfig> {
  const client = new Client({
    host: process.env.PG_HOST1,
    port: Number(process.env.PG_PORT1),
    user: process.env.POSTGRES_USER1,
    password: process.env.POSTGRES_PASSWORD1,
    database: process.env.POSTGRES_DB1,
  });
  await client.connect();
  try {
    const { rows } = await client.query(
      `SELECT nessus_url, gmp_username, gmp_password_encrypted, gmp_password_iv, gmp_password_auth_tag
       FROM openvas_configs
       WHERE is_active = true AND group_id IS NULL
       LIMIT 1`,
    );
    if (rows.length === 0) {
      throw new Error(
        'No active OpenVAS configuration found for the Super Administrator scope ' +
        '(openvas_configs: is_active = true AND group_id IS NULL). Configure one in ' +
        'Settings first, or point this script at a specific group_id.',
      );
    }
    const row = rows[0];
    const gmpPassword = decrypt(row.gmp_password_encrypted, row.gmp_password_iv, row.gmp_password_auth_tag);
    return { gsaUrl: row.nessus_url, gmpUsername: row.gmp_username, gmpPassword };
  } finally {
    await client.end();
  }
}

function validateHosts(raw: string): string | null {
  const validated = parseAndValidateTargets(raw);
  return validated ? validated.join(',') : null;
}

let checks = 0;
function check(condition: unknown, message: string): void {
  checks++;
  assert.ok(condition, message);
}

async function main() {
  const cfg = await loadLiveGvmConfig();
  const groupId: string | null = null; // Super Administrator's own scope.
  const runId = Date.now();
  const NAME_PREFIX = `SELFTEST_OPENVAS_EDIT_FLOWS_${runId}`;

  let credentialId: string | undefined;
  let targetId: string | undefined;
  let taskId: string | undefined;

  try {
    // ── Credential: create, then exercise updateCredential's save_credential ──
    // ── field-carryover logic (mirrors createCredential/updateCredential). ────
    console.log('Creating throwaway credential...');
    {
      const params: Record<string, string> = {
        name: `${NAME_PREFIX}_cred`,
        credential_type: 'up',
        credential_login: 'selftest_user',
        lsc_password: 'SelfTest-Pass-1!',
        autogenerate: '0',
        comment: 'created by openvasEditFlows.selftest.ts — safe to delete',
      };
      const result = await executeGmpPost(groupId, 'create_credential', params, cfg, EXTERNAL_API_TIMEOUT_MS);
      credentialId = result?.action_result?.id || result?.create_credential_response?.['@_id'];
      check(credentialId, 'create_credential must return a resolvable id');
    }

    console.log('Updating credential (name/login/comment) via save_credential...');
    {
      const allCreds = await executeGmpCommand(groupId, 'get_credentials', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const current = ensureArray(allCreds?.get_credentials_response?.credential).find((c: any) => c['@_id'] === credentialId);
      check(current, 'freshly created credential must be found by get_credentials');

      const newName = `${NAME_PREFIX}_cred_renamed`;
      const newLogin = 'selftest_user_renamed';
      const newComment = 'updated by openvasEditFlows.selftest.ts';
      const effectiveLogin = newLogin;
      const params: Record<string, string> = {
        credential_id: credentialId!,
        name: newName,
        comment: newComment,
        login: effectiveLogin,
        credential_login: effectiveLogin,
        credential_type: current.type,
      };
      // Exercise the "no password supplied" branch — updateCredential's own
      // convention for leaving the stored password unchanged.
      await executeGmpPost(groupId, 'save_credential', params, cfg, EXTERNAL_API_TIMEOUT_MS);

      const after = await executeGmpCommand(groupId, 'get_credentials', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const updated = ensureArray(after?.get_credentials_response?.credential).find((c: any) => c['@_id'] === credentialId);
      check(updated, 'updated credential must still be found by get_credentials');
      check(updated.name === newName, `credential name must be updated (got ${JSON.stringify(updated.name)})`);
      check(updated.login === newLogin, `credential login must be updated (got ${JSON.stringify(updated.login)})`);
      check(updated.comment === newComment, `credential comment must be updated (got ${JSON.stringify(updated.comment)})`);
      check(updated.type === current.type, 'credential type must be carried over unchanged (save_credential does not accept type changes)');
    }

    // ── Target: create, then exercise updateTarget's save_target ─────────────
    // ── field-carryover + credential-attach logic. ────────────────────────────
    console.log('Creating throwaway target...');
    {
      const hosts = validateHosts('10.255.255.253');
      check(hosts, 'throwaway target host must pass the private-range validator');
      const params: Record<string, string> = {
        ...OPENVAS_DEFAULT_TARGET_PARAMS,
        name: `${NAME_PREFIX}_target`,
        hosts: hosts!,
        comment: 'created by openvasEditFlows.selftest.ts — safe to delete',
        port_list_id: OPENVAS_DEFAULT_PORT_LIST_ID,
        ssh_credential_id: '0',
        smb_credential_id: '0',
      };
      const result = await executeGmpPost(groupId, 'create_target', params, cfg, EXTERNAL_API_TIMEOUT_MS);
      targetId = result?.action_result?.id || result?.create_target_response?.['@_id'];
      check(targetId, 'create_target must return a resolvable id');
    }

    console.log('Updating target (name/comment, attach ssh credential) via save_target...');
    {
      const allTargets = await executeGmpCommand(groupId, 'get_targets', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const current = ensureArray(allTargets?.get_targets_response?.target).find((t: any) => t['@_id'] === targetId);
      check(current, 'freshly created target must be found by get_targets');
      check(String(current.in_use) !== '1', 'freshly created, never-scanned target must not be in_use');

      const newName = `${NAME_PREFIX}_target_renamed`;
      const newComment = 'updated by openvasEditFlows.selftest.ts';
      const params: Record<string, string> = {
        target_id: targetId!,
        name: newName,
        hosts: current.hosts,
        exclude_hosts: '',
        comment: newComment,
        port_list_id: current.port_list?.['@_id'] || OPENVAS_DEFAULT_PORT_LIST_ID,
        ssh_credential_id: credentialId!, // exercise the credential-attach path
        smb_credential_id: current.smb_credential?.['@_id'] || '0',
        ssh_elevate_credential_id: '0',
        esxi_credential_id: '0',
        reverse_lookup_only: '0',
        reverse_lookup_unify: '0',
        'alive_tests:': 'Scan Config Default',
        port: '22',
        target_source: 'manual',
        target_exclude_source: 'manual',
        allow_simultaneous_ips: '1',
        hosts_ordering: '',
      };
      await executeGmpPost(groupId, 'save_target', params, cfg, EXTERNAL_API_TIMEOUT_MS);

      const after = await executeGmpCommand(groupId, 'get_targets', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const updated = ensureArray(after?.get_targets_response?.target).find((t: any) => t['@_id'] === targetId);
      check(updated, 'updated target must still be found by get_targets');
      check(updated.name === newName, `target name must be updated (got ${JSON.stringify(updated.name)})`);
      check(updated.comment === newComment, `target comment must be updated (got ${JSON.stringify(updated.comment)})`);
      check(
        updated.ssh_credential?.['@_id'] === credentialId,
        `target ssh_credential_id must be attached (got ${JSON.stringify(updated.ssh_credential?.['@_id'])}, expected ${credentialId})`,
      );
    }

    // ── Task: create against the target above, then exercise updateTask's ────
    // ── save_task field-carryover + isNew branch (never-run task). ────────────
    console.log('Looking up a usable scan config (get_configs, family_count > 0)...');
    let configId: string | undefined;
    {
      const result = await executeGmpCommand(groupId, 'get_configs', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const usable = ensureArray(result?.get_configs_response?.config)
        .find((c: any) => parseInt(c.family_count?.['#text'] ?? c.family_count ?? '0', 10) > 0);
      configId = usable?.['@_id'];
      check(configId, 'at least one usable scan config (family_count > 0) must exist on this GVM instance');
    }

    console.log('Creating throwaway task...');
    {
      const params: Record<string, string> = {
        ...OPENVAS_DEFAULT_TASK_PARAMS,
        name: `${NAME_PREFIX}_task`,
        target_id: targetId!,
        config_id: configId!,
        scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
        comment: 'created by openvasEditFlows.selftest.ts — safe to delete, never started',
      };
      const result = await executeGmpPost(groupId, 'create_task', params, cfg, EXTERNAL_API_TIMEOUT_MS);
      taskId = result?.action_result?.id || result?.create_task_response?.['@_id'];
      check(taskId, 'create_task must return a resolvable id');
    }

    console.log('Updating task (name/comment) via save_task, exercising the isNew branch...');
    {
      const allTasks = await executeGmpCommand(groupId, 'get_tasks', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const current = ensureArray(allTasks?.get_tasks_response?.task).find((t: any) => t['@_id'] === taskId);
      check(current, 'freshly created task must be found by get_tasks');
      check(current.status === 'New', 'freshly created, never-started task must have status "New"');

      const isNew = current.status === 'New';
      const currentTargetId = current.target?.['@_id'] ?? '0';
      const currentConfigId = current.config?.['@_id'] ?? '0';
      const currentScannerId = current.scanner?.['@_id'] ?? '0';
      const newName = `${NAME_PREFIX}_task_renamed`;
      const newComment = 'updated by openvasEditFlows.selftest.ts';

      const params: Record<string, string> = {
        task_id: taskId!,
        name: newName,
        comment: newComment,
        target_id: isNew ? currentTargetId : '0',
        config_id: isNew ? currentConfigId : '0',
        scanner_id: isNew ? currentScannerId : '0',
        schedule_id: '0',
        schedule_periods: '0',
        in_assets: '1',
        apply_overrides: '1',
        min_qod: '70',
        alterable: '0',
        auto_delete: 'no',
        auto_delete_data: '5',
        max_checks: '4',
        max_hosts: '20',
        source_iface: '',
        hosts_ordering: '',
      };
      await executeGmpPost(groupId, 'save_task', params, cfg, EXTERNAL_API_TIMEOUT_MS);

      const after = await executeGmpCommand(groupId, 'get_tasks', cfg, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      const updated = ensureArray(after?.get_tasks_response?.task).find((t: any) => t['@_id'] === taskId);
      check(updated, 'updated task must still be found by get_tasks');
      check(updated.name === newName, `task name must be updated (got ${JSON.stringify(updated.name)})`);
      check(updated.comment === newComment, `task comment must be updated (got ${JSON.stringify(updated.comment)})`);
      check(
        updated.target?.['@_id'] === targetId,
        'task target_id must be unchanged after an update that did not request a target change',
      );
    }

    console.log(`openvasEditFlows.selftest: all ${checks} checks passed`);
  } finally {
    // ── Cleanup: best-effort, in dependency order (task before target/credential, ──
    // ── target before credential), regardless of pass/fail above. ───────────────
    if (taskId) {
      try {
        await executeGmpPost(groupId, 'delete_task', { task_id: taskId }, cfg, EXTERNAL_API_TIMEOUT_MS);
        console.log(`Cleaned up throwaway task ${taskId}`);
      } catch (err) {
        console.error(`WARNING: failed to clean up throwaway task ${taskId} — delete it manually in GVM.`, err);
      }
    }
    if (targetId) {
      try {
        await executeGmpPost(groupId, 'delete_target', { target_id: targetId }, cfg, EXTERNAL_API_TIMEOUT_MS);
        console.log(`Cleaned up throwaway target ${targetId}`);
      } catch (err) {
        console.error(`WARNING: failed to clean up throwaway target ${targetId} — delete it manually in GVM.`, err);
      }
    }
    if (credentialId) {
      try {
        await executeGmpPost(groupId, 'delete_credential', { credential_id: credentialId }, cfg, EXTERNAL_API_TIMEOUT_MS);
        console.log(`Cleaned up throwaway credential ${credentialId}`);
      } catch (err) {
        console.error(`WARNING: failed to clean up throwaway credential ${credentialId} — delete it manually in GVM.`, err);
      }
    }
  }
}

main().catch((err) => {
  console.error('openvasEditFlows.selftest FAILED:', err);
  process.exit(1);
});
