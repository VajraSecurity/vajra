/**
 * Self-contained test for patchPackageValidation.ts — the per-package
 * upgrade request-shape validation used by applyPatchUpgrade
 * (controllers/nodes/patch_management.ts) for mode:'packages' requests.
 * No test framework required:
 *
 *   node_modules/.bin/ts-node src/test/utils/patchPackageValidation.selftest.ts
 *
 * Imports ONLY the pure module, never controllers/nodes/patch_management.ts
 * directly — that file imports dbSourceConnection from ../../index, and
 * index.ts has a top-level bootstrap IIFE that connects to Postgres and
 * starts the real server, which a plain ts-node selftest must never trigger
 * (same rationale as patchBundle.ts's/patchPackageValidation.ts's header
 * comments).
 *
 * Covers validatePackagesByHost's shape/charset checks — the FIRST of two
 * validation layers applyPatchUpgrade applies to mode:'packages' requests
 * (the second, a subset-check against patch_available_updates, is a live DB
 * query and isn't covered here — see this file's header note on scope).
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { MAX_PACKAGES_PER_HOST, validatePackagesByHost } from '../../utils/patchPackageValidation';

function main() {
  const hosts = ['host-a', 'host-b'];

  // ── Happy path ─────────────────────────────────────────────────────────
  assert.deepStrictEqual(
    validatePackagesByHost(hosts, { 'host-a': ['curl', 'libc6'], 'host-b': ['python3.11'] }),
    { 'host-a': ['curl', 'libc6'], 'host-b': ['python3.11'] },
    'valid per-host package lists pass through unchanged',
  );

  // Duplicate names within one host are de-duplicated.
  assert.deepStrictEqual(
    validatePackagesByHost(['host-a'], { 'host-a': ['curl', 'curl', 'libc6'] }),
    { 'host-a': ['curl', 'libc6'] },
    'duplicate package names for the same host are de-duplicated',
  );

  // ── Shape rejections ──────────────────────────────────────────────────
  assert.strictEqual(validatePackagesByHost(hosts, null), null, 'null input rejected');
  assert.strictEqual(validatePackagesByHost(hosts, []), null, 'array input rejected (must be a host->list map)');
  assert.strictEqual(validatePackagesByHost(hosts, {}), null, 'missing entry for a targeted host rejected');
  assert.strictEqual(
    validatePackagesByHost(hosts, { 'host-a': ['curl'] }),
    null,
    'entry present for only SOME targeted hosts is rejected — every host in `hosts` must have a list',
  );
  assert.strictEqual(
    validatePackagesByHost(hosts, { 'host-a': [], 'host-b': ['curl'] }),
    null,
    'empty package list for a host is rejected',
  );

  // ── Per-host cap ──────────────────────────────────────────────────────
  const tooMany = Array.from({ length: MAX_PACKAGES_PER_HOST + 1 }, (_, i) => `pkg${i}`);
  assert.strictEqual(
    validatePackagesByHost(['host-a'], { 'host-a': tooMany }),
    null,
    `package list exceeding MAX_PACKAGES_PER_HOST (${MAX_PACKAGES_PER_HOST}) is rejected`,
  );
  const exactlyMax = Array.from({ length: MAX_PACKAGES_PER_HOST }, (_, i) => `pkg${i}`);
  assert.ok(
    validatePackagesByHost(['host-a'], { 'host-a': exactlyMax }) !== null,
    'package list exactly at MAX_PACKAGES_PER_HOST is accepted',
  );

  // ── Charset / flag-injection rejection — must mirror the Go agent's ─────
  // ── packageNameRe (upgrade_packages.go) exactly, same fixture set as ────
  // ── that file's TestPackageNameRe_RejectsFlagInjection. ─────────────────
  const badNames = ['-y', '--reinstall', '; rm -rf /', 'pkg;rm', 'pkg rm', '', 'a'.repeat(129)];
  for (const bad of badNames) {
    assert.strictEqual(
      validatePackagesByHost(['host-a'], { 'host-a': [bad] }),
      null,
      `package name ${JSON.stringify(bad)} must be rejected`,
    );
  }
  const goodNames = ['curl', 'python3.11', 'libc6:amd64', 'libssl-dev', 'a', 'a'.repeat(128)];
  for (const good of goodNames) {
    assert.ok(
      validatePackagesByHost(['host-a'], { 'host-a': [good] }) !== null,
      `package name ${JSON.stringify(good)} must be accepted`,
    );
  }

  // ── Non-string entries in a package list are rejected, not coerced ──────
  assert.strictEqual(
    validatePackagesByHost(['host-a'], { 'host-a': [123, 'curl'] }),
    null,
    'non-string package list entries are rejected rather than coerced to a string',
  );

  console.log('patchPackageValidation.selftest: all checks passed');
}

main();
