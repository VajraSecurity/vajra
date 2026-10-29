/**
 * Self-contained test for the server-side bundle-build pipeline's pure
 * helpers (utils/patchBundleBuildHelpers.ts). No test framework required —
 * run with ts-node (or `npm run test:patch-bundle-build`):
 *
 *   node_modules/.bin/ts-node src/test/utils/patchBundleBuild.selftest.ts
 *
 * Covers two things:
 *   1. Path-traversal / symlink-escape rejection in resolveWithinRoot — must
 *      reject BEFORE any filesystem read beyond the check itself.
 *   2. Metadata extraction against a real .deb (skips gracefully, not
 *      failing, if dpkg-deb/rpm aren't present in whatever environment runs
 *      this — same convention as this repo's other environment-dependent
 *      selftests).
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  BARE_DIR_NAME_RE,
  BinaryMissingError,
  CHANNEL_RE,
  extractDebMetadata,
  extractRpmMetadata,
  findSymlinks,
  OS_MATCH_RE,
  resolveWithinRoot,
  sha256File,
  VERSION_FIELD_RE,
} from '../../utils/patchBundleBuildHelpers';

function expectRejects(p: Promise<unknown>, label: string): Promise<void> {
  return p.then(
    () => assert.fail(`expected rejection: ${label}`),
    () => {},
  );
}

function hasBinary(name: string): boolean {
  try {
    execSync(`command -v ${name}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

async function main() {
  let checks = 0;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patch-bundle-build-selftest-'));

  try {
    // ── resolveWithinRoot: path-traversal / containment ──────────────────
    const root = path.join(tmp, 'staging');
    const legit = path.join(root, 'batch1');
    fs.mkdirSync(legit, { recursive: true });
    fs.writeFileSync(path.join(legit, 'a.txt'), 'hello');

    // 1. A legitimate bare subdirectory name resolves correctly.
    const resolved = await resolveWithinRoot(root, 'batch1');
    assert.strictEqual(fs.realpathSync(resolved), fs.realpathSync(legit));
    checks++;

    // 2. Embedded '..' components escaping the root must be rejected.
    // (realpath on a nonexistent target throws ENOENT before the containment
    // check even runs, which is itself a correct rejection — either failure
    // mode means "did not resolve inside the root".)
    await expectRejects(resolveWithinRoot(root, '../outside'), 'embedded ..');
    checks++;

    // 3. A deeper traversal attempt.
    fs.mkdirSync(path.join(tmp, 'secret'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'secret', 'passwords.txt'), 'hunter2');
    await expectRejects(resolveWithinRoot(root, '../secret'), 'traversal to sibling directory');
    checks++;

    // 4. A symlink planted INSIDE the root pointing OUTSIDE it must be
    // rejected — the exact "containment via realpath, not string prefix
    // matching" case this helper exists for (mirrors bundle_extract.go's
    // agent-side symlink-escape defense).
    const outsideTarget = path.join(tmp, 'outside-target');
    fs.mkdirSync(outsideTarget, { recursive: true });
    fs.writeFileSync(path.join(outsideTarget, 'exfil.txt'), 'should not be reachable');
    const escapeLink = path.join(root, 'escape');
    fs.symlinkSync(outsideTarget, escapeLink, 'dir');
    await expectRejects(resolveWithinRoot(root, 'escape'), 'symlink escaping the staging root');
    checks++;

    // 5. A name that is itself just "." resolves to the root (not a
    // rejection) — sanity check that the containment logic's `===` root
    // case doesn't false-positive-reject the root itself.
    const dot = await resolveWithinRoot(root, '.');
    assert.strictEqual(fs.realpathSync(dot), fs.realpathSync(root));
    checks++;

    // ── sha256File ─────────────────────────────────────────────────────
    // 6. Known content must hash to the known-correct SHA-256.
    const hashTarget = path.join(tmp, 'hashme.txt');
    fs.writeFileSync(hashTarget, 'abc');
    const digest = await sha256File(hashTarget);
    // sha256("abc") — a standard, independently-verifiable test vector.
    assert.strictEqual(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    checks++;

    // ── shape regexes (cheap, but these are the same patterns
    // patch_bundles_build.ts gates every request field on) ────────────────
    // 7. BARE_DIR_NAME_RE must reject traversal-shaped and slash-containing
    // names outright, before resolveWithinRoot is ever reached in the real
    // handler (defense in depth: two independent layers, not one).
    assert.ok(!BARE_DIR_NAME_RE.test('..'));
    assert.ok(!BARE_DIR_NAME_RE.test('../etc'));
    assert.ok(!BARE_DIR_NAME_RE.test('a/b'));
    assert.ok(!BARE_DIR_NAME_RE.test('/etc'));
    assert.ok(BARE_DIR_NAME_RE.test('batch1'));
    assert.ok(BARE_DIR_NAME_RE.test('batch-1.2_3'));
    checks++;

    // 8. OS_MATCH_RE / CHANNEL_RE / VERSION_FIELD_RE accept their documented
    // shapes and reject empty/malformed input.
    assert.ok(OS_MATCH_RE.test('ubuntu-22.04'));
    assert.ok(!OS_MATCH_RE.test(''));
    assert.ok(CHANNEL_RE.test('stable'));
    assert.ok(!CHANNEL_RE.test(''));
    assert.ok(VERSION_FIELD_RE.test('2024-07-20.1'));
    assert.ok(!VERSION_FIELD_RE.test(''));
    checks++;

    // ── findSymlinks ──────────────────────────────────────────────────
    // 9. A mix of regular files and a symlink (even one pointing at a
    // legitimate, readable target) must have the symlink flagged — lstat,
    // not stat, is what makes this correct.
    const symlinkBatch = path.join(tmp, 'symlink-batch');
    fs.mkdirSync(symlinkBatch, { recursive: true });
    fs.writeFileSync(path.join(symlinkBatch, 'real.deb'), 'regular file content');
    fs.symlinkSync(hashTarget, path.join(symlinkBatch, 'linked.deb'));
    const found = await findSymlinks(symlinkBatch, ['real.deb', 'linked.deb']);
    assert.deepStrictEqual(found, ['linked.deb']);
    checks++;

    // 10. No symlinks present -> empty result.
    const noneFound = await findSymlinks(symlinkBatch, ['real.deb']);
    assert.deepStrictEqual(noneFound, []);
    checks++;

    // ── metadata extraction against a real .deb ──────────────────────────
    // 11. dpkg-deb path: build a minimal real .deb with dpkg-deb itself (if
    // available) and confirm extractDebMetadata's parsed name/version/arch
    // match what we built it with. Skips gracefully (not a failure) when
    // dpkg-deb isn't present, matching this repo's convention for
    // environment-dependent tests.
    if (hasBinary('dpkg-deb')) {
      const pkgRoot = path.join(tmp, 'pkgroot');
      const debianDir = path.join(pkgRoot, 'DEBIAN');
      fs.mkdirSync(debianDir, { recursive: true });
      fs.writeFileSync(
        path.join(debianDir, 'control'),
        'Package: vajra-selftest-pkg\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: test <test@example.test>\nDescription: selftest fixture\n',
      );
      const debOut = path.join(tmp, 'built.deb');
      execSync(`dpkg-deb --build --root-owner-group ${JSON.stringify(pkgRoot)} ${JSON.stringify(debOut)}`, { stdio: 'ignore' });
      const meta = await extractDebMetadata(debOut);
      assert.strictEqual(meta.name, 'vajra-selftest-pkg');
      assert.strictEqual(meta.version, '1.2.3');
      assert.strictEqual(meta.arch, 'amd64');
      checks++;

      // 12. A nonexistent file must throw a real error, not silently
      // succeed with garbage metadata.
      await expectRejects(extractDebMetadata(path.join(tmp, 'does-not-exist.deb')), 'dpkg-deb on missing file');
      checks++;
    } else {
      console.log('patchBundleBuild.selftest: dpkg-deb not present — skipping deb metadata checks');
    }

    // 13. rpm path: same shape of check, skipped gracefully when `rpm`
    // isn't installed (true in most non-RHEL dev environments, including
    // this one) — BinaryMissingError must be the specific error thrown, not
    // some incidental fs/exec error, so callers can 503 with a clear message.
    if (hasBinary('rpm')) {
      await expectRejects(extractRpmMetadata(path.join(tmp, 'does-not-exist.rpm')), 'rpm on missing file');
      checks++;
    } else {
      let threw = false;
      try {
        await extractRpmMetadata(path.join(tmp, 'whatever.rpm'));
      } catch (e) {
        threw = e instanceof BinaryMissingError;
      }
      assert.ok(threw, 'extractRpmMetadata must throw BinaryMissingError when rpm is not installed');
      console.log('patchBundleBuild.selftest: rpm not present — confirmed BinaryMissingError is thrown instead');
      checks++;
    }

    console.log(`patchBundleBuild.selftest: all ${checks} checks passed`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
