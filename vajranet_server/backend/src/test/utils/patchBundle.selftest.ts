/**
 * Self-contained test for patch-bundle manifest verification. No test
 * framework required — run with ts-node (or `npm run test:patch-bundle`):
 *
 *   node_modules/.bin/ts-node src/test/utils/patchBundle.selftest.ts
 *
 * Signs manifests the exact way backend/src/scripts/sign-patch-bundle.ts does
 * (ECDSA over SHA-256 of the raw manifest JSON bytes, DER signature) and
 * asserts verifySignedPatchBundle accepts valid ones and rejects every
 * tampering. Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import crypto from 'crypto';
import { verifySignedPatchBundle, PATCH_BUNDLE_SCHEMA, MAX_PACKAGES_PER_BUNDLE } from '../../utils/patchBundle';
import { signPatchBundleManifest } from '../../utils/patchBundleSign';

function makeKeys() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// Mirrors sign-patch-bundle.ts's cmdSign: sign over SHA-256 of the exact
// payload bytes, DER encoding.
function sign(manifestObj: any, privateKeyPem: string): string {
  const payload = Buffer.from(JSON.stringify(manifestObj), 'utf-8');
  const signature = crypto.sign(null, payload, { key: privateKeyPem, dsaEncoding: 'der' });
  return JSON.stringify({
    payload: payload.toString('base64'),
    signature: signature.toString('base64'),
  });
}

function expectThrows(fn: () => void, label: string) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  assert.strictEqual(threw, true, `expected rejection: ${label}`);
}

function main() {
  const { publicKey, privateKey } = makeKeys();
  const other = makeKeys();

  const base = {
    schema: PATCH_BUNDLE_SCHEMA,
    bundle_id: '11111111-2222-4333-8444-555555555555',
    version: '2024-07-20.1',
    family: 'deb',
    os_match: 'ubuntu-22.04',
    channel: 'stable',
    packages: [
      { name: 'curl', version: '7.81.0-1ubuntu1.15', arch: 'amd64', filename: 'curl_7.81.0-1ubuntu1.15_amd64.deb', sha256: 'a'.repeat(64) },
      { name: 'openssl', version: '3.0.2-0ubuntu1.15', arch: 'amd64', filename: 'openssl_3.0.2-0ubuntu1.15_amd64.deb', sha256: 'b'.repeat(64) },
    ],
    archive_url: 'https://mirror.example.test/bundles/b1.tar.gz',
    archive_sha256: 'c'.repeat(64),
    archive_size: 12345,
    released_at: new Date().toISOString(),
  };

  // 1. Valid manifest verifies and round-trips its fields.
  const good = sign(base, privateKey);
  const m = verifySignedPatchBundle(good, publicKey);
  assert.strictEqual(m.version, '2024-07-20.1');
  assert.strictEqual(m.packages.length, 2);
  assert.strictEqual(m.family, 'deb');

  // 2. Wrong key must fail.
  expectThrows(() => verifySignedPatchBundle(good, other.publicKey), 'wrong key');

  // 3. Tampered payload (swap family) with the old signature must fail.
  const tampered = JSON.stringify({
    payload: Buffer.from(JSON.stringify({ ...base, family: 'rpm' }), 'utf-8').toString('base64'),
    signature: JSON.parse(good).signature,
  });
  expectThrows(() => verifySignedPatchBundle(tampered, publicKey), 'tampered payload');

  // 4. Unsupported schema must fail.
  expectThrows(() => verifySignedPatchBundle(sign({ ...base, schema: 99 }, privateKey), publicKey), 'bad schema');

  // 5. Bad family must fail.
  expectThrows(() => verifySignedPatchBundle(sign({ ...base, family: 'exe' }, privateKey), publicKey), 'bad family');

  // 6. Non-UUID bundle_id must fail.
  expectThrows(() => verifySignedPatchBundle(sign({ ...base, bundle_id: 'not-a-uuid' }, privateKey), publicKey), 'bad bundle_id');

  // 7. Empty packages array must fail.
  expectThrows(() => verifySignedPatchBundle(sign({ ...base, packages: [] }, privateKey), publicKey), 'empty packages');

  // 8. Malformed package (missing sha256) must fail.
  const badPkg = { ...base, packages: [{ name: 'curl', version: '1', arch: 'amd64', filename: 'curl.deb' }] };
  expectThrows(() => verifySignedPatchBundle(sign(badPkg, privateKey), publicKey), 'package missing sha256');

  // 9. Bad sha256 (not 64 hex chars) must fail.
  const badSha = { ...base, packages: [{ ...base.packages[0], sha256: 'zz' }] };
  expectThrows(() => verifySignedPatchBundle(sign(badSha, privateKey), publicKey), 'bad sha256');

  // 10. Package count over the cap must fail.
  const tooMany = {
    ...base,
    packages: Array.from({ length: MAX_PACKAGES_PER_BUNDLE + 1 }, (_, i) => ({
      name: `pkg${i}`,
      version: '1.0',
      arch: 'amd64',
      filename: `pkg${i}.deb`,
      sha256: 'c'.repeat(64),
    })),
  };
  expectThrows(() => verifySignedPatchBundle(sign(tooMany, privateKey), publicKey), 'too many packages');

  // 11. Invalid released_at must fail.
  expectThrows(() => verifySignedPatchBundle(sign({ ...base, released_at: 'not-a-date' }, privateKey), publicKey), 'bad released_at');

  // 12. Malformed JSON must fail.
  expectThrows(() => verifySignedPatchBundle('not json', publicKey), 'malformed json');

  // ── signPatchBundleManifest (patchBundleSign.ts) — server-side build+sign
  // path shares this exact verify function for its internal
  // self-check. See patch_bundles_build.ts's header comment for why this
  // matters: a bug here could otherwise silently produce a signed manifest
  // the upload/apply path would itself reject.

  // 13. signPatchBundleManifest's own output must verify against the public
  // key derived from the SAME private key it signed with.
  const built: Partial<any> = {
    version: '2024-07-20.2',
    family: 'deb',
    os_match: 'ubuntu-24.04',
    channel: 'stable',
    packages: base.packages,
    archive_url: 'https://mirror.example.test/bundles/b2.tar.gz',
    archive_sha256: 'd'.repeat(64),
    archive_size: 54321,
  };
  const { signed, manifest: signedManifest } = signPatchBundleManifest(built, privateKey);
  assert.strictEqual(signedManifest.family, 'deb');
  assert.strictEqual(signedManifest.version, '2024-07-20.2');
  // schema/bundle_id/released_at are auto-filled when omitted.
  assert.strictEqual(signedManifest.schema, PATCH_BUNDLE_SCHEMA);
  assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(signedManifest.bundle_id), 'auto-filled bundle_id must be a UUID');
  assert.ok(!Number.isNaN(Date.parse(signedManifest.released_at)), 'auto-filled released_at must be a valid date');
  const reVerified = verifySignedPatchBundle(JSON.stringify(signed), publicKey);
  assert.strictEqual(reVerified.bundle_id, signedManifest.bundle_id);

  // 14. Caller-supplied schema/bundle_id/released_at are preserved, not
  // overwritten.
  const withExplicitFields = signPatchBundleManifest(
    { ...built, bundle_id: '99999999-8888-4777-8666-555555555555', released_at: '2024-01-01T00:00:00.000Z' },
    privateKey,
  );
  assert.strictEqual(withExplicitFields.manifest.bundle_id, '99999999-8888-4777-8666-555555555555');
  assert.strictEqual(withExplicitFields.manifest.released_at, '2024-01-01T00:00:00.000Z');

  // 15. signPatchBundleManifest must itself reject a manifest that fails
  // shape validation (e.g. missing packages) — the internal self-check
  // (verifySignedPatchBundle) is what surfaces this, proving it actually
  // runs rather than being a no-op.
  expectThrows(() => signPatchBundleManifest({ ...built, packages: [] }, privateKey), 'sign rejects empty packages');

  // 16. Signing with one key must never verify against a different key's
  // public half (sanity check that signPatchBundleManifest doesn't leak/
  // reuse some cached key from an earlier call in this same process).
  const builtWithOtherKey = signPatchBundleManifest({ ...built, version: '2024-07-20.3' }, other.privateKey);
  expectThrows(() => verifySignedPatchBundle(JSON.stringify(builtWithOtherKey.signed), publicKey), 'built-and-signed-with-other-key must not verify against the original public key');

  console.log('patchBundle.selftest: all 16 checks passed');
}

main();
