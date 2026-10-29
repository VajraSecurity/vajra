#!/usr/bin/env -S node_modules/.bin/ts-node
/**
 * vajra-patch-bundle-sign — OFFLINE signer for Vajra Patch Bundles.
 *
 * Mirrors the Linux agent: cmd/vajra-release-sign (the agent-update signer) in shape
 * and trust model, but is a completely separate tool with its own key pair:
 * compromising the patch-bundle-signing key must never let an attacker forge an
 * agent-update manifest, or the reverse. It is not wired into any running server
 * code path; an operator runs it on a separate, offline machine and uploads only
 * the resulting signed-manifest JSON via `POST /api/patch/bundles`. The private
 * key must never touch the internet-facing backend.
 *
 * Dependency surface, so the offline signer stays auditable: this file imports
 * only node crypto/fs/path, utils/patchBundle.ts (pure, no dependencies beyond
 * the logger and two consts modules), and utils/patchBundleSign.ts, which also
 * pulls in the pino-backed logger. No express, no TypeORM, no server bootstrap.
 * Keep it that way — anything added here runs on the key-holding machine.
 *
 * Cross-language signature format: this tool signs with Node's
 * `crypto.sign(null, payload, { key, dsaEncoding: 'der' })`, which, like the
 * `crypto.verify('sha256', ...)` server-side verifier in patchBundle.ts,
 * produces an ASN.1 SEQUENCE{r,s} DER signature — the same ECDSA-Sig-Value
 * encoding Go's `ecdsa.SignASN1`/`VerifyASN1` use in
 * the Linux agent: updater/manifest.go. Keys travel as PKIX/SPKI public PEM and
 * PKCS#8 private PEM, which Go's x509 marshallers also emit, so no format
 * conversion is needed in either direction.
 *
 * Subcommands:
 *
 *   keygen [--out-dir DIR] [--force]
 *     Generate a P-256 signing key pair if one doesn't already exist at
 *     DIR/patch_bundle_sign.key (PKCS#8 PEM, mode 0600) and
 *     DIR/patch_bundle_verify.pem (PKIX/SPKI PEM, mode 0644 — provision this
 *     on the backend at the path pointed to by PATCH_BUNDLE_VERIFY_KEY_PATH,
 *     default backend/keys/patch_bundle_verify.pem). Refuses to overwrite an
 *     existing key pair unless --force is given.
 *
 *   sign --key PRIVATE_KEY_PEM --manifest MANIFEST_JSON [--out FILE]
 *     Reads an unsigned manifest JSON file (see PatchBundleManifest in
 *     patchBundle.ts for the required shape), fills in schema/bundle_id/
 *     released_at if omitted, validates its shape, computes
 *     ASN.1 DER ECDSA-over-SHA-256 over the exact serialized JSON bytes, and
 *     writes the signed-manifest wire wrapper `{payload, signature}` (stdout
 *     or -out) — ready to POST to /api/patch/bundles.
 *
 *   verify --pub PUBLIC_KEY_PEM --in SIGNED_MANIFEST_JSON
 *     Verifies a signed manifest against a public key (offline sanity check
 *     before uploading), using the exact same verifier the backend uses.
 *
 * Usage:
 *   cd backend
 *   node_modules/.bin/ts-node src/scripts/sign-patch-bundle.ts keygen --out-dir keys
 *   node_modules/.bin/ts-node src/scripts/sign-patch-bundle.ts sign \
 *     --key keys/patch_bundle_sign.key --manifest my-bundle.json --out signed-bundle.json
 *   node_modules/.bin/ts-node src/scripts/sign-patch-bundle.ts verify \
 *     --pub keys/patch_bundle_verify.pem --in signed-bundle.json
 *
 * Or via the package.json convenience script:
 *   npm run patch-bundle:sign -- keygen --out-dir keys
 *
 * This file lives under src/ only so it falls under tsconfig's rootDir for
 * `npm run build` and typecheck; it is never imported by the server's own
 * startup path.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { PatchBundleManifest, verifySignedPatchBundle } from '../utils/patchBundle';
import { signPatchBundleManifest } from '../utils/patchBundleSign';

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

function usage(exitCode: number): never {
  const stream = exitCode === 0 ? process.stdout : process.stderr;
  stream.write(
    `vajra-patch-bundle-sign — offline Vajra Patch Bundle signer

  keygen  [--out-dir DIR] [--force]
  sign    --key K --manifest FILE [--out FILE]
  verify  --pub P --in FILE
`,
  );
  process.exit(exitCode);
}

function cmdKeygen(args: Record<string, string | boolean>): void {
  const outDir = typeof args['out-dir'] === 'string' ? (args['out-dir'] as string) : '.';
  const force = args.force === true;
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

  const privPath = path.join(outDir, 'patch_bundle_sign.key');
  const pubPath = path.join(outDir, 'patch_bundle_verify.pem');

  if (!force && (fs.existsSync(privPath) || fs.existsSync(pubPath))) {
    throw new Error(
      `refusing to overwrite existing key material at ${privPath} / ${pubPath} — pass --force to regenerate (this invalidates every previously signed bundle for agents that don't yet trust the new key)`,
    );
  }

  // P-256, PKCS8 private / PKIX(SPKI) public PEM — matches
  // the Linux agent: updater/keys.go's GenerateSigningKey +
  // MarshalPrivateKeyPEM/MarshalPublicKeyPEM exactly (see this file's header
  // comment for the verified cross-language compatibility).
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });

  process.stdout.write(`wrote ${privPath} (private — keep offline, mode 0600)\n`);
  process.stdout.write(
    `wrote ${pubPath} (public — provision on the backend at the path pointed to by PATCH_BUNDLE_VERIFY_KEY_PATH, e.g. backend/keys/patch_bundle_verify.pem)\n`,
  );
}

function cmdSign(args: Record<string, string | boolean>): void {
  const keyPath = args.key;
  const manifestPath = args.manifest;
  const outPath = args.out;
  if (typeof keyPath !== 'string' || typeof manifestPath !== 'string') {
    throw new Error('sign requires --key and --manifest');
  }

  const privateKey = fs.readFileSync(keyPath, 'utf-8');
  const raw = fs.readFileSync(manifestPath, 'utf-8');
  let manifest: Partial<PatchBundleManifest>;
  try {
    manifest = JSON.parse(raw);
  } catch (e: any) {
    throw new Error(`manifest file is not valid JSON: ${e.message}`, { cause: e });
  }

  // Fills in fields an operator commonly leaves to the tool (schema/
  // bundle_id/released_at), signs, and self-verifies before ever writing/
  // printing anything, so a broken manifest never reaches the operator's
  // "upload" step — see patchBundleSign.ts, shared with the server-side
  // build+sign endpoint so there is exactly one signing implementation.
  const { signed: signedObj, manifest: verified } = signPatchBundleManifest(manifest, privateKey);
  const signed = JSON.stringify(signedObj);

  if (outPath && typeof outPath === 'string') {
    fs.writeFileSync(outPath, signed + '\n', { mode: 0o644 });
    process.stderr.write(
      `signed bundle ${verified.bundle_id} (${verified.family}, ${verified.version}, ${verified.packages.length} packages) -> ${outPath}\n`,
    );
  } else {
    process.stdout.write(signed + '\n');
  }
}

function cmdVerify(args: Record<string, string | boolean>): void {
  const pubPath = args.pub;
  const inPath = args.in;
  if (typeof pubPath !== 'string' || typeof inPath !== 'string') {
    throw new Error('verify requires --pub and --in');
  }
  const publicKeyPem = fs.readFileSync(pubPath, 'utf-8');
  const signedJson = fs.readFileSync(inPath, 'utf-8');
  const m = verifySignedPatchBundle(signedJson, publicKeyPem);
  process.stdout.write(
    `OK: bundle_id=${m.bundle_id} version=${m.version} family=${m.family} os_match=${m.os_match} channel=${m.channel} packages=${m.packages.length}\n`,
  );
}

function main(): void {
  const [, , sub, ...rest] = process.argv;
  if (!sub) usage(2);
  const args = parseArgs(rest);
  try {
    switch (sub) {
      case 'keygen':
        return cmdKeygen(args);
      case 'sign':
        return cmdSign(args);
      case 'verify':
        return cmdVerify(args);
      case '-h':
      case '--help':
      case 'help':
        usage(0);
        return;
      default:
        process.stderr.write(`unknown subcommand ${JSON.stringify(sub)}\n\n`);
        usage(2);
    }
  } catch (e: any) {
    process.stderr.write(`error: ${e.message}\n`);
    process.exit(1);
  }
}

main();
