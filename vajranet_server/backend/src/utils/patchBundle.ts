/**
 * Patch Bundle manifest schema + signature verification.
 *
 * A "Patch Bundle" is a signed, versioned snapshot of OS packages (Phase 1
 * scope: deb/rpm only) that can later be pushed to offline/air-gapped agents
 * as a fallback content source when a host's native package manager can't
 * reach a live repo (see controllers/nodes/patch_management.ts's
 * source='bundle' fallback jobs — the agent-side apply capability is a later
 * phase; this module is the server-side content pipeline for it).
 *
 * Trust model: an offline-signed manifest verified against a pinned public
 * key. It uses its OWN manifest schema and its OWN, SEPARATE ECDSA key pair —
 * compromising the patch-bundle-signing key must not let an attacker forge
 * agent-update manifests, or vice versa (different blast radius). Bundles
 * are signed OFFLINE with backend/src/scripts/sign-patch-bundle.ts; this module
 * only ever holds the PUBLIC verify key and is a pure integrity gate — same
 * wire format as SignedManifest: `{ payload: base64(json), signature:
 * base64(ASN.1 DER ECDSA-over-SHA-256 sig) }`, verified with Node's
 * crypto.verify('sha256', payload, pubKeyPem, sig), which is byte-compatible
 * with Go's ecdsa.VerifyASN1 (see sign-patch-bundle.ts's header comment for
 * the cross-language round-trip proof this claim is based on).
 *
 * Fail-closed throughout: every verification failure throws, and callers
 * (the upload endpoint) must never store a bundle whose signature didn't
 * verify.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getLogger } from './logger';
import { DEFAULT_KEYS_DIR } from '../consts/server';
import { HTTPS_URL_PATTERN } from '../consts/http';

const logger = getLogger('patch.bundle');

// The only wire schema this backend understands for patch bundles. Bump only
// on a breaking change.
export const PATCH_BUNDLE_SCHEMA = 1;

// Same pattern as PACKAGE_NAME_RE in utils/patchPackageValidation.ts, kept as a
// separate literal so this module stays dependency-free. Change both together.
const PACKAGE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9.+_:-]{0,127}$/;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$/;
const ARCH_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
// Package filenames only (e.g. "curl_7.81.0-1ubuntu1.15_amd64.deb") — never a
// path. Rejects '/' and '..' outright so nothing here can later be misused
// as a path-traversal primitive by a downstream consumer. Exported so
// patch_bundles_build.ts can sanity-check staged filenames before
// doing expensive tar/hash/sign work — validateManifestShape (below, run
// inside verifySignedPatchBundle) remains the single authoritative gate.
export const FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,254}$/;
export const SHA256_RE = /^[0-9a-f]{64}$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERSION_FIELD_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const OS_MATCH_RE = /^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$/;
const CHANNEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// Sanity cap: prevents an absurdly large manifest from being hashed/verified/
// stored. A real deb/rpm mirror snapshot rarely exceeds a few tens of
// thousands of packages; 100k gives generous headroom.
export const MAX_PACKAGES_PER_BUNDLE = 100_000;

// 'rpm' also covers zypper/SUSE (same package format). 'pacman'/'apk' added
// alongside the Go agent's matching apply_bundle support for those families
// (see the Linux agent: osupdate/apply_bundle.go's installPlanFor) — a bundle
// manifest naming either family will now actually reach and install on the
// agent, not just pass shape validation here.
export type PatchBundleFamily = 'deb' | 'rpm' | 'pacman' | 'apk';

export interface PatchBundlePackage {
  name: string;
  version: string;
  arch: string;
  filename: string;
  sha256: string;
}

export interface PatchBundleManifest {
  schema: number;
  bundle_id: string; // uuid
  version: string; // e.g. "2024-07-20.1"
  family: PatchBundleFamily;
  os_match: string; // e.g. "ubuntu-22.04", "rhel-9" — free text
  channel: string; // e.g. "stable"
  packages: PatchBundlePackage[];
  // The actual downloadable content: a single archive (tar.gz) containing
  // every file named in packages[].filename, hosted wherever the operator's
  // mirror/relay process puts it (this backend does not host it itself).
  // Contract: https-only, sha256-pinned, size-capped.
  archive_url: string; // https URL of the tar.gz archive
  archive_sha256: string; // hex sha256 of the archive bytes
  archive_size: number; // archive size in bytes (download cap)
  released_at: string; // RFC3339
  notes?: string;
}

export interface SignedPatchBundle {
  payload: string; // base64(manifest JSON bytes)
  signature: string; // base64(ASN.1 DER ECDSA signature over the payload bytes)
}

const KEY_DIR = DEFAULT_KEYS_DIR;
// Its OWN env var and its OWN default filename — a deliberately separate key
// from any other signing key (see module header).
const PATCH_BUNDLE_VERIFY_KEY_PATH =
  process.env.PATCH_BUNDLE_VERIFY_KEY_PATH || path.join(KEY_DIR, 'patch_bundle_verify.pem');

/**
 * Returns the PKIX public key PEM used to verify patch-bundle manifests —
 * the public half of the offline patch-bundle signing key produced by
 * `backend/src/scripts/sign-patch-bundle.ts keygen`. Throws if it has not been
 * provisioned, so upload fails closed rather than accepting an unverifiable
 * bundle.
 */
export function getPatchBundleVerifyKeyPem(): string {
  if (!fs.existsSync(PATCH_BUNDLE_VERIFY_KEY_PATH)) {
    throw new Error(
      `patch bundle verify key not found at ${PATCH_BUNDLE_VERIFY_KEY_PATH} — provision the public half of the offline patch-bundle signing key (see backend/src/scripts/sign-patch-bundle.ts) before uploading bundles`,
    );
  }
  return fs.readFileSync(PATCH_BUNDLE_VERIFY_KEY_PATH, 'utf-8');
}

/** True when the verify key has been provisioned (for capability reporting). */
export function patchBundleVerifyKeyAvailable(): boolean {
  return fs.existsSync(PATCH_BUNDLE_VERIFY_KEY_PATH);
}

/** Exposed for diagnostics/error messages only — not meant to be parsed. */
export function patchBundleVerifyKeyPath(): string {
  return PATCH_BUNDLE_VERIFY_KEY_PATH;
}

function assert(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message);
}

/**
 * Validates a parsed manifest payload against the schema in this file's
 * header comment. Throws with a specific message on the first violation.
 * Deliberately strict (allow-list charsets, length caps) — this is untrusted
 * input up until the signature has verified, and stays defense-in-depth
 * afterwards since it becomes stored jsonb served back over the API.
 */
function validateManifestShape(m: any): asserts m is PatchBundleManifest {
  assert(m && typeof m === 'object' && !Array.isArray(m), 'manifest payload is not a JSON object');
  assert(m.schema === PATCH_BUNDLE_SCHEMA, `unsupported manifest schema ${m.schema} (want ${PATCH_BUNDLE_SCHEMA})`);
  assert(typeof m.bundle_id === 'string' && UUID_RE.test(m.bundle_id), 'manifest bundle_id must be a UUID string');
  assert(typeof m.version === 'string' && VERSION_FIELD_RE.test(m.version), 'manifest version is missing or invalid');
  assert(
    m.family === 'deb' || m.family === 'rpm' || m.family === 'pacman' || m.family === 'apk',
    `manifest family must be "deb", "rpm", "pacman", or "apk" (got ${m.family})`,
  );
  assert(typeof m.os_match === 'string' && OS_MATCH_RE.test(m.os_match), 'manifest os_match is missing or invalid');
  assert(typeof m.channel === 'string' && CHANNEL_RE.test(m.channel), 'manifest channel is missing or invalid');
  // https-only —
  // never http, never a non-URL string an agent could misinterpret).
  assert(typeof m.archive_url === 'string' && HTTPS_URL_PATTERN.test(m.archive_url), 'manifest archive_url must be an https URL');
  assert(typeof m.archive_sha256 === 'string' && SHA256_RE.test(m.archive_sha256), 'manifest archive_sha256 must be a 64-hex-char SHA-256 digest');
  assert(Number.isInteger(m.archive_size) && m.archive_size > 0 && m.archive_size <= 20 * 1024 * 1024 * 1024, 'manifest archive_size must be a positive integer byte count (max 20GiB)');
  assert(typeof m.released_at === 'string' && !Number.isNaN(Date.parse(m.released_at)), 'manifest released_at must be a valid RFC3339 timestamp');
  if (m.notes !== undefined) {
    assert(typeof m.notes === 'string' && m.notes.length <= 2000, 'manifest notes must be a string of at most 2000 characters');
  }
  assert(Array.isArray(m.packages) && m.packages.length > 0, 'manifest packages must be a non-empty array');
  assert(m.packages.length <= MAX_PACKAGES_PER_BUNDLE, `manifest packages exceeds the ${MAX_PACKAGES_PER_BUNDLE}-package cap`);
  for (let i = 0; i < m.packages.length; i++) {
    const p = m.packages[i];
    const where = `packages[${i}]`;
    assert(p && typeof p === 'object', `${where} is not an object`);
    assert(typeof p.name === 'string' && PACKAGE_NAME_RE.test(p.name), `${where}.name is missing or invalid`);
    assert(typeof p.version === 'string' && VERSION_RE.test(p.version), `${where}.version is missing or invalid`);
    assert(typeof p.arch === 'string' && ARCH_RE.test(p.arch), `${where}.arch is missing or invalid`);
    assert(typeof p.filename === 'string' && FILENAME_RE.test(p.filename), `${where}.filename is missing or invalid`);
    assert(typeof p.sha256 === 'string' && SHA256_RE.test(p.sha256), `${where}.sha256 must be a 64-hex-char SHA-256 digest`);
  }
}

/**
 * Verifies a signed patch-bundle manifest (the `{payload, signature}` wire
 * wrapper as produced by sign-patch-bundle.ts) against the given PKIX public
 * key PEM and returns the parsed, shape-validated manifest. Throws on any
 * failure — malformed JSON, bad base64, an invalid signature, an unsupported
 * schema, or a manifest failing shape validation. Fail-closed: callers must
 * treat a throw as "do not store/serve this bundle".
 */
export function verifySignedPatchBundle(signedJson: string, publicKeyPem: string): PatchBundleManifest {
  let sm: SignedPatchBundle;
  try {
    sm = JSON.parse(signedJson);
  } catch (e: any) {
    logger.error({ err: e }, 'Signed patch bundle is not valid JSON');
    throw new Error(`signed bundle is not valid JSON: ${e.message}`, { cause: e });
  }
  if (!sm || typeof sm.payload !== 'string' || typeof sm.signature !== 'string') {
    logger.warn('Signed patch bundle is missing string payload/signature fields');
    throw new Error('signed bundle must have string payload and signature');
  }

  const payload = Buffer.from(sm.payload, 'base64');
  const signature = Buffer.from(sm.signature, 'base64');
  if (payload.length === 0 || signature.length === 0) {
    logger.warn('Signed patch bundle payload/signature failed to base64-decode');
    throw new Error('signed bundle payload/signature failed to base64-decode');
  }

  // crypto.verify('sha256', ...) hashes `payload` with SHA-256 internally and
  // verifies the DER-encoded ECDSA signature — exactly what Go's
  // ecdsa.VerifyASN1(pub, sha256(payload), sig) does. See
  // sign-patch-bundle.ts's header comment for the cross-language proof.
  const ok = crypto.verify('sha256', payload, publicKeyPem, signature);
  if (!ok) {
    // The upload endpoint (controllers/nodes/patch_bundles.ts) has no logger
    // of its own for this rejection — so this is the only place a rejected/tampered
    // bundle upload attempt would ever leave a trace in the server logs.
    logger.warn('Patch bundle manifest signature verification failed');
    throw new Error('bundle manifest signature verification failed');
  }

  let m: any;
  try {
    m = JSON.parse(payload.toString('utf-8'));
  } catch (e: any) {
    logger.error({ err: e }, 'Patch bundle manifest payload is not valid JSON');
    throw new Error(`bundle manifest payload is not valid JSON: ${e.message}`, { cause: e });
  }
  try {
    validateManifestShape(m);
  } catch (e: any) {
    logger.warn({ err: e, bundleId: m?.bundle_id, family: m?.family }, 'Patch bundle manifest failed shape validation');
    throw e;
  }
  logger.info(
    { bundleId: m.bundle_id, version: m.version, family: m.family },
    'Verified patch bundle manifest signature',
  );
  return m;
}
