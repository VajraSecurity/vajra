/**
 * Shared ECDSA signing logic for Patch Bundle manifests — used by both the
 * offline CLI (scripts/sign-patch-bundle.ts) and the server-side build+sign
 * endpoint (controllers/nodes/patch_bundles_build.ts). Extracted out of the
 * CLI so there is exactly one signing implementation, not two that could
 * silently drift apart — the CLI's cmdSign is now a thin wrapper around this.
 *
 * ACCEPTED RISK (see patch_bundles_build.ts's header comment for the full
 * note and required mitigations): calling this function from a
 * server-resident process means the private key is, by definition, no
 * longer confined to an offline-only machine for that caller. This module
 * itself has no opinion on WHERE the private key lives or how it's loaded —
 * it only implements the signing operation, byte-for-byte identical to what
 * the original offline-only CLI always did.
 */
import crypto from 'crypto';
import { PATCH_BUNDLE_SCHEMA, PatchBundleManifest, SignedPatchBundle, verifySignedPatchBundle } from './patchBundle';
import { getLogger } from './logger';

const logger = getLogger('patch.bundleSign');

/**
 * Fills in schema/bundle_id/released_at if omitted, computes ASN.1 DER
 * ECDSA-over-SHA-256 over the exact serialized JSON bytes, and returns the
 * signed-manifest wire wrapper `{payload, signature}` alongside the parsed,
 * shape-validated manifest it was derived from (so callers that need both —
 * e.g. to build a DB row — don't have to re-verify their own output).
 *
 * Self-verifies before returning: re-derives the public key from the
 * private key and runs the real verifySignedPatchBundle (the exact function
 * uploadPatchBundle's fail-closed gate uses) against its own output — a bug
 * in this function can never silently produce a signed manifest that the
 * upload path would itself reject.
 */
export function signPatchBundleManifest(
  manifest: Partial<PatchBundleManifest>,
  privateKeyPem: string,
): { signed: SignedPatchBundle; manifest: PatchBundleManifest } {
  if (manifest.schema === undefined) manifest.schema = PATCH_BUNDLE_SCHEMA;
  if (!manifest.bundle_id) manifest.bundle_id = crypto.randomUUID();
  if (!manifest.released_at) manifest.released_at = new Date().toISOString();

  // Sign over the EXACT bytes we're about to base64-carry — signer and
  // verifier must never disagree on canonicalisation (see patchBundle.ts).
  const payload = Buffer.from(JSON.stringify(manifest), 'utf-8');

  // The sole HTTP caller (patch_bundles_build.ts's buildPatchBundle) catches
  // this function's throw only to turn it into a 400 response — it logs
  // nothing of its own for this specific rejection, same situation
  // patchBundle.ts's header comments call out for its own
  // upload-side verification. Without a log here, a bad private key, a
  // self-verification bug, or a manifest that fails its own shape check
  // right after being built would be visible only in the client's HTTP
  // response, never in the server logs.
  try {
    // dsaEncoding:'der' -> ASN.1 SEQUENCE{r,s}, identical to Go's
    // ecdsa.SignASN1 output (verified by round-trip; see
    // sign-patch-bundle.ts's header comment).
    const signature = crypto.sign(null, payload, { key: privateKeyPem, dsaEncoding: 'der' });

    const signed: SignedPatchBundle = {
      payload: payload.toString('base64'),
      signature: signature.toString('base64'),
    };

    const pubKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }) as string;
    const verified = verifySignedPatchBundle(JSON.stringify(signed), pubKeyPem);

    logger.info(
      { bundleId: verified.bundle_id, version: verified.version, family: verified.family },
      'Signed patch bundle manifest',
    );

    return { signed, manifest: verified };
  } catch (err) {
    logger.error({ err, bundleId: manifest.bundle_id, family: manifest.family }, 'Failed to sign patch bundle manifest');
    throw err;
  }
}
