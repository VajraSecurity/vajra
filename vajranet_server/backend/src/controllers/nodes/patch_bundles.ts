/**
 * Patch Bundle content pipeline — the server-side storage and serving half of
 * offline-capable Patch Management. See patch_management.ts's header comment for how a
 * 'bundle'-source patch_jobs row relates to this.
 *
 * A Patch Bundle is a signed, versioned snapshot of packages, produced
 * OFFLINE by backend/src/scripts/sign-patch-bundle.ts using its own ECDSA key
 * pair (deliberately separate from the agent-update signing key — see
 * utils/patchBundle.ts's header comment) and uploaded here as the
 * `{payload, signature}` wire wrapper the signer produces. The signature is
 * verified BEFORE anything is stored — a bad signature is fail-closed
 * rejected with 400 and never touches the database, matching the
 * philosophy of validating everything before touching the database.
 *
 * Every route here is Super-Admin-only (see routes/api/patch.ts). Unlike
 * PATCH_APPLY/PATCH_APPLY_FALLBACK, uploading a bundle does not require MFA —
 * it stores signed content for later use, it does not itself apply anything
 * to a host.
 */

import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import {
  verifySignedPatchBundle,
  getPatchBundleVerifyKeyPem,
  PatchBundleManifest,
} from '../../utils/patchBundle';
import { dispatchToAgent } from '../../websocket/node';
import { detectHostPackageFamilies } from '../../utils/patchBundleSelect';
// The MFA gate, in-flight guard, host-list validation and job-creation primitive are
// imported from patch_management.ts rather than re-derived here. Duplicating
// security-relevant logic across these files has caused drift before (patchDispatch.ts's
// BUSY_STATUSES vs findHostsInFlight's status list), so this is a deliberate departure
// from the per-controller-duplication convention requireMfa's own comment describes.
import {
  createPatchJob,
  requireMfa,
  findHostsInFlight,
  validateHostIdentifiers,
  MAX_HOSTS,
  type PerHostResult,
} from './patch_management';
import { getLogger } from '../../utils/logger';
import { PATCH_LIST_DEFAULT_ROWS, PATCH_REASON_MAX_LENGTH } from '../../consts/pagination';

const logger = getLogger('nodes.patchBundles');

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

/**
 * Inserts one already-signature-verified patch_bundles row. Shared by uploadPatchBundle
 * (operator-signed-offline upload) and patch_bundles_build.ts's build+sign endpoint so
 * the two paths cannot drift on the ON CONFLICT DO NOTHING RETURNING race-safety this
 * insert relies on. Returns null rather than throwing when the bundle_id already exists
 * — the "409, nothing written" contract both callers expect.
 *
 * `payload`/`signature` must be the ORIGINAL signed wire bytes (base64), not
 * a re-serialization of `manifest` — see createPatchJob's comment in
 * patch_management.ts on why a re-stringified manifest_json can't stand in
 * for these when the agent later re-verifies.
 */
export async function insertVerifiedPatchBundle(
  fleetDb: any,
  manifest: PatchBundleManifest,
  payload: string,
  signature: string,
  createdById: number,
  createdByEmail: string,
): Promise<{ id: number; bundle_id: string; version: string; family: string; os_match: string; channel: string; packages_count: number; created_at: string } | null> {
  const rows = await fleetDb.query(
    `INSERT INTO patch_bundles
       (bundle_id, version, family, os_match, channel, manifest_json, signature_valid, packages_count, created_by_id, created_by_email, payload, signature)
     VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11)
     ON CONFLICT (bundle_id) DO NOTHING
     RETURNING id, bundle_id, version, family, os_match, channel, packages_count, created_at`,
    [
      manifest.bundle_id,
      manifest.version,
      manifest.family,
      manifest.os_match,
      manifest.channel,
      JSON.stringify(manifest),
      manifest.packages.length,
      createdById,
      createdByEmail,
      payload,
      signature,
    ],
  );
  return rows.length > 0 ? rows[0] : null;
}

/**
 * POST /api/patch/bundles
 * Body: the signed-manifest JSON `{ payload, signature }` exactly as
 * produced by `backend/src/scripts/sign-patch-bundle.ts sign`.
 *
 * Verifies the ECDSA signature against the public key at
 * PATCH_BUNDLE_VERIFY_KEY_PATH before storing anything. On any verification
 * failure: 400, nothing is written. On success: inserts one patch_bundles
 * row and logs PATCH_BUNDLE_UPLOADED to the audit trail.
 */
export const uploadPatchBundle = async (req: Request, res: Response, next: NextFunction) => {
  let verifiedBundleId: string | null = null;
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (!jwtPayload?.id) {
      return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    }

    const { payload, signature } = req.body ?? {};
    if (typeof payload !== 'string' || typeof signature !== 'string') {
      return res.status(400).json({ status: 'Fail', message: 'Body must be the signed-manifest wrapper { payload, signature }' });
    }

    let verifyKey: string;
    try {
      verifyKey = getPatchBundleVerifyKeyPem();
    } catch (e: any) {
      // Server misconfiguration (missing/unreadable verify key), not a bad
      // request — every upload will 503 until this is fixed, so it needs to
      // be visible in logs, not just returned to the one caller who noticed.
      logger.error({ err: e }, 'Patch bundle upload unavailable: verify key could not be loaded');
      return res.status(503).json({ status: 'Fail', message: e.message });
    }

    // Integrity gate: verify the offline signature BEFORE it is ever stored.
    // Fail-closed — any error here means "reject", never "store anyway".
    let manifest: PatchBundleManifest;
    try {
      manifest = verifySignedPatchBundle(JSON.stringify({ payload, signature }), verifyKey);
      verifiedBundleId = manifest.bundle_id;
    } catch (e: any) {
      // Audit-logged so repeated bad-signature submissions — a misconfigured key, or
      // genuine tampering — leave a trace. Never logs payload/signature themselves.
      logAuditTrail({
        action: 'PATCH_BUNDLE_UPLOAD_REJECTED',
        status: 'failure',
        userId: jwtPayload.id,
        email: jwtPayload.email,
        details: { reason: e.message },
        ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
      }).catch((auditErr) => {
        logger.warn({ err: auditErr }, 'Failed to write audit trail for rejected patch bundle upload');
      });
      logger.warn({ err: e }, 'Patch bundle upload rejected: signature verification failed');
      return res.status(400).json({ status: 'Fail', message: `bundle manifest rejected: ${e.message}` });
    }

    // The manifest for a given bundle_id is immutable — re-uploading the
    // same bundle_id must be a new bundle_id/version, not an overwrite.
    // insertVerifiedPatchBundle's ON CONFLICT DO NOTHING RETURNING (not a
    // SELECT-then-INSERT check) means two concurrent uploads of the same
    // bundle_id can't both pass a check and race on the insert — the loser
    // gets a clean 409 here instead of an unhandled unique-violation
    // surfacing as a raw 500.
    //
    // Original signed-manifest wire bytes (base64) are stored verbatim —
    // see migration 008_add_patch_bundle_raw_signed.sql. Required to forward
    // a re-verifiable signed manifest to the agent's apply_bundle action
    // later; manifest_json alone can't serve this (parse→re-stringify isn't
    // guaranteed to reproduce the exact bytes the signature was computed over).
    const bundle = await insertVerifiedPatchBundle(fleetDb, manifest, payload, signature, jwtPayload.id, jwtPayload.email);
    if (!bundle) {
      // Distinct code path from the signature rejection above; logged so a
      // repeated-upload conflict leaves the same trace a rejected signature does.
      logger.warn({ bundle_id: manifest.bundle_id }, 'Patch bundle upload rejected: bundle_id already exists');
      return res.status(409).json({ status: 'Fail', message: `bundle ${manifest.bundle_id} already exists` });
    }

    logAuditTrail({
      action: 'PATCH_BUNDLE_UPLOADED',
      status: 'success',
      userId: jwtPayload.id,
      email: jwtPayload.email,
      details: {
        bundle_id: manifest.bundle_id,
        version: manifest.version,
        family: manifest.family,
        os_match: manifest.os_match,
        channel: manifest.channel,
        packages_count: manifest.packages.length,
      },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, bundle_id: manifest.bundle_id }, 'Failed to write audit trail for patch bundle upload');
    });

    logger.info({ bundle_id: manifest.bundle_id, family: manifest.family, version: manifest.version }, 'Patch bundle uploaded');

    return res.status(201).json({ status: 'Success', bundle });
  } catch (error) {
    logger.error({ err: error, bundle_id: verifiedBundleId, user_id: (req as any).jwtPayload?.id }, 'Failed to upload patch bundle');
    return next(new CustomError(500, 'Raw', 'Failed to upload patch bundle', null, error));
  }
};

/** GET /api/patch/bundles — list bundles, most recently uploaded first. */
export const listPatchBundles = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const bundles = await fleetDb.query(`
      SELECT id, bundle_id, version, family, os_match, channel, packages_count, created_at, created_by_email
        FROM patch_bundles
       ORDER BY created_at DESC
       LIMIT ${PATCH_LIST_DEFAULT_ROWS}
    `);
    logger.debug({ count: bundles.length }, 'Patch bundles listed');
    return res.status(200).json({ status: 'Success', bundles });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list patch bundles');
    return next(new CustomError(500, 'Raw', 'Failed to list patch bundles', null, error));
  }
};

/** GET /api/patch/bundles/:id — full manifest detail, including the package list. */
export const getPatchBundleDetail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ status: 'Fail', message: 'Invalid bundle id' });
    }
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const rows = await fleetDb.query(`SELECT * FROM patch_bundles WHERE id = $1`, [id]);
    if (rows.length === 0) {
      return res.status(404).json({ status: 'Fail', message: 'Patch bundle not found' });
    }
    logger.debug({ bundle_id: id }, 'Patch bundle detail retrieved');
    return res.status(200).json({ status: 'Success', bundle: rows[0] });
  } catch (error) {
    logger.error({ err: error, bundle_id: req.params?.id }, 'Failed to get patch bundle detail');
    return next(new CustomError(500, 'Raw', 'Failed to get patch bundle', null, error));
  }
};

/**
 * POST /api/patch/bundles/:id/apply
 * Body: { host_identifiers: string[], totp_code: string, reason?: string }
 * Requires MFA (requireMfa, imported from patch_management.ts — same
 * gate/pattern as applyPatchUpgrade/applyPatchFallback).
 *
 * Rollback / deliberate-version-pin flow: unlike patch_gap.ts's automatic
 * "always pick the newest matching bundle" selection, this endpoint pins a
 * job to the EXACT bundle row named by :id, bypassing that selection logic
 * entirely — the intended use is pushing a deliberately OLDER bundle back
 * onto specific hosts (rollback), though nothing here checks that the named
 * bundle is actually older than what's installed; it's simply "apply this
 * exact bundle, whichever one it is" for any bundle row.
 *
 * Reuses createPatchJob's 'bundle'-source code path with the `bundleId` option, so the
 * created patch_jobs row's `bundle_id` column records exactly which bundle the job is
 * pinned to.
 *
 * Dispatch is wired: createPatchJob's `source === 'bundle'` branch builds `arg1` from
 * this bundle row's stored `{payload, signature}` — the original signed wire bytes, not
 * the parsed manifest_json — and dispatches an `apply_bundle` action per host like any
 * other patch job. Because `bundle_id` is recorded, no re-run of patch_gap.ts's
 * best-effort os_match auto-selection is needed, which would pick the newest bundle
 * again and defeat the point of a rollback.
 */
export const applyPatchBundle = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const fleetDb = dbSources[1];

    const user = await requireMfa(req, res, dbSources[0]);
    if (!user) return;

    const bundleId = Number(req.params.id);
    if (!Number.isInteger(bundleId) || bundleId <= 0) {
      return res.status(400).json({ status: 'Fail', message: 'Invalid bundle id' });
    }
    const bundleRows = await fleetDb.query(
      `SELECT id, bundle_id, version, family FROM patch_bundles WHERE id = $1`,
      [bundleId],
    );
    if (bundleRows.length === 0) {
      return res.status(404).json({ status: 'Fail', message: 'Patch bundle not found' });
    }
    const bundle = bundleRows[0];

    const hosts = validateHostIdentifiers(req.body?.host_identifiers);
    if (!hosts) {
      return res.status(400).json({ status: 'Fail', message: `host_identifiers must be a non-empty array (max ${MAX_HOSTS})` });
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, PATCH_REASON_MAX_LENGTH) : null;

    const inFlight = await findHostsInFlight(fleetDb, hosts);
    const rejected: PerHostResult[] = hosts
      .filter((h) => inFlight.has(h.toLowerCase()))
      .map((h) => ({ host_identifier: h, status: 'rejected_in_progress', message: 'a patch job is already in progress for this host' }));
    const notInFlight = hosts.filter((h) => !inFlight.has(h.toLowerCase()));

    // Family gate. This endpoint pins an exact bundle row by :id and bypasses
    // patch_gap.ts's os_match auto-selection, so nothing upstream has confirmed the
    // pinned bundle's family matches the target host's package manager: a typo'd :id,
    // stale UI state, or a direct API call could otherwise send an rpm bundle at deb
    // hosts with the Go agent as the only remaining defense. Rejects only on a positive
    // mismatch — a host with no detectable family yet is let through, matching how
    // createPatchJob's auto-select path treats a missing detection. Batched into two
    // queries rather than two per host.
    //
    // Scope limit: detectHostPackageFamilies only ever resolves 'deb'/'rpm', because
    // deb_packages/rpm_packages are the only per-host inventory tables in this schema.
    // A pacman/apk bundle always sees hostFamily === null and is always let through, so
    // this gate catches deb<->rpm mismatches only.
    const hostFamilies = await detectHostPackageFamilies(fleetDb, notInFlight);
    const eligible: string[] = [];
    for (const host of notInFlight) {
      const hostFamily = hostFamilies.get(host.toLowerCase()) ?? null;
      if (hostFamily && hostFamily !== bundle.family) {
        rejected.push({
          host_identifier: host,
          status: 'rejected_family_mismatch',
          message: `bundle family "${bundle.family}" does not match this host's detected package family "${hostFamily}"`,
        });
        continue;
      }
      eligible.push(host);
    }

    // Broken out by `status` (rejected_in_progress / rejected_family_mismatch)
    // — a bare rejected_count would leave "hosts already mid-job" and "hosts
    // whose detected package family doesn't match this bundle" indistinguishable
    // from logs alone, unlike createPatchJob's failureReasonCounts breakdown
    // for the analogous per-host-failure summary.
    const rejectedReasonCounts: Record<string, number> = {};
    for (const r of rejected) rejectedReasonCounts[r.status] = (rejectedReasonCounts[r.status] ?? 0) + 1;

    if (eligible.length === 0) {
      logger.info(
        { bundle_id: bundle.bundle_id, host_count: hosts.length, rejected_count: rejected.length, rejected_reasons: rejectedReasonCounts },
        'Patch bundle apply rejected: no targeted host is eligible for this bundle',
      );
      return res.status(409).json({ status: 'Fail', message: 'No targeted host is eligible for this bundle', per_host: rejected });
    }

    const { patch_job_id, per_host } = await createPatchJob(
      fleetDb, 'apply_bundle', eligible, null, reason, user.id, user.email,
      dispatchToAgent, { source: 'bundle', bundleId: bundle.id },
    );

    logAuditTrail({
      action: 'PATCH_BUNDLE_APPLY',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: {
        patch_job_id,
        bundle_row_id: bundle.id,
        bundle_id: bundle.bundle_id,
        version: bundle.version,
        family: bundle.family,
        host_count: eligible.length,
        reason,
      },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, patch_job_id, bundle_id: bundle.bundle_id }, 'Failed to write audit trail for patch bundle apply');
    });

    logger.debug(
      { patch_job_id, bundle_id: bundle.bundle_id, family: bundle.family, host_count: eligible.length, rejected_count: rejected.length, rejected_reasons: rejectedReasonCounts },
      'Patch bundle apply job dispatched',
    );

    return res.status(201).json({
      status: 'Success',
      patch_job_id,
      operation: 'apply_bundle',
      bundle: { id: bundle.id, bundle_id: bundle.bundle_id, version: bundle.version, family: bundle.family },
      per_host: [...per_host, ...rejected],
    });
  } catch (error) {
    logger.error({ err: error, bundle_id: req.params?.id, host_identifiers: req.body?.host_identifiers }, 'Failed to apply patch bundle');
    return next(new CustomError(500, 'Raw', 'Failed to apply patch bundle', null, error));
  }
};
