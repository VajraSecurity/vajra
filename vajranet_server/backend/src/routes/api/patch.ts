import { Router } from 'express';
import {
  triggerPatchCheck,
  applyPatchUpgrade,
  applyPatchFallback,
  listPatchJobs,
  getPatchJobDetail,
  listAvailableUpdates,
  triggerPatchReboot,
  listHostsNeedingReboot,
} from '../../controllers/nodes/patch_management';
import {
  uploadPatchBundle,
  listPatchBundles,
  getPatchBundleDetail,
  applyPatchBundle,
} from '../../controllers/nodes/patch_bundles';
import { buildPatchBundle } from '../../controllers/nodes/patch_bundles_build';
import { uploadPackagesForBuild } from '../../controllers/nodes/patch_bundles_upload_packages';
import { getPatchGap } from '../../controllers/nodes/patch_gap';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Patch Management is Super-Admin-only end to end (mirrors /api/network's
// blanket gate) — MFA is an additional, action-specific check inside
// applyPatchUpgrade/triggerPatchReboot/applyPatchBundle themselves, not a
// route-level middleware.
router.use([checkAccessJwt, requireSuperAdmin]);

router.post('/check', [apiMutationLimiter, checkCsrf], triggerPatchCheck);
router.post('/apply', [apiMutationLimiter, checkCsrf], applyPatchUpgrade);
router.post('/apply/fallback', [apiMutationLimiter, checkCsrf], applyPatchFallback);
router.get('/jobs', [apiDataLimiter], listPatchJobs);
router.get('/jobs/:id', [apiDataLimiter], getPatchJobDetail);
router.get('/available', [apiDataLimiter], listAvailableUpdates);

// Phase 4: admin-triggered reboot (plumbing-only — see triggerPatchReboot's
// header comment in patch_management.ts for the Go-agent capability gap).
router.post('/reboot', [apiMutationLimiter, checkCsrf], triggerPatchReboot);
router.get('/reboot-required', [apiDataLimiter], listHostsNeedingReboot);

// Patch Bundle content pipeline (offline-signed package snapshots) — see
// controllers/nodes/patch_bundles.ts. Upload verifies the ECDSA signature
// server-side before ever storing a row; no MFA gate (this stores signed
// content, it does not apply anything to a host). /bundles/:id/apply DOES
// require MFA (see applyPatchBundle) since it creates a job pinned to that
// bundle — same mutating-action gate as /apply and /apply/fallback.
router.post('/bundles', [apiMutationLimiter, checkCsrf], uploadPatchBundle);
router.get('/bundles', [apiDataLimiter], listPatchBundles);
router.get('/bundles/:id', [apiDataLimiter], getPatchBundleDetail);
router.post('/bundles/:id/apply', [apiMutationLimiter, checkCsrf], applyPatchBundle);

// Build + sign a bundle from a server-side staging folder — DOES
// require MFA (unlike upload above): this signs with a server-resident key
// on the admin's request, a materially different trust action than storing
// an already-offline-signed manifest. See patch_bundles_build.ts's header
// comment for the accepted-risk note.
router.post('/bundles/build', [apiMutationLimiter, checkCsrf], buildPatchBundle);

// Browser-facing companion to /bundles/build above — accepts a multipart
// upload of raw package files into a fresh staging subdirectory whose name
// can then be passed straight to /bundles/build as source_dir. Same gate as
// /bundles/build (MFA enforced inside the handler itself); see
// patch_bundles_upload_packages.ts's header comment.
router.post('/bundles/staging-upload', [apiMutationLimiter, checkCsrf], uploadPackagesForBuild);

// CVE-correlated installed-vs-available gap computation — see
// controllers/nodes/patch_gap.ts.
router.get('/gap', [apiDataLimiter], getPatchGap);

export default router;
