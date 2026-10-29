import { Router } from 'express';
import {
  listCatalog,
  getCatalogApp,
  getAvailability,
  requestInstall,
  listJobs,
  getJobDetail,
} from '../../controllers/nodes/windows_patch_management';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Windows maintained-app software install/uninstall is Super-Admin-only end
// to end (mirrors routes/api/patch.ts's blanket gate for the same reason —
// this dispatches code execution on a host) — MFA is an additional,
// action-specific check inside requestInstall itself, not a route-level
// middleware, matching that same precedent.
router.use([checkAccessJwt, requireSuperAdmin]);

router.get('/catalog', [apiDataLimiter], listCatalog);
router.get('/catalog/:slug', [apiDataLimiter], getCatalogApp);
router.get('/availability', [apiDataLimiter], getAvailability);
router.post('/install', [apiMutationLimiter, checkCsrf], requestInstall);
router.get('/jobs', [apiDataLimiter], listJobs);
router.get('/jobs/:job_id', [apiDataLimiter], getJobDetail);

export default router;
