import { Router } from 'express';
import { listAssets, getAsset, getAssetObservations } from '../../controllers/assets';
import { checkJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { apiDataLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Assets is read-only, so there is no mutating route here and therefore no
// checkCsrf / apiMutationLimiter — merges and review actions are a separate,
// later change that must add both.
//
// requireAdmin is exactly [Super Administrator, Group Admin] (see
// middleware/requireAdmin.ts), which is the same predicate the frontend gates
// the nav item on (`isSuperAdmin || userRole === 'Group Admin'` in
// Sidebar.tsx and MobileNavbar.tsx). Those three must stay in step: widen one
// without the others and the nav entry appears while every request 403s.
//
// Unlike /network this route is NOT wrapped in requireOnPrem. Assets are built
// from data already in the fleet DB (nodes, nmap/nuclei history, live OpenVAS
// reports) rather than from a scanner binary that only exists on-prem, so the
// view is meaningful in a cloud deployment too.
//
// Group scoping is enforced inside the controllers, not by route middleware: a
// Group Admin of several groups reads the union of those groups' assets, which
// a route-level guard cannot express.
router.use([checkJwt, requireAdmin]);

router.get('/', [apiDataLimiter], listAssets);
// Declared after '/' and both are literal-vs-param distinct, but keep any
// future fixed path (e.g. '/summary') above these two — Express matches in
// declaration order and '/:assetUuid' would otherwise swallow it.
router.get('/:assetUuid', [apiDataLimiter], getAsset);
router.get('/:assetUuid/observations', [apiDataLimiter], getAssetObservations);

export default router;
