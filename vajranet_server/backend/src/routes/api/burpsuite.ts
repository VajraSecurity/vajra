import { Router } from 'express';
import { checkJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import {
    saveBurpsuiteConfig,
    getBurpsuiteConfig,
    testBurpsuiteConnection,
    listBurpsuiteScans,
    launchBurpsuiteScan,
    deleteBurpsuiteConfig,
    testStoredBurpsuiteConnection,
    getBurpsuiteScanDetails,
    deleteBurpsuiteScan
} from '../../controllers/burpsuite/burpsuiteController';
import { listBurpsuiteAssets, getBurpsuiteAsset } from '../../controllers/burpsuiteAssets';

const router = Router();

// Apply auth middleware to all routes
// Super Administrator or Group Admin. This router backs the Vulnerability
// Scanner sub-tab of Network Security (features/Network/index.tsx renders
// <VulnerabilityScanner/> there), so its access must match routes/api/network.ts.
//
// Group-scoped: both the Burp Suite Enterprise config and (unlike Nessus/
// OpenVAS) its locally-stored scan history carry a group_id, resolved per
// request in burpsuiteController.ts via resolveScannerGroupContext /
// utils/scannerScope.ts — same model as Nessus/OpenVAS/the Scan Scheduler. A
// Group Admin is always forced onto their own group's config and scans. A
// Super Administrator may target any group (or their own scope) explicitly
// via ?groupId=/body groupId — but GET /scans is the one exception across all
// three scanners: since scan history lives in this app's own DB rather than
// being proxied live from a remote server, a Super Admin's default list view
// with no groupId param is a genuine merged list across every group's scans
// AND their own, not a per-group context switch. Passing ?groupId= narrows it
// to just that group, same as every other endpoint here.
router.use([checkJwt, requireAdmin]);

const mutate = [apiMutationLimiter, checkCsrf];

router.post('/config', mutate, saveBurpsuiteConfig);
router.get('/config', [apiDataLimiter], getBurpsuiteConfig);
router.delete('/config', mutate, deleteBurpsuiteConfig);
router.post('/test', mutate, testBurpsuiteConnection);
router.post('/test-stored', mutate, testStoredBurpsuiteConnection);

router.get('/scans', [apiDataLimiter], listBurpsuiteScans);
router.get('/scans/:taskId', [apiDataLimiter], getBurpsuiteScanDetails);
router.delete('/scans/:taskId', mutate, deleteBurpsuiteScan);
router.post('/scan', mutate, launchBurpsuiteScan);

// Burp Suite Assets: read-only aggregation of burpsuite_scan_history rows by
// normalized scan target (see controllers/burpsuiteAssets/). No conflict with
// any route above -- '/assets' is a distinct literal prefix from '/config',
// '/test', '/scans' and '/scan' -- but the literal list route is still
// declared before its own ':normalizedTarget' param route, same
// literal-before-param caution routes/api/assets.ts documents, so a future
// fixed path under '/assets' (e.g. '/assets/summary') must be added above the
// param route too.
router.get('/assets', [apiDataLimiter], listBurpsuiteAssets);
router.get('/assets/:normalizedTarget', [apiDataLimiter], getBurpsuiteAsset);

export default router;
