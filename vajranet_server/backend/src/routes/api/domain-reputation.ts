import { Router } from 'express';
import { checkJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import {
  listProviderConfigs, saveProviderConfig, deleteProviderConfig, testProviderConnection,
} from '../../controllers/domain-reputation/providerConfigController';
import { manualCheck, listHistory } from '../../controllers/domain-reputation/checkController';
import {
  listTargets, createTarget, updateTarget, deleteTarget, runTargetNow, listInventorySuggestions,
} from '../../controllers/domain-reputation/targetsController';
import { listMyGroups } from '../../controllers/domain-reputation/scopeController';

const router = Router();

// Group Admins can run checks and manage the watchlist, and may save/test/
// delete VirusTotal/AbuseIPDB config for group(s) they administer. Only
// Super Administrator may touch the shared Vajra Reputation Engine ('manual')
// config or another group's VirusTotal/AbuseIPDB config — both enforced
// inside the controllers (providerConfigController, targetsController), not
// by route middleware, since which provider/group a given request may touch
// varies per request in a way route-level guards can't express.
router.use([checkJwt, requireAdmin]);

// --- Provider configuration ---
router.get('/providers', apiDataLimiter, listProviderConfigs);
router.post('/providers/:provider/config', [apiMutationLimiter, checkCsrf], saveProviderConfig);
router.post('/providers/:provider/test', [apiMutationLimiter, checkCsrf], testProviderConnection);
router.delete('/providers/:provider/config', [apiMutationLimiter, checkCsrf], deleteProviderConfig);

// --- Caller's own group scope (drives the group picker on Settings/Check Now/Watchlist) ---
router.get('/my-groups', apiDataLimiter, listMyGroups);

// --- Ad-hoc checks (manual server's Manual Check tab + Threat Intel "Check Now") ---
router.post('/check', [apiMutationLimiter, checkCsrf], manualCheck);
router.get('/history', apiDataLimiter, listHistory);

// --- Threat Intel scheduled watchlist ---
router.get('/targets', apiDataLimiter, listTargets);
router.post('/targets', [apiMutationLimiter, checkCsrf], createTarget);
router.put('/targets/:id', [apiMutationLimiter, checkCsrf], updateTarget);
router.delete('/targets/:id', [apiMutationLimiter, checkCsrf], deleteTarget);
router.post('/targets/:id/run-now', [apiMutationLimiter, checkCsrf], runTargetNow);

// --- Inventory autocomplete ---
router.get('/inventory-suggestions', apiDataLimiter, listInventorySuggestions);

export default router;
