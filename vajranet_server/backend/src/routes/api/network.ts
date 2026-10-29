import { Router } from 'express';
import { runNmapScan, getNmapScanHistory, getKnownIps, getScanStatus, cancelScan, getActiveScan, updateScanCharts } from '../../controllers/network/nmapController';
import {
  runNucleiScan, getNucleiScanHistory, getNucleiScanStatus,
  cancelNucleiScan, getActiveNucleiScan, checkNucleiInstalled,
  updateNucleiTemplates, getTemplateUpdateStatus,
} from '../../controllers/network/nucleiController';
import {
  listSchedules, createSchedule, updateSchedule, deleteSchedule,
  runScheduleNow, getScheduleRuns,
} from '../../controllers/network/scanSchedules';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkJwt } from '../../middleware/checkJwt';
import { requireOnPrem } from '../../middleware/requireOnPrem';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Protect the entire network route with JWT, Admin (Super Administrator or
// Group Admin), and OnPrem middleware.
//
// NOTE: unlike Remote Shell and Policy Management, most of /network is not
// group-scoped. nmap/nuclei take an operator-supplied target (an IP, host or
// CIDR — see targetValidation.ts), not a node from the caller's group, so a
// Group Admin can scan anything the server can reach, and ad-hoc scan history
// is shared fleet-wide rather than partitioned per group. Widening this from
// requireSuperAdmin to requireAdmin was a deliberate product decision; if
// per-group restriction is wanted later it has to be built in the
// controllers, because the route guard alone cannot express it.
//
// The /schedules* routes below are the one exception: Scan Scheduler targets
// a recurring subnet, not an ad-hoc operator-supplied one, so it IS
// group-scoped, via backend/src/utils/scannerScope.ts — each schedule carries
// a group_id (null = a Super Administrator's own/"fleet-wide" schedule), and
// every scanSchedules/* controller enforces read/act scope on it.
router.use([checkJwt, requireAdmin, requireOnPrem]);

// --- Nmap (network discovery & port scanning) ---
router.post('/scan', [apiMutationLimiter, checkCsrf], runNmapScan);
router.get('/scan/active', [apiDataLimiter], getActiveScan);
router.get('/scan/history', [apiDataLimiter], getNmapScanHistory);
router.get('/scan/:id', [apiDataLimiter], getScanStatus);
router.post('/scan/:id/cancel', [apiMutationLimiter, checkCsrf], cancelScan);
router.put('/scan/:id/charts', [apiMutationLimiter, checkCsrf], updateScanCharts);
router.get('/known-ips', [apiDataLimiter], getKnownIps);

// --- Nuclei (vulnerability & misconfiguration scanning) ---
router.get('/nuclei/status', [apiDataLimiter], checkNucleiInstalled);
router.post('/nuclei/scan', [apiMutationLimiter, checkCsrf], runNucleiScan);
router.get('/nuclei/scan/active', [apiDataLimiter], getActiveNucleiScan);
router.get('/nuclei/scan/history', [apiDataLimiter], getNucleiScanHistory);
router.get('/nuclei/scan/:id', [apiDataLimiter], getNucleiScanStatus);
router.post('/nuclei/scan/:id/cancel', [apiMutationLimiter, checkCsrf], cancelNucleiScan);
router.post('/nuclei/templates/update', [apiMutationLimiter, checkCsrf], updateNucleiTemplates);
router.get('/nuclei/templates/status', [apiDataLimiter], getTemplateUpdateStatus);

// --- Scan Scheduler (recurring subnet discovery + auto advanced scan on new unmanaged hosts) ---
router.get('/schedules', [apiDataLimiter], listSchedules);
router.post('/schedules', [apiMutationLimiter, checkCsrf], createSchedule);
router.put('/schedules/:id', [apiMutationLimiter, checkCsrf], updateSchedule);
router.delete('/schedules/:id', [apiMutationLimiter, checkCsrf], deleteSchedule);
router.post('/schedules/:id/run-now', [apiMutationLimiter, checkCsrf], runScheduleNow);
router.get('/schedules/:id/runs', [apiDataLimiter], getScheduleRuns);

export default router;
