import { Router } from 'express';
import { checkJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import {
  saveOpenVASConfig, getOpenVASConfigEndpoint, testOpenVASConnection,
  testStoredOpenVASConnection, deleteOpenVASConfig,
  getGvmVersion, listScanConfigs, listScanners,
  listTargets, createTarget, updateTarget, deleteTarget,
  listTasks, createTask, updateTask, getTaskDetails, startTask, stopTask, resumeTask, deleteTask,
  getReport, listPortLists, listReportFormats, getFeedStatus,
  listCredentials, createCredential, updateCredential, deleteCredential,
  quickScan,
} from '../../controllers/openvas/openvasController';

const router = Router();

// Super Administrator or Group Admin. This router backs the Vulnerability
// Scanner sub-tab of Network Security (features/Network/index.tsx renders
// <VulnerabilityScanner/> there), so its access must match routes/api/network.ts.
// Config + everything proxied through it (server info, scan configs,
// scanners, targets, tasks, reports, port lists, report formats, feeds,
// credentials, quick scan) IS group-scoped: each handler in
// openvasController.ts calls resolveScannerGroupContext (scannerScope.ts) to
// resolve a single scope — a group the caller belongs to, or (Super
// Administrator only) their own null/global scope — and every OpenVAS/GVM
// config lookup, GSA session, and GMP command is keyed to that scope. A
// Group Admin is always forced onto their own group; a Super Administrator
// may target any group via ?groupId=/body groupId, or omit it for their own.
router.use([checkJwt, requireAdmin]);

const mutate = [apiMutationLimiter, checkCsrf];

// --- Configuration ---
router.get('/config', [apiDataLimiter], getOpenVASConfigEndpoint);
router.post('/config', mutate, saveOpenVASConfig);
router.post('/config/test', mutate, testOpenVASConnection);
router.get('/config/test', [apiDataLimiter], testStoredOpenVASConnection);
router.delete('/config', mutate, deleteOpenVASConfig);

// --- Server ---
router.get('/version', [apiDataLimiter], getGvmVersion);
router.get('/feeds', [apiDataLimiter], getFeedStatus);

// --- Scan Configs (profiles) ---
router.get('/configs', [apiDataLimiter], listScanConfigs);

// --- Scanners ---
router.get('/scanners', [apiDataLimiter], listScanners);

// --- Targets ---
router.get('/targets', [apiDataLimiter], listTargets);
router.post('/targets', mutate, createTarget);
router.put('/targets/:id', mutate, updateTarget);
router.delete('/targets/:id', mutate, deleteTarget);

// --- Tasks (Scans) ---
router.get('/tasks', [apiDataLimiter], listTasks);
router.post('/tasks', mutate, createTask);
router.get('/tasks/:id', [apiDataLimiter], getTaskDetails);
router.put('/tasks/:id', mutate, updateTask);
router.post('/tasks/:id/start', mutate, startTask);
router.post('/tasks/:id/stop', mutate, stopTask);
router.post('/tasks/:id/resume', mutate, resumeTask);
router.delete('/tasks/:id', mutate, deleteTask);

// --- Reports ---
router.get('/reports/:id', [apiDataLimiter], getReport);

// --- Port Lists ---
router.get('/port-lists', [apiDataLimiter], listPortLists);

// --- Report Formats ---
router.get('/report-formats', [apiDataLimiter], listReportFormats);

// --- Credentials ---
router.get('/credentials', [apiDataLimiter], listCredentials);
router.post('/credentials', mutate, createCredential);
router.put('/credentials/:id', mutate, updateCredential);
router.delete('/credentials/:id', mutate, deleteCredential);

// --- Quick Scan (target + task + start) ---
router.post('/quick-scan', mutate, quickScan);

export default router;
