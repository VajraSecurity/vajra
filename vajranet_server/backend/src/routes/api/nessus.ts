import { Router } from 'express';
import { checkJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import {
  saveNessusConfig, getNessusConfig, testNessusConnection, testStoredConnection, deleteNessusConfig,
  getServerStatus, getServerProperties,
  listScanTemplates, listPolicyTemplates,
  listScans, createScan, getScanDetails, updateScan, deleteScan,
  launchScan, pauseScan, resumeScan, stopScan,
  requestExport, getExportStatus, downloadExport,
  listPolicies, createPolicy, getPolicy, updatePolicy, deletePolicy,
  listFolders, createFolder, deleteFolder,
  listPluginFamilies, getPluginFamily, getPlugin,
} from '../../controllers/nessus/nessusController';

const router = Router();

// Super Administrator or Group Admin. This router backs the Vulnerability
// Scanner sub-tab of Network Security (features/Network/index.tsx renders
// <VulnerabilityScanner/> there), so its access must match routes/api/network.ts.
// Group-scoped: config plus everything proxied through it (server status,
// scans, policies, folders, plugins) is resolved per-request via
// resolveScannerGroupContext/scannerScope.ts, not enforced here at the router
// level. A Group Admin is always forced onto their own group's Nessus server —
// they can never reach the Super Administrator's own config or another
// group's. A Super Administrator has their own (default, no groupId) config
// plus can target any group's via `?groupId=` (GET) or a `groupId` body field
// (POST/DELETE), giving them full visibility into every group's scans too.
router.use([checkJwt, requireAdmin]);

const mutate = [apiMutationLimiter, checkCsrf];

// --- Configuration ---
router.get('/config', [apiDataLimiter], getNessusConfig);
router.post('/config', mutate, saveNessusConfig);
router.post('/config/test', mutate, testNessusConnection);
router.get('/config/test', [apiDataLimiter], testStoredConnection);
router.delete('/config', mutate, deleteNessusConfig);

// --- Server ---
router.get('/server/status', [apiDataLimiter], getServerStatus);
router.get('/server/properties', [apiDataLimiter], getServerProperties);

// --- Templates ---
router.get('/templates/scan', [apiDataLimiter], listScanTemplates);
router.get('/templates/policy', [apiDataLimiter], listPolicyTemplates);

// --- Scans ---
router.get('/scans', [apiDataLimiter], listScans);
router.post('/scans', mutate, createScan);
router.get('/scans/:id', [apiDataLimiter], getScanDetails);
router.put('/scans/:id', mutate, updateScan);
router.delete('/scans/:id', mutate, deleteScan);
router.post('/scans/:id/launch', mutate, launchScan);
router.post('/scans/:id/pause', mutate, pauseScan);
router.post('/scans/:id/resume', mutate, resumeScan);
router.post('/scans/:id/stop', mutate, stopScan);

// --- Export ---
router.post('/scans/:scanId/export', mutate, requestExport);
router.get('/scans/:scanId/export/:fileId/status', [apiDataLimiter], getExportStatus);
router.get('/scans/:scanId/export/:fileId/download', [apiDataLimiter], downloadExport);

// --- Policies ---
router.get('/policies', [apiDataLimiter], listPolicies);
router.post('/policies', mutate, createPolicy);
router.get('/policies/:id', [apiDataLimiter], getPolicy);
router.put('/policies/:id', mutate, updatePolicy);
router.delete('/policies/:id', mutate, deletePolicy);

// --- Folders ---
router.get('/folders', [apiDataLimiter], listFolders);
router.post('/folders', mutate, createFolder);
router.delete('/folders/:id', mutate, deleteFolder);

// --- Plugins ---
router.get('/plugins/families', [apiDataLimiter], listPluginFamilies);
router.get('/plugins/families/:id', [apiDataLimiter], getPluginFamily);
router.get('/plugins/:id', [apiDataLimiter], getPlugin);

export default router;
