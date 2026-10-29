import { Router } from 'express';
import {
  listPolicies, getPolicy, createPolicy, updatePolicy, deletePolicy, publishPolicy,
  listTemplates, listCatalog,
  initializeBaseline, getInitialization, listBaselineVersions,
  listAlerts, closeAlerts, reopenAlerts,
  listDrift, getDrift, resolveDrift, listBaseline, getSummary,
  upgradeTemplate, recheckDrift,
} from '../../controllers/fim/fim_management';
import * as reg from '../../controllers/fim/fim_registry';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// File Integrity Monitoring. Open to Super Administrator and Group Admin; Group
// Admin callers are restricted inside fim_management.ts to FIM policies whose
// targets are entirely within their own group(s), and to drift/baseline rows on
// their own hosts. No lower-role access (no existing read-only pattern applies).
const read = [checkAccessJwt, requireAdmin, apiDataLimiter];
const write = [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf];

router.get('/summary', read, getSummary);
router.get('/templates', read, listTemplates);
router.get('/catalog', read, listCatalog);
router.get('/policies', read, listPolicies);
router.post('/policies', write, createPolicy);
router.get('/policies/:id', read, getPolicy);
router.put('/policies/:id', write, updatePolicy);
router.delete('/policies/:id', write, deletePolicy);
router.post('/policies/:id/publish', write, publishPolicy);
router.post('/policies/:id/initialize', write, initializeBaseline);
router.get('/policies/:id/initialization', read, getInitialization);
router.get('/baseline/versions', read, listBaselineVersions);
router.get('/alerts', read, listAlerts);
router.post('/alerts/close', write, closeAlerts);
router.post('/alerts/reopen', write, reopenAlerts);
router.get('/drift', read, listDrift);
router.post('/drift/resolve', write, resolveDrift);
router.get('/drift/:id', read, getDrift);
router.post('/drift/:id/recheck', write, recheckDrift);
router.get('/baseline', read, listBaseline);
router.post('/policies/:id/upgrade-template', write, upgradeTemplate);

// Per-node Windows registry coverage (FIM_REGISTRY_DESIGN §3.13). Same middleware; scope and
// role checks (Super Admin vs Group Admin in scope, two-person waivers) live in the service.
router.get('/registry/settings', read, reg.getSettings);
router.put('/registry/settings', write, reg.putSettings);
router.get('/registry/catalog', read, reg.getCatalog);
router.get('/registry/profiles', read, reg.listProfiles);
router.post('/registry/profiles', write, reg.createProfile);
router.get('/registry/profiles/:id', read, reg.getProfile);
router.put('/registry/profiles/:id', write, reg.updateProfile);
router.delete('/registry/profiles/:id', write, reg.deleteProfile);
router.get('/registry/assignments', read, reg.listAssignments);
router.put('/registry/assignments/:scopeType/:scopeValue', write, reg.putAssignment);
router.get('/registry/rules', read, reg.listRules);
router.post('/registry/rules', write, reg.createRule);
router.delete('/registry/rules/:id', write, reg.revokeRule);
router.get('/registry/waivers', read, reg.listWaivers);
router.post('/registry/waivers', write, reg.requestWaiver);
router.post('/registry/waivers/:id/approve', write, reg.approveWaiver);
router.post('/registry/waivers/:id/reject', write, reg.rejectWaiver);
router.post('/registry/waivers/:id/revoke', write, reg.revokeWaiver);
router.post('/registry/waivers/:id/apply', write, reg.applyWaiver);
router.get('/registry/approver-candidates', read, reg.approverCandidates);
router.put('/registry/settings/approvers', write, reg.putApprovers);
router.get('/registry/nodes', read, reg.listNodes);
router.get('/registry/nodes/:host', read, reg.getNode);
router.post('/registry/nodes/:host/preview', write, reg.previewNode);
router.post('/registry/nodes/:host/measure', write, reg.measure);
router.post('/registry/nodes/:host/compact', write, reg.compact);
router.get('/registry/nodes/:host/hygiene', read, reg.hygiene);
router.post('/registry/nodes/:host/hygiene/ack', write, reg.ackHygiene);
router.get('/registry/measure/:id', read, reg.getMeasure);
router.get('/registry/groups/:groupId', read, reg.getGroup);
router.post('/registry/publish', write, reg.publish);
router.get('/registry/jobs/:id', read, reg.getJob);
router.post('/registry/jobs/:id/cancel', write, reg.cancelJob);
router.get('/registry/policy-problems', read, reg.policyProblems);
router.get('/registry/history', read, reg.history);
router.post('/registry/rollback', write, reg.rollback);
router.get('/registry/needs-init', read, reg.needsInit);
router.get('/registry/migration/legacy', read, reg.listLegacy);
router.post('/registry/migration/legacy/:policyId/apply', write, reg.applyLegacy);
router.post('/registry/migration/legacy/:policyId/remove-registry', write, reg.removeLegacy);

export default router;
