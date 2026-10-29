//Server/src/routes/api node.ts


import { Router } from 'express';
import { node_list, node_identifiers, node_my_group_roles, node_ips, node_detail, node_rename, node_critical, node_uncritical, node_programs, node_storage, node_listening_ports, node_network_uptime, node_compliance_latest, node_compliance_history, node_wifi_latest, nodes_export, org_compliance_history, org_compliance_save_snapshot, sebi_compliance_history, sebi_compliance_save_snapshot, irdai_compliance_history, irdai_compliance_save_snapshot, node_irdai_compliance_history, node_irdai_compliance_latest, node_sebi_compliance_history, node_sebi_compliance_latest, node_irdai_compliance_save_snapshot, node_sebi_compliance_save_snapshot, node_certin_compliance_history, node_certin_compliance_latest, node_certin_compliance_save_snapshot, certin_compliance_history, certin_compliance_save_snapshot, node_firewall_status, node_groups, generateCertProvisioningToken, revokeCertProvisioningToken, listCertProvisioningTokens } from '../../controllers/nodes';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiExportLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();
router.get('/list', [checkAccessJwt, apiDataLimiter], node_list);
router.get('/identifiers', [checkAccessJwt, apiDataLimiter], node_identifiers);
router.get('/my-group-roles', [checkAccessJwt, apiDataLimiter], node_my_group_roles);
router.get('/groups', [checkAccessJwt, apiDataLimiter], node_groups);
router.get('/export', [checkAccessJwt, apiExportLimiter], nodes_export);
router.post('/ip', [checkAccessJwt, apiDataLimiter, checkCsrf], node_ips);
router.post('/rename', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_rename);
router.post('/critical', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_critical);
router.post('/uncritical', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_uncritical);
router.get('/details/:host_identifier', [checkAccessJwt, apiDataLimiter], node_detail);
router.get('/storage/:host_identifier', [checkAccessJwt, apiDataLimiter], node_storage);
// Network posture — listening ports (differential inventory) and last-boot/uptime tracking
router.get('/network/listening-ports/:host_identifier', [checkAccessJwt, apiDataLimiter], node_listening_ports);
router.get('/network/uptime/:host_identifier', [checkAccessJwt, apiDataLimiter], node_network_uptime);
router.post('/programs', [checkAccessJwt, apiDataLimiter, checkCsrf], node_programs);
// Compliance — specific paths must be declared before any /:param catch-all
// Org-level compliance snapshot routes (must come before /:host_identifier routes)
router.get('/compliance/org/history',    [checkAccessJwt, apiDataLimiter], org_compliance_history);
router.post('/compliance/org/snapshot',  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], org_compliance_save_snapshot);

router.get('/compliance/sebi/history',    [checkAccessJwt, apiDataLimiter], sebi_compliance_history);
router.post('/compliance/sebi/snapshot',  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], sebi_compliance_save_snapshot);

router.get('/compliance/irdai/history',    [checkAccessJwt, apiDataLimiter], irdai_compliance_history);
router.post('/compliance/irdai/snapshot',  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], irdai_compliance_save_snapshot);

router.get('/compliance/certin/history',    [checkAccessJwt, apiDataLimiter], certin_compliance_history);
router.post('/compliance/certin/snapshot',  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], certin_compliance_save_snapshot);

router.get('/compliance/latest/:host_identifier',  [checkAccessJwt, apiDataLimiter], node_compliance_latest);
router.get('/compliance/history/:host_identifier', [checkAccessJwt, apiDataLimiter], node_compliance_history);

router.get('/compliance/sebi/latest/:host_identifier',  [checkAccessJwt, apiDataLimiter], node_sebi_compliance_latest);
router.get('/compliance/sebi/history/:host_identifier', [checkAccessJwt, apiDataLimiter], node_sebi_compliance_history);
router.post('/compliance/sebi/node-snapshot/:host_identifier', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_sebi_compliance_save_snapshot);

router.get('/compliance/irdai/latest/:host_identifier',  [checkAccessJwt, apiDataLimiter], node_irdai_compliance_latest);
router.get('/compliance/irdai/history/:host_identifier', [checkAccessJwt, apiDataLimiter], node_irdai_compliance_history);
router.post('/compliance/irdai/node-snapshot/:host_identifier', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_irdai_compliance_save_snapshot);

router.get('/compliance/certin/latest/:host_identifier',  [checkAccessJwt, apiDataLimiter], node_certin_compliance_latest);
router.get('/compliance/certin/history/:host_identifier', [checkAccessJwt, apiDataLimiter], node_certin_compliance_history);
router.post('/compliance/certin/node-snapshot/:host_identifier', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], node_certin_compliance_save_snapshot);

// WiFi telemetry
router.get('/wifi/:host_identifier', [checkAccessJwt, apiDataLimiter], node_wifi_latest);

// Linux firewall status (ufw / firewalld)
router.get('/firewall-status', [checkAccessJwt, apiDataLimiter], node_firewall_status);


// Agent mTLS cert-provisioning tokens — one-time, host-bound. NOT osquery's
// own enrollment (that's the separate C++ fleet server's enroll_secret /
// node_key flow). This only provisions the mTLS client cert the Go extension
// presents on its WebSocket connections here. The agent-facing consumption
// endpoint (no JWT) lives under /api/agent, not here.
router.post('/cert-provisioning-token/generate', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], generateCertProvisioningToken);
router.post('/cert-provisioning-token/revoke',   [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], revokeCertProvisioningToken);
router.get('/cert-provisioning-token/list',      [checkAccessJwt, requireAdmin, apiDataLimiter], listCertProvisioningTokens);

export default router;
