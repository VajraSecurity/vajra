import { Router } from 'express';
import { alert_assign, alert_assignee, alert_by_id, alert_list, alert_list_device, alert_list_my, alert_update, alerts_export, alert_status, clamav_alert_summary, clamav_scan_latest, saveCertinDraft, getCertinDraft, getCertinDraftHistory, deleteCertinDraft, markCertinDraftDownloaded, saveCertinCompliance, getCertinCompliance, resetCertinCompliance } from '../../controllers/alerts';
import { checkAccessJwt, checkAccessWithRefreshFallback } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiExportLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();
router.post('/list/device', [checkAccessJwt, apiDataLimiter, checkCsrf], alert_list_device);
router.get('/list', [checkAccessJwt, apiDataLimiter], alert_list);
router.get('/list/my', [checkAccessJwt, apiDataLimiter], alert_list_my);
router.get('/export', [checkAccessJwt, apiExportLimiter], alerts_export);
router.get('/assignee', [checkAccessJwt, apiDataLimiter], alert_assignee);
router.get('/by-id', [checkAccessJwt, apiDataLimiter], alert_by_id);
router.post('/update', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], alert_update);
router.post('/assign', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], alert_assign);
router.post('/status', [checkAccessJwt, requireAdmin, apiDataLimiter, checkCsrf], alert_status);
router.get('/clamav-summary', [checkAccessJwt, apiDataLimiter], clamav_alert_summary);
router.get('/clamav-scan-latest', [checkAccessJwt, apiDataLimiter], clamav_scan_latest);
// CERT-In draft endpoints
// Use refresh-fallback for certin-draft so a valid refresh token can renew access when needed.
router.post('/certin-draft', [checkAccessWithRefreshFallback, requireAdmin, apiMutationLimiter, checkCsrf], saveCertinDraft);
router.get('/certin-draft', [checkAccessWithRefreshFallback, apiDataLimiter], getCertinDraft);
router.get('/certin-draft/history', [checkAccessWithRefreshFallback, apiDataLimiter], getCertinDraftHistory);
router.delete('/certin-draft/:draftId', [checkAccessWithRefreshFallback, requireAdmin, apiMutationLimiter, checkCsrf], deleteCertinDraft);
router.post('/certin-draft/:draftId/downloaded', [checkAccessWithRefreshFallback, requireAdmin, apiMutationLimiter, checkCsrf], markCertinDraftDownloaded);
router.post('/certin-compliance', [checkAccessWithRefreshFallback, requireAdmin, apiMutationLimiter, checkCsrf], saveCertinCompliance);
router.get('/certin-compliance', [checkAccessWithRefreshFallback, apiDataLimiter], getCertinCompliance);
router.post('/certin-compliance/reset', [checkAccessWithRefreshFallback, requireAdmin, apiMutationLimiter, checkCsrf], resetCertinCompliance);

export default router;
