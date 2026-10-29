import { Router } from 'express';
import { generateSebiPdf, generateIrdaiPdf, generateCertinPdf, generateOrgPdf } from '../../controllers/reports';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { apiExportLimiter } from '../../middleware/rateLimiters';

const router = Router();

// These reports aggregate compliance data across the entire fleet (org-wide),
// not just the caller's assigned node group(s) — restricted to Super Admin
// rather than building group-scoped aggregate queries for a reporting feature.
// Each request launches a headless Chromium (puppeteer) plus several chart
// renders — apiExportLimiter (not apiDataLimiter, meant for cheap reads)
// matches that actual cost.
router.get('/reports/sebi-pdf',  [checkAccessJwt, requireSuperAdmin, apiExportLimiter], generateSebiPdf);
router.get('/reports/irdai-pdf', [checkAccessJwt, requireSuperAdmin, apiExportLimiter], generateIrdaiPdf);
router.get('/reports/certin-pdf',[checkAccessJwt, requireSuperAdmin, apiExportLimiter], generateCertinPdf);
// Combined org-wide report spanning all three regulatory standards.
router.get('/reports/pdf',       [checkAccessJwt, requireSuperAdmin, apiExportLimiter], generateOrgPdf);

export default router;
