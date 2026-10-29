import { Router } from 'express';
import { listVulnerabilities, getVulnerabilityDetail, getHostVulnerabilities } from '../../controllers/vulnerabilities/vulnexus_read';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { apiDataLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Read-only CVE data surfaced from the vulnexus pipeline's tables/materialized
// views (backend/src/migrations/create_grafana_views.sql). Gated the same way
// as this codebase's other read-mostly fleet-data GET endpoints — checkAccessJwt
// + apiDataLimiter, no requireAdmin/requireSuperAdmin (see routes/api/nodes.ts's
// /list, /details/:host_identifier, /storage/:host_identifier for the same
// convention) — deliberately looser than routes/api/patch.ts's blanket
// Super-Admin gate, since nothing here mutates anything. Node-group scoping is
// still enforced per-query inside the controllers (getUserNodeScope /
// assertHostInScope), same as nodes.ts / alerts.ts.
//
// Specific paths declared before the /:cve catch-all (same ordering rule as
// nodes.ts's compliance routes).
router.get('/', [checkAccessJwt, apiDataLimiter], listVulnerabilities);
router.get('/host/:host_identifier', [checkAccessJwt, apiDataLimiter], getHostVulnerabilities);
router.get('/:cve', [checkAccessJwt, apiDataLimiter], getVulnerabilityDetail);

export default router;
