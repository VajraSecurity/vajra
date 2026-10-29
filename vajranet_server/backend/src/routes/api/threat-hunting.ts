import { Router } from 'express';
import {
  run_query,
  list_saved_queries,
  get_saved_query,
  create_saved_query,
  update_saved_query,
  delete_saved_query,
  populate_default_saved_queries,
} from '../../controllers/threat-hunting';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Run an ad-hoc SELECT query against the fleet database
router.post('/run', [checkAccessJwt, requireAdmin, apiDataLimiter, checkCsrf], run_query);

// Saved queries CRUD — the library is shared/global (not per-user), matching
// /run's own requireAdmin gate: read access (list/get) stays open to any
// authenticated user, but every mutation requires Admin so a Viewer can't
// create/edit/delete the queries Admins rely on.
router.post('/queries/populate-saved-queries', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], populate_default_saved_queries);
router.get('/queries', [checkAccessJwt, apiDataLimiter], list_saved_queries);
router.get('/queries/:id', [checkAccessJwt, apiDataLimiter], get_saved_query);
router.post('/queries', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], create_saved_query);
router.put('/queries/:id', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], update_saved_query);
router.delete('/queries/:id', [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf], delete_saved_query);

export default router;
