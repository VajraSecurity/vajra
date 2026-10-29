import { Router } from 'express';
import {
  get_rules,
  create_rule,
  update_rule,
  delete_rule,
  run_now,
} from '../../controllers/node-assignment-rules';
import { checkJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Auto-assignment rules (IP -> group) are Super Admin only, same as group management.
router.get('/', [checkJwt, requireSuperAdmin, apiDataLimiter], get_rules);
router.post('/', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], create_rule);
router.put('/:id', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], update_rule);
router.delete('/:id', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], delete_rule);
router.post('/run', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], run_now);

export default router;
