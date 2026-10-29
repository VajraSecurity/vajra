import { Router } from 'express';
import {
  create_group,
  get_groups,
  assign_nodes,
  delete_group,
  assign_users,
  get_group_users,
} from '../../controllers/endpoint-groups';
import { checkJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Group management (create/delete groups, assign nodes/users to groups) is Super Admin only.
router.post('/', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], create_group);
router.get('/', [checkJwt, apiDataLimiter], get_groups);
router.put('/:id/nodes', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], assign_nodes);
router.get('/:id/users', [checkJwt, requireSuperAdmin, apiDataLimiter], get_group_users);
router.put('/:id/users', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], assign_users);
router.delete('/:id', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], delete_group);

export default router;
