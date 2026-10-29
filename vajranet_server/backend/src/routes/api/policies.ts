import { Router } from 'express';
import {
  listPolicies,
  createPolicy,
  updatePolicy,
  assignTargets,
  deletePolicy,
} from '../../controllers/policies/policy_management';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

// Open to Super Administrator and Group Admin. Group Admin callers are
// restricted inside policy_management.ts to policies fully targeted at their
// own group's nodes (org-wide "all" policies are visible read-only, never
// creatable/editable by them) — see isPolicyFullyInScope()/getScopeContext().
router.get(
  '/',
  [checkAccessJwt, requireAdmin, apiDataLimiter],
  listPolicies,
);

router.post(
  '/',
  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf],
  createPolicy,
);

router.patch(
  '/:id',
  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf],
  updatePolicy,
);

router.patch(
  '/:id/targets',
  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf],
  assignTargets,
);

router.delete(
  '/:id',
  [checkAccessJwt, requireAdmin, apiMutationLimiter, checkCsrf],
  deletePolicy,
);

export default router;
