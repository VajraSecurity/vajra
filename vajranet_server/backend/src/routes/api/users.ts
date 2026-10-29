import { Router } from 'express';
import {
  alert_audit_trail_list,
  audit_trail_list,
  session_actions_list,
  session_history_list,
  user_by_id,
  users_list,
} from '../../controllers/users';
import { team_list } from '../../controllers/users/team_list';
import { team_transfer_ownership } from '../../controllers/users/team_transfer_ownership';
import { team_update } from '../../controllers/users/team_update';
import { team_force_password_change } from '../../controllers/users/team_force_password_change';
import { invalidate_sessions, invalidate_user_sessions } from '../../controllers/users/session_management';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';

const router = Router();

router.get('/audit-trail', [checkAccessJwt, requireSuperAdmin, apiDataLimiter], audit_trail_list);
router.get('/audit-trail/alerts', [checkAccessJwt, requireSuperAdmin, apiDataLimiter], alert_audit_trail_list);
router.get('/session-history', [checkAccessJwt, requireSuperAdmin, apiDataLimiter], session_history_list);
router.get('/session-actions', [checkAccessJwt, requireSuperAdmin, apiDataLimiter], session_actions_list);
router.get('/list', [checkAccessJwt, apiDataLimiter], users_list);
router.get('/by-id', [checkAccessJwt, apiDataLimiter], user_by_id);
// Uses apiMutationLimiter (not apiDataLimiter, used above for the GET routes
// in this file) on every POST here — apiMutationLimiter's 15-min window is
// the appropriate throttle for state-changing requests.
router.post('/sessions/invalidate', [checkAccessJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], invalidate_sessions);
router.post('/sessions/invalidate-user', [checkAccessJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], invalidate_user_sessions);
router.get('/team', [checkAccessJwt, requireSuperAdmin, apiDataLimiter], team_list);
router.post('/team/update', [checkAccessJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], team_update);
router.post('/team/transfer-ownership', [checkAccessJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], team_transfer_ownership);
router.post('/team/force-password-change', [checkAccessJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], team_force_password_change);

export default router;
