import { Router } from 'express';

import { getSessionStatus, userProfile, user_register, login, update_profile, update_avatar, update_password, verifyPassword, logout, logoutAllDevices,setupMfa, verifyMfaSetup, verifyMfa, recoverMfa, disableMfa, validateGrafana } from '../../controllers/auth';
import { checkAccessJwt, checkAccessWithRefreshFallback, requireSuperAdminIfUsersExist } from '../../middleware/checkJwt';
import { checkCsrf, checkCsrfIfAuthenticated } from '../../middleware/checkCSRFToken';
import {
  registerIpLimiter,
  registerEmailLimiter,
  validatorRegister,
  validatorLogin,
  validatorUpdateProfile,
  validatorUpdatePassword,
} from '../../middleware/validation/auth';
import {
  loginIpLimiter,
  loginEmailLimiter,
  mfaAccountLimiter,
  passwordUpdateLimiter,
  profileUpdateLimiter,
  sessionStatusLimiter,
  grafanaValidateLimiter,
} from '../../middleware/rateLimiters';

const router = Router();

router.get('/status', [checkAccessWithRefreshFallback, sessionStatusLimiter], getSessionStatus);
router.post('/login', [loginIpLimiter, loginEmailLimiter, validatorLogin], login);
router.post('/mfa/setup', [checkAccessJwt, checkCsrf, passwordUpdateLimiter], setupMfa);
router.post('/mfa/verify-setup', [checkAccessJwt, checkCsrf, passwordUpdateLimiter], verifyMfaSetup);
router.post('/mfa/disable', [checkAccessJwt, checkCsrf, passwordUpdateLimiter], disableMfa);
router.post('/mfa/verify', [loginIpLimiter, mfaAccountLimiter], verifyMfa);
router.post('/mfa/recover', [loginIpLimiter, mfaAccountLimiter], recoverMfa);
router.post('/user_register', [registerIpLimiter, registerEmailLimiter, requireSuperAdminIfUsersExist, checkCsrfIfAuthenticated, validatorRegister], user_register);
router.post('/profile/update', [checkAccessJwt, profileUpdateLimiter, validatorUpdateProfile, checkCsrf], update_profile);
router.post('/profile/avatar', [checkAccessJwt, profileUpdateLimiter, checkCsrf], update_avatar);
router.post('/profile/password-update', [checkAccessJwt, passwordUpdateLimiter, validatorUpdatePassword, checkCsrf], update_password);
router.post('/profile/verify-password', [checkAccessJwt, checkCsrf, passwordUpdateLimiter], verifyPassword);
// Attach jwtPayload (access or refresh) so logout can close UserSession rows
router.post('/logout', [checkAccessWithRefreshFallback, checkCsrf], logout);
router.post('/logout-all', [checkAccessWithRefreshFallback, checkCsrf], logoutAllDevices);
router.get('/profile', [checkAccessJwt], userProfile);
router.get('/validate', [grafanaValidateLimiter], validateGrafana);

export default router;