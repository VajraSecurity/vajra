//Server/src/routes/api windows.ts

import { Router } from 'express';
import { windows_security_products_fetch, bios_info_fetch, firewall_rules_fetch, secureboot_fetch, windows_security_center_fetch, security_profile_info_fetch, system_info_fetch, tpm_info_fetch, windows_update_history_fetch, latest_update_history_fetch, firewall_rules_diff } from '../../controllers/windows';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter } from '../../middleware/rateLimiters';

const router = Router();
const windowsMiddleware = [checkAccessJwt, apiDataLimiter, checkCsrf];

router.post('/bios_info', windowsMiddleware, bios_info_fetch);
router.post('/firewall_rules', windowsMiddleware, firewall_rules_fetch);
router.post('/firewall_rules_diff', windowsMiddleware, firewall_rules_diff);
router.post('/secureboot', windowsMiddleware, secureboot_fetch);
router.post('/security_center', windowsMiddleware, windows_security_center_fetch);
router.post('/security_products', windowsMiddleware, windows_security_products_fetch);
router.post('/profile_info', windowsMiddleware, security_profile_info_fetch);
router.post('/system_info', windowsMiddleware, system_info_fetch);
router.post('/tpm_info', windowsMiddleware, tpm_info_fetch);
router.post('/update_history', windowsMiddleware, windows_update_history_fetch);
router.post('/latest_update', windowsMiddleware, latest_update_history_fetch);

export default router;