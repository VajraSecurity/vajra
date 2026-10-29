import { Router } from 'express';
import { alert_severity_count, weekly_alerts, alert_status, graph_node_compliance_latest } from '../../controllers/device-graphs'; //vul_programs_list, Top_Vul_List
import { checkAccessJwt } from '../../middleware/checkJwt';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { defender_count, os_count, top5_machine_alert, top5_machine_usb } from '../../controllers/general-graphs';
import { apiDataLimiter } from '../../middleware/rateLimiters';
import { nodes_memory_health } from '../../controllers/windows';
import { firewall_type } from '../../controllers/device-graphs/firewall_diff';

const router = Router();
router.post('/severity', [checkAccessJwt, apiDataLimiter, checkCsrf], alert_severity_count);
router.post('/weekly_alerts', [checkAccessJwt, apiDataLimiter, checkCsrf], weekly_alerts);
router.post('/alert_status', [checkAccessJwt, apiDataLimiter, checkCsrf], alert_status);
router.get('/os_count', [checkAccessJwt, apiDataLimiter], os_count);
router.get('/defender_count', [checkAccessJwt, apiDataLimiter], defender_count);
router.get('/top5_machine_alerts', [checkAccessJwt, apiDataLimiter], top5_machine_alert);
router.get('/top5_machine_usb', [checkAccessJwt, apiDataLimiter], top5_machine_usb);
router.post('/memory_graph', [checkAccessJwt, apiDataLimiter, checkCsrf], nodes_memory_health);
router.post('/firewall_diff', [checkAccessJwt, apiDataLimiter, checkCsrf], firewall_type);
router.post('/node_compliance_latest', [checkAccessJwt, apiDataLimiter, checkCsrf], graph_node_compliance_latest);


export default router;