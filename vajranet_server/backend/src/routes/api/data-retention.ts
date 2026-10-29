import { Router } from 'express';
import { checkJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import {
    getDataRetentionPolicies,
    createDataRetentionPolicy,
    updateDataRetentionPolicy,
    deleteDataRetentionPolicy,
    getDatabases,
    getTables,
    getColumns
} from '../../controllers/data-retention/dataRetentionController';

const router = Router();

// Only Super Administrators can view or modify data retention policies
router.get('/', [checkJwt, requireSuperAdmin, apiDataLimiter], getDataRetentionPolicies);
router.post('/', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], createDataRetentionPolicy);
router.put('/:id', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], updateDataRetentionPolicy);
router.delete('/:id', [checkJwt, requireSuperAdmin, apiMutationLimiter, checkCsrf], deleteDataRetentionPolicy);

router.get('/databases', [checkJwt, requireSuperAdmin, apiDataLimiter], getDatabases);
router.get('/tables/:db', [checkJwt, requireSuperAdmin, apiDataLimiter], getTables);
router.get('/columns/:db/:table', [checkJwt, requireSuperAdmin, apiDataLimiter], getColumns);

export default router;
