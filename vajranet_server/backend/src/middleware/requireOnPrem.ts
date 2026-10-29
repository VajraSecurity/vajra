import { Request, Response, NextFunction } from 'express';
import { getLogger } from '../utils/logger';

const logger = getLogger('middleware.requireOnPrem');

export const requireOnPrem = (req: Request, res: Response, next: NextFunction): void => {
    if (process.env.ON_PREM !== 'true') {
        logger.warn({ path: req.originalUrl }, 'Blocked network operation: ON_PREM is not enabled in this environment');
        res.status(403).json({ error: 'Network operations are disabled in this environment.' });
        return;
    }
    next();
};
