import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { auditPasswordChange } from '../../utils/auditLogger';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, CSRF_COOKIE_NAME, SECURE_HTTP_ONLY_STRICT_OPTIONS, CLIENT_READABLE_STRICT_OPTIONS } from '../../utils/cookieConfig';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.updatePassword');

const getCookieClearOptions = (isHttpOnly: boolean) => (isHttpOnly ? SECURE_HTTP_ONLY_STRICT_OPTIONS : CLIENT_READABLE_STRICT_OPTIONS);

export const update_password = async (req: Request, res: Response, next: NextFunction) => {
    const { currentPassword, newPassword } = req.body;
    const clientIp = req.ip || req.socket.remoteAddress || null;
    
    const jwtPayload: JwtPayload = (req as any).jwtPayload as JwtPayload;
    const userId = jwtPayload?.id;

    if (!currentPassword || !newPassword) {
        logger.warn({ userId }, 'Password update rejected: missing current or new password field');
        return next(new CustomError(400, 'Validation', 'Missing password fields.', []));
    }

    if (!jwtPayload || !userId) {
        return next(new CustomError(401, 'Unauthorized', 'Missing valid JWT payload in request.', []));
    }
    
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
        logger.error({ userId }, 'Database connection not established for password update');
        return next(new CustomError(500, 'Database', 'Database connection source is missing.', []));
    }
    const userRepository = dbSources[0].getRepository(VajraUser);

    try {
        const user = await userRepository.findOne({ where: { id: userId } });

        if (!user) {
            logger.warn({ userId }, 'Password update rejected: user not found');
            return next(new CustomError(404, 'General', 'User not found.', []));
        }

        const isPasswordValid = await user.checkIfPasswordMatch(currentPassword);

        if (!isPasswordValid) {
            logger.warn({ userId: user.id }, 'Password update rejected: incorrect current password');
            await logAuditTrail({
              action: 'PASSWORD_UPDATE',
              status: 'failure',
              userId: user.id,
              email: user.email,
              ipAddress: clientIp,
              details: { reason: 'incorrect_current_password' },
            });
            return next(new CustomError(401, 'Unauthorized', 'Incorrect current password.', []));
        }

        user.password_hash = newPassword;
        await user.hashPassword();
        user.forcePasswordChange = false;
        user.session_version = (user.session_version || 0) + 1;
        await userRepository.save(user);

        // Audit log the password change. Password is already saved and sessions already
        // invalidated at this point — distinguish an audit-logging failure here from an
        // actual password-update failure so the generic catch below isn't misleading.
        try {
          await auditPasswordChange(userId, user.email, clientIp ?? undefined);
          await logAuditTrail({
            action: 'PASSWORD_UPDATE',
            status: 'success',
            userId: user.id,
            email: user.email,
            ipAddress: clientIp,
          });
        } catch (auditErr) {
          logger.error({ err: auditErr, userId: user.id }, 'Password updated but audit trail logging failed');
          throw auditErr;
        }


        const secureOptions = getCookieClearOptions(true);
        const clientReadableOptions = getCookieClearOptions(false);

        res.clearCookie(ACCESS_TOKEN_COOKIE, secureOptions); 
        res.clearCookie(REFRESH_TOKEN_COOKIE, secureOptions); 
        res.clearCookie(CSRF_COOKIE_NAME, clientReadableOptions); 

        logger.info({ userId }, 'Password updated');

        // Do NOT generate new tokens. The user must log in again with their new password.
        res.status(200).json({
            status: 'Success',
            message: 'Password updated successfully. Please log in again with your new password.',
        });
        
    } catch (err) {
        logger.error({ err, userId }, 'Failed to update password');
        const jwtPayload: JwtPayload = (req as any).jwtPayload;
        if (jwtPayload?.id) {
            const userRepository = dbSourceConnection()?.[0]?.getRepository(VajraUser);
            const user = userRepository && (await userRepository.findOne({ where: { id: jwtPayload.id } }));
            await logAuditTrail({
              action: 'PASSWORD_UPDATE',
              status: 'failure',
              userId: jwtPayload.id,
              email: user?.email ?? null,
              ipAddress: clientIp,
              details: { reason: 'error' },
            }).catch((auditErr) => {
              logger.warn({ err: auditErr, userId: jwtPayload.id }, 'Failed to record audit trail for failed password update');
            });
        }
        const customError = new CustomError(500, 'Raw', 'Failed to update password.', null, err);
        return next(customError);
    }
};
