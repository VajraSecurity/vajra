import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { createAccessToken } from '../../utils/createJwtToken'; 
import { setAccessTokenCookie } from '../../utils/renewAccessToken';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.updateProfile');

export const update_profile = async (req: Request, res: Response, next: NextFunction) => {
    const { name, mobile, company, address } = req.body; 

    const jwtPayload: JwtPayload = (req as any).jwtPayload as JwtPayload;
    const userId = jwtPayload?.id;
    let tokenReissueNeeded = false;

    if (!jwtPayload || !userId) {
        return next(new CustomError(401, 'Unauthorized', 'Missing valid JWT payload in request.', []));
    }
    
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
        logger.error({ userId }, 'Database connection not established for profile update');
        return next(new CustomError(500, 'Database', 'Database connection source is missing.', []));
    }
    const userRepository = dbSources[0].getRepository(VajraUser);

    try {
        const user = await userRepository.findOne({ where: { id: userId } });

        if (!user) {
            logger.warn({ userId }, 'Profile update rejected: user not found');
            return next(new CustomError(404, 'General', 'User not found.', []));
        }
        const changedFields: string[] = [];
        if (name && user.name !== name) {
            user.name = name;
            tokenReissueNeeded = true;
            changedFields.push('name');
        }
        if (mobile && user.mobile !== mobile) {
            user.mobile = mobile;
            changedFields.push('mobile');
        }
        if (company && user.company !== company) {
            user.company = company;
            changedFields.push('company');
        }
        if (address && user.address !== address) {
            user.address = address;
            changedFields.push('address');
        }
        await userRepository.save(user);
        if (tokenReissueNeeded) {
            // Profile fields are already committed at this point — distinguish a token
            // reissue failure here from an actual save failure above, since both would
            // otherwise land in the generic catch below with the same log line and make
            // an already-successful update look like it never happened.
            try {
                const updatedJwtPayload: JwtPayload = {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: jwtPayload.role,
                    created_at: user.created_at,
                    session_version: user.session_version,
                    sessionId: jwtPayload.sessionId,
                    force_password_change: user.forcePasswordChange,
                };
                const updatedToken = createAccessToken(updatedJwtPayload);
                setAccessTokenCookie(res, updatedToken);
            } catch (err) {
                logger.error({ err, userId }, 'Profile updated but access token reissue failed');
                throw err;
            }
        }

        logger.info({ userId, changedFields, tokenReissued: tokenReissueNeeded }, 'Profile updated');

        res.status(200).json({
            status: 'Success',
            message: 'Profile updated successfully.',
            data: { 
                name: user.name, 
                email: user.email,
                mobile: user.mobile,
                company: user.company,
                address: user.address 
            }
        });
    } catch (err) {
        logger.error({ err, userId }, 'Failed to update profile');
        const customError = new CustomError(500, 'Raw', 'Failed to update profile.', null, err);
        return next(customError);
    }
};
