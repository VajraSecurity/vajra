import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.updateAvatar');

const CUSTOM_AVATAR_ID = 999;
const BUILT_IN_AVATAR_IDS = [1, 2, 3, 4];
// The frontend downscales uploads to 256x256 JPEG (~10-40KB as a data URL);
// 200KB leaves generous headroom while keeping profile rows small.
const MAX_IMAGE_LENGTH = 200_000;
const DATA_URL_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/;

export const update_avatar = async (req: Request, res: Response, next: NextFunction) => {
  const jwtPayload: JwtPayload = (req as any).jwtPayload as JwtPayload;
  const userId = jwtPayload?.id;

  if (!jwtPayload || !userId) {
    return next(new CustomError(401, 'Unauthorized', 'Missing valid JWT payload in request.', []));
  }

  const { avatarId, avatarImage } = req.body ?? {};
  const isCustom = avatarId === CUSTOM_AVATAR_ID;

  if (!Number.isInteger(avatarId) || (!isCustom && !BUILT_IN_AVATAR_IDS.includes(avatarId))) {
    logger.warn({ userId, avatarId }, 'Avatar update rejected: invalid avatar id');
    return next(new CustomError(400, 'Validation', 'Invalid avatar id.', []));
  }
  if (avatarImage !== undefined) {
    if (
      typeof avatarImage !== 'string' ||
      avatarImage.length > MAX_IMAGE_LENGTH ||
      !DATA_URL_RE.test(avatarImage)
    ) {
      logger.warn({ userId, avatarId, imageLength: typeof avatarImage === 'string' ? avatarImage.length : null }, 'Avatar update rejected: invalid avatar image');
      return next(new CustomError(400, 'Validation', 'Avatar image must be a jpeg/png/webp data URL under 200KB.', []));
    }
  }

  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length === 0) {
    logger.error({ userId }, 'Database connection not established for avatar update');
    return next(new CustomError(500, 'Database', 'Database connection source is missing.', []));
  }
  const userRepository = dbSources[0].getRepository(VajraUser);

  try {
    const user = await userRepository.findOne({ where: { id: userId } });
    if (!user) {
      logger.warn({ userId }, 'Avatar update rejected: user not found');
      return next(new CustomError(404, 'General', 'User not found.', []));
    }
    if (isCustom && !avatarImage && !user.avatar_image) {
      logger.warn({ userId }, 'Avatar update rejected: custom avatar requires an uploaded image');
      return next(new CustomError(400, 'Validation', 'Custom avatar requires an uploaded image.', []));
    }

    user.avatar_id = avatarId;
    if (avatarImage !== undefined) {
      user.avatar_image = avatarImage;
    }
    await userRepository.save(user);

    logger.info({ userId, avatarId: user.avatar_id }, 'Avatar updated');

    res.status(200).json({
      status: 'Success',
      message: 'Avatar updated successfully.',
      data: {
        avatar_id: user.avatar_id,
        avatar_image: user.avatar_image,
      },
    });
  } catch (err) {
    logger.error({ err, userId }, 'Failed to update avatar');
    const customError = new CustomError(500, 'Raw', 'Failed to update avatar.', null, err);
    return next(customError);
  }
};
