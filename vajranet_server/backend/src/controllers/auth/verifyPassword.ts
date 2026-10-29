import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { randomUUID } from 'crypto';
import { getRedisClient, storeShellToken } from '../../utils/redisClient';
import { storeShellTokenMemory } from '../../utils/memoryStore';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.verifyPassword');

const SHELL_TOKEN_EXPIRY_SECONDS = 60;

export const verifyPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { password } = req.body;
  const jwtPayload = req.jwtPayload;

  if (!jwtPayload || !jwtPayload.id) {
    const customError = new CustomError(401, 'Unauthorized', 'Not authorized');
    return next(customError);
  }

  if (!password) {
    logger.warn({ userId: jwtPayload.id }, 'Shell token request rejected: password missing from request body');
    return res.status(400).json({ status: 'Fail', message: 'Password is required' });
  }

  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length === 0) {
    logger.error({ userId: jwtPayload.id }, 'Database connection not established for password verification');
    const customError = new CustomError(500, 'Database', 'Primary database connection source is missing', []);
    return next(customError);
  }

  const dbConnection = dbSources[0];
  const userRepository = dbConnection.getRepository(VajraUser);

  try {
    const user = await userRepository.findOne({ where: { id: jwtPayload.id } });

    if (!user) {
      logger.warn({ userId: jwtPayload.id }, 'Shell token request rejected: user not found');
      return res.status(401).json({ status: 'Fail', message: 'User not found' });
    }

    const isValidPassword = await user.checkIfPasswordMatch(password);

    if (!isValidPassword) {
      logger.warn({ userId: jwtPayload.id }, 'Shell token request rejected: invalid password');
      return res.status(401).json({ status: 'Fail', message: 'Invalid password' });
    }

    const token = randomUUID();
    const userIdString = String(jwtPayload.id);

    // Password is already verified valid at this point — distinguish a shell-token
    // storage failure here from an actual password-check failure above, since both
    // would otherwise land in the generic catch below with the same log line.
    try {
      if (getRedisClient()) {
        await storeShellToken(token, userIdString, SHELL_TOKEN_EXPIRY_SECONDS);
      } else {
        storeShellTokenMemory(token, userIdString, SHELL_TOKEN_EXPIRY_SECONDS * 1000);
      }
    } catch (err) {
      logger.error({ err, userId: jwtPayload.id }, 'Password verified but shell token storage failed');
      throw err;
    }

    logger.info({ userId: jwtPayload.id }, 'Password verified, shell token issued');

    return res.status(200).json({
      status: 'Success',
      message: 'Password verified',
      shell_token: token
    });
  } catch (err) {
    logger.error({ err, userId: jwtPayload.id }, 'Failed to verify password');
    const customError = new CustomError(500, 'Raw', 'Error verifying password', null, err);
    return next(customError);
  }
};
