import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { UserSession } from '../../orm/entities/session/UserSession';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { 
    CSRF_COOKIE_NAME,
    ACCESS_TOKEN_COOKIE,
    REFRESH_TOKEN_COOKIE,
    SECURE_HTTP_ONLY_STRICT_OPTIONS,
    CLIENT_READABLE_STRICT_OPTIONS,
} from '../../utils/cookieConfig';
import { blacklistToken } from '../../utils/redisClient';
import { blacklistTokenMemory } from '../../utils/memoryStore';
import { getRedisClient } from '../../utils/redisClient';
import { JwtPayload } from '../../types/JwtPayload';
import {
  BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS,
  BLACKLIST_ACCESS_TOKEN_EXPIRY_MS,
  BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS,
  BLACKLIST_REFRESH_TOKEN_EXPIRY_MS,
} from '../../consts';
import { VajraUser } from '../../orm/entities/users/Users';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.logout');

export const logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const secureOptions = SECURE_HTTP_ONLY_STRICT_OPTIONS;
        const clientReadableOptions = CLIENT_READABLE_STRICT_OPTIONS;
        
        const jwtPayload: JwtPayload = (req as any).jwtPayload;
        const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
        
        // Blacklisted in both Redis and the in-memory store: the in-memory copy keeps the
        // token rejected if Redis goes down after logout.
        const accessToken = req.cookies[ACCESS_TOKEN_COOKIE];
        const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE];

        // Nothing has been mutated yet, so a blacklist failure here must be distinguishable
        // in the logs from a later session-update or audit-logging failure.
        try {
          if (accessToken) {
            blacklistTokenMemory(accessToken, BLACKLIST_ACCESS_TOKEN_EXPIRY_MS);
            if (getRedisClient()) {
              await blacklistToken(accessToken, BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS);
            }
          }

          if (refreshToken) {
            blacklistTokenMemory(refreshToken, BLACKLIST_REFRESH_TOKEN_EXPIRY_MS);
            if (getRedisClient()) {
              await blacklistToken(refreshToken, BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS);
            }
          }
        } catch (err) {
          logger.error({ err, userId: jwtPayload?.id }, 'Failed to blacklist tokens on logout');
          throw err;
        }

        if (jwtPayload?.id) {
          try {
            const dbSources = dbSourceConnection();
            if (!dbSources || dbSources.length === 0) {
              logger.warn({ userId: jwtPayload.id }, 'Database connection not established, skipping session record update on logout');
            } else {
              const sessionRepository = dbSources[0].getRepository(UserSession);

              let activeSession: UserSession | null = null;
              
              if (jwtPayload.sessionId) {
                activeSession = await sessionRepository.findOne({
                  where: { id: jwtPayload.sessionId, userId: jwtPayload.id, isActive: true },
                });
              }
              
              if (!activeSession) {
                // No session id in the token (older sessions): fall back to the most
                // recent active one.
                activeSession = await sessionRepository.findOne({
                  where: { userId: jwtPayload.id, isActive: true },
                  order: { loginTime: 'DESC' },
                });
              }
              
              if (activeSession) {
                activeSession.isActive = false;
                activeSession.logoutTime = new Date();
                activeSession.logoutReason = 'user_logout';

                if (activeSession.loginTime) {
                  const durationMs = activeSession.logoutTime.getTime() - activeSession.loginTime.getTime();
                  activeSession.durationSeconds = Math.floor(durationMs / 1000);
                }

                await sessionRepository.save(activeSession);
              } else {
                // No matching UserSession row to close (e.g. it was already closed, or
                // predates session tracking) — logout still proceeds, but the session
                // history table won't reflect this logout unless this is traceable.
                logger.debug({ userId: jwtPayload.id, sessionId: jwtPayload.sessionId }, 'No active session record found to close on logout');
              }
            }
          } catch (err) {
            logger.warn({ err, userId: jwtPayload.id }, 'Failed to update session record on logout');
            // Don't block logout if session update fails
          }
        }

        res.clearCookie(ACCESS_TOKEN_COOKIE, secureOptions);
        res.clearCookie(REFRESH_TOKEN_COOKIE, secureOptions);
        res.clearCookie(CSRF_COOKIE_NAME, clientReadableOptions);

        // Tokens are blacklisted and cookies cleared by this point, so an audit-logging
        // failure here must be distinguishable from the earlier steps in the logs.
        if (jwtPayload?.id && jwtPayload?.email) {
          try {
            await logAuditTrail({
              action: 'LOGOUT',
              status: 'success',
              userId: jwtPayload.id,
              email: jwtPayload.email,
              ipAddress: clientIp,
            });
          } catch (err) {
            logger.error({ err, userId: jwtPayload.id }, 'Tokens blacklisted but audit trail logging failed on logout');
            throw err;
          }
        }

        logger.info({ userId: jwtPayload?.id }, 'User logged out');

        res.status(200).json({
            status: 'Success',
            message: 'Logout successful. All session and security cookies cleared.',
        });

    } catch (err) {
        logger.error({ err }, 'Failed to perform logout');
        const customError = new CustomError(500, 'Raw', 'Failed to perform logout.', null, err);
        return next(customError);
    }
};

export const logoutAllDevices = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const secureOptions = SECURE_HTTP_ONLY_STRICT_OPTIONS;
    const clientReadableOptions = CLIENT_READABLE_STRICT_OPTIONS;

    const jwtPayload: JwtPayload = (req as any).jwtPayload;
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    const accessToken = req.cookies[ACCESS_TOKEN_COOKIE];
    const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE];

    // Nothing has been mutated yet, so a blacklist failure here must be distinguishable
    // in the logs from a later session-invalidation or audit-logging failure.
    try {
      if (accessToken) {
        blacklistTokenMemory(
          accessToken,
          BLACKLIST_ACCESS_TOKEN_EXPIRY_MS
        );

        if (getRedisClient()) {
          await blacklistToken(
            accessToken,
            BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS
          );
        }
      }

      if (refreshToken) {
        blacklistTokenMemory(
          refreshToken,
          BLACKLIST_REFRESH_TOKEN_EXPIRY_MS
        );

        if (getRedisClient()) {
          await blacklistToken(
            refreshToken,
            BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS
          );
        }
      }
    } catch (err) {
      logger.error({ err, userId: jwtPayload?.id }, 'Failed to blacklist tokens on logout from all devices');
      throw err;
    }

    let invalidatedSessionCount: number | null = null;
    if (jwtPayload?.id) {
      try {
        const dbSources = dbSourceConnection();

        if (!dbSources || dbSources.length === 0) {
          // Sessions/JWTs are NOT actually invalidated in this case, even though the
          // response below still reports success — this must be traceable in logs.
          logger.error({ userId: jwtPayload.id }, 'Database connection not established, sessions were not invalidated on logout-all-devices');
        } else {
          const userRepository =
            dbSources[0].getRepository(VajraUser);

          const sessionRepository =
            dbSources[0].getRepository(UserSession);

          await userRepository.increment(
            { id: jwtPayload.id },
            'session_version',
            1
          );

          const now = new Date();

          const activeSessions =
            await sessionRepository.find({
              where: {
                userId: jwtPayload.id,
                isActive: true,
              },
            });

          for (const session of activeSessions) {
            session.isActive = false;
            session.logoutTime = now;
            session.logoutReason = 'user_logout_all';

            session.durationSeconds = Math.floor(
              (now.getTime() -
                session.loginTime.getTime()) /
                1000
            );
          }

          if (activeSessions.length > 0) {
            await sessionRepository.save(
              activeSessions
            );
          }
          invalidatedSessionCount = activeSessions.length;
        }
      } catch (err) {
        logger.warn({ err, userId: jwtPayload.id }, 'Failed to update sessions on logout from all devices');
        // Don't block logout
      }
    }

    res.clearCookie(
      ACCESS_TOKEN_COOKIE,
      secureOptions
    );

    res.clearCookie(
      REFRESH_TOKEN_COOKIE,
      secureOptions
    );

    res.clearCookie(
      CSRF_COOKIE_NAME,
      clientReadableOptions
    );

    // Tokens are blacklisted and cookies cleared by this point, so an audit-logging
    // failure here must be distinguishable from the earlier steps in the logs.
    if (jwtPayload?.id && jwtPayload?.email) {
      try {
        await logAuditTrail({
          action: 'LOGOUT',
          status: 'success',
          userId: jwtPayload.id,
          email: jwtPayload.email,
          ipAddress: clientIp,
          details: { reason: 'logout_all_devices' },
        });
      } catch (err) {
        logger.error({ err, userId: jwtPayload.id }, 'Tokens blacklisted and sessions invalidated but audit trail logging failed on logout from all devices');
        throw err;
      }
    }

    logger.info({ userId: jwtPayload?.id, invalidatedSessionCount }, 'User logged out from all devices');

    res.status(200).json({
      status: 'Success',
      message:
        'Logout successful from all devices and sessions.',
    });
  } catch (err) {
    logger.error({ err }, 'Failed to perform logout from all devices');

    const customError = new CustomError(
      500,
      'Raw',
      'Failed to perform logout from all devices.',
      null,
      err
    );

    return next(customError);
  }
};