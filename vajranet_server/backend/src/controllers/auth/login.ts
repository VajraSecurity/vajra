import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { USER_ROLES, VajraUser, DEFAULT_USER_ROLE } from '../../orm/entities/users/Users';
import { UserSession } from '../../orm/entities/session/UserSession';
import { JwtPayload } from '../../types/JwtPayload';
import { createMfaToken, createAccessToken, createRefreshToken, generateCsrfToken } from '../../utils/createJwtToken';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { normalizeEmail } from '../../utils/sanitization';
import { setAccessTokenCookie } from '../../utils/renewAccessToken';
import { setRefreshTokenCookie } from '../../utils/renewRefreshToken';
import { setCsrfTokenCookie } from '../../utils/renewCSRFToken';
import { auditLoginAttempt } from '../../utils/auditLogger';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import svgCaptcha from 'svg-captcha';
import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import {
  getFailedAttempts,
  incrementFailedAttempts,
  clearFailedAttempts,
  storeCaptcha,
  verifyCaptcha,
  getRedisClient,
} from '../../utils/redisClient';
import {
  getFailedAttemptsMemory,
  incrementFailedAttemptsMemory,
  clearFailedAttemptsMemory,
  storeCaptchaMemory,
  verifyCaptchaMemory,
} from '../../utils/memoryStore';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.login');

const MAX_FAILED_ATTEMPTS = Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS);
const CAPTCHA_EXPIRY_MS = Number(process.env.LOGIN_CAPTCHA_EXPIRY_MS);

// Captcha and failed-attempt state lives in Redis when it is available, with an
// in-memory fallback so a single-instance deployment still rate-limits correctly.
async function storeLoginCaptcha(text: string): Promise<string> {
  const id = randomUUID();
  if (getRedisClient()) {
    await storeCaptcha(id, text, CAPTCHA_EXPIRY_MS);
  } else {
    storeCaptchaMemory(id, text, CAPTCHA_EXPIRY_MS);
  }
  return id;
}

async function verifyLoginCaptcha(id: string, input: string): Promise<boolean> {
  if (getRedisClient()) {
    return await verifyCaptcha(id, input);
  }
  return verifyCaptchaMemory(id, input);
}

async function getLoginAttempts(email: string): Promise<number> {
  if (getRedisClient()) {
    return await getFailedAttempts(email);
  }
  return getFailedAttemptsMemory(email);
}

async function incrementLoginAttempts(email: string): Promise<number> {
  if (getRedisClient()) {
    return await incrementFailedAttempts(email);
  }
  return incrementFailedAttemptsMemory(email);
}

async function clearLoginAttempts(email: string): Promise<void> {
  if (getRedisClient()) {
    await clearFailedAttempts(email);
  } else {
    clearFailedAttemptsMemory(email);
  }
}

function svgToDataUrl(svgMarkup: string): string {
  const b64 = Buffer.from(String(svgMarkup), 'utf8').toString('base64');
  return `data:image/svg+xml;base64,${b64}`;
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password, captcha, captchaId } = req.body;
  const clientIp = req.ip || req.socket.remoteAddress || null;
  const userAgent = req.get('user-agent') || null;

  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length === 0) {
    logger.error({ email }, 'Database connection not established for login');
    const customError = new CustomError(500, 'Database', 'Primary database connection source is missing or not initialized.', []);
    return next(customError);
  }

  const dbConnection = dbSources[0];
  const userRepository = dbConnection.getRepository(VajraUser);
  const sessionRepository = dbConnection.getRepository(UserSession);

  // --- BRUTE FORCE CHECK ---
  const normalizedEmail = normalizeEmail(email);
  const attempts = await getLoginAttempts(normalizedEmail);
  const captchaRequired = attempts >= MAX_FAILED_ATTEMPTS;

  if (captchaRequired) {
    if (!captcha || !captchaId || !(await verifyLoginCaptcha(captchaId, captcha))) {
      const newCaptcha = svgCaptcha.create();
      const newCaptchaId = await storeLoginCaptcha(newCaptcha.text);

      await auditLoginAttempt(normalizedEmail, false, clientIp ?? undefined, userAgent ?? undefined);
      await logAuditTrail({ action: 'LOGIN', status: 'failure', email: normalizedEmail, ipAddress: clientIp, userAgent });

      logger.warn({ email: normalizedEmail, attempts }, 'Login blocked: captcha required or not satisfied');

      return res.status(401).json({
        status: 'CaptchaRequired',
        message: `Too many failed attempts. Please verify CAPTCHA to proceed. Attempts: ${attempts}`,
        captcha: svgToDataUrl(newCaptcha.data),
        captchaId: newCaptchaId
      });
    }
  }
  // -------------------------

  try {
    const user = await userRepository.findOne({ where: { email: normalizedEmail } });

    // Timing attack protection: Always check password even if user doesn't exist
    // This ensures consistent response time whether user exists or not
    const isValidPassword = user ? await user.checkIfPasswordMatch(password) : false;

    // Perform a dummy password check if user doesn't exist to maintain consistent timing
    if (!user) {
      // Simulate password hashing time to prevent timing attacks using a cost-12 hash
      await bcrypt.compare(password, '$2b$12$z2xVDiIoqaV.KobFdCrPkO/I2lbbNd5V/fKP7sTYK7Rw15JiRTrZO');
      await incrementLoginAttempts(normalizedEmail);
      await auditLoginAttempt(normalizedEmail, false, clientIp ?? undefined, userAgent ?? undefined);
      await logAuditTrail({ action: 'LOGIN', status: 'failure', email: normalizedEmail, ipAddress: clientIp, userAgent });
      logger.warn({ email: normalizedEmail }, 'Login failed: user not found');
      return res.status(401).json({ status: 'Fail', message: 'Invalid email or password' });
    }

    if (!isValidPassword) {
      await incrementLoginAttempts(normalizedEmail);
      await auditLoginAttempt(normalizedEmail, false, clientIp ?? undefined, userAgent ?? undefined);
      await logAuditTrail({ action: 'LOGIN', status: 'failure', email: normalizedEmail, ipAddress: clientIp, userAgent });

      const currentAttempts = await getLoginAttempts(normalizedEmail);
      if (currentAttempts >= MAX_FAILED_ATTEMPTS) {
        const newCaptcha = svgCaptcha.create();
        const newCaptchaId = await storeLoginCaptcha(newCaptcha.text);

        logger.warn({ userId: user.id, email: user.email, attempts: currentAttempts }, 'Login failed: incorrect password, captcha now required');

        return res.status(401).json({
          status: 'CaptchaRequired',
          message: `Too many failed attempts (${currentAttempts}). CAPTCHA is now required.`,
          captcha: svgToDataUrl(newCaptcha.data),
          captchaId: newCaptchaId
        });
      }

      logger.warn({ userId: user.id, email: user.email, attempts: currentAttempts }, 'Login failed: incorrect password');

      return res.status(401).json({ status: 'Fail', message: 'Invalid email or password' });
    }

    if (user.suspended) {
      await incrementLoginAttempts(normalizedEmail);
      await auditLoginAttempt(normalizedEmail, false, clientIp ?? undefined, userAgent ?? undefined);
      await logAuditTrail({
        action: 'LOGIN',
        status: 'failure',
        userId: user.id,
        email: user.email,
        ipAddress: clientIp,
        userAgent,
        details: { reason: 'account_suspended' },
      });
      logger.warn({ userId: user.id, email: user.email }, 'Login blocked: account suspended');
      return res.status(403).json({
        status: 'Fail',
        message: 'Your account has been suspended. Contact your administrator.',
      });
    }

    // --- SUCCESSFUL LOGIN ---
    // Credentials are already verified at this point — distinguish an attempts/audit
    // bookkeeping failure here from an actual credential-check failure above, since
    // both would otherwise land in the generic catch below with the same log line.
    try {
      await clearLoginAttempts(normalizedEmail);
      await auditLoginAttempt(normalizedEmail, true, clientIp ?? undefined, userAgent ?? undefined);
      await logAuditTrail({ action: 'LOGIN', status: 'success', userId: user.id, email: user.email, ipAddress: clientIp, userAgent });
    } catch (err) {
      logger.error({ err, userId: user.id, email: user.email }, 'Credentials valid but login attempts/audit bookkeeping failed');
      throw err;
    }

    const normalizedRole = USER_ROLES.includes(user.role) ? user.role : DEFAULT_USER_ROLE;
    if (user.role !== normalizedRole) {
      logger.warn({ userId: user.id, storedRole: user.role, normalizedRole }, 'Invalid stored role corrected to default on login');
      await userRepository.update(user.id, { role: normalizedRole });
    }

    try {
      if (!user.mfa_enabled || !user.mfa_secret) {
        const userSession = new UserSession();
        userSession.userId = user.id;
        userSession.ipAddress = clientIp;
        userSession.userAgent = userAgent;
        userSession.isActive = true;

        try {
          await sessionRepository.save(userSession);
        } catch (err) {
          logger.warn({ err, userId: user.id }, 'Failed to create user session on login');
          // Proceed even if session tracking fails
        }

        const jwtPayload: JwtPayload = {
          id: user.id,
          name: user.name,
          email: user.email,
          role: normalizedRole,
          created_at: user.created_at,
          session_version: user.session_version,
          sessionId: userSession.id,
          force_password_change: user.forcePasswordChange,
        };


        const accessToken = createAccessToken(jwtPayload);
        const refreshToken = createRefreshToken(jwtPayload);
        const csrfToken = generateCsrfToken();
        setAccessTokenCookie(res, accessToken);
        setRefreshTokenCookie(res, refreshToken);
        setCsrfTokenCookie(res, csrfToken);

        logger.info({ userId: user.id, sessionId: userSession.id }, 'User login successful');

        return res.status(200).json({
          status: 'Success',
          message: 'Login successful.',
        });
      }

      const mfaToken = createMfaToken({ id: user.id, email: user.email });

      logger.info({ userId: user.id }, 'Login credentials valid, MFA verification required');

      return res.status(200).json({
        status: 'MfaRequired',
        message: 'MFA verification required.',
        mfaToken
      });

    } catch (err) {
      logger.error({ err, userId: user.id }, 'Session or token creation failed after login');
      const customError = new CustomError(400, 'Raw', "Session or token creation failed", null, err);
      return next(customError);
    }
  } catch (err) {
    logger.error({ err, email: normalizedEmail }, 'Error during login process');
    const customError = new CustomError(500, 'Raw', 'Error during login process', null, err);
    return next(customError);
  }
};