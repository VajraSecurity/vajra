import { Request, Response, NextFunction } from 'express';
import QRCode from 'qrcode';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { dbSourceConnection } from '../../index';
import { USER_ROLES, VajraUser, DEFAULT_USER_ROLE } from '../../orm/entities/users/Users';
import { UserSession } from '../../orm/entities/session/UserSession';
import { JwtPayload } from '../../types/JwtPayload';
import { createAccessToken, createRefreshToken, generateCsrfToken, verifyMfaToken } from '../../utils/createJwtToken';
import { setAccessTokenCookie } from '../../utils/renewAccessToken';
import { setRefreshTokenCookie } from '../../utils/renewRefreshToken';
import { setCsrfTokenCookie } from '../../utils/renewCSRFToken';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { BCRYPT_SALT_ROUNDS, RECOVERY_CODE_BCRYPT_SALT_ROUNDS } from '../../consts/auth';
import { getLogger } from '../../utils/logger';
import { claimTotpCodeOnce } from '../../utils/redisClient';
import { buildTotpAuthUrl, generateTotpSecret, verifyTotpCode } from '../../utils/totp';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('auth.mfa');

// Generate MFA Setup QR Code
export const setupMfa = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req as any).jwtPayload?.id;
    if (!userId) return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ userId }, 'Database connection not established for MFA setup');
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const dbConnection = dbSources[0];
    const userRepository = dbConnection.getRepository(VajraUser);
    const user = await userRepository.findOne({ where: { id: userId } });

    if (!user) {
      logger.warn({ userId }, 'MFA setup rejected: user not found');
      return res.status(404).json({ status: 'Fail', message: 'User not found' });
    }
    if (user.mfa_enabled) {
      logger.warn({ userId: user.id }, 'MFA setup rejected: MFA already enabled');
      return res.status(400).json({ status: 'Fail', message: 'MFA already enabled' });
    }

    const secret = generateTotpSecret();

    user.mfa_secret = secret;

    // Generated up front, then hashed together via Promise.all rather than one
    // `await bcrypt.hash` per loop iteration — 10 sequential cost-12 hashes
    // measured 3-6.5s end-to-end (this endpoint's own unit test timed out at
    // Vitest's 5s default). RECOVERY_CODE_BCRYPT_SALT_ROUNDS (not
    // BCRYPT_SALT_ROUNDS) is deliberate here: see its own comment in
    // consts/auth.ts for why a lower cost is fine for a 48-bit random secret
    // that isn't fine for a user-chosen password.
    const plainRecoveryCodes: string[] = Array.from({ length: 10 }, () => {
      const raw = crypto.randomBytes(6).toString('hex');
      return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
    });
    const hashedRecoveryCodes = await Promise.all(
      plainRecoveryCodes.map((code) => bcrypt.hash(code, RECOVERY_CODE_BCRYPT_SALT_ROUNDS)),
    );

    await userRepository.update(user.id, {
      mfa_secret: secret,
      recovery_codes: hashedRecoveryCodes
    });

    const qrCodeUrl = await QRCode.toDataURL(buildTotpAuthUrl(`VajraNet (${user.email})`, secret));

    logger.info({ userId: user.id }, 'MFA setup initiated');

    return res.status(200).json({
      status: 'Success',
      qrCode: qrCodeUrl,
      secret,
      recoveryCodes: plainRecoveryCodes,
    });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to setup MFA');
    return next(new CustomError(500, 'Raw', 'Failed to setup MFA', null, error));
  }
};

// Verify MFA setup and enable it for the user
export const verifyMfaSetup = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = req.body;
    if (!token) return res.status(400).json({ status: 'Fail', message: 'Missing MFA code' });
    if (!securityQuestion1 || !securityAnswer1 || !securityQuestion2 || !securityAnswer2) {
      return res.status(400).json({ status: 'Fail', message: 'Missing security questions or answers' });
    }

    const userId = (req as any).jwtPayload?.id;
    if (!userId) return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ userId }, 'Database connection not established for MFA setup verification');
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const dbConnection = dbSources[0];
    const userRepository = dbConnection.getRepository(VajraUser);
    const user = await userRepository.findOne({ where: { id: userId } });

    if (!user || !user.mfa_secret) {
      logger.warn({ userId, userFound: !!user }, 'MFA setup verification rejected: MFA not initialized for user');
      return res.status(400).json({ status: 'Fail', message: 'MFA not set up for this user' });
    }

    const verified = verifyTotpCode(user.mfa_secret, token);

    if (!verified) {
      logger.warn({ userId: user.id }, 'MFA setup verification failed: invalid code');
      return res.status(401).json({ status: 'Fail', message: 'Invalid MFA code' });
    }
    if (!(await claimTotpCodeOnce(user.id, token))) {
      logger.warn({ userId: user.id }, 'MFA setup verification rejected: code already used');
      return res.status(401).json({ status: 'Fail', message: 'Invalid MFA code' });
    }

    await userRepository.update(user.id, {
      mfa_enabled: true,
      security_question_1: securityQuestion1,
      security_answer_1_hash: await bcrypt.hash(securityAnswer1.toLowerCase().trim(), BCRYPT_SALT_ROUNDS),
      security_question_2: securityQuestion2,
      security_answer_2_hash: await bcrypt.hash(securityAnswer2.toLowerCase().trim(), BCRYPT_SALT_ROUNDS)
    });

    logger.info({ userId: user.id }, 'MFA setup completed and enabled');

    return res.status(200).json({
      status: 'Success',
      message: 'MFA setup completed successfully.',
    });

  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to verify MFA setup');
    return next(new CustomError(500, 'Raw', 'Failed to verify MFA setup', null, error));
  }
};

// Verify MFA and log in
export const verifyMfa = async (req: Request, res: Response, next: NextFunction) => {
  let decoded: any;
  try {
    const { mfaToken, token } = req.body; // token is the 6-digit code
    if (!mfaToken || !token) return res.status(400).json({ status: 'Fail', message: 'Missing MFA token or code' });

    try {
      decoded = verifyMfaToken(mfaToken);
    } catch (err) {
      logger.warn({ err }, 'MFA token verification failed');
      return res.status(401).json({ status: 'Fail', message: 'Invalid or expired MFA token' });
    }

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ userId: decoded.id }, 'Database connection not established for MFA login verification');
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const dbConnection = dbSources[0];
    const userRepository = dbConnection.getRepository(VajraUser);
    const sessionRepository = dbConnection.getRepository(UserSession);
    const user = await userRepository.findOne({ where: { id: decoded.id } });

    if (!user || !user.mfa_secret) {
      logger.warn({ userId: decoded.id, userFound: !!user }, 'Login blocked: MFA not initialized for user');
      return res.status(400).json({ status: 'Fail', message: 'MFA not set up for this user' });
    }

    const verified = verifyTotpCode(user.mfa_secret, token);

    if (!verified) {
      logger.warn({ userId: user.id }, 'Login blocked: invalid MFA code');
      return res.status(401).json({ status: 'Fail', message: 'Invalid MFA code' });
    }

    // Checked before claimTotpCodeOnce (which burns the code as single-use)
    // so a suspended user's still-unused code isn't consumed by a login
    // attempt that was always going to be rejected — mirrors recoverMfa's
    // order (match/verify first, suspension check next, consume last).
    if (user.suspended) {
      logger.warn({ userId: user.id, email: user.email }, 'Login blocked: account suspended');
      return res.status(403).json({
        status: 'Fail',
        message: 'Your account has been suspended. Contact your administrator.',
      });
    }

    if (!(await claimTotpCodeOnce(user.id, token))) {
      logger.warn({ userId: user.id }, 'Login blocked: MFA code already used');
      return res.status(401).json({ status: 'Fail', message: 'Invalid MFA code' });
    }

    if (!user.mfa_enabled) {
      // mfaToken is only issued to users with mfa_enabled=true (see login.ts), so reaching
      // here means MFA was disabled after the token was issued but before verification
      // completed — a state change worth a trace since it silently re-enables MFA.
      logger.warn({ userId: user.id }, 'MFA re-enabled during verification: was disabled after MFA token was issued');
      user.mfa_enabled = true;
      await userRepository.save(user);
    }

    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.get('user-agent') || 'unknown';

    const normalizedRole = USER_ROLES.includes(user.role) ? user.role : DEFAULT_USER_ROLE;
    
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

    // MFA code is already verified valid at this point (and mfa_enabled may already have
    // been persisted above) — distinguish a token/cookie issuance failure here from an
    // actual MFA-check failure, since both would otherwise land in the generic catch
    // below with the same log line.
    try {
      const accessToken = createAccessToken(jwtPayload);
      const refreshToken = createRefreshToken(jwtPayload);
      const csrfToken = generateCsrfToken();

      setAccessTokenCookie(res, accessToken);
      setRefreshTokenCookie(res, refreshToken);
      setCsrfTokenCookie(res, csrfToken);
    } catch (err) {
      logger.error({ err, userId: user.id }, 'MFA verified but token/cookie issuance failed');
      throw err;
    }

    logger.info({ userId: user.id, sessionId: userSession.id }, 'MFA verification successful, user logged in');

    return res.status(200).json({
      status: 'Success',
      message: 'Login successful. All security tokens set in cookies.',
    });

  } catch (error) {
    logger.error({ err: error, userId: decoded?.id }, 'Failed to verify MFA');
    return next(new CustomError(500, 'Raw', 'Failed to verify MFA', null, error));
  }
};

// Recover account using a backup recovery code
export const recoverMfa = async (req: Request, res: Response, next: NextFunction) => {
  let decoded: any;
  try {
    const { mfaToken, recoveryCode } = req.body;
    if (!mfaToken || !recoveryCode) {
      return res.status(400).json({ status: 'Fail', message: 'Missing MFA token or recovery code' });
    }

    try {
      decoded = verifyMfaToken(mfaToken);
    } catch (err) {
      logger.warn({ err }, 'MFA token verification failed during recovery login');
      return res.status(401).json({ status: 'Fail', message: 'Invalid or expired MFA token' });
    }

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ userId: decoded.id }, 'Database connection not established for MFA recovery');
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const dbConnection = dbSources[0];
    const userRepository = dbConnection.getRepository(VajraUser);
    const sessionRepository = dbConnection.getRepository(UserSession);
    const user = await userRepository.findOne({ where: { id: decoded.id } });

    if (!user) {
      logger.warn({ userId: decoded.id }, 'MFA recovery rejected: user not found');
      return res.status(404).json({ status: 'Fail', message: 'User not found' });
    }

    if (!user.recovery_codes || user.recovery_codes.length === 0) {
      logger.warn({ userId: user.id }, 'MFA recovery rejected: no recovery codes available');
      return res.status(400).json({ status: 'Fail', message: 'No recovery codes available for this user' });
    }

    let matchedIndex = -1;
    for (let i = 0; i < user.recovery_codes.length; i++) {
      if (await bcrypt.compare(recoveryCode, user.recovery_codes[i])) {
        matchedIndex = i;
        break;
      }
    }

    if (matchedIndex === -1) {
      logger.warn({ userId: user.id }, 'Login blocked: invalid MFA recovery code');
      return res.status(401).json({ status: 'Fail', message: 'Invalid recovery code' });
    }

    if (user.suspended) {
      logger.warn({ userId: user.id, email: user.email }, 'Login blocked: account suspended');
      return res.status(403).json({
        status: 'Fail',
        message: 'Your account has been suspended. Contact your administrator.',
      });
    }

    // Remove the used recovery code at the DB layer rather than by a read-modify-write
    // in memory: two concurrent requests presenting the same still-valid code would both
    // read the pre-splice array and both proceed. array_remove plus the
    // `$2 = ANY(recovery_codes)` guard makes the update conditional, so a racing second
    // request sees 0 affected rows and is rejected below, same as a wrong code.
    // returningRows() is required, not tidiness: TypeORM's Postgres driver returns an
    // UPDATE ... RETURNING as the tuple [rows, rowCount], whose .length is always 2 —
    // including the zero-match case ([[], 0]). Read raw, the rejection below never
    // fires and the reuse guard fails open. See utils/returningRows.ts.
    const usedCodeHash = user.recovery_codes[matchedIndex];
    const updateResult = await dbConnection.query(
      `UPDATE vajra_users
          SET recovery_codes = array_remove(recovery_codes, $2)
        WHERE id = $1 AND $2 = ANY(recovery_codes)
        RETURNING recovery_codes`,
      [user.id, usedCodeHash],
    );
    const updatedRows = returningRows<{ recovery_codes: string[] }>(updateResult);
    if (updatedRows.length === 0) {
      logger.warn({ userId: user.id }, 'Login blocked: MFA recovery code was already consumed by a concurrent request');
      return res.status(401).json({ status: 'Fail', message: 'Invalid recovery code' });
    }
    user.recovery_codes = updatedRows[0].recovery_codes;

    // --- SUCCESSFUL LOGIN AFTER RECOVERY ---
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.get('user-agent') || 'unknown';

    const normalizedRole = USER_ROLES.includes(user.role) ? user.role : DEFAULT_USER_ROLE;
    
    const userSession = new UserSession();
    userSession.userId = user.id;
    userSession.ipAddress = clientIp;
    userSession.userAgent = userAgent;
    userSession.isActive = true;
    
    try {
      await sessionRepository.save(userSession);
    } catch (err) {
      logger.warn({ err, userId: user.id }, 'Failed to create user session on recovery login');
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

    // The recovery code is already consumed and persisted at this point — distinguish a
    // token/cookie issuance failure here from an actual recovery-code-check failure, since
    // both would otherwise land in the generic catch below with the same log line and hide
    // that the user's one-time recovery code was burned even though login did not complete.
    try {
      const accessToken = createAccessToken(jwtPayload);
      const refreshToken = createRefreshToken(jwtPayload);
      const csrfToken = generateCsrfToken();

      setAccessTokenCookie(res, accessToken);
      setRefreshTokenCookie(res, refreshToken);
      setCsrfTokenCookie(res, csrfToken);
    } catch (err) {
      logger.error({ err, userId: user.id }, 'Recovery code consumed but token/cookie issuance failed');
      throw err;
    }

    logger.info({ userId: user.id, sessionId: userSession.id }, 'Account recovered via recovery code, user logged in');

    return res.status(200).json({
      status: 'Success',
      message: 'Login successful via recovery code. All security tokens set in cookies.',
    });

  } catch (error) {
    logger.error({ err: error, userId: decoded?.id }, 'Failed to recover account via MFA');
    return next(new CustomError(500, 'Raw', 'Failed to recover account', null, error));
  }
};

// Disable MFA
export const disableMfa = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ status: 'Fail', message: 'Password is required to disable MFA' });

    const userId = (req as any).jwtPayload?.id;
    if (!userId) return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.error({ userId }, 'Database connection not established for MFA disable');
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const dbConnection = dbSources[0];
    const userRepository = dbConnection.getRepository(VajraUser);
    const user = await userRepository.findOne({ where: { id: userId } });

    if (!user) {
      logger.warn({ userId }, 'MFA disable rejected: user not found');
      return res.status(404).json({ status: 'Fail', message: 'User not found' });
    }

    const isValidPassword = await user.checkIfPasswordMatch(password);
    if (!isValidPassword) {
      logger.warn({ userId: user.id }, 'MFA disable rejected: incorrect password');
      return res.status(401).json({ status: 'Fail', message: 'Incorrect password' });
    }

    await userRepository.update(user.id, {
      mfa_enabled: false,
      mfa_secret: null,
      recovery_codes: [],
      security_question_1: null,
      security_answer_1_hash: null,
      security_question_2: null,
      security_answer_2_hash: null
    });

    logger.info({ userId: user.id }, 'MFA disabled');

    return res.status(200).json({
      status: 'Success',
      message: 'MFA has been successfully disabled.',
    });
  } catch (error) {
    logger.error({ err: error, userId: (req as any).jwtPayload?.id }, 'Failed to disable MFA');
    return next(new CustomError(500, 'Raw', 'Failed to disable MFA', null, error));
  }
};
