import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../..';
import { USER_ROLES, VajraUser, SUPER_ADMIN_ROLE, DEFAULT_USER_ROLE } from '../../orm/entities/users/Users';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { normalizeEmail } from '../../utils/sanitization';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.register');

const MAX_USER_COUNT = Number(process.env.MAX_USER_COUNT);

export const user_register = async (req: Request, res: Response, next: NextFunction) => {
  const { name, email, password, mobile, role, forcePasswordChange } = req.body;
  
  // Normalize email to lowercase to prevent duplicates
  const normalizedEmail = normalizeEmail(email);

  const dbSources = dbSourceConnection();

  if (!dbSources || dbSources.length === 0) {
    logger.error({ email: normalizedEmail }, 'Database connection not established for user registration');
    const customError = new CustomError(500, 'Database', 'Database connection source is missing or not initialized.', []);
    return next(customError);
  }

  const queryRunner = dbSources[0].createQueryRunner();
  await queryRunner.connect();
  await queryRunner.startTransaction('SERIALIZABLE');
  
  try {
    const userRepository = queryRunner.manager.getRepository(VajraUser);
    const userCount = await userRepository.count();

    const existingUser = await userRepository.findOne({ where: { email: normalizedEmail } });
    const superAdminCount = await userRepository.count({
      where: { role: SUPER_ADMIN_ROLE },
    });

    if (existingUser) {
      const clientIp = req.ip || req.socket?.remoteAddress || null;
      logger.warn({ email: normalizedEmail }, 'Registration rejected: user already exists');
      await logAuditTrail({
        action: 'USER_REGISTER',
        status: 'failure',
        email: normalizedEmail,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { reason: 'user_already_exists' },
      });
      const customError = new CustomError(409, 'General', 'User already exists', [
        `email '${existingUser.email}' already exists`,
      ]);
      await queryRunner.rollbackTransaction();
      return next(customError);
    }

    if (userCount >= MAX_USER_COUNT) {
      logger.warn({ email: normalizedEmail, userCount, maxUserCount: MAX_USER_COUNT }, 'Registration rejected: max user count reached');
      await queryRunner.rollbackTransaction();
      return next(new CustomError(403, 'Database', 'A user already exists. Contact the admin team for assistance'));
    }

    try {
      const newUser = new VajraUser();
      newUser.name = name;
      newUser.email = normalizedEmail;
      newUser.password_hash = password;
      newUser.mobile = mobile;
      // Bootstrap access control safely:
      // if no super admin exists yet, promote the first created user to super admin.
      // Once one exists, block creation of additional super admins.
      const requestedRole = USER_ROLES.includes(role) ? role : DEFAULT_USER_ROLE;
      if (superAdminCount > 0 && requestedRole === SUPER_ADMIN_ROLE) {
        logger.warn({ email: normalizedEmail }, 'Registration rejected: attempted to create a second Super Administrator');
        await queryRunner.rollbackTransaction();
        return next(new CustomError(409, 'General', 'Only one Super Administrator is allowed.'));
      }
      if (superAdminCount === 0) {
        logger.info({ email: normalizedEmail }, 'Bootstrapping first registered user as Super Administrator');
      }
      newUser.role = superAdminCount === 0 ? SUPER_ADMIN_ROLE : requestedRole;
      newUser.forcePasswordChange = Boolean(forcePasswordChange);
      newUser.suspended = false;

      await newUser.hashPassword();
      const savedUser = await userRepository.save(newUser);
      await queryRunner.commitTransaction();

      const clientIp = req.ip || req.socket?.remoteAddress || null;
      try {
        await logAuditTrail({
          action: 'USER_REGISTER',
          status: 'success',
          userId: savedUser.id,
          email: savedUser.email,
          ipAddress: clientIp,
          userAgent: req.get('user-agent') || null,
        });
      } catch (auditErr) {
        // User row is already committed at this point — distinguish this from a
        // creation failure so a 400 here isn't mistaken for the registration itself failing.
        logger.error({ err: auditErr, userId: savedUser.id, email: savedUser.email }, 'User registered but audit trail logging failed');
        throw auditErr;
      }

      logger.info({ userId: savedUser.id, email: savedUser.email, role: savedUser.role }, 'User registered successfully');

      return res.status(200).json({
        status: 'Success',
        message: 'User successfully created.',
      });
    } catch (err) {
      await queryRunner.rollbackTransaction();
      logger.error({ err, email: normalizedEmail }, 'Failed to create user');
      const customError = new CustomError(400, 'Raw', `User '${normalizedEmail}' can't be created`, null, err);
      return next(customError);
    }
  } catch (err) {
    await queryRunner.rollbackTransaction();
    logger.error({ err, email: normalizedEmail }, 'User registration failed');
    const customError = new CustomError(400, 'Raw', 'Error', null, err);
    return next(customError);
  } finally {
    await queryRunner.release();
  }
};