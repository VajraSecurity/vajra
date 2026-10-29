import { Request, Response, NextFunction } from 'express';
import validator from 'validator';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { isDisposableEmail } from 'disposable-email-domains-js';

import { ConstsUser } from '../../../consts/ConstsUser';
import { USER_ROLES } from '../../../orm/entities/users/Users';
import {
  RATE_LIMIT_WINDOW_MS_15MIN,
  RATE_LIMIT_MAX_REGISTER_EMAIL,
  RATE_LIMIT_MAX_REGISTER_IP,
} from '../../../consts';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ErrorValidation } from '../../../utils/response/custom-error/types';
import { sanitizeString, normalizeEmail } from '../../../utils/sanitization';
import { getLogger } from '../../../utils/logger';

const logger = getLogger('validation.auth.register');

const emailOrIpKeyGenerator = (req: Request) => {
  const rawEmail = (req.body as any)?.email;
  const email = typeof rawEmail === 'string' ? normalizeEmail(rawEmail) : '';
  return email ? `email:${email}` : ipKeyGenerator(req.ip ?? '0.0.0.0');
};

/**
 * Logs every time a client actually gets rate-limited, then reproduces
 * express-rate-limit's own default `handler` behavior exactly (status +
 * message body) so the response sent to the client is unchanged. Without
 * this, a blocked registration attempt leaves zero trace in the logs.
 */
const rateLimitExceededHandler = (limiterName: string) =>
  async (req: Request, res: any, _next: any, options: any) => {
    let key: string | undefined;
    try {
      key = await options.keyGenerator(req, res);
    } catch (keyErr) {
      logger.warn({ err: keyErr, limiter: limiterName, path: req.originalUrl }, 'Rate limit key generation failed, logging exceeded event without key');
      key = undefined;
    }
    logger.warn({ limiter: limiterName, key, path: req.originalUrl }, 'Rate limit exceeded');
    res.status(options.statusCode);
    const message = typeof options.message === 'function' ? await options.message(req, res) : options.message;
    if (!res.writableEnded) res.send(message);
  };

export const registerIpLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_REGISTER_IP,
  keyGenerator: (req) => ipKeyGenerator(req.ip ?? '0.0.0.0'),
  handler: rateLimitExceededHandler('registerIp'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many accounts created from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const registerEmailLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS_15MIN,
  max: RATE_LIMIT_MAX_REGISTER_EMAIL,
  keyGenerator: emailOrIpKeyGenerator,
  handler: rateLimitExceededHandler('registerEmail'),
  message: {
    status: 'TooManyRequests',
    message: 'Too many account creations for this email, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const validatorRegister = (req: Request, _res: Response, next: NextFunction) => {
  let { email, password, passwordConfirm, name, mobile, role } = req.body;
  const errorsValidation: ErrorValidation[] = [];

  email = !email ? '' : email;
  password = !password ? '' : password;
  passwordConfirm = !passwordConfirm ? '' : passwordConfirm;
  name = !name ? '' : String(name).trim();
  mobile = !mobile ? '' : String(mobile).trim();
  role = !role ? '' : String(role).trim();

  if (validator.isEmpty(name)) {
    errorsValidation.push({ name: 'Name is required' });
  } else if (!validator.isLength(name, { min: 2, max: 128 })) {
    errorsValidation.push({ name: 'Name must be between 2 and 128 characters' });
  }

  if (validator.isEmpty(email)) {
    errorsValidation.push({ email: 'Email is required' });
  } else if (!validator.isEmail(email)) {
    errorsValidation.push({ email: 'Email is invalid' });
  } else if (isDisposableEmail(email)) {
    errorsValidation.push({ email: 'Disposable email addresses are not allowed' });
  }
  
  if (validator.isEmpty(password)) {
    errorsValidation.push({ password: 'Password is required' });
  } else if (!validator.isLength(password, { min: ConstsUser.PASSWORD_MIN_CHAR, max: ConstsUser.PASSWORD_MAX_CHAR })) {
    errorsValidation.push({ password: `Password must be between ${ConstsUser.PASSWORD_MIN_CHAR} and ${ConstsUser.PASSWORD_MAX_CHAR} characters.` });
  } else {

    const strongPasswordOptions = {
      minLength: ConstsUser.PASSWORD_MIN_CHAR,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    };

    if (!validator.isStrongPassword(password, strongPasswordOptions)) {
      errorsValidation.push({
        password:
          'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.',
      });
    }
  }

  if (validator.isEmpty(passwordConfirm)) {
    errorsValidation.push({ passwordConfirm: 'Confirm password is required' });
  } else if (!validator.equals(password, passwordConfirm)) {
    errorsValidation.push({ passwordConfirm: 'Passwords must match' });
  }

  if (validator.isEmpty(mobile)) {
    errorsValidation.push({ mobile: 'Mobile number is required' });
  } else {
    if (!validator.isMobilePhone(mobile, 'en-IN')) {
      errorsValidation.push({ mobile: 'Mobile number is invalid for India format' });
    }
  }

  if (validator.isEmpty(role)) {
    errorsValidation.push({ role: 'Role is required' });
  } else if (!USER_ROLES.includes(role as (typeof USER_ROLES)[number])) {
    errorsValidation.push({ role: `Role must be one of: ${USER_ROLES.join(', ')}` });
  }

  if (errorsValidation.length !== 0) {
    logger.warn({ errorsValidation }, 'Registration input validation failed');
    const customError = new CustomError(400, 'Validation', 'Register validation error', null, null, errorsValidation);
    return next(customError);
  }

  req.body.name = sanitizeString(name);
  req.body.email = email.toLowerCase().trim();
  req.body.mobile = sanitizeString(mobile);
  req.body.role = role;

  return next();
};
