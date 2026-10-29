import { Request, Response, NextFunction } from 'express';
import validator from 'validator';

import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ErrorValidation } from '../../../utils/response/custom-error/types';
import { getLogger } from '../../../utils/logger';

const logger = getLogger('validation.auth.login');

export const validatorLogin = (req: Request, _res: Response, next: NextFunction) => {
  let { email, password } = req.body;
  const errorsValidation: ErrorValidation[] = [];

  email = !email ? '' : email;
  password = !password ? '' : password;

  if (validator.isEmpty(email)) {
    errorsValidation.push({ email: 'Email field is required' });
  }

  if (validator.isEmpty(password)) {
    errorsValidation.push({ password: 'Password field is required' });
  }

  if (errorsValidation.length !== 0) {
    logger.warn({ errorsValidation }, 'Login input validation failed');
    const customError = new CustomError(400, 'Validation', 'Login validation error', null, null, errorsValidation);
    return next(customError);
  }
  return next();
};
