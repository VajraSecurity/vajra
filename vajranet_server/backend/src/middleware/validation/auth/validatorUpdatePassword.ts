// middleware/validation/validatorUpdatePassword.ts

import { Request, Response, NextFunction } from 'express';
import validator from 'validator';

import { ConstsUser } from '../../../consts/ConstsUser';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ErrorValidation } from '../../../utils/response/custom-error/types';
import { getLogger } from '../../../utils/logger';

const logger = getLogger('validation.auth.updatePassword');

export const validatorUpdatePassword = (req: Request, _res: Response, next: NextFunction) => {
  let { currentPassword, newPassword, newPasswordConfirm } = req.body;
  const errorsValidation: ErrorValidation[] = [];

  currentPassword = !currentPassword ? '' : currentPassword;
  newPassword = !newPassword ? '' : newPassword;
  newPasswordConfirm = !newPasswordConfirm ? '' : newPasswordConfirm;

  if (validator.isEmpty(currentPassword)) {
    errorsValidation.push({ currentPassword: 'Current password is required.' });
  }

  if (validator.isEmpty(newPassword)) {
    errorsValidation.push({ newPassword: 'New password is required.' });
  } else if (!validator.isLength(newPassword, { min: ConstsUser.PASSWORD_MIN_CHAR, max: ConstsUser.PASSWORD_MAX_CHAR })) {
    errorsValidation.push({ newPassword: `New password must be between ${ConstsUser.PASSWORD_MIN_CHAR} and ${ConstsUser.PASSWORD_MAX_CHAR} characters.` });
  } else {
    const strongPasswordOptions = {
      minLength: ConstsUser.PASSWORD_MIN_CHAR,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    };

    if (!validator.isStrongPassword(newPassword, strongPasswordOptions)) {
      errorsValidation.push({
        newPassword:
          'New password must include at least one uppercase letter, one lowercase letter, one number, and one special character.',
      });
    }
  }

  if (validator.isEmpty(newPasswordConfirm)) {
    errorsValidation.push({ newPasswordConfirm: 'Confirm new password is required.' });
  } else if (!validator.equals(newPassword, newPasswordConfirm)) {
    errorsValidation.push({ newPasswordConfirm: 'New passwords must match.' });
  }
  
  if (currentPassword === newPassword && !validator.isEmpty(currentPassword)) {
       errorsValidation.push({ newPassword: 'The new password cannot be the same as the current password.' });
  }

  if (errorsValidation.length !== 0) {
    logger.warn({ errorsValidation }, 'Password update input validation failed');
    const customError = new CustomError(400, 'Validation', 'Password update validation error', null, null, errorsValidation);
    return next(customError);
  }

  return next();
};