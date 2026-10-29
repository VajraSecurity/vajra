// middleware/validation/validatorUpdateProfile.ts

import { Request, Response, NextFunction } from 'express';
import validator from 'validator';

import { CustomError } from '../../../utils/response/custom-error/CustomError';
import { ErrorValidation } from '../../../utils/response/custom-error/types';
import { sanitizeString } from '../../../utils/sanitization';
import { getLogger } from '../../../utils/logger';

const logger = getLogger('validation.auth.updateProfile');

export const validatorUpdateProfile = (req: Request, _res: Response, next: NextFunction) => {
  let { name, mobile, company, address } = req.body;
  const errorsValidation: ErrorValidation[] = [];
  let updateAttempted = false;

  name = !name ? '' : String(name).trim();
  mobile = !mobile ? '' : String(mobile).trim();
  company = !company ? '' : String(company).trim();
  address = !address ? '' : String(address).trim();

  if (name.length > 0) {
    updateAttempted = true;
    if (!validator.isLength(name, { min: 2, max: 128 })) {
      errorsValidation.push({ name: 'Name must be between 2 and 128 characters' });
    }
  }

  if (mobile.length > 0) {
    updateAttempted = true;
    if (!validator.isMobilePhone(mobile, 'en-IN')) {
      errorsValidation.push({ mobile: 'Mobile number is invalid for India format' });
    }
  }

  if (company.length > 0) {
    updateAttempted = true;
    if (!validator.isLength(company, { min: 1, max: 255 })) {
      errorsValidation.push({ company: 'Company must be 1-255 characters' });
    }
  }

  if (address.length > 0) {
    updateAttempted = true;
    if (!validator.isLength(address, { min: 3, max: 512 })) {
      errorsValidation.push({ address: 'Address must be 3-512 characters' });
    }
  }

  if (!updateAttempted) {
    logger.warn('Profile update rejected: no update fields provided');
    const customError = new CustomError(400, 'General', 'No update fields provided. You must provide at least one field to update.', []);
    return next(customError);
  }

  if (errorsValidation.length !== 0) {
    logger.warn({ errorsValidation }, 'Profile update input validation failed');
    const customError = new CustomError(400, 'Validation', 'Profile update validation error', null, null, errorsValidation);
    return next(customError);
  }

  req.body.name = name ? sanitizeString(name) : undefined;
  req.body.mobile = mobile ? sanitizeString(mobile) : undefined;
  req.body.company = company ? sanitizeString(company) : undefined;
  req.body.address = address ? sanitizeString(address) : undefined;

  return next();
};