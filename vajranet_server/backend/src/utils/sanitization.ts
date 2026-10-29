import validator from 'validator';
export const sanitizeString = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  // Escape HTML entities to prevent XSS
  return validator.escape(input.trim());
};
export const sanitizeObject = <T extends Record<string, any>>(obj: T): T => {
  const sanitized: any = { ...obj };
  
  for (const key in sanitized) {
    if (typeof sanitized[key] === 'string') {
      sanitized[key] = sanitizeString(sanitized[key]);
    }
  }
  
  return sanitized as T;
};

export const normalizeEmail = (email: string): string => {
  if (!email || typeof email !== 'string') {
    return '';
  }

  return validator.normalizeEmail(email.trim().toLowerCase()) || '';
};

/**
 * Escapes ILIKE's own wildcard characters (`%`, `_`) in a user-supplied search
 * term, so it can be safely interpolated into a `%<term>%` ILIKE pattern
 * without the caller's raw input being treated as SQL LIKE wildcards.
 */
export const escapeIlikeSearchTerm = (search: string): string =>
  search.replace(/%/g, '\\%').replace(/_/g, '\\_');
