import { getLogger } from './logger';

const logger = getLogger('utils.validateEnv');

/**
 * Validates that all required environment variables are set.
 * Throws an error if any required variable is missing.
 */
export function validateEnvironmentVariables(): void {
  const requiredEnvVars = [
    'PORT',
    'NODE_ENV',
    // Primary database
    'PG_HOST',
    'PG_PORT',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD',
    'POSTGRES_DB',
    // Secondary (fleet) database — nodes, alerts, osquery data
    'PG_HOST1',
    'PG_PORT1',
    'POSTGRES_USER1',
    'POSTGRES_PASSWORD1',
    'POSTGRES_DB1',
    'ACCESS_JWT_SECRET',
    'REFRESH_JWT_SECRET',
    'ACCESS_JWT_EXPIRATION',
    'REFRESH_JWT_EXPIRATION',
    'ACCESS_TOKEN_MAX_AGE_MS',
    'REFRESH_TOKEN_MAX_AGE_MS',
    'CSRF_TOKEN_STRATEGY',
    'CSRF_COOKIE_NAME',
    'CSRF_HEADER_NAME',
    'FRONTEND_URL',
    'BACKEND_URL',
    'LOGIN_MAX_FAILED_ATTEMPTS',
    'LOGIN_CAPTCHA_EXPIRY_MS',
    'MAX_USER_COUNT',
  ];

  const missingVars: string[] = [];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      missingVars.push(envVar);
    }
  }

  if (missingVars.length > 0) {
    // This runs synchronously at module load, before index.ts registers its
    // uncaughtException/unhandledRejection handlers — a bare throw here
    // would only ever surface as Node's raw stderr stack trace, never through
    // the structured pino pipeline everything else in this file (and the
    // rest of the codebase) relies on. Log the missing var names here first
    // so a failed startup is still greppable/structured in aggregated logs.
    logger.error({ missingVars }, 'Startup aborted: missing required environment variables');
    throw new Error(
      `Missing required environment variables:\n${missingVars.map(v => `  - ${v}`).join('\n')}\n\n` +
      `Please check your .env file and ensure all required variables are set.\n` +
      `See .env.example for reference.`
    );
  }

  // Presence alone isn't enough for these — a typo'd non-numeric value (e.g.
  // "3600000ms") passes the missingVars check above but silently becomes NaN
  // at the call sites. For LOGIN_MAX_FAILED_ATTEMPTS in particular this is
  // security-relevant: `NaN >= count` is always false, which silently
  // disables the brute-force account-lockout feature entirely. Fail fast
  // here instead of letting it surface as a confusing runtime issue later.
  const requiredNumericEnvVars = [
    'LOGIN_MAX_FAILED_ATTEMPTS',
    'LOGIN_CAPTCHA_EXPIRY_MS',
    'ACCESS_TOKEN_MAX_AGE_MS',
    'REFRESH_TOKEN_MAX_AGE_MS',
    'MAX_USER_COUNT',
  ];

  const invalidNumericVars: string[] = [];

  for (const envVar of requiredNumericEnvVars) {
    if (!Number.isFinite(Number(process.env[envVar]))) {
      invalidNumericVars.push(envVar);
    }
  }

  if (invalidNumericVars.length > 0) {
    logger.error({ invalidNumericVars }, 'Startup aborted: non-numeric value for required numeric environment variables');
    throw new Error(
      `The following environment variables must be set to valid numbers:\n${invalidNumericVars.map(v => `  - ${v}`).join('\n')}\n\n` +
      `Please check your .env file and ensure all required variables are set.\n` +
      `See .env.example for reference.`
    );
  }

  // Additional validation for specific variables
  if (process.env.ACCESS_JWT_SECRET && process.env.ACCESS_JWT_SECRET.length < 32) {
    logger.warn('ACCESS_JWT_SECRET is too short, use at least 32 characters for production');
  }

  if (process.env.REFRESH_JWT_SECRET && process.env.REFRESH_JWT_SECRET.length < 32) {
    logger.warn('REFRESH_JWT_SECRET is too short, use at least 32 characters for production');
  }

  if (process.env.NODE_ENV === 'production') {
    // Production-specific warnings
    if (process.env.ACCESS_JWT_SECRET === 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_ACCESS_TOKEN' ||
        process.env.REFRESH_JWT_SECRET === 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_REFRESH_TOKEN') {
      // Same rationale as the missing-vars throw above: log via the
      // structured pipeline before this synchronous throw crashes the
      // process pre-uncaughtException-handler-registration. Booleans only —
      // never the secret values themselves, even though these two are known
      // placeholder constants rather than real secrets.
      logger.error(
        {
          accessSecretIsDefault: process.env.ACCESS_JWT_SECRET === 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_ACCESS_TOKEN',
          refreshSecretIsDefault: process.env.REFRESH_JWT_SECRET === 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_REFRESH_TOKEN',
        },
        'Startup aborted: default placeholder JWT secret value(s) in production',
      );
      throw new Error('Cannot use default JWT_SECRET values in production.');
    }

    if (!process.env.FRONTEND_URL?.startsWith('https://') || !process.env.BACKEND_URL?.startsWith('https://')) {
      logger.warn('Using HTTP URLs in production, HTTPS is strongly recommended');
    }

    const maxAttempts = Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS);
    if (maxAttempts > 10) {
      logger.warn({ maxAttempts }, 'LOGIN_MAX_FAILED_ATTEMPTS is higher than recommended, consider using 5-10 for production');
    }
  }

  logger.info('Environment variables validated successfully');
}
