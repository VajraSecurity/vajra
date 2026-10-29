/**
 * Central structured logger (pino). Use getLogger('moduleName') to get a
 * child logger tagged with its origin instead of importing the root logger
 * directly — the module tag is what makes multi-service log output greppable.
 *
 * Level: LOG_LEVEL env var, else 'debug' outside production and 'info' in
 * production. Output: pretty/colorized to stdout outside production, plain
 * JSON to stdout in production (the process manager — systemd/docker/pm2 —
 * owns capture/rotation from there; this app does not write log files).
 */

import pino from 'pino';
import { AsyncLocalStorage } from 'node:async_hooks';
import { CSRF_HEADER_DEFAULT } from '../consts/auth';

const isProduction = process.env.NODE_ENV === 'production';
const level = process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug');

// fast-redact paths: bare keys match that key at any depth one level under a
// wildcard, so both `foo` (top-level) and `*.foo` (nested one level) are
// listed for every sensitive field name actually used across the codebase
// (see utils/encryption.ts, orm/entities/users/*, controllers/users/*).
const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  `req.headers["${CSRF_HEADER_DEFAULT.toLowerCase()}"]`,
  'res.headers["set-cookie"]',
  ...[
    'password', 'newPassword', 'oldPassword', 'currentPassword', 'confirmPassword',
    'password_hash', 'passwordHash',
    'token', 'accessToken', 'access_token', 'refreshToken', 'refresh_token',
    'secret', 'apiKey', 'api_key', 'jwt',
    'mfaSecret', 'mfa_secret', 'recoveryCodes', 'recovery_codes',
    'securityAnswer', 'security_answer_hash',
    'privateKey', 'private_key', 'encryptionKey', 'encryption_key', 'nessusEncryptionKey',
    'authorization', 'cookie',
  ].flatMap((key) => [key, `*.${key}`]),
];

// Carries the current HTTP request's ID across every async hop of that
// request (controller -> service -> DB call, etc.) without threading it
// through every function signature. index.ts's request-scoped middleware
// populates this once per request (via runWithRequestId); pino's mixin then
// merges it into every log line emitted anywhere during that request, on
// every module-scoped logger (getLogger('x')), not just the top-level one —
// that's what lets a business log ("Alerts list retrieved") and its request's
// HTTP access log line be correlated by reqId under concurrent traffic.
interface RequestStore {
  reqId: string;
}
const requestContext = new AsyncLocalStorage<RequestStore>();

/** Run fn with reqId attached to every log line emitted during its execution (including async continuations). */
export function runWithRequestId<T>(reqId: string, fn: () => T): T {
  return requestContext.run({ reqId }, fn);
}

// pino-pretty is a devDependency: production-style images prune it, so only use it when installed.
const hasPrettyTransport = (() => {
  try {
    require.resolve('pino-pretty');
    return true;
  } catch {
    return false;
  }
})();

export const logger = pino({
  level,
  redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  timestamp: pino.stdTimeFunctions.isoTime,
  mixin() {
    const store = requestContext.getStore();
    return store ? { reqId: store.reqId } : {};
  },
  ...(isProduction || !hasPrettyTransport
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' },
        },
      }),
});

/** Child logger tagged with its origin module, e.g. getLogger('websocket'). */
export function getLogger(moduleName: string) {
  return logger.child({ module: moduleName });
}

export default logger;
