import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { validateEnvironmentVariables } from '../../../utils/validateEnv';

describe('validateEnvironmentVariables', () => {
  let envSnapshot: NodeJS.ProcessEnv;

  beforeEach(() => {
    envSnapshot = { ...process.env };
  });

  afterEach(() => {
    process.env = { ...envSnapshot };
  });

  it('does not throw when all required vars are set and NODE_ENV is not production', () => {
    expect(process.env.NODE_ENV).not.toBe('production');

    expect(() => validateEnvironmentVariables()).not.toThrow();
  });

  it('throws naming the missing variable when a required var is absent', () => {
    delete (process.env as Record<string, string | undefined>).PG_HOST;

    expect(() => validateEnvironmentVariables()).toThrow(/PG_HOST/);
  });

  it('throws naming the missing variable when CSRF_TOKEN_STRATEGY is absent', () => {
    delete (process.env as Record<string, string | undefined>).CSRF_TOKEN_STRATEGY;

    expect(() => validateEnvironmentVariables()).toThrow(/CSRF_TOKEN_STRATEGY/);
  });

  it('throws when NODE_ENV is production and ACCESS_JWT_SECRET is the default placeholder', () => {
    process.env.NODE_ENV = 'production';
    process.env.ACCESS_JWT_SECRET = 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_ACCESS_TOKEN';

    expect(() => validateEnvironmentVariables()).toThrow(/default JWT_SECRET/);
  });

  it('throws when NODE_ENV is production and REFRESH_JWT_SECRET is the default placeholder', () => {
    process.env.NODE_ENV = 'production';
    process.env.REFRESH_JWT_SECRET = 'CHANGE_ME_TO_A_SECURE_RANDOM_STRING_FOR_REFRESH_TOKEN';

    expect(() => validateEnvironmentVariables()).toThrow(/default JWT_SECRET/);
  });

  it('does not throw in production when secrets are not the default placeholders', () => {
    process.env.NODE_ENV = 'production';
    process.env.FRONTEND_URL = 'https://example.com';
    process.env.BACKEND_URL = 'https://api.example.com';

    expect(() => validateEnvironmentVariables()).not.toThrow();
  });
});
