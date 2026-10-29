// Dummy, non-production env values so auth modules never touch real secrets/services.
process.env.NODE_ENV = 'test';
process.env.PORT = '4000';

process.env.PG_HOST = 'localhost';
process.env.PG_PORT = '5432';
process.env.POSTGRES_USER = 'test';
process.env.POSTGRES_PASSWORD = 'test';
process.env.POSTGRES_DB = 'vajra_db_test';

process.env.PG_HOST1 = 'localhost';
process.env.PG_PORT1 = '5432';
process.env.POSTGRES_USER1 = 'test';
process.env.POSTGRES_PASSWORD1 = 'test';
process.env.POSTGRES_DB1 = 'fleet_test';

process.env.ACCESS_JWT_SECRET = 'test_access_jwt_secret_at_least_32_chars_long';
process.env.REFRESH_JWT_SECRET = 'test_refresh_jwt_secret_at_least_32_chars_long';
process.env.ACCESS_JWT_EXPIRATION = '15m';
process.env.REFRESH_JWT_EXPIRATION = '7d';
process.env.ACCESS_TOKEN_MAX_AGE_MS = '900000';
process.env.REFRESH_TOKEN_MAX_AGE_MS = '604800000';

process.env.CSRF_TOKEN_STRATEGY = 'UUID';
process.env.CSRF_COOKIE_NAME = 'XSRF-TOKEN';
process.env.CSRF_HEADER_NAME = 'X-XSRF-TOKEN';

process.env.FRONTEND_URL = 'http://localhost:5173';
process.env.BACKEND_URL = 'http://localhost:4000';

process.env.LOGIN_MAX_FAILED_ATTEMPTS = '5';
process.env.LOGIN_CAPTCHA_EXPIRY_MS = '300000';
process.env.MAX_USER_COUNT = '100';

// 32-byte hex key, used by utils/encryption.ts
process.env.NESSUS_ENCRYPTION_KEY = 'a'.repeat(64);
