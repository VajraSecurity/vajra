declare namespace NodeJS {
  export interface ProcessEnv {
    // Server Configuration
    PORT: string;
    NODE_ENV: 'development' | 'production' | 'test';
    
    // Database Configuration (Primary DB)
    PG_HOST: string;
    PG_PORT: string;
    POSTGRES_USER: string;
    POSTGRES_PASSWORD: string;
    POSTGRES_DB: string;
    
    // Database Configuration (Secondary DB)
    PG_HOST1: string;
    PG_PORT1: string;
    POSTGRES_USER1: string;
    POSTGRES_PASSWORD1: string;
    POSTGRES_DB1: string;
    
    // JWT Configuration
    ACCESS_JWT_SECRET: string;
    REFRESH_JWT_SECRET: string;
    ACCESS_JWT_EXPIRATION: string;
    REFRESH_JWT_EXPIRATION: string;
    ACCESS_TOKEN_MAX_AGE_MS: string;
    REFRESH_TOKEN_MAX_AGE_MS: string;
    
    // CSRF Configuration
    CSRF_TOKEN_STRATEGY: string;
    CSRF_COOKIE_NAME: string;
    CSRF_HEADER_NAME: string;
    
    // URLs
    FRONTEND_URL: string;
    BACKEND_URL: string;
    
    // Security Limits
    LOGIN_MAX_FAILED_ATTEMPTS: string;
    LOGIN_CAPTCHA_EXPIRY_MS: string;
    MAX_USER_COUNT: string;
  }
}
