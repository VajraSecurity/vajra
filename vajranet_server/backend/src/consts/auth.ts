/** Auth-related literal constants: CSRF defaults, token TTLs (no env). */

export const CSRF_HEADER_DEFAULT = 'X-XSRF-TOKEN';
export const CSRF_STRATEGY_RANDOM_BYTES = 'RANDOM_BYTES';
export const CSRF_STRATEGY_UUID = 'UUID';

/** jsonwebtoken signing/verification algorithm used for every access/refresh JWT. */
export const JWT_ALGORITHM = 'HS256';

/** bcrypt cost factor used for every user-chosen secret: password, security-answer hash. */
export const BCRYPT_SALT_ROUNDS = 12;

/**
 * bcrypt cost factor for MFA recovery codes specifically -- these are
 * `crypto.randomBytes(6)`-generated (48 bits of entropy), single-use, and
 * revocable by re-running MFA setup, unlike a password or security answer a
 * person chose themselves. Bcrypt's expensive KDF exists to slow down
 * brute-forcing a LOW-entropy human-chosen secret; it buys nothing extra
 * against a 48-bit random one, which is already infeasible to brute-force
 * regardless of hash cost. setupMfa hashes 10 of these sequentially in one
 * request (see its own comment) -- at BCRYPT_SALT_ROUNDS=12 that measured
 * 3-6.5s end-to-end (10 x ~300-650ms per hash), timing out its own unit test
 * and making every real MFA setup call take several seconds. A lower cost
 * factor here cuts that to well under a second while remaining more than
 * adequate for a secret this random.
 */
export const RECOVERY_CODE_BCRYPT_SALT_ROUNDS = 8;

/** TOTP verification window: number of 30s steps of drift allowed before/after. */
export const MFA_TOTP_VERIFICATION_WINDOW = 1;

/**
 * How long a successfully-verified TOTP code is remembered as "already used"
 * (see claimTotpCodeOnce in utils/redisClient.ts). With
 * MFA_TOTP_VERIFICATION_WINDOW=1, a single code is accepted for its own 30s
 * step plus one step before/after — up to 90s of real acceptance window — so
 * this must cover that full span for the single-use guarantee to hold.
 */
export const TOTP_CODE_CLAIM_TTL_SECONDS = 90;

/** Chars of a secret/API key kept visible (as a suffix) when displaying a masked key. */
export const API_KEY_MASK_SUFFIX_LENGTH = 4;

/** Access token renewal: renew when fewer than this many seconds remain (5 min) */
export const TOKEN_RENEWAL_THRESHOLD_SECONDS = 5 * 60;

/** Token blacklist expiry for access tokens (15 minutes) */
export const BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS = 900;
export const BLACKLIST_ACCESS_TOKEN_EXPIRY_MS = BLACKLIST_ACCESS_TOKEN_EXPIRY_SECONDS * 1000;

/** Token blacklist expiry for refresh tokens (7 days) */
export const BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS = 604800;
export const BLACKLIST_REFRESH_TOKEN_EXPIRY_MS = BLACKLIST_REFRESH_TOKEN_EXPIRY_SECONDS * 1000;
