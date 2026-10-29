/**
 * The single TOTP implementation for the codebase. Every MFA gate (login, cert
 * provisioning, patch apply, agent releases, uninstall tokens) verifies through
 * verifyTotpCode, so digits, period and window are defined in one place.
 *
 * Stored mfa_secret values are unpadded base32 and must keep validating as-is;
 * nothing here may require re-enrolment.
 *
 * MFA_TOTP_VERIFICATION_WINDOW is counted in 30s steps allowed in each
 * direction. otplib instead takes an epochTolerance in seconds, symmetric as a
 * scalar and [past, future] as a tuple, so the window is multiplied by the
 * period to keep the accepted range at +/- N steps.
 *
 * The window and claimTotpCodeOnce (utils/redisClient.ts) are load-bearing: the
 * window bounds accepted clock drift, and the claim makes an accepted code
 * single-use for a TTL that must cover the whole window. Neither may be
 * widened or dropped.
 */

import { createGuardrails, generateSecret, verifySync } from 'otplib';
import { MFA_TOTP_VERIFICATION_WINDOW } from '../consts/auth';

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_SECRET_BYTES = 20;

/**
 * Verification accepts any secret length. Enrolment always mints
 * TOTP_SECRET_BYTES, and a bound applied only at verification time would lock
 * out an already-enrolled secret rather than strengthen it.
 */
const GUARDRAILS = createGuardrails({ MIN_SECRET_BYTES: 1, MAX_SECRET_BYTES: 1024 });

const EPOCH_TOLERANCE_SECONDS = MFA_TOTP_VERIFICATION_WINDOW * TOTP_PERIOD_SECONDS;

/**
 * Verifies a submitted code against a stored base32 secret. epochSeconds
 * overrides the clock and exists for the selftest.
 *
 * Returns false rather than throwing on a malformed secret or code: both come
 * from request bodies and stored rows, and call sites treat false as "invalid
 * code" (401), not as a server error.
 */
export const verifyTotpCode = (secret: string, token: unknown, epochSeconds?: number): boolean => {
  try {
    return verifySync({
      secret,
      token: String(token),
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD_SECONDS,
      // Pinned, not inherited. Every enrolled authenticator app was provisioned
      // against SHA-1 (speakeasy's default, and the otpauth:// default that
      // buildTotpAuthUrl relies on). If a future otplib major changed its
      // default, every existing secret would silently stop validating and every
      // user would be locked out, so the value is stated here rather than
      // assumed.
      algorithm: 'sha1',
      epochTolerance: EPOCH_TOLERANCE_SECONDS,
      guardrails: GUARDRAILS,
      ...(epochSeconds !== undefined ? { epoch: epochSeconds } : {}),
    }).valid;
  } catch {
    return false;
  }
};

/** Unpadded base32 secret for storage in mfa_secret. */
export const generateTotpSecret = (): string => generateSecret({ length: TOTP_SECRET_BYTES });

/** Key URI format otpauth:// URL for the enrolment QR code. */
export const buildTotpAuthUrl = (label: string, secret: string): string =>
  `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}`;
