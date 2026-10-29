/**
 * Self-contained test for the TOTP layer. No test framework is required — run
 * it with ts-node:
 *
 *   node_modules/.bin/ts-node src/test/utils/totp.selftest.ts
 *
 * Guards the property that stored base32 secrets keep validating unchanged, so
 * a future library swap or upgrade cannot silently invalidate every enrolled
 * authenticator without failing CI. The fixed vectors are RFC 6238 SHA-1 rows
 * truncated to 6 digits plus codes for a secret of the shape already stored in
 * mfa_secret; they are literals so nothing recomputes them from the library
 * under test. Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { generateSync } from 'otplib';
import { MFA_TOTP_VERIFICATION_WINDOW } from '../../consts/auth';
import {
  TOTP_DIGITS,
  TOTP_PERIOD_SECONDS,
  TOTP_SECRET_BYTES,
  buildTotpAuthUrl,
  generateTotpSecret,
  verifyTotpCode,
} from '../../utils/totp';

/**
 * base32 of the RFC 6238 SHA-1 test key, ASCII "12345678901234567890" — the
 * published test vector the KNOWN_ANSWERS below are taken from, not a real
 * secret. gitleaks' generic-api-key rule matches it on entropy alone, hence
 * the allow directive.
 */
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // gitleaks:allow

/** 20 bytes / 32 unpadded base32 chars, the shape enrolment produces. */
const ENROLLED_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

const KNOWN_ANSWERS: Array<[string, number, string]> = [
  [RFC_SECRET, 59, '287082'],
  [RFC_SECRET, 1111111109, '081804'],
  [RFC_SECRET, 1111111111, '050471'],
  [RFC_SECRET, 1234567890, '005924'],
  [RFC_SECRET, 2000000000, '279037'],
  [RFC_SECRET, 20000000000, '353130'],
  [ENROLLED_SECRET, 0, '702218'],
  [ENROLLED_SECRET, 59, '503347'],
  [ENROLLED_SECRET, 1111111109, '088309'],
  [ENROLLED_SECRET, 1234567890, '401544'],
  [ENROLLED_SECRET, 1700000000, '406058'],
  [ENROLLED_SECRET, 1893456000, '233128'],
  [ENROLLED_SECRET, 2000000000, '978524'],
];

/** The code an authenticator app shows for one specific 30s step. */
function codeAt(secret: string, epoch: number): string {
  return generateSync({ secret, epoch, digits: TOTP_DIGITS, period: TOTP_PERIOD_SECONDS });
}

function main() {
  // Policy constants. Changing any of these changes what enrolled apps can log
  // in with, so they are asserted rather than assumed.
  assert.strictEqual(TOTP_DIGITS, 6, 'digits must stay 6');
  assert.strictEqual(TOTP_PERIOD_SECONDS, 30, 'period must stay 30s');
  assert.strictEqual(TOTP_SECRET_BYTES, 20, 'enrolment entropy must stay at 20 bytes');
  assert.strictEqual(MFA_TOTP_VERIFICATION_WINDOW, 1, 'accepted drift must stay +/- 1 step');

  // ── Known answers: an already-enrolled secret must accept exactly the codes ──
  // ── its authenticator app produces. ──────────────────────────────────────────
  for (const [secret, epoch, code] of KNOWN_ANSWERS) {
    assert.strictEqual(codeAt(secret, epoch), code, `code for ${secret} at epoch ${epoch}`);
    assert.ok(verifyTotpCode(secret, code, epoch), `${code} must verify at epoch ${epoch}`);
  }

  // ── Window: accepted range is exactly +/- MFA_TOTP_VERIFICATION_WINDOW steps, ──
  // ── from any position inside the current step. ────────────────────────────────
  for (const offsetInStep of [0, 1, 15, 29]) {
    const now = 1700000010 + offsetInStep;
    for (let delta = -3; delta <= 3; delta++) {
      const code = codeAt(ENROLLED_SECRET, now + delta * TOTP_PERIOD_SECONDS);
      assert.strictEqual(
        verifyTotpCode(ENROLLED_SECRET, code, now),
        Math.abs(delta) <= MFA_TOTP_VERIFICATION_WINDOW,
        `code from ${delta} step(s) away, ${offsetInStep}s into the step`,
      );
    }
  }

  // ── Malformed input arrives straight from request bodies and stored rows: it ──
  // ── must be rejected, never thrown. ───────────────────────────────────────────
  const codes: unknown[] = ['', '12345', '1234567', 'abcdef', '  5924', '5924  ', '05924x',
    '+05924', null, undefined, {}, []];
  for (const token of codes) {
    assert.strictEqual(verifyTotpCode(ENROLLED_SECRET, token, 1234567890), false,
      `malformed token ${JSON.stringify(token)} must be rejected`);
  }
  for (const secret of ['', 'not base32!!', 'ABC1890']) {
    assert.strictEqual(verifyTotpCode(secret, '000000', 0), false, `bad secret ${secret} must be rejected`);
  }
  assert.strictEqual(verifyTotpCode(ENROLLED_SECRET, 978524, 2000000000), true,
    'a numeric body value is coerced, not rejected');

  // ── Enrolment ─────────────────────────────────────────────────────────────────
  const fresh = generateTotpSecret();
  assert.match(fresh, /^[A-Z2-7]{32}$/, 'enrolment secret must be 32 unpadded base32 chars');
  assert.notStrictEqual(fresh, generateTotpSecret(), 'enrolment secrets must not repeat');
  assert.ok(verifyTotpCode(fresh, codeAt(fresh, 1700000000), 1700000000),
    'a freshly minted secret must verify');
  // Production passes no epoch, so cover the wall-clock path the controllers use.
  assert.ok(verifyTotpCode(fresh, codeAt(fresh, Math.floor(Date.now() / 1000))),
    'the current code must verify against the live clock');
  assert.strictEqual(
    buildTotpAuthUrl('VajraNet (alice@example.com)', ENROLLED_SECRET),
    'otpauth://totp/VajraNet%20(alice%40example.com)?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
    'otpauth URL must stay byte-identical to the one enrolled apps were given',
  );

  console.log('totp.selftest: all checks passed');
}

main();
