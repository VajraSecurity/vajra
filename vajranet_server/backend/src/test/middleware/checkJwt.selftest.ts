/**
 * Self-contained test for isMfaChallengeToken. No test framework is
 * required — run it with ts-node:
 *
 *   node_modules/.bin/ts-node src/test/middleware/checkJwt.selftest.ts
 *
 * Regression coverage for the MFA-bypass gap found across babb957's
 * verifiers of ACCESS_JWT_SECRET-signed tokens: createMfaToken (the interim,
 * password-only-verified token) is signed with the SAME secret as a real
 * access token, distinguished only by a `mfaToken: true` payload field.
 * checkAccessJwt/checkAccessWithRefreshFallback reject it via
 * isMfaChallengeToken; index.ts's verifyWsJwt, utils/wsAuth.ts's
 * getWsJwtPayload, and controllers/auth/validateGrafana.ts must reject it
 * the same way — this only tests the shared predicate they all now share,
 * not each call site's full auth flow (those need a running DB/Redis).
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { isMfaChallengeToken } from '../../middleware/checkJwt';

function main() {
  // The actual shape createMfaToken produces.
  assert.strictEqual(
    isMfaChallengeToken({ mfaToken: true }),
    true,
    'a real MFA-challenge payload must be flagged',
  );

  // A normal, fully-authenticated access-token payload never carries this field.
  assert.strictEqual(
    isMfaChallengeToken({ id: 1, email: 'a@b.com' } as any),
    false,
    'a normal access-token payload (no mfaToken field) must NOT be flagged',
  );

  // Explicit false and falsy-but-present values must not be misread as truthy
  // via loose comparison — only a strict `=== true` counts.
  assert.strictEqual(isMfaChallengeToken({ mfaToken: false }), false, 'mfaToken: false must not be flagged');
  assert.strictEqual(isMfaChallengeToken({ mfaToken: 0 as any }), false, 'truthy-coercion of 0 must not be flagged');
  assert.strictEqual(isMfaChallengeToken({ mfaToken: 1 as any }), false, 'truthy-coercion of 1 must not be flagged (only boolean true)');
  assert.strictEqual(isMfaChallengeToken({ mfaToken: 'true' as any }), false, 'string "true" must not be flagged (only boolean true)');

  // Defensive: a null/undefined payload (shouldn't happen post jwt.verify,
  // but every call site is inside a try/catch around jwt.verify) must not throw.
  assert.strictEqual(isMfaChallengeToken(undefined as any), false, 'undefined payload must not throw and must not be flagged');
  assert.strictEqual(isMfaChallengeToken(null as any), false, 'null payload must not throw and must not be flagged');

  console.log('checkJwt.selftest: all checks passed');
}

main();
