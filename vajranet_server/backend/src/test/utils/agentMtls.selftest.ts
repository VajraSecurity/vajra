/**
 * Self-contained test for agent mTLS verification. No test framework is
 * required — run it with ts-node:
 *
 *   node_modules/.bin/ts-node src/test/utils/agentMtls.selftest.ts
 *
 * Covers extractCN's DN parsing, agentInfoHostId's header parsing, and
 * verifyAgentMtls's mode and CN-binding logic, including the type-confusion
 * case: a non-string `host_identifier` in the agent-info header makes
 * agentInfoHostId return '', which a `hostIdentifier && ...` guard would treat
 * as "no host to bind to" and skip the CN check for. Exits non-zero on the
 * first failure so it can gate CI.
 */

import assert from 'assert';
import { extractCN, agentInfoHostId, verifyAgentMtls } from '../../utils/agentMtls';

type Headers = Record<string, string | string[] | undefined>;

function req(headers: Headers, socket?: { authorized?: boolean; getPeerCertificate?: () => { subject?: { CN?: unknown } } }) {
  return { headers, socket };
}

/** A cert Node's TLS stack did (or didn't) verify against the configured CA. */
function mockSocket(authorized: boolean, cn?: unknown) {
  return {
    authorized,
    // Real getPeerCertificate() returns subject details even for an
    // unauthorized/wrong-CA cert -- mirrored here since verifyAgentMtls must
    // gate on `authorized` before ever reading this, not rely on it being empty.
    getPeerCertificate: () => ({ subject: { CN: cn } }),
  };
}

function withMode<T>(mode: 'off' | 'optional' | 'required', fn: () => T): T {
  const prev = process.env.AGENT_MTLS_MODE;
  process.env.AGENT_MTLS_MODE = mode;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.AGENT_MTLS_MODE;
    else process.env.AGENT_MTLS_MODE = prev;
  }
}

const TEST_SECRET = 'selftest-shared-secret';

function withInternalSecret<T>(secret: string | undefined, fn: () => T): T {
  const prev = process.env.AGENT_MTLS_INTERNAL_SECRET;
  if (secret === undefined) delete process.env.AGENT_MTLS_INTERNAL_SECRET;
  else process.env.AGENT_MTLS_INTERNAL_SECRET = secret;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.AGENT_MTLS_INTERNAL_SECRET;
    else process.env.AGENT_MTLS_INTERNAL_SECRET = prev;
  }
}

function main() {
  // ── extractCN ──────────────────────────────────────────────────────────
  assert.strictEqual(extractCN('CN=abc-123,O=Vajra'), 'abc-123', 'comma-separated DN');
  assert.strictEqual(extractCN('/O=Vajra/CN=abc-123'), 'abc-123', 'slash-separated DN');
  assert.strictEqual(extractCN('O=Vajra'), '', 'DN with no CN');
  assert.strictEqual(extractCN('cn=abc-123,O=Vajra'), 'abc-123', 'lowercase cn=');
  assert.strictEqual(extractCN('CN = abc-123 , O=Vajra'), 'abc-123', 'whitespace around =');
  assert.strictEqual(extractCN(''), '', 'empty DN');

  // ── agentInfoHostId ────────────────────────────────────────────────────
  assert.strictEqual(agentInfoHostId(req({})), '', 'missing agent-info header');
  assert.strictEqual(agentInfoHostId(req({ 'agent-info': 'not json' })), '', 'malformed JSON');
  assert.strictEqual(
    agentInfoHostId(req({ 'agent-info': JSON.stringify({ host_identifier: 'host-1' }) })),
    'host-1',
    'valid string host_identifier',
  );
  assert.strictEqual(
    agentInfoHostId(req({ 'agent-info': JSON.stringify({ host_identifier: 12345 }) })),
    '',
    'numeric host_identifier must not be accepted as a string identity',
  );
  assert.strictEqual(
    agentInfoHostId(req({ 'agent-info': JSON.stringify({ host_identifier: ['host-1'] }) })),
    '',
    'array-wrapped host_identifier must not be accepted (JS template-literal coercion trick)',
  );
  assert.strictEqual(
    agentInfoHostId(req({ 'agent-info': [JSON.stringify({ host_identifier: 'host-1' })] })),
    'host-1',
    'repeated header (array of strings) reads the first value',
  );

  // ── verifyAgentMtls: mode off is always a no-op ──────────────────────────
  withMode('off', () => {
    assert.strictEqual(
      verifyAgentMtls(req({ 'x-ssl-client-verify': 'FAILED:expired' }), 'host-1'),
      null,
      'off mode ignores everything',
    );
  });

  // ── verifyAgentMtls: no cert presented ───────────────────────────────────
  withMode('optional', () => {
    assert.strictEqual(verifyAgentMtls(req({}), 'host-1'), null, 'optional admits no-cert agents');
  });
  withMode('required', () => {
    assert.ok(
      verifyAgentMtls(req({}), 'host-1'),
      'required rejects no-cert agents',
    );
  });

  // ── verifyAgentMtls: cert presented but verify != SUCCESS ────────────────
  withMode('optional', () => {
    assert.strictEqual(
      verifyAgentMtls(req({ 'x-ssl-client-verify': 'FAILED:expired' }), 'host-1'),
      null,
      'optional admits a failed-verify handshake (treated as no cert)',
    );
  });
  withMode('required', () => {
    assert.ok(
      verifyAgentMtls(req({ 'x-ssl-client-verify': 'FAILED:expired' }), 'host-1'),
      'required rejects a failed-verify handshake',
    );
  });

  // ── verifyAgentMtls: verified cert, matching CN (request genuinely transited nginx) ──
  const goodHeaders = {
    'x-ssl-client-verify': 'SUCCESS',
    'x-ssl-client-dn': 'CN=host-1,O=Vajra',
    'x-vajra-internal-secret': TEST_SECRET,
  };
  withInternalSecret(TEST_SECRET, () => {
    withMode('optional', () => {
      assert.strictEqual(verifyAgentMtls(req(goodHeaders), 'host-1'), null, 'optional admits matching CN');
    });
    withMode('required', () => {
      assert.strictEqual(verifyAgentMtls(req(goodHeaders), 'host-1'), null, 'required admits matching CN');
    });
    withMode('required', () => {
      // Case-insensitive verify header value.
      assert.strictEqual(
        verifyAgentMtls(req({ ...goodHeaders, 'x-ssl-client-verify': 'success' }), 'host-1'),
        null,
        'verify header is case-insensitive',
      );
    });

    // ── verifyAgentMtls: verified cert, mismatched CN — rejected in BOTH modes ──
    withMode('optional', () => {
      assert.ok(
        verifyAgentMtls(req(goodHeaders), 'host-2'),
        'optional still rejects a valid cert replayed for a different identity',
      );
    });
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req(goodHeaders), 'host-2'),
        'required rejects a valid cert replayed for a different identity',
      );
    });

    // ── verifyAgentMtls: verified cert, no CN in DN ──────────────────────────
    const noCnHeaders = { ...goodHeaders, 'x-ssl-client-dn': 'O=Vajra' };
    withMode('optional', () => {
      assert.strictEqual(verifyAgentMtls(req(noCnHeaders), 'host-1'), null, 'optional admits a CN-less cert');
    });
    withMode('required', () => {
      assert.ok(verifyAgentMtls(req(noCnHeaders), 'host-1'), 'required rejects a CN-less cert');
    });

    // ── Regression: verified cert + unparseable claimed identity must NOT ────
    // ── bypass the CN check (this was the type-confusion bug) ────────────────
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req(goodHeaders), ''),
        'a verified cert with an empty/unparseable claimed host_identifier must be rejected, not silently allowed',
      );
    });
    withMode('optional', () => {
      assert.ok(
        verifyAgentMtls(req(goodHeaders), ''),
        'same regression, optional mode: a presented+verified cert always needs a matching identity claim',
      );
    });
    // End-to-end shape of the original exploit: agent-info carries an
    // array-wrapped host_identifier, which agentInfoHostId correctly refuses to
    // treat as a string identity (-> ''); verifyAgentMtls must then reject.
    withMode('required', () => {
      const evilReq = req({
        ...goodHeaders,
        'agent-info': JSON.stringify({ host_identifier: ['host-1'] }),
      });
      const claimed = agentInfoHostId(evilReq);
      assert.strictEqual(claimed, '', 'sanity: array-wrapped id is not treated as a string identity');
      assert.ok(
        verifyAgentMtls(evilReq, claimed),
        'end-to-end: array-wrapped host_identifier must not grant a connection under a real cert CN',
      );
    });
  });

  // Header spoofing straight at the backend port must not be trusted as a
  // verified cert: a request with no certificate at all can self-supply
  // X-SSL-Client-Verify: SUCCESS and a matching CN. Those headers are only
  // trusted on requests carrying the correct AGENT_MTLS_INTERNAL_SECRET, which
  // only nginx's /ws location sets.
  const spoofedHeaders = { 'x-ssl-client-verify': 'SUCCESS', 'x-ssl-client-dn': 'CN=host-1,O=Vajra' };
  withInternalSecret(undefined, () => {
    withMode('optional', () => {
      assert.strictEqual(
        verifyAgentMtls(req(spoofedHeaders), 'host-1'),
        null,
        'no AGENT_MTLS_INTERNAL_SECRET configured: optional still admits the connection...',
      );
    });
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req(spoofedHeaders), 'host-1'),
        '...but required rejects it — a claimed-SUCCESS header must never substitute for a real nginx-verified cert',
      );
    });
  });
  withInternalSecret(TEST_SECRET, () => {
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req(spoofedHeaders), 'host-1'),
        'secret configured but request carries none: still rejected under required mode',
      );
      assert.ok(
        verifyAgentMtls(req({ ...spoofedHeaders, 'x-vajra-internal-secret': 'wrong-value' }), 'host-1'),
        'secret configured but request carries the wrong value: still rejected under required mode',
      );
      assert.strictEqual(
        verifyAgentMtls(req({ ...spoofedHeaders, 'x-vajra-internal-secret': TEST_SECRET }), 'host-1'),
        null,
        'sanity: the exact same claim IS trusted once the correct secret is present (i.e. genuinely transited nginx)',
      );
    });
  });

  // ── verifyAgentMtls: socket-verified cert (the real, direct-PORT path) ────
  // No AGENT_MTLS_INTERNAL_SECRET and no nginx headers involved at all here —
  // this is what real agent traffic looks like (extension.conf's tls_hostname
  // dials PORT directly), and it must work on its own.
  withInternalSecret(undefined, () => {
    withMode('required', () => {
      assert.strictEqual(
        verifyAgentMtls(req({}, mockSocket(true, 'host-1')), 'host-1'),
        null,
        'required admits a cert Node\'s own TLS stack verified directly, matching CN, no nginx involved',
      );
    });
    withMode('optional', () => {
      assert.strictEqual(
        verifyAgentMtls(req({}, mockSocket(true, 'host-1')), 'host-1'),
        null,
        'optional: same, socket-verified path',
      );
    });
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req({}, mockSocket(true, 'host-2')), 'host-1'),
        'required rejects a socket-verified cert replayed for a different identity',
      );
    });
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req({}, mockSocket(false, 'host-1')), 'host-1'),
        'required rejects when socket.authorized is false, even though getPeerCertificate() still has a CN ' +
          '(an untrusted/wrong-CA cert) — authorized must gate before the CN is ever read',
      );
    });
    withMode('optional', () => {
      assert.strictEqual(
        verifyAgentMtls(req({}, mockSocket(false, 'host-1')), 'host-1'),
        null,
        'optional: same unauthorized-socket case is treated as no cert, not rejected',
      );
    });
    withMode('required', () => {
      assert.ok(
        verifyAgentMtls(req({}, undefined), 'host-1'),
        'required rejects when there is no socket at all (e.g. non-TLS request)',
      );
    });
  });

  // ── Precedence: a socket-verified cert wins over noisy/spoofed headers on ──
  // ── the same request, and does not need (or trigger the warning for) the ──
  // ── nginx-secret fallback path at all. ─────────────────────────────────────
  withInternalSecret(undefined, () => {
    withMode('required', () => {
      assert.strictEqual(
        verifyAgentMtls(
          req({ 'x-ssl-client-verify': 'SUCCESS', 'x-ssl-client-dn': 'CN=wrong-host,O=Vajra' }, mockSocket(true, 'host-1')),
          'host-1',
        ),
        null,
        'socket verification wins even when headers on the same request claim a different (spoofed) identity',
      );
    });
  });

  console.log('agentMtls.selftest: all checks passed');
}

main();
