/**
 * Agent mTLS verification (phased rollout).
 *
 * Agents authenticate to the server with a client certificate issued at
 * enrollment (CN = host_identifier), signed by the deployment's Agent CA.
 * There are two independent sources of a verified identity, checked in
 * priority order:
 *
 *   1. socketVerifiedCn() — Node's own TLS stack, verifying a cert presented
 *      directly on THIS connection against the Agent CA (index.ts configures
 *      requestCert/ca on the HTTPS listener). This is the real, authoritative
 *      path: PORT is deliberately reachable on all interfaces, not just
 *      loopback, because Go agent extensions dial it directly over the
 *      public internet (see the NOTE at index.ts's PORT definition) —
 *      bypassing nginx entirely, so nginx never terminates their TLS.
 *   2. requestTransitedNginx() — a fallback for any deployment that DOES
 *      proxy agent traffic through nginx: nginx terminates TLS, passes the
 *      verification result and subject as request headers
 *      (X-SSL-Client-Verify / X-SSL-Client-DN), and those headers are
 *      trusted only when the request also carries the shared secret proving
 *      it actually transited nginx (see requestTransitedNginx doc below) —
 *      without that secret they're just self-supplied claims from whoever
 *      is talking to PORT directly, and are ignored entirely.
 *
 * Enabling mTLS must never lock out a fleet that has not finished enrolling, so
 * enforcement is staged via the AGENT_MTLS_MODE environment variable:
 *
 *   off       (default) — no check; behaviour is exactly as before.
 *   optional  — verify a cert when one is presented, but still admit agents
 *               without one (so you can watch enrollment progress in the logs).
 *               A presented cert whose CN does not match the claimed
 *               host_identifier is ALWAYS rejected, even here.
 *   required  — reject any agent that does not present a valid client cert whose
 *               CN matches its claimed host_identifier.
 */

import { timingSafeEqual } from 'crypto';
import { getLogger } from './logger';

const logger = getLogger('agent.mtls');

export type MtlsMode = 'off' | 'optional' | 'required';

// The effective enforcement mode appears nowhere else in the logs, so record it
// once at first use. Not per call: this is re-evaluated on every WS connection
// attempt, and repeating the same fact under load adds no information.
let loggedMode: MtlsMode | null = null;

export function agentMtlsMode(): MtlsMode {
  const v = String(process.env.AGENT_MTLS_MODE ?? 'off').trim().toLowerCase();
  const mode: MtlsMode = v === 'required' || v === 'optional' ? v : 'off';
  if (loggedMode === null) {
    loggedMode = mode;
    logger.info({ mode }, 'Agent mTLS enforcement mode resolved');
  }
  return mode;
}

// Header names nginx populates from $ssl_client_verify and $ssl_client_s_dn.
const VERIFY_HEADER = 'x-ssl-client-verify';
const DN_HEADER = 'x-ssl-client-dn';

// Internal-only shared secret nginx's /ws location sets on every request it
// proxies (NOT a client-facing credential — it never crosses the trust
// boundary the other direction). Its only job is proving a request actually
// transited nginx, so the X-SSL-Client-* headers on it are genuine rather
// than self-supplied by a client hitting PORT directly. See module header.
const INTERNAL_SECRET_HEADER = 'x-vajra-internal-secret';

/**
 * True only for requests nginx actually proxied. With no
 * AGENT_MTLS_INTERNAL_SECRET configured this always returns false — fail
 * closed, since there would otherwise be no way to tell a real nginx-proxied
 * request from one hitting PORT directly.
 */
function requestTransitedNginx(req: HeaderBag): boolean {
  const expected = process.env.AGENT_MTLS_INTERNAL_SECRET;
  if (!expected) return false;
  const actual = headerStr(req, INTERNAL_SECRET_HEADER);
  const actualBuf = Buffer.from(actual);
  const expectedBuf = Buffer.from(expected);
  return actualBuf.length === expectedBuf.length && timingSafeEqual(actualBuf, expectedBuf);
}

// Minimal shape of the tls.TLSSocket properties this module reads. Declared
// separately (rather than importing tls.TLSSocket) so plain HTTP requests in
// non-production, and mocked requests in agentMtls.selftest.ts, don't need a
// real socket -- req.socket is optional on HeaderBag below.
type PeerCert = { subject?: { CN?: unknown }; issuer?: { CN?: unknown }; valid_to?: unknown };
type SocketLike = {
  authorized?: boolean;
  authorizationError?: unknown;
  getPeerCertificate?: (detailed?: boolean) => PeerCert | undefined;
};

type HeaderBag = { headers: Record<string, string | string[] | undefined>; socket?: SocketLike };

function headerStr(req: HeaderBag, name: string): string {
  const v = req.headers[name];
  return Array.isArray(v) ? String(v[0] ?? '') : String(v ?? '');
}

/**
 * CN of a client certificate Node's own TLS stack verified directly against
 * the Agent CA on this connection (see index.ts's requestCert/ca options) —
 * the authoritative signal for the direct-PORT path real agents use. Empty
 * string when no cert was presented or it didn't chain to the Agent CA;
 * socket.authorized is checked BEFORE ever reading the CN, since
 * getPeerCertificate() still returns subject details for an untrusted/wrong
 * cert -- trusting the CN of a cert nothing verified would defeat the point.
 */
function socketVerifiedCn(req: HeaderBag): string {
  const socket = req.socket;
  if (!socket?.authorized || typeof socket.getPeerCertificate !== 'function') return '';
  const cn = socket.getPeerCertificate()?.subject?.CN;
  return typeof cn === 'string' ? cn : '';
}

/**
 * When socketVerifiedCn() comes back empty, logs which of two very different
 * situations actually happened: no cert was presented at all (the common,
 * expected case for an unenrolled/outdated agent -- silent, no operator
 * action possible), vs. a cert WAS presented but didn't chain to the Agent
 * CA (wrong CA, expired, corrupted key pair, ACL blocking the agent's own
 * read of its key, ...) -- an actionable failure worth surfacing, since
 * "agent has files on disk that look right" and "agent's TLS stack actually
 * negotiated with them successfully" are two different claims, and only the
 * second one this function can observe from the server side.
 */
function logSocketCertDiagnostics(req: HeaderBag, hostIdentifier: string): void {
  const socket = req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') return;
  const cert = socket.getPeerCertificate(true);
  const certWasPresented = !!cert && Object.keys(cert).length > 0;
  if (!certWasPresented) return; // no cert at all -- nothing more to say than the debug line callers already log
  logger.warn(
    {
      hostIdentifier,
      authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
      certIssuerCN: cert?.issuer?.CN,
      certSubjectCN: cert?.subject?.CN,
      certValidTo: cert?.valid_to,
    },
    'Agent presented a client certificate on this connection, but it did not verify against the Agent CA',
  );
}

/** Extract CN from an OpenSSL/RFC2253 DN, e.g. "CN=<uuid>,O=Vajra" or "/O=Vajra/CN=<uuid>". */
export function extractCN(dn: string): string {
  for (const part of dn.split(/[,/]/)) {
    const m = part.trim().match(/^CN\s*=\s*(.+)$/i);
    if (m) return m[1].trim();
  }
  return '';
}

/** Parse host_identifier from the agent-info header for the CN-binding check. */
export function agentInfoHostId(req: HeaderBag): string {
  const raw = req.headers['agent-info'];
  const s = Array.isArray(raw) ? raw[0] : raw;
  if (typeof s !== 'string') return '';
  try {
    const info = JSON.parse(s) as { host_identifier?: string };
    return typeof info.host_identifier === 'string' ? info.host_identifier : '';
  } catch (err) {
    logger.warn({ err }, 'Failed to parse agent-info header for host_identifier');
    return '';
  }
}

/**
 * Returns null when the agent connection is allowed, or a short reason string
 * when it must be rejected. A presented certificate must have CN ==
 * hostIdentifier so a valid cert proving identity A can never be replayed to
 * act as identity B.
 */
export function verifyAgentMtls(req: HeaderBag, hostIdentifier: string): string | null {
  const mode = agentMtlsMode();
  if (mode === 'off') return null;

  // Source 1 (authoritative): a cert Node's own TLS stack verified directly
  // on this connection. Source 2 (fallback): nginx-forwarded headers,
  // trusted only with the shared secret proving they actually came via
  // nginx. socketCn wins when both are present -- see module header.
  const socketCn = socketVerifiedCn(req);
  const certVerifiedBySocket = socketCn !== '';
  if (!certVerifiedBySocket) logSocketCertDiagnostics(req, hostIdentifier);

  const viaNginx = requestTransitedNginx(req);
  const rawVerify = headerStr(req, VERIFY_HEADER).toUpperCase();
  if (rawVerify === 'SUCCESS' && !viaNginx && !certVerifiedBySocket) {
    // Claims a verified client cert but the request didn't transit nginx (and
    // isn't independently verified at the TLS layer either) — X-SSL-Client-Verify
    // can only legitimately be set by nginx, so this is either a misconfigured
    // AGENT_MTLS_INTERNAL_SECRET or a client hitting PORT directly and forging
    // the header to impersonate a verified agent. Falls through to "no cert
    // presented" below in both modes, same as a genuinely unenrolled agent, but
    // logged distinctly because it is a different and actionable event.
    logger.warn({ hostIdentifier }, 'Agent connection claimed a verified mTLS certificate without transiting nginx — ignoring it (possible spoofing attempt against the direct PORT listener)');
  }
  const headerVerifiedSuccess = viaNginx && rawVerify === 'SUCCESS';
  const verified = certVerifiedBySocket || headerVerifiedSuccess;

  if (!verified) {
    if (mode === 'required') {
      logger.warn({ hostIdentifier }, 'Rejected agent connection with no valid client certificate');
      return 'client certificate required';
    }
    // Admitted without a cert under 'optional' mode. This is the "not yet
    // enrolled" case the module header says 'optional' exists to make
    // observable — without this line it is indistinguishable from a
    // verified connection, since only the success and required-mode
    // rejection paths logged anything.
    logger.debug({ hostIdentifier, mode }, 'Admitted agent connection with no client certificate (optional mode)');
    return null;
  }

  // socketCn is already known-verified; only fall back to parsing the header
  // DN when verification came from source 2 instead.
  const cn = certVerifiedBySocket ? socketCn : extractCN(headerStr(req, DN_HEADER));
  if (!cn) {
    if (mode === 'required') {
      logger.warn({ hostIdentifier }, 'Rejected agent connection with a client certificate that has no CN');
      return 'client certificate has no CN';
    }
    logger.debug({ hostIdentifier, mode }, 'Admitted agent connection with a client certificate that has no CN (optional mode)');
    return null;
  }
  // Reject a mismatched-but-valid cert in BOTH optional and required mode: a
  // certificate that proves identity A must not be usable to act as identity B.
  // No `hostIdentifier &&` guard here on purpose: cn is already known non-empty
  // (checked above), so an empty/unparseable claimed hostIdentifier — e.g. a
  // non-string host_identifier in agent-info that upstream parsing normalises
  // to '' — must fail this comparison rather than silently skip it. A verified
  // cert with no matching identity claim is not "nothing to check", it's a
  // mismatch.
  if (cn !== hostIdentifier) {
    logger.warn({ cn, hostIdentifier }, 'Rejected agent connection where client cert CN does not match host_identifier');
    return `client cert CN ${cn} does not match host_identifier ${hostIdentifier || '(missing)'}`;
  }
  // The one success signal this module produces — deliberately logged so an
  // operator watching a phased mTLS rollout can see enrollment progress (see
  // module header comment), not just rejections.
  logger.info({ hostIdentifier, mode, source: certVerifiedBySocket ? 'socket' : 'nginx-header' }, 'Verified agent mTLS client certificate');
  return null;
}
