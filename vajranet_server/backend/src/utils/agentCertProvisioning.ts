/**
 * Agent mTLS certificate provisioning — CSR signing against the deployment's
 * Agent CA.
 *
 * NOT osquery's own enrollment. That's a separate system: osqueryd talks
 * directly to the C++ fleet server (its own TLS listener, enroll_secret ->
 * node_key, /config, /log, /distributed/*) — a different port, different
 * process, different database rows. This module only issues the mTLS client
 * certificate the Go extension presents on its WebSocket connections to
 * *this* Node.js backend (/ws/ext). Naming throughout
 * deliberately avoids "enroll"/"enrollment" so the two systems stay
 * unambiguous in code, logs, and docs.
 *
 * The Agent CA is NOT generated here. Its public half
 * (agent-ca.crt) is baked into nginx's ssl_client_certificate config, so the
 * private half signing agent certs must be the exact same CA — an admin
 * provisions it once in AGENT_CA_DIR (default backend/keys; see the openssl
 * commands in .env.example).
 * If the files aren't present, cert provisioning is simply unavailable.
 *
 * host_identifier binds a provisioning token to one identity at issuance
 * (see AgentCertProvisioningToken). The certificate this module issues
 * always forces CN to that bound value via `-subj`, ignoring whatever
 * subject the agent's own CSR declares — so a CSR can only ever prove
 * possession of a keypair, never choose its own identity.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getLogger } from './logger';
import { DEFAULT_KEYS_DIR } from '../consts/server';
import { EXTERNAL_COMMAND_TIMEOUT_MS } from '../consts/timeout';

const logger = getLogger('utils.agentCertProvisioning');

const execFileAsync = promisify(execFile);

const CA_DIR = process.env.AGENT_CA_DIR || DEFAULT_KEYS_DIR;
const CA_KEY_PATH = path.join(CA_DIR, 'agent-ca.key');
const CA_CERT_PATH = path.join(CA_DIR, 'agent-ca.crt');
const CA_SERIAL_PATH = path.join(CA_DIR, 'agent-ca.srl');

// A malformed env var (non-numeric, negative, zero) must fall back to the
// documented default with a loud warning, not silently become NaN — NaN
// propagating into `-days NaN` (OpenSSL) or `Date.now() + NaN` (an Invalid
// Date whose .toISOString() throws) turns a config typo into a confusing
// runtime crash instead of a clear startup-time signal.
function parsePositiveNumberEnv(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    logger.warn({ name, raw, fallback }, 'Invalid environment variable value, falling back to default');
    return fallback;
  }
  return parsed;
}

const CERT_VALIDITY_DAYS = parsePositiveNumberEnv(process.env.AGENT_CERT_VALIDITY_DAYS, 397, 'AGENT_CERT_VALIDITY_DAYS');
const TOKEN_EXPIRY_HOURS = parsePositiveNumberEnv(process.env.AGENT_CERT_PROVISIONING_TOKEN_EXPIRY_HOURS, 1, 'AGENT_CERT_PROVISIONING_TOKEN_EXPIRY_HOURS');
const MAX_CSR_BYTES = 8 * 1024; // a P-256 CSR is ~600-900 bytes; this bounds a malicious/oversized body

const TOKEN_PREFIX = 'vacp_'; // Vajra Agent Cert Provisioning — greppable in logs/secret-scanners

export function getProvisioningTokenExpiryMs(): number {
  return TOKEN_EXPIRY_HOURS * 60 * 60 * 1000;
}

export function caFilesAvailable(): boolean {
  return fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH);
}

/**
 * True when just the CA's public certificate is present -- enough for the
 * server to request/verify agent client certs at the TLS layer (see
 * index.ts's https.createServer options), even on a deployment that keeps
 * the CA's private key (needed only for *signing* new certs, gated by
 * caFilesAvailable() above) offline elsewhere.
 */
export function caCertAvailable(): boolean {
  return fs.existsSync(CA_CERT_PATH);
}

export function getAgentCaCertPem(): string {
  return fs.readFileSync(CA_CERT_PATH, 'utf-8');
}

/** Random 256-bit bearer token. Only its hash is ever persisted (see hashProvisioningToken). */
export function generateProvisioningToken(): string {
  return TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
}

export function hashProvisioningToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf-8').digest('hex');
}

// osquery UUIDs are the expected shape, but kept loose enough for other
// identifier schemes; the point is excluding characters ('/', '=', ',',
// whitespace, control chars) that could otherwise confuse the OpenSSL -subj
// parser or leak into logs/paths unexpectedly.
const HOST_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;

export function isValidHostIdentifier(id: unknown): id is string {
  return typeof id === 'string' && HOST_IDENTIFIER_PATTERN.test(id);
}

const CSR_PEM_PATTERN = /^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\s*$/;

// Serializes the actual OpenSSL invocation so concurrent provisioning
// requests (realistic during bulk onboarding) can't race on the shared
// agent-ca.srl serial-number file — `-CAcreateserial`/`-CAserial` read,
// increment, and rewrite that file with no locking of their own, so two
// simultaneous openssl processes can read the same starting serial and
// collide. This only serializes within this one Node process; if this
// backend is ever run as multiple replicas sharing the same AGENT_CA_DIR,
// this queue alone would not be enough — a real file lock would be needed.
let signQueue: Promise<void> = Promise.resolve();

/**
 * Signs a client certificate for hostIdentifier from an agent-submitted CSR.
 * The CSR supplies only the public key; subject is always forced server-side.
 * Throws on any failure (missing CA, invalid host_identifier, malformed CSR,
 * or an OpenSSL signing error — e.g. the CSR's self-signature doesn't verify).
 */
export async function signAgentCsr(csrPem: string, hostIdentifier: string): Promise<string> {
  if (!caFilesAvailable()) {
    logger.error('Rejected agent cert provisioning request: Agent CA not provisioned on this server');
    throw new Error('Agent CA not provisioned on this server');
  }
  if (!isValidHostIdentifier(hostIdentifier)) {
    logger.warn({ hostIdentifier }, 'Rejected agent cert provisioning request: invalid host_identifier');
    throw new Error('Invalid host_identifier');
  }
  if (typeof csrPem !== 'string' || csrPem.length === 0 || csrPem.length > MAX_CSR_BYTES) {
    logger.warn({ hostIdentifier, csrLength: typeof csrPem === 'string' ? csrPem.length : null }, 'Rejected agent cert provisioning request: invalid or oversized CSR');
    throw new Error('Invalid or oversized CSR');
  }
  const trimmed = csrPem.trim();
  if (!CSR_PEM_PATTERN.test(trimmed)) {
    logger.warn({ hostIdentifier }, 'Rejected agent cert provisioning request: malformed CSR PEM');
    throw new Error('Malformed CSR PEM');
  }

  // Queue the actual signing behind whatever is already in flight. Chain off
  // a settled (never-rejecting) continuation so one failed attempt doesn't
  // wedge every request queued behind it.
  const result = signQueue.then(() => signWithOpenssl(trimmed, hostIdentifier));
  signQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

async function signWithOpenssl(trimmedCsrPem: string, hostIdentifier: string): Promise<string> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vajra-cert-provision-'));
  const csrPath = path.join(tmpDir, 'req.csr');
  const certPath = path.join(tmpDir, 'cert.pem');
  try {
    fs.writeFileSync(csrPath, trimmedCsrPem, { mode: 0o600 });
    // -subj forces the issued cert's subject regardless of the CSR's own
    // declared subject — the agent-supplied CSR is trusted only for its
    // public key and self-signature, never for what identity it claims.
    await execFileAsync(
      'openssl',
      [
        'x509', '-req',
        '-in', csrPath,
        '-CA', CA_CERT_PATH,
        '-CAkey', CA_KEY_PATH,
        '-CAcreateserial',
        '-CAserial', CA_SERIAL_PATH,
        '-subj', `/O=Vajra/OU=Agent/CN=${hostIdentifier}`,
        '-sha256',
        '-days', String(CERT_VALIDITY_DAYS),
        '-out', certPath,
      ],
      { timeout: EXTERNAL_COMMAND_TIMEOUT_MS },
    );
    const cert = fs.readFileSync(certPath, 'utf-8');
    logger.info({ hostIdentifier }, 'Signed agent mTLS certificate');
    return cert;
  } catch (err) {
    logger.error({ err, hostIdentifier }, 'OpenSSL certificate signing failed');
    throw new Error('Failed to sign certificate — CSR may be invalid or malformed', { cause: err });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
