import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { AgentCertProvisioningToken } from '../../orm/entities/fleet/AgentCertProvisioningToken';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import {
  generateProvisioningToken,
  hashProvisioningToken,
  getProvisioningTokenExpiryMs,
  isValidHostIdentifier,
  signAgentCsr,
  caFilesAvailable,
  getAgentCaCertPem,
} from '../../utils/agentCertProvisioning';
import { getUserNodeScope, assertCanActOnHost, assertHostInScope, getScopedHostIdentifiers } from '../../utils/nodeScope';
import { verifyTotpCode } from '../../utils/totp';
import { TOKEN_LIST_MAX_ROWS } from '../../consts/pagination';
import { returningRows } from '../../utils/returningRows';
import { getLogger } from '../../utils/logger';
import { claimTotpCodeOnce } from '../../utils/redisClient';

const logger = getLogger('nodes.agentCertProvisioning');

/**
 * POST /api/nodes/cert-provisioning-token/generate
 *
 * Admin issues a one-time mTLS cert-provisioning token bound to a single
 * host_identifier. Requires MFA, and the
 * host must already be within the caller's node scope (a Group Admin can
 * only mint a cert-provisioning token for a host owned by one of their own
 * actable groups; a brand-new host with no `nodes` row yet, or one owned by
 * a different group, is only reachable by a Super Administrator). Without
 * this check any Group Admin could mint a valid mTLS identity credential for
 * a host outside their authority — exactly the impersonation primitive mTLS
 * exists to prevent, just handed to a lower-trust role instead of an
 * external attacker.
 *
 * NOT osquery's own enrollment (enroll_secret / node_key against the
 * separate C++ fleet server) — this only provisions the mTLS client
 * certificate the Go extension uses for its WebSocket connections here.
 *
 * Body: { host_identifier: string, totp_code: string }
 */
export const generateCertProvisioningToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { host_identifier, totp_code } = req.body ?? {};
    if (!isValidHostIdentifier(host_identifier) || !totp_code) {
      return res.status(400).json({ status: 'Fail', message: 'Missing or invalid host_identifier, or missing totp_code' });
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (!jwtPayload?.id) {
      logger.warn({ host_identifier }, 'Cert-provisioning token generation rejected: no authenticated user on request');
      return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    }

    if (!caFilesAvailable()) {
      logger.warn({ host_identifier }, 'Cert-provisioning token generation rejected: agent CA not provisioned on this server');
      return res.status(503).json({ status: 'Fail', message: 'Agent CA is not provisioned on this server yet' });
    }

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) {
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }

    const userRepo = dbSources[0].getRepository(VajraUser);
    const user = await userRepo.findOne({ where: { id: jwtPayload.id } });
    if (!user || !user.mfa_enabled || !user.mfa_secret) {
      logger.warn({ user_id: jwtPayload.id, host_identifier }, 'Cert-provisioning token generation denied: MFA not enabled for user');
      return res.status(403).json({ status: 'Fail', message: 'MFA must be enabled to generate cert-provisioning tokens' });
    }
    const verified = verifyTotpCode(user.mfa_secret, totp_code);
    if (!verified) {
      logger.warn({ user_id: jwtPayload.id, host_identifier }, 'Cert-provisioning token generation denied: invalid TOTP code');
      return res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    }
    if (!(await claimTotpCodeOnce(jwtPayload.id, totp_code))) {
      logger.warn({ user_id: jwtPayload.id, host_identifier }, 'Cert-provisioning token generation denied: TOTP code already used');
      return res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    if (!(await assertCanActOnHost(scope, host_identifier))) {
      logger.warn({ user_id: jwtPayload.id, host_identifier }, 'Cert-provisioning token generation rejected: host not in caller scope');
      return res.status(404).json({ status: 'Fail', message: 'Node not found' });
    }

    const fleetDb = dbSources[1];
    const tokenRepo = fleetDb.getRepository(AgentCertProvisioningToken);

    // One active token per host — revoke any prior active one so a lost/leaked
    // earlier token for this host stops being usable the moment a new one is cut.
    const revokeResult = await tokenRepo.update(
      { hostIdentifier: host_identifier, status: 'active' },
      { status: 'revoked', revokedAt: new Date(), revokedById: jwtPayload.id },
    );
    if ((revokeResult.affected ?? 0) > 1) {
      // Invariant is "one active token per host" — more than one revoked here
      // means that invariant was already broken before this request.
      logger.warn({ host_identifier, revoked_count: revokeResult.affected }, 'Cert-provisioning token generation revoked more than one prior active token for this host');
    }

    const token = generateProvisioningToken();
    const expiresAt = new Date(Date.now() + getProvisioningTokenExpiryMs());

    const record = tokenRepo.create({
      tokenHash: hashProvisioningToken(token),
      hostIdentifier: host_identifier,
      issuedById: jwtPayload.id,
      issuedByEmail: user.email,
      status: 'active',
      expiresAt,
    });
    await tokenRepo.save(record);

    try {
      await logAuditTrail({
        action: 'GENERATE_AGENT_CERT_TOKEN',
        status: 'success',
        userId: jwtPayload.id,
        email: user.email,
        details: { host_identifier, token_id: record.id },
        ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
      });
    } catch (auditErr) {
      logger.warn({ err: auditErr, host_identifier }, 'Failed to record audit trail for cert-provisioning token generation');
    }

    logger.info({ host_identifier, token_id: record.id }, 'Cert-provisioning token generated');

    return res.status(200).json({
      status: 'Success',
      // Returned once, never persisted or retrievable again — the agent's
      // install step must consume it immediately.
      provisioning_token: token,
      host_identifier,
      expires_at: expiresAt.toISOString(),
    });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.body?.host_identifier }, 'Failed to generate cert-provisioning token');
    return next(new CustomError(500, 'Raw', 'Failed to generate cert-provisioning token', null, error));
  }
};

/**
 * POST /api/agent/provision-cert
 *
 * Agent calls this once, at install time, with the token an admin generated
 * for it plus a CSR for a keypair it just created locally (the private key
 * never leaves the agent). No JWT — the token itself is the auth.
 * Single-use: the token row is atomically
 * flipped to 'used' as part of the same query that looks it up, closing the
 * TOCTOU window a naive check-then-update would leave open.
 *
 * Body: { provisioning_token: string, host_identifier: string, csr_pem: string }
 */
export const provisionAgentCert = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { provisioning_token, host_identifier, csr_pem } = req.body ?? {};
    if (typeof provisioning_token !== 'string' || !provisioning_token || !isValidHostIdentifier(host_identifier) || typeof csr_pem !== 'string' || !csr_pem) {
      return res.status(400).json({ status: 'Fail', message: 'Missing or invalid provisioning_token, host_identifier, or csr_pem' });
    }

    // The provisioning token is a genuine bearer secret ("No JWT — the token
    // itself is the auth", above), so on any deployment that has TLS material
    // configured, refuse to hand out a signed cert over a connection that
    // sent it in the clear — PORT now accepts both plaintext and TLS on the
    // same listener (see index.ts), and this endpoint must not be the one
    // that quietly accepts the weaker of the two. deploymentHasTls is read
    // straight from SSL_KEY_PATH/SSL_CERT_PATH rather than inferred from this
    // connection: httpolyglot never sets req.socket.encrypted at all on its
    // plaintext branch (it's `undefined`, exactly as on a deployment with no
    // TLS material whatsoever), so req.socket.encrypted alone cannot tell
    // "this deployment has no TLS capability" apart from "this deployment
    // has TLS, but this particular request skipped it" — only the env vars
    // can. Also NOT using req.secure/X-Forwarded-Proto: Express has 'trust
    // proxy' enabled for real nginx-proxied traffic, but agents dial PORT
    // directly (bypassing nginx entirely, see index.ts's NOTE at PORT's
    // definition), so a caller hitting PORT directly could otherwise spoof
    // X-Forwarded-Proto: https over an actually-plaintext socket. A
    // deployment with no TLS material at all (e.g. local dev) has no secure
    // alternative to fall back to, so it keeps today's plaintext behaviour.
    const deploymentHasTls = !!(process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH);
    const connectionIsEncrypted = !!(req.socket as any)?.encrypted;
    if (deploymentHasTls && !connectionIsEncrypted) {
      logger.warn({ host_identifier }, 'Agent cert provisioning rejected: request was not sent over TLS');
      return res.status(403).json({ status: 'Fail', message: 'Certificate provisioning requires a TLS connection' });
    }

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) {
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const fleetDb = dbSources[1];

    const tokenHash = hashProvisioningToken(provisioning_token);

    // Atomic: only claim the row if it's currently active, not expired, and
    // bound to the SAME host_identifier being claimed here — a token issued
    // for host A can never be consumed by a request claiming to be host B,
    // even if the raw token leaked. 0 rows affected covers unknown, expired,
    // already-used, revoked, and host-mismatched in one shot; we don't need
    // to distinguish those to the caller (an unauthenticated agent) beyond
    // "provisioning failed".
    // returningRows() is load-bearing here, not tidiness: TypeORM's Postgres driver
    // returns [rows, rowCount] for an UPDATE ... RETURNING, so the raw result's .length is
    // always 2 even when zero rows matched ([[], 0]). Read raw, the rejection branch below
    // is unreachable and this endpoint signs a CSR for an unknown, expired, spent, revoked
    // or host-mismatched token — it fails open on exactly the check above. See
    // utils/returningRows.ts.
    const claimedRows = returningRows<{ id: number }>(
      await fleetDb.query(
        `UPDATE agent_cert_provisioning_tokens
         SET status = 'used', used_at = NOW()
         WHERE token_hash = $1 AND host_identifier = $2 AND status = 'active' AND expires_at > NOW()
         RETURNING id`,
        [tokenHash, host_identifier],
      ),
    );

    if (claimedRows.length === 0) {
      // Folds unknown/expired/already-used/revoked/host-mismatched into one
      // outcome for the (unauthenticated) caller by design, but that's still
      // a distinct failure path worth a server-side trail — a spike here for
      // one host can mean a stale token, a retry storm, or a probing attempt.
      logger.warn({ host_identifier }, 'Agent cert provisioning rejected: no matching active, unexpired token for this host');
      return res.status(403).json({ status: 'Fail', message: 'Invalid, expired, or already-used provisioning token' });
    }

    let signedCert: string;
    try {
      signedCert = await signAgentCsr(csr_pem, host_identifier);
    } catch (signErr) {
      logger.error({ err: signErr, host_identifier }, 'CSR signing failed during agent cert provisioning');
      // The token is already burned at this point (by design — a malformed
      // CSR submitted with a valid token should not get unlimited retries
      // against that same token; the admin re-issues if this was a mistake).
      return res.status(400).json({ status: 'Fail', message: 'Failed to sign certificate — CSR was invalid or malformed' });
    }

    try {
      await logAuditTrail({
        action: 'PROVISION_AGENT_CERT',
        status: 'success',
        userId: null,
        email: 'agent',
        details: { host_identifier },
        ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
      });
    } catch (auditErr) {
      logger.warn({ err: auditErr, host_identifier }, 'Failed to record audit trail for agent cert provisioning');
    }

    logger.info({ host_identifier }, 'Agent certificate provisioned');

    return res.status(200).json({
      status: 'Success',
      certificate: signedCert,
      ca_certificate: getAgentCaCertPem(),
    });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.body?.host_identifier }, 'Certificate provisioning failed');
    return next(new CustomError(500, 'Raw', 'Certificate provisioning failed', null, error));
  }
};

/**
 * POST /api/nodes/cert-provisioning-token/revoke
 *
 * Body: { id: number, totp_code: string }
 */
export const revokeCertProvisioningToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id, totp_code } = req.body ?? {};
    if (!id || !totp_code) {
      return res.status(400).json({ status: 'Fail', message: 'Missing id or totp_code' });
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (!jwtPayload?.id) {
      logger.warn({ id }, 'Cert-provisioning token revocation rejected: no authenticated user on request');
      return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    }

    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) {
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }

    const userRepo = dbSources[0].getRepository(VajraUser);
    const user = await userRepo.findOne({ where: { id: jwtPayload.id } });
    if (!user || !user.mfa_enabled || !user.mfa_secret) {
      logger.warn({ user_id: jwtPayload.id, id }, 'Cert-provisioning token revocation denied: MFA not enabled for user');
      return res.status(403).json({ status: 'Fail', message: 'MFA required' });
    }
    const verified = verifyTotpCode(user.mfa_secret, totp_code);
    if (!verified) {
      logger.warn({ user_id: jwtPayload.id, id }, 'Cert-provisioning token revocation denied: invalid TOTP code');
      return res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    }
    if (!(await claimTotpCodeOnce(jwtPayload.id, totp_code))) {
      logger.warn({ user_id: jwtPayload.id, id }, 'Cert-provisioning token revocation denied: TOTP code already used');
      return res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    }

    const tokenRepo = dbSources[1].getRepository(AgentCertProvisioningToken);
    const record = await tokenRepo.findOne({ where: { id } });
    if (!record) {
      logger.warn({ id }, 'Cert-provisioning token revocation rejected: token not found');
      return res.status(404).json({ status: 'Fail', message: 'Token not found' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    if (!(await assertCanActOnHost(scope, record.hostIdentifier))) {
      logger.warn({ user_id: jwtPayload.id, id, host_identifier: record.hostIdentifier }, 'Cert-provisioning token revocation rejected: host not in caller scope');
      return res.status(404).json({ status: 'Fail', message: 'Token not found' });
    }

    if (record.status !== 'active') {
      logger.warn({ id, status: record.status }, 'Cert-provisioning token revocation rejected: token already inactive');
      return res.status(400).json({ status: 'Fail', message: `Token is already ${record.status}` });
    }

    await tokenRepo.update({ id }, { status: 'revoked', revokedAt: new Date(), revokedById: jwtPayload.id });

    try {
      await logAuditTrail({
        action: 'REVOKE_AGENT_CERT_TOKEN',
        status: 'success',
        userId: jwtPayload.id,
        email: user.email,
        details: { id, host_identifier: record.hostIdentifier },
        ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
      });
    } catch (auditErr) {
      logger.warn({ err: auditErr, id, host_identifier: record.hostIdentifier }, 'Failed to record audit trail for cert-provisioning token revocation');
    }

    logger.info({ id, host_identifier: record.hostIdentifier }, 'Cert-provisioning token revoked');

    return res.status(200).json({ status: 'Success', message: 'Token revoked' });
  } catch (error) {
    logger.error({ err: error, id: req.body?.id }, 'Failed to revoke cert-provisioning token');
    return next(new CustomError(500, 'Raw', 'Failed to revoke cert-provisioning token', null, error));
  }
};

/**
 * GET /api/nodes/cert-provisioning-token/list
 *
 * Never returns token_hash — only metadata. The raw token was shown once, at
 * generation time, and cannot be retrieved again.
 */
export const listCertProvisioningTokens = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) {
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (!jwtPayload?.id) {
      logger.warn('Cert-provisioning token list rejected: no authenticated user on request');
      return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    }
    const scope = await getUserNodeScope(jwtPayload.id);

    const tokenRepo = dbSources[1].getRepository(AgentCertProvisioningToken);
    const qb = tokenRepo.createQueryBuilder('t').orderBy('t.issuedAt', 'DESC').limit(TOKEN_LIST_MAX_ROWS);

    const hostFilter = req.query.host_identifier as string | undefined;
    if (hostFilter) {
      if (!(await assertHostInScope(scope, hostFilter))) {
        // Distinct `reason` from the genuine-zero-results path below (same
        // count:0 shape otherwise) — without it, "caller has no access to
        // this host" is indistinguishable in logs from "host is in scope but
        // has no tokens".
        logger.debug({ count: 0, host_identifier: hostFilter, reason: 'host_out_of_scope' }, 'Cert-provisioning tokens listed');
        return res.status(200).json({ status: 'Success', tokens: [] });
      }
      qb.where('t.hostIdentifier = :host', { host: hostFilter });
    } else if (!scope.unrestricted) {
      const scopedHosts = await getScopedHostIdentifiers(scope);
      if (!scopedHosts || scopedHosts.length === 0) {
        logger.debug({ count: 0, host_identifier: null, reason: 'no_scoped_hosts' }, 'Cert-provisioning tokens listed');
        return res.status(200).json({ status: 'Success', tokens: [] });
      }
      qb.where('t.hostIdentifier IN (:...hosts)', { hosts: scopedHosts });
    }

    const tokens = await qb.getMany();

    logger.debug({ count: tokens.length }, 'Cert-provisioning tokens listed');

    return res.status(200).json({
      status: 'Success',
      tokens: tokens.map((t) => ({
        id: t.id,
        host_identifier: t.hostIdentifier,
        issued_by: t.issuedByEmail,
        status: t.status,
        issued_at: t.issuedAt,
        expires_at: t.expiresAt,
        used_at: t.usedAt,
        revoked_at: t.revokedAt,
      })),
    });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.query?.host_identifier }, 'Failed to list cert-provisioning tokens');
    return next(new CustomError(500, 'Raw', 'Failed to list cert-provisioning tokens', null, error));
  }
};
