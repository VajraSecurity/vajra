/**
 * WebSocket auth: get JWT payload from upgrade request (e.g. for audit trail,
 * or combined DB checks via resolveNodeUiWsSession).
 * Uses access_token cookie only.
 */

import jwt from 'jsonwebtoken';
import type { JwtPayload } from '../types/JwtPayload';
import { ACCESS_TOKEN_COOKIE } from '../consts/cookies';
import { JWT_ALGORITHM } from '../consts/auth';
import { dbSourceConnection } from '../index';
import { parseCookies } from './cookieUtils';
import type { NodeScope } from './nodeScope';
import { isMfaChallengeToken, checkTokenBlacklist } from '../middleware/checkJwt';
import { SUPER_ADMIN_ROLE } from '../orm/entities/users/Users';
import { GROUP_MEMBERSHIP_ROLE_ADMIN, GROUP_MEMBERSHIP_ROLE_VIEWER } from '../orm/entities/users/UserGroupMembership';
import { getLogger } from './logger';

const logger = getLogger('websocket.auth');

export type ReqLike = { headers: { [key: string]: string | undefined } };



/**
 * Returns the verified JWT payload from the request cookies, or null if the
 * cookie is absent, the signature fails, the token is blacklisted, or it is an
 * MFA-challenge token.
 */
export async function getWsJwtPayload(req: ReqLike): Promise<JwtPayload | null> {
  try {
    const cookieHeader = req?.headers?.cookie;
    if (!cookieHeader) return null;
    const cookies = parseCookies(cookieHeader);
    const accessToken = cookies[ACCESS_TOKEN_COOKIE];
    if (!accessToken) return null;
    const secret = process.env.ACCESS_JWT_SECRET;
    if (!secret) return null;
    const payload = jwt.verify(accessToken, secret, { algorithms: [JWT_ALGORITHM] }) as JwtPayload;
    // The same blacklist check checkAccessJwt applies to every REST request.
    // Without it a revoked access token stays cryptographically valid, and so
    // keeps working over /ws/ui for its full remaining lifetime, because this
    // function is the authorization gate for every caller below.
    if (await checkTokenBlacklist(accessToken)) {
      logger.debug({ userId: payload.id }, 'WS JWT rejected: token is blacklisted');
      return null;
    }
    // Reject the interim MFA-challenge token (see isMfaChallengeToken in
    // middleware/checkJwt.ts): it verifies against this same secret but
    // represents a password-only session, which no caller may treat as
    // a completed one.
    if (isMfaChallengeToken(payload)) {
      logger.debug({ userId: payload.id }, 'WS JWT rejected: MFA verification not completed');
      return null;
    }
    return payload;
  } catch (err) {
    logger.debug({ err }, 'Failed to verify WS JWT payload');
    return null;
  }
}

/**
 * Validates the JWT and the database session for UI WebSocket messages, and
 * returns the caller's JWT alongside the role and node scope read from the
 * database. `effectiveRole` always comes from the database row, never from the
 * JWT, so it stays authoritative for Viewer checks after a role change.
 *
 * Fails closed: returns null — rejecting the session — on a database error, an
 * uninitialized database, a missing or suspended user, or a session_version
 * mismatch.
 */

export async function resolveNodeUiWsSession(
  req: ReqLike,
): Promise<{ jwt: JwtPayload; effectiveRole: string; scope: NodeScope } | null> {
  const jwtPayload = await getWsJwtPayload(req);
  if (!jwtPayload?.id) return null;

  try {
    const ds = dbSourceConnection();
    if (!ds || ds.length === 0 || !ds[0].isInitialized) {
      logger.warn({ userId: jwtPayload.id }, 'WS UI session rejected: primary database not initialized');
      return null;
    }

    const rows: {
      session_version: number;
      suspended: boolean;
      role: string | null;
      group_id: string | null;
      membership_role: string | null;
    }[] = await ds[0].query(
      `SELECT u.session_version AS session_version, u.suspended AS suspended, u.role AS role,
              ugm.group_id AS group_id, ugm.role AS membership_role
       FROM vajra_users u
       LEFT JOIN user_group_memberships ugm ON ugm.user_id = u.id
       WHERE u.id = $1`,
      [jwtPayload.id],
    );

    if (!rows || rows.length === 0) {
      logger.warn({ userId: jwtPayload.id }, 'WS UI session rejected: no matching user row');
      return null;
    }
    if (rows[0].suspended) {
      logger.debug({ userId: jwtPayload.id }, 'WS UI session rejected: user suspended');
      return null;
    }
    if (rows[0].session_version !== (jwtPayload.session_version ?? 0)) {
      logger.debug({ userId: jwtPayload.id }, 'WS UI session rejected: session_version mismatch (logged out or session invalidated elsewhere)');
      return null;
    }

    const effectiveRole = String(rows[0].role ?? '');
    const scope: NodeScope =
      effectiveRole === SUPER_ADMIN_ROLE
        ? { unrestricted: true }
        : {
            unrestricted: false,
            groups: rows
              .filter((r): r is typeof r & { group_id: string } => !!r.group_id)
              .map((r) => ({
                id: r.group_id,
                role: r.membership_role === GROUP_MEMBERSHIP_ROLE_VIEWER ? GROUP_MEMBERSHIP_ROLE_VIEWER : GROUP_MEMBERSHIP_ROLE_ADMIN,
              })),
          };

    return { jwt: jwtPayload, effectiveRole, scope };
  } catch (err) {
    logger.error({ err, userId: jwtPayload.id }, 'Failed to resolve WS UI session');
    return null;
  }
}
