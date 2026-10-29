import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { ACCESS_TOKEN_COOKIE } from '../../utils/cookieConfig';
import { JwtPayload } from '../../types/JwtPayload';
import { checkTokenBlacklist, validateSessionVersion, isMfaChallengeToken } from '../../middleware/checkJwt';
import { JWT_ALGORITHM } from '../../consts/auth';
import { SUPER_ADMIN_ROLE, GROUP_ADMIN_ROLE, VajraUser } from '../../orm/entities/users/Users';
import { getLogger } from '../../utils/logger';

const logger = getLogger('auth.validateGrafana');

/**
 * Reads the caller's role from the primary database instead of trusting the
 * copy inside the JWT. Same rule middleware/requireRole.ts follows: the token
 * carries the role held at login, so a demotion would otherwise keep Grafana
 * open for the rest of that token's lifetime. Returns null on any failure,
 * which the caller treats as a denial.
 */
async function resolveCurrentRole(userId: number): Promise<string | null> {
  try {
    const { dbSourceConnection } = await import('../../index');
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length === 0) {
      logger.warn({ userId }, 'Cannot resolve role for Grafana auth validation: DB not available');
      return null;
    }
    const user = await dbSources[0].getRepository(VajraUser).findOne({
      where: { id: userId },
      select: ['id', 'role'],
    });
    return (user as { role?: string } | null)?.role ?? null;
  } catch (err) {
    logger.warn({ err, userId }, 'Failed to resolve role for Grafana auth validation');
    return null;
  }
}

/**
 * Gatekeeper for the entire /grafana/ reverse-proxy path (nginx auth_request
 * -> /api/auth/validate). A cryptographically valid JWT is not enough here:
 * logout blacklists the token and logout-all-devices/suspension bump
 * session_version, and both must be honored or a revoked session keeps a
 * live X-WEBAUTH-USER identity into Grafana for the rest of the token's
 * lifetime. Reuses the same checks checkAccessJwt applies to every other
 * authenticated route instead of only calling jwt.verify().
 *
 * On top of those, access is restricted to Super Administrators and Group
 * Admins; the dashboards scope themselves to the viewer's groups from the
 * X-User-Email this function returns. This is the only gate on /grafana/ —
 * nginx delegates the whole path here, so anything not rejected in this
 * function is served.
 */
export const validateGrafana = async (req: Request, res: Response) => {
  try {
    const token = req.cookies?.[ACCESS_TOKEN_COOKIE];
    if (!token) {
      logger.debug('Grafana auth validation rejected: no access token cookie present');
      return res.status(401).send('Unauthorized');
    }

    if (await checkTokenBlacklist(token)) {
      logger.warn('Grafana auth validation rejected: access token is blacklisted');
      return res.status(401).send('Unauthorized');
    }

    const decoded = jwt.verify(token, process.env.ACCESS_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as JwtPayload;

    // Reject the interim MFA-challenge token (see isMfaChallengeToken in
    // middleware/checkJwt.ts): it verifies against this same secret but
    // represents a password-only session, and must not grant Grafana access.
    if (isMfaChallengeToken(decoded)) {
      logger.warn({ userId: decoded.id }, 'Grafana auth validation rejected: MFA verification not completed');
      return res.status(401).send('Unauthorized');
    }

    // Both checks are required and neither depends on the other, so they are
    // issued together and cost one round trip rather than two.
    const [isSessionValid, currentRole] = await Promise.all([
      validateSessionVersion(decoded.id, decoded.session_version, decoded.sessionId),
      resolveCurrentRole(decoded.id),
    ]);

    if (!isSessionValid) {
      logger.warn({ userId: decoded.id, sessionId: decoded.sessionId }, 'Grafana auth validation rejected: session no longer valid');
      return res.status(401).send('Unauthorized');
    }

    // Super Administrator and Group Admin. A Group Admin sees only their own
    // groups' nodes: every panel and template variable in the three provisioned
    // dashboards filters on grafana_group_visible('${__user.email}',
    // owner_group_id), which is true for a Super Administrator or for a node
    // owned by a group the viewing email belongs to (setupGrafanaGroupScoping
    // in orm/config/ormconfig-setup.ts).
    //
    // Two things this gate depends on, both of which must hold:
    //
    //  - That function and its postgres_fdw bridge must actually be provisioned
    //    on the fleet DB. Its absence is not fail-closed — the panels error
    //    rather than silently widening, but nothing here can detect it.
    //  - A Group Admin must never hold Grafana Editor. Editor can rewrite panel
    //    SQL and drop the filter, and can reach Explore, which is arbitrary SQL
    //    as grafana_reader. See the role header below.
    //
    // Viewers are excluded: the dashboards are an administrative reporting
    // surface, matching requireAdmin's split everywhere else.
    if (currentRole !== SUPER_ADMIN_ROLE && currentRole !== GROUP_ADMIN_ROLE) {
      logger.warn({ userId: decoded.id, role: currentRole }, 'Grafana auth validation rejected: insufficient role');
      return res.status(403).send('Forbidden');
    }

    res.setHeader('X-User-Email', decoded.email);
    res.setHeader('X-User-Name', decoded.name || decoded.email);
    // Group Admin maps to Viewer, and that is load-bearing rather than
    // cosmetic: their scoping is a filter written into each panel's SQL, so
    // Editor — which can rewrite that SQL, and can open Explore to run
    // arbitrary queries as grafana_reader — would hand them the whole fleet.
    // Editor rather than Admin for a Super Administrator keeps Grafana's own
    // org-admin surface (datasources, plugins, org users) out of reach.
    //
    // Grafana honours this header only if [auth.proxy] in grafana.ini lists it
    // under `headers`. It currently does not, so every proxied user is assigned
    // [users] auto_assign_org_role (Viewer) regardless — which is why admitting
    // Group Admins is safe today even though this header is ignored. If that
    // line is ever added, this ternary is what keeps them out of Editor.
    res.setHeader('X-User-Role', currentRole === SUPER_ADMIN_ROLE ? 'Editor' : 'Viewer');

    logger.debug({ userId: decoded.id }, 'Grafana auth validation succeeded');

    return res.status(200).send('OK');
  } catch (err) {
    logger.warn({ err }, 'Grafana auth validation rejected request');
    return res.status(401).send('Unauthorized');
  }
};
