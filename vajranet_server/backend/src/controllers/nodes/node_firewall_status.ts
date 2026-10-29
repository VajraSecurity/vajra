import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodes.firewallStatus');

/**
 * GET /api/nodes/firewall-status
 *
 * Returns the latest firewall status for all Linux nodes.
 * Populated by firewall_status_push messages from the agent (ufw / firewalld).
 */
export async function node_firewall_status(req: Request, res: Response, _next: NextFunction) {
  try {
    const ds = dbSourceConnection();
    const db = ds?.[1];
    if (!db) {
      logger.error('Database connection not initialised while fetching firewall status');
      return res.status(500).json({ status: 'Error', message: 'Database not initialised' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    const rows = scope.unrestricted
      ? await db.query(
          `SELECT host_identifier, manager, active, enabled_on_boot,
                  default_policy_in, default_policy_out, zone_or_profile,
                  installed, distro, init_system, details,
                  EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at
           FROM firewall_status`,
        )
      : await db.query(
          `SELECT fs.host_identifier, fs.manager, fs.active, fs.enabled_on_boot,
                  fs.default_policy_in, fs.default_policy_out, fs.zone_or_profile,
                  fs.installed, fs.distro, fs.init_system, fs.details,
                  EXTRACT(EPOCH FROM fs.updated_at)::bigint AS updated_at
           FROM firewall_status fs
           JOIN nodes n ON n.host_identifier = fs.host_identifier
           WHERE n.owner_group_id = ANY($1::text[])`,
          [scopeGroupIds(scope)],
        );

    logger.debug({ count: Array.isArray(rows) ? rows.length : 0 }, 'Firewall status retrieved');

    return res.status(200).json({
      status: 'Success',
      data: Array.isArray(rows)
        ? rows.map((r: any) => ({
            host_identifier:    String(r.host_identifier),
            manager:            String(r.manager ?? 'none'),
            active:             Boolean(r.active),
            enabled_on_boot:    Boolean(r.enabled_on_boot),
            default_policy_in:  String(r.default_policy_in  ?? 'unknown'),
            default_policy_out: String(r.default_policy_out ?? 'unknown'),
            zone_or_profile:    r.zone_or_profile ?? null,
            installed:          Array.isArray(r.installed) ? r.installed : [],
            distro:             r.distro ?? null,
            init_system:        r.init_system ?? null,
            details:            r.details ?? null,
            updated_at:         r.updated_at != null ? Number(r.updated_at) : null,
          }))
        : [],
    });
  } catch (err) {
    logger.error({ err }, 'Failed to fetch firewall status');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
