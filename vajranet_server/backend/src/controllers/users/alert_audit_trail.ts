import { Request, Response, NextFunction } from 'express';
import { Brackets } from 'typeorm';
import { JwtPayload } from '../../types/JwtPayload';
import { AuditTrail, AuditTrailAction } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';
import { PAGINATION_MAX_ROWS_ADMIN_ACTIVITY, PAGINATION_DEFAULT_ROWS_AUDIT } from '../../consts/pagination';
import { escapeIlikeSearchTerm } from '../../utils/sanitization';

const logger = getLogger('users.alertAuditTrail');

/**
 * GET /users/audit-trail/alerts
 * Returns only alert-related audit trail entries:
 *  - ALERT_STATUS_UPDATE (open/close)
 *  - ALERT_ASSIGN_UPDATE (assign/reassign)
 *
 * Query: page, limit, search (optional), sort_by (created_at|action|status), order (asc|desc)
 */
export const alert_audit_trail_list = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  const page = Math.max(1, parseInt(String(req.query.page), 10) || 1);
  const limit = Math.min(PAGINATION_MAX_ROWS_ADMIN_ACTIVITY, Math.max(1, parseInt(String(req.query.limit), 10) || PAGINATION_DEFAULT_ROWS_AUDIT));
  const offset = (page - 1) * limit;
  const allUsers = req.query.all_users === 'true';

  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  const sortBy =
    req.query.sort_by === 'action' || req.query.sort_by === 'status' ? (req.query.sort_by as string) : 'created_at';
  const orderDir = req.query.order === 'asc' || req.query.order === 'desc' ? req.query.order.toUpperCase() : 'DESC';

  const alertActions: AuditTrailAction[] = ['ALERT_STATUS_UPDATE', 'ALERT_ASSIGN_UPDATE', 'ALERT_MARK_UPDATE'];

  try {
    const { dbSourceConnection } = await import('../../index');
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ userId: jwtPayload.id }, 'Database connection not established for alert audit trail listing');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const repo = primaryDataSource.getRepository(AuditTrail);

    const orderColumn =
      sortBy === 'created_at' ? 'trail.createdAt' : sortBy === 'action' ? 'trail.action' : 'trail.status';

    const qb = repo
      .createQueryBuilder('trail')
      .leftJoinAndSelect('trail.user', 'user')
      .where('trail.action IN (:...actions)', { actions: alertActions })
      .orderBy(orderColumn, orderDir as 'ASC' | 'DESC')
      .skip(offset)
      .take(limit);

    if (!allUsers) {
      qb.andWhere('trail.userId = :userId', { userId: jwtPayload.id });
    }

    if (search.length > 0) {
      const searchPattern = `%${escapeIlikeSearchTerm(search)}%`;
      qb.andWhere(
        new Brackets((sub) => {
          sub.where('user.name ILIKE :search', { search: searchPattern });
          sub.orWhere('user.email ILIKE :search', { search: searchPattern });
          sub.orWhere('trail.email ILIKE :search', { search: searchPattern });
        }),
      );
    }

    const [logs, total] = await qb.getManyAndCount();

    // Backfill missing hostnames in older alert audit entries.
    // Some alert records were stored with only `host_identifier` (no `hostname`),
    // so the UI can't render the "Host" column for audit-trail drawers.
    try {
      const hostIdentifiersToEnrich = new Set<string>();
      for (const l of logs) {
        const d: any = l.details;
        const alerts = Array.isArray(d?.alerts) ? d.alerts : [];
        for (const a of alerts) {
          const hid = (a as any)?.host_identifier;
          if (hid == null) continue;
          hostIdentifiersToEnrich.add(String(hid));
        }
      }

      const fleetDb = dbSources?.[1];
      if (hostIdentifiersToEnrich.size > 0 && fleetDb) {
        const lowerIds = Array.from(hostIdentifiersToEnrich).map((s) => s.toLowerCase());
        const nodeRows: Array<{ host_identifier: any; hostname: any }> = await fleetDb.query(
          `SELECT host_identifier, hostname
           FROM nodes
           WHERE LOWER(host_identifier::text) = ANY($1)`,
          [lowerIds],
        );

        const hostnameByLower = new Map<string, string>();
        for (const r of nodeRows ?? []) {
          const hid = r?.host_identifier;
          const hn = r?.hostname;
          if (hid == null || hn == null) continue;
          if (typeof hn !== 'string' || !hn.trim()) continue;
          hostnameByLower.set(String(hid).toLowerCase(), hn);
        }

        for (const l of logs) {
          const d: any = l.details;
          if (!d || typeof d !== 'object') continue;

          // Fill hostname inside alerts array
          if (Array.isArray(d.alerts)) {
            for (const a of d.alerts) {
              const hid = (a as any)?.host_identifier;
              const hn = (a as any)?.hostname;
              const hnMissing = hn == null || (typeof hn === 'string' && !hn.trim());
              if (hnMissing && hid != null) {
                const mapped = hostnameByLower.get(String(hid).toLowerCase());
                if (mapped) (a as any).hostname = mapped;
              }
            }
          }

          // Also fill root-level hostname if present in payload shape
          const rootHn = d.hostname;
          const rootHid = d.host_identifier;
          const rootHnMissing = rootHn == null || (typeof rootHn === 'string' && !rootHn.trim());
          if (rootHnMissing && rootHid != null) {
            const mapped = hostnameByLower.get(String(rootHid).toLowerCase());
            if (mapped) d.hostname = mapped;
          }
        }
      }
    } catch (err) {
      logger.warn({ err, userId: jwtPayload.id, page }, 'Failed to backfill hostnames for alert audit trail entries');
      // Best-effort: don't break audit trail listing if backfill fails.
    }

    logger.debug({ count: logs.length, page }, 'Alert audit trail listed');

    return res.status(200).json({
      status: 'Success',
      data: {
        logs: logs.map((l) => ({
          id: l.id,
          action: l.action,
          status: l.status,
          created_at: l.createdAt,
          user_name: l.user?.name ?? null,
          user_email: l.user?.email ?? l.email ?? null,
          ip_address: l.ipAddress ?? null,
          details: l.details ?? null,
        })),
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, userId: jwtPayload.id, page }, 'Failed to list alert audit trail');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

