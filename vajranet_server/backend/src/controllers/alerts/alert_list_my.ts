import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_ALERTS, ALERT_SEVERITY_SQL_CONDITIONS } from '../../consts';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertListMy');

/**
 * GET /alerts/list/my
 * Returns open alerts assigned to the currently authenticated user.
 *
 * Query params (same as /alerts/list):
 *  - rows, pageno
 *  - search
 *  - start_time, end_time
 *  - severity (critical|high|medium|low)
 */
export const alert_list_my = async (req: Request, res: Response, _next: NextFunction) => {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  try {
    const connections = dbSourceConnection();
    const entityManager = connections?.[1];
    if (!entityManager) {
      logger.error({ userId: jwtPayload.id }, 'Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const rows = Math.min(
      parseInt(String(req.query.rows ?? ''), 10) || PAGINATION_DEFAULT_ROWS,
      PAGINATION_MAX_ROWS_ALERTS,
    );
    const pageno = Math.max(parseInt(String(req.query.pageno ?? ''), 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    const search = ((req.query.search as string) ?? '').trim();
    const startTime = (req.query.start_time as string | undefined);
    const endTime = (req.query.end_time as string | undefined);
    const positiveRaw = ((req.query.positive as string | undefined) ?? '').toLowerCase().trim();
    const positiveFilter = positiveRaw === 'true_positive' || positiveRaw === 'false_positive' ? positiveRaw : null;

    const scope = await getUserNodeScope(jwtPayload.id);

    const conditions: string[] = [];
    const filterParams: unknown[] = [];
    let idx = 1;

    conditions.push(`a.is_open = $${idx}`);
    filterParams.push(true);
    idx++;

    conditions.push(`a.assignee_id = $${idx}`);
    filterParams.push(jwtPayload.id);
    idx++;

    if (search) {
      conditions.push(
        `(a.event_code ILIKE $${idx} OR a.alert_type ILIKE $${idx} OR n.hostname ILIKE $${idx} OR a.hostname ILIKE $${idx} OR n.os_name ILIKE $${idx} OR a.host_identifier ILIKE $${idx})`,
      );
      filterParams.push(`%${search}%`);
      idx++;
    }

    if (startTime) {
      const t = parseInt(startTime, 10);
      if (!isNaN(t)) {
        conditions.push(`a.unixTime >= $${idx}`);
        filterParams.push(t);
        idx++;
      }
    }

    if (endTime) {
      const t = parseInt(endTime, 10);
      if (!isNaN(t)) {
        conditions.push(`a.unixTime <= $${idx}`);
        filterParams.push(t);
        idx++;
      }
    }

    if (positiveFilter) {
      conditions.push(`a.mark_type = $${idx}`);
      filterParams.push(positiveFilter);
      idx++;
    }

    // Same scoping as /alerts/list — see the comment there for why a.group_id
    // is also checked (the Scan Scheduler's consolidated unmanaged-hosts alert
    // has no matching `nodes` row to scope via n.owner_group_id).
    if (!scope.unrestricted) {
      conditions.push(`(n.owner_group_id = ANY($${idx}::text[]) OR a.group_id = ANY($${idx}::text[]))`);
      filterParams.push(scopeGroupIds(scope));
      idx++;
    }

    const sev = ((req.query.severity as string) ?? '').toLowerCase().trim();
    const severitySql = ALERT_SEVERITY_SQL_CONDITIONS;

    const whereNoSeverity =
      conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const sevCondition = sev && severitySql[sev] ? severitySql[sev] : null;

    if (sevCondition) {
      conditions.push(sevCondition);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Plain equality, not LOWER(), so the join can use nodes_pkey.
    const joinClause = `FROM alerts a LEFT JOIN nodes n ON a.host_identifier = n.host_identifier`;

    // Run count + data + per-severity totals (excluding severity filter) in parallel.
    // Byte-for-byte the same count shape as alert_list.ts — see the invariants
    // documented there (the COALESCE(..., 0) guards, the low-cardinality and
    // deterministic-collation requirements on `severity`, and why hoisting the
    // normalisation into a lateral or CTE does not work). It buys nothing on this
    // endpoint, whose WHERE carries `assignee_id = <me>` and is served by
    // idx_alerts_assignee_open; it is here so the two files cannot drift.
    const totalExpr = sevCondition
      ? `COALESCE(SUM(a.c) FILTER (WHERE ${sevCondition}), 0)::int`
      : 'COALESCE(SUM(a.c), 0)::int';
    const countAndSevQuery = `
      SELECT
        ${totalExpr} AS total,
        COALESCE(SUM(a.c) FILTER (WHERE ${severitySql.critical}), 0)::int AS critical,
        COALESCE(SUM(a.c) FILTER (WHERE ${severitySql.high}), 0)::int AS high,
        COALESCE(SUM(a.c) FILTER (WHERE ${severitySql.medium}), 0)::int AS medium,
        COALESCE(SUM(a.c) FILTER (WHERE ${severitySql.low}), 0)::int AS low
      FROM (
        SELECT a.severity, COUNT(*) AS c
        ${joinClause}
        ${whereNoSeverity}
        GROUP BY a.severity
      ) a
    `;

    const [countSevResult, alerts] = await Promise.all([
      entityManager.query(countAndSevQuery, filterParams),
      entityManager.query(
        `SELECT
           a.id,
           a.host_identifier,
           COALESCE(n.hostname, a.hostname) AS hostname,
           COALESCE(n.os_name, a.os_name) AS os_name,
           a.unixTime,
           a.event_code,
           a.metadata::json AS metadata,
           a.is_alert,
           a.is_open,
           a.severity,
           a.alert_type,
           a.mark_type,
           a.assignee_id,
           a.assigned_at
         ${joinClause}
         ${where}
         ORDER BY COALESCE(a.assigned_at, TO_TIMESTAMP(NULLIF(a.unixTime::text, '')::double precision)) DESC, a.id DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...filterParams, rows, offset],
      ),
    ]);

    const total = parseInt(countSevResult?.[0]?.total ?? '0', 10);
    const sc = countSevResult?.[0] ?? {};
    const severity_counts = {
      critical: parseInt(String(sc.critical ?? '0'), 10),
      high: parseInt(String(sc.high ?? '0'), 10),
      medium: parseInt(String(sc.medium ?? '0'), 10),
      low: parseInt(String(sc.low ?? '0'), 10),
    };

    logger.debug(
      { userId: jwtPayload.id, count: alerts?.length ?? 0, total, page: pageno },
      'My alerts list retrieved',
    );
    return res.status(200).json({
      success: true,
      total,
      severity_counts,
      count: alerts?.length ?? 0,
      page: pageno,
      rows,
      alerts: alerts ?? [],
    });
  } catch (error) {
    logger.error({ err: error, userId: jwtPayload.id }, 'Failed to list alerts assigned to user');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

