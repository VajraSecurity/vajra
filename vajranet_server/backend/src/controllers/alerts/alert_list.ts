import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_ALERTS, ALERT_SEVERITY_SQL_CONDITIONS } from '../../consts';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('alerts.alertList');

/**
 * GET /alerts/list
 * Paginated alert list plus per-severity totals for the current filter set.
 *
 * Query params: rows, pageno, search, is_open, start_time, end_time,
 * assignee (assigned|unassigned), positive (true_positive|false_positive),
 * severity (critical|high|medium|low).
 *
 * Non-Super-Admin callers are restricted to alerts within their group scope;
 * see the scope clause below for what that includes.
 */
export async function alert_list(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const entityManager = dataSources?.[1];

    if (!entityManager) {
      logger.error('Database connection not initialized');
      return res.status(500).json({ status: 'Error', message: 'Database connection not initialized' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };


    const rows   = Math.min(parseInt(req.query.rows   as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_ALERTS);
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    const search    = ((req.query.search     as string) ?? '').trim();
    const isOpenRaw = (req.query.is_open    as string | undefined);
    const startTime = (req.query.start_time as string | undefined);
    const endTime   = (req.query.end_time   as string | undefined);
    const assigneeRaw = ((req.query.assignee as string | undefined) ?? '').toLowerCase().trim();
    const positiveRaw = ((req.query.positive as string | undefined) ?? '').toLowerCase().trim();
    const positiveFilter = positiveRaw === 'true_positive' || positiveRaw === 'false_positive' ? positiveRaw : null;

    const conditions: string[] = [];
    const filterParams: unknown[] = [];
    let idx = 1;

    if (search) {
      // Both n.hostname and a.hostname are searched so a host renamed since the
      // alert was raised is still findable under either name.
      conditions.push(
        `(a.event_code ILIKE $${idx} OR a.alert_type ILIKE $${idx} OR n.hostname ILIKE $${idx} OR a.hostname ILIKE $${idx} OR n.os_name ILIKE $${idx} OR a.host_identifier ILIKE $${idx})`
      );
      filterParams.push(`%${search}%`);
      idx++;
    }

    if (isOpenRaw === 'true' || isOpenRaw === 'false') {
      conditions.push(`a.is_open = $${idx}`);
      filterParams.push(isOpenRaw === 'true');
      idx++;
    }

    if (startTime) {
      const t = parseInt(startTime, 10);
      if (!isNaN(t)) { conditions.push(`a.unixTime >= $${idx}`); filterParams.push(t); idx++; }
    }

    if (endTime) {
      const t = parseInt(endTime, 10);
      if (!isNaN(t)) { conditions.push(`a.unixTime <= $${idx}`); filterParams.push(t); idx++; }
    }

    if (assigneeRaw === 'assigned') {
      conditions.push(`COALESCE(a.assignee_id, 0) > 0`);
    } else if (assigneeRaw === 'unassigned') {
      conditions.push(`COALESCE(a.assignee_id, 0) = 0`);
    }

    if (positiveFilter) {
      conditions.push(`a.mark_type = $${idx}`);
      filterParams.push(positiveFilter);
      idx++;
    }

    // Scoped (non-Super-Admin) callers only see alerts on nodes in their group(s),
    // plus alert types that carry their own group_id directly (currently just the
    // Scan Scheduler's consolidated "Unmanaged Hosts Detected" alert, whose
    // synthetic host_identifier has no `nodes` row to inherit a group from; see
    // createRunAlert in scanSchedulerService.ts). Fail closed: alerts on ungrouped
    // nodes and group_id-less alerts are hidden from scoped callers either way.
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
    //
    // The count aggregates FIRST and normalises AFTER: it groups by the raw
    // `a.severity` and evaluates the severity expressions over the few resulting
    // groups rather than over every row. The obvious alternative — hoisting the
    // normalisation into a lateral or a CTE — does not work, because the planner
    // flattens the subquery back into the parent's target list and re-inlines
    // every copy.
    //
    // The form depends on all of the following; none of them are optional:
    //  - The COALESCE(..., 0) wrappers are load-bearing, not tidiness: SUM over
    //    zero groups is NULL where a bare COUNT(*) is 0. Do not simplify them away.
    //  - `severity` must stay low-cardinality. If it ever became free text the
    //    group-by would degenerate and this would be slower than COUNT(*) FILTER.
    //  - The column's collation must stay deterministic; a non-deterministic one
    //    could merge byte-distinct values the severity predicates tell apart.
    //  - The subquery is aliased `a` and exposes a `severity` column, so
    //    ALERT_SEVERITY_SQL_CONDITIONS is pasted in verbatim and cannot drift from
    //    the severity filter applied to the data query.
    // alert_list_my.ts carries the same block — keep the two in lockstep.
    //
    // The LEFT JOIN stays even though nothing here references n.*: nodes_pkey is on
    // nodes.host_identifier so Postgres elides the join itself, and keeping it
    // means one code path instead of two.
    //
    // Serving `severity` from a narrow index does not pay off while `alerts` sits
    // below the all-visible ratio an index-only scan needs to beat a seq scan; see
    // backend/migrations/017_add_alerts_severity_summary_index.sql, written but
    // deliberately not applied.
    //
    // `total` is computed over the relation whereNoSeverity has already narrowed,
    // so only the severity predicate is left to apply on top of it.
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
           a.assignee_id
         ${joinClause}
         ${where}
         ORDER BY a.id DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...filterParams, rows, offset]
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

    logger.debug({ count: alerts?.length ?? 0, total, page: pageno }, 'Alerts list retrieved');
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
    logger.error({ err: error, query: req.query, userId: (req as any).jwtPayload?.id }, 'Failed to list alerts');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}