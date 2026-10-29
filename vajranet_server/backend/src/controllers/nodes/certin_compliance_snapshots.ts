import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, scopeGroupIds, actableGroupIds } from '../../utils/nodeScope';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { AUDIT_ACTION_COMPLIANCE } from '../../orm/entities/audit/AuditTrail';
import { toFiniteNumberOrNull } from '../../utils/numeric';
import { getLogger } from '../../utils/logger';
import { COMPLIANCE_ORG_HISTORY_MAX_ROWS } from '../../consts/pagination';
import { COMPLIANCE_SNAPSHOT_DEFAULT_SOURCE } from '../../consts/database';

const logger = getLogger('nodes.certinComplianceSnapshots');

/** Percentage columns hold 0-100; anything outside that range is a malformed payload, not data. */
const COMPLIANCE_PERCENT_MIN = 0;
const COMPLIANCE_PERCENT_MAX = 100;

/** An optional numeric field is well-formed when it is absent/null or a finite number. */
function isOptionalFiniteNumber(value: unknown): boolean {
  return value === null || value === undefined || toFiniteNumberOrNull(value) !== null;
}

/** An optional percentage field is well-formed when it is absent/null or a finite 0-100 number. */
function isOptionalPercent(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  const percent = toFiniteNumberOrNull(value);
  return percent !== null && percent >= COMPLIANCE_PERCENT_MIN && percent <= COMPLIANCE_PERCENT_MAX;
}

/** An optional list field is well-formed when it is absent/null or an array. */
function isOptionalArray(value: unknown): boolean {
  return value === null || value === undefined || Array.isArray(value);
}

/**
 * Window in which a second org sweep for the same framework + scope counts as the
 * same fleet moment. Two operators (or two tabs) starting the fleet sweep seconds
 * apart used to produce two divergent evidence rows for one moment; inside this
 * window the later sweep is collapsed onto the row the first one wrote instead.
 */
const COMPLIANCE_SNAPSHOT_DEDUPE_WINDOW_SECONDS = 60;

/**
 * Stable advisory-lock key for one framework + owner scope. Group ids are sorted
 * so two callers whose membership rows came back in different orders still take
 * the same lock; unrestricted callers (owner_group_ids NULL, i.e. fleet-wide) all
 * share the '*' key.
 */
function snapshotScopeLockKey(ownerGroupIds: string[] | null): string {
  return `certin-org:${ownerGroupIds === null ? '*' : [...ownerGroupIds].sort().join(',')}`;
}

/**
 * GET /api/nodes/compliance/certin/history
 * Returns the newest certin compliance snapshots, capped at
 * COMPLIANCE_ORG_HISTORY_MAX_ROWS and scoped to the caller's node group(s). See
 * org_compliance_snapshot.ts for the scoping rationale: unrestricted callers see
 * everything including legacy rows, scoped callers never see legacy/fleet-wide rows.
 */
export async function certin_compliance_history(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error('Database connection not available while fetching certin compliance history');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    const scopeWhere = scope.unrestricted ? '' : 'WHERE owner_group_ids && $1::text[]';
    const params: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    // Deferred fetch: page the ids first, then join back for the wide columns.
    // control_pass_rates and the two node lists are multi-kB jsonb, and there is no
    // index that can supply `ORDER BY id DESC` under the owner_group_ids filter
    // (the only index on it is GIN, which cannot provide ordering), so the sort is
    // unavoidable — this keeps 8-byte ids in it instead of the jsonb payloads.
    // Same rows, same order as the previous single-statement form.
    const rows = await db.query(
      `WITH page AS (
         SELECT id
         FROM certin_historical_compliance
         ${scopeWhere}
         ORDER BY id DESC
         LIMIT ${COMPLIANCE_ORG_HISTORY_MAX_ROWS}
       )
       SELECT h.id, h.snapshot_at, h.total_nodes, h.windows_hosts, h.windows_with_results, h.fully_compliant_nodes,
              h.avg_compliance_percent, h.strong_count, h.moderate_count, h.needs_attention_count,
              h.control_pass_rates, h.source, h.fully_compliant_nodes_list, h.non_compliant_nodes_list, h.owner_group_ids
       FROM certin_historical_compliance h
       JOIN page ON page.id = h.id
       ORDER BY h.id DESC`,
      params,
    );

    logger.debug({ count: rows?.length ?? 0 }, 'Certin compliance history retrieved');

    return res.status(200).json({ success: true, data: rows ?? [] });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch certin compliance history');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}

/**
 * POST /api/nodes/compliance/certin/snapshot
 * Saves a new certin-level compliance snapshot to certin_historical_compliance.
 * Body: { snapshotAt, totalNodes, windowsHosts, windowsWithResults,
 *         avgCompliancePercent, strongCount, moderateCount, needsAttentionCount,
 *         controlPassRates, source }
 */
export async function certin_compliance_save_snapshot(req: Request, res: Response, _next: NextFunction) {
  try {
    // snapshotAt is deliberately not read from the body: it is stamped
    // server-side below, so a client-supplied value is discarded.
    const {
      totalNodes,
      windowsHosts,
      windowsWithResults,
      fullyCompliantNodes,
      avgCompliancePercent,
      strongCount,
      moderateCount,
      needsAttentionCount,
      controlPassRates,
      source,
      fullyCompliantNodesList,
      nonCompliantNodesList,
    } = req.body as Record<string, unknown>;

    if (!Array.isArray(controlPassRates)) {
      return res.status(400).json({ status: 'Error', message: 'controlPassRates is required' });
    }
    if (![totalNodes, windowsHosts, windowsWithResults, fullyCompliantNodes, strongCount, moderateCount, needsAttentionCount].every(isOptionalFiniteNumber)
      || !isOptionalPercent(avgCompliancePercent)
      || !isOptionalArray(fullyCompliantNodesList)
      || !isOptionalArray(nonCompliantNodesList)) {
      return res.status(400).json({ status: 'Error', message: 'Malformed compliance snapshot payload' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error('Database connection not available while saving certin compliance snapshot');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    // Attribute the write with the caller's act-level groups only: a Group Viewer
    // membership must not be able to stamp another group's compliance history.
    const ownerGroupIds = scope.unrestricted ? null : actableGroupIds(scope);
    if (ownerGroupIds !== null && ownerGroupIds.length === 0) {
      logger.warn({ user_id: jwtPayload?.id ?? null }, 'Certin compliance snapshot rejected: caller has no act-level group');
      return res.status(403).json({ status: 'Error', message: 'Forbidden' });
    }

    // windowsHosts/windowsWithResults are computed client-side and, until now, only
    // shape/range-checked, never cross-checked against reality — an authenticated but
    // buggy or stale client could persist a fabricated fleet size that then drives the
    // PDF and dashboard denominators indefinitely. This is a plausibility bound, not a
    // recomputation: it does not attempt to replicate the frontend's online/offline
    // eligibility filtering (too easy to drift out of sync with it), it only rejects
    // values that cannot possibly be true — more Windows hosts than the fleet actually
    // has, or more hosts-with-results than hosts claimed. Scoped to the caller's own
    // group(s) (ownerGroupIds), the same scope the row is about to be written under —
    // counting fleet-wide here would let a small group's snapshot validate against
    // the whole fleet's Windows count, a bound wide enough to defeat its own purpose.
    const realWindowsHostCount = await (async () => {
      const rows = ownerGroupIds === null
        ? await db.query(
          `SELECT COUNT(*)::int AS c FROM nodes WHERE LOWER(COALESCE(os_platform,'')) LIKE '%windows%' OR LOWER(COALESCE(os_name,'')) LIKE '%windows%'`,
        )
        : await db.query(
          `SELECT COUNT(*)::int AS c FROM nodes WHERE owner_group_id = ANY($1::text[]) AND (LOWER(COALESCE(os_platform,'')) LIKE '%windows%' OR LOWER(COALESCE(os_name,'')) LIKE '%windows%')`,
          [ownerGroupIds],
        );
      return Number(rows?.[0]?.c ?? 0);
    })();
    const claimedWindowsHosts = toFiniteNumberOrNull(windowsHosts);
    const claimedWindowsWithResults = toFiniteNumberOrNull(windowsWithResults);
    if ((claimedWindowsHosts !== null && claimedWindowsHosts > realWindowsHostCount)
      || (claimedWindowsWithResults !== null && claimedWindowsHosts !== null && claimedWindowsWithResults > claimedWindowsHosts)) {
      logger.warn(
        { claimedWindowsHosts, claimedWindowsWithResults, realWindowsHostCount, owner_group_ids: ownerGroupIds },
        'Rejected certin compliance snapshot: implausible windowsHosts/windowsWithResults',
      );
      return res.status(400).json({ status: 'Error', message: 'windowsHosts/windowsWithResults is implausible for the current fleet' });
    }

    // snapshot_at is stamped from the server clock and any client-supplied value
    // ignored: these rows are the point-in-time record behind the trend charts and
    // exported PDFs, so they must not be back-datable.
    const snapshotAt = Math.floor(Date.now() / 1000);

    // Two operators — or two tabs — can start the same fleet sweep at the same
    // moment; with no mutual exclusion both reached this INSERT and the framework
    // ended up with two divergent evidence rows for one fleet moment. The advisory
    // lock makes "look for a recent snapshot, then insert" atomic per framework +
    // scope, and being transaction-scoped it is released on commit or rollback.
    const snapshot = await db.transaction(async (manager) => {
      await manager.query('SELECT pg_advisory_xact_lock(hashtext($1))', [snapshotScopeLockKey(ownerGroupIds)]);

      // Set equality (@> together with <@), not array equality: the caller's group
      // ids arrive in whatever order the membership query returned them, and two
      // operators in the same group(s) must still collapse onto one row.
      const scopeMatch = ownerGroupIds === null
        ? 'owner_group_ids IS NULL'
        : 'owner_group_ids @> $2::text[] AND owner_group_ids <@ $2::text[]';
      const existing = await manager.query(
        `SELECT id, snapshot_at
           FROM certin_historical_compliance
          WHERE snapshot_at >= $1
            AND ${scopeMatch}
          ORDER BY snapshot_at DESC, id DESC
          LIMIT 1`,
        ownerGroupIds === null
          ? [snapshotAt - COMPLIANCE_SNAPSHOT_DEDUPE_WINDOW_SECONDS]
          : [snapshotAt - COMPLIANCE_SNAPSHOT_DEDUPE_WINDOW_SECONDS, ownerGroupIds],
      );
      if (existing?.[0]) {
        return { id: existing[0].id ?? null, deduplicated: true };
      }

      const inserted = await manager.query(
        `INSERT INTO certin_historical_compliance
           (snapshot_at, total_nodes, windows_hosts, windows_with_results, fully_compliant_nodes,
            avg_compliance_percent, strong_count, moderate_count, needs_attention_count,
            control_pass_rates, source, fully_compliant_nodes_list, non_compliant_nodes_list,
            owner_group_ids)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         RETURNING id`,
        [
          snapshotAt,
          toFiniteNumberOrNull(totalNodes),
          toFiniteNumberOrNull(windowsHosts),
          toFiniteNumberOrNull(windowsWithResults),
          toFiniteNumberOrNull(fullyCompliantNodes),
          toFiniteNumberOrNull(avgCompliancePercent),
          toFiniteNumberOrNull(strongCount),
          toFiniteNumberOrNull(moderateCount),
          toFiniteNumberOrNull(needsAttentionCount),
          JSON.stringify(controlPassRates),
          typeof source === 'string' ? source : COMPLIANCE_SNAPSHOT_DEFAULT_SOURCE,
          Array.isArray(fullyCompliantNodesList) ? JSON.stringify(fullyCompliantNodesList) : null,
          Array.isArray(nonCompliantNodesList) ? JSON.stringify(nonCompliantNodesList) : null,
          ownerGroupIds,
        ],
      );
      return { id: inserted?.[0]?.id ?? null, deduplicated: false };
    });

    try {
      await logAuditTrail({
        action: AUDIT_ACTION_COMPLIANCE,
        status: 'success',
        userId: jwtPayload?.id ?? null,
        email: jwtPayload?.email ?? null,
        details: {
          framework: 'certin-org',
          snapshot_id: snapshot.id,
          owner_group_ids: ownerGroupIds,
          source: 'org-snapshot',
          // The sweep ran, but it may have been collapsed onto an existing row for
          // the same scope rather than writing a new one — recorded so the trail
          // still shows who ran it without implying a second snapshot exists.
          deduplicated: snapshot.deduplicated,
        },
      });
    } catch (auditErr) {
      // The snapshot transaction has already committed at this point — distinguish
      // this from an actual snapshot-save failure so it isn't misread as the
      // INSERT failing.
      logger.error(
        { err: auditErr, snapshot_id: snapshot.id, deduplicated: snapshot.deduplicated },
        'Failed to record audit trail for certin compliance snapshot; the snapshot itself was already resolved',
      );
      throw auditErr;
    }

    logger.info(
      { snapshot_id: snapshot.id, deduplicated: snapshot.deduplicated },
      snapshot.deduplicated
        ? 'Certin compliance snapshot collapsed onto a concurrent snapshot for the same scope'
        : 'Certin compliance snapshot saved',
    );

    // 201 for a row this request created, 200 for one it was collapsed onto; the
    // id returned is the snapshot the caller's numbers are represented by either way.
    return res
      .status(snapshot.deduplicated ? 200 : 201)
      .json({ success: true, id: snapshot.id, deduplicated: snapshot.deduplicated });
  } catch (error) {
    logger.error({ err: error }, 'Failed to save certin compliance snapshot');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}
