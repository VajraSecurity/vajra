import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope, assertCanActOnHost } from '../../utils/nodeScope';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { AUDIT_ACTION_COMPLIANCE } from '../../orm/entities/audit/AuditTrail';
import { getLogger } from '../../utils/logger';
import { NODE_COMPLIANCE_HISTORY_MAX_ROWS } from '../../consts/pagination';

const logger = getLogger('nodes.certinCompliance');

/**
 * Shape check for a node compliance payload before it is persisted: an array of
 * plain objects. Mirrors the websocket compliance path, which validates the rows
 * it was handed rather than storing whatever arrived.
 */
function isComplianceRowArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.every((row) => typeof row === 'object' && row !== null && !Array.isArray(row));
}

/**
 * GET /api/nodes/compliance/certin/latest/:host_identifier
 *
 * Returns the most recent certin_compliance_results row for the given node. Note the
 * table is certin_compliance_results, not the unrelated `compliance_results` table.
 */
export async function node_certin_compliance_latest(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error({ host_identifier }, 'Database connection not initialized while fetching latest certin compliance');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const scope = (req as any).jwtPayload?.id
      ? await getUserNodeScope((req as any).jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Latest certin compliance request rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    // Ordered by unixtime (not id) so the existing (host_identifier, unixtime)
    // index can serve the ordering instead of a backward primary-key scan with a
    // host_identifier discard filter. unixtime is stamped from the server clock in
    // the one INSERT below that also generates id — this controller is the only
    // writer of this table — so the two sequences agree and `id DESC` is kept as
    // the tiebreak, leaving the row order identical to the previous `ORDER BY id DESC`.
    const rows = await db.query(
      `SELECT id, host_identifier, unixtime, compliance_data
       FROM certin_compliance_results
       WHERE host_identifier = $1
       ORDER BY unixtime DESC, id DESC
       LIMIT 1`,
      [host_identifier],
    );

    logger.debug({ host_identifier, found: !!rows?.[0] }, 'Latest certin compliance retrieved');

    return res.status(200).json({ success: true, data: rows?.[0] ?? null });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to fetch latest certin compliance');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}

/**
 * GET /api/nodes/compliance/certin/history/:host_identifier
 *
 * Returns the newest certin_compliance_results rows for the given node, capped at
 * NODE_COMPLIANCE_HISTORY_MAX_ROWS, to build the historical trend chart.
 */
export async function node_certin_compliance_history(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ status: 'Error', message: 'host_identifier is required' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error({ host_identifier }, 'Database connection not initialized while fetching certin compliance history');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    const scope = (req as any).jwtPayload?.id
      ? await getUserNodeScope((req as any).jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Certin compliance history request rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    // Ordered by unixtime (not id) so the existing (host_identifier, unixtime)
    // index can serve the ordering instead of a backward primary-key scan with a
    // host_identifier discard filter. unixtime is stamped from the server clock in
    // the one INSERT below that also generates id — this controller is the only
    // writer of this table — so the two sequences agree and `id DESC` is kept as
    // the tiebreak, leaving the row order identical to the previous `ORDER BY id DESC`.
    const rows = await db.query(
      `SELECT id, host_identifier, unixtime, compliance_data
       FROM certin_compliance_results
       WHERE host_identifier = $1
       ORDER BY unixtime DESC, id DESC
       LIMIT ${NODE_COMPLIANCE_HISTORY_MAX_ROWS}`,
      [host_identifier],
    );

    logger.debug({ host_identifier, count: rows?.length ?? 0 }, 'Certin compliance history retrieved');

    return res.status(200).json({ success: true, data: rows ?? [] });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to fetch certin compliance history');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}

// POST /api/nodes/compliance/certin/node-snapshot

export async function node_certin_compliance_save_snapshot(req: Request, res: Response, _next: NextFunction) {
  try {
    const hostIdentifier = req.params.host_identifier;
    // unixtime is deliberately not read from the body: it is stamped server-side
    // below, so a client-supplied value is discarded rather than persisted.
    const {
      complianceData,
    } = req.body as Record<string, unknown>;

    if (!hostIdentifier || !isComplianceRowArray(complianceData)) {
      return res.status(400).json({ status: 'Error', message: 'hostIdentifier and a well-formed complianceData array are required' });
    }

    const scope = (req as any).jwtPayload?.id
      ? await getUserNodeScope((req as any).jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertCanActOnHost(scope, hostIdentifier))) {
      logger.warn({ host_identifier: hostIdentifier }, 'Certin compliance snapshot save rejected: host not in caller scope');
      return res.status(404).json({ status: 'Error', message: 'Node not found' });
    }

    const dataSources = dbSourceConnection();
    const db = dataSources?.[1];
    if (!db) {
      logger.error({ host_identifier: hostIdentifier }, 'Database connection not initialized while saving certin compliance snapshot');
      return res.status(500).json({ status: 'Error', message: 'Database not available' });
    }

    // CERT-In compliance scope is deliberately Windows-only (CMPL-DB-06 in reports.ts;
    // same os_platform/os_name predicate as the read-path LATERAL there, and the
    // client-side filters in Compliance/index.tsx / NodesViewCertInCompliance.tsx).
    // assertCanActOnHost above does not enforce this — for an unrestricted caller it
    // does not even confirm the host exists in `nodes` — so nothing before this point
    // stopped a non-Windows (or nonexistent) host_identifier from reaching the INSERT.
    const nodeRows = await db.query(
      `SELECT os_platform, os_name FROM nodes WHERE host_identifier = $1 LIMIT 1`,
      [hostIdentifier],
    );
    const nodeRow = nodeRows?.[0] as { os_platform?: string | null; os_name?: string | null } | undefined;
    const isWindowsHost = !!nodeRow
      && (String(nodeRow.os_platform ?? '').toLowerCase().includes('windows')
        || String(nodeRow.os_name ?? '').toLowerCase().includes('windows'));
    if (!isWindowsHost) {
      logger.warn({ host_identifier: hostIdentifier }, 'Certin compliance snapshot rejected: no Windows node found for this host_identifier');
      return res.status(400).json({ status: 'Error', message: 'Certin compliance is Windows-only: no Windows node found for this host_identifier' });
    }

    // Compliance rows are regulatory evidence, so the time on them is the server's
    // clock at insert, never a time the caller chose — same stamping as the
    // websocket compliance path.
    const unixtime = Math.floor(Date.now() / 1000);

    await db.query(
      `INSERT INTO certin_compliance_results (host_identifier, unixtime, compliance_data)
       VALUES ($1, $2, $3)`,
      [hostIdentifier, unixtime, JSON.stringify(complianceData)],
    );

    try {
      await logAuditTrail({
        action: AUDIT_ACTION_COMPLIANCE,
        status: 'success',
        userId: (req as any).jwtPayload?.id ?? null,
        email: (req as any).jwtPayload?.email ?? null,
        details: { framework: 'certin', host_identifier: hostIdentifier, source: 'node-snapshot' },
      });
    } catch (auditErr) {
      // Row is already committed at this point — distinguish this from an
      // actual snapshot-save failure so it isn't misread as the INSERT failing.
      logger.error({ err: auditErr, host_identifier: hostIdentifier }, 'Failed to record audit trail for certin compliance snapshot; snapshot itself was already saved');
      throw auditErr;
    }

    logger.info({ host_identifier: hostIdentifier }, 'Certin compliance snapshot saved');

    return res.status(200).json({ success: true });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to save certin compliance snapshot');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
}