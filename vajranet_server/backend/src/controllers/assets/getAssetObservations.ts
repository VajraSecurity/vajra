import { Request, Response, NextFunction } from 'express';
import { DataSource } from 'typeorm';
import { dbSourceConnection } from '../../index';
import {
  PAGINATION_DEFAULT_ROWS,
  PAGINATION_MAX_ROWS_NODES,
} from '../../consts';
import { getUserNodeScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import type {
  AssetObservationDto,
  MatchReason,
  ObservationSource,
  ObservedAttrs,
} from '../../types/assetIdentity';
import { isValidAssetUuid, loadScopedAssetRow } from './getAsset';
import { executeGmpCommand } from '../../utils/openvasClient';
import { computeSeverityCountsForHost, extractInnerReport } from '../../services/assetIdentity/openvasFeeder';
import { EXTERNAL_API_TIMEOUT_MS } from '../../consts/timeout';

const logger = getLogger('controllers.assets.getAssetObservations');

/**
 * Backfill cap per request — this feature's own severity-history graph needs
 * every observation to carry `attrs.extra.severityCounts`, but that field was
 * only added going forward (SPEC.md, 2026-09-08): observations from before
 * this change have no severity data recorded. Rather than a one-off migration
 * script re-fetching every historical report from GVM, this mirrors the exact
 * backfill idiom controllers/network/nmapController.ts already uses for
 * chart_data — compute what's missing on read, persist it, never block the
 * response on it. The one difference from that precedent: nmap's backfill
 * only reads already-local DB rows, while this one calls out to GVM, so it is
 * capped tightly (a handful of reports per page view, not the whole page) and
 * never awaited before responding.
 */
const MAX_SEVERITY_BACKFILL_PER_REQUEST = 5;

/**
 * Fire-and-forget: re-fetches each listed report from GVM, computes that
 * host's severity counts, and writes them into the observation's existing
 * `attrs.extra`. Never awaited by the caller — a slow or unreachable GVM must
 * not slow down or fail the observations list, which is the actual product
 * here; the severity graph is a nice-to-have that fills in on a later view.
 */
function backfillSeverityCounts(
  fleetDb: DataSource,
  ownerGroupId: string | null,
  rows: { id: string; ip: string; reportId: string; attrs: ObservedAttrs }[],
): void {
  if (rows.length === 0) return;
  void (async () => {
    for (const row of rows) {
      try {
        const reportResult = await executeGmpCommand(
          ownerGroupId,
          'get_report',
          undefined,
          EXTERNAL_API_TIMEOUT_MS,
          { report_id: row.reportId, ignore_pagination: '1', details: '1' },
        );
        const inner = extractInnerReport(reportResult);
        if (!inner) continue;
        const severityCounts = computeSeverityCountsForHost(inner, row.ip);
        const nextAttrs: ObservedAttrs = {
          ...row.attrs,
          extra: { ...(row.attrs.extra ?? {}), severityCounts },
        };
        await fleetDb.query('UPDATE asset_observations SET attrs = $2::jsonb WHERE id = $1::bigint', [
          row.id,
          JSON.stringify(nextAttrs),
        ]);
      } catch (err) {
        // Expected and non-fatal: the report may have since been deleted from
        // GVM, the OpenVAS config may be unreachable, or the group may no
        // longer have one. Skip and try again on a later view.
        logger.debug({ err, observationId: row.id }, 'Severity-count backfill skipped for one observation');
      }
    }
  })();
}

interface ObservationRow {
  id: string;
  asset_uuid: string | null;
  source: ObservationSource;
  source_ref: string | null;
  observed_at: Date;
  attrs: ObservedAttrs | null;
  match_score: number | null;
  match_reason: MatchReason | null;
}

/**
 * GET /api/assets/:assetUuid/observations — the per-asset timeline: every scan
 * that ever saw this machine ("scan 1, scan 2, ..."), newest first, with the
 * raw attributes it reported and the full scoring explanation for why the
 * matcher attached it here.
 *
 * Scope is enforced on the PARENT asset, not on the observation rows: an
 * observation carries no group of its own, and asset_observations.asset_uuid is
 * never rewritten (a merge only moves assets.merged_into), so the asset row is
 * the only authority on who may read this timeline.
 */
export async function getAssetObservations(req: Request, res: Response, _next: NextFunction) {
  try {
    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.error('Fleet database not available while fetching asset observations');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const jwtPayload = (req as any).jwtPayload;
    if (!jwtPayload?.id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const assetUuid = req.params.assetUuid;
    if (!isValidAssetUuid(assetUuid)) {
      return res.status(400).json({ success: false, message: 'Invalid asset id' });
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    const baseRow = await loadScopedAssetRow(fleetDb, scope, assetUuid);
    if (!baseRow) {
      logger.warn({ assetUuid }, 'Asset observations rejected: not found or out of scope for caller');
      return res.status(404).json({ success: false, message: 'Asset not found' });
    }

    const rows = Math.max(
      1,
      Math.min(parseInt(req.query.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_NODES),
    );
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    // (asset_uuid, observed_at) is idx_asset_obs_asset_observed, so this is an
    // index scan in the ORDER BY's own direction — no sort of the whole table.
    const observationRows: (ObservationRow & { total_count: string })[] = await fleetDb.query(
      `
      SELECT o.id,
             o.asset_uuid,
             o.source,
             o.source_ref,
             o.observed_at,
             o.attrs,
             o.match_score,
             o.match_reason,
             COUNT(*) OVER () AS total_count
      FROM asset_observations o
      WHERE o.asset_uuid = $3::uuid
      ORDER BY o.observed_at DESC, o.id DESC
      LIMIT $1 OFFSET $2
    `,
      [rows, offset, assetUuid],
    );

    const total = observationRows.length > 0 ? Number(observationRows[0].total_count) : 0;

    // Fire-and-forget backfill for the severity-history graph — see the
    // comment on backfillSeverityCounts above. Only this page's rows are
    // candidates, and it is capped besides, so a large `rows=` request cannot
    // turn into a burst of GVM calls.
    const backfillCandidates: { id: string; ip: string; reportId: string; attrs: ObservedAttrs }[] = [];
    for (const row of observationRows) {
      if (backfillCandidates.length >= MAX_SEVERITY_BACKFILL_PER_REQUEST) break;
      if (row.source !== 'openvas' || !row.attrs) continue;
      const extra = row.attrs.extra as Record<string, unknown> | undefined;
      const reportId = typeof extra?.reportId === 'string' ? extra.reportId : null;
      if (!reportId || extra?.severityCounts !== undefined) continue;
      const ip = row.attrs.ips?.[0] ?? row.source_ref?.split(':').pop() ?? null;
      if (!ip) continue;
      backfillCandidates.push({ id: String(row.id), ip, reportId, attrs: row.attrs });
    }
    backfillSeverityCounts(fleetDb, baseRow.owner_group_id ?? null, backfillCandidates);

    const data: AssetObservationDto[] = observationRows.map((row) => ({
      // bigserial arrives from node-postgres as a string; the DTO keeps it a
      // string deliberately so a large id cannot lose precision in JSON.
      id: String(row.id),
      source: row.source,
      source_ref: row.source_ref,
      observed_at: new Date(row.observed_at).toISOString(),
      // attrs and match_reason are nullable in the table (the matcher may write
      // an audit row with neither), so both are defaulted rather than trusted.
      attrs: row.attrs ?? {},
      match_score: Number(row.match_score ?? 0),
      match_reason: row.match_reason as MatchReason,
    }));

    logger.debug({ assetUuid, count: data.length, total, page: pageno }, 'Asset observations retrieved');
    return res.status(200).json({
      success: true,
      total,
      count: data.length,
      page: pageno,
      rows,
      data,
    });
  } catch (err) {
    logger.error({ err }, 'Failed to fetch asset observations');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
