import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import {
  ERROR_MISSING_HOST_IDENTIFIER,
  ERROR_DATABASE_CONNECTION,
  ERROR_NODE_NOT_FOUND,
  ERROR_DATABASE_FETCH_FAILED,
} from '../../consts/http';
import { getLogger } from '../../utils/logger';

const logger = getLogger('windows.updateHistory');

export async function windows_update_history_fetch(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const { host_identifier } = req.body;

  if (!host_identifier || typeof host_identifier !== 'string') {
    return res.status(400).json({
      status: "Error",
      message: ERROR_MISSING_HOST_IDENTIFIER
    });
  }

  const dataSources = dbSourceConnection();
  if (!dataSources?.[1]) {
    logger.error({ host_identifier }, 'Database connection error');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_CONNECTION
    });
  }

  const entityManager = dataSources[1];

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Windows update history lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // One row per logical install event: agents re-post full history on each sync with a new
    // unixtime (ingestion time), duplicating identical (update_id, revision, event date) rows.
    //
    // Two departures from the obvious formulation, both access-path only.
    //
    // 1. The host and the id window are pinned into single-row MATERIALIZED CTEs
    //    and joined in, rather than written as plain `WHERE host_identifier = $1
    //    AND id > (SELECT ...)` predicates. Written flat, `id >` becomes the
    //    cheapest available indexed bound and the planner drives the scan off
    //    windows_update_history_pkey across the whole id window, applying
    //    host_identifier as a post-filter. Materialising the host makes it a
    //    runtime value the planner cannot fold into that pkey bound, so it reaches
    //    idx_windows_update_history_host_id (host_identifier, id DESC) instead.
    //    (Same treatment, and same reason, as windows/memory_info.ts.)
    //
    // 2. Dedup is GROUP BY + MAX(id) plus a pkey join back, not
    //    ROW_NUMBER() ... rn = 1. These pick the same rows: host_identifier is
    //    fixed by an equality predicate, so PARTITION BY host_identifier is a
    //    no-op, and "ROW_NUMBER() ORDER BY id DESC, take rn = 1" is by definition
    //    the row with the greatest id in each group. id is the primary key, so
    //    each group has exactly one winner and there are no ties to break. The
    //    window form would have to sort every in-window row of the host, carrying
    //    all wide columns through the sort, to emit a few hundred; GROUP BY
    //    hash-aggregates the four narrow key expressions and only touches wide
    //    columns for the survivors.
    //
    // `rn` is emitted as a literal 1::bigint: it was always 1 for every returned
    // row, and it is part of the response body, so it is reproduced not dropped.
    //
    // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` guard is load-bearing for the
    // result set, not dead weight; it is only relocated to the join condition.
    const result = await entityManager.query(
      `
        WITH lo AS MATERIALIZED (
          SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} AS min_id
          FROM windows_update_history
        ),
        h AS MATERIALIZED (
          SELECT $1::varchar AS hid
        ),
        winners AS MATERIALIZED (
          SELECT MAX(wuh.id) AS id
          FROM h
          CROSS JOIN lo
          JOIN windows_update_history wuh
            ON wuh.host_identifier = h.hid
           AND wuh.id > lo.min_id
          GROUP BY
            COALESCE(NULLIF(BTRIM(wuh.update_id::text), ''), ''),
            COALESCE(NULLIF(BTRIM(wuh.update_revision::text), ''), ''),
            COALESCE(NULLIF(BTRIM(wuh."date"::text), ''), ''),
            COALESCE(NULLIF(BTRIM(wuh.operation::text), ''), '')
        )
        SELECT
          wuh.*,
          COALESCE(NULLIF(BTRIM(wuh.update_id::text), ''), '') AS n_update_id,
          COALESCE(NULLIF(BTRIM(wuh.update_revision::text), ''), '') AS n_update_revision,
          COALESCE(NULLIF(BTRIM(wuh."date"::text), ''), '') AS n_date,
          COALESCE(NULLIF(BTRIM(wuh.operation::text), ''), '') AS n_operation,
          1::bigint AS rn
        FROM winners w
        JOIN windows_update_history wuh ON wuh.id = w.id
        ORDER BY
          CASE
            WHEN COALESCE(NULLIF(BTRIM(wuh."date"::text), ''), '') ~ '^[0-9]+$'
              THEN COALESCE(NULLIF(BTRIM(wuh."date"::text), ''), '')::bigint
            ELSE 0
          END DESC NULLS LAST,
          wuh.id DESC
      `,
      [host_identifier]
    );

    if (!result?.length) {
      logger.info({ host_identifier }, 'No Windows update history found for host');
      return res.status(404).json({
        status: "Error",
        message: "No Windows update history found for this host"
      });
    }

    logger.info({ host_identifier, count: result.length }, 'Windows update history retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Windows update history fetched successfully.",
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch Windows update history');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}