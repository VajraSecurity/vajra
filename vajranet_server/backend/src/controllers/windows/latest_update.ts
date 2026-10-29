import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import { DEFAULT_LOCALE, DEFAULT_DISPLAY_TIMEZONE } from '../../consts/server';
import {
  ERROR_MISSING_HOST_IDENTIFIER,
  ERROR_DATABASE_CONNECTION,
  ERROR_NODE_NOT_FOUND,
} from '../../consts/http';
import { getLogger } from '../../utils/logger';

const logger = getLogger('windows.latestUpdate');

export async function latest_update_history_fetch(
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
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Latest update lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    // Single read-only SELECT — no transaction needed for atomicity here.
    // Latest by Windows event time ("date"), not ingestion unixtime (re-sync duplicates rows).
    //
    // Deliberately no DISTINCT ON re-sync dedup, unlike update_history.ts. Such a
    // dedup over (host_identifier, update_id, update_revision, "date", operation)
    // would be dead work here: "date" is part of that key, so a group never spans
    // two "date" values, and the dedup keeps the highest `id` in each group. The
    // outer ORDER BY is (date-sort-key DESC, id DESC), so the row it lands on is
    // the highest-id row carrying the highest "date" — by construction the survivor
    // of its own group. Dedup could only discard lower-id rows inside a group, i.e.
    // rows that could never have won, and `id` is the primary key so the ordering
    // is total and the winner unique.
    //
    // The host and the id window are pinned into single-row MATERIALIZED CTEs and
    // joined in, rather than written as flat `WHERE host_identifier = $1 AND
    // id > (SELECT ...)` predicates. `h` and `lo` each yield exactly one row, so
    // the joins are no-op multipliers and the surviving rows and ordering are
    // unchanged — this buys an index, nothing else. windows_update_history carries
    // idx_windows_update_history_host_id (host_identifier, id DESC), which
    // satisfies both predicates, but the flat form never reaches it: with `id >`
    // written as a plain comparison against an InitPlan scalar the planner takes it
    // as the cheapest index bound, drives the scan off
    // windows_update_history_pkey across the whole id window and demotes
    // host_identifier to a post-filter. Materialising the host makes it a runtime
    // value the planner cannot fold into that bound.
    //
    // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` guard is load-bearing and is
    // only relocated to the join condition: dropping it would widen the candidates
    // to a host's whole history and can change which row wins.
    const result = await entityManager.query(
        `WITH lo AS MATERIALIZED (
           SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} AS min_id
           FROM windows_update_history
         ),
         h AS MATERIALIZED (
           SELECT $1::varchar AS hid
         )
         SELECT w.title, w.description, w.unixtime, w.result_code, w.operation, w."date"
           FROM h
           CROSS JOIN lo
           JOIN windows_update_history w
             ON w.host_identifier = h.hid
            AND w.id > lo.min_id
          ORDER BY
            CASE
              WHEN w."date"::text ~ '^[0-9]+$' THEN (w."date"::text)::bigint
              ELSE 0
            END DESC NULLS LAST,
            w.id DESC
          LIMIT 1`,
        [host_identifier]
      );

      if (!result?.length) {
        logger.info({ host_identifier }, 'No update records found for host');
        return res.status(404).json({
          status: "Error",
          message: "No update records found for this host"
        });
      }

      const update = result[0];
      const title = update.title || "";
      const description = update.description || "";

      let category = "General Update";
      const combinedText = (title + " " + description).toLowerCase();

      if (combinedText.includes("version 24h2") || combinedText.includes("cumulative update")) {
        category = "Major OS Update";
      } else if (combinedText.includes("security") || combinedText.includes("defender") || combinedText.includes("malicious")) {
        category = "Security Patch";
      } else if (combinedText.includes("driver") || combinedText.includes("extension") || combinedText.includes("firmware")) {
        category = "Driver/Hardware Extension";
      }

      const kbMatch = title.match(/KB\d+/i);
      const versionMatch = title.match(/\b\d+(\.\d+){2,}\b/);
      const reference = kbMatch ? kbMatch[0].toUpperCase() : (versionMatch ? versionMatch[0] : "N/A");

      // Prefer the Windows event time ("date") over ingestion unixtime.
      const eventSecRaw = update.date != null && String(update.date).match(/^[0-9]+$/)
        ? parseInt(String(update.date), 10)
        : parseInt(String(update.unixtime ?? ''), 10);
      const dateObj = Number.isFinite(eventSecRaw)
        ? new Date(eventSecRaw * 1000)
        : new Date();

      const responseData = {
        summary: {
          update_title: title,
          category: category,
          version_reference: reference,
          install_status: update.result_code,
          timestamp: dateObj.toLocaleString(DEFAULT_LOCALE, { timeZone: DEFAULT_DISPLAY_TIMEZONE }),
          description_summary: description.split('.')[0] + '.'
        }
      };

    logger.info({ host_identifier, category }, 'Latest update metadata retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Latest update metadata derived successfully.",
      data: responseData
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch latest update history');
    return res.status(500).json({ status: "Error", message: "Internal server error." });
  }
}