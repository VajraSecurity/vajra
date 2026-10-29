import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { CustomError } from '../../utils/response/custom-error/CustomError';

import { validateSql } from '../../mcp/guardrails';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { THREAT_HUNTING_DEFAULT_ROW_LIMIT, THREAT_HUNTING_MAX_ROW_LIMIT, RLS_GROUP_SESSION_VAR } from '../../consts/database';

const logger = getLogger('controllers.threatHunting.runQuery');

export async function run_query(req: Request, res: Response, next: NextFunction) {
  try {
    const { query, limit } = req.body as { query?: unknown; limit?: unknown };

    if (typeof query !== 'string') {
      return res.status(400).json({ success: false, message: 'query must be a string' });
    }

    const guard = validateSql(query, [], 'secondary');
    if (!guard.valid) {
      logger.warn({ userId: (req as any).jwtPayload?.id ?? null, reason: guard.reason }, 'Threat hunting query rejected by SQL guardrails');
      return res.status(400).json({ success: false, message: guard.reason });
    }

    const dataSources = dbSourceConnection();
    if (!dataSources || dataSources.length < 2 || !dataSources[1].isInitialized) {
      logger.warn({}, 'Threat hunting query aborted: fleet database not available');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    // Group-scoped (Group Admin) callers run on a separate, lower-privilege
    // connection (vajra_hunt) that does not own the fleet tables — Postgres
    // enforces the Row-Level Security policies on that connection, filtering
    // every host-keyed table down to the caller's group(s) regardless of how
    // the query is phrased. There is no reliable way to scope free-form SQL by
    // rewriting or post-filtering it, so the caller's SQL below is never modified
    // or inspected for a host_identifier column.
    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };

    let db = dataSources[1]; // secondary/fleet DB, owner role — Super Admin / global path
    let groupsForSession: string | null = null;

    if (!scope.unrestricted) {
      const groupIds = scopeGroupIds(scope);
      if (groupIds.length === 0) {
        logger.info({ count: 0 }, 'Threat hunting query returned no results: caller has no scoped groups');
        return res.status(200).json({ success: true, data: [], count: 0, truncated: false });
      }

      const huntDb = dataSources[2];
      if (!huntDb || !huntDb.isInitialized) {
        logger.warn({ userId: jwtPayload?.id ?? null }, 'Threat hunting query aborted: group-scoped hunt database not available on this deployment');
        return res.status(503).json({
          success: false,
          message: 'Group-scoped historical hunting is not available on this deployment yet.',
        });
      }
      db = huntDb;
      groupsForSession = groupIds.join(',');
    }

    // Enforce a row cap so large tables don't blow up the response.
    const rowLimit = Math.min(
      Math.max(1, parseInt(String(limit ?? THREAT_HUNTING_DEFAULT_ROW_LIMIT), 10) || THREAT_HUNTING_DEFAULT_ROW_LIMIT),
      THREAT_HUNTING_MAX_ROW_LIMIT,
    );

    // Wrap in a CTE to inject LIMIT safely without modifying the user's SQL
    const wrapped = `SELECT * FROM (${query.trim().replace(/;+\s*$/, '')}) __q LIMIT ${rowLimit}`;

    try {
      const rows = await db.transaction(async (manager) => {
        await manager.query("SET LOCAL statement_timeout = '30s'");
        // SET LOCAL (not SET): scoped to this transaction only, cleared at
        // commit. vajra_hunt is a pooled connection reused across requests
        // from different users — SET LOCAL is what stops a later request on
        // the same pooled connection from inheriting a previous caller's
        // group list.
        if (groupsForSession !== null) {
          // SET/SET LOCAL are utility statements — Postgres does not accept a
          // bind parameter as the value (it must be a literal), so `SET LOCAL
          // vajra.groups = $1` is a syntax error, not just untested. set_config()
          // is a normal function call and takes a real parameter; its third
          // argument (true) gives it identical "local to transaction" semantics.
          await manager.query('SELECT set_config($1, $2, true)', [RLS_GROUP_SESSION_VAR, groupsForSession]);
        }
        return manager.query(wrapped);
      });

      const truncated = rows.length >= rowLimit;
      logger.debug({ count: rows.length, truncated, scoped: !scope.unrestricted }, 'Threat hunting query executed');
      return res.status(200).json({
        success: true,
        data: rows,
        count: rows.length,
        truncated,
      });
    } catch (queryErr: unknown) {
      logger.info({ err: queryErr, query: query.trim().slice(0, 500), scoped: !scope.unrestricted }, 'Threat hunting query execution failed');
      return res.status(400).json({
        success: false,
        message: 'Query execution failed. Please check your SQL syntax or verify that the tables/columns exist.',
      });
    }
  } catch (err: unknown) {
    // Infrastructure / unexpected errors; query-execution failures are answered
    // with a 400 in the inner catch above.
    logger.error({ err, userId: (req as any).jwtPayload?.id ?? null }, 'Threat hunting query request failed');
    return next(new CustomError(500, 'Raw', 'Internal server error', null, err));
  }
}
