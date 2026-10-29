import { DataSource } from 'typeorm';
import { DataRetentionPolicy } from '../orm/entities/fleet/DataRetentionPolicy';
import * as cron from 'node-cron';
import { getLogger } from '../utils/logger';
import { DB_SOURCE_PRIMARY } from '../consts/database';
import { logAuditTrail } from '../utils/auditTrailLogger';

const logger = getLogger('services.dataRetention');

// Defence in depth for runCleanup's raw DELETE statements. tableName and
// timestampColumn are validated and normalised at the API boundary in
// controllers/data-retention/dataRetentionController.ts, but this service also
// reads policies straight from the DB (e.g. on restart via initializeJobs()),
// so it quotes identifiers itself rather than trusting that boundary alone.
const quoteIdent = (identifier: string): string => `"${identifier.replace(/"/g, '""')}"`;

/**
 * Tables no retention policy may touch: core system tables the product cannot
 * run without, plus compliance evidence that cannot be regenerated once
 * deleted. audit_trail/audit_logs are the CERT-In/SEBI/IRDAI evidence trail,
 * alerts is what incident reports are built from, user_sessions is the
 * login/logout record, *historical_compliance are point-in-time snapshots of a
 * fleet state that no longer exists, and *compliance_results/certin_compliance/
 * certin_drafts are the per-node evidence those snapshots are derived from — a
 * rollup is a set of counts, so protecting it while leaving the underlying
 * per-node findings purgeable leaves nothing to substantiate the counts with.
 * Scan/patch
 * history and raw telemetry stay eligible; the retentionDays floor below is what
 * keeps policies on them lawful.
 */
export const SYSTEM_BLACKLIST = [
    // Core system tables
    'vajra_users',
    'nodes',
    'schema_migrations',
    'migrations',
    'data_retention_policies',
    // Compliance evidence
    'audit_trail',
    'audit_logs',
    'alerts',
    'user_sessions',
    'historical_compliance',
    'certin_historical_compliance',
    'sebi_historical_compliance',
    'irdai_historical_compliance',
    // Per-node compliance evidence behind the rollups above
    'compliance_results',
    'certin_compliance_results',
    'sebi_compliance_results',
    'irdai_compliance_results',
    'certin_compliance',
    'certin_drafts',
];

/**
 * Floor for a policy's retentionDays; 0/null ("keep forever") is unaffected.
 *
 * 180 is the CERT-In Directions 28.04.2022, Direction (iv) requirement ("shall
 * mandatorily enable logs of all their ICT systems and maintain them securely
 * for a rolling period of 180 days") that this product reports its own
 * compliance against, not an engineering preference. Every table this feature
 * can target holds those logs or telemetry derived from them. There is no CISO
 * waiver here: the discretion to specify a shorter period exists only in the
 * separate guideline for government entities, so a body corporate cannot
 * lawfully retain below this floor. DATA_RETENTION_MIN_DAYS may only raise the
 * floor — a value below it is refused and logged, never silently applied.
 */
export const CERTIN_MINIMUM_LOG_RETENTION_DAYS = 180;
export const MINIMUM_RETENTION_DAYS_ENV_VAR = 'DATA_RETENTION_MIN_DAYS';

export function getMinimumRetentionDays(): number {
    const raw = process.env[MINIMUM_RETENTION_DAYS_ENV_VAR];
    if (raw === undefined || raw.trim() === '') return CERTIN_MINIMUM_LOG_RETENTION_DAYS;

    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < 1) {
        logger.error(
            { [MINIMUM_RETENTION_DAYS_ENV_VAR]: raw, minimumRetentionDays: CERTIN_MINIMUM_LOG_RETENTION_DAYS },
            'Invalid DATA_RETENTION_MIN_DAYS (must be a whole number of days >= 1); falling back to the CERT-In 180-day floor',
        );
        return CERTIN_MINIMUM_LOG_RETENTION_DAYS;
    }
    if (parsed < CERTIN_MINIMUM_LOG_RETENTION_DAYS) {
        // Fail closed: the floor is not waivable by a body corporate, so an
        // env var asking for less than it is ignored rather than honoured.
        logger.error(
            { [MINIMUM_RETENTION_DAYS_ENV_VAR]: raw, requestedMinimumRetentionDays: parsed, minimumRetentionDays: CERTIN_MINIMUM_LOG_RETENTION_DAYS },
            'DATA_RETENTION_MIN_DAYS is below the 180-day log-retention floor of the CERT-In Directions 28.04.2022, Direction (iv), which a body corporate cannot waive; ignoring it and keeping the 180-day floor',
        );
        return CERTIN_MINIMUM_LOG_RETENTION_DAYS;
    }
    return parsed;
}

/** Shared wording so the API rejection and the skipped-run log say the same thing. */
export function retentionDaysBelowMinimumMessage(minimumDays: number): string {
    return (
        `Retention period must be at least ${minimumDays} days (or empty to keep forever). ` +
        `The CERT-In Directions 28.04.2022, Direction (iv) require logs of ICT systems to be ` +
        `maintained for a rolling period of ${CERTIN_MINIMUM_LOG_RETENTION_DAYS} days.`
    );
}

/**
 * A sweep over a multi-GB table must not be one transaction: an unbounded
 * DELETE holds the xmin horizon open for hours (blocking autovacuum
 * database-wide), writes tens of GB of WAL against max_wal_size, and rolls back
 * everything on failure, so a run that cannot finish never makes progress.
 * Small committed batches keep progress monotonic.
 */
export const DEFAULT_DELETE_BATCH_SIZE = 20000;
const DELETE_BATCH_SIZE_ENV_VAR = 'DATA_RETENTION_BATCH_SIZE';
const MIN_DELETE_BATCH_SIZE = 100;
const MAX_DELETE_BATCH_SIZE = 200000;
/** Per-batch statement_timeout. A batch that cannot finish in this long is a sign the table lacks a usable index; better to fail one batch than to wedge a connection. */
const BATCH_STATEMENT_TIMEOUT_MS = 300000;
/** Per-batch lock_timeout: never queue behind a long-running lock holder, just retry on the next batch/run. */
const BATCH_LOCK_TIMEOUT_MS = 5000;
/** Breathing room between batches so autovacuum, replication and ordinary traffic get the table back. */
const BATCH_PAUSE_MS = 250;
/** Safety stop: at the default batch size this is 100M rows in a single run. Anything left is picked up by the next scheduled run. */
const MAX_BATCHES_PER_TABLE = 5000;
const PROGRESS_LOG_EVERY_BATCHES = 20;

/** Optional IANA timezone for cron evaluation (e.g. 'Asia/Kolkata'). Unset keeps node-cron's default of the server's local time. */
const RETENTION_TIMEZONE_ENV_VAR = 'DATA_RETENTION_TZ';

function getDeleteBatchSize(): number {
    const raw = process.env[DELETE_BATCH_SIZE_ENV_VAR];
    if (raw === undefined || raw.trim() === '') return DEFAULT_DELETE_BATCH_SIZE;

    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < MIN_DELETE_BATCH_SIZE || parsed > MAX_DELETE_BATCH_SIZE) {
        logger.error(
            { [DELETE_BATCH_SIZE_ENV_VAR]: raw, batchSize: DEFAULT_DELETE_BATCH_SIZE, min: MIN_DELETE_BATCH_SIZE, max: MAX_DELETE_BATCH_SIZE },
            'Invalid DATA_RETENTION_BATCH_SIZE; falling back to the default batch size',
        );
        return DEFAULT_DELETE_BATCH_SIZE;
    }
    return parsed;
}

function getScheduleTimezone(): string | undefined {
    const tz = process.env[RETENTION_TIMEZONE_ENV_VAR]?.trim();
    return tz ? tz : undefined;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Row addressing for chunked deletes. 'id' is a single-column integer primary
 * key: index-backed and stable. 'ctid' is the fallback for tables without one;
 * it is a physical pointer valid only inside the statement that selects it, so
 * a row moved by a concurrent UPDATE survives that batch and is deleted by the
 * next one.
 */
type ChunkKey = { kind: 'id'; column: string } | { kind: 'ctid' };

export class DataRetentionService {
    private primaryDb: DataSource;
    private secondaryDb: DataSource;
    private activeJobs: Map<string, cron.ScheduledTask> = new Map();
    // Guards against a scheduled tick or manual trigger starting a second
    // concurrent runCleanup() for a policy whose previous run is still in
    // flight; see runCleanup()'s try/finally below.
    private runningPolicyIds: Set<string> = new Set();

    constructor(primaryDb: DataSource, secondaryDb: DataSource) {
        this.primaryDb = primaryDb;
        this.secondaryDb = secondaryDb;
    }

    /**
     * Initializes all cron jobs based on the policies in the DB.
     */
    public async initializeJobs() {
        const policyRepo = this.secondaryDb.getRepository(DataRetentionPolicy);
        let policies: DataRetentionPolicy[];
        try {
            policies = await policyRepo.find();
        } catch (err) {
            // Failures below are logged individually with their policyId, but a
            // failure loading the list itself would otherwise surface only in
            // index.ts's generic top-level catch.
            logger.error({ err }, 'Failed to initialize data retention jobs: could not load policies from the database');
            throw err;
        }

        let scheduled = 0;
        for (const policy of policies) {
            try {
                this.scheduleJob(policy);
                scheduled++;
            } catch (err) {
                // One unusable policy must not leave the remaining ones unscheduled.
                logger.error(
                    { err, policyId: policy.id, tableNames: policy.tableNames, cronExpression: policy.cronExpression },
                    'Failed to schedule data retention policy; skipping it — remaining policies are unaffected',
                );
            }
        }
        logger.info({ scheduled, total: policies.length }, 'Initialized data retention jobs');
    }

    /**
     * Schedules or reschedules a cron job for a specific policy.
     */
    public scheduleJob(policy: DataRetentionPolicy) {
        // Cancel existing job if any
        if (this.activeJobs.has(policy.id.toString())) {
            this.activeJobs.get(policy.id.toString())?.stop();
            this.activeJobs.delete(policy.id.toString());
        }

        // If both limits are missing, do not schedule
        if (
            (!policy.retentionDays || policy.retentionDays <= 0) &&
            (!policy.rowCountLimit || policy.rowCountLimit <= 0)
        ) {
            logger.warn({ policyId: policy.id, tableNames: policy.tableNames }, 'Data retention policy has no retentionDays or rowCountLimit set; not scheduling');
            return;
        }

        // Stored rows are not necessarily controller-validated; leave a bad one
        // unscheduled rather than throwing out of the startup loop.
        if (!cron.validate(policy.cronExpression)) {
            logger.error(
                { policyId: policy.id, tableNames: policy.tableNames, cronExpression: policy.cronExpression },
                'Data retention policy has an invalid cron expression; not scheduling. Edit the policy to fix its schedule',
            );
            return;
        }

        // The UI builds the cron string in the admin's browser timezone;
        // DATA_RETENTION_TZ pins evaluation to a matching zone. Unset keeps
        // node-cron's default of server-local time.
        const timezone = getScheduleTimezone();
        const task = cron.schedule(
            policy.cronExpression,
            () => {
                // cron.schedule does not await the callback; an unhandled rejection is fatal on Node >= 15.
                this.runCleanup(policy).catch((err) =>
                    logger.error({ err, policyId: policy.id, tableNames: policy.tableNames }, 'Scheduled data retention cleanup failed'),
                );
            },
            timezone ? { timezone } : undefined,
        );

        this.activeJobs.set(policy.id.toString(), task);
        logger.info(
          { policyId: policy.id, tableNames: policy.tableNames, cronExpression: policy.cronExpression, retentionDays: policy.retentionDays, timezone: timezone ?? null },
          'Scheduled data retention cleanup',
        );
    }

    /**
     * Executes the raw SQL cleanup for a specific policy.
     */
    public async runCleanup(policy: DataRetentionPolicy) {
        if (
            (!policy.retentionDays || policy.retentionDays <= 0) &&
            (!policy.rowCountLimit || policy.rowCountLimit <= 0)
        ) {
            logger.warn({ policyId: policy.id, tableNames: policy.tableNames }, 'Data retention cleanup skipped: policy has no retentionDays or rowCountLimit set');
            return;
        }

        // Second enforcement point for policies written outside the controller:
        // refuse the run rather than delete below the floor. Not gated on
        // retentionType — a row_count policy that also carries a sub-floor
        // retentionDays is refused here, and a row_count policy with no
        // retentionDays at all is floored in the predicate built below, which
        // ANDs the rank threshold with the same age cutoff.
        if (policy.retentionDays && policy.retentionDays > 0) {
            const minimumRetentionDays = getMinimumRetentionDays();
            if (policy.retentionDays < minimumRetentionDays) {
                logger.error(
                    { policyId: policy.id, tableNames: policy.tableNames, retentionDays: policy.retentionDays, minimumRetentionDays },
                    `Data retention cleanup skipped: ${retentionDaysBelowMinimumMessage(minimumRetentionDays)}`,
                );
                return;
            }
        }

        const policyKey = policy.id.toString();
        if (this.runningPolicyIds.has(policyKey)) {
            logger.warn({ policyId: policy.id, tableNames: policy.tableNames }, 'Data retention cleanup skipped: previous run for this policy is still in progress');
            return;
        }
        this.runningPolicyIds.add(policyKey);

        try {
            await this.runCleanupUnguarded(policy);
        } finally {
            this.runningPolicyIds.delete(policyKey);
        }
    }

    private async runCleanupUnguarded(policy: DataRetentionPolicy) {
        // Must match the exact literal the controller stores: getDatabases()
        // offers 'primary'/'fleet' and dataRetentionController.ts stores
        // databaseName as-is. A mismatch here silently routes every policy to the
        // fleet DB regardless of what the admin configured.
        const db = policy.databaseName === DB_SOURCE_PRIMARY ? this.primaryDb : this.secondaryDb;
        // Same default as the entity and the create/update controller.
        const timestampColumn = policy.timestampColumn || 'unixtime';
        // Resolved once per run so every table in the policy is cut at the same floor.
        const minimumRetentionDays = getMinimumRetentionDays();

        let succeeded = 0;
        let failed = 0;
        let skipped = 0;
        let totalRowsDeleted = 0;

        // Resolve the timestamp column's type for every table in one round-trip.
        // information_schema.columns is a catalog view that is re-planned and
        // re-scanned per call, and a policy can name dozens of tables.
        //
        // Blacklisted tables are excluded because the loop skips them anyway. If
        // the batch lookup fails the map stays null and each table falls back to
        // a per-table query inside its own try/catch, so one table's metadata
        // error still counts as that table's `failed` rather than failing the
        // whole policy.
        const tablesToInspect = policy.tableNames.filter((tableName) => !SYSTEM_BLACKLIST.includes(tableName));
        // No initialiser: every branch below assigns before first read, and
        // eslint's no-useless-assignment flags a dead one.
        let columnTypeByTable: Map<string, string> | null;
        if (tablesToInspect.length === 0) {
            columnTypeByTable = new Map();
        } else {
            try {
                const columnTypeRows: { table_name: string; data_type: string }[] = await db.query(
                    `SELECT table_name, data_type FROM information_schema.columns WHERE table_name = ANY($1) AND column_name = $2`,
                    [tablesToInspect, timestampColumn]
                );
                columnTypeByTable = new Map();
                for (const row of columnTypeRows) {
                    // First row wins, matching the per-table fallback query below.
                    if (!columnTypeByTable.has(row.table_name)) columnTypeByTable.set(row.table_name, row.data_type);
                }
            } catch (err) {
                logger.warn({ err, policyId: policy.id }, 'Batched timestamp-column type lookup failed; falling back to per-table lookups');
                columnTypeByTable = null;
            }
        }

        for (const tableName of policy.tableNames) {
            if (SYSTEM_BLACKLIST.includes(tableName)) {
                logger.error({ tableName, policyId: policy.id }, 'Attempted to clean blacklisted table');
                skipped++;
                continue;
            }

            try {
                logger.debug({ tableName, policyId: policy.id }, 'Running data retention cleanup');

                // Determine if timestampColumn is a numeric (unixtime) or a date/timestamp
                const columnTypeResult: { data_type: string }[] = columnTypeByTable
                    ? (columnTypeByTable.has(tableName) ? [{ data_type: columnTypeByTable.get(tableName) as string }] : [])
                    : await db.query(
                          `SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
                          [tableName, timestampColumn]
                      );

                if (columnTypeResult.length === 0) {
                    logger.error({ tableName, timestampColumn, policyId: policy.id }, 'Timestamp column not found; skipping cleanup for table');
                    skipped++;
                    continue;
                }

                const dataType = columnTypeResult[0].data_type;
                const isNumeric = dataType === 'bigint' || dataType === 'integer';

                const quotedTable = quoteIdent(tableName);
                const quotedColumn = quoteIdent(timestampColumn);
                const chunkKey = await this.resolveChunkKey(db, tableName);

                // `${column} < now - N days`, in whichever form the column's
                // type needs. Shared so the row-count path is floored by exactly
                // the same age cutoff the time-based path uses.
                const olderThanDaysSql = (placeholder: string): string =>
                    isNumeric
                        // EXTRACT(EPOCH ...) is numeric on PG14+; comparing it to a
                        // bigint column casts the column and loses the index. Cast
                        // the computed constant instead.
                        ? `${quotedColumn} < EXTRACT(EPOCH FROM (NOW() - (${placeholder} * INTERVAL '1 day')))::bigint`
                        // Standard timestamp
                        : `${quotedColumn} < NOW() - (${placeholder} * INTERVAL '1 day')`;

                let predicateSql = '';
                const predicateParams: any[] = [];
                // The boundary this table was actually cut at, recorded in the
                // audit trail below so a missing log range can be answered with a
                // record rather than an inference.
                let cutoff: Record<string, any> = {};

                if (policy.retentionType === 'row_count' && policy.rowCountLimit && policy.rowCountLimit > 0) {
                    // Keep the newest N rows, addressed by primary key: an OFFSET
                    // probe down the PK index for the cut-off id, then the same
                    // chunked delete as the time-based path. A `ctid NOT IN (...)`
                    // form re-probes the kept-row list once per heap row and is
                    // unstable under concurrent UPDATEs. "Newest" therefore means
                    // highest PK, which holds on append-only tables; without a
                    // single-column integer PK the run fails rather than guessing.
                    if (chunkKey.kind !== 'id') {
                        throw new Error(
                            `Row-count retention requires a single-column integer primary key to identify the newest rows, and "${tableName}" has none. Use time-based retention (retention days) for this table instead.`,
                        );
                    }
                    const quotedKey = quoteIdent(chunkKey.column);
                    // OFFSET limit-1 is the id of the oldest row to keep, so
                    // `< threshold` targets everything below the newest
                    // rowCountLimit rows (the age floor ANDed in below then
                    // spares any of those that are still too young to delete).
                    const thresholdRows: { threshold: string | number }[] = await db.query(
                        `SELECT ${quotedKey} AS threshold FROM ${quotedTable} ORDER BY ${quotedKey} DESC OFFSET $1 LIMIT 1`,
                        [policy.rowCountLimit - 1],
                    );
                    if (thresholdRows.length === 0) {
                        // Fewer rows than the limit: nothing to delete.
                        logger.debug({ tableName, policyId: policy.id, rowCountLimit: policy.rowCountLimit }, 'Data retention cleanup: table holds fewer rows than the row-count limit; nothing to delete');
                        succeeded++;
                        continue;
                    }
                    // The rank threshold alone would delete every row below the
                    // Nth-newest id whatever its age. ANDing the age cutoff keeps
                    // the retention floor unconditional: a row younger than
                    // minimumRetentionDays is never removed, so the table settles
                    // above rowCountLimit rather than below the floor.
                    predicateSql = `${quotedKey} < $1 AND ${olderThanDaysSql('$2')}`;
                    predicateParams.push(thresholdRows[0].threshold, minimumRetentionDays);
                    cutoff = {
                        retentionType: 'row_count',
                        rowCountLimit: policy.rowCountLimit,
                        primaryKeyColumn: chunkKey.column,
                        primaryKeyThreshold: thresholdRows[0].threshold,
                        timestampColumn,
                        minimumRetentionDays,
                    };
                } else if (policy.retentionDays && policy.retentionDays > 0) {
                    // Time-based deletion
                    predicateSql = olderThanDaysSql('$1');
                    predicateParams.push(policy.retentionDays);
                    cutoff = {
                        retentionType: policy.retentionType,
                        retentionDays: policy.retentionDays,
                        timestampColumn,
                        minimumRetentionDays,
                    };
                }

                if (predicateSql) {
                    const rowsDeleted = await this.deleteInBatches(db, {
                        policyId: policy.id,
                        tableName,
                        quotedTable,
                        chunkKey,
                        predicateSql,
                        predicateParams,
                    });
                    totalRowsDeleted += rowsDeleted;
                    logger.info({ tableName, policyId: policy.id, rowsDeleted }, 'Data retention cleanup successful');
                    // The purge itself is evidence: without a record of what was
                    // removed and where the line was drawn, a missing log range
                    // can only be explained by inference. logAuditTrail swallows
                    // its own write errors, so this cannot fail the run.
                    await logAuditTrail({
                        action: 'DATA_RETENTION_PURGE',
                        status: 'success',
                        details: {
                            policyId: policy.id,
                            databaseName: policy.databaseName,
                            tableName,
                            rowsDeleted,
                            cutoff,
                        },
                    });
                    succeeded++;
                } else {
                    logger.warn(
                        { tableName, policyId: policy.id, retentionType: policy.retentionType, retentionDays: policy.retentionDays, rowCountLimit: policy.rowCountLimit },
                        'Data retention cleanup skipped for table: retentionType does not match a usable limit',
                    );
                    skipped++;
                }
            } catch (err) {
                logger.error({ err, tableName, policyId: policy.id }, 'Data retention cleanup failed');
                failed++;
            }
        }

        logger.info(
            { policyId: policy.id, tableCount: policy.tableNames.length, succeeded, failed, skipped, totalRowsDeleted },
            'Data retention cleanup run finished',
        );
    }

    /** Single-column integer primary key if the table has one, else ctid; catalog errors also degrade to ctid. */
    private async resolveChunkKey(db: DataSource, tableName: string): Promise<ChunkKey> {
        try {
            const rows: { column_name: string; type_name: string }[] = await db.query(
                `SELECT a.attname AS column_name, t.typname AS type_name
                   FROM pg_index i
                   JOIN pg_class c ON c.oid = i.indrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
                   JOIN pg_type t ON t.oid = a.atttypid
                  WHERE i.indisprimary AND n.nspname = 'public' AND c.relname = $1`,
                [tableName],
            );
            if (rows.length === 1 && ['int2', 'int4', 'int8'].includes(rows[0].type_name)) {
                return { kind: 'id', column: rows[0].column_name };
            }
            logger.warn(
                { tableName, primaryKeyColumns: rows.map((r) => r.column_name) },
                'Table has no single-column integer primary key; falling back to ctid-based chunked deletes',
            );
        } catch (err) {
            logger.warn({ err, tableName }, 'Primary-key lookup failed; falling back to ctid-based chunked deletes');
        }
        return { kind: 'ctid' };
    }

    /** Deletes rows matching `predicateSql` in committed batches until a batch removes nothing; returns the total deleted. */
    private async deleteInBatches(
        db: DataSource,
        ctx: {
            policyId: number;
            tableName: string;
            quotedTable: string;
            chunkKey: ChunkKey;
            predicateSql: string;
            predicateParams: any[];
        },
    ): Promise<number> {
        const batchSize = getDeleteBatchSize();
        const limitPlaceholder = `$${ctx.predicateParams.length + 1}`;

        // The predicate stays inside the subquery so it can use the index on the
        // timestamp or primary key column.
        const batchSql =
            ctx.chunkKey.kind === 'id'
                ? `DELETE FROM ${ctx.quotedTable} WHERE ${quoteIdent(ctx.chunkKey.column)} IN (` +
                  `SELECT ${quoteIdent(ctx.chunkKey.column)} FROM ${ctx.quotedTable} WHERE ${ctx.predicateSql} ` +
                  `ORDER BY ${quoteIdent(ctx.chunkKey.column)} LIMIT ${limitPlaceholder})`
                : `DELETE FROM ${ctx.quotedTable} WHERE ctid IN (` +
                  `SELECT ctid FROM ${ctx.quotedTable} WHERE ${ctx.predicateSql} LIMIT ${limitPlaceholder})`;
        const batchParams = [...ctx.predicateParams, batchSize];

        let rowsDeleted = 0;
        let batches = 0;

        for (;;) {
            const affected = await this.runDeleteBatch(db, batchSql, batchParams);
            rowsDeleted += affected;
            batches++;

            if (affected === 0) break;

            if (batches >= MAX_BATCHES_PER_TABLE) {
                logger.warn(
                    { tableName: ctx.tableName, policyId: ctx.policyId, batches, rowsDeleted, batchSize },
                    'Data retention cleanup hit the per-run batch cap for this table; the remaining rows will be removed on the next scheduled run',
                );
                break;
            }

            if (batches % PROGRESS_LOG_EVERY_BATCHES === 0) {
                logger.info(
                    { tableName: ctx.tableName, policyId: ctx.policyId, batches, rowsDeleted, batchSize },
                    'Data retention cleanup in progress',
                );
            }

            await sleep(BATCH_PAUSE_MS);
        }

        return rowsDeleted;
    }

    /** One batch = one short transaction with its own statement/lock timeouts. */
    private async runDeleteBatch(db: DataSource, sql: string, params: any[]): Promise<number> {
        const runner = db.createQueryRunner();
        try {
            await runner.connect();
            await runner.startTransaction();
            try {
                // SET LOCAL accepts literals only; set_config is its parameterised
                // form. Unitless values are milliseconds.
                await runner.query(
                    `SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true)`,
                    [String(BATCH_STATEMENT_TIMEOUT_MS), String(BATCH_LOCK_TIMEOUT_MS)],
                );
                const result = await runner.query(sql, params, true);
                await runner.commitTransaction();
                return typeof result.affected === 'number' ? result.affected : 0;
            } catch (err) {
                if (runner.isTransactionActive) {
                    await runner.rollbackTransaction().catch(() => undefined);
                }
                throw err;
            }
        } finally {
            await runner.release();
        }
    }

    /**
     * Force runs a cleanup immediately (useful for testing or manual triggers)
     */
    public async triggerManualCleanup(id: number) {
        const policyRepo = this.secondaryDb.getRepository(DataRetentionPolicy);
        let policy: DataRetentionPolicy | null;
        try {
            policy = await policyRepo.findOne({ where: { id } });
        } catch (err) {
            logger.error({ err, policyId: id }, 'Manual data retention cleanup failed: could not load policy');
            throw err;
        }
        if (policy) {
            logger.info({ policyId: id, tableNames: policy.tableNames }, 'Manual data retention cleanup triggered');
            await this.runCleanup(policy);
        } else {
            logger.warn({ policyId: id }, 'Manual data retention cleanup requested for unknown policy id');
        }
    }

    /**
     * Stops and removes a policy's cron job, e.g. after the policy was deleted.
     * Without it the job keeps running against the stale in-memory policy object
     * until the process restarts.
     */
    public unscheduleJob(policyId: number) {
        const key = policyId.toString();
        const task = this.activeJobs.get(key);
        if (task) {
            task.stop();
            this.activeJobs.delete(key);
            logger.info({ policyId }, 'Unscheduled data retention cleanup job');
        }
    }
}

// Module-level accessor so controllers can reach the single instance created in
// index.ts and (re)schedule or cancel a job as soon as a policy changes, rather
// than waiting for the next process restart. Same pattern as
// getScanSchedulerServiceInstance in services/scanSchedulerService.ts.
let instance: DataRetentionService | null = null;

export function setDataRetentionServiceInstance(service: DataRetentionService) {
    instance = service;
}

export function getDataRetentionServiceInstance(): DataRetentionService | null {
    return instance;
}
