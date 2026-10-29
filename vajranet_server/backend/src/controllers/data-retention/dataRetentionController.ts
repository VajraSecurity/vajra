import { Request, Response } from 'express';
import * as cron from 'node-cron';
import {
    SYSTEM_BLACKLIST,
    getDataRetentionServiceInstance,
    getMinimumRetentionDays,
    retentionDaysBelowMinimumMessage,
} from '../../services/dataRetentionService';
import { dbSourceConnection } from '../../index';
import { DataRetentionPolicy, CRON_DAILY_AT_MIDNIGHT, DEFAULT_RETENTION_CLEANUP_TIME } from '../../orm/entities/fleet/DataRetentionPolicy';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { getLogger } from '../../utils/logger';
import { DB_SOURCE_PRIMARY, DB_SOURCE_FLEET } from '../../consts/database';

const logger = getLogger('controllers.dataRetention');

// SYSTEM_BLACKLIST is compared with exact string equality, so an untrimmed
// value (e.g. "nodes " from a stray form-field space) would slip past the
// blacklist check here while still resolving to the real "nodes" table once
// interpolated into dataRetentionService.ts's raw DELETE FROM ${tableName}.
// Normalizing here closes that gap at the one place every policy is created
// or edited.
const normalizeIdentifier = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

/**
 * Validates the fields nothing else checks, returning an error message or null.
 * An invalid cronExpression otherwise only fails inside node-cron at schedule
 * time, where the operator never sees it. The retentionDays floor is
 * CERTIN_MINIMUM_LOG_RETENTION_DAYS in services/dataRetentionService.ts and
 * applies to every policy, not only time-based ones.
 */
function validatePolicySchedulingInput(
    retentionDays: unknown,
    cronExpression: unknown,
    retentionType: unknown,
    rowCountLimit: unknown,
): string | null {
    if (cronExpression !== undefined && cronExpression !== null && cronExpression !== '') {
        if (typeof cronExpression !== 'string' || !cron.validate(cronExpression)) {
            return 'Invalid cron expression. Use a standard five-field cron schedule, for example "0 0 * * *" for daily at midnight.';
        }
    }

    if (retentionDays !== undefined && retentionDays !== null && retentionDays !== '') {
        if (typeof retentionDays !== 'number' || !Number.isInteger(retentionDays) || retentionDays < 0) {
            return 'Retention period must be a whole number of days (or empty to keep forever).';
        }
        // 0 is stored as null ("keep forever"), so only positive values are
        // floored. Not gated on retentionType: a row_count policy that also
        // carries a sub-floor retentionDays is rejected here too.
        const minimumRetentionDays = getMinimumRetentionDays();
        if (retentionDays > 0 && retentionDays < minimumRetentionDays) {
            return retentionDaysBelowMinimumMessage(minimumRetentionDays);
        }
    }

    // A row_count policy carries no retentionDays, so the check above never saw
    // it and the age floor used to be skipped for it entirely. The floor is now
    // enforced unconditionally in runCleanup, which ANDs the rank threshold with
    // the same age cutoff — a row_count policy therefore settles above its
    // rowCountLimit rather than deleting below the floor. All that is left to do
    // here is refuse a limit that cannot be applied at all, rather than storing
    // it and failing inside the OFFSET probe at run time. null/empty stays
    // "keep forever", as it already did.
    if (retentionType === 'row_count' && rowCountLimit !== undefined && rowCountLimit !== null && rowCountLimit !== '') {
        if (typeof rowCountLimit !== 'number' || !Number.isInteger(rowCountLimit) || rowCountLimit < 0) {
            return 'Row count limit must be a whole number of rows (or empty to keep forever).';
        }
    }

    return null;
}

/** Confirms every table (and, if given, the column on each) actually exists — run unconditionally, not only when a timestampColumn happens to be supplied. */
async function validateTablesExist(
    connection: { query: (sql: string, params?: any[]) => Promise<any[]> },
    tableNames: string[],
    timestampColumn?: string,
): Promise<string[]> {
    // One `= ANY($1)` round-trip for the whole list rather than one information_schema
    // query per table. All four call sites pass the policy's entire table list, and
    // information_schema never plans cheaply, so a 20-table policy would otherwise pay
    // 20 sequential catalog round-trips before the request could get any further.
    // `missing` is still built by walking tableNames in its original order, so the
    // ordering and any duplicates in the resulting error message are unchanged.
    const rows = timestampColumn
        ? await connection.query(
              `SELECT table_name FROM information_schema.columns WHERE table_name = ANY($1) AND column_name = $2`,
              [tableNames, timestampColumn],
          )
        : await connection.query(
              `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ANY($1)`,
              [tableNames],
          );
    const present = new Set<string>(rows.map((r: any) => r.table_name as string));
    return tableNames.filter((tableName) => !present.has(tableName));
}

export const getDataRetentionPolicies = async (_req: Request, res: Response) => {
    try {
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({}, 'Data retention policy list aborted: fleet database not available');
            return res.status(503).json({ success: false, message: 'Fleet database not available' });
        }

        const policyRepo = ds[1].getRepository(DataRetentionPolicy);
        const policies = await policyRepo.find();
        logger.debug({ count: policies.length }, 'Data retention policies retrieved');
        return res.json({ success: true, data: policies });
    } catch (error) {
        logger.error({ err: error }, 'Failed to fetch data retention policies');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

export const createDataRetentionPolicy = async (req: Request, res: Response) => {
    const rawTableNames = req.body?.tableNames;
    // req.body is guaranteed non-null by the global express.json() middleware, but
    // destructure defensively (Coverity REVERSE_INULL) so this doesn't rely on that
    // middleware-ordering knowledge being obvious from inside this file.
    const { databaseName, retentionType, rowCountLimit, retentionDays, scheduleType, cronExpression, cleanupTime } = req.body ?? {};
    const timestampColumn = normalizeIdentifier(req.body?.timestampColumn) || undefined;

    if (!rawTableNames || !Array.isArray(rawTableNames) || rawTableNames.length === 0) {
        return res.status(400).json({ success: false, message: 'Please select at least one table.' });
    }
    const tableNames = rawTableNames.map(normalizeIdentifier).filter((t: string) => t.length > 0);
    if (tableNames.length === 0) {
        return res.status(400).json({ success: false, message: 'Please select at least one table.' });
    }

    const hasBlacklisted = tableNames.some((table: string) => SYSTEM_BLACKLIST.includes(table));
    if (hasBlacklisted) {
        logger.warn({ tableNames, userId: (req as any).jwtPayload?.id ?? null }, 'Data retention policy creation blocked: request included blacklisted table(s)');
        return res.status(403).json({ success: false, message: 'One or more tables are blacklisted from retention policies.' });
    }

    const validationError = validatePolicySchedulingInput(retentionDays, cronExpression, retentionType, rowCountLimit);
    if (validationError) {
        return res.status(400).json({ success: false, message: validationError });
    }

    try {
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({}, 'Data retention policy creation aborted: fleet database not available');
            return res.status(503).json({ success: false, message: 'Fleet database not available' });
        }

        const connection = databaseName === DB_SOURCE_PRIMARY ? ds[0] : ds[1];

        // Verify every selected table (and the timestamp column, if given) actually
        // exists — run unconditionally, not only when timestampColumn was supplied,
        // otherwise an unvalidated table name is stored as-is.
        const missingTables = await validateTablesExist(connection, tableNames, timestampColumn);
        if (missingTables.length > 0) {
            return res.status(400).json({
                success: false,
                message: timestampColumn
                    ? `The selected timestamp column '${timestampColumn}' does not exist in the following tables: ${missingTables.join(', ')}. Please deselect these tables or choose a different column.`
                    : `The following tables do not exist: ${missingTables.join(', ')}.`,
            });
        }

        const policyRepo = ds[1].getRepository(DataRetentionPolicy);

        // Conflict Validation: Ensure tables are not already managed by another policy
        const existingPolicies = await policyRepo.find();
        const conflictingTables = tableNames.filter(t => 
            existingPolicies.some(p => p.tableNames.includes(t))
        );

        if (conflictingTables.length > 0) {
            return res.status(400).json({
                success: false,
                message: `Warning: The following tables are already managed by another Data Retention policy: ${conflictingTables.join(', ')}. Please remove them to avoid conflicts.`
            });
        }
        
        const policy = new DataRetentionPolicy();
        policy.tableNames = tableNames;
        policy.databaseName = databaseName || DB_SOURCE_FLEET;
        policy.timestampColumn = timestampColumn || 'unixtime';
        policy.retentionType = retentionType || 'time';
        policy.rowCountLimit = rowCountLimit === 0 ? null : rowCountLimit;
        policy.retentionDays = retentionDays === 0 ? null : retentionDays; // 0 means forever
        policy.scheduleType = scheduleType || 'daily';
        policy.cronExpression = cronExpression || CRON_DAILY_AT_MIDNIGHT;
        policy.cleanupTime = cleanupTime || DEFAULT_RETENTION_CLEANUP_TIME;

        await policyRepo.save(policy);

        const liveService = getDataRetentionServiceInstance();
        if (liveService) {
            liveService.scheduleJob(policy);
        } else {
            logger.warn({ policyId: policy.id }, 'Data retention policy saved but no running service instance to schedule it in; it will take effect after the next service restart');
        }

        // Audit Logging
        const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
        const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
        
        if (jwtPayload?.id) {
            await logAuditTrail({
                action: 'DATA_RETENTION_UPDATE',
                status: 'success',
                userId: jwtPayload.id,
                email: jwtPayload.email ?? null,
                ipAddress: clientIp,
                userAgent: req.get('user-agent') || null,
                details: { tableNames, newRetentionDays: policy.retentionDays, cronExpression: policy.cronExpression },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        logger.info({ policyId: policy.id, tableNames }, 'Data retention policy created');
        return res.json({ success: true, data: policy });
    } catch (error) {
        logger.error({ err: error, tableNames }, 'Failed to create data retention policy');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

export const updateDataRetentionPolicy = async (req: Request, res: Response) => {
    const id = parseInt(req.params.id as string);
    const rawTableNames = req.body?.tableNames;
    // req.body is guaranteed non-null by the global express.json() middleware, but
    // destructure defensively (Coverity REVERSE_INULL) so this doesn't rely on that
    // middleware-ordering knowledge being obvious from inside this file.
    const { databaseName, retentionType, rowCountLimit, retentionDays, scheduleType, cronExpression, cleanupTime } = req.body ?? {};
    const timestampColumn = normalizeIdentifier(req.body?.timestampColumn) || undefined;

    if (!rawTableNames || !Array.isArray(rawTableNames) || rawTableNames.length === 0) {
        return res.status(400).json({ success: false, message: 'Please select at least one table.' });
    }
    const tableNames = rawTableNames.map(normalizeIdentifier).filter((t: string) => t.length > 0);
    if (tableNames.length === 0) {
        return res.status(400).json({ success: false, message: 'Please select at least one table.' });
    }

    const hasBlacklisted = tableNames.some((table: string) => SYSTEM_BLACKLIST.includes(table));
    if (hasBlacklisted) {
        logger.warn({ policyId: id, tableNames, userId: (req as any).jwtPayload?.id ?? null }, 'Data retention policy update blocked: request included blacklisted table(s)');
        return res.status(403).json({ success: false, message: 'One or more tables are blacklisted from retention policies.' });
    }

    const validationError = validatePolicySchedulingInput(retentionDays, cronExpression, retentionType, rowCountLimit);
    if (validationError) {
        return res.status(400).json({ success: false, message: validationError });
    }

    try {
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({ policyId: id }, 'Data retention policy update aborted: fleet database not available');
            return res.status(503).json({ success: false, message: 'Fleet database not available' });
        }

        const connection = databaseName === DB_SOURCE_PRIMARY ? ds[0] : ds[1];

        // Verify every selected table (and the timestamp column, if given) actually
        // exists — run unconditionally, not only when timestampColumn was supplied.
        const missingTables = await validateTablesExist(connection, tableNames, timestampColumn);
        if (missingTables.length > 0) {
            return res.status(400).json({
                success: false,
                message: timestampColumn
                    ? `The selected timestamp column '${timestampColumn}' does not exist in the following tables: ${missingTables.join(', ')}. Please deselect these tables or choose a different column.`
                    : `The following tables do not exist: ${missingTables.join(', ')}.`,
            });
        }

        const policyRepo = ds[1].getRepository(DataRetentionPolicy);

        // Conflict Validation: Ensure tables are not already managed by another policy (excluding this one)
        const existingPolicies = await policyRepo.find();
        const conflictingTables = tableNames.filter(t => 
            existingPolicies.some(p => p.id !== id && p.tableNames.includes(t))
        );

        if (conflictingTables.length > 0) {
            return res.status(400).json({
                success: false,
                message: `Warning: The following tables are already managed by another Data Retention policy: ${conflictingTables.join(', ')}. Please remove them to avoid conflicts.`
            });
        }

        const policy = await policyRepo.findOne({ where: { id } });
        
        if (!policy) {
            return res.status(404).json({ success: false, message: 'Policy not found' });
        }
        
        policy.tableNames = tableNames;
        policy.databaseName = databaseName || DB_SOURCE_FLEET;
        policy.timestampColumn = timestampColumn || 'unixtime';
        policy.retentionType = retentionType || 'time';
        policy.rowCountLimit = rowCountLimit === 0 ? null : rowCountLimit;
        policy.retentionDays = retentionDays === 0 ? null : retentionDays;
        policy.scheduleType = scheduleType || 'daily';
        policy.cronExpression = cronExpression || CRON_DAILY_AT_MIDNIGHT;
        policy.cleanupTime = cleanupTime || DEFAULT_RETENTION_CLEANUP_TIME;

        await policyRepo.save(policy);

        const liveService = getDataRetentionServiceInstance();
        if (liveService) {
            liveService.scheduleJob(policy);
        } else {
            logger.warn({ policyId: id }, 'Data retention policy saved but no running service instance to re-schedule it in; changes will take effect after the next service restart');
        }

        // Audit Logging
        const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
        const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';

        if (jwtPayload?.id) {
            await logAuditTrail({
                action: 'DATA_RETENTION_UPDATE',
                status: 'success',
                userId: jwtPayload.id,
                email: jwtPayload.email ?? null,
                ipAddress: clientIp,
                userAgent: req.get('user-agent') || null,
                details: { updatedPolicyId: id, tableNames, newRetentionDays: policy.retentionDays, cronExpression: policy.cronExpression },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        logger.info({ policyId: id, tableNames }, 'Data retention policy updated');
        return res.json({ success: true, data: policy });
    } catch (error) {
        logger.error({ err: error, policyId: id, tableNames }, 'Failed to update data retention policy');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

export const deleteDataRetentionPolicy = async (req: Request, res: Response) => {
    const id = parseInt(req.params.id as string);
    try {
        const ds = dbSourceConnection();
        if (!ds || ds.length < 2 || !ds[1].isInitialized) {
            logger.warn({ policyId: id }, 'Data retention policy deletion aborted: fleet database not available');
            return res.status(503).json({ success: false, message: 'Fleet database not available' });
        }

        const policyRepo = ds[1].getRepository(DataRetentionPolicy);
        const policy = await policyRepo.findOne({ where: { id } });
        if (!policy) {
            return res.status(404).json({ success: false, message: 'Policy not found' });
        }

        await policyRepo.remove(policy);
        getDataRetentionServiceInstance()?.unscheduleJob(id);

        // Audit Logging
        const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
        const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
        if (jwtPayload?.id) {
            await logAuditTrail({
                action: 'DATA_RETENTION_UPDATE',
                status: 'success',
                userId: jwtPayload.id,
                email: jwtPayload.email ?? null,
                ipAddress: clientIp,
                userAgent: req.get('user-agent') || null,
                details: { deletedPolicyId: id, tableNames: policy.tableNames },
            }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
        }

        logger.info({ policyId: id }, 'Data retention policy deleted');
        return res.json({ success: true });
    } catch (error) {
        logger.error({ err: error, policyId: id }, 'Failed to delete data retention policy');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

export const getDatabases = async (_req: Request, res: Response) => {
    logger.debug({ count: 2 }, 'Available databases listed');
    return res.json({ success: true, data: [DB_SOURCE_PRIMARY, DB_SOURCE_FLEET] });
};

export const getTables = async (req: Request, res: Response) => {
    const dbName = req.params.db;
    try {
        const ds = dbSourceConnection();
        if (!ds) {
            logger.warn({ db: dbName }, 'Retention-eligible table listing aborted: database not available');
            return res.status(503).json({ success: false, message: 'Database not available' });
        }
        const connection = dbName === DB_SOURCE_PRIMARY ? ds[0] : ds[1];

        if (!connection || !connection.isInitialized) {
            logger.warn({ db: dbName }, 'Retention-eligible table listing aborted: database not available');
            return res.status(503).json({ success: false, message: 'Database not available' });
        }

        const tables = await connection.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'");
        const tableNames = tables.map((t: any) => t.table_name).filter((name: string) => !SYSTEM_BLACKLIST.includes(name));

        logger.debug({ db: dbName, count: tableNames.length }, 'Retention-eligible tables retrieved');
        return res.json({ success: true, data: tableNames });
    } catch (error) {
        logger.error({ err: error, db: dbName }, 'Failed to fetch tables');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

export const getColumns = async (req: Request, res: Response) => {
    const { db, table } = req.params;
    try {
        const ds = dbSourceConnection();
        if (!ds) {
            logger.warn({ db, table }, 'Retention-eligible column listing aborted: database not available');
            return res.status(503).json({ success: false, message: 'Database not available' });
        }
        const connection = db === DB_SOURCE_PRIMARY ? ds[0] : ds[1];

        if (!connection || !connection.isInitialized) {
            logger.warn({ db, table }, 'Retention-eligible column listing aborted: database not available');
            return res.status(503).json({ success: false, message: 'Database not available' });
        }

        const columns = await connection.query(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = $1 AND data_type IN ('timestamp with time zone', 'timestamp without time zone', 'date', 'bigint', 'integer')",
            [table]
        );
        
        const filteredColumns = columns.filter((c: any) => {
            const isNumeric = c.data_type === 'bigint' || c.data_type === 'integer';
            if (isNumeric) {
                const name = c.column_name.toLowerCase();
                return name.includes('time') || name.includes('date') || name.includes('stamp') || name.includes('created') || name.includes('updated');
            }
            return true; // Keep all actual timestamp/date types
        });
        
        const columnNames = filteredColumns.map((c: any) => c.column_name);

        logger.debug({ db, table, count: columnNames.length }, 'Retention-eligible columns retrieved');
        return res.json({ success: true, data: columnNames });
    } catch (error) {
        logger.error({ err: error, db, table }, 'Failed to fetch columns');
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};
