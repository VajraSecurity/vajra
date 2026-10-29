/**
 * Audit Logger - Logs sensitive operations for compliance and security
 * Persists to database and optionally logs to console
 */

import { dbSourceConnection } from '../index';
import { AuditLog, AuditAction } from '../orm/entities/audit/AuditLog';
import { getLogger } from './logger';

const logger = getLogger('audit.auditLogger');

export interface AuditLogEntry {
  timestamp: Date;
  action: AuditAction;
  userId?: number;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  status: 'success' | 'failure';
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Log an audit event to database and console
 */
export const auditLog = async (entry: AuditLogEntry): Promise<void> => {
  const auditContext = {
    action: entry.action,
    status: entry.status,
    severity: entry.severity,
    userId: entry.userId,
    email: entry.email,
    ipAddress: entry.ipAddress,
    details: entry.details,
  };

  if (process.env.NODE_ENV === 'production') {
    if (entry.severity === 'high' || entry.severity === 'critical') {
      logger.error(auditContext, 'Audit event recorded');
    } else {
      logger.info(auditContext, 'Audit event recorded');
    }
  } else {
    logger.info(auditContext, 'Audit event recorded');
  }

  // --- PERSIST TO DATABASE ---
  try {
    const dbSources = dbSourceConnection();
    if (dbSources && dbSources.length > 0) {
      const dbConnection = dbSources[0];
      const auditLogRepository = dbConnection.getRepository(AuditLog);

      const auditLogRecord = new AuditLog();
      auditLogRecord.action = entry.action;
      auditLogRecord.status = entry.status;
      auditLogRecord.severity = entry.severity;
      auditLogRecord.userId = entry.userId || null;
      auditLogRecord.email = entry.email || null;
      auditLogRecord.ipAddress = entry.ipAddress || null;
      auditLogRecord.userAgent = entry.userAgent || null;
      auditLogRecord.details = entry.details || null;

      await auditLogRepository.save(auditLogRecord);
    } else {
      // Mirrors auditTrailLogger.ts's logAuditTrail: without this, a
      // compliance-relevant audit event (login, password change, ...) that
      // arrives before the DB is initialized (or after it drops out) is
      // silently dropped from persistent storage — the line above only ever
      // reaches stdout, and nothing here distinguishes "no rows to persist
      // because dbSourceConnection() returned nothing" from "persisted fine".
      logger.warn({ ...auditContext }, 'Skipped audit log persistence to database: no database source available');
    }
  } catch (err) {
    logger.error({ err, ...auditContext }, 'Failed to persist audit log to database');
  }
};

/**
 * Helper to log login attempt
 */
export const auditLoginAttempt = async (
  email: string,
  success: boolean,
  ipAddress?: string,
  userAgent?: string
): Promise<void> => {
  await auditLog({
    timestamp: new Date(),
    action: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
    email,
    status: success ? 'success' : 'failure',
    ipAddress,
    userAgent,
    severity: success ? 'low' : 'medium',
  });
};

/**
 * Helper to log password change
 */
export const auditPasswordChange = async (
  userId: number,
  email: string,
  ipAddress?: string
): Promise<void> => {
  await auditLog({
    timestamp: new Date(),
    action: 'PASSWORD_CHANGE',
    userId,
    email,
    status: 'success',
    ipAddress,
    severity: 'high',
  });
};

/**
 * Helper to log profile update
 */
export const auditProfileUpdate = async (
  userId: number,
  email: string,
  changes: Record<string, any>,
  ipAddress?: string
): Promise<void> => {
  await auditLog({
    timestamp: new Date(),
    action: 'PROFILE_UPDATE',
    userId,
    email,
    status: 'success',
    ipAddress,
    details: changes,
    severity: 'medium',
  });
};

/**
 * Helper to log logout
 */
export const auditLogout = async (
  userId: number,
  email: string,
  ipAddress?: string
): Promise<void> => {
  await auditLog({
    timestamp: new Date(),
    action: 'LOGOUT',
    userId,
    email,
    status: 'success',
    ipAddress,
    severity: 'low',
  });
};
