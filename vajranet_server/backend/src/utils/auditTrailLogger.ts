/**
 * Audit Trail Logger - Writes user actions to audit_trail table.
 * Used for: login (success/fail), rename node, alert status update, user register, password update (success/fail).
 */

import { dbSourceConnection } from '../index';
import { AuditTrail, AuditTrailAction, AuditTrailStatus } from '../orm/entities/audit/AuditTrail';
import { getLogger } from './logger';

const logger = getLogger('audit.auditTrailLogger');

export interface AuditTrailEntry {
  action: AuditTrailAction;
  status: AuditTrailStatus;
  userId?: number | null;
  email?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  details?: Record<string, any> | null;
}

export async function logAuditTrail(entry: AuditTrailEntry): Promise<void> {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources?.length) {
      logger.warn(
        { action: entry.action, status: entry.status, userId: entry.userId, email: entry.email },
        'Skipped audit_trail write: no database source available',
      );
      return;
    }
    const ds = dbSources[0];
    const repo = ds.getRepository(AuditTrail);
    const record = repo.create({
      action: entry.action,
      status: entry.status,
      userId: entry.userId ?? null,
      email: entry.email ?? null,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      details: entry.details ?? null,
    });
    await repo.save(record);
  } catch (err) {
    logger.error(
      { err, action: entry.action, status: entry.status, userId: entry.userId, email: entry.email },
      'Failed to write audit_trail',
    );
  }
}
