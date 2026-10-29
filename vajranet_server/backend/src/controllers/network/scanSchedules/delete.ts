import { Request, Response } from 'express';
import { dbSourceConnection } from '../../../index';
import { ScanSchedule } from '../../../orm/entities/fleet/ScanSchedule';
import { getScanSchedulerServiceInstance } from '../../../services/scanSchedulerService';
import { logAuditTrail } from '../../../utils/auditTrailLogger';
import { JwtPayload } from '../../../types/JwtPayload';
import { getLogger } from '../../../utils/logger';
import { resolveScannerGroupContext } from '../../../utils/scannerScope';
import { canActOnGroup } from '../../../utils/nodeScope';

const logger = getLogger('network.scanSchedules.delete');

export async function deleteSchedule(req: Request, res: Response) {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      logger.warn({ status: scopeResult.status, message: scopeResult.message }, 'Scan schedule delete rejected: group scope resolution failed');
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { scope } = scopeResult.ctx;

    const id = parseInt(req.params.id as string, 10);
    if (!Number.isFinite(id)) {
      logger.warn({ rawId: req.params.id }, 'Scan schedule delete rejected: invalid schedule id');
      return res.status(400).json({ success: false, message: 'Invalid schedule id.' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ scheduleId: id }, 'Fleet database not available while deleting scan schedule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const repo = fleetDb.getRepository(ScanSchedule);
    const schedule = await repo.findOne({ where: { id } });
    if (!schedule) {
      logger.warn({ scheduleId: id }, 'Scan schedule delete requested for a schedule that does not exist');
      return res.status(404).json({ success: false, message: 'Schedule not found.' });
    }

    if (schedule.groupId === null) {
      if (!scope.unrestricted) {
        logger.warn({ scheduleId: id }, 'Scan schedule delete rejected: caller cannot manage a Super Administrator-owned schedule');
        return res.status(403).json({ success: false, message: 'Only a Super Administrator can manage this schedule.' });
      }
    } else if (!canActOnGroup(scope, schedule.groupId)) {
      logger.warn({ scheduleId: id, groupId: schedule.groupId }, 'Scan schedule delete rejected: caller cannot act on this schedule\'s group');
      return res.status(403).json({ success: false, message: 'You do not have access to this group.' });
    }

    // markDeleted (not just cancelJob) also signals any in-flight run for this
    // schedule to stop launching further child scans/alerts once it notices.
    const schedulerService = getScanSchedulerServiceInstance();
    if (schedulerService) {
      schedulerService.markDeleted(id);
    } else {
      logger.warn({ scheduleId: id }, 'Scan scheduler service not available, deleted schedule was not marked to stop any in-flight run');
    }
    await repo.remove(schedule);

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'SCAN_SCHEDULE_DELETE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { deletedScheduleId: id, name: schedule.name, target: schedule.target },
      }).catch((err) => logger.error({ err, scheduleId: id }, 'Failed to log audit trail'));
    }

    logger.info({ scheduleId: id }, 'Scan schedule deleted');
    return res.status(200).json({ success: true });
  } catch (error) {
    logger.error({ err: error, scheduleId: req.params?.id }, 'Failed to delete scan schedule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
