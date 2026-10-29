import { Request, Response } from 'express';
import { dbSourceConnection } from '../../../index';
import { ScanSchedule } from '../../../orm/entities/fleet/ScanSchedule';
import { getScanSchedulerServiceInstance } from '../../../services/scanSchedulerService';
import { logAuditTrail } from '../../../utils/auditTrailLogger';
import { JwtPayload } from '../../../types/JwtPayload';
import { getLogger } from '../../../utils/logger';
import { resolveScannerGroupContext } from '../../../utils/scannerScope';
import { canActOnGroup } from '../../../utils/nodeScope';

const logger = getLogger('network.scanSchedules.runNow');

export async function runScheduleNow(req: Request, res: Response) {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      logger.warn({ status: scopeResult.status, message: scopeResult.message }, 'Manual scan schedule run rejected: group scope resolution failed');
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { scope } = scopeResult.ctx;

    const id = parseInt(req.params.id as string, 10);
    if (!Number.isFinite(id)) {
      logger.warn({ rawId: req.params.id }, 'Manual scan schedule run rejected: invalid schedule id');
      return res.status(400).json({ success: false, message: 'Invalid schedule id.' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ scheduleId: id }, 'Fleet database not available while running scan schedule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const repo = fleetDb.getRepository(ScanSchedule);
    const schedule = await repo.findOne({ where: { id } });
    if (!schedule) {
      logger.warn({ scheduleId: id }, 'Manual run requested for a scan schedule that does not exist');
      return res.status(404).json({ success: false, message: 'Schedule not found.' });
    }

    if (schedule.groupId === null) {
      if (!scope.unrestricted) {
        logger.warn({ scheduleId: id }, 'Manual scan schedule run rejected: caller cannot manage a Super Administrator-owned schedule');
        return res.status(403).json({ success: false, message: 'Only a Super Administrator can manage this schedule.' });
      }
    } else if (!canActOnGroup(scope, schedule.groupId)) {
      logger.warn({ scheduleId: id, groupId: schedule.groupId }, 'Manual scan schedule run rejected: caller cannot act on this schedule\'s group');
      return res.status(403).json({ success: false, message: 'You do not have access to this group.' });
    }

    const service = getScanSchedulerServiceInstance();
    if (!service) {
      logger.warn({ scheduleId: id }, 'Scan scheduler service not available, cannot run schedule now');
      return res.status(503).json({ success: false, message: 'Scan scheduler is not available.' });
    }

    // A full run (discovery + any advanced scans) can take minutes, so this
    // doesn't block on it — the frontend polls the schedule's last_run_* fields.
    logger.info({ scheduleId: id }, 'Manual scan schedule run triggered');
    service.runNow(id).catch((err) => logger.error({ err, scheduleId: id }, 'Manual scan schedule run failed'));

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'SCAN_SCHEDULE_RUN',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { scheduleId: id, name: schedule.name, target: schedule.target },
      }).catch((err) => logger.error({ err, scheduleId: id }, 'Failed to log audit trail'));
    }

    return res.status(202).json({ success: true, message: 'Scan schedule run started.' });
  } catch (error) {
    logger.error({ err: error, scheduleId: req.params?.id }, 'Failed to run scan schedule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
