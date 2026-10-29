import { Request, Response } from 'express';
import { dbSourceConnection } from '../../../index';
import { ScanSchedule } from '../../../orm/entities/fleet/ScanSchedule';
import { isValidScheduleCidr } from '../nmapController';
import { resolveCronExpression, getScanSchedulerServiceInstance } from '../../../services/scanSchedulerService';
import { validateKnownIps } from './validate';
import { logAuditTrail } from '../../../utils/auditTrailLogger';
import { JwtPayload } from '../../../types/JwtPayload';
import { getLogger } from '../../../utils/logger';
import { SCAN_SCHEDULE_FREQUENCY_PRESETS } from '../../../consts/scanning';
import { resolveScannerGroupContext } from '../../../utils/scannerScope';
import { canActOnGroup } from '../../../utils/nodeScope';

const logger = getLogger('network.scanSchedules.update');

const VALID_FREQUENCY_PRESETS: readonly string[] = SCAN_SCHEDULE_FREQUENCY_PRESETS;

export async function updateSchedule(req: Request, res: Response) {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: true });
    if (!scopeResult.ok) {
      logger.warn({ status: scopeResult.status, message: scopeResult.message }, 'Scan schedule update rejected: group scope resolution failed');
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { scope } = scopeResult.ctx;

    const id = parseInt(req.params.id as string, 10);
    if (!Number.isFinite(id)) {
      logger.warn({ rawId: req.params.id }, 'Scan schedule update rejected: invalid schedule id');
      return res.status(400).json({ success: false, message: 'Invalid schedule id.' });
    }

    const { name, target, frequencyPreset, cronExpression, reason, enabled, knownIps } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      logger.warn({ scheduleId: id }, 'Scan schedule update rejected: missing name');
      return res.status(400).json({ success: false, message: 'Schedule name is required.' });
    }
    if (!isValidScheduleCidr(target)) {
      logger.warn({ scheduleId: id, target }, 'Scan schedule update rejected: invalid target CIDR');
      return res.status(400).json({ success: false, message: 'Target must be a private CIDR of /16 or smaller (e.g. 10.0.0.0/16 or 10.0.5.0/24).' });
    }
    if (!VALID_FREQUENCY_PRESETS.includes(frequencyPreset)) {
      logger.warn({ scheduleId: id, frequencyPreset }, 'Scan schedule update rejected: invalid frequency preset');
      return res.status(400).json({ success: false, message: `Frequency must be one of: ${VALID_FREQUENCY_PRESETS.join(', ')}.` });
    }
    if (!reason || typeof reason !== 'string' || !reason.trim()) {
      logger.warn({ scheduleId: id }, 'Scan schedule update rejected: missing reason');
      return res.status(400).json({ success: false, message: 'Reason is required for scheduled scans.' });
    }

    const knownIpsResult = validateKnownIps(knownIps);
    if ('error' in knownIpsResult) {
      logger.warn({ scheduleId: id, error: knownIpsResult.error }, 'Scan schedule update rejected: invalid knownIps');
      return res.status(400).json({ success: false, message: knownIpsResult.error });
    }

    let resolvedCronExpression: string;
    try {
      resolvedCronExpression = resolveCronExpression(frequencyPreset, cronExpression);
    } catch (err: any) {
      logger.warn({ scheduleId: id, frequencyPreset, err }, 'Scan schedule update rejected: failed to resolve cron expression');
      return res.status(400).json({ success: false, message: err.message });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ scheduleId: id }, 'Fleet database not available while updating scan schedule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const repo = fleetDb.getRepository(ScanSchedule);
    const schedule = await repo.findOne({ where: { id } });
    if (!schedule) {
      logger.warn({ scheduleId: id }, 'Scan schedule update requested for a schedule that does not exist');
      return res.status(404).json({ success: false, message: 'Schedule not found.' });
    }

    if (schedule.groupId === null) {
      if (!scope.unrestricted) {
        logger.warn({ scheduleId: id }, 'Scan schedule update rejected: caller cannot manage a Super Administrator-owned schedule');
        return res.status(403).json({ success: false, message: 'Only a Super Administrator can manage this schedule.' });
      }
    } else if (!canActOnGroup(scope, schedule.groupId)) {
      logger.warn({ scheduleId: id, groupId: schedule.groupId }, 'Scan schedule update rejected: caller cannot act on this schedule\'s group');
      return res.status(403).json({ success: false, message: 'You do not have access to this group.' });
    }

    // group_id is intentionally left unchanged here even if the request body
    // includes a groupId — reassigning a schedule to a different group is not
    // supported by update, only by create.
    schedule.name = name.trim();
    schedule.target = target.trim();
    schedule.frequencyPreset = frequencyPreset;
    schedule.cronExpression = resolvedCronExpression;
    schedule.reason = reason.trim();
    schedule.knownIps = knownIpsResult.knownIps;
    schedule.enabled = enabled === undefined ? schedule.enabled : Boolean(enabled);
    await repo.save(schedule);

    const scheduler = getScanSchedulerServiceInstance();
    if (scheduler) {
      if (schedule.enabled) {
        scheduler.scheduleJob(schedule);
      } else {
        scheduler.cancelJob(schedule.id);
      }
    } else {
      logger.warn({ scheduleId: schedule.id, enabled: schedule.enabled }, 'Scan scheduler service not available, schedule updated in DB but the running cron job was not re-synced');
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'SCAN_SCHEDULE_UPDATE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { scheduleId: schedule.id, name: schedule.name, target: schedule.target, enabled: schedule.enabled },
      }).catch((err) => logger.error({ err, scheduleId: schedule.id }, 'Failed to log audit trail'));
    }

    logger.info({ scheduleId: schedule.id, name: schedule.name, enabled: schedule.enabled }, 'Scan schedule updated');
    return res.status(200).json({ success: true, schedule });
  } catch (error) {
    logger.error({ err: error, scheduleId: req.params?.id }, 'Failed to update scan schedule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
