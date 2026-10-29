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

const logger = getLogger('network.scanSchedules.create');

const VALID_FREQUENCY_PRESETS: readonly string[] = SCAN_SCHEDULE_FREQUENCY_PRESETS;

export async function createSchedule(req: Request, res: Response) {
  try {
    const scopeResult = await resolveScannerGroupContext(req);
    if (!scopeResult.ok) {
      logger.warn({ status: scopeResult.status, message: scopeResult.message }, 'Scan schedule create rejected: group scope resolution failed');
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { groupId } = scopeResult.ctx;

    const { name, target, frequencyPreset, cronExpression, reason, enabled, knownIps } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      logger.warn('Scan schedule create rejected: missing name');
      return res.status(400).json({ success: false, message: 'Schedule name is required.' });
    }
    if (!isValidScheduleCidr(target)) {
      logger.warn({ name, target }, 'Scan schedule create rejected: invalid target CIDR');
      return res.status(400).json({ success: false, message: 'Target must be a private CIDR of /16 or smaller (e.g. 10.0.0.0/16 or 10.0.5.0/24).' });
    }
    if (!VALID_FREQUENCY_PRESETS.includes(frequencyPreset)) {
      logger.warn({ name, frequencyPreset }, 'Scan schedule create rejected: invalid frequency preset');
      return res.status(400).json({ success: false, message: `Frequency must be one of: ${VALID_FREQUENCY_PRESETS.join(', ')}.` });
    }
    if (!reason || typeof reason !== 'string' || !reason.trim()) {
      logger.warn({ name }, 'Scan schedule create rejected: missing reason');
      return res.status(400).json({ success: false, message: 'Reason is required for scheduled scans.' });
    }

    const knownIpsResult = validateKnownIps(knownIps);
    if ('error' in knownIpsResult) {
      logger.warn({ name, error: knownIpsResult.error }, 'Scan schedule create rejected: invalid knownIps');
      return res.status(400).json({ success: false, message: knownIpsResult.error });
    }

    let resolvedCronExpression: string;
    try {
      resolvedCronExpression = resolveCronExpression(frequencyPreset, cronExpression);
    } catch (err: any) {
      logger.warn({ name, frequencyPreset, err }, 'Scan schedule create rejected: failed to resolve cron expression');
      return res.status(400).json({ success: false, message: err.message });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ name, target }, 'Fleet database not available while creating scan schedule');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

    const repo = fleetDb.getRepository(ScanSchedule);
    const schedule = repo.create({
      groupId,
      name: name.trim(),
      enabled: enabled === undefined ? true : Boolean(enabled),
      target: target.trim(),
      frequencyPreset,
      cronExpression: resolvedCronExpression,
      reason: reason.trim(),
      knownIps: knownIpsResult.knownIps,
      createdByUserId: jwtPayload?.id ?? null,
      createdByName: jwtPayload?.name ?? null,
    });
    const saved = await repo.save(schedule);

    const schedulerService = getScanSchedulerServiceInstance();
    if (schedulerService) {
      schedulerService.scheduleJob(saved);
    } else {
      logger.warn({ scheduleId: saved.id }, 'Scan scheduler service not available, new schedule saved to DB but not registered with the running cron job');
    }

    if (jwtPayload?.id) {
      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
      await logAuditTrail({
        action: 'SCAN_SCHEDULE_CREATE',
        status: 'success',
        userId: jwtPayload.id,
        email: jwtPayload.email ?? null,
        ipAddress: clientIp,
        userAgent: req.get('user-agent') || null,
        details: { scheduleId: saved.id, name: saved.name, target: saved.target, cronExpression: saved.cronExpression },
      }).catch((err) => logger.error({ err, scheduleId: saved.id }, 'Failed to log audit trail'));
    }

    logger.info({ scheduleId: saved.id, name: saved.name }, 'Scan schedule created');
    return res.status(200).json({ success: true, schedule: saved });
  } catch (error) {
    logger.error({ err: error, name: req.body?.name, target: req.body?.target }, 'Failed to create scan schedule');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
