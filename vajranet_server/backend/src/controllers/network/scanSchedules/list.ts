import { Request, Response } from 'express';
import { In } from 'typeorm';
import { dbSourceConnection } from '../../../index';
import { ScanSchedule } from '../../../orm/entities/fleet/ScanSchedule';
import { getUserNodeScope, scopeGroupIds } from '../../../utils/nodeScope';
import type { JwtPayload } from '../../../types/JwtPayload';
import { getLogger } from '../../../utils/logger';

const logger = getLogger('network.scanSchedules.list');

export async function listSchedules(req: Request, res: Response) {
  try {
    const jwtPayload = (req as unknown as { jwtPayload?: JwtPayload }).jwtPayload;
    if (!jwtPayload?.id) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Intentionally resolves the raw NodeScope (getUserNodeScope) rather than
    // going through resolveScannerGroupContext: that helper resolves to a
    // single target scope and 400s a caller who reads/acts on more than one
    // group (correct for the single-config-row Nessus/OpenVAS/Burp use case
    // it was built for). A schedule list is not a single row — a Group Admin
    // of several groups must see the union of every one of those groups'
    // schedules in one response, so this filters directly on scopeGroupIds
    // instead of forcing a single-group disambiguation.
    const scope = await getUserNodeScope(jwtPayload.id);

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn('Fleet database not available while listing scan schedules');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const repo = fleetDb.getRepository(ScanSchedule);
    const schedules = scope.unrestricted
      ? await repo.find({ order: { createdAt: 'DESC' } })
      : await repo.find({ where: { groupId: In(scopeGroupIds(scope)) }, order: { createdAt: 'DESC' } });

    logger.debug({ count: schedules.length }, 'Scan schedules listed');
    return res.status(200).json({ success: true, schedules });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list scan schedules');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
