import { Request, Response } from 'express';
import { dbSourceConnection } from '../../../index';
import { NetworkScanHistory } from '../../../orm/entities/fleet/NetworkScanHistory';
import { ScanSchedule } from '../../../orm/entities/fleet/ScanSchedule';
import { getLogger } from '../../../utils/logger';
import { resolveScannerGroupContext } from '../../../utils/scannerScope';
import { scopeGroupIds } from '../../../utils/nodeScope';

const logger = getLogger('network.scanSchedules.getRuns');

export async function getScheduleRuns(req: Request, res: Response) {
  try {
    const scopeResult = await resolveScannerGroupContext(req, { forWrite: false });
    if (!scopeResult.ok) {
      logger.warn({ status: scopeResult.status, message: scopeResult.message }, 'Scan schedule runs lookup rejected: group scope resolution failed');
      return res.status(scopeResult.status).json({ success: false, message: scopeResult.message });
    }
    const { scope } = scopeResult.ctx;

    const scheduleId = parseInt(req.params.id as string, 10);
    if (!Number.isFinite(scheduleId)) {
      logger.warn({ rawId: req.params.id }, 'Scan schedule runs lookup rejected: invalid schedule id');
      return res.status(400).json({ success: false, message: 'Invalid schedule id.' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn({ scheduleId }, 'Fleet database not available while fetching scan schedule runs');
      return res.status(500).json({ success: false, message: 'Database connection error' });
    }

    const scheduleRepo = fleetDb.getRepository(ScanSchedule);
    const parentSchedule = await scheduleRepo.findOne({ where: { id: scheduleId } });
    if (!parentSchedule) {
      logger.warn({ scheduleId }, 'Scan schedule runs requested for a schedule that does not exist');
      return res.status(404).json({ success: false, message: 'Schedule not found.' });
    }

    if (parentSchedule.groupId === null) {
      if (!scope.unrestricted) {
        logger.warn({ scheduleId }, 'Scan schedule runs lookup rejected: caller cannot view a Super Administrator-owned schedule');
        return res.status(403).json({ success: false, message: 'Only a Super Administrator can manage this schedule.' });
      }
    } else if (!scope.unrestricted && !scopeGroupIds(scope).includes(parentSchedule.groupId)) {
      logger.warn({ scheduleId, groupId: parentSchedule.groupId }, 'Scan schedule runs lookup rejected: caller cannot view this schedule\'s group');
      return res.status(403).json({ success: false, message: 'You do not have access to this group.' });
    }

    const repo = fleetDb.getRepository(NetworkScanHistory);
    const runs = await repo.createQueryBuilder('history')
      .where('history.schedule_id = :scheduleId', { scheduleId })
      .andWhere('history.parent_id IS NULL')
      .orderBy('history.created_at', 'DESC')
      .take(100)
      .getMany();

    const runIds = runs.map((r) => r.id);
    if (runIds.length > 0) {
      const childScans = await repo.createQueryBuilder('child')
        .where('child.parent_id IN (:...runIds)', { runIds })
        .getMany();

      // Index the child scans once, then look up per run. Scanning the childScans array
      // for every run is O(runs x children), and a scheduled /20 discovery run fans out
      // to one child row per responding host (up to MAX_EXPANDED_HOSTS), so that product
      // reaches the hundreds of thousands on a single request. childScans is walked in
      // its original order, so each bucket keeps the order a .filter() would produce.
      const childrenByParent = new Map<number, typeof childScans>();
      for (const c of childScans) {
        const parentId = Number(c.parent_id);
        const bucket = childrenByParent.get(parentId);
        if (bucket) bucket.push(c);
        else childrenByParent.set(parentId, [c]);
      }

      runs.forEach((r) => {
        (r as any).childScans = childrenByParent.get(Number(r.id)) ?? [];
      });
    }

    logger.debug({ scheduleId, count: runs.length }, 'Scan schedule runs retrieved');
    return res.status(200).json({ success: true, runs });
  } catch (error) {
    logger.error({ err: error, scheduleId: req.params?.id }, 'Failed to fetch scan schedule runs');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
