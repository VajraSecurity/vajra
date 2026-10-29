import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { NodeAssignmentRule } from '../../orm/entities/fleet/NodeAssignmentRule';
import { getLogger } from '../../utils/logger';

const logger = getLogger('nodeAssignmentRules.get');

export async function get_rules(_req: Request, res: Response) {
  try {
    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];
    if (!fleetDb) {
      logger.warn('Fleet database not available while fetching node assignment rules');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const ruleRepo = fleetDb.getRepository(NodeAssignmentRule);
    const rules = await ruleRepo.find({ order: { priority: 'ASC', id: 'ASC' } });

    logger.debug({ count: rules.length }, 'Node assignment rules retrieved');
    return res.status(200).json({ success: true, rules });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch node assignment rules');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
