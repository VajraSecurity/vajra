import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { getLogger } from '../../utils/logger';

const logger = getLogger('endpointGroups.create');

export async function create_group(req: Request, res: Response) {
  try {
    const { name, organisation, manager } = req.body;
    if (!name) {
      logger.debug('Endpoint group create rejected: missing name');
      return res.status(400).json({ error: 'Name is required' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];

    if (!fleetDb) {
      logger.warn({ name }, 'Fleet database not available while creating endpoint group');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const groupRepository = fleetDb.getRepository(EndpointGroup);
    
    const newGroup = groupRepository.create({
      name,
      organisation: organisation || '',
      manager: manager || '',
      createdBy: (req as any).jwtPayload?.email ?? 'unknown',
      groupId: `group_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      unixtime: Date.now().toString()
    });

    await groupRepository.save(newGroup);

    logger.info({ groupId: newGroup.groupId, name: newGroup.name }, 'Endpoint group created');
    return res.status(201).json({ success: true, group: newGroup });
  } catch (error) {
    logger.error({ err: error, name: req.body?.name }, 'Failed to create endpoint group');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
