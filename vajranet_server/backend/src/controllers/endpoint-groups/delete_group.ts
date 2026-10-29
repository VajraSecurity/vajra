import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { getLogger } from '../../utils/logger';

const logger = getLogger('endpointGroups.delete');

export async function delete_group(req: Request, res: Response) {
  try {
    const { id } = req.params;
    
    if (!id) {
      logger.debug('Endpoint group delete rejected: missing group id');
      return res.status(400).json({ error: 'Group ID is required' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];

    if (!fleetDb) {
      logger.warn({ groupId: id }, 'Fleet database not available while deleting endpoint group');
      return res.status(500).json({ error: 'Database connection error' });
    }

    // Steps 1-3 run in a single transaction so a failure partway through
    // never leaves nodes/rules pointing at a group_id that no longer exists.
    try {
      await fleetDb.transaction(async (manager) => {
        // 1. Delete the group row itself (EndpointGroup maps to the nodes_groups table).
        await manager.getRepository(EndpointGroup).delete({ groupId: id as string });

        // 2. Release every node this group owned, so none of them are left
        // pointing at a group_id that no longer exists.
        const removeQuery = `
          UPDATE nodes
          SET owner_group_id = NULL, group_ids = '[]'::jsonb
          WHERE owner_group_id = $1
        `;
        await manager.query(removeQuery, [id]);

        // 3. Delete any auto-assignment rules targeting this group. Same fleet DB as
        // nodes/EndpointGroup, so this is a plain follow-up query, not a best-effort
        // cross-DB cleanup like step 4. Without it, a rule left enabled keeps matching
        // new unassigned nodes on every cron run and sets their owner_group_id to a
        // group that no longer exists in nodes_groups — those nodes become invisible to
        // every group admin, while the rule's match count keeps climbing.
        await manager.query(`DELETE FROM node_assignment_rules WHERE group_id = $1`, [id]);
      });
    } catch (err) {
      logger.error({ err, groupId: id, step: 'delete_group_transaction' }, 'Failed to delete endpoint group and clean up dependent rows');
      throw err;
    }

    // 4. Remove user<->group memberships for this group (primary DB — separate
    // connection, no cross-DB transaction possible). Best-effort: an orphaned
    // membership row just means a slightly stale/over-restrictive scope, which
    // is fail-safe, not fail-open.
    try {
      const primaryDb = dataSources?.[0];
      if (primaryDb) {
        await primaryDb.query(`DELETE FROM user_group_memberships WHERE group_id = $1`, [id]);
      } else {
        logger.warn({ groupId: id, step: 'delete_memberships' }, 'Primary database not available, user_group_memberships for deleted group were not cleaned up');
      }
    } catch (membershipCleanupError) {
      logger.error({ err: membershipCleanupError, groupId: id }, 'Failed to clean up user_group_memberships after group deletion');
    }

    logger.info({ groupId: id }, 'Endpoint group deleted');
    return res.status(200).json({ success: true, message: 'Group deleted successfully' });
  } catch (error) {
    logger.error({ err: error, groupId: req.params?.id }, 'Failed to delete endpoint group');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
