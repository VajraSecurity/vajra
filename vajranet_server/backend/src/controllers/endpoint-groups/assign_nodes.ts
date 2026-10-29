import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { getLogger } from '../../utils/logger';

const logger = getLogger('endpointGroups.assignNodes');

/**
 * Assigns nodes to a group. A node belongs to at most one group at a time
 * (owner_group_id is a single column, not a list) — assigning a node here
 * always supersedes whatever group it was in before, on any group. This is
 * what keeps a division's node set exclusive: there is no state where a node
 * can satisfy two different groups' access checks simultaneously.
 *
 * group_ids stays in sync purely for the existing UI code that reads it for
 * display (chips/labels) — it plays no part in any access decision.
 */
export async function assign_nodes(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const { nodeIdentifiers } = req.body;

    if (!id || !Array.isArray(nodeIdentifiers)) {
      logger.warn({ groupId: id }, 'Assign nodes to group rejected: invalid payload');
      return res.status(400).json({ error: 'Invalid payload' });
    }

    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];

    if (!fleetDb) {
      logger.warn({ groupId: id }, 'Fleet database not available while assigning nodes to group');
      return res.status(500).json({ error: 'Database connection error' });
    }

    // Tracks how many of the requested identifiers actually matched a node
    // row in the claim UPDATE below — nodeIdentifiers.length alone (the
    // request's own input) can't tell a caller-supplied typo/stale
    // host_identifier apart from a real assignment, since a WHERE ... = ANY()
    // match miss fails silently (0 rows affected, no thrown error).
    let matchedCount = 0;

    await fleetDb.transaction(async (manager) => {
      // Release any node this group currently owns but that isn't in the new
      // selection — otherwise a node removed from the list here would keep
      // pointing at this group forever.
      const releaseQuery = nodeIdentifiers.length > 0
        ? `UPDATE nodes
           SET owner_group_id = NULL, group_ids = '[]'::jsonb
           WHERE owner_group_id = $1 AND host_identifier != ALL($2)`
        : `UPDATE nodes
           SET owner_group_id = NULL, group_ids = '[]'::jsonb
           WHERE owner_group_id = $1`;
      try {
        await manager.query(releaseQuery, nodeIdentifiers.length > 0 ? [id, nodeIdentifiers] : [id]);
      } catch (err) {
        logger.error({ err, groupId: id, step: 'release_previous_nodes' }, 'Failed to release nodes previously owned by group');
        throw err;
      }

      // Claim the selected nodes for this group. A node already owned by a
      // DIFFERENT group is reassigned here too — assignment is exclusive by
      // design, so the newest assignment always wins.
      if (nodeIdentifiers.length > 0) {
        try {
          const [, affected] = await manager.query(
            `UPDATE nodes
             SET owner_group_id = $1, group_ids = $2::jsonb
             WHERE host_identifier = ANY($3)`,
            [id, JSON.stringify([id]), nodeIdentifiers],
          );
          matchedCount = affected ?? 0;
        } catch (err) {
          logger.error({ err, groupId: id, step: 'claim_new_nodes' }, 'Failed to claim selected nodes for group');
          throw err;
        }
      }
    });

    if (matchedCount !== nodeIdentifiers.length) {
      logger.warn(
        { groupId: id, requested: nodeIdentifiers.length, matched: matchedCount },
        'Some node identifiers in the assignment request did not match any existing node and were silently skipped',
      );
    }

    logger.info({ groupId: id, requested: nodeIdentifiers.length, matched: matchedCount }, 'Nodes assigned to group');
    return res.status(200).json({ success: true, message: 'Nodes assigned successfully' });
  } catch (error) {
    logger.error({ err: error, groupId: req.params?.id }, 'Failed to assign nodes to group');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
