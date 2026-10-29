import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { EndpointGroup } from '../../orm/entities/fleet/EndpointGroup';
import { getUserNodeScope, scopeGroupIds } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';

const logger = getLogger('endpointGroups.get');

export async function get_groups(req: Request, res: Response) {
  try {
    const dataSources = dbSourceConnection();
    const fleetDb = dataSources?.[1];

    if (!fleetDb) {
      logger.warn('Fleet database not available while fetching endpoint groups');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };

    const groupRepository = fleetDb.getRepository(EndpointGroup);
    const allGroups = await groupRepository.find({ order: { createdAt: 'DESC' } });
    // Non-Super-Admin callers only see the groups they are a member of. The id list is
    // hoisted into a Set outside the filter callback so the membership test is O(n+m).
    const visibleGroupIds = scope.unrestricted ? null : new Set(scopeGroupIds(scope));
    const groups = visibleGroupIds === null
      ? allGroups
      : allGroups.filter((g) => visibleGroupIds.has(g.groupId));
    // Node counts per group, restricted to the groups this response actually renders.
    // The `WHERE group_ids ?| $1` predicate is what matters: without it the aggregate is
    // a full seq scan of `nodes`, whose heap is badly bloated, and `?|` is what lets the
    // existing GIN index idx_nodes_group_ids turn it into a bitmap scan instead.
    //
    // Restricting to the rendered groups is safe because the only counts ever read are
    // nodeCounts.get(g.groupId) for g in `groups`. A node overlapping none of them could
    // only contribute to keys this response never looks up.
    //
    // `?|` matches string array elements only. group_ids must therefore stay a JSON array
    // of strings — jsonb_build_array($1::text) in nodeAutoAssignService,
    // JSON.stringify([id]) in assign_nodes.
    // confirms all 17 stored elements are strings.)
    const nodeCounts = new Map<string, number>();
    if (groups.length > 0) {
      const nodeCountsRaw = await fleetDb.query(
        `
          SELECT group_id, count(*) as count
          FROM nodes, jsonb_array_elements_text(COALESCE(group_ids, '[]'::jsonb)) as group_id
          WHERE group_ids ?| $1
          GROUP BY group_id
        `,
        [groups.map((g) => g.groupId)],
      );
      for (const row of nodeCountsRaw as { group_id: string; count: string }[]) {
        nodeCounts.set(row.group_id, parseInt(row.count));
      }
    }

    const enrichedGroups = groups.map(g => ({
      ...g,
      nodeCount: nodeCounts.get(g.groupId) || 0
    }));

    logger.debug({ count: enrichedGroups.length }, 'Endpoint groups retrieved');
    return res.status(200).json({ success: true, groups: enrichedGroups });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch endpoint groups');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
