import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { GROUP_MEMBERSHIP_ROLES, GROUP_MEMBERSHIP_ROLE_ADMIN, type GroupMembershipRole } from '../../orm/entities/users/UserGroupMembership';
import { getLogger } from '../../utils/logger';

const logger = getLogger('endpointGroups.assignUsers');

function normalizeMembershipRole(value: unknown): GroupMembershipRole {
  return (GROUP_MEMBERSHIP_ROLES as readonly string[]).includes(value as string)
    ? (value as GroupMembershipRole)
    : GROUP_MEMBERSHIP_ROLE_ADMIN;
}

export async function get_group_users(req: Request, res: Response) {
  try {
    const { id } = req.params;
    if (!id) {
      logger.warn('Group users lookup rejected: missing group id');
      return res.status(400).json({ error: 'Group ID is required' });
    }

    const dataSources = dbSourceConnection();
    const primaryDb = dataSources?.[0];
    if (!primaryDb) {
      logger.warn({ groupId: id }, 'Primary database not available while fetching group users');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const users = await primaryDb.query(
      `SELECT u.id, u.name, u.email, u.role, ugm.role AS membership_role
       FROM user_group_memberships ugm
       JOIN vajra_users u ON u.id = ugm.user_id
       WHERE ugm.group_id = $1
       ORDER BY u.name`,
      [id],
    );

    logger.debug({ groupId: id, count: users.length }, 'Group users retrieved');
    return res.status(200).json({ success: true, users });
  } catch (error) {
    logger.error({ err: error, groupId: req.params?.id }, 'Failed to fetch group users');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}

/**
 * Body:
 *  - userIds: number[] — full replace-set of this group's membership.
 *  - roles?: Record<userId, 'Group Admin' | 'Group Viewer'> — per-user access
 *    level within this group ('Group Admin' = read + act, 'Group Viewer' =
 *    read only; see canActOnGroup()/assertCanActOnHost() in utils/nodeScope.ts).
 *    Omitted or invalid entries default to 'Group Admin'.
 */
export async function assign_users(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const { userIds, roles } = req.body as { userIds?: unknown; roles?: Record<string, unknown> };

    if (!id || !Array.isArray(userIds)) {
      logger.warn({ groupId: id }, 'Assign users to group rejected: invalid payload');
      return res.status(400).json({ error: 'Invalid payload' });
    }

    const dataSources = dbSourceConnection();
    const primaryDb = dataSources?.[0];
    if (!primaryDb) {
      logger.warn({ groupId: id }, 'Primary database not available while assigning users to group');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const numericUserIds = userIds
      .map((u: unknown) => Number(u))
      .filter((n: number) => Number.isInteger(n) && n > 0);

    if (numericUserIds.length !== userIds.length) {
      logger.warn(
        { groupId: id, submittedCount: userIds.length, validCount: numericUserIds.length },
        'Some userIds were invalid and silently dropped while assigning users to group',
      );
    }

    await primaryDb.transaction(async (manager) => {
      // Replace-set: remove all current membership for this group, then re-add.
      try {
        await manager.query(`DELETE FROM user_group_memberships WHERE group_id = $1`, [id]);
      } catch (err) {
        logger.error({ err, groupId: id, step: 'clear_existing_memberships' }, 'Failed to clear existing group memberships');
        throw err;
      }

      if (numericUserIds.length > 0) {
        const values = numericUserIds.map((_uid: number, i: number) => `($1, $${i * 2 + 2}, $${i * 2 + 3})`).join(', ');
        const params = numericUserIds.flatMap((uid) => [uid, normalizeMembershipRole(roles?.[String(uid)])]);
        try {
          await manager.query(
            `INSERT INTO user_group_memberships (group_id, user_id, role) VALUES ${values}
             ON CONFLICT (user_id, group_id) DO NOTHING`,
            [id, ...params],
          );
        } catch (err) {
          logger.error({ err, groupId: id, step: 'insert_new_memberships' }, 'Failed to insert new group memberships');
          throw err;
        }
      }
    });

    logger.info({ groupId: id, count: numericUserIds.length }, 'Users assigned to group');
    return res.status(200).json({ success: true, message: 'Users assigned successfully' });
  } catch (error) {
    logger.error({ err: error, groupId: req.params?.id }, 'Failed to assign users to group');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
