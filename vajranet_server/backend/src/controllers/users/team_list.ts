import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { USER_ROLES, VajraUser, DEFAULT_USER_ROLE } from '../../orm/entities/users/Users';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.teamList');

export const team_list = async (_req: Request, res: Response) => {
  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error('Database connection not established for team list');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    const repo = primaryDataSource.getRepository(VajraUser);
    const users = await repo.find({
      select: ['id', 'name', 'email', 'mobile', 'company', 'address', 'role', 'suspended', 'forcePasswordChange', 'created_at', 'updated_at'],
      order: { created_at: 'DESC' },
    });

    const membershipRows: { user_id: number; group_id: string }[] = await primaryDataSource.query(
      `SELECT user_id, group_id FROM user_group_memberships`,
    );
    const groupIdsByUser = new Map<number, string[]>();
    for (const row of membershipRows) {
      const list = groupIdsByUser.get(row.user_id) ?? [];
      list.push(row.group_id);
      groupIdsByUser.set(row.user_id, list);
    }

    logger.debug({ count: users.length }, 'Team users listed');

    return res.status(200).json({
      status: 'Success',
      data: {
        users: users.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          mobile: u.mobile,
          company: u.company,
          address: u.address,
          role: USER_ROLES.includes((u as any).role) ? (u as any).role : DEFAULT_USER_ROLE,
          suspended: Boolean(u.suspended),
          forcePasswordChange: Boolean(u.forcePasswordChange),
          groupIds: groupIdsByUser.get(u.id) ?? [],
          created_at: u.created_at,
          updated_at: u.updated_at,
        })),
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list team users');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

