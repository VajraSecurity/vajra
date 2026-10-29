import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { USER_ROLES, UserRole, VajraUser, SUPER_ADMIN_ROLE } from '../../orm/entities/users/Users';
import { GROUP_MEMBERSHIP_ROLE_ADMIN } from '../../orm/entities/users/UserGroupMembership';
import { normalizeEmail } from '../../utils/sanitization';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.teamUpdate');

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const normalizeString = (value: unknown): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

export const team_update = async (req: Request, res: Response) => {
  const requesterId = Number((req as any).jwtPayload?.id);
  const userId = Number(req.body?.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Valid user id is required' });
  }

  const name = normalizeString(req.body?.name);
  const email = typeof req.body?.email === 'string' ? normalizeEmail(req.body.email) || undefined : undefined;
  const mobile = normalizeString(req.body?.mobile);
  const company = normalizeString(req.body?.company);
  const address = normalizeString(req.body?.address);
  const role = normalizeString(req.body?.role);
  const suspended = req.body?.suspended;
  const groupIdsRaw = req.body?.groupIds;
  const groupIds: string[] | undefined = Array.isArray(groupIdsRaw)
    ? groupIdsRaw.filter((g: unknown): g is string => typeof g === 'string' && g.length > 0)
    : undefined;

  if (!name || !email || !mobile || !role || typeof suspended !== 'boolean') {
    return res.status(400).json({ status: 'Error', message: 'name, email, mobile, role, and suspended are required' });
  }

  if (!EMAIL_REGEX.test(email)) {
    return res.status(400).json({ status: 'Error', message: 'Invalid email format' });
  }

  if (!USER_ROLES.includes(role as UserRole)) {
    return res.status(400).json({
      status: 'Error',
      message: `Invalid role. Allowed roles: ${USER_ROLES.join(', ')}`,
    });
  }

  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ requesterId, userId }, 'Database connection not established for team member update');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    // The singleton-super-admin count check below and the save that acts on it
    // must be atomic — otherwise two concurrent promotions can each pass the
    // count check before either commits, leaving two Super Administrators
    // (the same invariant register.ts protects with SERIALIZABLE for the
    // bootstrap case).
    const queryRunner = primaryDataSource.createQueryRunner();
    let targetUser: VajraUser;
    let roleChanged: boolean;
    let suspensionChanged: boolean;
    let savedUser: VajraUser;
    try {
      // connect()/startTransaction() live inside this try too: if either
      // throws (transient DB error, pool exhaustion), the acquired
      // connection must still hit release() in the finally below, or a
      // string of failures here would leak it out of the pool for good.
      await queryRunner.connect();
      await queryRunner.startTransaction('SERIALIZABLE');

      const repo = queryRunner.manager.getRepository(VajraUser);
      const found = await repo.findOne({ where: { id: userId } });
      if (!found) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, userId }, 'Team update rejected: user not found');
        return res.status(404).json({ status: 'Error', message: 'User not found' });
      }
      targetUser = found;

      // Prevent the signed-in Super Administrator from changing their own role.
      if (
        Number.isInteger(requesterId) &&
        requesterId === targetUser.id &&
        targetUser.role === SUPER_ADMIN_ROLE &&
        (role as UserRole) !== SUPER_ADMIN_ROLE
      ) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, userId: targetUser.id }, 'Team update rejected: Super Administrator attempted to change own role');
        return res.status(403).json({
          status: 'Error',
          message: 'Super Administrator cannot change their own role',
        });
      }

      // Prevent the Super Administrator from suspending their own account.
      if (
        Number.isInteger(requesterId) &&
        requesterId === targetUser.id &&
        targetUser.role === SUPER_ADMIN_ROLE &&
        suspended
      ) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, userId: targetUser.id }, 'Team update rejected: Super Administrator attempted to suspend own account');
        return res.status(403).json({
          status: 'Error',
          message: 'Super Administrator cannot suspend themselves',
        });
      }

      // Enforce singleton super admin.
      // Only allow assigning Super Administrator when no other user already has it.
      if ((role as UserRole) === SUPER_ADMIN_ROLE && targetUser.role !== SUPER_ADMIN_ROLE) {
        const existingSuperAdminCount = await repo.count({
          where: { role: SUPER_ADMIN_ROLE },
        });
        if (existingSuperAdminCount > 0) {
          await queryRunner.rollbackTransaction();
          logger.warn({ requesterId, userId: targetUser.id }, 'Team update rejected: attempted to assign a second Super Administrator');
          return res.status(409).json({ status: 'Error', message: 'Only one Super Administrator is allowed' });
        }
      }

      const duplicateEmail = await repo.findOne({ where: { email } });
      if (duplicateEmail && duplicateEmail.id !== userId) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, userId, conflictingUserId: duplicateEmail.id }, 'Team update rejected: email already in use by another account');
        return res.status(409).json({ status: 'Error', message: 'Email is already used by another account' });
      }

      roleChanged = targetUser.role !== (role as UserRole);

      targetUser.name = name;
      targetUser.email = email;
      targetUser.mobile = mobile;
      targetUser.company = company ?? null;
      targetUser.address = address ?? null;
      targetUser.role = role as UserRole;
      suspensionChanged = Boolean(targetUser.suspended) !== suspended;
      targetUser.suspended = suspended;
      // Invalidate existing JWTs / WebSocket sessions when role or suspension changes,
      // so demoted users cannot keep acting with a stale access token (e.g. Viewer WS checks).
      if (suspensionChanged || roleChanged) {
        targetUser.session_version = (targetUser.session_version ?? 0) + 1;
      }

      savedUser = await repo.save(targetUser);
      await queryRunner.commitTransaction();
    } catch (err) {
      // Only rollback if a transaction actually started: connect() or
      // startTransaction() itself throwing is caught here too, and rolling back a
      // transaction that was never opened would throw a second, masking error.
      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }
      throw err;
    } finally {
      await queryRunner.release();
    }

    // Group assignment (replace-set), only when the caller explicitly sent groupIds.
    if (groupIds !== undefined) {
      try {
        await primaryDataSource.transaction(async (manager) => {
          // Read each existing membership's role BEFORE the delete below —
          // the client only ever sends group ids, never a role alongside
          // them, so re-inserting without this would silently reset every
          // existing membership to the role column's DEFAULT (Group Admin)
          // on every edit, even one that only changed e.g. the user's name —
          // upgrading an existing 'Group Viewer' to 'Group Admin' on every
          // group they already belonged to.
          const existing: { group_id: string; role: string }[] = await manager.query(
            `SELECT group_id, role FROM user_group_memberships WHERE user_id = $1`,
            [savedUser.id],
          );
          const existingRoleByGroup = new Map(existing.map((r) => [r.group_id, r.role]));

          await manager.query(`DELETE FROM user_group_memberships WHERE user_id = $1`, [savedUser.id]);
          if (groupIds.length > 0) {
            const values = groupIds.map((_g, i) => `($1, $${i * 2 + 2}, $${i * 2 + 3})`).join(', ');
            const params = groupIds.flatMap((g) => [g, existingRoleByGroup.get(g) ?? GROUP_MEMBERSHIP_ROLE_ADMIN]);
            await manager.query(
              `INSERT INTO user_group_memberships (user_id, group_id, role) VALUES ${values}
               ON CONFLICT (user_id, group_id) DO NOTHING`,
              [savedUser.id, ...params],
            );
          }
        });
      } catch (err) {
        // User fields above are already committed at this point — distinguish this
        // from a core-update failure so a 500 here isn't mistaken for the save failing.
        logger.error({ err, userId: savedUser.id, groupCount: groupIds.length }, 'Team member fields saved but group membership replace failed');
        throw err;
      }
    }

    logger.info(
      {
        userId: savedUser.id,
        requesterId,
        roleChanged,
        newRole: roleChanged ? savedUser.role : undefined,
        suspensionChanged,
        suspended: suspensionChanged ? savedUser.suspended : undefined,
      },
      'Team member updated',
    );

    return res.status(200).json({
      status: 'Success',
      message: 'Team member updated successfully',
      data: {
        user: {
          id: savedUser.id,
          name: savedUser.name,
          email: savedUser.email,
          mobile: savedUser.mobile,
          company: savedUser.company,
          address: savedUser.address,
          role: savedUser.role,
          suspended: Boolean(savedUser.suspended),
          created_at: savedUser.created_at,
          updated_at: savedUser.updated_at,
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, userId }, 'Failed to update team user');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};

