import { Request, Response } from 'express';
import { dbSourceConnection } from '../../index';
import { UserRole, VajraUser, SUPER_ADMIN_ROLE } from '../../orm/entities/users/Users';
import { getLogger } from '../../utils/logger';

const logger = getLogger('users.teamTransferOwnership');

const ADMIN_ROLE: UserRole = 'Group Admin';

export const team_transfer_ownership = async (req: Request, res: Response) => {
  const requesterId = Number((req as any).jwtPayload?.id);
  const targetUserId = Number(req.body?.targetUserId);

  if (!Number.isInteger(requesterId) || requesterId <= 0) {
    return res.status(401).json({ status: 'Error', message: 'Unauthorized' });
  }

  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).json({ status: 'Error', message: 'Valid targetUserId is required' });
  }

  if (requesterId === targetUserId) {
    return res.status(400).json({ status: 'Error', message: 'Ownership can only be transferred to another user' });
  }

  try {
    const dbSources = dbSourceConnection();
    const primaryDataSource = dbSources?.[0];
    if (!primaryDataSource) {
      logger.error({ requesterId, targetUserId }, 'Database connection not established for ownership transfer');
      return res.status(500).json({ status: 'Error', message: 'Database connection not established' });
    }

    // The singleton-super-admin invariant this endpoint maintains (exactly
    // one Super Administrator) must be checked and acted on atomically —
    // otherwise two concurrent transfer-ownership calls naming different
    // targets can each read requester.role === SUPER_ADMIN_ROLE as still
    // true (neither has committed yet under the default READ COMMITTED
    // isolation) and both promote their target, leaving two Super
    // Administrators. Same invariant, same fix register.ts and
    // team_update.ts already use for this exact reason.
    const queryRunner = primaryDataSource.createQueryRunner();
    let result: { requester: VajraUser; targetUser: VajraUser };
    try {
      // connect()/startTransaction() live inside this try too: if either
      // throws (transient DB error, pool exhaustion), the acquired
      // connection must still hit release() in the finally below, or a
      // string of failures here would leak it out of the pool for good.
      await queryRunner.connect();
      await queryRunner.startTransaction('SERIALIZABLE');

      const repo = queryRunner.manager.getRepository(VajraUser);

      const requester = await repo.findOne({ where: { id: requesterId } });
      if (!requester) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, targetUserId, statusCode: 404, reason: 'Requester not found' }, 'Ownership transfer rejected');
        return res.status(404).json({ status: 'Error', message: 'Requester not found' });
      }

      if (requester.role !== SUPER_ADMIN_ROLE) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, targetUserId, statusCode: 403, reason: 'Only Super Administrator can transfer ownership' }, 'Ownership transfer rejected');
        return res.status(403).json({ status: 'Error', message: 'Only Super Administrator can transfer ownership' });
      }

      const targetUser = await repo.findOne({ where: { id: targetUserId } });
      if (!targetUser) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, targetUserId, statusCode: 404, reason: 'Target user not found' }, 'Ownership transfer rejected');
        return res.status(404).json({ status: 'Error', message: 'Target user not found' });
      }

      if (targetUser.role === SUPER_ADMIN_ROLE) {
        await queryRunner.rollbackTransaction();
        logger.warn({ requesterId, targetUserId, statusCode: 409, reason: 'Selected user is already Super Administrator' }, 'Ownership transfer rejected');
        return res.status(409).json({ status: 'Error', message: 'Selected user is already Super Administrator' });
      }

      requester.role = ADMIN_ROLE;
      requester.session_version = (requester.session_version ?? 0) + 1;

      targetUser.role = SUPER_ADMIN_ROLE;
      targetUser.session_version = (targetUser.session_version ?? 0) + 1;

      const savedRequester = await repo.save(requester);
      const savedTargetUser = await repo.save(targetUser);

      result = { requester: savedRequester, targetUser: savedTargetUser };
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

    logger.info(
      { fromUserId: result.requester.id, toUserId: result.targetUser.id },
      'Super Administrator ownership transferred',
    );

    return res.status(200).json({
      status: 'Success',
      message: 'Ownership transferred successfully',
      data: {
        fromUser: {
          id: result.requester.id,
          role: result.requester.role,
          session_version: result.requester.session_version,
        },
        toUser: {
          id: result.targetUser.id,
          role: result.targetUser.role,
          session_version: result.targetUser.session_version,
        },
      },
    });
  } catch (error) {
    logger.error({ err: error, requesterId, targetUserId }, 'Failed to transfer ownership');
    return res.status(500).json({ status: 'Error', message: 'Internal Server Error' });
  }
};
