import { Request, Response, NextFunction } from 'express';
import { In } from 'typeorm';
import { getUserNodeScope } from '../../utils/nodeScope';
import { jwtFrom } from '../../utils/requestContext';
import { getLogger } from '../../utils/logger';

const logger = getLogger('controllers.domainReputation.scope');

/**
 * Tells the frontend which group(s) the caller may configure a group-scoped
 * provider (virustotal/abuseipdb) or watchlist entry for — the group picker
 * in Settings/Check Now/the watchlist modal is driven entirely by this, since
 * (unlike role) no group membership is otherwise ever sent to the frontend.
 */
export const listMyGroups = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { EndpointGroup } = await import('../../orm/entities/fleet/EndpointGroup');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }
    const groupRepo = ds[1].getRepository(EndpointGroup);

    const jwt = jwtFrom(req);
    const scope = jwt?.id ? await getUserNodeScope(jwt.id) : ({ unrestricted: false, groups: [] } as const);

    if (scope.unrestricted) {
      const all = await groupRepo.find({ order: { name: 'ASC' } });
      return res.status(200).json({
        success: true,
        data: { unrestricted: true, groups: all.map((g) => ({ group_id: g.groupId, name: g.name, role: 'Group Admin' as const })) },
      });
    }

    const ids = scope.groups.map((g) => g.id);
    const rows = ids.length ? await groupRepo.find({ where: { groupId: In(ids) } }) : [];
    const nameById = new Map(rows.map((r) => [r.groupId, r.name]));
    const groups = scope.groups.map((g) => ({ group_id: g.id, name: nameById.get(g.id) ?? g.id, role: g.role }));

    return res.status(200).json({ success: true, data: { unrestricted: false, groups } });
  } catch (err: any) {
    logger.error({ err }, 'Failed to load caller\'s domain reputation group scope');
    return res.status(500).json({ success: false, message: err.message || 'Failed to load groups' });
  }
};
