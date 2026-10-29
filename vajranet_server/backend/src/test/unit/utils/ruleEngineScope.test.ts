import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

vi.mock('../../../index', () => ({
  dbSourceConnection: vi.fn(),
}));

import { dbSourceConnection } from '../../../index';
import {
  canActOnRuleEngineResource,
  requireCanActOnRuleEngineResource,
  getRuleEngineResourceOwner,
  setRuleEngineResourceOwner,
} from '../../../utils/ruleEngineScope';
import { CustomError } from '../../../utils/response/custom-error/CustomError';
import type { NodeScope } from '../../../utils/nodeScope';

const mockedDbSourceConnection = dbSourceConnection as unknown as ReturnType<typeof vi.fn>;

// isInitialized: true — getUserNodeScope (nodeScope.ts) checks this before
// querying and fails closed if it's falsy; ruleEngineScope.ts's own
// getPrimaryDb() doesn't check it, but setting it unconditionally here is
// harmless for those call sites and keeps this one factory usable for both.
function makeFakeDataSource(queryImpl: (...args: any[]) => any) {
  return { query: vi.fn(queryImpl), isInitialized: true };
}

const UNRESTRICTED: NodeScope = { unrestricted: true };
function scoped(groups: { id: string; role: 'Group Admin' | 'Group Viewer' }[]): NodeScope {
  return { unrestricted: false, groups };
}

describe('canActOnRuleEngineResource', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
  });

  it('always allows an unrestricted (Super Admin) scope, without querying the database', async () => {
    const allowed = await canActOnRuleEngineResource(UNRESTRICTED, 'ip_watch_group', 'finance_servers');
    expect(allowed).toBe(true);
    expect(mockedDbSourceConnection).not.toHaveBeenCalled();
  });

  it('denies a scope with no act-level group memberships, without querying the database', async () => {
    const allowed = await canActOnRuleEngineResource(scoped([]), 'ip_watch_group', 'finance_servers');
    expect(allowed).toBe(false);
    expect(mockedDbSourceConnection).not.toHaveBeenCalled();
  });

  it('denies a Group Viewer (not Group Admin) membership even if it were the owner', async () => {
    // actableGroupIds filters to Group Admin only, so a Viewer-only scope
    // never reaches the owner lookup at all.
    const allowed = await canActOnRuleEngineResource(
      scoped([{ id: 'grp-1', role: 'Group Viewer' }]),
      'ip_watch_group',
      'finance_servers',
    );
    expect(allowed).toBe(false);
    expect(mockedDbSourceConnection).not.toHaveBeenCalled();
  });

  it('fails closed when the resource has never been assigned an owner', async () => {
    const db = makeFakeDataSource(() => Promise.resolve([]));
    mockedDbSourceConnection.mockReturnValue([db]);

    const allowed = await canActOnRuleEngineResource(
      scoped([{ id: 'grp-1', role: 'Group Admin' }]),
      'ip_watch_group',
      'unowned_group',
    );
    expect(allowed).toBe(false);
  });

  it('allows a Group Admin whose group owns the resource', async () => {
    const db = makeFakeDataSource(() => Promise.resolve([{ owner_group_id: 'grp-1' }]));
    mockedDbSourceConnection.mockReturnValue([db]);

    const allowed = await canActOnRuleEngineResource(
      scoped([{ id: 'grp-1', role: 'Group Admin' }]),
      'ip_watch_group',
      'finance_servers',
    );
    expect(allowed).toBe(true);
  });

  it("denies a Group Admin whose group does not own the resource (another group's watch group)", async () => {
    const db = makeFakeDataSource(() => Promise.resolve([{ owner_group_id: 'grp-2' }]));
    mockedDbSourceConnection.mockReturnValue([db]);

    const allowed = await canActOnRuleEngineResource(
      scoped([{ id: 'grp-1', role: 'Group Admin' }]),
      'ip_watch_group',
      'other_teams_servers',
    );
    expect(allowed).toBe(false);
  });
});

describe('getRuleEngineResourceOwner / setRuleEngineResourceOwner', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
  });

  it('returns null when no ownership row exists', async () => {
    const db = makeFakeDataSource(() => Promise.resolve([]));
    mockedDbSourceConnection.mockReturnValue([db]);

    const owner = await getRuleEngineResourceOwner('ip_watch_group', 'finance_servers');
    expect(owner).toBeNull();
  });

  it('returns the tracked owner_group_id', async () => {
    const db = makeFakeDataSource(() => Promise.resolve([{ owner_group_id: 'grp-9' }]));
    mockedDbSourceConnection.mockReturnValue([db]);

    const owner = await getRuleEngineResourceOwner('ip_watch_group', 'finance_servers');
    expect(owner).toBe('grp-9');
  });

  it('upserts on conflict (create-then-recreate with a different owner)', async () => {
    const query = vi.fn().mockResolvedValue([]);
    mockedDbSourceConnection.mockReturnValue([{ query }]);

    await setRuleEngineResourceOwner('ip_watch_group', 'finance_servers', 'grp-1', 'admin@example.com');

    expect(query).toHaveBeenCalledWith(
      expect.stringContaining('ON CONFLICT (resource_type, resource_key) DO UPDATE'),
      ['ip_watch_group', 'finance_servers', 'grp-1', 'admin@example.com'],
    );
  });
});

describe('requireCanActOnRuleEngineResource middleware', () => {
  beforeEach(() => {
    mockedDbSourceConnection.mockReset();
  });

  function makeReq(jwtPayload: any, params: Record<string, string>): Request {
    return { jwtPayload, params } as unknown as Request;
  }

  function getError(next: NextFunction): CustomError {
    return (next as any).mock.calls[0][0] as CustomError;
  }

  it('rejects with 401 when there is no authenticated session', async () => {
    const middleware = requireCanActOnRuleEngineResource('ip_watch_group', 'name');
    const req = makeReq(undefined, { name: 'finance_servers' });
    const next = vi.fn() as NextFunction;

    await middleware(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(401);
  });

  it('rejects with 403 when the caller does not own the resource', async () => {
    // getUserNodeScope resolves via a raw query against vajra_users LEFT JOIN
    // user_group_memberships; simulate a Group Admin on grp-2 only.
    const db = makeFakeDataSource((sql: string) => {
      if (sql.includes('FROM vajra_users')) {
        return Promise.resolve([{ role: 'Group Admin', group_id: 'grp-2', membership_role: 'Group Admin' }]);
      }
      // Ownership lookup: owned by a different group.
      return Promise.resolve([{ owner_group_id: 'grp-1' }]);
    });
    mockedDbSourceConnection.mockReturnValue([db]);

    const middleware = requireCanActOnRuleEngineResource('ip_watch_group', 'name');
    const req = makeReq({ id: 42 }, { name: 'finance_servers' });
    const next = vi.fn() as NextFunction;

    await middleware(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    const err = getError(next);
    expect(err).toBeInstanceOf(CustomError);
    expect(err.HttpStatusCode).toBe(403);
  });

  it('allows through with no error when the caller owns the resource', async () => {
    const db = makeFakeDataSource((sql: string) => {
      if (sql.includes('FROM vajra_users')) {
        return Promise.resolve([{ role: 'Group Admin', group_id: 'grp-1', membership_role: 'Group Admin' }]);
      }
      return Promise.resolve([{ owner_group_id: 'grp-1' }]);
    });
    mockedDbSourceConnection.mockReturnValue([db]);

    const middleware = requireCanActOnRuleEngineResource('ip_watch_group', 'name');
    const req = makeReq({ id: 42 }, { name: 'finance_servers' });
    const next = vi.fn() as NextFunction;

    await middleware(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('allows a Super Administrator through unconditionally', async () => {
    const db = makeFakeDataSource((sql: string) => {
      if (sql.includes('FROM vajra_users')) {
        return Promise.resolve([{ role: 'Super Administrator', group_id: null, membership_role: null }]);
      }
      throw new Error('should not query ownership for an unrestricted scope');
    });
    mockedDbSourceConnection.mockReturnValue([db]);

    const middleware = requireCanActOnRuleEngineResource('ip_watch_group', 'name');
    const req = makeReq({ id: 1 }, { name: 'any_group_at_all' });
    const next = vi.fn() as NextFunction;

    await middleware(req, {} as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });
});
