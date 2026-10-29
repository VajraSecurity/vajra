import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FimRegGroupCoverage, FimRegProfile } from '@/api/services/fimApi';
import * as fimApi from '@/api/services/fimApi';
import { ToastContext } from '@/context/useToast';
import { ConfirmDialogContext } from '@/context/useConfirm';
import { GroupView } from '@/features/FileIntegrity/RegistryCoverage/GroupCoverage';
import ProfileEditor from '@/features/FileIntegrity/RegistryCoverage/ProfileEditor';
import { STALE_COVERAGE_TEXT, groupPublishBody, profilePublishBody, publishReviewed } from '@/features/FileIntegrity/RegistryCoverage/regActions';

vi.mock(import('@/api/services/fimApi'), async (orig) => ({
  ...(await orig()),
  publishFimReg: vi.fn(),
  startFimRegProfilePublish: vi.fn(),
  getFimRegJob: vi.fn(),
  getFimRegGroup: vi.fn(),
  listFimRegProfiles: vi.fn(),
  getFimRegCatalog: vi.fn(),
}));

const api = vi.mocked(fimApi);
const showToast = vi.fn();
const confirm = vi.fn(async () => false);
const okRes = { results: [{ host: 'h1', status: 'in_sync' as const, policyId: 5, rev: 2, revChanged: true, needsInit: [], retired: [], error: null }], published: 1, failed: 0 };
const stale409 = { response: { status: 409, data: { message: 'group coverage changed' } } };

function wrap(ui: ReactNode) {
  return render(
    <ToastContext.Provider value={{ showToast }}>
      <ConfirmDialogContext.Provider value={{ confirm }}>{ui}</ConfirmDialogContext.Provider>
    </ToastContext.Provider>,
  );
}

const tierSum = { entries: 1, rows: 1, bytes: 1 };
const group = (over: Partial<FimRegGroupCoverage> = {}): FimRegGroupCoverage => ({
  groupId: 'g1', assignment: null, profile: { id: 1, name: 'Default', source: 'default' }, tier: { value: 'essential', source: 'profile' },
  entries: [], blocked: [], warnings: [], errors: [], totals: tierSum,
  tierOptions: { essential: tierSum, recommended: tierSum, comprehensive: tierSum },
  rules: { group: [], profile: [] }, waivers: [],
  members: [{ host: 'h1', hostname: 'host-1', status: 'pending', profileName: 'Default', tier: 'essential', entries: 1, nodeRules: 0, realtimeAvailable: false, publishedAt: null } as unknown as FimRegGroupCoverage['members'][number]],
  canManage: true, resolvedHash: 'rh-reviewed', ...over,
});
const profile = (over: Partial<FimRegProfile> = {}): FimRegProfile => ({
  id: 7, name: 'Workstation', description: '', tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', version: 3,
  createdBy: null, updatedBy: null, createdAt: 1, updatedAt: 1, affectedNodes: 2, rules: [], digest: 'pd-reviewed', ...over,
});

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  try { sessionStorage.clear(); } catch { /* no storage */ }
  api.getFimRegCatalog.mockResolvedValue({ items: [] } as never);
});

describe('publish body helpers', () => {
  it('group publish states expectedGroupHash', () => {
    expect(groupPublishBody('g1', { resolvedHash: 'rh' }, 'n', false)).toEqual({ group: 'g1', expectedGroupHash: 'rh', note: 'n', confirm: false });
  });
  it('profile publish states expectedProfileDigest', () => {
    expect(profilePublishBody({ id: 3, digest: 'pd' }, 'n', true)).toEqual({ profile: 3, expectedProfileDigest: 'pd', note: 'n', confirm: true });
  });
  it('refuses to build a body without the reviewed hash', () => {
    expect(() => groupPublishBody('g1', { resolvedHash: '' }, 'n', false)).toThrow(/reload/);
    expect(() => profilePublishBody({ id: 3 }, 'n', false)).toThrow(/reload/);
  });
  it('publishReviewed maps 409 to a stale outcome and rethrows other errors', async () => {
    api.publishFimReg.mockRejectedValueOnce(stale409);
    const r = await publishReviewed({ group: 'g1', expectedGroupHash: 'x', note: 'n' });
    expect(r.stale).toBe(true);
    expect(r.stale && r.message).toContain(STALE_COVERAGE_TEXT);
    api.publishFimReg.mockRejectedValueOnce({ response: { status: 500 } });
    await expect(publishReviewed({ group: 'g1', expectedGroupHash: 'x', note: 'n' })).rejects.toBeTruthy();
  });
});

async function publishGroup() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: /Apply to all members \(1\)/ }));
  await user.type(screen.getByLabelText('Note (required)'), 'CHG-9');
  await user.click(screen.getByRole('button', { name: 'Publish' }));
}

describe('group publish flow', () => {
  it('sends expectedGroupHash = the resolvedHash the user reviewed', async () => {
    api.getFimRegGroup.mockResolvedValue(group());
    api.listFimRegProfiles.mockResolvedValue({ items: [] });
    api.publishFimReg.mockResolvedValue(okRes);
    wrap(<GroupView groupId="g1" groupName="Finance" isSuperAdmin limits={null} />);
    await publishGroup();
    await waitFor(() => expect(api.publishFimReg).toHaveBeenCalledWith({ group: 'g1', expectedGroupHash: 'rh-reviewed', note: 'CHG-9', confirm: false }));
  });

  it('409: shows "coverage changed since you reviewed it; reload" and reloads', async () => {
    api.getFimRegGroup.mockResolvedValue(group());
    api.listFimRegProfiles.mockResolvedValue({ items: [] });
    api.publishFimReg.mockRejectedValue(stale409);
    wrap(<GroupView groupId="g1" groupName="Finance" isSuperAdmin limits={null} />);
    await publishGroup();
    await waitFor(() => expect(showToast).toHaveBeenCalledWith(expect.stringContaining('Coverage changed since you reviewed it; reload'), 'error'));
    await waitFor(() => expect(api.getFimRegGroup).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

async function publishProfile() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: /Publish all nodes/ }));
  await user.type(screen.getByLabelText('Note (required)'), 'CHG-10');
  await user.click(screen.getByRole('button', { name: 'Publish' }));
}

describe('profile publish flow', () => {
  it('sends expectedProfileDigest = the digest of the listed profile', async () => {
    api.listFimRegProfiles.mockResolvedValue({ items: [profile()] });
    api.startFimRegProfilePublish.mockResolvedValue({ job: { id: 1, kind: 'publish_profile', status: 'queued', total: 2, done: 0, failed: 0, results: [], error: null, createdBy: null, createdAt: 1, heartbeatAt: null, finishedAt: null } });
    api.getFimRegJob.mockReturnValue(new Promise(() => {}));
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    await publishProfile();
    await waitFor(() => expect(api.startFimRegProfilePublish).toHaveBeenCalledWith({ profile: 7, expectedProfileDigest: 'pd-reviewed', note: 'CHG-10', confirm: false }));
    expect(api.publishFimReg).not.toHaveBeenCalled();
  });

  it('409: shows the stale message and reloads the profiles', async () => {
    api.listFimRegProfiles.mockResolvedValue({ items: [profile()] });
    api.startFimRegProfilePublish.mockRejectedValue({ response: { status: 409, data: { message: 'This profile changed since it was reviewed; reload and review it again' } } });
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    await publishProfile();
    await waitFor(() => expect(showToast).toHaveBeenCalledWith(expect.stringContaining('Coverage changed since you reviewed it; reload'), 'error'));
    await waitFor(() => expect(api.listFimRegProfiles).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
