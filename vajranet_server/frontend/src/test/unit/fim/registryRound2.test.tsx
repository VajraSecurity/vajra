import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FimPolicy, FimRegJob, FimRegProfile, FimRegSettings } from '@/api/services/fimApi';
import * as fimApi from '@/api/services/fimApi';
import { ToastContext } from '@/context/useToast';
import { ConfirmDialogContext } from '@/context/useConfirm';
import ProfileEditor from '@/features/FileIntegrity/RegistryCoverage/ProfileEditor';
import MigrationView from '@/features/FileIntegrity/RegistryCoverage/MigrationView';
import PolicyFormModal from '@/features/FileIntegrity/PolicyFormModal';
import RegistryTab from '@/features/FileIntegrity/RegistryTab';
import {
  PUBLISH_RUNNING_TEXT, STALE_COVERAGE_TEXT, hostsPublishBody, jobFailedHosts, jobProgressText, pollRegistryJob, startProfilePublish,
} from '@/features/FileIntegrity/RegistryCoverage/regActions';
import { HISTORY_UNKEYED_TEXT } from '@/features/FileIntegrity/RegistryCoverage/regModel';
import { entryIndexFromError } from '@/features/FileIntegrity/constants';
import { isOwnOversightAlert } from '@/features/FileIntegrity/alertGuards';

vi.mock(import('@/api/services/fimApi'), async (orig) => ({
  ...(await orig()),
  publishFimReg: vi.fn(),
  startFimRegProfilePublish: vi.fn(),
  getFimRegJob: vi.fn(),
  listFimRegProfiles: vi.fn(),
  getFimRegCatalog: vi.fn(),
  getFimRegSettings: vi.fn(),
  listFimRegLegacy: vi.fn(),
  listFimRegPolicyProblems: vi.fn(),
  listFimPolicies: vi.fn(),
  listFimTemplates: vi.fn(),
  updateFimPolicy: vi.fn(),
  publishFimPolicy: vi.fn(),
}));
// Heavy sub-views and the node/group loader are not under test here.
vi.mock('@/features/FileIntegrity/RegistryCoverage/NodeCoverage', () => ({ default: () => <div>node coverage</div> }));
vi.mock('@/features/FileIntegrity/useFimNodes', () => ({
  useFimNodes: () => ({ nodes: [], groups: [], loading: false, error: null }),
  nodeMatchesOs: () => true,
}));

const api = vi.mocked(fimApi);
const showToast = vi.fn();
const confirm = vi.fn(async () => true);

function wrap(ui: ReactNode) {
  return render(
    <ToastContext.Provider value={{ showToast }}>
      <ConfirmDialogContext.Provider value={{ confirm }}>{ui}</ConfirmDialogContext.Provider>
    </ToastContext.Provider>,
  );
}

const job = (over: Partial<FimRegJob> = {}): FimRegJob => ({
  id: 42, kind: 'publish_profile', status: 'running', total: 3, done: 1, failed: 0, results: [], error: null,
  createdBy: 'sa@example.com', createdAt: 1, heartbeatAt: 2, finishedAt: null, ...over,
});
const profile = (over: Partial<FimRegProfile> = {}): FimRegProfile => ({
  id: 7, name: 'Workstation', description: '', tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', version: 3,
  createdBy: null, updatedBy: null, createdAt: 1, updatedAt: 1, affectedNodes: 3, rules: [], digest: 'pd-1', ...over,
});

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  try { sessionStorage.clear(); } catch { /* no storage */ }
  api.getFimRegCatalog.mockResolvedValue({ items: [] } as never);
  api.listFimTemplates.mockResolvedValue([]);
});

// ---------------------------------------------------------------- 1. profile publish background job
describe('profile publish job helpers', () => {
  it('startProfilePublish returns the job on 202', async () => {
    api.startFimRegProfilePublish.mockResolvedValueOnce({ job: job({ status: 'queued', done: 0 }) });
    const r = await startProfilePublish({ profile: 7, expectedProfileDigest: 'pd', note: 'n' });
    expect(r).toEqual({ kind: 'started', job: expect.objectContaining({ id: 42, status: 'queued' }) });
  });

  it('distinguishes the "already running" 409 from the stale-digest 409', async () => {
    api.startFimRegProfilePublish.mockRejectedValueOnce({ response: { status: 409, data: { message: 'A profile publish is already running; wait for it to finish' } } });
    const running = await startProfilePublish({ profile: 7, expectedProfileDigest: 'pd', note: 'n' });
    expect(running.kind).toBe('running');
    expect(running.kind === 'running' && running.message).toContain(PUBLISH_RUNNING_TEXT);
    api.startFimRegProfilePublish.mockRejectedValueOnce({ response: { status: 409, data: { message: 'This profile changed since it was reviewed' } } });
    const stale = await startProfilePublish({ profile: 7, expectedProfileDigest: 'pd', note: 'n' });
    expect(stale.kind).toBe('stale');
    expect(stale.kind === 'stale' && stale.message).toContain(STALE_COVERAGE_TEXT);
  });

  it('pollRegistryJob polls until done, retries transient errors, reports every update', async () => {
    const seq: (FimRegJob | Error)[] = [job({ status: 'queued', done: 0 }), new Error('network'), job({ done: 2 }), job({ status: 'done', done: 2, failed: 1, results: [{ host: 'h3', error: 'boom' }] })];
    const fetchJob = vi.fn(async () => { const x = seq.shift()!; if (x instanceof Error) throw x; return x; });
    const sleep = vi.fn(async () => {});
    const updates: string[] = [];
    const onError = vi.fn();
    const final = await pollRegistryJob(42, { fetchJob, sleep, onError, onUpdate: (j) => updates.push(jobProgressText(j)) });
    expect(final?.status).toBe('done');
    expect(fetchJob).toHaveBeenCalledTimes(4);
    expect(sleep).toHaveBeenCalledWith(2000);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(updates).toEqual(['Publish queued (0/3, 0 failed)', 'Publishing 2/3, 0 failed', 'Published 2/3, 1 failed']);
    expect(jobFailedHosts(final!)).toEqual([{ host: 'h3', error: 'boom' }]);
  });

  it('pollRegistryJob stops on 404', async () => {
    const fetchJob = vi.fn(async () => { throw { response: { status: 404 } }; });
    await expect(pollRegistryJob(1, { fetchJob, sleep: async () => {} })).rejects.toBeTruthy();
    expect(fetchJob).toHaveBeenCalledTimes(1);
  });
});

async function startPublishFromEditor() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: /Publish all nodes/ }));
  await user.type(screen.getByLabelText('Note (required)'), 'CHG-1');
  await user.click(screen.getByRole('button', { name: 'Publish' }));
}

describe('ProfileEditor background publish', () => {
  it('shows "Publishing N/M, F failed" and keeps it visible after the modal closes', async () => {
    api.listFimRegProfiles.mockResolvedValue({ items: [profile()] });
    api.startFimRegProfilePublish.mockResolvedValue({ job: job() });
    api.getFimRegJob.mockReturnValue(new Promise(() => {})); // still running
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    await startPublishFromEditor();
    const panel = await screen.findByTestId('fim-publish-job');
    expect(panel).toHaveTextContent('Publishing 1/3, 0 failed');
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => expect(api.getFimRegJob).toHaveBeenCalledWith(42));
  });

  it('shows the failed hosts when the job ends', async () => {
    api.listFimRegProfiles.mockResolvedValue({ items: [profile()] });
    api.startFimRegProfilePublish.mockResolvedValue({ job: job({ status: 'queued', done: 0 }) });
    api.getFimRegJob.mockResolvedValue(job({ status: 'done', done: 2, failed: 1, results: [{ host: 'win-07', error: 'node configuration invalid' }, { host: 'win-01', status: 'in_sync', error: null }], finishedAt: 9 }));
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    await startPublishFromEditor();
    const panel = await screen.findByTestId('fim-publish-job');
    await waitFor(() => expect(panel).toHaveTextContent('Published 2/3, 1 failed'));
    expect(within(panel).getByText('win-07')).toBeInTheDocument();
    expect(within(panel).getByText('node configuration invalid')).toBeInTheDocument();
    expect(within(panel).queryByText('win-01')).toBeNull();
    await waitFor(() => expect(showToast).toHaveBeenCalledWith(expect.stringContaining('1 failed'), 'error'));
  });

  it('409 "already running" is shown as such (not as stale)', async () => {
    api.listFimRegProfiles.mockResolvedValue({ items: [profile()] });
    api.startFimRegProfilePublish.mockRejectedValue({ response: { status: 409, data: { message: 'A profile publish is already running; wait for it to finish' } } });
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    await startPublishFromEditor();
    await waitFor(() => expect(showToast).toHaveBeenCalledWith(expect.stringContaining('already running'), 'error'));
    expect(screen.getByText(/A profile publish is already running; wait for it to finish \(/)).toBeInTheDocument();
    expect(showToast).not.toHaveBeenCalledWith(expect.stringContaining('Coverage changed'), expect.anything());
  });
});

// ---------------------------------------------------------------- 2. hosts publish: expected for every host
describe('hosts publish sends a non-empty expected[host] for every host', () => {
  it('builds expected for every host', () => {
    expect(hostsPublishBody([{ host: 'a', resolvedHash: 'ha' }, { host: 'b', resolvedHash: 'hb' }], 'n')).toEqual({ hosts: ['a', 'b'], expected: { a: 'ha', b: 'hb' }, note: 'n' });
  });

  it('refuses (sends nothing) when any host lacks a reviewed hash', () => {
    expect(() => hostsPublishBody([{ host: 'a', resolvedHash: 'ha' }, { host: 'b', resolvedHash: '' }], 'n')).toThrow(/missing for 1 host/);
    expect(() => hostsPublishBody([{ host: 'a' }], 'n')).toThrow(/reload/);
    expect(() => hostsPublishBody([], 'n')).toThrow();
  });

  it('every publishFimReg call site in the feature builds its body with hostsPublishBody (audit)', () => {
    const sources = import.meta.glob('/src/features/FileIntegrity/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
    const calls: { file: string; arg: string }[] = [];
    for (const [file, src] of Object.entries(sources)) {
      for (const m of src.matchAll(/publishFimReg\(\s*([^\s,)]+)/g)) calls.push({ file, arg: m[1] });
    }
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) {
      const ok = c.arg.startsWith('hostsPublishBody(') || (c.file.endsWith('regActions.ts') && c.arg === 'body');
      expect(ok, `${c.file}: publishFimReg(${c.arg}...)`).toBe(true);
    }
  });
});

// ---------------------------------------------------------------- 3. history chain keyed warning
const settings = (over: Partial<FimRegSettings> = {}): FimRegSettings => ({
  managedEnabled: true, updatedBy: null, updatedAt: null, catalogVersion: 1, isSuperAdmin: false,
  limits: {} as FimRegSettings['limits'], ...over,
});

describe('Registry tab: history hash chain not keyed', () => {
  it('shows the prominent warning when historyKeyed is false', async () => {
    api.getFimRegSettings.mockResolvedValue(settings({ historyKeyed: false }));
    wrap(<RegistryTab />);
    const w = await screen.findByTestId('fim-history-unkeyed');
    expect(w).toHaveTextContent(HISTORY_UNKEYED_TEXT);
    expect(HISTORY_UNKEYED_TEXT).toBe('History hash chain is NOT keyed (FIM_HISTORY_HMAC_KEY missing; FIM_HISTORY_ALLOW_UNKEYED=1): tamper evidence is weaker');
    expect(w).toHaveAttribute('role', 'alert');
  });

  it('shows no warning when keyed (or when an older server omits the field)', async () => {
    api.getFimRegSettings.mockResolvedValue(settings({ historyKeyed: true }));
    wrap(<RegistryTab />);
    await screen.findByText('node coverage');
    expect(screen.queryByTestId('fim-history-unkeyed')).toBeNull();
    cleanup();
    api.getFimRegSettings.mockResolvedValue(settings());
    wrap(<RegistryTab />);
    await screen.findByText('node coverage');
    expect(screen.queryByTestId('fim-history-unkeyed')).toBeNull();
  });
});

// ---------------------------------------------------------------- 4. unbuildable policy entries
const policy = (over: Partial<FimPolicy> = {}): FimPolicy => ({
  id: 5, name: 'Win persistence', description: '', osPlatform: 'linux', mode: 'enforce', scanIntervalSecs: 3600, realtime: false, enabled: true,
  paths: [
    { kind: 'path', path: '/etc/ok', severity: 'medium', category: '', ignore: [], hash: true },
    { kind: 'path', path: '/etc/bad', severity: 'medium', category: '', ignore: [], hash: true },
  ],
  targets: [{ type: 'all', value: '*' }], template: null, ...over,
} as unknown as FimPolicy);

describe('entryIndexFromError', () => {
  it('finds the entry a server error names', () => {
    expect(entryIndexFromError('paths[3]: registry key must be printable ASCII')).toBe(3);
    expect(entryIndexFromError('entry #2 cannot be built')).toBe(2);
    expect(entryIndexFromError('Name is required')).toBeNull();
    expect(entryIndexFromError(undefined)).toBeNull();
  });
});

describe('MigrationView: policies with entries that can no longer be built', () => {
  it('lists the offending entries (index, path, error) and opens the editor with the entry highlighted', async () => {
    api.listFimRegLegacy.mockResolvedValue({ items: [] });
    api.listFimRegPolicyProblems.mockResolvedValue({ items: [{ policyId: 5, name: 'Win persistence', entries: [{ index: 1, path: '/etc/bad', error: 'cannot build scan query' }] }] });
    api.listFimPolicies.mockResolvedValue({ items: [policy()] } as never);
    wrap(<MigrationView isSuperAdmin />);
    const row = await screen.findByTestId('fim-problem-5-1');
    expect(row).toHaveTextContent('1');
    expect(row).toHaveTextContent('/etc/bad');
    expect(row).toHaveTextContent('cannot build scan query');
    expect(screen.getByTestId('fim-policy-problems')).toHaveTextContent(/fix or remove/i);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Open in policy editor' }));
    const entry = await screen.findByTestId('fim-entry-1');
    expect(entry).toHaveAttribute('data-problem', 'true');
    expect(entry).toHaveTextContent('cannot build scan query');
    expect(screen.getByTestId('fim-entry-0')).not.toHaveAttribute('data-problem');
  });

  it('is not loaded for non Super Admins', () => {
    wrap(<MigrationView isSuperAdmin={false} />);
    expect(api.listFimRegPolicyProblems).not.toHaveBeenCalled();
  });
});

describe('policy editor highlights the entry a save error names', () => {
  it('marks entry #1 when the server answers "paths[1]: ..."', async () => {
    api.updateFimPolicy.mockRejectedValue({ response: { status: 400, data: { message: 'paths[1]: path must not contain single quotes' } } });
    const onSaved = vi.fn();
    wrap(<PolicyFormModal policy={policy()} onClose={vi.fn()} onSaved={onSaved} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Save' }));
    const entry = await screen.findByTestId('fim-entry-1');
    await waitFor(() => expect(entry).toHaveAttribute('data-problem', 'true'));
    expect(within(entry).getByText(/fix this entry or remove it/)).toBeInTheDocument();
    expect(screen.getByTestId('fim-entry-0')).not.toHaveAttribute('data-problem');
    expect(onSaved).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------- 5. own oversight alerts
describe('isOwnOversightAlert', () => {
  const me = { id: 12, email: 'SA@example.com' };
  it('matches by user id, else by e-mail; only for fim_config', () => {
    expect(isOwnOversightAlert({ alertType: 'fim_config', metadata: JSON.stringify({ by: 'x@y', byUserId: 12 }) }, me)).toBe(true);
    expect(isOwnOversightAlert({ alertType: 'fim_config', metadata: { by: 'sa@example.com', byUserId: 13 } }, me)).toBe(false);
    expect(isOwnOversightAlert({ alertType: 'fim_config', metadata: { by: 'sa@example.com' } }, me)).toBe(true);
    expect(isOwnOversightAlert({ alertType: 'fim', metadata: { by: 'sa@example.com' } }, me)).toBe(false);
    expect(isOwnOversightAlert({ alertType: 'fim_config', metadata: { by: 'sa@example.com' } }, null)).toBe(false);
    expect(isOwnOversightAlert({ alertType: 'fim_config', metadata: 'not json' }, me)).toBe(false);
  });
});
