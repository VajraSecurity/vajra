import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FimRegJob, FimRegProfile, FimRegSettings } from '@/api/services/fimApi';
import * as fimApi from '@/api/services/fimApi';
import { ToastContext } from '@/context/useToast';
import { ConfirmDialogContext } from '@/context/useConfirm';
import { csvCell, hasInvisible, isNotNfc, safeText, safeTokens } from '@/features/FileIntegrity/safeText';
import { RegText } from '@/features/FileIntegrity/UntrustedText';
import HistoryDrawer from '@/features/FileIntegrity/RegistryCoverage/HistoryDrawer';
import RegistryTab from '@/features/FileIntegrity/RegistryTab';
import ProfileEditor from '@/features/FileIntegrity/RegistryCoverage/ProfileEditor';
import PublishJobPanel from '@/features/FileIntegrity/RegistryCoverage/PublishJobPanel';
import { chainView } from '@/features/FileIntegrity/RegistryCoverage/regModel';
import { JobPollError, jobProgressText, pollRegistryJob } from '@/features/FileIntegrity/RegistryCoverage/regActions';
import { HISTORY_KEY_MISSING_TEXT, errMsg, historyKeyMissing } from '@/features/FileIntegrity/constants';

vi.mock(import('@/api/services/fimApi'), async (orig) => ({
  ...(await orig()),
  listFimRegHistory: vi.fn(),
  getFimRegSettings: vi.fn(),
  listFimRegProfiles: vi.fn(),
  getFimRegCatalog: vi.fn(),
  startFimRegProfilePublish: vi.fn(),
  getFimRegJob: vi.fn(),
  cancelFimRegJob: vi.fn(),
}));
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
const ch = (cp: number) => String.fromCodePoint(cp);

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  try { sessionStorage.clear(); } catch { /* no storage */ }
  api.getFimRegCatalog.mockResolvedValue({ items: [] } as never);
});

// ---------------------------------------------------------------- M8 / spoof probes (review4)
describe('M8 safeText spoof probes', () => {
  it('P1: look-alike brackets cannot imitate the escape marker in plain-text sinks', () => {
    const real = safeText('a\u202Eb');
    for (const [o, c] of [[0x3008, 0x3009], [0x2329, 0x232a], [0x27ea, 0x27eb]]) {
      const data = `a${ch(o)}U+202E${ch(c)}b`;
      const out = safeText(data);
      expect(out).not.toBe(real);
      expect(out).toContain(`\u27E8U+${o.toString(16).toUpperCase()}\u27E9`);
      expect(hasInvisible(data)).toBe(false);
      expect(csvCell(data)).not.toContain(ch(o));
    }
  });

  it('P2: variation selectors, Khmer inherent vowels, Braille blank, null notehead, U+FFFC and U+FFF9-FFFB are escaped and flagged', () => {
    for (const cp of [0xfe00, 0xfe0f, 0xe0100, 0xe01ef, 0x17b4, 0x17b5, 0x2800, 0x1d159, 0xfffc, 0xfff9, 0xfffa, 0xfffb, 0x180b]) {
      const s = `evil${ch(cp)}.exe`;
      expect(hasInvisible(s), cp.toString(16)).toBe(true);
      expect(safeText(s)).toBe(`evil\u27E8U+${cp.toString(16).toUpperCase().padStart(4, '0')}\u27E9.exe`);
      const t = safeTokens(s).find((x) => x.kind === 'escape');
      expect(t).toMatchObject({ hidden: true, reason: 'hidden' });
    }
  });

  it('P3: NFC vs NFD paths are distinguishable and flagged, never normalised', () => {
    const a = '/etc/caf\u00e9.conf';
    const b = '/etc/cafe\u0301.conf';
    expect(isNotNfc(a)).toBe(false);
    expect(isNotNfc(b)).toBe(true);
    expect(safeText(a)).toBe(a);
    expect(safeText(b)).toBe('/etc/cafe\u27E8U+0301\u27E9.conf');
    expect(safeText(b)).not.toBe(safeText(a));
    const { container } = render(<RegText value={b} />);
    expect(container.querySelector('[data-testid="fim-not-nfc"]')).not.toBeNull();
    expect(container.querySelector('[data-fim-reason="decomposed"]')).not.toBeNull();
    cleanup();
    const r2 = render(<RegText value={a} />);
    expect(r2.container.querySelector('[data-testid="fim-not-nfc"]')).toBeNull();
  });

  it('P4: lone surrogates are escaped by code point and flagged (U+FFFD is not)', () => {
    expect(safeText('x\uD800y')).toBe('x\u27E8U+D800\u27E9y');
    expect(safeText('x\uDBFFy')).toBe('x\u27E8U+DBFF\u27E9y');
    expect(hasInvisible('x\uDC00y')).toBe(true);
    expect(safeText('x\uFFFDy')).toBe('x\uFFFDy');
    expect(safeText('ok \u{1F600}')).toBe('ok \u{1F600}');
  });

  it('P5: RegText preserves double and trailing spaces (pre-wrap, or pre for single-line cells)', () => {
    const { container } = render(<RegText value={'C:\\x\\a  b '} />);
    const span = container.firstElementChild as HTMLElement;
    expect(span).toHaveClass('whitespace-pre-wrap');
    expect(span.textContent).toBe('C:\\x\\a  b ');
    cleanup();
    const r2 = render(<RegText value="a  b" nowrap />);
    expect(r2.container.firstElementChild).toHaveClass('whitespace-pre');
  });

  it('P6: NBSP and every other non-ASCII space / separator is escaped and flagged; ASCII space is not', () => {
    for (const cp of [0xa0, 0x1680, 0x2000, 0x2007, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]) {
      const s = `a${ch(cp)}b`;
      expect(safeText(s), cp.toString(16)).not.toBe(s);
      expect(hasInvisible(s)).toBe(true);
    }
    expect(safeText('a b')).toBe('a b');
    expect(hasInvisible('a b')).toBe(false);
  });
});

// ---------------------------------------------------------------- M6 chain status
const page = (over: Record<string, unknown>) => ({ items: [], total: 0, page: 1, pageSize: 25, chainOk: true, chainBrokenAt: null, ...over });

describe('M6 chainView', () => {
  it('ok + keyed is green', () => {
    expect(chainView({ chainOk: true, chainBrokenAt: null, chainStatus: 'ok', chainKeyed: true })).toMatchObject({ status: 'ok', tone: 'ok', headline: 'Hash chain verified' });
  });
  it('ok but not keyed is amber', () => {
    const v = chainView({ chainOk: true, chainBrokenAt: null, chainStatus: 'ok', chainKeyed: false, chainUnkeyedRows: 3 });
    expect(v).toMatchObject({ status: 'ok', tone: 'warn' });
    expect(v.headline).toMatch(/NOT keyed/);
    expect(v.detail).toMatch(/3 row/);
  });
  it('unverifiable is amber and does not claim tampering', () => {
    const v = chainView({ chainOk: false, chainBrokenAt: null, chainStatus: 'unverifiable', chainReason: 'history key unavailable' });
    expect(v).toMatchObject({ status: 'unverifiable', tone: 'warn', headline: 'Integrity cannot be verified right now: history key unavailable' });
    expect(`${v.headline} ${v.detail}`).not.toMatch(/may have been tampered|broken/i);
  });
  it('broken is red with row and reason', () => {
    expect(chainView({ chainOk: false, chainBrokenAt: 7, chainStatus: 'broken', chainReason: 'row hash mismatch' }))
      .toMatchObject({ status: 'broken', tone: 'error', headline: 'Hash chain broken at row 7: row hash mismatch' });
  });
  it('older servers fall back to chainOk', () => {
    expect(chainView({ chainOk: false, chainBrokenAt: 2 }).status).toBe('broken');
    expect(chainView({ chainOk: true, chainBrokenAt: null }).status).toBe('ok');
  });
});

describe('M6 HistoryDrawer renders three states', () => {
  const open = () => wrap(<HistoryDrawer scopeType="group" scopeValue="g" title="History" canRollback={false} onClose={vi.fn()} onRolledBack={vi.fn()} />);
  it('unverifiable: amber banner with the reason, not "tampered"', async () => {
    api.listFimRegHistory.mockResolvedValue(page({ chainOk: false, chainStatus: 'unverifiable', chainReason: 'key missing', chainKeyed: false }) as never);
    open();
    const s = await screen.findByTestId('fim-chain-status');
    expect(s).toHaveAttribute('data-chain', 'unverifiable');
    expect(s).toHaveAttribute('data-tone', 'warn');
    expect(s).toHaveTextContent('Integrity cannot be verified right now: key missing');
    expect(s.textContent).not.toMatch(/may have been tampered/);
  });
  it('broken: red banner with row N and reason', async () => {
    api.listFimRegHistory.mockResolvedValue(page({ chainOk: false, chainBrokenAt: 12, chainStatus: 'broken', chainReason: 'prev hash mismatch' }) as never);
    open();
    const s = await screen.findByTestId('fim-chain-status');
    expect(s).toHaveAttribute('data-tone', 'error');
    expect(s).toHaveTextContent('Hash chain broken at row 12: prev hash mismatch');
  });
  it('ok but not keyed: amber "not keyed"', async () => {
    api.listFimRegHistory.mockResolvedValue(page({ chainStatus: 'ok', chainKeyed: false }) as never);
    open();
    const s = await screen.findByTestId('fim-chain-status');
    expect(s).toHaveAttribute('data-tone', 'warn');
    expect(s).toHaveTextContent(/NOT keyed/);
  });
});

// ---------------------------------------------------------------- M7 registry disabled
const keyMissing503 = { response: { status: 503, data: { message: 'FIM registry is disabled: FIM_HISTORY_HMAC_KEY is missing or too short', errors: ['history_key_missing'] } } };

describe('M7 registry disabled (history key missing)', () => {
  it('errMsg maps the 503 history_key_missing to a clear message', () => {
    expect(historyKeyMissing(keyMissing503)).toBe(true);
    expect(errMsg(keyMissing503, 'x')).toBe(HISTORY_KEY_MISSING_TEXT);
    expect(historyKeyMissing({ response: { status: 503, data: { errors: ['other'] } } })).toBe(false);
  });

  it('Registry tab shows a banner when registryDisabledReason is set', async () => {
    api.getFimRegSettings.mockResolvedValue({ managedEnabled: true, updatedBy: null, updatedAt: null, catalogVersion: 1, isSuperAdmin: false, limits: {} as FimRegSettings['limits'], historyKeyed: false, registryDisabledReason: 'FIM_HISTORY_HMAC_KEY is missing or too short' });
    wrap(<RegistryTab />);
    const b = await screen.findByTestId('fim-registry-disabled');
    expect(b).toHaveTextContent('Registry coverage changes are disabled by the server: FIM_HISTORY_HMAC_KEY is missing or too short');
    cleanup();
    api.getFimRegSettings.mockResolvedValue({ managedEnabled: true, updatedBy: null, updatedAt: null, catalogVersion: 1, isSuperAdmin: false, limits: {} as FimRegSettings['limits'], historyKeyed: true, registryDisabledReason: null });
    wrap(<RegistryTab />);
    await screen.findByText('node coverage');
    expect(screen.queryByTestId('fim-registry-disabled')).toBeNull();
  });

  it('a registry write answered with 503 history_key_missing shows the clear message', async () => {
    const prof: FimRegProfile = { id: 7, name: 'W', description: '', tier: 'essential', isDefault: false, scanIntervalSecs: 3600, mode: 'enforce', version: 1, createdBy: null, updatedBy: null, createdAt: 1, updatedAt: 1, affectedNodes: 2, rules: [], digest: 'd' };
    api.listFimRegProfiles.mockResolvedValue({ items: [prof] });
    api.startFimRegProfilePublish.mockRejectedValue(keyMissing503);
    wrap(<ProfileEditor isSuperAdmin limits={null} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Publish all nodes/ }));
    await user.type(screen.getByLabelText('Note (required)'), 'n');
    await user.click(screen.getByRole('button', { name: 'Publish' }));
    expect(await screen.findByText(HISTORY_KEY_MISSING_TEXT)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------- L7 job polling
const job = (over: Partial<FimRegJob> = {}): FimRegJob => ({
  id: 9, kind: 'publish_profile', status: 'running', total: 4, done: 1, failed: 0, results: [], error: null,
  createdBy: null, createdAt: 1, heartbeatAt: 1, finishedAt: null, ...over,
});

describe('L7 pollRegistryJob', () => {
  it('stops at once on any 4xx (401 / 400)', async () => {
    for (const status of [401, 400, 409]) {
      const fetchJob = vi.fn(async () => { throw { response: { status, data: { message: 'nope' } } }; });
      let sleeps = 0;
      await expect(pollRegistryJob(9, { fetchJob, sleep: async () => { if (++sleeps > 20) throw new Error('kept polling'); } })).rejects.toBeInstanceOf(JobPollError);
      expect(fetchJob).toHaveBeenCalledTimes(1);
    }
  });

  it('retries 5xx / network errors with exponential backoff and gives up after 5 consecutive failures', async () => {
    const fetchJob = vi.fn(async () => { throw { response: { status: 502 } }; });
    // Guard: if the cap were missing this would poll forever; fail loudly instead of hanging.
    const sleep = vi.fn<(ms: number) => Promise<void>>(async () => { if (sleep.mock.calls.length > 20) throw new Error('kept polling past the failure cap'); });
    const err = await pollRegistryJob(9, { fetchJob, sleep }).catch((e) => e);
    expect(err).toBeInstanceOf(JobPollError);
    expect(String(err.message)).toMatch(/after 5 attempts/);
    expect(fetchJob).toHaveBeenCalledTimes(5);
    expect(sleep.mock.calls.map((c) => c[0])).toEqual([4000, 8000, 16000, 30000]);
  });

  it('a success resets the failure count', async () => {
    const seq = [new Error('net'), new Error('net'), job(), new Error('net'), job({ status: 'done', done: 4 })];
    const fetchJob = vi.fn(async () => { const x = seq.shift()!; if (x instanceof Error) throw x; return x; });
    const final = await pollRegistryJob(9, { fetchJob, sleep: async () => {} });
    expect(final?.status).toBe('done');
  });

  it('ends on an unknown status and on aborted', async () => {
    const unknown = await pollRegistryJob(9, { fetchJob: async () => job({ status: 'paused' as never }), sleep: async () => { throw new Error('should not sleep'); } });
    expect(unknown?.status).toBe('paused');
    expect(jobProgressText(unknown!)).toMatch(/unknown status "paused"/);
    const aborted = await pollRegistryJob(9, { fetchJob: async () => job({ status: 'aborted', error: 'profile changed during publish' }), sleep: async () => {} });
    expect(jobProgressText(aborted!)).toBe('Publish aborted at 1/4, 0 failed: profile changed during publish');
  });
});

describe('L7 PublishJobPanel', () => {
  it('aborted: shows the error and already-published hosts, no spinner', async () => {
    api.getFimRegJob.mockResolvedValue(job({ status: 'aborted', done: 2, error: 'profile changed during publish', results: [{ host: 'w1', status: 'ok', error: null }, { host: 'w2', status: 'ok', error: null }] }));
    wrap(<PublishJobPanel jobId={9} initial={job()} onDismiss={vi.fn()} canCancel />);
    const p = screen.getByTestId('fim-publish-job');
    await waitFor(() => expect(p).toHaveTextContent('Publish aborted at 2/4, 0 failed: profile changed during publish'));
    expect(p).toHaveTextContent('2 host(s) were already published');
    expect(screen.queryByTestId('fim-job-spinner')).toBeNull();
    expect(p).toHaveAttribute('data-active', 'false');
    expect(screen.queryByRole('button', { name: /Cancel publish/ })).toBeNull();
  });

  it('unknown status ends the spinner; error text goes through safeText', async () => {
    api.getFimRegJob.mockResolvedValue(job({ status: 'weird' as never, error: `bad\u202Etxt.exe` }));
    wrap(<PublishJobPanel jobId={9} initial={job()} onDismiss={vi.fn()} />);
    const p = screen.getByTestId('fim-publish-job');
    await waitFor(() => expect(p).toHaveTextContent(/unknown status/));
    expect(screen.queryByTestId('fim-job-spinner')).toBeNull();
    expect(p.textContent).not.toContain('\u202E');
    expect(p.textContent).toContain('\u27E8U+202E\u27E9');
  });

  it('a 4xx while polling stops with a message and no spinner', async () => {
    api.getFimRegJob.mockRejectedValue({ response: { status: 401, data: { message: 'Session expired' } } });
    wrap(<PublishJobPanel jobId={9} initial={job()} onDismiss={vi.fn()} />);
    const p = screen.getByTestId('fim-publish-job');
    await waitFor(() => expect(p).toHaveTextContent(/HTTP 401/));
    expect(screen.queryByTestId('fim-job-spinner')).toBeNull();
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeInTheDocument();
  });

  it('Super Admin can cancel a running job', async () => {
    api.getFimRegJob.mockReturnValue(new Promise(() => {}));
    api.cancelFimRegJob.mockResolvedValue(job({ status: 'cancelled', done: 1 }));
    wrap(<PublishJobPanel jobId={9} initial={job()} onDismiss={vi.fn()} canCancel />);
    expect(screen.getByTestId('fim-job-spinner')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: /Cancel publish/ }));
    await waitFor(() => expect(api.cancelFimRegJob).toHaveBeenCalledWith(9));
    expect(confirm).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByTestId('fim-publish-job')).toHaveTextContent('Publish cancelled at 1/4'));
    expect(screen.queryByTestId('fim-job-spinner')).toBeNull();
  });

  it('no Cancel button without Super Admin rights', () => {
    api.getFimRegJob.mockReturnValue(new Promise(() => {}));
    wrap(<PublishJobPanel jobId={9} initial={job()} onDismiss={vi.fn()} />);
    expect(screen.queryByRole('button', { name: /Cancel publish/ })).toBeNull();
  });
});

// ---------------------------------------------------------------- Round 5: registry health warnings
describe('Registry tab health warnings', () => {
  const base = { managedEnabled: true, updatedBy: null, updatedAt: null, catalogVersion: 1, isSuperAdmin: false, limits: {} as FimRegSettings['limits'], historyKeyed: true };

  it('shows healthWarnings as an amber list next to the red disabled banner', async () => {
    api.getFimRegSettings.mockResolvedValue({
      ...base, registryDisabledReason: 'FIM registry schema could not be applied: permission denied',
      healthWarnings: ['FIM perf indexes are being built in the background', 'FIM perf indexes missing: idx_query_result_qname_host_id'],
    });
    wrap(<RegistryTab />);
    const list = await screen.findByTestId('fim-health-warnings');
    expect(list).toHaveClass('bg-amber-50');
    expect(list.querySelectorAll('li')).toHaveLength(2);
    expect(list).toHaveTextContent('FIM perf indexes are being built in the background');
    expect(list).toHaveTextContent('FIM perf indexes missing: idx_query_result_qname_host_id');
    const red = screen.getByTestId('fim-registry-disabled');
    expect(red).toHaveClass('bg-red-50');
    expect(red).toHaveTextContent('FIM registry schema could not be applied: permission denied');
  });

  it('shows nothing for an empty array (or when the field is missing)', async () => {
    api.getFimRegSettings.mockResolvedValue({ ...base, registryDisabledReason: null, healthWarnings: [] });
    wrap(<RegistryTab />);
    await screen.findByText('node coverage');
    expect(screen.queryByTestId('fim-health-warnings')).toBeNull();
    cleanup();
    api.getFimRegSettings.mockResolvedValue({ ...base });
    wrap(<RegistryTab />);
    await screen.findByText('node coverage');
    expect(screen.queryByTestId('fim-health-warnings')).toBeNull();
  });

  it('routes warning and disabled-reason text through safeText (U+202E escaped)', async () => {
    api.getFimRegSettings.mockResolvedValue({ ...base, registryDisabledReason: 'schema ‮dab', healthWarnings: ['FIM schema invariant broken: trigger trg‮fdp.exe disabled (re-applied)'] });
    wrap(<RegistryTab />);
    const list = await screen.findByTestId('fim-health-warnings');
    expect(list.textContent).not.toContain('‮');
    expect(list.textContent).toContain('trg⟨U+202E⟩fdp.exe');
    expect(list.querySelector('[data-fim-escape="U+202E"][data-fim-hidden="true"]')).not.toBeNull();
    const red = screen.getByTestId('fim-registry-disabled');
    expect(red.textContent).not.toContain('‮');
    expect(red.textContent).toContain('schema ⟨U+202E⟩dab');
  });
});
