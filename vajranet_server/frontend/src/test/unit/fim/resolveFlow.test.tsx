import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FimAlert, FimDrift } from '@/api/services/fimApi';
import * as fimApi from '@/api/services/fimApi';
import { ToastContext } from '@/context/useToast';
import { ConfirmDialogContext } from '@/context/useConfirm';
import DriftTab, { ResolveModal } from '@/features/FileIntegrity/DriftTab';
import { CloseModal } from '@/features/FileIntegrity/AlertsTab';

vi.mock(import('@/api/services/fimApi'), async (orig) => ({
  ...(await orig()),
  resolveFimDrift: vi.fn(),
  closeFimAlerts: vi.fn(),
  listFimDrift: vi.fn(),
  listFimPolicies: vi.fn(),
  recheckFimDrift: vi.fn(),
}));

const api = vi.mocked(fimApi);
const showToast = vi.fn();
const confirm = vi.fn(async () => false);

function wrap(ui: ReactNode) {
  return render(
    <ToastContext.Provider value={{ showToast }}>
      <ConfirmDialogContext.Provider value={{ confirm }}>{ui}</ConfirmDialogContext.Provider>
    </ToastContext.Provider>,
  );
}

const drift = (id: number, over: Partial<FimDrift> = {}): FimDrift => ({
  id, policyId: 1, policyName: 'Linux baseline', hostIdentifier: 'h1', hostname: 'host-1', path: `/etc/file${id}`, kind: 'file',
  changeType: 'modified', source: 'scan', severity: 'low', oldSha256: 'old', newSha256: `new${id}`, oldAttrs: null, newAttrs: null,
  actorProcess: null, actorUser: null, status: 'open', occurrences: 1, detectedAt: 1, lastSeenAt: 2, resolvedBy: null, resolvedAt: null,
  note: null, contentHash: `ch${id}`, ...over,
});

const err409 = (message: string, errors: string[]) => ({ response: { status: 409, data: { message, errors } } });

async function chooseAndSubmit(action: 'Approve' | 'Reject' | 'Ignore', note = 'CHG-1') {
  const user = userEvent.setup();
  await user.click(screen.getByRole('radio', { name: action }));
  await user.type(screen.getByLabelText('Note (required)'), note);
  await user.click(screen.getByRole('button', { name: action }));
  return user;
}

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  confirm.mockResolvedValue(false);
});

describe('ResolveModal', () => {
  it('has no default action: nothing is selected and submit is disabled until the user picks one', async () => {
    wrap(<ResolveModal items={[drift(1)]} onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    for (const name of ['Approve', 'Reject', 'Ignore']) expect(screen.getByRole('radio', { name })).not.toBeChecked();
    const submit = screen.getByRole('button', { name: 'Choose an action' });
    expect(submit).toBeDisabled();
    await userEvent.setup().type(screen.getByLabelText('Note (required)'), 'note');
    expect(screen.getByRole('button', { name: 'Choose an action' })).toBeDisabled();
    expect(api.resolveFimDrift).not.toHaveBeenCalled();
  });

  it('approves with expected = { id: { contentHash } } only (no lastSeenAt)', async () => {
    api.resolveFimDrift.mockResolvedValue({ resolved: 1, skipped: 0, results: [{ id: 1, outcome: 'resolved' }] });
    const onDone = vi.fn();
    wrap(<ResolveModal items={[drift(1)]} onClose={vi.fn()} onDone={onDone} onStale={vi.fn()} />);
    await chooseAndSubmit('Approve');
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.resolveFimDrift).toHaveBeenCalledWith([1], 'approve', 'CHG-1', { expected: { 1: { contentHash: 'ch1' } } });
    expect(showToast).toHaveBeenCalledWith(expect.any(String), 'success');
  });

  it('409 drift_changed: shows the message, keeps the modal open and reloads keeping the item', async () => {
    api.resolveFimDrift.mockRejectedValue(err409('The drift changed since it was reviewed (1 item(s))', ['drift_changed', JSON.stringify({ id: 1, contentHash: 'x', newSha256: 'zz', changeType: 'modified', lastSeenAt: 9 })]));
    const onDone = vi.fn(); const onClose = vi.fn(); const onStale = vi.fn();
    wrap(<ResolveModal items={[drift(1)]} onClose={onClose} onDone={onDone} onStale={onStale} />);
    await chooseAndSubmit('Approve');
    expect(await screen.findByText('The drift changed since it was reviewed (1 item(s))')).toBeInTheDocument();
    expect(screen.getByText(/Nothing was approved/)).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(onStale).toHaveBeenCalledWith([1]);
    expect(screen.getByRole('button', { name: 'Review again' })).toBeDisabled();
  });

  it('409 awaiting_confirmation: shows the message and does not close the modal', async () => {
    api.resolveFimDrift.mockRejectedValue(err409('Awaiting confirmation scan: 1 real-time registry change(s)', ['awaiting_confirmation', '1']));
    const onDone = vi.fn(); const onClose = vi.fn();
    wrap(<ResolveModal items={[drift(1)]} onClose={onClose} onDone={onDone} onStale={vi.fn()} />);
    await chooseAndSubmit('Approve');
    expect(await screen.findByText('Awaiting confirmation scan: 1 real-time registry change(s)')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('multi-item partial approve lists the items NOT approved with the reason and is not reported as success', async () => {
    api.resolveFimDrift.mockResolvedValue({
      resolved: 1, skipped: 2,
      results: [
        { id: 1, outcome: 'resolved' },
        { id: 2, outcome: 'drift_changed', current: { contentHash: 'x', newSha256: 'changed-hash', changeType: 'modified', lastSeenAt: 9 } },
        { id: 3, outcome: 'awaiting_confirmation' },
      ],
    });
    const onDone = vi.fn(); const onStale = vi.fn();
    wrap(<ResolveModal items={[drift(1), drift(2), drift(3)]} onClose={vi.fn()} onDone={onDone} onStale={onStale} />);
    await chooseAndSubmit('Approve');
    const notice = await screen.findByTestId('fim-bulk-refused');
    expect(notice).toHaveTextContent('1 of 3 drift item(s) approved; 2 NOT approved');
    expect(within(screen.getByTestId('fim-refused-2')).getByText(/content changed/)).toBeInTheDocument();
    expect(within(screen.getByTestId('fim-refused-2')).getByText('changed-hash')).toBeInTheDocument();
    expect(within(screen.getByTestId('fim-refused-3')).getByText(/confirmation scan/)).toBeInTheDocument();
    expect(screen.queryByTestId('fim-refused-1')).toBeNull();
    expect(onDone).not.toHaveBeenCalled();
    expect(onStale).toHaveBeenCalledWith([2, 3]);
    expect(showToast).not.toHaveBeenCalledWith(expect.anything(), 'success');
    expect(api.resolveFimDrift).toHaveBeenCalledWith([1, 2, 3], 'approve', 'CHG-1', { expected: { 1: { contentHash: 'ch1' }, 2: { contentHash: 'ch2' }, 3: { contentHash: 'ch3' } } });
  });

  it('approve is unavailable when a row carries no contentHash', () => {
    wrap(<ResolveModal items={[drift(1, { contentHash: null })]} onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    expect(screen.getByRole('radio', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByRole('radio', { name: 'Reject' })).not.toBeDisabled();
  });
});

describe('DriftTab keeps NOT-approved items selected after a partial approve', () => {
  it('reloads the list with the refused items still selected', async () => {
    api.listFimPolicies.mockResolvedValue({ items: [] } as never);
    api.listFimDrift
      .mockResolvedValueOnce({ items: [drift(1), drift(2)], total: 2, page: 1, pageSize: 25 })
      .mockResolvedValue({ items: [drift(2, { contentHash: 'ch2b', newSha256: 'changed' })], total: 1, page: 1, pageSize: 25 });
    api.resolveFimDrift.mockResolvedValue({
      resolved: 1, skipped: 1,
      results: [{ id: 1, outcome: 'resolved' }, { id: 2, outcome: 'drift_changed', current: { contentHash: 'ch2b', newSha256: 'changed', changeType: 'modified', lastSeenAt: 3 } }],
    });
    const user = userEvent.setup();
    wrap(<DriftTab />);
    await user.click(await screen.findByRole('checkbox', { name: 'Select all open on this page' }));
    await user.click(screen.getByRole('button', { name: 'Resolve selected...' }));
    await chooseAndSubmit('Approve');
    await screen.findByTestId('fim-bulk-refused');
    await user.click(screen.getByRole('button', { name: 'Close and review' }));
    await waitFor(() => expect(api.listFimDrift).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Select /etc/file2' })).toBeChecked());
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });
});

const alert = (alertId: number, driftId: number | null, over: Partial<FimAlert> = {}): FimAlert => ({
  alertId, alertType: 'fim', severity: 'low', eventCode: 'FIM_DRIFT', hostIdentifier: 'h1', hostname: 'host-1', detectedAt: 1, isOpen: true,
  markType: null, remarks: null, policyId: 1, policyName: 'p', driftId, kind: 'file', changeType: driftId ? 'modified' : null, path: driftId ? `/etc/a${alertId}` : null,
  source: 'scan', oldSha256: null, newSha256: null, actorProcess: null, actorUser: null, occurrences: 1, driftStatus: driftId ? 'open' : null,
  driftLastSeenAt: null, contentHash: driftId ? `ah${driftId}` : null, ...over,
});

describe('CloseModal (alerts, approveChange)', () => {
  it('sends expected keyed by driftId with contentHash only and lists alerts NOT closed', async () => {
    api.closeFimAlerts.mockResolvedValue({
      closed: 2, skipped: 1,
      results: [{ id: 1, driftId: 11, outcome: 'closed' }, { id: 2, driftId: 12, outcome: 'drift_changed', current: { contentHash: 'q', newSha256: 'n', changeType: 'modified', lastSeenAt: 1 } }, { id: 3, driftId: null, outcome: 'closed' }],
    });
    const onDone = vi.fn(); const onStale = vi.fn();
    const user = userEvent.setup();
    wrap(<CloseModal alerts={[alert(1, 11), alert(2, 12), alert(3, null)]} verdict="false_positive" onClose={vi.fn()} onDone={onDone} onStale={onStale} />);
    await user.type(screen.getByLabelText('Note (required)'), 'benign');
    await user.click(screen.getByRole('checkbox', { name: /Also approve this change/ }));
    await user.click(screen.getByRole('button', { name: 'Close alerts' }));
    const notice = await screen.findByTestId('fim-bulk-refused');
    expect(notice).toHaveTextContent('2 of 3 alert(s) closed; 1 NOT closed');
    expect(showToast).toHaveBeenCalledWith(expect.stringContaining('NOT closed'), 'error');
    expect(showToast).not.toHaveBeenCalledWith(expect.anything(), 'success');
    expect(within(screen.getByTestId('fim-refused-2')).getByText(/content changed/)).toBeInTheDocument();
    expect(api.closeFimAlerts).toHaveBeenCalledWith([1, 2, 3], 'false_positive', 'benign', { approveChange: true, expected: { 11: { contentHash: 'ah11' }, 12: { contentHash: 'ah12' } } });
    expect(onDone).not.toHaveBeenCalled();
    expect(onStale).toHaveBeenCalledWith([2]);
  });

  it('single alert 409 drift_changed keeps the modal open', async () => {
    api.closeFimAlerts.mockRejectedValue(err409('The drift changed since it was reviewed', ['drift_changed', JSON.stringify({ id: 11, contentHash: 'z', newSha256: 'n', changeType: 'modified', lastSeenAt: 2 })]));
    const onDone = vi.fn(); const onStale = vi.fn();
    const user = userEvent.setup();
    const onClose = vi.fn();
    wrap(<CloseModal alerts={[alert(1, 11)]} verdict="false_positive" onClose={onClose} onDone={onDone} onStale={onStale} />);
    await user.type(screen.getByLabelText('Note (required)'), 'benign');
    await user.click(screen.getByRole('checkbox', { name: /Also approve this change/ }));
    await user.click(screen.getByRole('button', { name: 'Close alerts' }));
    expect(await screen.findByText('The drift changed since it was reviewed')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(onStale).toHaveBeenCalledWith([1]);
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('unconfirmed real-time registry drift cannot be approved client-side', () => {
  const unconfirmed = (id: number) => drift(id, { source: 'realtime', kind: 'item', path: `registry|HKEY_LOCAL_MACHINE\\SOFTWARE\\Run${id}`, confirmedAt: null });

  it('ResolveModal: Approve is not offered, "awaiting confirmation" is shown, and approve is never submitted', async () => {
    const user = userEvent.setup();
    wrap(<ResolveModal items={[unconfirmed(5)]} onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    expect(screen.getByRole('radio', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByRole('radio', { name: 'Reject' })).not.toBeDisabled();
    expect(screen.getAllByText(/Waiting for confirmation scan/).length).toBeGreaterThan(0);
    await user.click(screen.getByRole('radio', { name: 'Approve' }));
    await user.type(screen.getByLabelText('Note (required)'), 'x');
    expect(screen.getByRole('radio', { name: 'Approve' })).not.toBeChecked();
    expect(api.resolveFimDrift).not.toHaveBeenCalled();
  });

  it('ResolveModal: a confirmed real-time registry item can be approved', () => {
    wrap(<ResolveModal items={[{ ...unconfirmed(6), confirmedAt: 99 }]} onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    expect(screen.getByRole('radio', { name: 'Approve' })).not.toBeDisabled();
  });

  it('ResolveModal: one unconfirmed item in a bulk selection blocks Approve for the selection', () => {
    wrap(<ResolveModal items={[drift(1), unconfirmed(5)]} onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    expect(screen.getByRole('radio', { name: 'Approve' })).toBeDisabled();
  });

  it('CloseModal: "Also approve" is disabled with an awaiting-confirmation note; closing never sends approveChange', async () => {
    api.closeFimAlerts.mockResolvedValue({ closed: 1, skipped: 0, results: [{ id: 1, driftId: 11, outcome: 'closed' }] });
    const user = userEvent.setup();
    const a = alert(1, 11, { source: 'realtime', kind: 'item', path: 'registry|HKEY_LOCAL_MACHINE\\SOFTWARE\\Run', driftConfirmedAt: null });
    wrap(<CloseModal alerts={[a]} verdict="false_positive" onClose={vi.fn()} onDone={vi.fn()} onStale={vi.fn()} />);
    const box = screen.getByRole('checkbox', { name: /Also approve this change/ });
    expect(box).toBeDisabled();
    expect(screen.getByText(/waiting for confirmation scan/)).toBeInTheDocument();
    await user.click(box);
    await user.type(screen.getByLabelText('Note (required)'), 'benign');
    await user.click(screen.getByRole('button', { name: 'Close alerts' }));
    await waitFor(() => expect(api.closeFimAlerts).toHaveBeenCalled());
    expect(api.closeFimAlerts).toHaveBeenCalledWith([1], 'false_positive', 'benign', {});
  });
});
