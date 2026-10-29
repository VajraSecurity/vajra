import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import {
  getFimInitialization, initializeFimBaseline, type FimInitHost, type FimInitStatus, type FimInitialization, type FimPolicy,
} from '../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';
import { errMsg, fmtTime } from './constants';
import { useFimNodes } from './useFimNodes';
import { Dropdown, ErrorBanner, Field, FimModal, LoadingRows } from './ui';
import { btnGhost, btnPrimary, inputCls, tdCls, thCls } from './styles';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';

const STATUS_STYLE: Record<FimInitStatus, string> = {
  none: 'bg-amber-100 text-amber-800',
  pending: 'bg-blue-100 text-blue-700',
  partial: 'bg-amber-100 text-amber-700',
  done: 'bg-emerald-100 text-emerald-700',
  failed: 'bg-red-100 text-red-700',
};
const POLL_MS = 5000;
const NOTE_MAX = 2000;
const noteError = (n: string) => (n.trim().length > NOTE_MAX ? `At most ${NOTE_MAX} characters` : null);

const REPLACE_WARNING = 'This replaces the baseline with what the machine reports right now: the agent is asked for an immediate full scan, the stored baseline is overwritten, and open drift is superseded. Any pending request for the same host is replaced. Only do this on hosts you trust: anything malicious already present becomes the new normal.';

/** Per-host Initialize / Retry: a user-typed note, then a confirm dialog. */
function HostRunModal({ h, kind, policyName, error, onClose, onRun }: {
  h: FimInitHost; kind: 'init' | 'retry'; policyName: string; error: string | null; onClose: () => void; onRun: (note: string) => Promise<void>;
}) {
  const confirm = useConfirm();
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const label = safeText(h.hostname || h.hostIdentifier);
  const nErr = noteError(note);
  const go = async () => {
    const ok = await confirm({
      title: kind === 'init' ? `Initialize baseline for ${label}?` : `Retry initialization for ${label}?`,
      variant: 'danger',
      confirmLabel: kind === 'init' ? 'Initialize now' : 'Retry now',
      description: `Policy "${safeText(policyName)}". ${REPLACE_WARNING}`,
    });
    if (!ok) return;
    setBusy(true);
    try { await onRun(note.trim()); } finally { setBusy(false); }
  };
  return (
    <FimModal title={kind === 'init' ? `Initialize ${label}` : `Retry initialization of ${label}`} onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>Cancel</button><button className={btnPrimary} disabled={busy || !note.trim() || !!nErr} onClick={go}>{busy ? 'Requesting...' : kind === 'init' ? 'Initialize...' : 'Retry...'}</button></>}>
      <div className="space-y-3">
        {error && <ErrorBanner message={error} />}
        <p className="text-sm text-slate-600 dark:text-slate-300">{kind === 'retry' ? 'The previous initialization failed or completed only partly. ' : ''}{REPLACE_WARNING}</p>
        <Field label="Note (required)" htmlFor="fim-init-host-note" hint={`Why this host is (re)initialized; recorded in the audit log and with the baseline version (at most ${NOTE_MAX} characters).`} error={nErr}>
          <textarea id="fim-init-host-note" rows={2} className={inputCls} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </FimModal>
  );
}

/** Initialize baselines (Tripwire --init) for a policy and watch progress per host. */
export default function InitializationModal({ policy, onClose, onChanged }: { policy: FimPolicy; onClose: () => void; onChanged: () => void }) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const { nodes, loading: nodesLoading, error: nodesErr } = useFimNodes();
  const [scope, setScope] = useState<'all' | 'host'>('all');
  const [host, setHost] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [data, setData] = useState<FimInitialization | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const [hostRun, setHostRun] = useState<{ h: FimInitHost; kind: 'init' | 'retry' } | null>(null);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try { setData(await getFimInitialization(policy.id, { status: filter, page })); setLoadErr(null); }
    catch (e) { setLoadErr(errMsg(e, 'Failed to load initialization status')); }
    finally { setLoading(false); }
  }, [policy.id, filter, page]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [filter]);

  const anyPending = !!data && (data.totals.pending > 0 || data.hosts.some((h) => h.entries.pending > 0));
  useEffect(() => {
    if (!anyPending) return;
    const t = setInterval(() => { load(true); }, POLL_MS);
    return () => clearInterval(t);
  }, [anyPending, load]);

  const run = async (hosts: string[] | undefined, runNote: string): Promise<boolean> => {
    setBusy(true); setErr(null);
    try {
      const r = await initializeFimBaseline(policy.id, runNote, hosts);
      const skipped = r.skipped.length ? `, ${r.skipped.length} skipped` : '';
      showToast(r.requests > 0 ? `Initialization requested for ${r.hosts} host(s)${skipped}` : `Nothing to request${skipped}`, r.requests > 0 ? 'success' : 'info');
      onChanged();
      await load(true);
      return true;
    } catch (e) { setErr(errMsg(e, 'Initialization request failed')); return false; } finally { setBusy(false); }
  };

  const go = async () => {
    const hostLabel = nodes.find((n) => n.host_identifier === host)?.hostname || host;
    const target = scope === 'all' ? `every in-scope host of "${safeText(policy.name)}"` : `host ${safeText(hostLabel)}`;
    const ok = await confirm({
      title: 'Initialize baselines?',
      variant: 'danger',
      confirmLabel: 'Initialize now',
      description: `Target: ${target}. ${REPLACE_WARNING}`,
    });
    if (!ok) return;
    if (await run(scope === 'host' ? [host] : undefined, note.trim())) setNote('');
  };

  const totals = data?.totals;
  const hostLabel = (h: FimInitHost) => h.hostname || h.hostIdentifier;
  const nErr = noteError(note);
  const stale = !!loadErr && !!data;

  return (
    <FimModal wide title={`Baseline initialization: ${safeText(policy.name)}`} onClose={onClose}
      footer={<><button className={btnGhost} onClick={() => load()} disabled={loading}><RefreshCw className="inline h-4 w-4" /> {loading ? 'Refreshing...' : 'Refresh'}</button><button className={btnGhost} onClick={onClose}>Close</button></>}>
      <div className="space-y-4">
        {err && <ErrorBanner message={err} />}
        <p className="text-sm text-slate-600 dark:text-slate-300">Take an immediate full snapshot of the in-scope machines and make it their baseline. Hosts without a baseline are not monitored, and baselines never change automatically - only here or when you approve a drift.</p>
        <fieldset className="space-y-2">
          <legend className="text-xs font-semibold text-slate-600 dark:text-slate-300">Scope</legend>
          <label className="flex items-center gap-2 text-sm"><input type="radio" name="fim-init-scope" checked={scope === 'all'} onChange={() => setScope('all')} /> All hosts in the policy</label>
          <label className="flex items-center gap-2 text-sm"><input type="radio" name="fim-init-scope" checked={scope === 'host'} onChange={() => setScope('host')} /> One host</label>
          {scope === 'host' && (
            <Dropdown aria-label="Host" value={host} onChange={setHost} placeholder={nodesLoading ? 'Loading hosts...' : nodesErr ? 'Hosts unavailable' : 'Choose a host'} options={nodes.map((n) => ({ value: n.host_identifier, label: safeText(n.hostname || n.host_identifier) }))} />
          )}
          {scope === 'host' && nodesErr && <p className="text-xs text-red-600 dark:text-red-400">{safeText(nodesErr)}</p>}
        </fieldset>
        <Field label="Note (required)" htmlFor="fim-init-note" hint={`Recorded in the audit log and with the baseline version (at most ${NOTE_MAX} characters).`} error={nErr}>
          <textarea id="fim-init-note" rows={2} className={inputCls} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <button className={btnPrimary} disabled={busy || !note.trim() || !!nErr || (scope === 'host' && !host) || !policy.enabled} onClick={go}>{busy ? 'Requesting...' : 'Initialize baselines'}</button>
        {!policy.enabled && <p className="text-xs text-amber-600">Enable the policy first.</p>}

        <div>
          {loadErr && <div className="mb-2"><ErrorBanner message={loadErr} onRetry={() => load()} stale={stale} /></div>}
          <div className={`mb-2 flex flex-wrap items-center gap-2 ${stale ? 'opacity-50 grayscale' : ''}`} role="group" aria-label="Initialization totals">
            {(['none', 'pending', 'partial', 'done', 'failed'] as FimInitStatus[]).map((s) => (
              <button key={s} onClick={() => setFilter(filter === s ? '' : s)} aria-pressed={filter === s}
                className={`rounded-full px-2.5 py-1 text-xs font-semibold capitalize ${STATUS_STYLE[s]} ${filter === s ? 'ring-2 ring-indigo-400' : ''}`}>
                {s === 'none' ? 'Not baselined' : s} {totals ? totals[s] : '-'}
              </button>
            ))}
            {anyPending && !stale && <span className="text-xs text-slate-500">Updating every 5 s...</span>}
          </div>
          {loading && !data ? <LoadingRows /> : !data ? (
            <p className="rounded-lg border border-slate-200 px-3 py-6 text-center text-sm text-slate-500 dark:border-white/10">Initialization status could not be loaded. Use Retry above.</p>
          ) : (
            <div className={`overflow-x-auto rounded-lg border border-slate-200 dark:border-white/10 ${stale ? 'opacity-60' : ''}`}>
              <table className="w-full min-w-[640px]">
                <thead className="bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>Host</th><th className={thCls}>Status</th><th className={thCls}>Entries (done / pending / failed)</th><th className={thCls}>Last requested</th><th className={thCls}>Version</th><th className={thCls}><span className="sr-only">Actions</span></th></tr></thead>
                <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                  {data.hosts.length === 0 ? (
                    <tr><td colSpan={6} className={`${tdCls} text-center text-slate-500`}>No hosts in scope.</td></tr>
                  ) : data.hosts.map((h) => (
                    <tr key={h.hostIdentifier}>
                      <td className={tdCls}><RegText value={hostLabel(h)} /></td>
                      <td className={tdCls}><span className={`rounded-full px-2 py-0.5 text-xs font-semibold capitalize ${STATUS_STYLE[h.status] ?? STATUS_STYLE.none}`}>{h.status === 'none' ? 'not baselined' : safeText(h.status)}</span></td>
                      <td className={`${tdCls} tabular-nums`}>{h.entries.done} / {h.entries.pending} / {h.entries.failed + h.entries.expired}</td>
                      <td className={`${tdCls} whitespace-nowrap`}>{fmtTime(h.lastInitAt)}</td>
                      <td className={`${tdCls} tabular-nums`}>{h.latestVersion != null ? `v${h.latestVersion}` : '-'}</td>
                      <td className={tdCls}>
                        {h.status === 'none' && (
                          <button className={btnPrimary} disabled={busy || !policy.enabled || stale} onClick={() => setHostRun({ h, kind: 'init' })}>Initialize...</button>
                        )}
                        {(h.status === 'failed' || h.status === 'partial') && h.entries.pending === 0 && (
                          <button className={btnGhost} disabled={busy || stale} onClick={() => setHostRun({ h, kind: 'retry' })}>Retry...</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data && <Pagination page={page} totalPages={Math.ceil(data.total / (data.pageSize || 1))} total={data.total} pageSize={data.pageSize} onPageChange={setPage} itemLabel="hosts" />}
        </div>
      </div>
      {hostRun && (
        <HostRunModal h={hostRun.h} kind={hostRun.kind} policyName={policy.name} error={err} onClose={() => { setHostRun(null); setErr(null); }}
          onRun={async (n) => { if (await run([hostRun.h.hostIdentifier], n)) setHostRun(null); }} />
      )}
    </FimModal>
  );
}
