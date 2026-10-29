import { useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Upload, Trash2, ScanSearch } from 'lucide-react';
import {
  deleteFimPolicy, listFimPolicies, publishFimPolicy, updateFimPolicy, type FimPolicy,
} from '../../api/services/fimApi';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';
import { MODE_LABEL, errMsg, humanInterval } from './constants';
import { EmptyBox, ErrorBanner, LoadingRows } from './ui';
import { btnGhost, btnPrimary, cardCls } from './styles';
import PolicyFormModal from './PolicyFormModal';
import InitializationModal from './InitializationModal';
import { StatusToggle } from '../RuleEngine/ui';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';

export default function PoliciesTab() {
  const [items, setItems] = useState<FimPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<{ policy?: FimPolicy } | null>(null);
  const [initPolicy, setInitPolicy] = useState<FimPolicy | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [showManaged, setShowManaged] = useState(false);
  const confirm = useConfirm();
  const { showToast } = useToast();

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setItems((await listFimPolicies()).items ?? []); setLoaded(true); } catch (e) { setError(errMsg(e, 'Failed to load policies')); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const toggle = async (p: FimPolicy) => {
    const ok = await confirm({
      title: `${p.enabled ? 'Disable' : 'Enable'} "${safeText(p.name)}"?`,
      description: p.configQueryId
        ? `This will also re-publish the policy so hosts ${p.enabled ? 'stop' : 'start'} scanning.`
        : 'The policy has not been published yet; publish it to send it to hosts.',
      confirmLabel: p.enabled ? 'Disable' : 'Enable',
    });
    if (!ok) return;
    setBusyId(p.id);
    try {
      await updateFimPolicy(p.id, { enabled: !p.enabled });
      if (p.configQueryId) await publishFimPolicy(p.id);
      await load();
    } catch (e) { showToast(safeText(errMsg(e, 'Failed to update policy')), 'error'); } finally { setBusyId(null); }
  };

  const publish = async (p: FimPolicy) => {
    const ok = await confirm({ title: `Publish "${safeText(p.name)}"?`, description: 'The saved configuration will be sent to every host in the policy target. Hosts removed from the target stop receiving it.', confirmLabel: 'Publish' });
    if (!ok) return;
    setBusyId(p.id);
    try { await publishFimPolicy(p.id); showToast('Policy published', 'success'); await load(); }
    catch (e) { showToast(safeText(errMsg(e, 'Publish failed')), 'error'); } finally { setBusyId(null); }
  };

  const remove = async (p: FimPolicy) => {
    const ok = await confirm({ title: `Delete "${safeText(p.name)}"?`, description: 'Hosts stop receiving this policy. Its baseline and drift history are removed with it.', confirmLabel: 'Delete', variant: 'danger' });
    if (!ok) return;
    setBusyId(p.id);
    try { await deleteFimPolicy(p.id); await load(); } catch (e) { showToast(safeText(errMsg(e, 'Delete failed')), 'error'); } finally { setBusyId(null); }
  };

  const managedCount = items.filter((p) => p.managedKind === 'registry_node').length;
  const shown = showManaged ? items : items.filter((p) => p.managedKind !== 'registry_node');

  return (
    <div className="h-full overflow-y-auto pb-6 space-y-3">
      <div className="flex flex-wrap items-center justify-end gap-3">
        {managedCount > 0 && (
          <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
            <input type="checkbox" checked={showManaged} onChange={(e) => setShowManaged(e.target.checked)} />
            Show managed registry policies ({managedCount})
          </label>
        )}
        <button className={btnPrimary} onClick={() => setForm({})}><Plus className="h-4 w-4" /> New policy</button>
      </div>
      {error && <ErrorBanner message={error} onRetry={load} stale={loaded} />}
      {loading && !loaded ? <LoadingRows /> : !loaded ? null : shown.length === 0 ? (
        <div className={cardCls}><EmptyBox title="No FIM policies yet" description={managedCount > 0 ? 'Only managed registry policies exist; they are managed from the Registry tab.' : 'Create one (a template is the quickest start), then publish it to your hosts.'} /></div>
      ) : shown.map((p) => { const managed = p.managedKind === 'registry_node'; return (
        <article key={p.id} className={`${cardCls} p-4 ${error ? 'opacity-60' : ''}`} aria-label={`Policy ${safeText(p.name)}`}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h3 className="flex flex-wrap items-center gap-2 text-base font-semibold text-slate-900 dark:text-slate-100"><RegText value={p.name} />
                <span className="rounded-full bg-indigo-100 text-indigo-700 px-2 py-0.5 text-xs font-semibold">{MODE_LABEL[p.mode]}</span>
                <span className="rounded-full bg-slate-100 dark:bg-white/10 px-2 py-0.5 text-xs font-semibold capitalize">{safeText(p.osPlatform)}</span>
                {managed && <span className="rounded-full bg-amber-100 text-amber-800 px-2 py-0.5 text-xs font-semibold" title="Read-only here: change it from the Registry tab">Managed by Registry coverage</span>}
                {!p.configQueryId && <span className="rounded-full bg-amber-100 text-amber-700 px-2 py-0.5 text-xs font-semibold">Not published</span>}
                {p.configQueryId && p.publishedRev != null && p.rev != null && p.publishedRev !== p.rev && <span className="rounded-full bg-amber-100 text-amber-700 px-2 py-0.5 text-xs font-semibold">Changes not published</span>}
              </h3>
              {p.description && <p className="text-sm text-slate-500"><RegText value={p.description} /></p>}
              <p className="mt-1 text-xs text-slate-500">{p.paths.length} path{p.paths.length === 1 ? '' : 's'} - {humanInterval(p.scanIntervalSecs)}{p.realtime ? ' - real-time' : ''}</p>
            </div>
            {managed
              ? <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${p.enabled ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400' : 'bg-slate-100 text-slate-500 dark:bg-white/10'}`}>{p.enabled ? 'Enabled' : 'Disabled'}</span>
              : <StatusToggle enabled={p.enabled} busy={busyId === p.id} onToggle={() => toggle(p)} />}
          </div>
          <dl className="mt-3 grid grid-cols-2 sm:grid-cols-5 gap-2 text-center">
            {([['Hosts', p.stats.hosts], ['Baselined', p.stats.hostsBaselined ?? p.stats.locked], ['Not baselined', p.stats.hostsNotBaselined ?? p.stats.learning], ['Baseline files', p.stats.baselineFiles], ['Open drift', p.stats.openDrift]] as [string, number][]).map(([l, v]) => (
              <div key={l} className="rounded-lg bg-slate-50 dark:bg-white/5 py-2"><dt className="text-xs text-slate-500">{l}</dt><dd className={`text-lg font-bold tabular-nums ${l === 'Open drift' && v > 0 ? 'text-red-600' : ''} ${l === 'Not baselined' && v > 0 ? 'text-amber-600' : ''}`}>{v.toLocaleString()}</dd></div>
            ))}
          </dl>
          <div className="mt-3 flex flex-wrap gap-2">
            {!managed && <button className={btnGhost} onClick={() => setForm({ policy: p })}><Pencil className="h-4 w-4" /> Edit</button>}
            {!managed && <button className={btnGhost} disabled={busyId === p.id} onClick={() => publish(p)}><Upload className="h-4 w-4" /> Publish</button>}
            {!managed && <button className={btnGhost} onClick={() => setInitPolicy(p)}><ScanSearch className="h-4 w-4" /> Initialize baselines</button>}
            {!managed && <button className={`${btnGhost} text-red-600`} disabled={busyId === p.id} onClick={() => remove(p)}><Trash2 className="h-4 w-4" /> Delete</button>}
            {managed && <span className="self-center text-xs text-slate-500">Edit, publish and delete from the Registry tab. Initialize per node in the Registry tab (its Needs init view, or the node&apos;s own view); whole-policy initialization is not offered for managed registry policies.</span>}
          </div>
        </article>
      ); })}
      {form && <PolicyFormModal policy={form.policy} onClose={() => setForm(null)} onSaved={() => { setForm(null); load(); }} />}
      {initPolicy && <InitializationModal policy={initPolicy} onClose={() => setInitPolicy(null)} onChanged={load} />}
    </div>
  );
}
