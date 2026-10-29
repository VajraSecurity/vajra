import { useCallback, useEffect, useState } from 'react';
import { listFimRegNeedsInit, type FimRegNeedsInit } from '../../../api/services/fimApi';
import { errMsg, fmtTime } from '../constants';
import { EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost, btnPrimary, cardCls, tdCls, thCls } from '../styles';
import { RegText } from './RegUi';
import InitPromptModal from './InitPromptModal';

/** Nodes with published registry slots that have no baseline yet (not monitored until initialised). */
export default function NeedsInitView() {
  const [items, setItems] = useState<FimRegNeedsInit[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [target, setTarget] = useState<FimRegNeedsInit | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setErr(null); setLoading(true);
    try { setItems((await listFimRegNeedsInit()).items ?? []); } catch (e) { setErr(errMsg(e, 'Failed to load the Needs init queue')); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-slate-600 dark:text-slate-300">These entries are published but have no baseline, so changes to them are not detected. Baselines are only created when you click Initialize.</p>
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {err && <ErrorBanner message={err} onRetry={load} stale={!!items} />}
      <div className={`${cardCls} overflow-x-auto ${err && items ? 'opacity-60' : ''}`}>
        {!items ? (loading ? <LoadingRows /> : <EmptyBox title="The queue could not be loaded" description="Use Retry above." />) : items.length === 0 ? <EmptyBox title="Nothing waiting for Initialize" /> : (
          <table className="w-full min-w-[760px]">
            <thead className="bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>Host</th><th className={thCls}>Entries waiting</th><th className={thCls}>Since</th><th className={thCls}><span className="sr-only">Actions</span></th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {items.map((n) => (
                <tr key={n.host} className="align-top">
                  <td className={tdCls}><RegText value={n.hostname || n.host} />{n.hostname && <RegText value={n.host} mono className="block text-[11px] text-slate-400" />}</td>
                  <td className={`${tdCls} text-xs`}>
                    <details>
                      <summary className="cursor-pointer">{n.slots.length} entr{n.slots.length === 1 ? 'y' : 'ies'}</summary>
                      <ul className="mt-1 space-y-0.5">{n.slots.map((s) => <li key={s.slot}>slot {s.slot} <RegText value={s.entryKey} mono /> <RegText value={s.path} mono className="text-slate-500" /></li>)}</ul>
                    </details>
                  </td>
                  <td className={`${tdCls} whitespace-nowrap text-xs`}>{fmtTime(n.since)}</td>
                  <td className={tdCls}><button className={btnPrimary} disabled={n.slots.length === 0 || !!err} onClick={() => setTarget(n)}>Initialize</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {target && (
        <InitPromptModal policyId={target.policyId} host={target.host} hostLabel={target.hostname || target.host} slots={target.slots.map((s) => s.slot)}
          onClose={(done) => { setTarget(null); if (done) load(); }} />
      )}
    </div>
  );
}
