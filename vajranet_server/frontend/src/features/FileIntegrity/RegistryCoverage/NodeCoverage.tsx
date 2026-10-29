import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Search } from 'lucide-react';
import { listFimRegNodes, type FimRegLimits, type FimRegNodeRow } from '../../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useConfirm } from '../../../context/useConfirm';
import { errMsg, fmtTime } from '../constants';
import { Dropdown, EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost, cardCls, inputCls, tdCls, thCls } from '../styles';
import { useDebounced } from '../useDebounced';
import { RegText, StatusChip, TierBadge } from './RegUi';
import { STATUSES, STATUS_META } from './regModel';
import NodeCoverageView from './NodeCoverageView';

function NodePicker({ onPick }: { onPick: (host: string) => void }) {
  const [qInput, setQInput] = useState('');
  const q = useDebounced(qInput.trim());
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [data, setData] = useState<{ items: FimRegNodeRow[]; total: number; pageSize: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setErr(null);
    try { const r = await listFimRegNodes({ q, status, page }); setData({ items: r.items ?? [], total: r.total ?? 0, pageSize: r.pageSize || 50 }); }
    catch (e) { setErr(errMsg(e, 'Failed to load Windows nodes')); } finally { setLoading(false); }
  }, [q, status, page]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [q, status]);

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="flex flex-wrap items-end gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input aria-label="Search nodes" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="Search host or hostname" className={`${inputCls} w-64 pl-8`} />
        </div>
        <Dropdown aria-label="Status" value={status} onChange={setStatus} placeholder="Any status" options={STATUSES.map((s) => ({ value: s, label: STATUS_META[s].label }))} className="w-48" />
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {err && <ErrorBanner message={err} onRetry={load} stale={!!data} />}
      <div className={`${cardCls} min-h-0 flex-1 overflow-auto`}>
        {loading && !data ? <LoadingRows /> : !data ? <EmptyBox title="Windows nodes could not be loaded" description="Use Retry above." /> : (data?.items ?? []).length === 0 ? <EmptyBox title="No Windows nodes" description="Managed registry coverage applies to Windows nodes in your scope." /> : (
          <table className="w-full min-w-[960px]">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800"><tr>
              <th className={thCls}>Host</th><th className={thCls}>Status</th><th className={thCls}>Profile</th><th className={thCls}>Tier</th><th className={thCls}>Entries</th>
              <th className={thCls}>Needs init</th><th className={thCls}>Node rules</th><th className={thCls}>Real-time</th><th className={thCls}>Published</th>
            </tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {(data?.items ?? []).map((n) => (
                <tr key={n.host} className="hover:bg-slate-50 dark:hover:bg-white/5">
                  <td className={tdCls}>
                    <button className="text-left font-semibold text-indigo-700 hover:underline dark:text-indigo-300" onClick={() => onPick(n.host)}><RegText value={n.hostname || n.host} /></button>
                    {n.hostname && <RegText value={n.host} mono className="block text-[11px] text-slate-400" />}
                  </td>
                  <td className={tdCls}><StatusChip status={n.status} needsInit={n.needsInit} stale={!!err} /></td>
                  <td className={tdCls}><RegText value={n.profileName ?? '-'} /></td>
                  <td className={tdCls}>{n.tier ? <TierBadge tier={n.tier} /> : '-'}</td>
                  <td className={`${tdCls} tabular-nums`}>{n.entries}</td>
                  <td className={`${tdCls} tabular-nums ${n.needsInit ? 'text-blue-700 dark:text-blue-300 font-semibold' : ''}`}>{n.needsInit}</td>
                  <td className={`${tdCls} tabular-nums`}>{n.nodeRules}</td>
                  <td className={tdCls}>{n.realtimeAvailable ? 'yes' : 'no'}</td>
                  <td className={`${tdCls} whitespace-nowrap text-xs`}>{fmtTime(n.publishedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && <Pagination page={page} totalPages={Math.ceil(data.total / data.pageSize)} total={data.total} pageSize={data.pageSize} onPageChange={setPage} itemLabel="nodes" />}
    </div>
  );
}

/** Nodes sub-view: pick a Windows node, then edit its registry coverage. */
export default function NodeCoverage({ isSuperAdmin, limits }: { isSuperAdmin: boolean; limits: FimRegLimits | null }) {
  const confirm = useConfirm();
  const [host, setHost] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const back = async () => {
    if (dirty && !(await confirm({ title: 'Discard pending changes?', description: 'Your pending changes for this node have not been applied and will be lost.', confirmLabel: 'Discard', variant: 'danger' }))) return;
    setDirty(false); setHost(null);
  };
  if (!host) return <NodePicker onPick={setHost} />;
  return (
    <div className="space-y-3">
      <button className={btnGhost} onClick={back}><ArrowLeft className="h-4 w-4" />All nodes</button>
      <NodeCoverageView key={host} host={host} isSuperAdmin={isSuperAdmin} limits={limits} onDirtyChange={setDirty} />
    </div>
  );
}
