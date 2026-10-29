import { useCallback, useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { listFimBaseline, listFimPolicies, type FimBaselineItem, type FimPolicy } from '../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { errMsg, fmtTime } from './constants';
import { useFimNodes } from './useFimNodes';
import { Dropdown, KindBadge, EmptyBox, ErrorBanner, LoadingRows } from './ui';
import { btnGhost, cardCls, inputCls, tdCls, thCls } from './styles';
import { useDebounced } from './useDebounced';
import BaselineVersions from './BaselineVersions';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';
import { SegmentedControl } from './ui';

const itemText = (d: Record<string, unknown> | null | undefined) => Object.entries(d ?? {}).map(([k, v]) => `${k}=${typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}`).join('; ');

export default function BaselineTab() {
  const [view, setView] = useState<'files' | 'versions'>('files');
  const [policies, setPolicies] = useState<FimPolicy[]>([]);
  const [policy, setPolicy] = useState('');
  const [host, setHost] = useState('');
  const [kind, setKind] = useState('');
  const [qInput, setQInput] = useState('');
  const q = useDebounced(qInput.trim());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [items, setItems] = useState<FimBaselineItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [policiesErr, setPoliciesErr] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const { nodes, error: nodesErr } = useFimNodes();

  useEffect(() => { listFimPolicies().then((r) => { setPolicies(r.items ?? []); setPoliciesErr(null); }).catch((e) => { setPolicies([]); setPoliciesErr(errMsg(e, 'Could not load policies')); }); }, []);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await listFimBaseline({ policy, host, q, page, kind });
      setItems(r.items ?? []); setTotal(r.total ?? 0); if (r.pageSize) setPageSize(r.pageSize); setLoaded(true);
    } catch (e) { setError(errMsg(e, 'Failed to load baseline')); } finally { setLoading(false); }
  }, [policy, host, q, page, kind]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [policy, host, q, kind]);

  const hostName = (id: string) => nodes.find((n) => n.host_identifier === id)?.hostname || id;

  if (view === 'versions') {
    return (
      <div className="flex h-full flex-col gap-3 min-h-0">
        <SegmentedControl value={view} onChange={setView} size="sm" options={[{ value: 'files', label: 'Files' }, { value: 'versions', label: 'Versions' }]} />
        <div className="flex-1 min-h-0"><BaselineVersions /></div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-3 min-h-0">
      <SegmentedControl value={view} onChange={setView} size="sm" options={[{ value: 'files', label: 'Files' }, { value: 'versions', label: 'Versions' }]} />
      <div className="flex flex-wrap items-end gap-2">
        <Dropdown aria-label="Policy" value={policy} onChange={setPolicy} placeholder="All policies" options={policies.map((p) => ({ value: String(p.id), label: safeText(p.name) }))} />
        <Dropdown aria-label="Kind" value={kind} onChange={setKind} placeholder="All kinds" options={[{ value: 'file', label: 'Files' }, { value: 'directory', label: 'Directories' }, { value: 'item', label: 'Config items' }]} />
        <Dropdown aria-label="Host" value={host} onChange={setHost} placeholder="All hosts" options={nodes.map((n) => ({ value: n.host_identifier, label: safeText(n.hostname || n.host_identifier) }))} />
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input aria-label="Search path" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="Search path" className={`${inputCls} pl-8 w-56`} />
        </div>
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {(policiesErr || nodesErr) && <p className="text-xs text-red-600 dark:text-red-400">Some filters are unavailable: {safeText([policiesErr, nodesErr].filter(Boolean).join('; '))}</p>}
      {error && <ErrorBanner message={error} onRetry={load} stale={loaded} />}
      <div className={`${cardCls} flex-1 min-h-0 overflow-auto ${error && loaded ? 'opacity-60' : ''}`}>
        {loading && !loaded ? <LoadingRows /> : !loaded ? <EmptyBox title="Baseline could not be loaded" description="Use Retry above." /> : items.length === 0 ? (
          <EmptyBox title="No baseline files" description="Baselines fill in as hosts complete their first scans of a published policy." />
        ) : (
          <table className="w-full min-w-[820px]">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>Path</th><th className={thCls}>Host</th><th className={thCls}>SHA-256</th><th className={thCls}>Size</th><th className={thCls}>Mode</th><th className={thCls}>Last seen</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {items.map((b) => {
                const key = `${b.policyId}|${b.hostIdentifier}|${b.path}`;
                return (
                  <tr key={key} className="align-top hover:bg-slate-50 dark:hover:bg-white/5">
                    <td className={`${tdCls} max-w-[320px]`}><span className="block truncate font-mono text-xs" title={safeText(b.path)}><KindBadge kind={b.kind} /> <RegText value={b.path} nowrap /></span></td>
                    <td className={tdCls}><RegText value={hostName(b.hostIdentifier)} /></td>
                    <td className={tdCls}>
                      <button className="font-mono text-xs text-left hover:underline" aria-expanded={expanded === key} onClick={() => setExpanded(expanded === key ? null : key)} title="Show full hashes">
                        {b.kind === 'item'
                          ? (expanded === key ? <RegText value={itemText(b.data) || '-'} /> : <RegText value={Array.from(itemText(b.data)).slice(0, 40).join('') || '-'} />)
                          : b.kind === 'directory' ? <span>directory (no content hash)</span>
                          : expanded === key ? (<span className="break-all">SHA-256 <RegText value={b.sha256 || '-'} /><br />MD5 <RegText value={b.md5 || '-'} /></span>) : b.sha256 ? <RegText value={`${b.sha256.slice(0, 16)}...`} /> : '-'}
                      </button>
                    </td>
                    <td className={`${tdCls} tabular-nums`}><RegText value={b.size ?? '-'} /></td>
                    <td className={`${tdCls} font-mono text-xs`}><RegText value={`${b.mode ?? '-'}${b.uid != null ? ` ${b.uid}:${b.gid ?? '?'}` : ''}`} /></td>
                    <td className={`${tdCls} whitespace-nowrap`}>{fmtTime(b.lastSeen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <Pagination page={page} totalPages={Math.ceil(total / pageSize)} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="files" />
    </div>
  );
}
