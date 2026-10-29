import { useCallback, useEffect, useState } from 'react';
import { Copy } from 'lucide-react';
import { listFimBaselineVersions, listFimPolicies, type FimBaselineVersion, type FimPolicy } from '../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useToast } from '../../context/useToast';
import { errMsg, fmtTime } from './constants';
import { useFimNodes } from './useFimNodes';
import { Dropdown, EmptyBox, ErrorBanner, LoadingRows } from './ui';
import { btnGhost, cardCls, tdCls, thCls } from './styles';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';

/** Baseline versions: one row per (re)initialisation of a policy on a host. */
export default function BaselineVersions() {
  const { showToast } = useToast();
  const { nodes, error: nodesErr } = useFimNodes();
  const [policies, setPolicies] = useState<FimPolicy[]>([]);
  const [policy, setPolicy] = useState('');
  const [host, setHost] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [items, setItems] = useState<FimBaselineVersion[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [policiesErr, setPoliciesErr] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { listFimPolicies().then((r) => { setPolicies(r.items ?? []); setPoliciesErr(null); }).catch((e) => { setPolicies([]); setPoliciesErr(errMsg(e, 'Could not load policies')); }); }, []);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await listFimBaselineVersions({ policy, host, page });
      setItems(r.items ?? []); setTotal(r.total ?? 0); if (r.pageSize) setPageSize(r.pageSize); setLoaded(true);
    } catch (e) { setError(errMsg(e, 'Failed to load baseline versions')); } finally { setLoading(false); }
  }, [policy, host, page]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [policy, host]);

  const copy = async (digest: string) => {
    try { await navigator.clipboard.writeText(digest); showToast('Digest copied', 'success'); }
    catch { showToast('Could not copy digest', 'error'); }
  };

  return (
    <div className="flex h-full flex-col gap-3 min-h-0">
      <div className="flex flex-wrap items-end gap-2">
        <Dropdown aria-label="Policy" value={policy} onChange={setPolicy} placeholder="All policies" options={policies.map((p) => ({ value: String(p.id), label: safeText(p.name) }))} />
        <Dropdown aria-label="Host" value={host} onChange={setHost} placeholder="All hosts" options={nodes.map((n) => ({ value: n.host_identifier, label: safeText(n.hostname || n.host_identifier) }))} />
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {(policiesErr || nodesErr) && <p className="text-xs text-red-600 dark:text-red-400">Some filters are unavailable: {safeText([policiesErr, nodesErr].filter(Boolean).join('; '))}</p>}
      {error && <ErrorBanner message={error} onRetry={load} stale={loaded} />}
      <div className={`${cardCls} flex-1 min-h-0 overflow-auto ${error && loaded ? 'opacity-60' : ''}`}>
        {loading && !loaded ? <LoadingRows /> : !loaded ? <EmptyBox title="Baseline versions could not be loaded" description="Use Retry above." /> : items.length === 0 ? (
          <EmptyBox title="No baseline versions" description="A version is recorded each time a baseline is initialized for a host." />
        ) : (
          <table className="w-full min-w-[820px]">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>Host</th><th className={thCls}>Policy</th><th className={thCls}>Version</th><th className={thCls}>When</th><th className={thCls}>By</th><th className={thCls}>Files</th><th className={thCls}>Digest</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {items.map((v) => (
                <tr key={`${v.policyId}|${v.hostIdentifier}|${v.version}`} className="hover:bg-slate-50 dark:hover:bg-white/5">
                  <td className={tdCls}><RegText value={v.hostname || v.hostIdentifier} /></td>
                  <td className={tdCls}><RegText value={v.policyName} /></td>
                  <td className={`${tdCls} tabular-nums`} title={v.note ? safeText(v.note) : undefined}>v{v.version}{v.note && <span className="block max-w-[220px] text-xs text-slate-500"><RegText value={v.note} /></span>}</td>
                  <td className={`${tdCls} whitespace-nowrap`}>{fmtTime(v.createdAt)}</td>
                  <td className={tdCls}><RegText value={v.createdBy || 'system'} /></td>
                  <td className={`${tdCls} tabular-nums`}>{v.fileCount}</td>
                  <td className={tdCls}>
                    <span className="font-mono text-xs" title={safeText(v.digest)}>{safeText(v.digest.slice(0, 12))}</span>
                    <button className="ml-2 align-middle text-slate-500 hover:text-slate-800" aria-label={`Copy digest of ${safeText(v.hostname || v.hostIdentifier)} v${v.version}`} onClick={() => copy(v.digest)}><Copy className="h-3.5 w-3.5" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pagination page={page} totalPages={Math.ceil(total / pageSize)} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="versions" />
    </div>
  );
}
