import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, History, ShieldAlert, ShieldQuestion, ShieldX } from 'lucide-react';
import { listFimRegHistory, rollbackFimReg, type FimRegHistoryItem } from '../../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useToast } from '../../../context/useToast';
import { errMsg, fmtTime, shortHash } from '../constants';
import { Drawer, EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost } from '../styles';
import { safeText } from './safeText';
import { Banner, RegText } from './RegUi';
import NoteModal from './NoteModal';
import { chainView } from './regModel';

function ChainStatus({ data }: { data: Parameters<typeof chainView>[0] }) {
  const v = chainView(data);
  const Icon = v.status === 'broken' ? ShieldX : v.status === 'unverifiable' ? ShieldQuestion : v.tone === 'warn' ? ShieldAlert : CheckCircle2;
  const body = (
    <span data-testid="fim-chain-status" data-chain={v.status} data-tone={v.tone} className="block">
      <span className="flex items-center gap-1 font-semibold"><Icon aria-hidden className="h-4 w-4 shrink-0" />{safeText(v.headline)}</span>
      {v.detail && <span className="block text-xs font-normal">{safeText(v.detail)}</span>}
    </span>
  );
  if (v.tone === 'ok') return <div className="text-sm text-emerald-700 dark:text-emerald-300">{body}</div>;
  return <Banner tone={v.tone === 'error' ? 'error' : 'warn'}>{body}</Banner>;
}

/** Hash-chained configuration history of one scope, with forward-only rollback (result is pending until Apply). */
export default function HistoryDrawer({ scopeType, scopeValue, title, canRollback, onClose, onRolledBack }: {
  scopeType: string; scopeValue: string; title: string; canRollback: boolean; onClose: () => void; onRolledBack: () => void;
}) {
  const { showToast } = useToast();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Awaited<ReturnType<typeof listFimRegHistory>> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [rollback, setRollback] = useState<FimRegHistoryItem | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setErr(null);
    try { setData(await listFimRegHistory({ scopeType, scopeValue, page })); } catch (e) { setErr(errMsg(e, 'Failed to load history')); } finally { setLoading(false); }
  }, [scopeType, scopeValue, page]);
  useEffect(() => { load(); }, [load]);

  return (
    <Drawer title={title} onClose={onClose}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} onRetry={load} stale={!!data} />}
        {data && <ChainStatus data={data} />}
        {loading && !data ? <LoadingRows /> : !data ? null : (data?.items ?? []).length === 0 ? <EmptyBox title="No history yet" /> : (
          <ol className="space-y-2">
            {(data?.items ?? []).map((h) => (
              <li key={h.id} className="rounded-lg border border-slate-200 p-3 text-sm dark:border-white/10">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold">#{h.id} · <RegText value={h.actor} /> · {fmtTime(h.at)}</span>
                  {canRollback && <button className={btnGhost} onClick={() => setRollback(h)}><History className="h-4 w-4" />Roll back to this</button>}
                </div>
                {h.reason && <p className="text-xs text-slate-600 dark:text-slate-300">Reason: <RegText value={h.reason} /></p>}
                <p className="text-[11px] text-slate-400 font-mono">row {shortHash(h.rowHash)} · prev {shortHash(h.prevHash)}</p>
                <details className="mt-1">
                  <summary className="cursor-pointer text-xs text-indigo-700 dark:text-indigo-300">Snapshot</summary>
                  <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-2 text-[11px] dark:bg-white/5">{safeText(JSON.stringify(h.snapshot, null, 2))}</pre>
                </details>
              </li>
            ))}
          </ol>
        )}
        {data && <Pagination page={page} totalPages={Math.ceil(data.total / (data.pageSize || 1))} total={data.total} pageSize={data.pageSize} onPageChange={setPage} itemLabel="entries" />}
      </div>
      {rollback && (
        <NoteModal title={`Roll back to history #${rollback.id}?`} confirmLabel="Create rollback rules"
          description={<>Rollback is forward-only: it creates <b>new</b> rules equal to that snapshot (audited). Nothing is published: the scope becomes <b>Pending publish</b> until you review and Apply. Slots revived within 7 days keep their baselines.</>}
          onClose={() => setRollback(null)}
          onSubmit={async (note) => {
            const r = await rollbackFimReg(rollback.id, note);
            showToast(`Rollback created ${r.rules} rule(s); status ${safeText(r.status)}. Review and Apply to publish.`, 'success');
            setRollback(null); onRolledBack(); load();
          }} />
      )}
    </Drawer>
  );
}
