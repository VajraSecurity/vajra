import { useCallback, useEffect, useState } from 'react';
import { listFimRegWaivers, decideFimRegWaiver, type FimRegWaiver } from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { errMsg, fmtTime } from '../constants';
import { EmptyBox, ErrorBanner, LoadingRows, SegmentedControl } from '../ui';
import { btnGhost, btnPrimary, cardCls, tdCls, thCls } from '../styles';
import { safeText } from './safeText';
import { Banner, RegText } from './RegUi';
import { WAIVER_ACTION_LABEL, canApplyWaiver } from './regModel';
import NoteModal from './NoteModal';
import { ApplyWaiverModal, WaiverRuleView } from './WaiverList';

type Tab = 'pending' | 'approved' | 'history';
const SOON = 7 * 86400;
const STATUS_CLS: Record<string, string> = {
  pending: 'bg-amber-100 text-amber-800', approved: 'bg-emerald-100 text-emerald-700', rejected: 'bg-red-100 text-red-700',
  revoked: 'bg-slate-100 text-slate-600', expired: 'bg-slate-100 text-slate-600',
};

/** Waiver queue (two-person rule): pending, approved (expiring soon highlighted) and history. */
export default function WaiversView({ isSuperAdmin }: { isSuperAdmin: boolean }) {
  const { showToast } = useToast();
  const [tab, setTab] = useState<Tab>('pending');
  const [items, setItems] = useState<FimRegWaiver[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [decide, setDecide] = useState<{ w: FimRegWaiver; d: 'approve' | 'reject' | 'revoke' } | null>(null);
  const [apply, setApply] = useState<FimRegWaiver | null>(null);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));

  const load = useCallback(async () => {
    setErr(null); setLoading(true);
    try {
      const r = tab === 'history' ? await listFimRegWaivers() : await listFimRegWaivers({ status: tab });
      const list = r.items ?? [];
      setItems(tab === 'history' ? list.filter((w) => w.status !== 'pending' && w.status !== 'approved') : list);
      setNow(Math.floor(Date.now() / 1000));
    } catch (e) { setErr(errMsg(e, 'Failed to load waivers')); } finally { setLoading(false); }
  }, [tab]);
  useEffect(() => { setItems(null); load(); }, [load]);

  const sorted = (items ?? []).slice().sort((a, b) => (tab === 'approved' ? a.expiresAt - b.expiresAt : b.requestedAt - a.requestedAt));
  const stale = !!err && !!items;

  return (
    <div className="space-y-3">
      <Banner tone="info">
        Protected entries can only be disabled, narrowed, excluded or lowered in severity with an approved waiver. <b>Two-person rule:</b> a waiver is requested by a Group Admin or Super Admin for <b>one exact change</b> and must be approved by a <b>different</b> Super Admin or designated approver. After approval, the requester (or a Super Admin) clicks <b>Apply approved change</b> to create that change once; then Apply / publish the scope. Waivers last at most 30 days; on expiry the rule stops applying, coverage is restored at the next reconcile, and an alert is raised.
      </Banner>
      <div className="flex flex-wrap items-center gap-2">
        <SegmentedControl value={tab} onChange={setTab} size="sm" options={[{ value: 'pending', label: 'Pending' }, { value: 'approved', label: 'Approved' }, { value: 'history', label: 'History' }]} />
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {err && <ErrorBanner message={err} onRetry={load} stale={stale} />}
      <div className={`${cardCls} overflow-x-auto ${stale ? 'opacity-60' : ''}`}>
        {!items ? (loading ? <LoadingRows /> : <EmptyBox title="Waivers could not be loaded" description="Use Retry above." />) : sorted.length === 0 ? <EmptyBox title={`No ${tab} waivers`} /> : (
          <table className="w-full min-w-[1100px]">
            <thead className="bg-slate-50 dark:bg-slate-800"><tr>
              <th className={thCls}>#</th><th className={thCls}>Entry / change</th><th className={thCls}>Action</th><th className={thCls}>Scope</th><th className={thCls}>Reason</th>
              <th className={thCls}>Requested</th><th className={thCls}>Decision</th><th className={thCls}>Expires</th><th className={thCls}>Status</th><th className={thCls}><span className="sr-only">Actions</span></th>
            </tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {sorted.map((w) => {
                const soon = w.status === 'approved' && w.expiresAt - now < SOON;
                return (
                  <tr key={w.id} className={`align-top ${soon ? 'bg-amber-50 dark:bg-amber-500/10' : ''}`}>
                    <td className={`${tdCls} tabular-nums`}>{w.id}</td>
                    <td className={`${tdCls} max-w-[300px] text-xs`}><RegText value={w.entryKey} mono />
                      {w.rule && <details className="mt-1"><summary className="cursor-pointer text-indigo-700 dark:text-indigo-300">Bound change</summary><WaiverRuleView w={w} /></details>}</td>
                    <td className={tdCls}>{WAIVER_ACTION_LABEL[w.action] ?? safeText(w.action)}</td>
                    <td className={`${tdCls} text-xs`}>{safeText(w.scopeType)} <RegText value={w.scopeValue} mono /></td>
                    <td className={`${tdCls} max-w-[260px] text-xs`}><RegText value={w.reason} /></td>
                    <td className={`${tdCls} whitespace-nowrap text-xs`}><RegText value={w.requestedBy} /><span className="block text-slate-400">{fmtTime(w.requestedAt)}</span></td>
                    <td className={`${tdCls} text-xs`}>{w.approvedBy ? <><RegText value={w.approvedBy} /><span className="block text-slate-400">{fmtTime(w.approvedAt)}</span></> : w.revokedBy ? <>revoked by <RegText value={w.revokedBy} /></> : '-'}
                      {w.decisionNote && <span className="block text-slate-500"><RegText value={w.decisionNote} /></span>}</td>
                    <td className={`${tdCls} whitespace-nowrap text-xs ${soon ? 'font-semibold text-amber-800 dark:text-amber-300' : ''}`}>{fmtTime(w.expiresAt)}{soon && <span className="block">expires within 7 days</span>}</td>
                    <td className={tdCls}><span className={`rounded-full px-2 py-0.5 text-xs font-semibold capitalize ${STATUS_CLS[w.status] ?? STATUS_CLS.expired}`}>{safeText(w.status)}</span>
                      {w.ruleId != null && <span className="block text-[11px] text-slate-500">used: rule #{w.ruleId}</span>}</td>
                    <td className={`${tdCls} whitespace-nowrap`}>
                      {w.status === 'pending' && w.canDecide && <>
                        <button className={`${btnPrimary} mr-1 px-2 py-1 text-xs`} disabled={stale} onClick={() => setDecide({ w, d: 'approve' })}>Approve</button>
                        <button className={`${btnGhost} mr-1 px-2 py-1 text-xs`} disabled={stale} onClick={() => setDecide({ w, d: 'reject' })}>Reject</button>
                      </>}
                      {w.status === 'pending' && !w.canDecide && <span className="text-xs text-slate-400">awaiting another Super Admin or approver</span>}
                      {canApplyWaiver(w, isSuperAdmin, now * 1000) && <button className={`${btnPrimary} mr-1 px-2 py-1 text-xs`} disabled={stale} onClick={() => setApply(w)}>Apply approved change</button>}
                      {(w.status === 'pending' || w.status === 'approved') && w.canRevoke && <button className={`${btnGhost} px-2 py-1 text-xs text-red-600`} disabled={stale} onClick={() => setDecide({ w, d: 'revoke' })}>Revoke</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {decide && (
        <NoteModal title={`${decide.d === 'approve' ? 'Approve' : decide.d === 'reject' ? 'Reject' : 'Revoke'} waiver #${decide.w.id}?`} confirmLabel={decide.d === 'approve' ? 'Approve' : decide.d === 'reject' ? 'Reject' : 'Revoke'}
          danger={decide.d === 'approve'} onClose={() => setDecide(null)}
          description={<>
            <p>{WAIVER_ACTION_LABEL[decide.w.action] ?? safeText(decide.w.action)} <RegText value={decide.w.entryKey} mono /> on {safeText(decide.w.scopeType)} <RegText value={decide.w.scopeValue} mono />, requested by <RegText value={decide.w.requestedBy} />.</p>
            <p className="mt-1">Reason: <RegText value={decide.w.reason} /></p>
            <div className="mt-2 rounded-lg border border-slate-200 p-2 dark:border-white/10">
              <p className="mb-1 text-xs font-semibold uppercase text-slate-500">Exact change {decide.d === 'approve' ? 'you are approving' : 'bound to this waiver'}</p>
              <WaiverRuleView w={decide.w} />
            </div>
            <p className="mt-2">{decide.d === 'approve' ? 'Approving allows exactly this change, once, until the waiver expires. It takes effect after the requester (or a Super Admin) clicks Apply approved change and the scope is published. An alert is raised.' : decide.d === 'reject' ? 'The change cannot be applied.' : 'The waiver stops applying; if its change was applied, coverage is restored at the next Apply.'}</p>
          </>}
          onSubmit={async (note) => { await decideFimRegWaiver(decide.w.id, decide.d, note); showToast(`Waiver #${decide.w.id} ${decide.d === 'approve' ? 'approved' : decide.d === 'reject' ? 'rejected' : 'revoked'}`, 'success'); setDecide(null); load(); }} />
      )}
      {apply && <ApplyWaiverModal w={apply} onClose={() => setApply(null)} onApplied={() => { setApply(null); load(); }} />}
    </div>
  );
}
