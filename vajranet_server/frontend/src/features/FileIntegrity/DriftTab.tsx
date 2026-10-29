import { useCallback, useEffect, useRef, useState } from 'react';
import { Search } from 'lucide-react';
import {
  listFimDrift, getFimDrift, resolveFimDrift, listFimPolicies,
  type FimDrift, type FimPolicy, type FimResolveAction,
} from '../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import { SEVERITIES, errMsg, errStatus, fmtTime, normalizeAttrs } from './constants';
import { ChangeBadge, KindBadge, Dropdown, Drawer, EmptyBox, ErrorBanner, Field, FimModal, LoadingRows, SeverityBadge, StatusPill } from './ui';
import { btnGhost, btnPrimary, cardCls, inputCls, tdCls, thCls } from './styles';
import { useDebounced } from './useDebounced';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';
import { AwaitingConfirmation, BulkRefusedNotice, DriftChangedNotice, RecheckButton, type DriftBefore } from './RecheckButton';
import {
  AWAITING_TEXT, anyRisk, awaitingConfirmation, driftChanged, expectedOf, isProtectedCoverage, isUnconfirmed, needsReview, riskCounts, summarizeBulk,
  type BulkSummary, type DriftChangedItem,
} from './driftSafety';

export interface DriftPreset { severity?: string; host?: string; status?: string }

const ACTIONS: { action: FimResolveAction; label: string; help: string }[] = [
  { action: 'approve', label: 'Approve', help: 'The change is legitimate. The baseline is updated to the new state.' },
  { action: 'reject', label: 'Reject', help: 'The change is bad. It is closed as confirmed-bad and the baseline is kept unchanged.' },
  { action: 'ignore', label: 'Ignore', help: 'Close without judging. The baseline is not changed.' },
];

const NOTE_MAX = 2000;

function HashRow({ label, v }: { label: string; v: string | null }) {
  return <div className="text-xs"><span className="text-slate-400">{label}: </span><RegText value={v || '-'} mono /></div>;
}

function DriftFlags({ d }: { d: FimDrift }) {
  return <>
    {d.reverted && <span title="A check scan found the value back at the baseline after a real-time change (possible tamper-then-revert); kept open for review" className="ml-1 inline-flex rounded-md bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">Reverted</span>}
    {d.confirmedAt ? <span title="Confirmed by a check scan" className="ml-1 inline-flex rounded-md bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold text-slate-600 dark:bg-white/10 dark:text-slate-300">Confirmed</span> : null}
    {isUnconfirmed(d) && d.status === 'open' && <span title={AWAITING_TEXT} className="ml-1 inline-flex rounded-md bg-blue-100 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700 dark:bg-blue-500/15 dark:text-blue-300">Awaiting check scan</span>}
    {isProtectedCoverage(d) && <span title="Registry item of a managed Registry coverage policy" className="ml-1 inline-flex rounded-md bg-violet-100 px-1.5 py-0.5 text-[10px] font-semibold text-violet-700 dark:bg-violet-500/15 dark:text-violet-300">Protected coverage</span>}
  </>;
}

const attrText = (v: unknown) => (v == null ? '-' : typeof v === 'object' ? JSON.stringify(v) : String(v));

export function AttrsTable({ oldA, newA }: { oldA: Record<string, unknown>; newA: Record<string, unknown> }) {
  const keys = Array.from(new Set([...Object.keys(oldA), ...Object.keys(newA)]));
  if (keys.length === 0) return <p className="text-xs text-slate-400">No attribute data.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead><tr><th className={thCls}>Attribute</th><th className={thCls}>Old</th><th className={thCls}>New</th></tr></thead>
        <tbody>
          {keys.map((k) => {
            const o = attrText(oldA[k]);
            const n = attrText(newA[k]);
            return (
              <tr key={k} className={o !== n ? 'bg-amber-50 dark:bg-amber-500/10' : ''}>
                <td className="px-3 py-1 font-semibold"><RegText value={k} /></td><td className="px-3 py-1"><RegText value={o} mono /></td><td className="px-3 py-1"><RegText value={n} mono /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DriftDetail({ id, onClose, onResolve }: { id: number; onClose: () => void; onResolve: (d: FimDrift) => void }) {
  const [d, setD] = useState<FimDrift | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancel = false;
    setLoading(true); setErr(null);
    getFimDrift(id).then((r) => { if (!cancel) setD(r); }).catch((e) => { if (!cancel) setErr(errMsg(e, 'Failed to load drift')); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [id, tick]);
  const reload = () => setTick((t) => t + 1);
  return (
    <Drawer title="Drift detail" onClose={onClose}>
      {err && <ErrorBanner message={err} onRetry={reload} stale={!!d} />}
      {!d && loading && <LoadingRows />}
      {!d && !loading && !err && <EmptyBox title="Drift not found" />}
      {d && (
        <div className={`space-y-5 ${err ? 'opacity-60' : ''}`}>
          <div>
            <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={d.severity} /><KindBadge kind={d.kind} /><ChangeBadge type={d.changeType} /><StatusPill status={d.status} /><DriftFlags d={d} /></div>
            <p className="mt-2 text-sm"><RegText value={d.path} mono /></p>
            <p className="text-xs text-slate-500"><RegText value={d.hostname || d.hostIdentifier} /> - policy <RegText value={d.policyName} />{d.policyDeleted ? ' (deleted; read-only except Ignore)' : ''} - detected via <RegText value={d.source} /></p>
          </div>
          {d.status === 'open' && isUnconfirmed(d) && <AwaitingConfirmation driftId={d.id} />}
          {(d.kind ?? 'file') === 'file' && (
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Content hash (SHA-256)</h4>
              <HashRow label="Old" v={d.oldSha256} /><HashRow label="New" v={d.newSha256} />
            </section>
          )}
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">{d.kind === 'item' ? 'Changed fields (old to new)' : d.kind === 'directory' ? 'Permissions & owner (old to new)' : 'Attributes'}</h4>
            <AttrsTable oldA={normalizeAttrs(d.oldAttrs)} newA={normalizeAttrs(d.newAttrs)} />
          </section>
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Who changed it</h4>
            <p className="text-sm">Process: <RegText value={d.actorProcess || 'unknown (scan-detected)'} mono /></p>
            <p className="text-sm">User: <RegText value={d.actorUser || 'unknown'} mono /></p>
            <p className="text-sm">Occurrences: {d.occurrences}</p>
          </section>
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Timeline</h4>
            <ol className="space-y-1 border-l-2 border-slate-200 dark:border-white/10 pl-3 text-sm">
              <li>First detected: {fmtTime(d.detectedAt)}</li>
              {d.occurrences > 1 && <li>Last seen: {fmtTime(d.lastSeenAt)} ({d.occurrences} times)</li>}
              {d.confirmedAt ? <li>Confirmed by a check scan: {fmtTime(d.confirmedAt)}</li> : null}
              {d.resolvedAt && <li><RegText value={d.status} /> by <RegText value={d.resolvedBy || 'unknown'} />: {fmtTime(d.resolvedAt)}{d.note ? <> - &quot;<RegText value={d.note} />&quot;</> : null}</li>}
            </ol>
          </section>
          <div className="flex flex-wrap gap-2">
            {d.status === 'open' && <button className={btnPrimary} disabled={!!err} title={err ? 'Reload first: this view may be out of date' : undefined} onClick={() => onResolve(d)}>Resolve...</button>}
            <button className={btnGhost} onClick={reload} disabled={loading}>{loading ? 'Reloading...' : 'Reload'}</button>
          </div>
        </div>
      )}
    </Drawer>
  );
}

/**
 * Resolve one or more drift items. There is no default action. Approval is guarded server-side by
 * the reviewed content digest: a single item refused is a 409 (shown, modal stays open); a
 * multi-item request returns per-item results and the items NOT approved are listed here and kept
 * selected (`onStale(ids)` reloads the list keeping those ids selected).
 */
export function ResolveModal({ items, onClose, onDone, onStale }: { items: FimDrift[]; onClose: () => void; onDone: () => void; onStale: (keepSelected?: number[]) => void }) {
  const ids = items.map((i) => i.id);
  const [action, setAction] = useState<FimResolveAction | null>(null);
  const [note, setNote] = useState('');
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [awaiting, setAwaiting] = useState<{ message: string; ids: number[] } | null>(null);
  const [changed, setChanged] = useState<{ message: string; items: DriftChangedItem[] } | null>(null);
  const [partial, setPartial] = useState<BulkSummary | null>(null);
  const { showToast } = useToast();
  const confirm = useConfirm();
  const counts = riskCounts(items);
  const unconfirmed = items.filter(isUnconfirmed);
  const bulk = items.length > 1;
  const needAck = bulk && anyRisk(counts);
  const expected = expectedOf(items);
  const approveBlocked = counts.unconfirmed > 0 || expected === null;
  const noteTrim = note.trim();
  const noteErr = noteTrim.length > NOTE_MAX ? `At most ${NOTE_MAX} characters` : null;
  const finished = !!changed || !!partial;
  const canSubmit = !busy && !finished && action !== null && !!noteTrim && !noteErr && (!needAck || ack) && !(action === 'approve' && approveBlocked);
  const help = action ? ACTIONS.find((a) => a.action === action)!.help : 'Choose what to do with the selected drift. There is no default.';
  const before: DriftBefore = Object.fromEntries(items.map((d) => [String(d.id), { newSha256: d.newSha256, changeType: d.changeType, lastSeenAt: d.lastSeenAt, label: d.path }]));

  /** Handles the approval guards; returns true when the error was one of them (shown, not retried). */
  const guarded = (e: unknown): boolean => {
    const aw = awaitingConfirmation(e);
    if (aw) { setAwaiting(aw); return true; }
    const ch = driftChanged(e);
    if (ch) { setChanged(ch); onStale(ch.items.map((c) => c.id)); return true; }
    return false;
  };

  const submit = async () => {
    if (!action) return;
    // Defence in depth: never submit an approve the UI does not offer (unconfirmed real-time registry drift, no digest).
    if (action === 'approve' && (approveBlocked || !expected)) return;
    setBusy(true); setErr(null); setAwaiting(null);
    const opts = action === 'approve' && expected ? { expected } : {};
    try {
      let r;
      try {
        r = await resolveFimDrift(ids, action, noteTrim, opts);
      } catch (e) {
        if (guarded(e)) return;
        // Other 409 = some selected changes were never hashed; only retry after explicit confirmation.
        if (action !== 'approve' || errStatus(e) !== 409) throw e;
        const ok = await confirm({
          title: 'Approve unverified changes?',
          variant: 'danger',
          confirmLabel: 'Approve anyway',
          description: `${safeText(errMsg(e, 'Some changes have no content hash.'))} The content of these files has not been hashed, so approving them means the next scan will trust whatever is on disk.`,
        });
        if (!ok) return;
        try {
          r = await resolveFimDrift(ids, action, noteTrim, { ...opts, acceptUnverified: true });
        } catch (e2) {
          if (guarded(e2)) return;
          throw e2;
        }
      }
      const sum = summarizeBulk(ids, r, 'resolved');
      const review = needsReview(sum);
      if (review.length > 0) {
        // Partial approve: keep the modal open with the refused items listed; they stay selected.
        setPartial(sum);
        showToast(`${sum.done.length} of ${ids.length} drift item(s) ${action === 'approve' ? 'approved' : 'resolved'}; ${sum.refused.length} NOT: review them again`, 'error');
        onStale(review.map((x) => x.id));
        return;
      }
      const doneCount = sum.unknown ? Number(r?.resolved ?? 0) : sum.done.length;
      if (doneCount < ids.length) {
        showToast(`${doneCount} of ${ids.length} drift item(s): ${action}; ${ids.length - doneCount} skipped (already resolved, not visible or not permitted)`, 'info');
      } else {
        showToast(`${ids.length} drift item(s): ${action}`, 'success');
      }
      onDone();
    } catch (e) { setErr(errMsg(e, 'Failed to resolve')); } finally { setBusy(false); }
  };

  const label = finished ? 'Review again' : action ? ACTIONS.find((a) => a.action === action)!.label : 'Choose an action';
  return (
    <FimModal title={`Resolve ${ids.length} drift item${ids.length === 1 ? '' : 's'}`} onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>{finished ? 'Close and review' : 'Cancel'}</button><button className={btnPrimary} disabled={!canSubmit} onClick={submit}>{busy ? 'Saving...' : label}</button></>}>
      <div className="space-y-4">
        {err && <ErrorBanner message={err} />}
        {changed && <DriftChangedNotice info={changed} before={before} />}
        {partial && <BulkRefusedNotice summary={partial} total={ids.length} verb={action === 'approve' ? 'approved' : 'resolved'} unit="drift item" before={before}
          labelOf={(id) => items.find((x) => x.id === id)?.path} />}
        {awaiting && (
          <div role="alert" className="space-y-2 rounded-lg bg-blue-50 px-3 py-2 text-sm text-blue-900 dark:bg-blue-500/10 dark:text-blue-200">
            <p><b>{safeText(awaiting.message)}</b></p>
            <p className="text-xs">Nothing was approved. The check scan was requested automatically and normally answers within up to about a minute. Re-check, then try again, or choose Reject / Ignore.</p>
            {awaiting.ids.length > 0 && (
              <ul className="space-y-1 text-xs">
                {awaiting.ids.map((did) => {
                  const it = items.find((x) => x.id === did);
                  return <li key={did} className="flex flex-wrap items-center gap-2">drift #{did}{it ? <RegText value={it.path} mono className="text-slate-600 dark:text-slate-300" /> : null}<RecheckButton driftId={did} compact /></li>;
                })}
              </ul>
            )}
          </div>
        )}
        {anyRisk(counts) && (
          <div className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
            <p className="font-semibold">This selection contains:</p>
            <ul className="mt-1 list-disc pl-5 text-xs">
              {counts.critical > 0 && <li>{counts.critical} critical item(s)</li>}
              {counts.protectedCov > 0 && <li>{counts.protectedCov} protected registry coverage item(s) (managed Registry coverage policies)</li>}
              {counts.reverted > 0 && <li>{counts.reverted} reverted item(s): a check scan found the value back at the baseline after a real-time change (possible tamper-then-revert)</li>}
              {counts.unconfirmed > 0 && <li>{counts.unconfirmed} unconfirmed real-time registry item(s): waiting for a confirmation scan; they cannot be approved yet</li>}
            </ul>
            {needAck && (
              <label className="mt-2 flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-1" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                <span>I have reviewed these items and want to resolve all {items.length} of them together.</span>
              </label>
            )}
          </div>
        )}
        {unconfirmed.length > 0 && (
          <div className="space-y-1 rounded-lg bg-blue-50 px-3 py-2 text-xs text-blue-900 dark:bg-blue-500/10 dark:text-blue-200">
            <p><b>{AWAITING_TEXT}.</b> Approve is disabled while the selection contains these items{bulk ? ' (deselect them to approve the rest)' : ''}; Reject and Ignore stay allowed.</p>
            <ul className="space-y-1">
              {unconfirmed.slice(0, 20).map((d) => <li key={d.id} className="flex flex-wrap items-center gap-2">#{d.id} <RegText value={d.path} mono /> <RecheckButton driftId={d.id} compact /></li>)}
              {unconfirmed.length > 20 && <li>... and {unconfirmed.length - 20} more</li>}
            </ul>
          </div>
        )}
        {expected === null && counts.unconfirmed === 0 && (
          <p className="rounded-lg bg-slate-100 px-3 py-2 text-xs text-slate-700 dark:bg-white/10 dark:text-slate-200">Approve is unavailable: the list does not carry the reviewed content digest for every selected item. Reload the list first; Reject and Ignore stay allowed.</p>
        )}
        <fieldset disabled={finished}>
          <legend className="mb-1 text-xs font-semibold text-slate-600 dark:text-slate-300">Action (required)</legend>
          <div className="flex flex-wrap gap-2">
            {ACTIONS.map((a) => {
              const disabled = a.action === 'approve' && approveBlocked;
              return (
                <label key={a.action} title={disabled ? (counts.unconfirmed > 0 ? AWAITING_TEXT : 'Reload the list first') : undefined} className={`rounded-lg border px-3 py-1.5 text-sm font-semibold ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${action === a.action ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300' : 'border-slate-200 dark:border-white/10'}`}>
                  <input type="radio" className="sr-only" name="fim-resolve" disabled={disabled} checked={action === a.action} onChange={() => setAction(a.action)} />{a.label}
                </label>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-slate-500">{help}</p>
        </fieldset>
        <Field label="Note (required)" htmlFor="fim-resolve-note" hint={`Recorded with the decision, e.g. change ticket number (at most ${NOTE_MAX} characters).`} error={noteErr}>
          <textarea id="fim-resolve-note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} className={inputCls} />
        </Field>
      </div>
    </FimModal>
  );
}

export default function DriftTab({ preset }: { preset?: DriftPreset }) {
  const [items, setItems] = useState<FimDrift[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [total, setTotal] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState(preset?.status ?? 'open');
  const [severity, setSeverity] = useState(preset?.severity ?? '');
  const [host, setHost] = useState(preset?.host ?? '');
  const [policy, setPolicy] = useState('');
  const [qInput, setQInput] = useState('');
  const q = useDebounced(qInput.trim());
  const hostD = useDebounced(host.trim());
  const [policies, setPolicies] = useState<FimPolicy[]>([]);
  const [policiesErr, setPoliciesErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [detailId, setDetailId] = useState<number | null>(null);
  const [resolveItems, setResolveItems] = useState<FimDrift[] | null>(null);
  /** Ids to keep selected across the next reload (items that still need re-review). */
  const keepRef = useRef<number[] | null>(null);

  useEffect(() => { listFimPolicies().then((r) => { setPolicies(r.items ?? []); setPoliciesErr(null); }).catch((e) => { setPolicies([]); setPoliciesErr(errMsg(e, 'Could not load policies')); }); }, []);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await listFimDrift({ status, severity, host: hostD, policy, q, page });
      const next = r.items ?? [];
      const keep = keepRef.current; keepRef.current = null;
      setItems(next); setTotal(r.total ?? 0); if (r.pageSize) setPageSize(r.pageSize);
      setSelected(keep ? new Set(next.filter((i) => i.status === 'open' && keep.includes(i.id)).map((i) => i.id)) : new Set()); setLoaded(true);
    } catch (e) { setError(errMsg(e, 'Failed to load drift')); } finally { setLoading(false); }
  }, [status, severity, hostD, policy, q, page]);
  const reloadKeeping = (ids?: number[]) => { keepRef.current = ids && ids.length ? ids : null; load(); };
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [status, severity, hostD, policy, q]);

  const openRows = items.filter((i) => i.status === 'open');
  const allSelected = openRows.length > 0 && openRows.every((i) => selected.has(i.id));
  const toggle = (id: number) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const stale = !!error && loaded;

  return (
    <div className="flex h-full flex-col gap-3 min-h-0">
      <div className="flex flex-wrap items-end gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input aria-label="Search path" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="Search path" className={`${inputCls} pl-8 w-52`} />
        </div>
        <Dropdown aria-label="Status" value={status} onChange={setStatus} placeholder="Any status" options={['open', 'approved', 'rejected', 'ignored'].map((v) => ({ value: v, label: v }))} />
        <Dropdown aria-label="Severity" value={severity} onChange={setSeverity} placeholder="Any severity" options={SEVERITIES.map((v) => ({ value: v, label: v }))} />
        <Dropdown aria-label="Policy" value={policy} onChange={setPolicy} placeholder={policiesErr ? 'Policies unavailable' : 'Any policy'} options={policies.map((p) => ({ value: String(p.id), label: safeText(p.name) }))} />
        <input aria-label="Host identifier" value={host} onChange={(e) => setHost(e.target.value)} placeholder="Host identifier" className={`${inputCls} w-44`} />
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-slate-500" aria-live="polite">{selected.size} selected</span>
          <button className={btnPrimary} disabled={selected.size === 0 || stale} title={stale ? 'Reload first: the list may be out of date' : undefined} onClick={() => setResolveItems(items.filter((i) => selected.has(i.id)))}>Resolve selected...</button>
        </div>
      </div>
      {policiesErr && <p className="text-xs text-red-600 dark:text-red-400">Policy filter unavailable: {safeText(policiesErr)}</p>}
      {error && <ErrorBanner message={error} onRetry={load} stale={stale} />}
      <div className={`${cardCls} flex-1 min-h-0 overflow-auto ${stale ? 'opacity-60' : ''}`}>
        {loading && !loaded ? <LoadingRows /> : !loaded ? (
          <EmptyBox title="Drift could not be loaded" description="Use Retry above." />
        ) : items.length === 0 ? (
          <EmptyBox title="No drift found" description="Nothing matches these filters. Drift appears when a baselined host differs from its baseline." />
        ) : (
          <table className="w-full min-w-[820px]">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800">
              <tr>
                <th className="w-8 px-3"><input type="checkbox" aria-label="Select all open on this page" checked={allSelected} onChange={() => setSelected(allSelected ? new Set() : new Set(openRows.map((i) => i.id)))} /></th>
                <th className={thCls}>Severity</th><th className={thCls}>Change</th><th className={thCls}>Path</th><th className={thCls}>Host</th><th className={thCls}>Policy</th><th className={thCls}>Detected</th><th className={thCls}>Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {items.map((d) => (
                <tr key={d.id} className="hover:bg-slate-50 dark:hover:bg-white/5">
                  <td className="px-3"><input type="checkbox" aria-label={`Select ${safeText(d.path)}`} disabled={d.status !== 'open'} checked={selected.has(d.id)} onChange={() => toggle(d.id)} /></td>
                  <td className={tdCls}><SeverityBadge severity={d.severity} /></td>
                  <td className={tdCls}><KindBadge kind={d.kind} /> <ChangeBadge type={d.changeType} /><DriftFlags d={d} />{d.occurrences > 1 && <span className="ml-1 text-xs text-slate-400">x{d.occurrences}</span>}</td>
                  <td className={`${tdCls} max-w-[320px]`}><button className="block max-w-full truncate text-left font-mono text-xs text-indigo-700 dark:text-indigo-300 hover:underline" title={safeText(d.path)} onClick={() => setDetailId(d.id)}><RegText value={d.path} nowrap /></button></td>
                  <td className={tdCls}><RegText value={d.hostname || d.hostIdentifier} /></td>
                  <td className={tdCls}><RegText value={d.policyName} />{d.policyDeleted && <span className="ml-1 rounded-full bg-slate-200 dark:bg-white/10 px-1.5 py-0.5 text-[10px] font-semibold">policy deleted</span>}</td>
                  <td className={`${tdCls} whitespace-nowrap`}>{fmtTime(d.detectedAt)}</td>
                  <td className={tdCls}><StatusPill status={d.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pagination page={page} totalPages={Math.ceil(total / pageSize)} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="drift items" />
      {detailId != null && <DriftDetail id={detailId} onClose={() => setDetailId(null)} onResolve={(d) => { setDetailId(null); setResolveItems([d]); }} />}
      {resolveItems && <ResolveModal items={resolveItems} onClose={() => setResolveItems(null)} onDone={() => { setResolveItems(null); load(); }} onStale={reloadKeeping} />}
    </div>
  );
}
