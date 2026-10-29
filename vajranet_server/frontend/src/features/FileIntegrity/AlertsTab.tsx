import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Search } from 'lucide-react';
import {
  closeFimAlerts, getFimDrift, listFimAlerts, listFimPolicies, reopenFimAlerts,
  type FimAlert, type FimAlertVerdict, type FimDrift, type FimPolicy, type FimSeverity,
} from '../../api/services/fimApi';
import { Pagination } from '@/components/ui/pagination';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';
import { SEVERITIES, errMsg, errStatus, fmtTime, normalizeAttrs, shortHash } from './constants';
import { AttrsTable } from './DriftTab';
import { useFimNodes } from './useFimNodes';
import { OWN_OVERSIGHT_TEXT, currentUser, isOwnOversightAlert, type CurrentUser } from './alertGuards';
import { ChangeBadge, KindBadge, Dropdown, Drawer, EmptyBox, ErrorBanner, Field, FimModal, LoadingRows, SegmentedControl, SeverityBadge, StatusPill } from './ui';
import { btnGhost, btnPrimary, cardCls, inputCls, tdCls, thCls } from './styles';
import { useDebounced } from './useDebounced';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';
import { AwaitingConfirmation, BulkRefusedNotice, DriftChangedNotice, RecheckButton, type DriftBefore } from './RecheckButton';
import {
  awaitingConfirmation, driftChanged, expectedOfAlerts, isUnconfirmed, needsReview, summarizeBulk, type BulkSummary, type DriftChangedItem,
} from './driftSafety';

export interface AlertsPreset { severity?: string; status?: 'open' | 'closed' | 'all' }

const sev = (s: string) => (SEVERITIES as readonly string[]).includes(s) ? (s as FimSeverity) : 'medium';
const NOTE_MAX = 2000;
const SA_ONLY = 'Configuration alerts are closed by a Super Administrator.';
/** Server says the caller may close it, and it is not the caller's own oversight alert (refused by the server). */
const canCloseAlert = (a: FimAlert, me: CurrentUser | null) => a.canClose !== false && !isOwnOversightAlert(a, me);
const notAllowedText = (a: FimAlert, me: CurrentUser | null) => (isOwnOversightAlert(a, me) ? OWN_OVERSIGHT_TEXT : SA_ONLY);
const isConfig = (a: FimAlert) => a.alertType === 'fim_config';

function VerdictChip({ a }: { a: FimAlert }) {
  if (a.isOpen) return <span className="rounded-full bg-red-100 text-red-700 px-2 py-0.5 text-xs font-semibold">Open</span>;
  if (a.markType === 'true_positive') return <span className="rounded-full bg-purple-100 text-purple-700 px-2 py-0.5 text-xs font-semibold">True positive</span>;
  if (a.markType === 'false_positive') return <span className="rounded-full bg-emerald-100 text-emerald-700 px-2 py-0.5 text-xs font-semibold">False positive</span>;
  return <span className="rounded-full bg-slate-100 text-slate-600 px-2 py-0.5 text-xs font-semibold">Closed</span>;
}

/**
 * Close alerts (optionally approving the linked drift). A refused approval of one alert is a 409
 * (shown, modal stays open); with several alerts the server closes what it can and the alerts
 * whose drift was NOT approved stay open, are listed here and stay selected (`onStale(alertIds)`).
 */
export function CloseModal({ alerts, verdict, onClose, onDone, onStale }: { alerts: FimAlert[]; verdict: FimAlertVerdict; onClose: () => void; onDone: () => void; onStale: (keepSelected?: number[]) => void }) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const ids = alerts.map((a) => a.alertId);
  const [note, setNote] = useState('');
  const [approve, setApprove] = useState(false);
  const [configAck, setConfigAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [awaiting, setAwaiting] = useState<{ message: string; ids: number[] } | null>(null);
  const [changed, setChanged] = useState<{ message: string; items: DriftChangedItem[] } | null>(null);
  const [partial, setPartial] = useState<BulkSummary | null>(null);
  const finished = !!changed || !!partial;
  const tp = verdict === 'true_positive';
  const configOne = alerts.length === 1 && isConfig(alerts[0]);
  const driftAlerts = alerts.filter((a) => a.driftId != null);
  const expected = expectedOfAlerts(driftAlerts);
  // Real-time registry changes are approvable only after a check scan confirmed them (server 409 otherwise).
  const unconfirmedAlerts = driftAlerts.filter((a) => a.source === 'realtime' && typeof a.path === 'string' && a.path.startsWith('registry|') && !a.driftConfirmedAt);
  const approveImpossible = driftAlerts.length === 0 || expected === null || unconfirmedAlerts.length > 0;
  const noteTrim = note.trim();
  const noteErr = noteTrim.length > NOTE_MAX ? `At most ${NOTE_MAX} characters` : null;
  const ok = !busy && !finished && !!noteTrim && !noteErr && (!configOne || tp || configAck) && !(approve && approveImpossible);
  const before: DriftBefore = Object.fromEntries(driftAlerts.map((a) => [String(a.driftId), { newSha256: a.newSha256, changeType: a.changeType ?? '?', lastSeenAt: a.driftLastSeenAt ?? null, label: a.path ?? undefined }]));

  const guarded = (e: unknown): boolean => {
    const aw = awaitingConfirmation(e);
    if (aw) { setAwaiting(aw); return true; }
    const ch = driftChanged(e);
    if (ch) {
      setChanged(ch);
      const changedDrift = new Set(ch.items.map((c) => c.id));
      onStale(alerts.filter((a) => a.driftId != null && changedDrift.has(a.driftId)).map((a) => a.alertId));
      return true;
    }
    return false;
  };

  const submit = async () => {
    // Defence in depth: never submit an approve the UI does not offer (e.g. unconfirmed real-time registry change).
    if (approve && approveImpossible) return;
    setBusy(true); setErr(null); setAwaiting(null);
    const opts = approve && expected ? { approveChange: true, expected } : {};
    try {
      let r;
      try {
        r = await closeFimAlerts(ids, verdict, noteTrim, opts);
      } catch (e) {
        if (guarded(e)) return;
        // Other 409 = approving content that was never hashed; retry only after an explicit confirmation.
        if (!approve || errStatus(e) !== 409) throw e;
        const yes = await confirm({
          title: 'Approve unverified changes?',
          variant: 'danger',
          confirmLabel: 'Approve anyway',
          description: `${safeText(errMsg(e, 'Some changes have no content hash.'))} The content of these files has not been hashed, so approving them means the next scan will trust whatever is on disk.`,
        });
        if (!yes) return;
        try {
          r = await closeFimAlerts(ids, verdict, noteTrim, { ...opts, acceptUnverified: true });
        } catch (e2) {
          if (guarded(e2)) return;
          throw e2;
        }
      }
      const sum = summarizeBulk(ids, r, 'closed');
      const review = needsReview(sum);
      if (review.length > 0) {
        // Partial: alerts whose drift was not approved stay open; list them and keep them selected.
        setPartial(sum);
        showToast(`${sum.done.length} of ${ids.length} alert(s) closed; ${sum.refused.length} NOT closed: review them again`, 'error');
        onStale(review.map((x) => x.id));
        return;
      }
      const closed = sum.unknown ? Number(r?.closed ?? 0) : sum.done.length;
      const skipped = ids.length - closed;
      showToast(`${closed} alert(s) closed${skipped > 0 ? `, ${skipped} skipped (not allowed or already closed)` : ''}`, skipped > 0 ? 'info' : 'success');
      onDone();
    } catch (e) { setErr(errMsg(e, 'Failed to close alerts')); } finally { setBusy(false); }
  };

  return (
    <FimModal title={`Close ${ids.length} alert${ids.length === 1 ? '' : 's'} as ${tp ? 'true positive' : 'false positive'}`} onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>{finished ? 'Close and review' : 'Cancel'}</button><button className={btnPrimary} disabled={!ok} onClick={submit}>{busy ? 'Saving...' : finished ? 'Review again' : 'Close alerts'}</button></>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        {changed && <DriftChangedNotice info={changed} before={before} />}
        {partial && <BulkRefusedNotice summary={partial} total={ids.length} verb="closed" unit="alert" before={before}
          labelOf={(id) => { const a = alerts.find((x) => x.alertId === id); return a ? (a.path ?? a.eventCode) : null; }} />}
        {awaiting && (
          <div role="alert" className="space-y-2 rounded-lg bg-blue-50 px-3 py-2 text-sm text-blue-900 dark:bg-blue-500/10 dark:text-blue-200">
            <p><b>{safeText(awaiting.message)}</b></p>
            <p className="text-xs">Nothing was closed or approved. The check scan was requested automatically and normally answers within up to about a minute. Re-check and try again, or close without approving the change.</p>
            {awaiting.ids.length > 0 && <ul className="space-y-1 text-xs">{awaiting.ids.map((did) => <li key={did} className="flex flex-wrap items-center gap-2">drift #{did} <RecheckButton driftId={did} compact /></li>)}</ul>}
          </div>
        )}
        {configOne && (
          <div className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
            <p>Configuration alert: <RegText value={alerts[0].eventCode} /> on <RegText value={alerts[0].hostname || alerts[0].hostIdentifier} />.</p>
            {!tp && (
              <label className="mt-2 flex items-start gap-2"><input type="checkbox" className="mt-1" checked={configAck} onChange={(e) => setConfigAck(e.target.checked)} />
                <span>I reviewed this configuration event (waiver, coverage reduction, invalid configuration, bulk publish or history-chain check) and confirm it is benign.</span></label>
            )}
          </div>
        )}
        <p className="text-sm text-slate-600 dark:text-slate-300">
          {tp ? 'The change is real and unwanted. The linked drift is rejected and the baseline is kept unchanged.'
            : 'The alert was benign. The linked drift is ignored and the baseline is not changed, unless you also approve the change below.'}
        </p>
        <Field label="Note (required)" htmlFor="fim-alert-note" hint={`Recorded with the decision, e.g. change ticket number (at most ${NOTE_MAX} characters).`} error={noteErr}>
          <textarea id="fim-alert-note" rows={3} className={inputCls} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        {!tp && driftAlerts.length > 0 && (
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={approve} disabled={approveImpossible || finished} onChange={(e) => setApprove(e.target.checked)} />
            <span>Also approve this change into the baseline <span className="block text-xs text-slate-500">The baseline is updated to exactly the content shown in the list (refused if that content changed since; a rescan that only repeats the same change does not count). Real-time registry changes can only be approved after a confirmation scan.{expected === null ? ' Unavailable: the list does not carry the drift details needed; reload it.' : ''}{unconfirmedAlerts.length ? ` Unavailable for ${unconfirmedAlerts.length} selected real-time registry change(s): waiting for confirmation scan (up to about a minute).` : ''}</span></span>
          </label>
        )}
      </div>
    </FimModal>
  );
}

function AlertDetail({ a, me, onClose, onCloseOne }: { a: FimAlert; me: CurrentUser | null; onClose: () => void; onCloseOne: (a: FimAlert, v: FimAlertVerdict) => void }) {
  const [drift, setDrift] = useState<FimDrift | null>(null);
  const [driftErr, setDriftErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (a.driftId == null) return;
    let cancel = false;
    setDriftErr(null);
    getFimDrift(a.driftId).then((d) => { if (!cancel) setDrift(d); }).catch((e) => { if (!cancel) setDriftErr(errMsg(e, 'Failed to load the linked drift')); });
    return () => { cancel = true; };
  }, [a.driftId, tick]);
  const isFile = (a.kind ?? 'file') === 'file';
  return (
    <Drawer title="Alert detail" onClose={onClose}>
      <div className="space-y-5">
        <div>
          <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={sev(a.severity)} />{a.kind && <KindBadge kind={a.kind} />}{a.changeType && <ChangeBadge type={a.changeType} />}<VerdictChip a={a} /></div>
          <p className="mt-2 text-sm font-semibold"><RegText value={a.eventCode} /></p>
          {a.path && <p className="text-sm"><RegText value={a.path} mono /></p>}
          <p className="text-xs text-slate-500"><RegText value={a.hostname || a.hostIdentifier} />{a.policyName ? <> - policy <RegText value={a.policyName} /></> : null} - {fmtTime(a.detectedAt)}{a.source ? <> - detected via <RegText value={a.source} /></> : null}</p>
        </div>
        {driftErr && <ErrorBanner message={driftErr} onRetry={() => setTick((t) => t + 1)} />}
        {drift && drift.status === 'open' && isUnconfirmed(drift) && <AwaitingConfirmation driftId={drift.id} />}
        {a.driftId != null ? (
          <>
            {isFile ? (
              <section>
                <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">What changed (SHA-256)</h4>
                <div className="text-xs"><span className="text-slate-400">Old: </span><RegText value={a.oldSha256 || '-'} mono /></div>
                <div className="text-xs"><span className="text-slate-400">New: </span><RegText value={a.newSha256 || '-'} mono /></div>
              </section>
            ) : (
              <section>
                <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">{a.kind === 'item' ? 'Changed fields (old to new)' : 'Permissions & owner (old to new)'}</h4>
                {drift ? <AttrsTable oldA={normalizeAttrs(drift.oldAttrs)} newA={normalizeAttrs(drift.newAttrs)} /> : driftErr ? <p className="text-xs text-red-600">Not available (see the error above).</p> : <p className="text-xs text-slate-400">Loading...</p>}
              </section>
            )}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Who changed it</h4>
              <p className="text-sm">Process: <RegText value={a.actorProcess || 'unknown (scan-detected)'} mono /></p>
              <p className="text-sm">User: <RegText value={a.actorUser || 'unknown'} mono /></p>
              <p className="text-sm">Occurrences: {a.occurrences ?? 1}</p>
            </section>
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Linked drift</h4>
              <p className="text-sm">#{a.driftId} <StatusPill status={a.driftStatus || 'open'} /></p>
            </section>
          </>
        ) : <p className="text-sm text-slate-500">{a.alertType === 'fim_health' ? 'Health alert: a scheduled scan did not report in time.'
          : isConfig(a) ? 'Configuration alert: a registry-coverage configuration event (waiver requested, approved or expired, protected coverage reduced, node configuration invalid, bulk publish, or history chain check failure). See the Registry tab.'
            : 'No linked drift record.'}</p>}
        {!a.isOpen && a.remarks && <section><h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">Closing note</h4><p className="text-sm"><RegText value={a.remarks} /></p></section>}
        {a.isOpen && isConfig(a) && (
          canCloseAlert(a, me) ? (
            <section className="space-y-2">
              <p className="text-xs text-slate-500">Configuration alerts are closed one at a time, each with its own confirmation.</p>
              <div className="flex flex-wrap gap-2">
                <button className={btnPrimary} onClick={() => onCloseOne(a, 'true_positive')}>Close as true positive...</button>
                <button className={btnGhost} onClick={() => onCloseOne(a, 'false_positive')}>Close as false positive...</button>
              </div>
            </section>
          ) : <p data-testid="fim-alert-close-blocked" className="text-xs text-slate-500">{notAllowedText(a, me)}</p>
        )}
      </div>
    </Drawer>
  );
}

export default function AlertsTab({ preset, onChanged }: { preset?: AlertsPreset; onChanged: () => void }) {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const { nodes, error: nodesErr } = useFimNodes();
  const me = useMemo(() => currentUser(), []);
  const [policies, setPolicies] = useState<FimPolicy[]>([]);
  const [policiesErr, setPoliciesErr] = useState<string | null>(null);
  const [status, setStatus] = useState<'open' | 'closed' | 'all'>(preset?.status ?? 'open');
  const [verdict, setVerdict] = useState('');
  const [severity, setSeverity] = useState(preset?.severity ?? '');
  const [type, setType] = useState('');
  const [policy, setPolicy] = useState('');
  const [host, setHost] = useState('');
  const [qInput, setQInput] = useState('');
  const q = useDebounced(qInput.trim());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [items, setItems] = useState<FimAlert[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState({ open: 0, closed: 0, truePositive: 0, falsePositive: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [detail, setDetail] = useState<FimAlert | null>(null);
  const [closing, setClosing] = useState<{ alerts: FimAlert[]; verdict: FimAlertVerdict } | null>(null);
  const [busy, setBusy] = useState(false);
  /** Alert ids to keep selected across the next reload (still open, need re-review). */
  const keepRef = useRef<number[] | null>(null);

  useEffect(() => { listFimPolicies().then((r) => { setPolicies(r.items ?? []); setPoliciesErr(null); }).catch((e) => { setPolicies([]); setPoliciesErr(errMsg(e, 'Could not load policies')); }); }, []);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await listFimAlerts({ status, verdict, severity, type, policy, host, q, page });
      const next = r.items ?? [];
      const keep = keepRef.current; keepRef.current = null;
      setItems(next); setTotal(r.total ?? 0); if (r.counts) setCounts(r.counts); if (r.pageSize) setPageSize(r.pageSize);
      setSelected(keep ? new Set(next.filter((a) => keep.includes(a.alertId)).map((a) => a.alertId)) : new Set()); setLoaded(true);
    } catch (e) { setError(errMsg(e, 'Failed to load alerts')); } finally { setLoading(false); }
  }, [status, verdict, severity, type, policy, host, q, page]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [status, verdict, severity, type, policy, host, q]);

  const toggle = (id: number) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const sel = items.filter((a) => selected.has(a.alertId));
  const closable = sel.filter((a) => a.isOpen && canCloseAlert(a, me));
  const tpSel = closable;
  // Configuration alerts are never bulk-closed as false positive: one at a time from the detail view.
  const fpSel = closable.filter((a) => !isConfig(a));
  const fpExcluded = closable.length - fpSel.length;
  const notAllowedSel = sel.filter((a) => !canCloseAlert(a, me));
  const notAllowed = notAllowedSel.length;
  const ownSel = notAllowedSel.filter((a) => isOwnOversightAlert(a, me)).length;
  const closedSel = sel.filter((a) => !a.isOpen && canCloseAlert(a, me)).map((a) => a.alertId);
  const done = () => { setClosing(null); setDetail(null); load(); onChanged(); };
  const reloadKeeping = (ids?: number[]) => { keepRef.current = ids && ids.length ? ids : null; load(); onChanged(); };
  const stale = !!error && loaded;

  const reopen = async () => {
    const ok = await confirm({ title: `Reopen ${closedSel.length} alert(s)?`, description: 'They return to the open queue.', confirmLabel: 'Reopen' });
    if (!ok) return;
    setBusy(true);
    try { const r = await reopenFimAlerts(closedSel); showToast(`${r.reopened} alert(s) reopened${r.skipped ? `, ${r.skipped} skipped` : ''}`, 'success'); done(); }
    catch (e) { showToast(safeText(errMsg(e, 'Failed to reopen')), 'error'); } finally { setBusy(false); }
  };

  return (
    <div className="flex h-full flex-col gap-3 min-h-0">
      <div className="flex flex-wrap items-end gap-2">
        <SegmentedControl value={status} onChange={setStatus} size="sm" options={[
          { value: 'open', label: `Open (${counts.open})` }, { value: 'closed', label: `Closed (${counts.closed})` }, { value: 'all', label: 'All' }]} />
        <Dropdown aria-label="Verdict" value={verdict} onChange={setVerdict} placeholder="Any verdict" options={[
          { value: 'true_positive', label: `True positive (${counts.truePositive})` }, { value: 'false_positive', label: `False positive (${counts.falsePositive})` }, { value: 'unmarked', label: 'Unmarked' }]} />
        <Dropdown aria-label="Severity" value={severity} onChange={setSeverity} placeholder="Any severity" options={SEVERITIES.map((s) => ({ value: s, label: s }))} />
        <Dropdown aria-label="Type" value={type} onChange={setType} placeholder="Any type" options={[{ value: 'drift', label: 'Drift' }, { value: 'health', label: 'Scan health' }, { value: 'config', label: 'Configuration' }]} />
        <Dropdown aria-label="Policy" value={policy} onChange={setPolicy} placeholder={policiesErr ? 'Policies unavailable' : 'All policies'} options={policies.map((p) => ({ value: String(p.id), label: safeText(p.name) }))} />
        <Dropdown aria-label="Host" value={host} onChange={setHost} placeholder={nodesErr ? 'Hosts unavailable' : 'All hosts'} options={nodes.map((n) => ({ value: n.host_identifier, label: safeText(n.hostname || n.host_identifier) }))} />
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input aria-label="Search alerts" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="Search path, host, message" className={`${inputCls} pl-8 w-56`} />
        </div>
        <button className={btnGhost} onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
      </div>
      {(policiesErr || nodesErr) && <p className="text-xs text-red-600 dark:text-red-400">Some filters are unavailable: {safeText([policiesErr, nodesErr].filter(Boolean).join('; '))}</p>}
      <div className="flex flex-wrap items-center gap-2">
        <button className={btnPrimary} disabled={busy || stale || tpSel.length === 0} onClick={() => setClosing({ alerts: tpSel, verdict: 'true_positive' })}>Close as true positive{tpSel.length ? ` (${tpSel.length})` : ''}</button>
        <button className={btnGhost} disabled={busy || stale || fpSel.length === 0} onClick={() => setClosing({ alerts: fpSel, verdict: 'false_positive' })}>Close as false positive{fpSel.length ? ` (${fpSel.length})` : ''}</button>
        <button className={btnGhost} disabled={busy || stale || closedSel.length === 0} onClick={reopen}>Reopen</button>
        {selected.size > 0 && <span className="text-xs text-slate-500">{selected.size} selected</span>}
        {fpExcluded > 0 && <span className="text-xs text-amber-700 dark:text-amber-300">{fpExcluded} configuration alert(s) are not included in a bulk false-positive close: open each one and close it individually.</span>}
        {notAllowed > 0 && <span className="text-xs text-slate-500">{notAllowed} selected alert(s) cannot be closed or reopened by you. {ownSel > 0 ? `${ownSel} were raised by your own action: another Super Administrator must close them. ` : ''}{notAllowed > ownSel ? SA_ONLY : ''}</span>}
      </div>
      {error && <ErrorBanner message={error} onRetry={load} stale={stale} />}
      <div className={`${cardCls} flex-1 min-h-0 overflow-auto ${stale ? 'opacity-60' : ''}`}>
        {loading && !loaded ? <LoadingRows /> : !loaded ? (
          <EmptyBox title="Alerts could not be loaded" description="Use Retry above." />
        ) : items.length === 0 ? (
          <EmptyBox title="No FIM alerts" description="Alerts appear when a baselined host differs from its baseline in an alerting policy, or a scheduled scan is overdue." />
        ) : (
          <table className="w-full min-w-[980px]">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800"><tr>
              <th className="w-8 px-3"><span className="sr-only">Select</span></th><th className={thCls}>Severity</th><th className={thCls}>Time</th><th className={thCls}>Host</th>
              <th className={thCls}>Policy</th><th className={thCls}>Change</th><th className={thCls}>Path</th><th className={thCls}>Source</th><th className={thCls}>State</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {items.map((a) => (
                <tr key={a.alertId} className="hover:bg-slate-50 dark:hover:bg-white/5">
                  <td className="px-3"><input type="checkbox" aria-label={`Select alert ${a.alertId}`} checked={selected.has(a.alertId)} onChange={() => toggle(a.alertId)} /></td>
                  <td className={tdCls}><SeverityBadge severity={sev(a.severity)} /></td>
                  <td className={`${tdCls} whitespace-nowrap`}>{fmtTime(a.detectedAt)}</td>
                  <td className={tdCls}><RegText value={a.hostname || a.hostIdentifier} /></td>
                  <td className={tdCls}><RegText value={a.policyName ?? '-'} /></td>
                  <td className={tdCls}>{a.kind && a.kind !== 'file' && <><KindBadge kind={a.kind} />{' '}</>}{a.changeType ? <ChangeBadge type={a.changeType} /> : <span className="text-xs text-slate-500">{a.alertType === 'fim_health' ? 'scan health' : isConfig(a) ? 'Configuration' : '-'}</span>}</td>
                  <td className={`${tdCls} max-w-[320px]`}><button className="block max-w-full truncate text-left font-mono text-xs text-indigo-700 dark:text-indigo-300 hover:underline" title={safeText(a.path ?? a.eventCode)} onClick={() => setDetail(a)}><RegText value={a.path ?? a.eventCode} nowrap /></button>
                    {a.newSha256 && <span className="font-mono text-[10px] text-slate-400">{safeText(shortHash(a.newSha256))}</span>}</td>
                  <td className={tdCls}><RegText value={a.source ?? '-'} /></td>
                  <td className={tdCls}><VerdictChip a={a} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pagination page={page} totalPages={Math.ceil(total / pageSize)} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="alerts" />
      {detail && <AlertDetail a={detail} me={me} onClose={() => setDetail(null)} onCloseOne={(a, v) => setClosing({ alerts: [a], verdict: v })} />}
      {closing && <CloseModal alerts={closing.alerts} verdict={closing.verdict} onClose={() => setClosing(null)} onDone={done} onStale={reloadKeeping} />}
    </div>
  );
}
