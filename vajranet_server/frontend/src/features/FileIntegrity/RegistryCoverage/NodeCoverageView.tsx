import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Archive, History, Plus, RefreshCw, Stethoscope } from 'lucide-react';
import {
  compactFimRegNode, createFimRegRule, getFimRegNode, listFimRegProfiles, previewFimRegNode, publishFimReg, putFimRegAssignment, requestFimRegWaiver, revokeFimRegRule,
  type FimRegChange, type FimRegEntry, type FimRegLimits, type FimRegNodeCoverage, type FimRegPreview, type FimRegProfile, type FimRegTier,
} from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { MODE_LABEL, errMsg, errStatus, humanInterval } from '../constants';
import { Dropdown, ErrorBanner, LoadingRows, SegmentedControl } from '../ui';
import { btnGhost, cardCls } from '../styles';
import { useDebounced } from '../useDebounced';
import { fmtBytes, fmtCount, safeText } from './safeText';
import { Banner, RealtimeChip, RegText, StatusChip, TierBadge } from './RegUi';
import {
  STEP_TIMEOUT_MS, TIERS, TIER_LABEL, WAIVER_FLOW_TEXT, changesOf, draftSummary, mentionsCompaction, newPendingId, protectedCoverageEntry, ruleSummary,
  waiverRequestedText, waiverRuleOf, withTimeout,
  type PendingChange, type RowAction, type RuleDraft, type WaiverDraft,
} from './regModel';
import EntriesTable from './EntriesTable';
import RulesList from './RulesList';
import PendingDiff from './PendingDiff';
import RuleActionModal from './RuleActionModal';
import AddKeyModal from './AddKeyModal';
import NoteModal from './NoteModal';
import InitPromptModal from './InitPromptModal';
import HistoryDrawer from './HistoryDrawer';
import HygieneDrawer from './HygieneDrawer';
import WaiverRequestModal from './WaiverRequestModal';
import WaiverList from './WaiverList';
import { hostsPublishBody } from './regActions';

type Assign = { profileId: number | null; tier: FimRegTier | null };
const sameAssign = (a: Assign, b: Assign) => a.profileId === b.profileId && a.tier === b.tier;

/** Coverage of one Windows node: header, entries, local edits with live preview, Apply (+ Initialize prompt). */
export default function NodeCoverageView({ host, isSuperAdmin, limits, onDirtyChange }: {
  host: string; isSuperAdmin: boolean; limits: FimRegLimits | null; onDirtyChange?: (dirty: boolean) => void;
}) {
  const { showToast } = useToast();
  const [cov, setCov] = useState<FimRegNodeCoverage | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [profiles, setProfiles] = useState<FimRegProfile[]>([]);
  const [profilesErr, setProfilesErr] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingChange[]>([]);
  const [assign, setAssign] = useState<Assign | null>(null);
  const [preview, setPreview] = useState<FimRegPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [view, setView] = useState<'current' | 'after'>('current');
  const [action, setAction] = useState<{ entry: FimRegEntry; action: RowAction } | null>(null);
  const [adding, setAdding] = useState(false);
  const [applyOpen, setApplyOpen] = useState(false);
  const [applyStep, setApplyStep] = useState<string | null>(null);
  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [requestedWaivers, setRequestedWaivers] = useState<number[]>([]);
  const [waiverFor, setWaiverFor] = useState<PendingChange | null>(null);
  const [initPrompt, setInitPrompt] = useState<{ policyId: number; slots: number[]; headline?: string; full?: boolean } | null>(null);
  const [drawer, setDrawer] = useState<'history' | 'hygiene' | null>(null);
  const [compactOpen, setCompactOpen] = useState(false);

  const load = useCallback(async () => {
    setLoadErr(null); setLoading(true);
    try { setCov(await withTimeout(getFimRegNode(host), STEP_TIMEOUT_MS, 'Loading the node coverage')); }
    catch (e) { setLoadErr(errMsg(e, 'Failed to load the node coverage')); }
    finally { setLoading(false); }
  }, [host]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    listFimRegProfiles().then((r) => { setProfiles(r.items ?? []); setProfilesErr(null); })
      .catch((e) => { setProfiles([]); setProfilesErr(errMsg(e, 'Could not load profiles')); });
  }, []);

  const previewChanges = useMemo(() => changesOf(pending), [pending]);
  const previewDirty = previewChanges.length > 0 || assign !== null;
  const dirty = pending.length > 0 || assign !== null;
  const waiverItems = pending.filter((p) => !!p.waiver);
  const needsWaiver = pending.filter((p) => p.needsWaiverFor && !p.waiver);
  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);

  // Live dry-run of the local edits that are saved directly (waiver-bound changes wait for approval). Stale answers are dropped.
  const body = useMemo(() => (previewDirty ? JSON.stringify({ changes: previewChanges, ...(assign ? { assignment: assign } : {}) }) : ''), [previewDirty, previewChanges, assign]);
  const debounced = useDebounced(body, 400);
  const seq = useRef(0);
  useEffect(() => {
    const my = ++seq.current;
    if (!debounced) { setPreview(null); setPreviewErr(null); setPreviewing(false); return; }
    setPreviewing(true);
    const req = JSON.parse(debounced) as { changes: FimRegChange[]; assignment?: Assign };
    withTimeout(previewFimRegNode(host, req), STEP_TIMEOUT_MS, 'The preview')
      .then((p) => { if (seq.current === my) { setPreview(p); setPreviewErr(null); } })
      .catch((e) => { if (seq.current === my) { setPreview(null); setPreviewErr(errMsg(e, 'Preview failed')); } })
      .finally(() => { if (seq.current === my) setPreviewing(false); });
  }, [debounced, host]);
  useEffect(() => { if (!preview) setView('current'); }, [preview]);

  const addPending = (change: FimRegChange, summary: string, waiver?: WaiverDraft) => setPending((p) => [...p, { id: newPendingId(), change, summary, ...(waiver ? { waiver } : {}) }]);
  const pendingRevokes = useMemo(() => new Set(pending.flatMap((p) => (p.change.action === 'revoke' ? [p.change.ruleId] : []))), [pending]);

  if (loadErr && !cov) return <ErrorBanner message={loadErr} onRetry={load} />;
  if (!cov) return loading ? <LoadingRows label="Loading coverage" /> : <ErrorBanner message="The node coverage could not be loaded." onRetry={load} />;

  const stale = !!loadErr;
  const hostLabel = cov.hostname || cov.host;
  const canEdit = cov.canManage && cov.managedEnabled;
  const currentAssign: Assign = { profileId: cov.assignment.node?.profileId ?? null, tier: cov.assignment.node?.tier ?? null };
  const shownAssign = assign ?? currentAssign;
  const setAssignment = (next: Assign) => setAssign(sameAssign(next, currentAssign) ? null : next);
  const profileName = (id: number | null) => (id === null ? 'inherit' : profiles.find((p) => p.id === id)?.name ?? `profile #${id}`);
  const assignmentText = assign ? `profile ${profileName(assign.profileId)}, tier ${assign.tier ? TIER_LABEL[assign.tier] : 'inherit'}` : null;
  const previewStale = body !== debounced || previewing;
  const publishOnly = !dirty && cov.status === 'pending';

  const applyDisabledReason = !cov.canManage ? 'You cannot manage this node.'
    : !cov.managedEnabled ? 'Registry coverage is disabled.'
      : stale ? 'Reload first: the last refresh failed, so this view may be out of date.'
        : needsWaiver.length > 0 ? 'A pending change reduces protected coverage: click "Request waiver" on it (or remove it).'
          : previewDirty ? (previewStale ? 'Waiting for the preview...' : previewErr ? 'The preview failed; fix or remove the changes.' : !preview?.ok ? 'The preview reports errors; Apply is disabled.' : null)
            : waiverItems.length > 0 || publishOnly ? null : 'No changes to apply.';

  const profileSource = cov.profile.source === 'group' ? `from group ${cov.ownerGroupId ?? '?'}` : cov.profile.source;
  const existingKeys = new Set([...cov.entries.map((e) => e.entryKey), ...pending.flatMap((p) => (p.change.action === 'add' && p.change.rule.op === 'add' ? [p.change.rule.target] : []))]);
  const shownEntries = view === 'after' && preview ? preview.entries : cov.entries;

  const runApply = async (note: string) => {
    const approvedHash = preview?.resolvedHash ?? cov.resolvedHash;
    const fromRev = cov.rev;
    const wasPublishOnly = publishOnly;
    const items = [...pending];
    const remaining = new Set(items.map((i) => i.id));
    const requested: number[] = [];
    let saved = 0;
    setApplyErr(null);

    const reportWaivers = () => {
      if (!requested.length) return;
      setRequestedWaivers((r) => [...r, ...requested]);
      for (const id of requested) showToast(waiverRequestedText(id), 'success');
    };
    /** Stops the flow: keeps unsaved changes, closes the dialog, states exactly what was saved. */
    const fail = async (headline: string, e?: unknown, mark?: { id: string; entryKey: string }) => {
      setPending(items.filter((i) => remaining.has(i.id)).map((i) => (mark && i.id === mark.id ? { ...i, needsWaiverFor: mark.entryKey } : i)));
      reportWaivers();
      setApplyStep(null); setApplyOpen(false);
      const savedLine = saved > 0 ? `${saved} change(s) were saved but NOT published; review and Apply again.` : 'Nothing was saved or published.';
      const detail = e === undefined ? '' : ` (${errMsg(e, 'request failed')})`;
      const msg = `${headline} ${savedLine}${detail}`;
      setApplyErr(msg);
      showToast(safeText(msg), 'error');
      await load();
    };

    // 1. Waiver requests (each bound to its exact rule). The rules themselves are NOT created now.
    const waivers = items.filter((p) => p.waiver);
    for (let i = 0; i < waivers.length; i++) {
      const p = waivers[i];
      if (p.change.action !== 'add' || !p.waiver) continue;
      setApplyStep(`Requesting waiver ${i + 1} of ${waivers.length}...`);
      try {
        const w = await withTimeout(requestFimRegWaiver({
          entryKey: p.waiver.entryKey, scopeType: 'node', scopeValue: host, action: p.waiver.action, reason: p.waiver.reason,
          expiresAt: p.waiver.expiresAt, rule: waiverRuleOf(p.change.rule),
        }), STEP_TIMEOUT_MS, 'The waiver request');
        requested.push(w.id); remaining.delete(p.id);
      } catch (e) { await fail('A waiver request failed.', e); return; }
    }

    // 2. Directly saved changes, in order, then the assignment.
    const direct = items.filter((p) => !p.waiver);
    for (let i = 0; i < direct.length; i++) {
      const p = direct[i];
      setApplyStep(`Saving change ${i + 1} of ${direct.length}...`);
      try {
        if (p.change.action === 'add') await withTimeout(createFimRegRule({ layer: 'node', scopeValue: host, ...p.change.rule, reason: p.change.rule.reason || note }), STEP_TIMEOUT_MS, 'Saving a change');
        else await withTimeout(revokeFimRegRule(p.change.ruleId, note), STEP_TIMEOUT_MS, 'Saving a change');
        saved++; remaining.delete(p.id);
      } catch (e) {
        const entryKey = errStatus(e) === 422 && p.change.action === 'add' ? protectedCoverageEntry(errMsg(e, '')) : null;
        if (entryKey) { await fail(`"${safeText(p.summary)}" overlaps protected coverage of ${safeText(entryKey)} and needs a waiver: click "Request waiver" on it in Pending changes.`, undefined, { id: p.id, entryKey }); return; }
        await fail('The server refused a change.', e); return;
      }
    }
    if (assign) {
      setApplyStep('Saving the assignment...');
      try {
        await withTimeout(putFimRegAssignment('node', host, { ...assign, reason: note, ...(cov.assignment.node ? { version: cov.assignment.node.version } : {}) }), STEP_TIMEOUT_MS, 'Saving the assignment');
        saved++; setAssign(null);
      } catch (e) { await fail('Saving the assignment failed.', e); return; }
    }
    setPending([]);
    reportWaivers();
    requested.length = 0;

    if (saved === 0 && !wasPublishOnly) {
      // Only waiver requests: nothing to publish until a waiver is approved and its change applied.
      setApplyStep(null); setApplyOpen(false);
      await load();
      return;
    }

    // 3. Re-check that what was saved resolves to the preview the user approved.
    setApplyStep('Re-checking the node...');
    let fresh: FimRegNodeCoverage;
    try { fresh = await withTimeout(getFimRegNode(host), STEP_TIMEOUT_MS, 'Re-checking the node'); }
    catch (e) { await fail('Re-checking the node failed.', e); return; }
    setCov(fresh);
    if (fresh.resolvedHash !== approvedHash) {
      await fail('The saved configuration resolves differently from the preview you approved (someone else may have changed this node at the same time).');
      return;
    }

    // 4. Publish this one node, guarded by the hash the user approved.
    setApplyStep('Publishing...');
    let res: Awaited<ReturnType<typeof publishFimReg>>;
    try {
      res = await withTimeout(publishFimReg(hostsPublishBody([{ host, resolvedHash: fresh.resolvedHash }], note)), STEP_TIMEOUT_MS, 'Publishing');
    } catch (e) {
      await fail(errStatus(e) === 409 ? "Someone else changed this node's coverage since you loaded it, so nothing was published." : 'Publishing failed.', e);
      return;
    }
    const results = Array.isArray(res?.results) ? res.results : [];
    const r = results.find((x) => x.host === host) ?? (results.length === 1 ? results[0] : undefined);
    if (!r) { await fail('The server returned no publish result for this node, so it is treated as NOT published.'); return; }
    if (r.error || r.status === 'invalid') { await fail(`Publish failed: ${safeText(r.error || 'the configuration is invalid')}.`); return; }
    setApplyOpen(false); setApplyStep(null);
    await load();
    const revLine = r.revChanged ? `Published: rev ${fromRev ?? '-'} -> ${r.rev ?? '-'}` : `Published: rev ${r.rev ?? fromRev ?? '-'} unchanged (no slot changes)`;
    showToast(revLine, 'success');
    if (r.needsInit.length > 0 && r.policyId !== null) setInitPrompt({ policyId: r.policyId, slots: r.needsInit, headline: revLine });
  };

  const tierLabel = (t: FimRegTier) => {
    const o = cov.tierOptions[t];
    return o ? `${TIER_LABEL[t]} - ${fmtCount(o.entries)} entries, ${fmtCount(o.rows)} rows, ${fmtBytes(o.bytes)}` : TIER_LABEL[t];
  };

  const directCount = pending.length - waiverItems.length;

  return (
    <div className="space-y-3">
      {loadErr && <ErrorBanner message={loadErr} onRetry={load} stale />}
      {applyErr && (
        <Banner tone="error">
          <div className="flex flex-wrap items-start justify-between gap-2"><span><b>Apply did not complete.</b> <RegText value={applyErr} /></span>
            <button className="text-xs font-semibold underline" onClick={() => setApplyErr(null)}>Dismiss</button></div>
        </Banner>
      )}
      {requestedWaivers.length > 0 && (
        <Banner tone="info">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <ul className="list-disc pl-4 text-xs">{requestedWaivers.map((id) => <li key={id}>{waiverRequestedText(id)}</li>)}</ul>
            <button className="text-xs font-semibold underline" onClick={() => setRequestedWaivers([])}>Dismiss</button>
          </div>
        </Banner>
      )}
      <header className={`${cardCls} p-4`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100"><RegText value={hostLabel} /></h3>
            {cov.hostname && <RegText value={cov.host} mono className="block text-xs text-slate-500" />}
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-violet-100 px-2 py-0.5 text-xs font-semibold text-violet-700 dark:bg-violet-500/15 dark:text-violet-300" title="Effective profile and where it comes from">
                Profile: <RegText value={cov.profile.name} /> ({safeText(profileSource)})
              </span>
              <TierBadge tier={cov.tier.value} suffix={`from ${safeText(cov.tier.source)}`} />
              <StatusChip status={cov.status} needsInit={cov.needsInitSlots.length} stale={stale} />
              <RealtimeChip available={cov.realtimeAvailable} />
            </div>
            <p className="mt-1 text-xs text-slate-500">
              {humanInterval(cov.scanIntervalSecs)} · {MODE_LABEL[cov.mode]} · rev {cov.rev ?? '-'} (published {cov.publishedRev ?? '-'}) · {fmtCount(cov.totals.entries)} entries, {fmtCount(cov.totals.rows)} rows, {fmtBytes(cov.totals.bytes)} · catalog v{cov.catalogVersion}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className={btnGhost} onClick={load} disabled={loading}><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />{loading ? 'Reloading...' : 'Reload'}</button>
            <button className={btnGhost} onClick={() => setDrawer('history')}><History className="h-4 w-4" />History</button>
            <button className={btnGhost} onClick={() => setDrawer('hygiene')}><Stethoscope className="h-4 w-4" />Hygiene</button>
            {canEdit && mentionsCompaction(cov.warnings) && <button className={btnGhost} disabled={stale} onClick={() => setCompactOpen(true)}><Archive className="h-4 w-4" />Compact coverage</button>}
          </div>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <div>
            <p className="mb-1 text-xs font-semibold text-slate-600 dark:text-slate-300">Tier (node assignment)</p>
            <Dropdown aria-label="Tier" value={shownAssign.tier ?? ''} disabled={!canEdit}
              onChange={(v) => setAssignment({ ...shownAssign, tier: v ? (v as FimRegTier) : null })}
              placeholder={`Inherit (${cov.tier.source === 'node' ? 'from group or profile' : TIER_LABEL[cov.tier.value]})`}
              options={TIERS.map((t) => ({ value: t, label: tierLabel(t) }))} />
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold text-slate-600 dark:text-slate-300">Profile (node assignment)</p>
            <Dropdown aria-label="Profile" value={shownAssign.profileId === null ? '' : String(shownAssign.profileId)} disabled={!canEdit}
              onChange={(v) => setAssignment({ ...shownAssign, profileId: v ? Number(v) : null })}
              placeholder={`Inherit (${cov.profile.source === 'node' ? 'group or default' : safeText(cov.profile.name)})`}
              options={profiles.map((p) => ({ value: String(p.id), label: `${safeText(p.name)}${p.isDefault ? ' (default)' : ''} - ${TIER_LABEL[p.tier]}` }))} />
            {profilesErr && <p className="mt-1 text-xs text-red-600 dark:text-red-400">Profiles unavailable: {safeText(profilesErr)}</p>}
          </div>
        </div>
        {(shownAssign.tier !== currentAssign.tier || shownAssign.profileId !== currentAssign.profileId) && <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">Assignment change pending: see the preview, then Apply.</p>}
      </header>

      {!cov.managedEnabled && <Banner tone="warn">Registry coverage is disabled. This view is read-only.</Banner>}
      {cov.errors.length > 0 && <Banner tone="error"><b>Resolution errors</b> (the last good published config keeps running):<ul className="list-disc pl-4">{cov.errors.map((e, i) => <li key={i}><RegText value={e} /></li>)}</ul></Banner>}
      {cov.blocked.length > 0 && (
        <Banner tone="warn"><b>Blocked rules ({cov.blocked.length})</b>: not applied until an approved waiver exists.
          <ul className="list-disc pl-4 text-xs">{cov.blocked.map((b, i) => <li key={`${b.ruleId}-${i}`}>{safeText(b.layer)} rule #{b.ruleId} {safeText(b.op)} <RegText value={b.entryKey || b.target} mono />: <RegText value={b.reason} /></li>)}</ul>
        </Banner>
      )}
      {cov.warnings.length > 0 && <Banner tone="warn"><ul className="list-disc pl-4 text-xs">{cov.warnings.map((w, i) => <li key={i}><RegText value={w} /></li>)}</ul></Banner>}
      {cov.retiredPending.length > 0 && (
        <Banner tone="info"><b>Will be removed on Apply</b> ({cov.retiredPending.length}):
          <ul className="list-disc pl-4 text-xs">{cov.retiredPending.map((r) => <li key={r.slot}>slot {r.slot} <RegText value={r.entryKey} mono /> <RegText value={r.path} mono className="text-slate-500" /></li>)}</ul>
        </Banner>
      )}

      <div className={`grid gap-3 xl:grid-cols-[minmax(0,1fr)_360px] ${stale ? 'opacity-70' : ''}`}>
        <div className="space-y-3 min-w-0">
          <div className={cardCls}>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 p-3 dark:border-white/10">
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-semibold">Entries ({shownEntries.length})</h4>
                {preview && <SegmentedControl value={view} onChange={setView} size="sm" options={[{ value: 'current', label: 'Current' }, { value: 'after', label: 'After pending changes' }]} />}
              </div>
              {canEdit && <button className={btnGhost} onClick={() => setAdding(true)}><Plus className="h-4 w-4" />Add key</button>}
            </div>
            <EntriesTable entries={shownEntries} canManage={canEdit && view === 'current'} onAction={(entry, a) => setAction({ entry, action: a })}
              showBaseline realtimeAvailable={cov.realtimeAvailable} emptyText="No effective registry entries" />
          </div>
          <div className={`${cardCls} space-y-4 p-4`}>
            <RulesList title="Node rules" rules={cov.rules.node} pendingRevokes={pendingRevokes} revokeLabel="Revoke (pending)"
              onRevoke={canEdit ? (r) => addPending({ action: 'revoke', ruleId: r.id }, ruleSummary(r)) : undefined} emptyText="No node-specific rules." />
            <details>
              <summary className="cursor-pointer text-xs font-semibold uppercase text-slate-500">Inherited rules (group {cov.rules.group.length}, profile {cov.rules.profile.length})</summary>
              <div className="mt-2 space-y-3">
                <RulesList title="Group rules (edit in Groups)" rules={cov.rules.group} />
                <RulesList title="Profile rules (edit in Profiles)" rules={cov.rules.profile} />
              </div>
            </details>
            {cov.waivers.length > 0 && <WaiverList title={`Waivers for this node (${cov.waivers.length})`} waivers={cov.waivers} isSuperAdmin={isSuperAdmin} onApplied={load} />}
          </div>
        </div>
        <div className="xl:sticky xl:top-0 self-start">
          <PendingDiff pending={pending} assignmentText={assignmentText} preview={previewStale ? null : preview} previewing={previewStale && previewDirty} previewErr={previewErr}
            onRemove={(id) => setPending((p) => p.filter((x) => x.id !== id))} onClearAssignment={() => setAssign(null)}
            onRequestWaiver={(p) => setWaiverFor(p)}
            onApply={() => { setApplyErr(null); setApplyOpen(true); }} applyDisabledReason={applyDisabledReason} publishOnly={publishOnly} />
        </div>
      </div>

      {action && (
        <RuleActionModal entry={action.entry} action={action.action} layer="node" scopeValue={host} limits={limits} allowRecursive={isSuperAdmin}
          submitLabel="Add to pending changes" waiverMode="collect" onClose={() => setAction(null)}
          onSubmit={async (d: RuleDraft, waiver?: WaiverDraft) => { addPending({ action: 'add', rule: d }, draftSummary(d), waiver); setAction(null); }} />
      )}
      {adding && (
        <AddKeyModal measureHosts={[{ host, label: hostLabel }]} existing={existingKeys} existingPaths={cov.entries.map((e) => ({ entryKey: e.entryKey, path: e.path }))}
          isSuperAdmin={isSuperAdmin} submitLabel="Add to pending changes" onClose={() => setAdding(false)}
          onSubmit={async (d) => { addPending({ action: 'add', rule: d }, draftSummary(d)); setAdding(false); }} />
      )}
      {waiverFor && waiverFor.change.action === 'add' && waiverFor.needsWaiverFor && (
        <WaiverRequestModal entryKey={waiverFor.needsWaiverFor} entryPath={String(waiverFor.change.rule.spec.path ?? waiverFor.change.rule.target)} action="narrow"
          scopeType="node" scopeValue={host} changeText={waiverFor.summary} rule={waiverRuleOf(waiverFor.change.rule)} mode="collect" maxDays={limits?.waiverMaxDays}
          onClose={() => setWaiverFor(null)}
          onCollected={(wd) => { setPending((p) => p.map((x) => (x.id === waiverFor.id ? { ...x, waiver: wd } : x))); setWaiverFor(null); }} />
      )}
      {applyOpen && (
        <NoteModal title={`Apply changes to ${safeText(hostLabel)}`} confirmLabel={directCount === 0 && !assign && !publishOnly ? 'Request waiver(s)' : 'Apply and publish'}
          onClose={() => { if (!applyStep) setApplyOpen(false); }} onSubmit={runApply} disabled={!!applyStep}
          description={<>
            {waiverItems.length > 0 && <p className="mb-1"><b>{waiverItems.length} waiver request(s)</b> are sent first. Their changes are NOT made now. {WAIVER_FLOW_TEXT}</p>}
            {(directCount > 0 || assign) && <p>{`${directCount} rule change(s)${assign ? ' and an assignment change' : ''} are saved in order, then the node's managed policy is published`}{preview?.rev && preview.rev.current !== preview.rev.next ? ` (rev ${preview.rev.current ?? '-'} -> ${preview.rev.next ?? '-'})` : ''}.</p>}
            {publishOnly && <p>The saved configuration is published.</p>}
            <p className="mt-1">Each step times out after {Math.round(STEP_TIMEOUT_MS / 1000)} s. If a step fails after changes were saved, you are told how many were saved but not published.</p>
            <p className="mt-1">Nothing is initialised automatically: new entries are offered for Initialize afterwards. Removed entries are soft-retired for 7 days and their open drift is closed as ignored.</p>
          </>}>
          {applyStep && <p role="status" className="text-sm font-semibold text-indigo-700 dark:text-indigo-300">{applyStep}</p>}
        </NoteModal>
      )}
      {initPrompt && (
        <InitPromptModal policyId={initPrompt.policyId} host={host} hostLabel={hostLabel} slots={initPrompt.slots} headline={initPrompt.headline} full={initPrompt.full}
          onClose={() => { setInitPrompt(null); load(); }} />
      )}
      {compactOpen && (
        <NoteModal title="Compact coverage?" confirmLabel="Compact" danger onClose={() => setCompactOpen(false)}
          description={<>Compaction renumbers every slot of this node&apos;s managed policy under a new revision to drop retired slots. <b>Every entry then needs a full re-initialisation</b>, and registry monitoring of this node pauses until it is initialised. It is never automatic.</>}
          onSubmit={async (note) => {
            const r = await compactFimRegNode(host, note);
            if (r.error) throw new Error(r.error);
            setCompactOpen(false); await load();
            showToast(`Coverage compacted: rev ${r.rev ?? '-'}`, 'success');
            if (r.needsInit.length > 0 && r.policyId !== null) setInitPrompt({ policyId: r.policyId, slots: r.needsInit, full: true, headline: `Compacted: rev ${r.rev ?? '-'}` });
          }} />
      )}
      {drawer === 'history' && <HistoryDrawer scopeType="node" scopeValue={host} title={`History: ${safeText(hostLabel)}`} canRollback={canEdit} onClose={() => setDrawer(null)} onRolledBack={load} />}
      {drawer === 'hygiene' && <HygieneDrawer host={host} hostLabel={safeText(hostLabel)} canAck={cov.canManage} onClose={() => setDrawer(null)} />}
    </div>
  );
}
