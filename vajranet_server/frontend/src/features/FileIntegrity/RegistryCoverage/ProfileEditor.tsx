import { useCallback, useEffect, useMemo, useState } from 'react';
import { Pencil, Plus, Trash2, Upload } from 'lucide-react';
import {
  createFimRegRule, deleteFimRegProfile, getFimRegCatalog, listFimRegProfiles, revokeFimRegRule,
  type FimRegCatalog, type FimRegEntry, type FimRegJob, type FimRegLimits, type FimRegProfile, type FimRegRule, type FimRegWaiver,
} from '../../../api/services/fimApi';
import { useConfirm } from '../../../context/useConfirm';
import { useToast } from '../../../context/useToast';
import { MODE_LABEL, errMsg, humanInterval } from '../constants';
import { EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost, btnPrimary, cardCls } from '../styles';
import { safeText } from './safeText';
import { Banner, RegText, TierBadge } from './RegUi';
import { catalogToEntry, draftSummary, ruleSummary, tierIncludes, waiverRequestedText, type RowAction, type RuleDraft } from './regModel';
import EntriesTable from './EntriesTable';
import RulesList from './RulesList';
import RuleActionModal from './RuleActionModal';
import AddKeyModal from './AddKeyModal';
import NoteModal from './NoteModal';
import ProfileFormModal from './ProfileFormModal';
import { profilePublishBody, rememberProfileJob, rememberedProfileJob, startProfilePublish } from './regActions';
import PublishJobPanel from './PublishJobPanel';

/** Profiles sub-view. Everyone can read; only Super Admins edit, delete, change rules or publish. */
export default function ProfileEditor({ isSuperAdmin, limits }: { isSuperAdmin: boolean; limits: FimRegLimits | null }) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const [items, setItems] = useState<FimRegProfile[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [catalog, setCatalog] = useState<FimRegCatalog | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [form, setForm] = useState<{ profile?: FimRegProfile } | null>(null);
  const [del, setDel] = useState<FimRegProfile | null>(null);
  const [publish, setPublish] = useState<FimRegProfile | null>(null);
  const [bigConfirm, setBigConfirm] = useState(false);
  const [action, setAction] = useState<{ entry: FimRegEntry; action: RowAction } | null>(null);
  const [adding, setAdding] = useState(false);
  const [revoke, setRevoke] = useState<FimRegRule | null>(null);
  /** Background profile publish started from this tab (kept visible after the modal closes; resumed on remount). */
  const [job, setJob] = useState<{ id: number; initial: FimRegJob | null; label: string | null } | null>(() => {
    const id = rememberedProfileJob();
    return id ? { id, initial: null, label: null } : null;
  });
  const [runningMsg, setRunningMsg] = useState<string | null>(null);
  const [jobDone, setJobDone] = useState(false);
  const [catalogErr, setCatalogErr] = useState<string | null>(null);
  const [catalogTick, setCatalogTick] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setErr(null); setLoading(true);
    try { setItems((await listFimRegProfiles()).items ?? []); } catch (e) { setErr(errMsg(e, 'Failed to load profiles')); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setCatalogErr(null); getFimRegCatalog().then(setCatalog).catch((e) => { setCatalog(null); setCatalogErr(errMsg(e, 'Failed to load the registry catalog')); }); }, [catalogTick]);

  const dismissJob = useCallback(() => { rememberProfileJob(null); setJob(null); setJobDone(false); }, []);
  const jobFinished = useCallback((j: FimRegJob) => {
    setJobDone(true);
    showToast(safeText(`Profile publish ${String(j.status)}: ${j.done} published, ${j.failed} failed${j.error ? ` (${j.error})` : ''}`), j.status === 'done' && j.failed === 0 ? 'success' : 'error');
    load();
  }, [showToast, load]);

  const prof = items?.find((p) => p.id === selected) ?? null;
  const entries = useMemo(() => (prof && catalog ? catalog.items.filter((c) => !c.optInOnly && tierIncludes(prof.tier, c.tier)).map(catalogToEntry) : []), [prof, catalog]);
  const bigThreshold = limits?.publishConfirmAbove ?? 200;

  const waiverRequested = (w: FimRegWaiver) => {
    showToast(waiverRequestedText(w.id), 'success');
    setAction(null); setAdding(false); load();
  };

  const createRule = async (d: RuleDraft) => {
    if (!prof) return;
    const ok = await confirm({
      title: 'Create profile rule?',
      description: `${safeText(draftSummary(d))} - affects up to ${prof.affectedNodes} node(s) using "${safeText(prof.name)}". They become Pending publish until you publish them.`,
      confirmLabel: 'Create rule',
    });
    if (!ok) return;
    await createFimRegRule({ layer: 'profile', scopeValue: String(prof.id), ...d });
    showToast('Profile rule created', 'success');
    setAction(null); setAdding(false); load();
  };

  if (err && !items) return <ErrorBanner message={err} onRetry={load} />;
  if (!items) return loading ? <LoadingRows label="Loading profiles" /> : <ErrorBanner message="Profiles could not be loaded." onRetry={load} />;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-slate-600 dark:text-slate-300">A node uses its node assignment, else its group's, else the default profile. {isSuperAdmin ? '' : 'Only Super Admins can edit profiles; this view is read-only.'}</p>
        {isSuperAdmin && <button className={btnPrimary} onClick={() => setForm({})}><Plus className="h-4 w-4" />New profile</button>}
      </div>
      {err && <ErrorBanner message={err} onRetry={load} stale />}
      {job && <PublishJobPanel key={job.id} jobId={job.id} initial={job.initial} label={job.label ?? undefined} onFinished={jobFinished} onDismiss={dismissJob} canCancel={isSuperAdmin} />}
      {runningMsg && !job && <Banner tone="warn"><span className="flex flex-wrap items-center justify-between gap-2"><span>{safeText(runningMsg)}</span><button className={`${btnGhost} px-2 py-1 text-xs`} onClick={() => setRunningMsg(null)}>Dismiss</button></span></Banner>}
      {items.length === 0 ? <div className={cardCls}><EmptyBox title="No profiles" description="Create a default profile (e.g. Workstation default, Essential)." /></div> : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {items.map((p) => (
            <article key={p.id} aria-label={`Profile ${safeText(p.name)}`} className={`${cardCls} p-4 ${selected === p.id ? 'ring-2 ring-indigo-400' : ''}`}>
              <h3 className="flex flex-wrap items-center gap-2 font-semibold"><RegText value={p.name} />{p.isDefault && <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-700">default</span>}<TierBadge tier={p.tier} /></h3>
              {p.description && <p className="text-sm text-slate-500"><RegText value={p.description} /></p>}
              <p className="mt-1 text-xs text-slate-500">{humanInterval(p.scanIntervalSecs)} · {MODE_LABEL[p.mode]} · {p.rules.filter((r) => r.status === 'active').length} rule(s) · v{p.version}</p>
              <p className="text-sm font-semibold">Affected nodes: {p.affectedNodes.toLocaleString()}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <button className={btnGhost} onClick={() => setSelected(selected === p.id ? null : p.id)} aria-expanded={selected === p.id}>{selected === p.id ? 'Hide rules' : 'Entries & rules'}</button>
                {isSuperAdmin && <>
                  <button className={btnGhost} onClick={() => setForm({ profile: p })}><Pencil className="h-4 w-4" />Edit</button>
                  <button className={btnGhost} disabled={p.affectedNodes === 0 || (!!job && !jobDone)} title={job && !jobDone ? 'A profile publish is running' : undefined} onClick={() => { setBigConfirm(false); setPublish(p); }}><Upload className="h-4 w-4" />Publish all nodes</button>
                  <button className={`${btnGhost} text-red-600`} disabled={p.isDefault} title={p.isDefault ? 'Make another profile the default first' : undefined} onClick={() => setDel(p)}><Trash2 className="h-4 w-4" />Delete</button>
                </>}
              </div>
            </article>
          ))}
        </div>
      )}

      {prof && (
        <section className="space-y-3">
          <div className={cardCls}>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 p-3 dark:border-white/10">
              <h4 className="text-sm font-semibold">Catalog entries in tier {prof.tier} for <RegText value={prof.name} /> ({entries.length})</h4>
              {isSuperAdmin && <button className={btnGhost} onClick={() => setAdding(true)}><Plus className="h-4 w-4" />Add key</button>}
            </div>
            <div className="p-3"><Banner tone="info">Shown before this profile's own rules (listed below); node and group views show the fully resolved result.</Banner></div>
            {!catalog ? (catalogErr ? <div className="p-3"><ErrorBanner message={catalogErr} onRetry={() => setCatalogTick((t) => t + 1)} /></div> : <LoadingRows label="Loading catalog" />) : <EntriesTable entries={entries} canManage={isSuperAdmin} onAction={(entry, a) => setAction({ entry, action: a })} />}
          </div>
          <div className={`${cardCls} p-4`}>
            <RulesList title="Profile rules" rules={prof.rules} onRevoke={isSuperAdmin ? setRevoke : undefined} emptyText="No profile rules." />
          </div>
        </section>
      )}

      {form && <ProfileFormModal profile={form.profile} onClose={() => setForm(null)} onSaved={() => { setForm(null); load(); }} onConflict={() => { setForm(null); load(); }} />}
      {del && (
        <NoteModal title={`Delete profile "${safeText(del.name)}"?`} confirmLabel="Delete" danger noteLabel="Reason (required)"
          description={<>Its {del.affectedNodes} node(s) fall back to their group's or the default profile and become Pending publish. Its rules are revoked.</>}
          onClose={() => setDel(null)}
          onSubmit={async (reason) => { await deleteFimRegProfile(del.id, reason); showToast('Profile deleted', 'success'); if (selected === del.id) setSelected(null); setDel(null); load(); }} />
      )}
      {publish && (
        <NoteModal title={`Publish all ${publish.affectedNodes} node(s) using "${safeText(publish.name)}"?`} confirmLabel="Publish" disabled={publish.affectedNodes > bigThreshold && !bigConfirm} onClose={() => setPublish(null)}
          description={<>Re-resolves and publishes the managed registry policy of every node whose effective profile is this one, for the profile exactly as listed (v{publish.version}); if it changed since, the server refuses and the list is reloaded. The publish runs as a background job (one at a time); its progress stays visible here after this dialog closes. New entries appear in the Needs init queue; nothing is initialised automatically.</>}
          onSubmit={async (note) => {
            const out = await startProfilePublish(profilePublishBody(publish, note, publish.affectedNodes > bigThreshold));
            if (out.kind === 'stale') { setPublish(null); showToast(safeText(out.message), 'error'); load(); return; }
            if (out.kind === 'running') { setPublish(null); setRunningMsg(out.message); showToast(safeText(out.message), 'error'); return; }
            setPublish(null); setRunningMsg(null);
            rememberProfileJob(out.job.id); setJobDone(false);
            setJob({ id: out.job.id, initial: out.job, label: `Publishing "${publish.name}"` });
            showToast(`Publish of "${safeText(publish.name)}" started in the background (job #${out.job.id}); progress is shown above the profiles.`, 'info');
          }}>
          {publish.affectedNodes > bigThreshold && (
            <label className="flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
              <input type="checkbox" className="mt-1" checked={bigConfirm} onChange={(e) => setBigConfirm(e.target.checked)} />
              <span>I confirm publishing to {publish.affectedNodes} nodes (raises an audit alert).</span>
            </label>
          )}
        </NoteModal>
      )}
      {action && prof && (
        <RuleActionModal entry={action.entry} action={action.action} layer="profile" scopeValue={String(prof.id)} limits={limits} allowRecursive={isSuperAdmin}
          submitLabel="Create profile rule" onClose={() => setAction(null)} onSubmit={createRule} waiverMode="submit" onWaiverRequested={waiverRequested} />
      )}
      {adding && prof && (
        <AddKeyModal measureHosts={[]} existing={new Set(entries.map((e) => e.entryKey))} existingPaths={entries.map((e) => ({ entryKey: e.entryKey, path: e.path }))}
          isSuperAdmin={isSuperAdmin} submitLabel="Create profile rule" onClose={() => setAdding(false)} onSubmit={createRule}
          waiverScope={{ scopeType: 'profile', scopeValue: String(prof.id), maxDays: limits?.waiverMaxDays, onRequested: waiverRequested }} />
      )}
      {revoke && (
        <NoteModal title={`Revoke profile rule #${revoke.id}?`} confirmLabel="Revoke rule" danger noteLabel="Reason (required)"
          description={<><RegText value={ruleSummary(revoke)} />. Affected nodes become Pending publish.</>}
          onClose={() => setRevoke(null)}
          onSubmit={async (reason) => { await revokeFimRegRule(revoke.id, reason); showToast('Rule revoked', 'success'); setRevoke(null); load(); }} />
      )}
    </div>
  );
}
