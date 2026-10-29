import { useCallback, useEffect, useState } from 'react';
import { ArrowUpCircle, Eraser, Pencil, Wand2 } from 'lucide-react';
import {
  applyFimRegLegacy, listFimPolicies, listFimRegLegacy, listFimRegPolicyProblems, removeFimRegLegacyEntries, upgradeFimPolicyTemplate,
  type FimPolicy, type FimRegLegacyPolicy, type FimRegPolicyProblem,
} from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { errMsg } from '../constants';
import { EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost, cardCls, tdCls, thCls } from '../styles';
import { safeText } from './safeText';
import { Banner, RegText } from './RegUi';
import NoteModal from './NoteModal';
import PolicyFormModal from '../PolicyFormModal';

type Act = { p: FimRegLegacyPolicy; kind: 'apply' | 'remove' | 'upgrade' };

/** Migration assistant (Super Admin): map hand-made Windows registry policies onto managed coverage. */
export default function MigrationView({ isSuperAdmin }: { isSuperAdmin: boolean }) {
  const { showToast } = useToast();
  const [items, setItems] = useState<FimRegLegacyPolicy[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [act, setAct] = useState<Act | null>(null);
  const [typed, setTyped] = useState('');
  const [problems, setProblems] = useState<FimRegPolicyProblem[] | null>(null);
  const [problemsErr, setProblemsErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ policy: FimPolicy; problem: FimRegPolicyProblem } | null>(null);
  const [opening, setOpening] = useState<number | null>(null);

  const loadProblems = useCallback(async () => {
    setProblemsErr(null);
    try { setProblems((await listFimRegPolicyProblems()).items ?? []); } catch (e) { setProblemsErr(errMsg(e, 'Failed to load policy problems')); }
  }, []);
  const load = useCallback(async () => {
    setErr(null);
    loadProblems();
    try { setItems((await listFimRegLegacy()).items ?? []); } catch (e) { setErr(errMsg(e, 'Failed to load legacy policies')); }
  }, [loadProblems]);

  const openEditor = async (problem: FimRegPolicyProblem) => {
    setOpening(problem.policyId);
    try {
      const policy = ((await listFimPolicies()).items ?? []).find((p) => p.id === problem.policyId);
      if (!policy) { showToast('The policy was not found (it may have been deleted); reload.', 'error'); return; }
      setEditing({ policy, problem });
    } catch (e) { showToast(safeText(errMsg(e, 'Could not load the policy')), 'error'); } finally { setOpening(null); }
  };
  useEffect(() => { if (isSuperAdmin) load(); }, [load, isSuperAdmin]);

  if (!isSuperAdmin) return <div className={cardCls}><EmptyBox title="Super Admin only" description="The migration assistant is available to Super Admins." /></div>;

  return (
    <div className="space-y-3">
      <Banner tone="info">
        Hand-made Windows policies with registry entries keep working. For each one, the assistant maps entries to catalog ids (exact pattern match) or custom rules on the policy's target groups and nodes.
        Suggested order: create the rules, Apply and Initialize the managed policies, check one scan cycle, then remove the registry entries from the legacy policy.
        <b> Baselines are not copied</b> (filters change fingerprints, and copying would bypass the strict Initialize rule): expect one Initialize per node.
      </Banner>
      {problemsErr && <ErrorBanner message={problemsErr} onRetry={loadProblems} stale={!!problems} />}
      {problems && problems.length > 0 && (
        <section aria-label="Policies that can no longer be built" data-testid="fim-policy-problems" className={`${cardCls} space-y-3 border-red-300 p-4 dark:border-red-500/40`}>
          <Banner tone="error">
            <b>{problems.length} polic{problems.length === 1 ? 'y has' : 'ies have'} stored entries that can no longer be built: republishing {problems.length === 1 ? 'it' : 'them'} is blocked.</b>{' '}
            Open each policy in the policy editor and fix or remove the highlighted entry, then save and publish.
          </Banner>
          {problems.map((p) => (
            <article key={p.policyId} aria-label={`Policy problem ${safeText(p.name)}`} className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-semibold"><RegText value={p.name} /> <span className="text-xs font-normal text-slate-500">#{p.policyId}</span></h3>
                <button className={btnGhost} disabled={opening === p.policyId} onClick={() => openEditor(p)}><Pencil className="h-4 w-4" />{opening === p.policyId ? 'Opening...' : 'Open in policy editor'}</button>
              </div>
              <div className="overflow-x-auto rounded-lg border border-red-200 dark:border-red-500/30">
                <table className="w-full min-w-[640px]">
                  <thead className="bg-red-50 dark:bg-red-500/10"><tr><th className={thCls}>Entry #</th><th className={thCls}>Path</th><th className={thCls}>Why it cannot be built</th></tr></thead>
                  <tbody className="divide-y divide-red-100 dark:divide-red-500/20">
                    {p.entries.map((e) => (
                      <tr key={e.index} data-testid={`fim-problem-${p.policyId}-${e.index}`} className="bg-red-50/60 dark:bg-red-500/5">
                        <td className={`${tdCls} font-semibold tabular-nums text-red-700 dark:text-red-300`}>{e.index}</td>
                        <td className={`${tdCls} text-xs`}><RegText value={e.path} mono /></td>
                        <td className={`${tdCls} text-xs text-red-700 dark:text-red-300`}><RegText value={e.error} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-slate-500">Fix or remove entr{p.entries.length === 1 ? 'y' : 'ies'} {p.entries.map((e) => `#${e.index}`).join(', ')} in the policy editor (Policies tab, Edit), then save and publish.</p>
            </article>
          ))}
        </section>
      )}
      {err && <ErrorBanner message={err} onRetry={load} stale={!!items} />}
      {!items ? (!err ? <LoadingRows /> : null) : items.length === 0 ? <div className={cardCls}><EmptyBox title="No legacy registry policies" /></div> : items.map((p) => (
        <article key={p.id} className={`${cardCls} space-y-3 p-4`} aria-label={`Legacy policy ${safeText(p.name)}`}>
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <h3 className="font-semibold"><RegText value={p.name} /> <span className="text-xs font-normal text-slate-500">#{p.id}{p.template ? <> · template <RegText value={p.template} /></> : null}</span></h3>
              <p className="text-xs text-slate-500">Targets: {p.targets.length === 0 ? 'none' : p.targets.map((t, i) => <span key={i}>{i > 0 && ', '}{safeText(t.type)} <RegText value={t.value} mono /></span>)}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button className={btnGhost} onClick={() => setAct({ p, kind: 'apply' })}><Wand2 className="h-4 w-4" />Create rules from this policy</button>
              <button className={`${btnGhost} text-red-600`} onClick={() => { setTyped(''); setAct({ p, kind: 'remove' }); }}><Eraser className="h-4 w-4" />Remove registry entries from legacy policy</button>
              {p.templateUpgradeAvailable && <button className={btnGhost} onClick={() => setAct({ p, kind: 'upgrade' })}><ArrowUpCircle className="h-4 w-4" />Update to template v2</button>}
            </div>
          </div>
          {p.overlapHosts > 0 && (
            <Banner tone="warn">{p.overlapHosts} host(s) also have a managed registry policy: both the legacy and the managed policy raise drift and alerts for the same change until the legacy registry entries are removed.</Banner>
          )}
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-white/10">
            <table className="w-full min-w-[700px]">
              <thead className="bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>#</th><th className={thCls}>Legacy key</th><th className={thCls}>Proposed mapping</th></tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                {p.entries.map((e) => (
                  <tr key={e.index}>
                    <td className={`${tdCls} tabular-nums`}>{e.index}</td>
                    <td className={`${tdCls} text-xs`}><RegText value={e.path} mono /></td>
                    <td className={`${tdCls} text-xs`}>
                      {e.mapping.type === 'catalog' && <>catalog <RegText value={e.mapping.entryKey} mono />{e.mapping.exact ? ' (exact match)' : ' (closest match; the catalog entry may use allow-lists)'}</>}
                      {e.mapping.type === 'custom' && <>custom rule <RegText value={JSON.stringify(e.mapping.spec)} mono className="text-slate-500" /></>}
                      {e.mapping.type === 'invalid' && <span className="text-red-700 dark:text-red-300">cannot be mapped: <RegText value={e.mapping.error} /></span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      ))}

      {editing && (
        <PolicyFormModal policy={editing.policy} problems={editing.problem.entries.map((e) => ({ index: e.index, path: e.path, error: e.error }))}
          onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} />
      )}
      {act?.kind === 'apply' && (
        <NoteModal title={`Create rules from "${safeText(act.p.name)}"?`} confirmLabel="Create rules" onClose={() => setAct(null)}
          description={<>Creates add rules (catalog or custom) on the policy's target groups and nodes. Nothing is published and no baseline is copied: the nodes become Pending publish, then Apply and Initialize them. Until the legacy registry entries are removed, both policies alert.</>}
          onSubmit={async (note) => { const r = await applyFimRegLegacy(act.p.id, note); showToast(`${r.rules} rule(s) created, ${r.skipped} skipped`, 'success'); setAct(null); load(); }} />
      )}
      {act?.kind === 'remove' && (
        <NoteModal title={`Remove registry entries from "${safeText(act.p.name)}"?`} confirmLabel="Remove registry entries" danger disabled={typed !== 'REMOVE'} onClose={() => setAct(null)}
          description={<>
            <p>All registry entries are removed from this legacy policy (its other entries stay). Their baseline rows and open drift belong to the legacy policy and stop being updated. Only do this after the managed policies of its hosts are published, initialised and have completed a scan cycle; otherwise those keys are unmonitored.</p>
          </>}
          onSubmit={async (note) => { const r = await removeFimRegLegacyEntries(act.p.id, note); showToast(`${r.removed} registry entr${r.removed === 1 ? 'y' : 'ies'} removed`, 'success'); setAct(null); load(); }}>
          <label className="block text-sm">Type REMOVE to confirm
            <input className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-white/10 dark:bg-slate-800" value={typed} onChange={(e) => setTyped(e.target.value)} aria-label="Type REMOVE to confirm" />
          </label>
        </NoteModal>
      )}
      {act?.kind === 'upgrade' && (
        <NoteModal title={`Update "${safeText(act.p.name)}" to template v2?`} confirmLabel="Update template" onClose={() => setAct(null)}
          description={<>Replaces the policy's registry entries with the fixed v2 template (value allow-lists that stop boot/logoff/update false drift, and real-time on). This bumps the policy revision, which makes its current baselines stale: <b>Initialize the policy afterwards</b> (Policies tab).</>}
          onSubmit={async (note) => { await upgradeFimPolicyTemplate(act.p.id, note); showToast('Template updated: initialise the policy from the Policies tab', 'success'); setAct(null); load(); }} />
      )}
    </div>
  );
}
