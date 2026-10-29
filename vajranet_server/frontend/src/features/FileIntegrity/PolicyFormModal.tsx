import { useEffect, useMemo, useState } from 'react';
import {
  createFimPolicy, initializeFimBaseline, listFimTemplates, publishFimPolicy, updateFimPolicy,
  type FimMode, type FimOsPlatform, type FimPolicy, type FimPolicyInput, type FimPolicyPath, type FimTemplate,
} from '../../api/services/fimApi';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';
import { BASELINE_RULE, INTERVAL_OPTIONS, blankEntry, MODE_HELP, MODE_LABEL, TARGET_TYPES, entryError, entryIndexFromError, entryKeyOf, errMsg, humanInterval, type EntryProblem } from './constants';
import { nodeMatchesOs, useFimNodes } from './useFimNodes';
import { Dropdown, ErrorBanner, Field, FimModal } from './ui';
import EntriesEditor from './EntriesEditor';
import { btnGhost, btnPrimary, inputCls } from './styles';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';

type TargetMode = 'all' | 'group' | 'node';
const blankPath = (): FimPolicyPath => blankEntry('path');

function initialTargetMode(p?: FimPolicy): TargetMode {
  const t = p?.targets ?? [];
  if (t.some((x) => x.type === TARGET_TYPES.group)) return 'group';
  if (t.some((x) => x.type === TARGET_TYPES.node)) return 'node';
  return 'all';
}

/**
 * `problems`: entries to highlight when the editor opens (e.g. stored entries that can no longer
 * be built, from the Migration view). A save / publish error naming an entry ("paths[3]: ...")
 * highlights that entry too.
 */
export default function PolicyFormModal({ policy, onClose, onSaved, problems }: { policy?: FimPolicy; onClose: () => void; onSaved: () => void; problems?: EntryProblem[] }) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const [name, setName] = useState(policy?.name ?? '');
  const [description, setDescription] = useState(policy?.description ?? '');
  const [os, setOs] = useState<FimOsPlatform>(policy?.osPlatform ?? 'linux');
  const [mode, setMode] = useState<FimMode>(policy?.mode ?? 'enforce');
  const [interval, setIntervalSecs] = useState(policy?.scanIntervalSecs ?? 3600);
  const [realtime, setRealtime] = useState(policy?.realtime ?? false);
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  // Checked by default for a new policy, unchecked when editing.
  const [initNow, setInitNow] = useState(!policy);
  const [paths, setPaths] = useState<FimPolicyPath[]>(policy?.paths?.length ? policy.paths : [blankPath()]);
  const [ignoreText, setIgnoreText] = useState<string[]>((policy?.paths?.length ? policy.paths : [blankPath()]).map((p) => (p.ignore ?? []).join(', ')));
  const [template, setTemplate] = useState<string | null>(policy?.template ?? null);
  const [targetMode, setTargetMode] = useState<TargetMode>(initialTargetMode(policy));
  const [groupIds, setGroupIds] = useState<string[]>((policy?.targets ?? []).filter((t) => t.type === TARGET_TYPES.group).map((t) => t.value));
  const [nodeIds, setNodeIds] = useState<string[]>((policy?.targets ?? []).filter((t) => t.type === TARGET_TYPES.node).map((t) => t.value));
  const [nodeFilter, setNodeFilter] = useState('');
  const [templates, setTemplates] = useState<FimTemplate[]>([]);
  const [tplError, setTplError] = useState(false);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [entryProblems, setEntryProblems] = useState<EntryProblem[]>(problems ?? []);
  const { nodes, groups, loading: nodesLoading, error: nodesError } = useFimNodes();

  useEffect(() => {
    listFimTemplates()
      .then((r) => setTemplates(Array.isArray(r) ? r : r.items ?? []))
      .catch(() => setTplError(true));
  }, []);

  const applyTemplate = (id: string) => {
    const t = templates.find((x) => x.id === id);
    if (!t) return;
    setTemplate(t.id);
    setOs(t.osPlatform);
    setPaths(t.paths.map((p) => ({ ...p, ignore: p.ignore ?? [] })));
    setIgnoreText(t.paths.map((p) => (p.ignore ?? []).join(', ')));
    setIntervalSecs(t.scanIntervalSecs);
    setRealtime(t.realtime);
    if (!name.trim()) setName(t.name);
    if (!description.trim()) setDescription(t.description);
  };

  const pathErrors = useMemo(() => paths.map((p) => entryError(p, os)), [paths, os]);
  const nameErr = !name.trim() ? 'Name is required' : name.length > 200 ? 'Name is too long' : null;
  const targetErr = targetMode === 'group' && groupIds.length === 0 ? 'Pick at least one group' : targetMode === 'node' && nodeIds.length === 0 ? 'Pick at least one host' : null;
  const pathsErr = paths.length === 0 ? 'Add at least one path' : null;
  const valid = !nameErr && !targetErr && !pathsErr && pathErrors.every((e) => !e);


  const targets = (): FimPolicyInput['targets'] =>
    targetMode === 'all' ? [{ type: TARGET_TYPES.all, value: '*' }]
      : targetMode === 'group' ? groupIds.map((v) => ({ type: TARGET_TYPES.group, value: v }))
        : nodeIds.map((v) => ({ type: TARGET_TYPES.node, value: v }));

  const estimatedHosts = (): { n: number; approx: boolean } => {
    if (targetMode === 'node') return { n: nodeIds.length, approx: false };
    if (targetMode === 'group') return { n: groups.filter((g) => groupIds.includes(g.groupId)).reduce((a, g) => a + (g.nodeCount || 0), 0), approx: true };
    return { n: nodes.filter((x) => nodeMatchesOs(x, os)).length, approx: nodes.length === 0 };
  };

  const save = async (publish: boolean) => {
    setTouched(true);
    if (!valid) return;
    if (publish) {
      const { n, approx } = estimatedHosts();
      const ok = await confirm({
        title: 'Save and publish this policy?',
        description: (
          <span>
            This will push the configuration to {approx ? 'up to ' : ''}<strong>{n} {os === 'windows' ? 'Windows' : 'Linux'} host{n === 1 ? '' : 's'}</strong>.
            They will begin scanning {humanInterval(interval).toLowerCase()}{realtime ? ' and watching for real-time changes' : ''}. Hosts outside the target no longer receive it.
          </span>
        ),
        confirmLabel: 'Save and publish',
      });
      if (!ok) return;
    }
    setBusy(true); setError(null);
    /** Highlights the entry a server error names (index into the paths sent = the editor's order). */
    const markEntry = (msg: string) => {
      const idx = entryIndexFromError(msg);
      if (idx !== null && idx < paths.length) setEntryProblems([{ index: idx, path: entryKeyOf(paths[idx]), error: msg }]);
    };
    const body: FimPolicyInput = {
      name: name.trim(), description: description.trim(), osPlatform: os, mode, scanIntervalSecs: interval, realtime, enabled,
      paths: paths.map((p, i): FimPolicyPath => {
        const kind = p.kind ?? 'path';
        // Item kinds: only identifiers go to the server; it fills label/prefix/columns from the catalog.
        if (kind === 'table') return { kind, source: p.source, severity: p.severity, category: p.category.trim(), ignore: [], hash: false, ...(p.extensionEnabled ? { extensionEnabled: true } : {}) };
        if (kind !== 'path') return { kind, path: (p.path ?? '').trim(), severity: p.severity, category: p.category.trim(), ignore: [], hash: false };
        return { kind, path: (p.path ?? '').trim(), severity: p.severity, category: p.category.trim(), hash: p.hash !== false, ignore: (ignoreText[i] ?? '').split(',').map((x) => x.trim()).filter(Boolean) };
      }),
      targets: targets(), template,
    };
    try {
      const saved = policy ? await updateFimPolicy(policy.id, body) : await createFimPolicy(body);
      if (publish) {
        let published = false;
        try { await publishFimPolicy(saved.id ?? policy!.id); showToast('Policy saved and published', 'success'); published = true; }
        catch (e) {
          const msg = errMsg(e, 'error');
          showToast(`Saved, but publish failed: ${safeText(msg)}`, 'error');
          // Editing: stay open with the entry highlighted (a new policy closes, since saving again would create a duplicate).
          if (policy && entryIndexFromError(msg) !== null) { markEntry(msg); setError(`Saved, but publish failed: ${msg}`); return; }
        }
        if (published && initNow) {
          try { await initializeFimBaseline(saved.id ?? policy!.id, 'initial baseline'); showToast('Baseline initialization requested', 'success'); }
          catch (e) { showToast(`Published, but baseline initialization failed: ${safeText(errMsg(e, 'error'))}`, 'error'); }
        }
      } else showToast('Policy saved (not yet published)', 'success');
      onSaved();
    } catch (e) { const msg = errMsg(e, 'Failed to save policy'); setError(msg); markEntry(msg); } finally { setBusy(false); }
  };

  const shownNodes = nodes.filter((n) => nodeMatchesOs(n, os) && `${n.hostname} ${n.host_identifier}`.toLowerCase().includes(nodeFilter.toLowerCase()));

  return (
    <FimModal wide title={policy ? `Edit policy: ${safeText(policy.name)}` : 'New FIM policy'} onClose={onClose}
      footer={<>
        <button className={btnGhost} onClick={onClose}>Cancel</button>
        <label className="mr-auto flex items-center gap-2 text-sm" title="New policies are NOT monitored until baselines are initialized."><input type="checkbox" checked={initNow} onChange={(e) => setInitNow(e.target.checked)} /> Initialize baselines now <span className="text-xs text-slate-500">(without a baseline a host is not monitored)</span></label>
        <button className={btnGhost} disabled={busy} onClick={() => save(false)}>Save</button>
        <button className={btnPrimary} disabled={busy} onClick={() => save(true)}>{busy ? 'Working...' : 'Save and publish'}</button>
      </>}>
      <div className="space-y-5">
        {error && <ErrorBanner message={error} />}
        {touched && !valid && <ErrorBanner message="Please fix the highlighted fields." />}

        <Field label="Start from template" htmlFor="fim-tpl" hint={tplError ? 'Templates could not be loaded.' : 'Fills in platform, paths, scan interval and real-time. You can edit everything afterwards.'}>
          <Dropdown aria-label="Start from template" value="" onChange={applyTemplate} placeholder={templates.length ? 'Choose a template...' : 'No templates'} options={[...templates].sort((a, b) => a.osPlatform.localeCompare(b.osPlatform)).map((t) => ({ value: t.id, label: `${t.osPlatform === 'windows' ? 'Windows' : 'Linux'} - ${t.name.replace(/^(Linux|Windows): /, '')}` }))} />
        </Field>

        <div className="grid sm:grid-cols-2 gap-4">
          <Field label="Name" htmlFor="fim-name" error={touched ? nameErr : null}><input id="fim-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="OS platform" htmlFor="fim-os" hint="Changing platform re-checks every path.">
            <Dropdown aria-label="OS platform" value={os} onChange={(v) => setOs(v as FimOsPlatform)} options={[{ value: 'linux', label: 'Linux' }, { value: 'windows', label: 'Windows' }]} />
          </Field>
        </div>
        <Field label="Description" htmlFor="fim-desc"><textarea id="fim-desc" rows={2} className={inputCls} value={description} onChange={(e) => setDescription(e.target.value)} /></Field>

        <fieldset className="space-y-3">
          <legend className="text-xs font-semibold text-slate-600 dark:text-slate-300">Mode</legend>
          <div className="flex gap-2">
            {(['learn', 'enforce'] as FimMode[]).map((m) => (
              <label key={m} className={`cursor-pointer rounded-lg border px-3 py-1.5 text-sm font-semibold ${mode === m ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300' : 'border-slate-200 dark:border-white/10'}`}>
                <input type="radio" className="sr-only" name="fim-mode" checked={mode === m} onChange={() => setMode(m)} />{MODE_LABEL[m]}
              </label>
            ))}
          </div>
          <p className="text-xs text-slate-500">{MODE_HELP[mode]} {BASELINE_RULE}</p>
        </fieldset>

        <div className="grid sm:grid-cols-2 gap-4">
          <Field label="Scan interval" htmlFor="fim-int">
            <Dropdown aria-label="Scan interval" value={String(interval)} onChange={(v) => setIntervalSecs(Number(v))}
              options={INTERVAL_OPTIONS.some((o) => o.value === interval) ? INTERVAL_OPTIONS.map((o) => ({ value: String(o.value), label: o.label })) : [{ value: String(interval), label: humanInterval(interval) }, ...INTERVAL_OPTIONS.map((o) => ({ value: String(o.value), label: o.label }))]} />
          </Field>
          <div className="space-y-2 pt-5">
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={realtime} onChange={(e) => setRealtime(e.target.checked)} /> Real-time monitoring</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
          </div>
        </div>
        <p className="-mt-3 text-xs text-slate-500">Real-time watches for changes as they happen and records which process and user made them. Scheduled scans only compare against the baseline; they never build or change it.</p>

        <EntriesEditor os={os} paths={paths} setPaths={setPaths} ignoreText={ignoreText} setIgnoreText={setIgnoreText} touched={touched} pathsErr={pathsErr} problems={entryProblems} />

        <fieldset className="space-y-2">
          <legend className="text-xs font-semibold text-slate-600 dark:text-slate-300">Applies to</legend>
          <div className="flex flex-wrap gap-2">
            {([['all', `All ${os === 'windows' ? 'Windows' : 'Linux'} hosts`], ['group', 'Group'], ['node', 'Specific hosts']] as [TargetMode, string][]).map(([v, l]) => (
              <label key={v} className={`cursor-pointer rounded-lg border px-3 py-1.5 text-sm font-semibold ${targetMode === v ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300' : 'border-slate-200 dark:border-white/10'}`}>
                <input type="radio" className="sr-only" name="fim-target" checked={targetMode === v} onChange={() => setTargetMode(v)} />{l}
              </label>
            ))}
          </div>
          {nodesError && <p className="text-xs text-amber-600">{nodesError}</p>}
          {targetMode === 'group' && (
            <div className="max-h-40 overflow-y-auto rounded-lg border border-slate-200 dark:border-white/10 p-2 space-y-1">
              {nodesLoading ? <p className="text-xs text-slate-400">Loading groups...</p> : groups.length === 0 ? <p className="text-xs text-slate-400">No groups available.</p> : groups.map((g) => (
                <label key={g.groupId} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={groupIds.includes(g.groupId)} onChange={() => setGroupIds((x) => (x.includes(g.groupId) ? x.filter((y) => y !== g.groupId) : [...x, g.groupId]))} /><RegText value={g.name} /> <span className="text-xs text-slate-400">({g.nodeCount} hosts)</span></label>
              ))}
            </div>
          )}
          {targetMode === 'node' && (
            <div className="space-y-1">
              <input aria-label="Filter hosts" className={inputCls} placeholder="Filter hosts" value={nodeFilter} onChange={(e) => setNodeFilter(e.target.value)} />
              <div className="max-h-48 overflow-y-auto rounded-lg border border-slate-200 dark:border-white/10 p-2 space-y-1">
                {nodesLoading ? <p className="text-xs text-slate-400">Loading hosts...</p> : shownNodes.length === 0 ? <p className="text-xs text-slate-400">No matching {os} hosts.</p> : shownNodes.map((n) => (
                  <label key={n.host_identifier} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={nodeIds.includes(n.host_identifier)} onChange={() => setNodeIds((x) => (x.includes(n.host_identifier) ? x.filter((y) => y !== n.host_identifier) : [...x, n.host_identifier]))} /><RegText value={n.hostname || n.host_identifier} /></label>
                ))}
              </div>
              <p className="text-xs text-slate-500">{nodeIds.length} selected</p>
            </div>
          )}
          {touched && targetErr && <p role="alert" className="text-xs text-red-600">{targetErr}</p>}
        </fieldset>
      </div>
    </FimModal>
  );
}
