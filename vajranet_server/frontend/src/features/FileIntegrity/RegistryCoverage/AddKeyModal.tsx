import { useEffect, useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { getFimRegCatalog, type FimRegCatalog, type FimRegCatalogItem, type FimRegLayer, type FimRegWaiver, type FimSeverity } from '../../../api/services/fimApi';
import { SEVERITIES, errMsg, errStatus } from '../constants';
import WaiverRequestModal from './WaiverRequestModal';
import { Dropdown, ErrorBanner, Field, FimModal, LoadingRows, SegmentedControl, SeverityBadge } from '../ui';
import { btnGhost, btnPrimary, inputCls } from '../styles';
import { AttackChips, Banner, ChipInput, EstimateCell, NoteField, ProtectedLock, RegText, TierBadge, ValuesFilter } from './RegUi';
import MeasurePanel, { type MeasureOutcome } from './MeasurePanel';
import { CUSTOM_TARGET, draftSummary, protectedCoverageEntry, waiverRuleOf, type RuleDraft } from './regModel';
import { patternsIntersect, validateExcludeKeys, validateRegKeyPattern, validateValueList, validateValueName } from './regValidation';

const CATEGORIES = ['persistence', 'defense-evasion', 'credential-access', 'privilege-escalation', 'execution', 'remote-access', 'hijack', 'agent', 'posture', 'custom'];


function CatalogList({ catalog, existing, onPick, picked }: { catalog: FimRegCatalog; existing: Set<string>; onPick: (c: FimRegCatalogItem) => void; picked: string | null }) {
  const [q, setQ] = useState('');
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return catalog.items.filter((c) => !existing.has(c.id)).filter((c) => !needle
      || `${c.id} ${c.tier} ${c.label} ${c.path} ${c.category} ${c.attack.join(' ')}`.toLowerCase().includes(needle));
  }, [catalog, existing, q]);
  return (
    <div className="space-y-2">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
        <input aria-label="Search catalog" className={`${inputCls} pl-8`} placeholder="Search by ATT&CK id (T1547.001), tier, label or key path" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <p className="text-xs text-slate-500">Catalog v{catalog.version}. Entries already effective on this scope are hidden.</p>
      <ul className="max-h-[45vh] space-y-2 overflow-y-auto pr-1">
        {shown.map((c) => (
          <li key={c.id}>
            <button type="button" onClick={() => onPick(c)} aria-pressed={picked === c.id}
              className={`w-full rounded-lg border p-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 ${picked === c.id ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-500/10' : 'border-slate-200 hover:bg-slate-50 dark:border-white/10 dark:hover:bg-white/5'}`}>
              <span className="flex flex-wrap items-center gap-2 text-sm font-semibold">
                {c.protected && <ProtectedLock />}<RegText value={c.label} /><TierBadge tier={c.tier} suffix={c.optInOnly ? 'opt-in only' : undefined} /><SeverityBadge severity={c.severity} />
                {!c.verified && <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-bold text-slate-700 dark:bg-white/15 dark:text-slate-200">UNVERIFIED (estimate)</span>}
                {c.realtimeRequired && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800">needs real-time</span>}
              </span>
              <RegText value={c.path} mono className="block text-xs text-slate-600 dark:text-slate-300" />
              <span className="mt-1 flex flex-wrap items-center gap-2"><ValuesFilter values={c.values} ignoreValues={c.ignoreValues} /><AttackChips ids={c.attack} /><EstimateCell estimate={c.estimate} /><span className="text-[10px] text-slate-500">noise: {c.noise}</span></span>
              {c.notes && <span className="mt-1 block text-xs text-slate-500"><RegText value={c.notes} /></span>}
            </button>
          </li>
        ))}
        {shown.length === 0 && <li className="text-sm text-slate-400">No matching catalog entries.</li>}
      </ul>
    </div>
  );
}

/**
 * Add a registry key: a catalog entry or a custom key with live validation (§4.2), allow/deny
 * lists, and a measurement on a node (custom keys must be measured unless a Super Admin overrides).
 */
export default function AddKeyModal({ measureHosts, existing, existingPaths, isSuperAdmin, submitLabel, onSubmit, onClose, waiverScope }: {
  measureHosts: { host: string; label: string }[]; existing: Set<string>; existingPaths: { entryKey: string; path: string }[];
  isSuperAdmin: boolean; submitLabel: string; onSubmit: (d: RuleDraft) => Promise<void>; onClose: () => void;
  /** Immediate-save views: a custom key refused with 422 "protected coverage: <id>" offers a waiver request (bound to this add). */
  waiverScope?: { scopeType: FimRegLayer; scopeValue: string; maxDays?: number; onRequested: (w: FimRegWaiver) => Promise<void> | void };
}) {
  const [waiverFor, setWaiverFor] = useState<{ entryKey: string; draft: RuleDraft } | null>(null);
  const [catalog, setCatalog] = useState<FimRegCatalog | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [mode, setMode] = useState<'catalog' | 'custom'>('catalog');
  const [picked, setPicked] = useState<FimRegCatalogItem | null>(null);
  const [path, setPath] = useState('');
  const [values, setValues] = useState<string[]>([]);
  const [ignoreValues, setIgnoreValues] = useState<string[]>([]);
  const [excludeKeys, setExcludeKeys] = useState<string[]>([]);
  const [severity, setSeverity] = useState<FimSeverity>('high');
  const [label, setLabel] = useState('');
  const [category, setCategory] = useState('custom');
  const [measure, setMeasure] = useState<MeasureOutcome | null>(null);
  const [override, setOverride] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { getFimRegCatalog().then(setCatalog).catch((e) => setLoadErr(errMsg(e, 'Failed to load the registry catalog'))); }, []);
  const limits = catalog?.limits;

  const pathErr = path === '' ? null : validateRegKeyPattern(path, { allowRecursive: isSuperAdmin });
  const listErr = validateValueList(values, limits?.valuesMax ?? 64, 'values')
    ?? validateValueList(ignoreValues, limits?.ignoreValuesMax ?? 64, 'ignored values')
    ?? (path && !pathErr ? validateExcludeKeys(excludeKeys, path, limits?.excludeKeysMax ?? 32, isSuperAdmin) : null);
  const customSpec = useMemo(() => ({
    path,
    ...(values.length ? { values } : {}),
    ...(ignoreValues.length ? { ignoreValues } : {}),
    ...(excludeKeys.length ? { excludeKeys } : {}),
  }), [path, values, ignoreValues, excludeKeys]);
  const signature = JSON.stringify(customSpec);
  const overlaps = useMemo(() => (path && !pathErr ? existingPaths.filter((e) => patternsIntersect(e.path, path)) : []), [existingPaths, path, pathErr]);
  const measured = !!measure && measure.signature === signature && measure.m.status === 'done';

  const customReady = path !== '' && !pathErr && !listErr && label.trim() !== ''
    && (measured ? !measure?.overBlock : isSuperAdmin && override && overrideReason.trim().length >= 3);
  const reasonOk = reason.trim().length >= 3;
  const canSubmit = reasonOk && (mode === 'catalog' ? !!picked : customReady);

  const submit = async () => {
    setBusy(true); setErr(null);
    let draft: RuleDraft | null = null;
    try {
      if (mode === 'catalog' && picked) {
        draft = { op: 'add', target: picked.id, spec: {}, reason: reason.trim() };
      } else {
        const useOverride = !measured && override;
        draft = {
          op: 'add', target: CUSTOM_TARGET,
          spec: { ...customSpec, severity, category, label: label.trim(), ...(useOverride ? { measureOverride: true } : {}) },
          reason: useOverride ? `${reason.trim()} [measure override: ${overrideReason.trim()}]` : reason.trim(),
        };
      }
      await onSubmit(draft);
    } catch (e) {
      const protectedKey = errStatus(e) === 422 ? protectedCoverageEntry(errMsg(e, '')) : null;
      if (protectedKey && waiverScope && draft) { setWaiverFor({ entryKey: protectedKey, draft }); return; }
      setErr(errMsg(e, 'Could not add the key'));
    } finally { setBusy(false); }
  };

  if (waiverFor && waiverScope) {
    return (
      <WaiverRequestModal entryKey={waiverFor.entryKey} entryPath={String(waiverFor.draft.spec.path ?? path)} action="narrow"
        scopeType={waiverScope.scopeType} scopeValue={waiverScope.scopeValue} changeText={`${draftSummary(waiverFor.draft)} (overlaps protected coverage of ${waiverFor.entryKey})`}
        rule={waiverRuleOf(waiverFor.draft)} mode="submit" maxDays={waiverScope.maxDays} onClose={onClose}
        onCreated={async (w) => { await waiverScope.onRequested(w); }} />
    );
  }

  return (
    <FimModal wide title="Add registry key" onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>Cancel</button><button className={btnPrimary} disabled={busy || !canSubmit} onClick={submit}>{busy ? 'Working...' : submitLabel}</button></>}>
      <div className="space-y-3">
        {loadErr && <ErrorBanner message={loadErr} />}
        {err && <ErrorBanner message={err} />}
        <SegmentedControl value={mode} onChange={setMode} size="sm" options={[{ value: 'catalog', label: 'From catalog' }, { value: 'custom', label: 'Custom key' }]} />
        {mode === 'catalog' ? (
          !catalog ? (!loadErr && <LoadingRows label="Loading catalog" />) : <CatalogList catalog={catalog} existing={existing} picked={picked?.id ?? null} onPick={setPicked} />
        ) : (
          <div className="space-y-3">
            <Field label="Key pattern" htmlFor="reg-add-path" error={pathErr}
              hint={<>HKEY_LOCAL_MACHINE\ or HKEY_USERS\ only. % = exactly one key segment (HKEY_USERS\%\... for every loaded user hive){isSuperAdmin ? '; %% (recursive) only as the last segment' : ''}.</>}>
              <input id="reg-add-path" className={`${inputCls} font-mono`} spellCheck={false} autoComplete="off" value={path} onChange={(e) => setPath(e.target.value)}
                placeholder="HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Agent" aria-invalid={!!pathErr} />
            </Field>
            {overlaps.length > 0 && (
              <Banner tone="warn">May overlap with {overlaps.map((o, i) => <span key={o.entryKey}>{i > 0 && ', '}<RegText value={o.entryKey} mono /></span>)}. Identical patterns are merged; other overlapping patterns make the resolution fail (the server decides).</Banner>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <ChipInput id="reg-add-values" label="Value allow-list" values={values} onChange={setValues} validate={validateValueName} max={limits?.valuesMax ?? 64} placeholder="(Default)" hint="Empty = all values (and subkey rows)." />
              <ChipInput id="reg-add-ignore" label="Ignore values" values={ignoreValues} onChange={setIgnoreValues} validate={validateValueName} max={limits?.ignoreValuesMax ?? 64} strike />
            </div>
            <ChipInput id="reg-add-exkeys" label="Exclude subkeys" values={excludeKeys} onChange={setExcludeKeys} strike max={limits?.excludeKeysMax ?? 32}
              validate={(v) => validateRegKeyPattern(v, { allowRecursive: isSuperAdmin, what: 'Excluded subkey' })} hint="Full key patterns inside the key above." />
            {listErr && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{listErr}</p>}
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Label (required)" htmlFor="reg-add-label"><input id="reg-add-label" className={inputCls} maxLength={120} value={label} onChange={(e) => setLabel(e.target.value)} /></Field>
              <Field label="Severity" htmlFor="reg-add-sev"><Dropdown aria-label="Severity" value={severity} onChange={(v) => setSeverity(v as FimSeverity)} options={SEVERITIES.map((s) => ({ value: s, label: s }))} /></Field>
              <Field label="Category" htmlFor="reg-add-cat"><Dropdown aria-label="Category" value={category} onChange={setCategory} options={CATEGORIES.map((c) => ({ value: c, label: c }))} /></Field>
            </div>
            {measureHosts.length > 0 ? (
              <MeasurePanel hosts={measureHosts} entry={customSpec} signature={signature} limits={limits} disabled={!path || !!pathErr || !!listErr} onResult={setMeasure} />
            ) : <p className="text-xs text-slate-500">No node to measure on in this scope.</p>}
            {!measured && (
              isSuperAdmin ? (
                <div className="space-y-2 rounded-lg border border-amber-200 p-3 dark:border-amber-500/30">
                  <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={override} onChange={(e) => setOverride(e.target.checked)} />
                    <span>Add without a measurement (measureOverride)<span className="block text-xs text-slate-500">Super Admin only. The size is unknown until the first scan; a pattern that is too large can be dropped by osquery.</span></span></label>
                  {override && <NoteField id="reg-add-override" value={overrideReason} onChange={setOverrideReason} minLength={3} label="Override reason (required)" />}
                </div>
              ) : <p className="text-xs text-amber-700 dark:text-amber-300">Custom keys must be measured on a node before they can be added.</p>
            )}
          </div>
        )}
        <NoteField id="reg-add-reason" value={reason} onChange={setReason} minLength={3} label="Reason (required)" hint="Stored with the rule in the audit trail." />
      </div>
    </FimModal>
  );
}
