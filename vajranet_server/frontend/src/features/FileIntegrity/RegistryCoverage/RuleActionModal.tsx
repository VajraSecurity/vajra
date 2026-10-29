import { useState } from 'react';
import type { FimRegEntry, FimRegLayer, FimRegLimits, FimRegWaiver, FimSeverity } from '../../../api/services/fimApi';
import { SEVERITIES, errMsg } from '../constants';
import { Dropdown, ErrorBanner, Field, FimModal, SeverityBadge } from '../ui';
import { btnGhost, btnPrimary } from '../styles';
import { ChipInput, NoteField, ProtectedLock, RegText } from './RegUi';
import { safeText } from './safeText';
import WaiverRequestModal from './WaiverRequestModal';
import { WAIVER_FLOW_TEXT, draftSummary, sevRank, waiverNeeded, waiverRuleOf, type RowAction, type RuleDraft, type WaiverDraft } from './regModel';
import { validateExcludeKeys, validateRegKeyPattern, validateValueList, validateValueName } from './regValidation';

const sameList = (x: string[], y: string[]) => x.length === y.length && x.every((v) => y.some((w) => w.toLowerCase() === v.toLowerCase()));

const TITLE: Record<RowAction, string> = { severity: 'Change severity', filter: 'Narrow values', exclude: 'Exclude value or subkey', disable: 'Disable entry' };

/**
 * Builds one rule (severity / filter / exclude / disable) for an entry. Raising severity and widening
 * are free. A reduction of a protected entry needs a waiver bound to this exact rule:
 *  - waiverMode 'collect' (node view): the waiver form data goes into the pending change via
 *    onSubmit(draft, waiver) and is requested on Apply;
 *  - waiverMode 'submit' (group / profile): the waiver is requested now and onWaiverRequested(w)
 *    is called; the rule itself is created later from the approved waiver.
 */
export default function RuleActionModal({ entry, action, layer, scopeValue, limits, allowRecursive, submitLabel, onSubmit, onClose, waiverMode, onWaiverRequested }: {
  entry: FimRegEntry; action: RowAction; layer: FimRegLayer; scopeValue: string; limits?: FimRegLimits | null; allowRecursive: boolean;
  submitLabel: string; onSubmit: (d: RuleDraft, waiver?: WaiverDraft) => Promise<void>; onClose: () => void;
  waiverMode: 'collect' | 'submit'; onWaiverRequested?: (w: FimRegWaiver) => Promise<void> | void;
}) {
  const [severity, setSeverity] = useState<FimSeverity>(entry.severity);
  const [values, setValues] = useState<string[]>(entry.values);
  const [ignoreValues, setIgnoreValues] = useState<string[]>([]);
  const [excludeKeys, setExcludeKeys] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [waiverFor, setWaiverFor] = useState<{ draft: RuleDraft; action: NonNullable<ReturnType<typeof waiverNeeded>> } | null>(null);

  const valuesMax = limits?.valuesMax ?? 64;
  const ignoreMax = limits?.ignoreValuesMax ?? 64;
  const exclMax = limits?.excludeKeysMax ?? 32;

  const spec: Record<string, unknown> =
    action === 'severity' ? { severity }
      : action === 'filter' ? { values }
        : action === 'exclude' ? { ...(ignoreValues.length ? { ignoreValues } : {}), ...(excludeKeys.length ? { excludeKeys } : {}) }
          : {};
  const op = action;
  const formErr =
    action === 'severity' ? (severity === entry.severity ? 'Choose a different severity' : null)
      : action === 'filter' ? (sameList(values, entry.values) ? 'The allow-list is unchanged' : validateValueList(values, valuesMax, 'values'))
        : action === 'exclude' ? (ignoreValues.length + excludeKeys.length === 0 ? 'Add at least one value or subkey to exclude'
          : validateValueList(ignoreValues, ignoreMax, 'ignored values') ?? validateExcludeKeys(excludeKeys, entry.path, exclMax, allowRecursive))
          : null;
  const reasonOk = reason.trim().length >= 3;
  const need = waiverNeeded(entry, op, spec);

  const submit = async () => {
    const draft: RuleDraft = { op, target: entry.entryKey, spec, reason: reason.trim() };
    if (need) { setWaiverFor({ draft, action: need }); return; }
    setBusy(true); setErr(null);
    try { await onSubmit(draft); } catch (e) { setErr(errMsg(e, 'Could not create the rule')); } finally { setBusy(false); }
  };

  if (waiverFor) {
    return (
      <WaiverRequestModal entryKey={entry.entryKey} entryPath={entry.path} action={waiverFor.action} scopeType={layer} scopeValue={scopeValue}
        changeText={draftSummary(waiverFor.draft)} maxDays={limits?.waiverMaxDays} rule={waiverRuleOf(waiverFor.draft)} mode={waiverMode}
        onClose={onClose}
        onCollected={async (wd) => { await onSubmit(waiverFor.draft, wd); }}
        onCreated={async (w) => { await onWaiverRequested?.(w); }} />
    );
  }

  return (
    <FimModal title={TITLE[action]} onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>Cancel</button>
        <button className={btnPrimary} disabled={busy || !!formErr || !reasonOk} onClick={submit}>{busy ? 'Working...' : need ? 'Continue to waiver request' : submitLabel}</button></>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        <div className="rounded-lg bg-slate-50 p-3 text-sm dark:bg-white/5">
          <p className="flex items-center gap-2 font-semibold">{entry.protected && <ProtectedLock />}<RegText value={entry.label || entry.entryKey} /></p>
          <RegText value={entry.path} mono className="text-xs text-slate-500" />
        </div>
        {action === 'severity' && (
          <Field label="New severity" htmlFor="reg-act-sev" hint={entry.protected ? 'Raising is free. Lowering a protected entry needs a waiver.' : undefined}>
            <div className="flex items-center gap-2">
              <Dropdown aria-label="New severity" value={severity} onChange={(v) => setSeverity(v as FimSeverity)} options={SEVERITIES.map((s) => ({ value: s, label: s }))} className="w-48" />
              <span className="text-xs text-slate-500">current</span> <SeverityBadge severity={entry.severity} />
              {severity !== entry.severity && <span className="text-xs text-slate-500">{sevRank(severity) > sevRank(entry.severity) ? 'raise' : 'lower'}</span>}
            </div>
          </Field>
        )}
        {action === 'filter' && (
          <ChipInput id="reg-act-values" label="Value allow-list" values={values} onChange={setValues} validate={validateValueName} max={valuesMax}
            placeholder="e.g. Shell" hint="Only these value names are scanned (case-insensitive). Empty = all values. Replaces the current allow-list." />
        )}
        {action === 'exclude' && (
          <>
            <ChipInput id="reg-act-ignore" label="Ignore values (deny-list)" values={ignoreValues} onChange={setIgnoreValues} validate={validateValueName} max={ignoreMax} strike placeholder="e.g. LastUsedUsername" />
            <ChipInput id="reg-act-exkeys" label="Exclude subkeys" values={excludeKeys} onChange={setExcludeKeys}
              validate={(v) => validateRegKeyPattern(v, { allowRecursive, what: 'Excluded subkey' })} max={exclMax} strike
              placeholder={`${safeText(entry.path)}\\...`} hint="Full key pattern inside this entry. Exclusions accumulate across layers; only the layer that added one can remove it." />
          </>
        )}
        {action === 'disable' && (
          <p className="text-sm text-slate-600 dark:text-slate-300">The entry is dropped from this scope. Its baseline rows are soft-retired for 7 days and open drift on it is closed as ignored after the next Apply. A more specific layer can add it back.</p>
        )}
        {formErr && (action !== 'severity' || severity !== entry.severity) && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{formErr}</p>}
        <NoteField id="reg-act-reason" value={reason} onChange={setReason} minLength={3} label="Reason (required)" hint="Stored with the rule in the audit trail." />
        {need && <p className="text-xs text-amber-700 dark:text-amber-300">This reduces a protected entry: the next step is a waiver request (two-person rule){waiverMode === 'collect' ? ', sent when you click Apply' : ''}. {WAIVER_FLOW_TEXT}</p>}
      </div>
    </FimModal>
  );
}
