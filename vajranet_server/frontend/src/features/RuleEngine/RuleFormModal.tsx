import { useMemo, useState } from 'react';
import { Plus, Trash2, CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { Modal, Dropdown, TagInput, SegmentedControl, RawJsonView, ErrorBanner, SeverityBadge } from './ui';
import { EVENT_TYPES, OPERATORS, OPERATOR_LABELS, OPERATORS_WITHOUT_VALUE, SEVERITY_DEFAULT_LEVEL } from './constants';
import type { NewDetectionRule, RuleCondition, ValidateResult } from '../../api/services/ruleEngineApi';
import { createRule, validateRule } from '../../api/api';

interface RuleFormModalProps {
  onClose: () => void;
  onCreated: () => void;
  /** Pre-fills the form, e.g. from an AI `propose_rule` chat card's "Load into builder" action. Still requires a human to edit/Validate/Save — never auto-saved. */
  initialRule?: Partial<NewDetectionRule> | null;
  /** Suggestions for the groups/mitre tag inputs, sourced from already-loaded rules (a low-effort autocomplete per the spec — "a hardcoded full MITRE ATT&CK list is a nice-to-have, not required"). */
  groupSuggestions?: string[];
  mitreSuggestions?: string[];
}

function emptyCondition(): RuleCondition {
  return { field: '', op: 'equals', value: '', icase: false };
}

export default function RuleFormModal({ onClose, onCreated, initialRule, groupSuggestions = [], mitreSuggestions = [] }: RuleFormModalProps) {
  const [view, setView] = useState<'guided' | 'raw'>('guided');
  const [eventType, setEventType] = useState(initialRule?.event_type ?? '');
  const [level, setLevel] = useState(initialRule?.level ?? SEVERITY_DEFAULT_LEVEL.medium);
  const [description, setDescription] = useState(initialRule?.description ?? '');
  const [groups, setGroups] = useState<string[]>(initialRule?.groups ?? []);
  const [mitre, setMitre] = useState<string[]>(initialRule?.mitre ?? []);
  const [conditions, setConditions] = useState<RuleCondition[]>(
    initialRule?.conditions && initialRule.conditions.length > 0 ? initialRule.conditions : [emptyCondition()],
  );
  const [idOverride, setIdOverride] = useState<string>(initialRule?.id !== undefined ? String(initialRule.id) : '');

  const [rawText, setRawText] = useState(() => JSON.stringify(initialRule ?? { event_type: '', level: 5, description: '', groups: [], mitre: [], conditions: [emptyCondition()] }, null, 2));
  const [rawError, setRawError] = useState<string | null>(null);

  const [validating, setValidating] = useState(false);
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  // The exact JSON string that was last successfully validated. Save is
  // gated on the CURRENT payload still matching this, not just on
  // `validation.ok` being true — otherwise editing a field after a
  // successful Validate would let a stale "ok" carry over to Save, which
  // would defeat the whole "engine validates before it's ever accepted"
  // guarantee this modal exists to enforce.
  const [validatedSnapshot, setValidatedSnapshot] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const guidedRule: NewDetectionRule = useMemo(() => ({
    ...(idOverride.trim() ? { id: /^\d+$/.test(idOverride.trim()) ? Number(idOverride.trim()) : idOverride.trim() } : {}),
    event_type: eventType,
    level,
    description,
    groups,
    mitre,
    conditions: conditions
      .filter((c) => c.field.trim())
      .map((c) => (OPERATORS_WITHOUT_VALUE.has(c.op) ? { field: c.field, op: c.op, icase: c.icase } : c)),
  }), [idOverride, eventType, level, description, groups, mitre, conditions]);

  const currentPayload = (): NewDetectionRule | null => {
    if (view === 'guided') return guidedRule;
    try {
      const parsed = JSON.parse(rawText);
      setRawError(null);
      return parsed;
    } catch (e) {
      setRawError(e instanceof Error ? e.message : 'Invalid JSON');
      return null;
    }
  };

  const handleValidate = async () => {
    const payload = currentPayload();
    if (!payload) return;
    if (view === 'guided' && !idOverride.trim()) {
      setValidation({ ok: false, message: 'Rule ID is required — the engine has no auto-assign, despite what this form used to claim.' });
      return;
    }
    const snapshot = JSON.stringify(payload);
    setValidating(true);
    setValidation(null);
    setValidatedSnapshot(null);
    try {
      const result = await validateRule(payload);
      setValidation(result);
      if (result.ok) setValidatedSnapshot(snapshot);
    } catch (err) {
      setValidation({ ok: false, message: err instanceof Error ? err.message : 'Validation request failed' });
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async () => {
    const payload = currentPayload();
    if (!payload) return;
    if (JSON.stringify(payload) !== validatedSnapshot) {
      setSaveError('The rule changed since it was last validated — click Validate again before saving.');
      return;
    }
    setSaving(true);
    setSaveError(null);
    try {
      await createRule(payload);
      onCreated();
      onClose();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const updateCondition = (idx: number, patch: Partial<RuleCondition>) => {
    setConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, ...patch } : c)));
  };

  return (
    <Modal title="Add Detection Rule" onClose={onClose} wide>
      <div className="flex items-center justify-between mb-4">
        <SegmentedControl
          value={view}
          onChange={(next) => {
            // One-way sync guided -> raw on switching tabs, so "Raw JSON"
            // always reflects exactly what the guided form currently holds
            // (same underlying JSON, two views onto it — never two data
            // models that can drift apart).
            if (next === 'raw' && view === 'guided') setRawText(JSON.stringify(guidedRule, null, 2));
            setView(next);
          }}
          size="sm"
          options={[{ value: 'guided', label: 'Guided Form' }, { value: 'raw', label: 'Raw JSON' }]}
        />
        <SeverityBadge level={view === 'guided' ? level : 0} />
      </div>

      {view === 'guided' ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
                Event Type <span className="text-red-500">*</span>
              </label>
              <Dropdown
                value={eventType}
                onChange={setEventType}
                placeholder="Select event type…"
                options={EVENT_TYPES.map((t) => ({ value: t, label: t }))}
                aria-label="Event type"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
                Level (0–15+) — bucket shown live
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="number"
                  min={0}
                  max={20}
                  value={level}
                  onChange={(e) => setLevel(Number(e.target.value))}
                  className="w-24 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                />
                <SeverityBadge level={level} />
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
              Description <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What does this rule detect?"
              className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Groups</label>
              <TagInput values={groups} onChange={setGroups} suggestions={groupSuggestions} placeholder="e.g. defense-evasion" />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">MITRE ATT&amp;CK</label>
              <TagInput values={mitre} onChange={setMitre} suggestions={mitreSuggestions} placeholder="e.g. T1140" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
              Rule ID <span className="text-red-500">*</span>{' '}
              <span className="font-normal normal-case text-slate-400">(numeric, must not already exist — the engine has no auto-assign)</span>
            </label>
            <input
              type="text"
              value={idOverride}
              onChange={(e) => setIdOverride(e.target.value)}
              placeholder="e.g. 900001"
              className="w-48 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                Conditions (AND — the engine has no OR primitive; add branch rules for OR logic)
              </label>
              <button
                type="button"
                onClick={() => setConditions((prev) => [...prev, emptyCondition()])}
                className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline"
              >
                <Plus className="h-3.5 w-3.5" /> Add condition
              </button>
            </div>
            <div className="space-y-2">
              {conditions.map((c, idx) => (
                <div key={idx} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 dark:border-white/10 p-2.5">
                  <input
                    type="text"
                    value={c.field}
                    onChange={(e) => updateCondition(idx, { field: e.target.value })}
                    placeholder="field, e.g. process.command_line"
                    className="min-w-[180px] flex-1 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                  />
                  <Dropdown
                    value={c.op}
                    onChange={(v) => updateCondition(idx, { op: v as RuleCondition['op'] })}
                    options={OPERATORS.map((op) => ({ value: op, label: OPERATOR_LABELS[op] ?? op }))}
                    className="w-56 shrink-0"
                    aria-label="Operator"
                  />
                  {!OPERATORS_WITHOUT_VALUE.has(c.op) && (
                    <input
                      type="text"
                      value={c.value ?? ''}
                      onChange={(e) => updateCondition(idx, { value: e.target.value })}
                      placeholder={c.op === 'between' ? 'min,max' : 'value'}
                      className="min-w-[140px] flex-1 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                    />
                  )}
                  <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 shrink-0">
                    <input
                      type="checkbox"
                      checked={!!c.icase}
                      onChange={(e) => updateCondition(idx, { icase: e.target.checked })}
                      className="accent-indigo-600"
                    />
                    icase
                  </label>
                  <button
                    type="button"
                    onClick={() => setConditions((prev) => prev.filter((_, i) => i !== idx))}
                    disabled={conditions.length === 1}
                    aria-label="Remove condition"
                    className="text-slate-400 hover:text-red-500 disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Preview (what will be sent)</p>
            <RawJsonView value={guidedRule} />
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            rows={16}
            spellCheck={false}
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-black/30 p-3 font-mono text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          />
          {rawError && <ErrorBanner message={`Invalid JSON: ${rawError}`} />}
        </div>
      )}

      <div className="mt-5 flex items-center justify-between border-t border-slate-200 dark:border-white/10 pt-4">
        <div className="flex-1 min-w-0">
          {validation && (
            validation.ok ? (
              <div className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span className="truncate">{validation.message || 'Valid — the real engine accepted this rule.'}</span>
                {validation.warnings && validation.warnings.length > 0 && (
                  <span className="text-amber-600 dark:text-amber-400">({validation.warnings.join('; ')})</span>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                <XCircle className="h-4 w-4 shrink-0" />
                <span className="truncate">{validation.message}</span>
              </div>
            )
          )}
          {saveError && <ErrorBanner message={saveError} />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleValidate}
            disabled={validating}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-white/10 px-4 py-2 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-white/5 disabled:opacity-50"
          >
            {validating && <Loader2 className="h-4 w-4 animate-spin" />}
            Validate
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !validatedSnapshot}
            title={!validatedSnapshot ? 'Validate successfully before saving' : undefined}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 disabled:pointer-events-none"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            Save Rule
          </button>
        </div>
      </div>
      <p className="mt-2 text-[11px] text-slate-400 dark:text-slate-500">Save is disabled until Validate returns ok — the same "engine validates before it's ever accepted" flow the console enforces server-side.</p>
    </Modal>
  );
}
