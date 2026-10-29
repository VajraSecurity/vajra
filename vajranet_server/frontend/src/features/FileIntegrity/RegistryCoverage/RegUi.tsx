import { useState, type KeyboardEvent, type ReactNode } from 'react';
import { Lock, Radio, ShieldAlert, X } from 'lucide-react';
import type { FimRegEstimate, FimRegSourceBadge, FimRegStatus, FimRegTier } from '../../../api/services/fimApi';
import { inputCls } from '../styles';
import { Field } from '../ui';
import { safeText, fmtBytes, fmtCount } from './safeText';
import { HISTORY_UNKEYED_TEXT, STATUS_META, TIER_LABEL, sourceLabel } from './regModel';

export { RegText } from '../UntrustedText';

/** `stale`: the last refresh failed, so the status may be out of date (rendered greyed out). */
export function StatusChip({ status, needsInit, stale }: { status: FimRegStatus; needsInit?: number; stale?: boolean }) {
  const m = STATUS_META[status] ?? STATUS_META.unmanaged;
  const label = status === 'needs_init' && needsInit ? `${m.label} (${needsInit})` : m.label;
  if (stale) {
    return <span title={`${m.hint} The last refresh failed: this status may be out of date.`} className="inline-flex whitespace-nowrap rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-400 line-through decoration-slate-300 dark:bg-white/5 dark:text-slate-500">{label} (may be out of date)</span>;
  }
  return <span title={m.hint} className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold ${m.cls}`}>{label}</span>;
}

export function RealtimeChip({ available }: { available: boolean }) {
  return (
    <span
      title={available
        ? 'win_registry_events were received from this host in the last 24 h (plgx agent). Real-time raises early drift with process and user; scheduled scans remain the source of truth.'
        : 'No win_registry_events from this host in the last 24 h. Real-time registry events need the plgx agent; stock osquery only scans on schedule. Scans are the source of truth either way.'}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold ${available ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300' : 'bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-300'}`}
    >
      <Radio aria-hidden className="h-3 w-3" />{available ? 'Real-time available' : 'No real-time'}
    </span>
  );
}

export function TierBadge({ tier, suffix }: { tier: FimRegTier; suffix?: string }) {
  return <span className="inline-flex whitespace-nowrap rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-semibold text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300">{TIER_LABEL[tier] ?? tier}{suffix ? ` · ${suffix}` : ''}</span>;
}

const SOURCE_CLS: Record<string, string> = {
  builtin: 'bg-slate-100 text-slate-700 dark:bg-white/10 dark:text-slate-300',
  profile: 'bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300',
  group: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-500/15 dark:text-cyan-300',
  node: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300',
  merge: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
  carve: 'bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300',
};

export function SourceBadges({ sources }: { sources: FimRegSourceBadge[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {sources.map((s, i) => {
        const l = sourceLabel(s);
        return <span key={i} title={safeText(l.title)} className={`whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-semibold ${SOURCE_CLS[s.layer] ?? SOURCE_CLS.builtin}`}>{l.label}</span>;
      })}
    </span>
  );
}

export function AttackChips({ ids }: { ids: string[] }) {
  if (!ids.length) return <span className="text-xs text-slate-400">-</span>;
  return <span className="flex flex-wrap gap-1">{ids.map((a) => <span key={a} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-white/10 dark:text-slate-300">{safeText(a)}</span>)}</span>;
}

export function ValuesFilter({ values, ignoreValues, excludeKeys }: { values: string[]; ignoreValues: string[]; excludeKeys?: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {values.length === 0 ? <span className="text-xs italic text-slate-500">all values</span>
        : values.map((v) => <span key={`a-${v}`} className="rounded bg-emerald-50 px-1.5 py-0.5 font-mono text-[10px] text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300">{safeText(v)}</span>)}
      {ignoreValues.map((v) => <span key={`d-${v}`} title="Ignored value (deny-list)" className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 line-through dark:bg-white/10">{safeText(v)}</span>)}
      {(excludeKeys ?? []).map((k) => <span key={`k-${k}`} title="Excluded subkey" className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 line-through dark:bg-white/10">{safeText(k)}\</span>)}
    </span>
  );
}

const BASIS_CLS: Record<string, string> = { measured: 'text-emerald-600 dark:text-emerald-400', estimated: 'text-amber-600 dark:text-amber-400', unknown: 'text-slate-400' };
export function EstimateCell({ estimate }: { estimate: FimRegEstimate }) {
  return (
    <span className="whitespace-nowrap text-xs tabular-nums">
      {fmtCount(estimate.rows)} rows / {fmtBytes(estimate.bytes)}
      <span className={`ml-1 text-[10px] font-semibold ${BASIS_CLS[estimate.basis] ?? BASIS_CLS.unknown}`}>{estimate.basis}</span>
    </span>
  );
}

export function ProtectedLock() {
  return (
    <span title="Protected entry: disabling, narrowing, excluding or lowering its severity needs a waiver approved by a different Super Admin.">
      <Lock aria-label="Protected" className="h-3.5 w-3.5 text-amber-600" />
    </span>
  );
}

/**
 * Chip list input: Enter or comma adds a chip (validated), Backspace on an empty field removes the
 * last chip. `strike` renders chips struck through (deny-lists).
 */
export function ChipInput({ id, label, values, onChange, validate, max, placeholder, strike, hint, disabled }: {
  id: string; label: string; values: string[]; onChange: (v: string[]) => void; validate: (v: string) => string | null;
  max: number; placeholder?: string; strike?: boolean; hint?: string; disabled?: boolean;
}) {
  const [draft, setDraft] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const add = () => {
    const v = draft;
    if (v.trim() === '') return;
    const e = validate(v);
    if (e) { setErr(e); return; }
    if (values.length >= max) { setErr(`At most ${max}`); return; }
    if (values.some((x) => x.toLowerCase() === v.toLowerCase())) { setErr('Already listed (names are case-insensitive)'); return; }
    onChange([...values, v]); setDraft(''); setErr(null);
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { e.preventDefault(); add(); }
    else if (e.key === 'Backspace' && draft === '' && values.length) onChange(values.slice(0, -1));
  };
  return (
    <Field label={`${label} (${values.length}/${max})`} htmlFor={id} hint={hint ?? 'Press Enter to add.'} error={err}>
      <div className="flex flex-wrap gap-1 rounded-lg border border-slate-200 p-1.5 dark:border-white/10">
        {values.map((v, i) => (
          <span key={`${v}-${i}`} className={`inline-flex items-center gap-1 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs dark:bg-white/10 ${strike ? 'line-through text-slate-500' : ''}`}>
            {safeText(v)}
            {!disabled && <button type="button" aria-label={`Remove ${safeText(v)}`} onClick={() => onChange(values.filter((_, j) => j !== i))} className="rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"><X className="h-3 w-3" /></button>}
          </span>
        ))}
        <input id={id} disabled={disabled} value={draft} placeholder={placeholder} onChange={(e) => { setDraft(e.target.value); setErr(null); }} onKeyDown={onKey} onBlur={add}
          className="min-w-[10rem] flex-1 bg-transparent px-1 py-0.5 text-sm text-slate-700 outline-none dark:text-slate-200" />
      </div>
    </Field>
  );
}

export function NoteField({ id, value, onChange, label = 'Note (required)', hint, minLength = 1, maxLength, rows = 2 }: {
  id: string; value: string; onChange: (v: string) => void; label?: string; hint?: string; minLength?: number; maxLength?: number; rows?: number;
}) {
  const short = value.trim().length > 0 && value.trim().length < minLength;
  const long = maxLength !== undefined && value.trim().length > maxLength;
  return (
    <Field label={label} htmlFor={id} hint={hint} error={short ? `At least ${minLength} characters` : long ? `At most ${maxLength} characters` : null}>
      <textarea id={id} rows={rows} className={inputCls} value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

export function Banner({ tone, children }: { tone: 'warn' | 'error' | 'info'; children: ReactNode }) {
  const cls = tone === 'error' ? 'bg-red-50 text-red-800 dark:bg-red-500/10 dark:text-red-300'
    : tone === 'warn' ? 'bg-amber-50 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200'
      : 'bg-blue-50 text-blue-900 dark:bg-blue-500/10 dark:text-blue-200';
  return <div role={tone === 'error' ? 'alert' : undefined} className={`rounded-lg px-3 py-2 text-sm ${cls}`}>{children}</div>;
}

/** Prominent health warning: the registry history hash chain is not keyed (weaker tamper evidence). */
export function HistoryKeyWarning({ detail }: { detail?: ReactNode }) {
  return (
    <div role="alert" data-testid="fim-history-unkeyed" className="flex items-start gap-2 rounded-lg border-2 border-red-400 bg-red-50 px-3 py-2 text-sm font-semibold text-red-800 dark:border-red-500/60 dark:bg-red-500/15 dark:text-red-200">
      <ShieldAlert aria-hidden className="mt-0.5 h-5 w-5 shrink-0" />
      <span>{HISTORY_UNKEYED_TEXT}{detail ? <span className="block text-xs font-normal">{detail}</span> : null}</span>
    </div>
  );
}
