import { useState, type ReactNode, type KeyboardEvent } from 'react';
import { X, ChevronDown, PlayCircle, PauseCircle } from 'lucide-react';

/**
 * Local, self-contained themed primitives for the Rule Engine feature —
 * mirrors `features/DomainReputation/ui.tsx`'s role (small styled wrappers
 * kept local to the feature) but built on plain elements + Tailwind `dark:`
 * variants rather than @base-ui/react, so every one of them respects
 * `ThemeContext`/`useTheme`'s light/dark toggle (the `.dark` class on
 * `<html>`) the same way the rest of this app's `dark:`-variant screens do
 * (see e.g. `features/Alerts/UnmanagedHostsAlertDetails.tsx`) — no new/
 * separate color system, no dark-mode gap.
 */

// ── Dropdown (native <select>, styled) — real single-choice dropdown ─────

interface DropdownOption {
  value: string;
  label: string;
}

interface DropdownProps {
  value: string;
  onChange: (value: string) => void;
  options: DropdownOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  'aria-label'?: string;
}

export function Dropdown({ value, onChange, options, placeholder, disabled, className = '', ...rest }: DropdownProps) {
  return (
    <div className={`relative ${className}`}>
      <select
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        aria-label={rest['aria-label']}
        className="w-full appearance-none rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 pr-8 text-sm font-medium text-slate-700 dark:text-slate-200 shadow-sm transition-colors hover:border-slate-300 dark:hover:border-white/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 dark:focus-visible:ring-indigo-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {placeholder && <option value="">{placeholder}</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
    </div>
  );
}

// ── Multi-select checkboxes — real checkbox list, not comma-separated text ─

interface CheckboxMultiSelectProps {
  values: string[];
  onChange: (values: string[]) => void;
  options: DropdownOption[];
  columns?: 1 | 2 | 3;
  disabled?: boolean;
}

export function CheckboxMultiSelect({ values, onChange, options, columns = 2, disabled }: CheckboxMultiSelectProps) {
  const toggle = (v: string) => {
    onChange(values.includes(v) ? values.filter((x) => x !== v) : [...values, v]);
  };
  const gridCols = columns === 1 ? 'grid-cols-1' : columns === 3 ? 'grid-cols-3' : 'grid-cols-2';
  return (
    <div className={`grid ${gridCols} gap-1.5`}>
      {options.map((o) => (
        <label
          key={o.value}
          className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-sm transition-colors select-none ${
            disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'
          } ${
            values.includes(o.value)
              ? 'border-indigo-300 dark:border-indigo-500/50 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300'
              : 'border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-white/20'
          }`}
        >
          <input
            type="checkbox"
            checked={values.includes(o.value)}
            disabled={disabled}
            onChange={() => toggle(o.value)}
            className="h-3.5 w-3.5 rounded border-slate-300 dark:border-white/20 accent-indigo-600"
          />
          <span className="truncate">{o.label}</span>
        </label>
      ))}
    </div>
  );
}

// ── Tag input — free-form multi-value (groups / mitre), Enter or comma adds ─

interface TagInputProps {
  values: string[];
  onChange: (values: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
}

export function TagInput({ values, onChange, suggestions = [], placeholder }: TagInputProps) {
  const [draft, setDraft] = useState('');
  const listId = `tag-input-suggestions-${placeholder?.replace(/\s+/g, '-') ?? 'x'}`;

  const commit = (raw: string) => {
    const v = raw.trim();
    if (!v || values.includes(v)) { setDraft(''); return; }
    onChange([...values, v]);
    setDraft('');
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      commit(draft);
    } else if (e.key === 'Backspace' && !draft && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-2 py-1.5 focus-within:ring-2 focus-within:ring-indigo-300 dark:focus-within:ring-indigo-500/50">
      {values.map((v) => (
        <span
          key={v}
          className="inline-flex items-center gap-1 rounded-md bg-indigo-50 dark:bg-indigo-500/15 px-2 py-0.5 text-xs font-medium text-indigo-700 dark:text-indigo-300"
        >
          {v}
          <button type="button" onClick={() => onChange(values.filter((x) => x !== v))} aria-label={`Remove ${v}`}>
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <input
        type="text"
        list={listId}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={() => commit(draft)}
        placeholder={values.length === 0 ? placeholder : ''}
        className="min-w-[100px] flex-1 bg-transparent text-sm text-slate-700 dark:text-slate-200 outline-none placeholder:text-slate-400"
      />
      <datalist id={listId}>
        {suggestions.filter((s) => !values.includes(s)).map((s) => <option key={s} value={s} />)}
      </datalist>
    </div>
  );
}

// ── Severity badge — shows the level number + its live bucket (low/medium/high/critical) ─

export function SeverityBadge({ level }: { level: number }) {
  const bucket = level >= 12 ? { label: 'critical', color: '#dc2626' }
    : level >= 8 ? { label: 'high', color: '#ea580c' }
    : level >= 4 ? { label: 'medium', color: '#d97706' }
    : { label: 'low', color: '#64748b' };
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold"
      style={{ background: `${bucket.color}1a`, color: bucket.color }}
    >
      {level} · {bucket.label}
    </span>
  );
}

// ── Status toggle — fixed-width Enabled/Disabled pill button ────────────────
//
// "Enabled" and "Disabled" are different lengths; an inline-flex pill sized
// only by its own padding (the pattern every other status pill in this app
// also uses, e.g. NodesView's presence badges) visibly changes width when
// toggled, which shifts every column to its right in a plain <table> (no
// fixed table-layout). Fixed width + centered content keeps the column
// stable across a toggle, without touching the wider app-wide pattern.
export function StatusToggle({ enabled, busy, onToggle }: { enabled: boolean; busy?: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      disabled={busy}
      className={`inline-flex w-[92px] items-center justify-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold transition-colors disabled:opacity-50 ${
        enabled ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' : 'bg-slate-100 dark:bg-white/10 text-slate-500 dark:text-slate-400'
      }`}
    >
      {enabled ? <PlayCircle className="h-3 w-3" /> : <PauseCircle className="h-3 w-3" />}
      {enabled ? 'Enabled' : 'Disabled'}
    </button>
  );
}

// ── Segmented control (tab switcher) — plain version, no motion dependency ──

interface SegmentedControlProps<T extends string> {
  options: { value: T; label: ReactNode }[];
  value: T;
  onChange: (value: T) => void;
  size?: 'sm' | 'md';
}

export function SegmentedControl<T extends string>({ options, value, onChange, size = 'md' }: SegmentedControlProps<T>) {
  return (
    <div className="inline-flex items-center gap-0.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-100/70 dark:bg-white/5 p-1">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={`rounded-lg font-semibold transition-colors ${size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2 text-sm'} ${
            value === opt.value
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// ── Modal shell ───────────────────────────────────────────────────────────

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className={`w-full ${wide ? 'max-w-4xl' : 'max-w-lg'} max-h-[90vh] flex flex-col rounded-2xl bg-white dark:bg-slate-900 shadow-xl border border-slate-200 dark:border-white/10`}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-white/10 shrink-0">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

// ── Raw JSON view — plain-text pre block. React text nodes are escaped by
// default (no dangerouslySetInnerHTML anywhere here), so this is safe to
// render for engine-returned or AI-proposed JSON without any sanitizer —
// same discipline this app applies elsewhere (dompurify is reserved for the
// few places that render actual HTML, e.g.
// features/VulnerabilityScanner/BurpsuiteScanDetail.tsx; plain JSON text is
// never HTML). ──────────────────────────────────────────────────────────

export function RawJsonView({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return (
    <pre className="max-h-96 overflow-auto rounded-lg bg-slate-50 dark:bg-black/30 border border-slate-200 dark:border-white/10 p-3 text-xs font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-words">
      {text}
    </pre>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg bg-red-50 dark:bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
      <span>{message}</span>
      {onRetry && (
        <button onClick={onRetry} className="font-semibold underline shrink-0">Try again</button>
      )}
    </div>
  );
}
