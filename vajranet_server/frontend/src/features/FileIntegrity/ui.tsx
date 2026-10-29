import type { ReactNode } from 'react';
import { X } from 'lucide-react';
import type { FimChangeType, FimSeverity } from '../../api/services/fimApi';
import { useModalA11y } from '../../hooks/useModalA11y';
import { CHANGE_LABEL, KIND_LABEL, SEVERITY_COLOR } from './constants';
import { safeText } from './safeText';

export { Dropdown, SegmentedControl } from '../RuleEngine/ui';

/**
 * Load / action error. The message (often server text) is rendered through safeText. `stale`: data
 * from an earlier successful load is still on screen, so it is labelled as possibly out of date.
 */
export function ErrorBanner({ message, onRetry, stale }: { message: string; onRetry?: () => void; stale?: boolean }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-lg bg-red-50 dark:bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
      <span className="min-w-0 break-words">
        {stale && <b>The last refresh failed: the data shown may be out of date. </b>}
        {safeText(message)}
      </span>
      {onRetry && (
        <button onClick={onRetry} className="font-semibold underline shrink-0">Retry</button>
      )}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: FimSeverity }) {
  const color = SEVERITY_COLOR[severity] ?? '#64748b';
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold capitalize" style={{ background: `${color}1a`, color }}>
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {safeText(severity)}
    </span>
  );
}

export function ChangeBadge({ type }: { type: FimChangeType }) {
  const c = CHANGE_LABEL[type] ?? { label: safeText(type), color: '#64748b', hint: '' };
  return (
    <span title={c.hint} className="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold" style={{ background: `${c.color}1a`, color: c.color }}>
      {c.label}
    </span>
  );
}

const KIND_COLOR: Record<string, string> = { file: '#64748b', directory: '#0891b2', item: '#7c3aed', path: '#64748b', xattr: '#0891b2', registry: '#b45309', acl: '#be123c', table: '#7c3aed' };
export function KindBadge({ kind }: { kind?: string | null }) {
  const k = kind ?? 'file';
  const color = KIND_COLOR[k] ?? '#64748b';
  return <span className="inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide" style={{ background: `${color}1a`, color }}>{KIND_LABEL[k] ?? safeText(k)}</span>;
}

const STATUS_COLOR: Record<string, string> = {
  open: '#dc2626', approved: '#059669', rejected: '#7c3aed', ignored: '#64748b',
  learning: '#d97706', locked: '#059669',
};
export function StatusPill({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? '#64748b';
  return <span className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold capitalize" style={{ background: `${color}1a`, color }}>{safeText(status)}</span>;
}

/** Accessible modal (focus trap, Escape, focus restore) — wraps the same look as RuleEngine's Modal. */
export function FimModal({ title, onClose, children, wide, footer }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean; footer?: ReactNode }) {
  const ref = useModalA11y<HTMLDivElement>(true, onClose);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-2 sm:p-4" onClick={onClose} role="presentation">
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()}
        className={`w-full ${wide ? 'max-w-4xl' : 'max-w-lg'} max-h-[92vh] flex flex-col rounded-2xl bg-white dark:bg-slate-900 shadow-xl border border-slate-200 dark:border-white/10`}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-white/10 shrink-0">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="rounded-lg p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto p-5">{children}</div>
        {footer && <div className="px-5 py-3 border-t border-slate-200 dark:border-white/10 flex flex-wrap justify-end gap-2 shrink-0">{footer}</div>}
      </div>
    </div>
  );
}

/** Right-side slide-over drawer. */
export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useModalA11y<HTMLDivElement>(true, onClose);
  return (
    <div className="fixed inset-0 z-50 bg-black/40" onClick={onClose} role="presentation">
      <aside ref={ref} role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()}
        className="absolute right-0 top-0 h-full w-full sm:max-w-xl bg-white dark:bg-slate-900 shadow-xl border-l border-slate-200 dark:border-white/10 flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-white/10 shrink-0">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="rounded-lg p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  );
}

export function Field({ label, htmlFor, hint, error, children }: { label: string; htmlFor?: string; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  return (
    <div>
      <label htmlFor={htmlFor} className="mb-1 block text-xs font-semibold text-slate-600 dark:text-slate-300">{label}</label>
      {children}
      {hint && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
      {error && <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">{error}</p>}
    </div>
  );
}

export function EmptyBox({ title, description }: { title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</p>
      {description && <p className="mt-1 max-w-sm text-sm text-slate-400">{description}</p>}
    </div>
  );
}

export function LoadingRows({ label = 'Loading' }: { label?: string }) {
  return <div role="status" aria-live="polite" className="px-4 py-10 text-center text-sm text-slate-400">{label}...</div>;
}

