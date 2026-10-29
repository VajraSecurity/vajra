import type { ReactNode } from 'react';
import { Minus, Plus, RefreshCw, Trash2, Upload } from 'lucide-react';
import type { FimRegPreview } from '../../../api/services/fimApi';
import { ErrorBanner, SeverityBadge } from '../ui';
import { btnPrimary, cardCls } from '../styles';
import { fmtBytes, fmtCount, fmtSigned } from './safeText';
import { Banner, RegText } from './RegUi';
import type { PendingChange } from './regModel';

function Section({ title, hint, count, tone, children }: { title: string; hint: string; count: number; tone: string; children: ReactNode }) {
  if (count === 0) return null;
  return (
    <section>
      <h4 className={`text-xs font-semibold uppercase ${tone}`}>{title} ({count})</h4>
      <p className="text-[11px] text-slate-500">{hint}</p>
      <ul className="mt-1 space-y-1">{children}</ul>
    </section>
  );
}

/** "Pending changes" side panel: local edits plus the server's dry-run diff (preview). */
export default function PendingDiff({ pending, assignmentText, preview, previewing, previewErr, onRemove, onClearAssignment, onApply, applyDisabledReason, publishOnly, onRequestWaiver }: {
  pending: PendingChange[]; assignmentText: string | null; preview: FimRegPreview | null; previewing: boolean; previewErr: string | null;
  onRemove: (id: string) => void; onClearAssignment: () => void; onApply: () => void; applyDisabledReason: string | null; publishOnly: boolean;
  onRequestWaiver?: (p: PendingChange) => void;
}) {
  const hasLocal = pending.length > 0 || !!assignmentText;
  const d = preview?.diff;
  const before = preview?.estimate.before;
  const after = preview?.estimate.after;
  return (
    <aside aria-label="Pending changes" className={`${cardCls} flex flex-col p-4 gap-3`}>
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Pending changes</h3>
        {previewing && <span role="status" className="flex items-center gap-1 text-xs text-slate-500"><RefreshCw className="h-3 w-3 animate-spin" />previewing</span>}
      </div>
      {!hasLocal && !publishOnly && <p className="text-sm text-slate-500">No changes yet. Use the row actions, Add key, the tier or profile pickers, or revoke a node rule. Nothing is saved until you click Apply.</p>}
      {publishOnly && !hasLocal && <Banner tone="info">The saved configuration differs from what is published (status Pending publish). Apply publishes it.</Banner>}
      {hasLocal && (
        <ol className="space-y-1">
          {assignmentText && (
            <li className="flex items-start justify-between gap-2 rounded bg-slate-50 px-2 py-1 text-xs dark:bg-white/5">
              <span>Assignment: <RegText value={assignmentText} /></span>
              <button aria-label="Undo assignment change" onClick={onClearAssignment} className="text-slate-400 hover:text-red-600"><Trash2 className="h-3.5 w-3.5" /></button>
            </li>
          )}
          {pending.map((p, i) => (
            <li key={p.id} className="flex items-start justify-between gap-2 rounded bg-slate-50 px-2 py-1 text-xs dark:bg-white/5">
              <span><span className="text-slate-400">{i + 1}.</span> {p.change.action === 'revoke' ? 'Revoke ' : ''}<RegText value={p.summary} />
                {p.waiver && <span className="mt-0.5 block text-[11px] text-amber-700 dark:text-amber-300">Waiver request for <RegText value={p.waiver.entryKey} mono />: sent on Apply; the change is made only after a different Super Admin approves it (then &quot;Apply approved change&quot;). Not part of the preview.</span>}
                {!p.waiver && p.needsWaiverFor && (
                  <span className="mt-0.5 block text-[11px] text-red-700 dark:text-red-300">Overlaps protected coverage of <RegText value={p.needsWaiverFor} mono />: a waiver is required.
                    {onRequestWaiver && <button className="ml-1 font-semibold underline" onClick={() => onRequestWaiver(p)}>Request waiver...</button>}</span>
                )}
              </span>
              <button aria-label={`Remove pending change ${i + 1}`} onClick={() => onRemove(p.id)} className="text-slate-400 hover:text-red-600"><Trash2 className="h-3.5 w-3.5" /></button>
            </li>
          ))}
        </ol>
      )}
      {previewErr && <ErrorBanner message={previewErr} />}
      {preview && hasLocal && d && (
        <div className="space-y-3 border-t border-slate-200 pt-3 dark:border-white/10">
          <Section title="Added" tone="text-emerald-700 dark:text-emerald-400" count={d.added.length} hint="New slots: not monitored until you Initialize them.">
            {d.added.map((e) => <li key={`a-${e.entryKey}`} className="flex gap-1 text-xs"><Plus aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-emerald-600" /><span><RegText value={e.entryKey} mono /> <RegText value={e.path} mono className="text-slate-500" /></span></li>)}
          </Section>
          <Section title="Removed" tone="text-red-700 dark:text-red-400" count={d.removed.length} hint="Baseline rows are soft-retired for 7 days; open drift on them is closed as ignored.">
            {d.removed.map((e) => <li key={`r-${e.entryKey}-${e.slot ?? ''}`} className="flex gap-1 text-xs"><Minus aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-red-600" /><span><RegText value={e.entryKey} mono /> <RegText value={e.path} mono className="text-slate-500" /></span></li>)}
          </Section>
          <Section title="Changed" tone="text-amber-700 dark:text-amber-400" count={d.changed.length} hint="Pattern or filters changed: the entry moves to a new slot and needs Initialize.">
            {d.changed.map((e) => <li key={`c-${e.entryKey}`} className="text-xs">~ <RegText value={e.entryKey} mono /></li>)}
          </Section>
          <Section title="Severity only" tone="text-slate-600 dark:text-slate-300" count={d.severityOnly.length} hint="No re-initialisation needed.">
            {d.severityOnly.map((e) => <li key={`s-${e.entryKey}`} className="flex items-center gap-1 text-xs"><RegText value={e.entryKey} mono /> <SeverityBadge severity={e.severity} /></li>)}
          </Section>
          {before && after && (
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Estimated size: {fmtCount(before.entries)} -&gt; {fmtCount(after.entries)} entries, {fmtCount(before.rows)} -&gt; {fmtCount(after.rows)} rows ({fmtSigned(after.rows - before.rows, fmtCount)}), {fmtBytes(before.bytes)} -&gt; {fmtBytes(after.bytes)} ({fmtSigned(after.bytes - before.bytes, fmtBytes)})
            </p>
          )}
          {preview.rev.current !== preview.rev.next && <p className="text-xs text-slate-600 dark:text-slate-300">Policy revision: rev {preview.rev.current ?? '-'} -&gt; {preview.rev.next ?? '-'}</p>}
          {preview.needsInit.length > 0 && <p className="text-xs text-blue-700 dark:text-blue-300">{preview.needsInit.length} entr{preview.needsInit.length === 1 ? 'y' : 'ies'} will need Initialize after Apply.</p>}
          {preview.blocked.length > 0 && (
            <Banner tone="warn">
              <b>Blocked rules ({preview.blocked.length})</b> - they have no effect until their waiver is approved:
              <ul className="mt-1 list-disc pl-4 text-xs">{preview.blocked.map((b, i) => <li key={`${b.ruleId}-${i}`}><RegText value={`${b.op} ${b.entryKey || b.target}: ${b.reason}`} /></li>)}</ul>
            </Banner>
          )}
          {preview.warnings.length > 0 && <Banner tone="warn"><ul className="list-disc pl-4 text-xs">{preview.warnings.map((w, i) => <li key={i}><RegText value={w} /></li>)}</ul></Banner>}
          {preview.errors.length > 0 && <Banner tone="error"><b>Cannot apply:</b><ul className="list-disc pl-4 text-xs">{preview.errors.map((w, i) => <li key={i}><RegText value={w} /></li>)}</ul></Banner>}
        </div>
      )}
      <button className={btnPrimary} disabled={!!applyDisabledReason} onClick={onApply} title={applyDisabledReason ?? undefined}><Upload className="h-4 w-4" />Apply</button>
      {applyDisabledReason && (hasLocal || publishOnly) && <p className="text-xs text-slate-500">{applyDisabledReason}</p>}
    </aside>
  );
}
