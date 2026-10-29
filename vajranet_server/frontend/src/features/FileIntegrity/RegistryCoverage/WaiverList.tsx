import { useState } from 'react';
import { applyFimRegWaiver, type FimRegWaiver } from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { fmtTime } from '../constants';
import { btnPrimary } from '../styles';
import { safeText } from './safeText';
import { RegText } from './RegUi';
import { OP_LABEL, WAIVER_ACTION_LABEL, canApplyWaiver } from './regModel';
import NoteModal from './NoteModal';

/** The exact rule a waiver is bound to (op, target, spec as formatted JSON), rendered safely. */
export function WaiverRuleView({ w }: { w: FimRegWaiver }) {
  if (!w.rule) return <p className="text-xs text-slate-500">No bound rule was reported for this waiver.</p>;
  const op = w.rule.op as keyof typeof OP_LABEL;
  return (
    <div className="text-xs">
      <p><b>{OP_LABEL[op] ?? safeText(w.rule.op)}</b> <RegText value={w.rule.target} mono /> on {safeText(w.scopeType)} <RegText value={w.scopeValue} mono /></p>
      <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-2 text-[11px] dark:bg-white/5">{safeText(JSON.stringify(w.rule.spec ?? {}, null, 2))}</pre>
    </div>
  );
}

/** "Apply approved change": creates the waiver's stored rule (POST /waivers/:id/apply). */
export function ApplyWaiverModal({ w, onClose, onApplied }: { w: FimRegWaiver; onClose: () => void; onApplied: () => void }) {
  const { showToast } = useToast();
  return (
    <NoteModal title={`Apply approved change of waiver #${w.id}?`} confirmLabel="Apply approved change" onClose={onClose} noteLabel="Note (required)"
      description={<>
        <p>Creates exactly the rule this waiver was approved for. The waiver is single use. Afterwards the scope is <b>Pending publish</b>: review it and Apply / publish as usual to make the change effective on the nodes.</p>
        <div className="mt-2"><WaiverRuleView w={w} /></div>
      </>}
      onSubmit={async (note) => {
        const r = await applyFimRegWaiver(w.id, note);
        showToast(`Approved change applied: rule #${r?.id ?? '?'} created. The scope is now Pending publish: Apply to publish it.`, 'success');
        onApplied();
      }} />
  );
}

/** Compact waiver list for the node and group views, with "Apply approved change". */
export default function WaiverList({ title, waivers, isSuperAdmin, onApplied }: { title: string; waivers: FimRegWaiver[]; isSuperAdmin: boolean; onApplied: () => void }) {
  const [apply, setApply] = useState<FimRegWaiver | null>(null);
  return (
    <section>
      <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">{title}</h4>
      <ul className="space-y-1 text-xs">
        {waivers.map((w) => (
          <li key={w.id} className="flex flex-wrap items-center gap-2">
            <span>#{w.id} {WAIVER_ACTION_LABEL[w.action] ?? safeText(w.action)} <RegText value={w.entryKey} mono /> - <b>{safeText(w.status)}</b>{w.ruleId != null ? `, used (rule #${w.ruleId})` : ''}, expires {fmtTime(w.expiresAt)} - <RegText value={w.reason} /></span>
            {canApplyWaiver(w, isSuperAdmin) && <button className={`${btnPrimary} px-2 py-1 text-xs`} onClick={() => setApply(w)}>Apply approved change</button>}
          </li>
        ))}
      </ul>
      {apply && <ApplyWaiverModal w={apply} onClose={() => setApply(null)} onApplied={() => { setApply(null); onApplied(); }} />}
    </section>
  );
}
