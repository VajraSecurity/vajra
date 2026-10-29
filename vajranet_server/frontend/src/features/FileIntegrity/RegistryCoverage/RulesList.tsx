import { Undo2 } from 'lucide-react';
import type { FimRegRule } from '../../../api/services/fimApi';
import { fmtTime } from '../constants';
import { tdCls, thCls } from '../styles';
import { RegText } from './RegUi';
import { OP_LABEL, specSummary } from './regModel';

/** Rules of one layer. `onRevoke` is offered on active rules the caller may manage. */
export default function RulesList({ rules, title, onRevoke, revokeLabel = 'Revoke', pendingRevokes, emptyText }: {
  rules: FimRegRule[]; title: string; onRevoke?: (r: FimRegRule) => void; revokeLabel?: string; pendingRevokes?: Set<number>; emptyText?: string;
}) {
  const active = rules.filter((r) => r.status === 'active');
  return (
    <section aria-label={title}>
      <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">{title} ({active.length})</h4>
      {active.length === 0 ? <p className="text-sm text-slate-400">{emptyText ?? 'No rules.'}</p> : (
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-white/10">
          <table className="w-full min-w-[760px]">
            <thead className="bg-slate-50 dark:bg-slate-800"><tr>
              <th className={thCls}>#</th><th className={thCls}>Op</th><th className={thCls}>Target</th><th className={thCls}>Spec</th><th className={thCls}>Reason</th><th className={thCls}>Waiver</th><th className={thCls}>Created</th>
              {onRevoke && <th className={thCls}><span className="sr-only">Actions</span></th>}
            </tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {active.map((r) => {
                const pend = pendingRevokes?.has(r.id);
                return (
                  <tr key={r.id} className={pend ? 'opacity-50 line-through' : ''}>
                    <td className={`${tdCls} tabular-nums`}>{r.id}</td>
                    <td className={tdCls}>{OP_LABEL[r.op] ?? r.op}</td>
                    <td className={`${tdCls} text-xs`}><RegText value={r.target} mono /></td>
                    <td className={`${tdCls} max-w-[280px] text-xs`}><RegText value={specSummary(r.op, r.spec ?? {})} /></td>
                    <td className={`${tdCls} max-w-[220px] text-xs`}><RegText value={r.reason} /></td>
                    <td className={`${tdCls} text-xs`}>{r.waiverId ? `#${r.waiverId}` : '-'}</td>
                    <td className={`${tdCls} whitespace-nowrap text-xs`}><RegText value={r.createdBy} /><span className="block text-slate-400">{fmtTime(r.createdAt)}</span></td>
                    {onRevoke && (
                      <td className={tdCls}>
                        {r.canManage !== false && !pend && (
                          <button className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-semibold text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-500/10" onClick={() => onRevoke(r)}>
                            <Undo2 className="h-3.5 w-3.5" />{revokeLabel}
                          </button>
                        )}
                        {pend && <span className="text-xs no-underline">pending revoke</span>}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
