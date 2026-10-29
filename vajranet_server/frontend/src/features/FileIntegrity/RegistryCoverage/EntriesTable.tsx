import { AlertTriangle, HelpCircle } from 'lucide-react';
import type { FimRegEntry } from '../../../api/services/fimApi';
import { fmtTime } from '../constants';
import { Dropdown, EmptyBox, SeverityBadge } from '../ui';
import { tdCls, thCls } from '../styles';
import { fmtCount, safeText } from './safeText';
import { AttackChips, EstimateCell, ProtectedLock, RegText, SourceBadges, ValuesFilter } from './RegUi';
import type { RowAction } from './regModel';

const PENDING_LABEL: Record<string, string> = { added: 'new: needs Initialize', changed: 'changed: new slot', severity: 'severity only' };

const UNVERIFIED_HINT = 'The registry SQL, row/size estimate and real-time mapping for this entry have not yet been probed on a Windows agent. Treat the numbers as estimates until verified.';

function Hives({ e }: { e: FimRegEntry }) {
  if (!e.hiveScoped || !e.hives || e.hives.length === 0) return null;
  const last = e.baseline?.lastScanAt ?? 0;
  const missing = e.hives.filter((h) => last && h.lastSeen < last);
  if (missing.length === 0) return <p className="mt-1 text-[11px] text-slate-500">{e.hives.length} user hive{e.hives.length === 1 ? '' : 's'} seen in the last scan</p>;
  return (
    <details className="mt-1 text-[11px] text-slate-500">
      <summary className="cursor-pointer text-amber-700 dark:text-amber-300">{missing.length} user hive{missing.length === 1 ? '' : 's'} not loaded in the last scan</summary>
      <ul className="mt-1 space-y-0.5">
        {missing.map((h) => <li key={h.sid}><RegText value={h.sid} mono /> not loaded since {fmtTime(h.lastSeen)}</li>)}
      </ul>
      <p className="mt-1">A user that is logged off is not a deletion: edits made while logged off are seen at the next logon.</p>
    </details>
  );
}

/** Resolved registry entries (node, group or catalog view). Untrusted text is rendered via RegText. */
export default function EntriesTable({ entries, canManage, onAction, showBaseline, realtimeAvailable, emptyText }: {
  entries: FimRegEntry[]; canManage: boolean; onAction?: (e: FimRegEntry, a: RowAction) => void; showBaseline?: boolean;
  realtimeAvailable?: boolean; emptyText?: string;
}) {
  if (entries.length === 0) return <EmptyBox title={emptyText ?? 'No registry entries'} />;
  const actions = canManage && !!onAction;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[1100px]">
        <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800"><tr>
          <th className={thCls}>Key</th><th className={thCls}>Values</th><th className={thCls}>Severity</th><th className={thCls}>ATT&amp;CK</th>
          <th className={thCls}>Source</th><th className={thCls}>Estimate</th>{showBaseline && <th className={thCls}>Baseline</th>}
          {actions && <th className={thCls}><span className="sr-only">Actions</span></th>}
        </tr></thead>
        <tbody className="divide-y divide-slate-100 dark:divide-white/5">
          {entries.map((e) => (
            <tr key={`${e.entryKey}-${e.slot ?? 'n'}`} className="align-top hover:bg-slate-50 dark:hover:bg-white/5">
              <td className={`${tdCls} max-w-[420px]`}>
                <div className="flex flex-wrap items-center gap-1.5">
                  {e.protected && <ProtectedLock />}
                  <span className="text-sm font-semibold"><RegText value={e.label || e.entryKey} /></span>
                  {e.pending && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">{PENDING_LABEL[e.pending] ?? e.pending}</span>}
                  {e.needsInit && <span className="rounded bg-blue-100 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700 dark:bg-blue-500/15 dark:text-blue-300">needs init</span>}
                  {!e.verified && <span title={UNVERIFIED_HINT} className="inline-flex items-center gap-0.5 rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-bold text-slate-700 dark:bg-white/15 dark:text-slate-200"><HelpCircle aria-hidden className="h-3 w-3" />UNVERIFIED (estimate)</span>}
                </div>
                <RegText value={e.path} mono className="block text-xs text-slate-600 dark:text-slate-300" />
                <p className="text-[11px] text-slate-400"><RegText value={e.entryKey} mono />{e.slot !== null ? ` · slot ${e.slot}` : ''}{e.category ? <> · <RegText value={e.category} /></> : null}</p>
                {e.realtimeRequired && realtimeAvailable === false && (
                  <p className="mt-1 flex items-center gap-1 text-[11px] text-amber-700 dark:text-amber-300"><AlertTriangle aria-hidden className="h-3 w-3" />Needs real-time (created and removed within seconds); this node has no real-time events, so scans can miss it.</p>
                )}
                {e.redactValues.length > 0 && <p className="text-[11px] text-slate-500">Redacted on the host: {e.redactValues.map((v, i) => <span key={v}>{i > 0 && ', '}<RegText value={v} mono /></span>)}</p>}
                <Hives e={e} />
              </td>
              <td className={`${tdCls} max-w-[260px]`}><ValuesFilter values={e.values} ignoreValues={e.ignoreValues} excludeKeys={e.excludeKeys} /></td>
              <td className={tdCls}><SeverityBadge severity={e.severity} /></td>
              <td className={tdCls}><AttackChips ids={e.attack} /></td>
              <td className={tdCls}><SourceBadges sources={e.sources} /></td>
              <td className={tdCls}><EstimateCell estimate={e.estimate} /></td>
              {showBaseline && (
                <td className={`${tdCls} whitespace-nowrap text-xs`}>
                  {e.baseline ? (<>
                    <span className="tabular-nums">{fmtCount(e.baseline.rows)} rows</span> <span className="text-slate-400">({safeText(e.baseline.state)})</span>
                    <span className="block text-slate-500">verified {fmtTime(e.baseline.lastScanAt)}</span>
                  </>) : <span className="text-slate-400">-</span>}
                </td>
              )}
              {actions && (
                <td className={tdCls}>
                  <Dropdown aria-label={`Actions for ${safeText(e.entryKey)}`} value="" placeholder="Actions" className="w-36"
                    onChange={(v) => { if (v) onAction?.(e, v as RowAction); }}
                    options={[
                      { value: 'severity', label: 'Change severity' },
                      { value: 'filter', label: 'Narrow values' },
                      { value: 'exclude', label: 'Exclude value / subkey' },
                      { value: 'disable', label: 'Disable' },
                    ]} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
