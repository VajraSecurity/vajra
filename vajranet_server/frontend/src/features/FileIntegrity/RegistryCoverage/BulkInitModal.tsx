import { useEffect, useRef, useState } from 'react';
import { useConfirm } from '../../../context/useConfirm';
import { initializeFimBaselineEntries } from '../../../api/services/fimApi';
import { errMsg, errStatus } from '../constants';
import { FimModal } from '../ui';
import { btnGhost, btnPrimary } from '../styles';
import { NoteField, RegText } from './RegUi';

export interface BulkInitTarget { host: string; hostLabel: string; policyId: number; slots: number[] }
type Outcome = { state: 'ok' } | { state: 'failed'; msg: string } | { state: 'force'; msg: string };

/**
 * Initialise the new slots on many nodes, one request per host, sequentially, with progress and
 * cancel. Hosts that need "force" (open critical drift) are skipped and listed: force is a
 * per-host, explicit decision (Needs init view).
 */
export default function BulkInitModal({ targets, title, onClose }: { targets: BulkInitTarget[]; title: string; onClose: () => void }) {
  const confirm = useConfirm();
  const [note, setNote] = useState('');
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [idx, setIdx] = useState(0);
  const [results, setResults] = useState<Record<string, Outcome>>({});
  const cancelled = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; cancelled.current = true; }; }, []);
  const totalSlots = targets.reduce((a, t) => a + t.slots.length, 0);

  const start = async () => {
    const ok = await confirm({
      title: `Initialize ${totalSlots} entr${totalSlots === 1 ? 'y' : 'ies'} on ${targets.length} node${targets.length === 1 ? '' : 's'}?`,
      variant: 'danger',
      confirmLabel: 'Initialize now',
      description: 'Each agent is asked for an immediate scan of the listed slots and the result becomes their baseline. Only do this for hosts you trust: anything malicious already present becomes the new normal.',
    });
    if (!ok) return;
    cancelled.current = false; setRunning(true); setResults({});
    for (let i = 0; i < targets.length; i++) {
      if (cancelled.current || !alive.current) break;
      const t = targets[i];
      setIdx(i + 1);
      let out: Outcome;
      try { await initializeFimBaselineEntries(t.policyId, note.trim(), [t.host], t.slots); out = { state: 'ok' }; }
      catch (e) { out = errStatus(e) === 409 ? { state: 'force', msg: errMsg(e, 'Open critical drift') } : { state: 'failed', msg: errMsg(e, 'Request failed') }; }
      if (!alive.current) return;
      setResults((r) => ({ ...r, [t.host]: out }));
    }
    if (alive.current) { setRunning(false); setDone(true); }
  };

  const vals = Object.values(results);
  const ok = vals.filter((v) => v.state === 'ok').length;
  const failed = vals.filter((v) => v.state === 'failed').length;
  const force = vals.filter((v) => v.state === 'force').length;

  return (
    <FimModal wide title={title} onClose={() => { if (!running) onClose(); }}
      footer={running
        ? <button className={btnGhost} onClick={() => { cancelled.current = true; }}>Cancel after current host</button>
        : <><button className={btnGhost} onClick={onClose}>{done ? 'Close' : 'Initialize later'}</button>{!done && <button className={btnPrimary} disabled={!note.trim() || note.trim().length > 2000 || targets.length === 0} onClick={start}>Initialize now</button>}</>}>
      <div className="space-y-3">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          {targets.length} node{targets.length === 1 ? '' : 's'} have {totalSlots} new entr{totalSlots === 1 ? 'y' : 'ies'} without a baseline. Initialising asks each agent for an immediate scan of only those slots and makes the result their baseline. Only do this for hosts you trust.
          If you initialise later, the nodes stay in the Needs init queue.
        </p>
        {!running && !done && <NoteField id="reg-bulk-init-note" value={note} onChange={setNote} maxLength={2000} hint="Recorded with every baseline version and in the audit trail." />}
        {(running || done) && (
          <div aria-live="polite" className="space-y-2">
            <div className="h-2 w-full overflow-hidden rounded bg-slate-100 dark:bg-white/10"><div className="h-full bg-indigo-600 transition-all" style={{ width: `${targets.length ? (idx / targets.length) * 100 : 0}%` }} /></div>
            <p className="text-sm">{running ? `Requesting ${idx} of ${targets.length}...` : `Finished: ${ok} requested, ${failed} failed, ${force} need force${cancelled.current && idx < targets.length ? ', cancelled' : ''}.`}</p>
          </div>
        )}
        <ul className="max-h-64 space-y-1 overflow-y-auto text-xs">
          {targets.map((t) => {
            const r = results[t.host];
            return (
              <li key={t.host} className="flex flex-wrap items-center gap-2">
                <RegText value={t.hostLabel} /> <span className="text-slate-400">slots {t.slots.join(', ')}</span>
                {r?.state === 'ok' && <span className="text-emerald-700 dark:text-emerald-300">requested</span>}
                {r?.state === 'failed' && <span className="text-red-700 dark:text-red-300">failed: <RegText value={r.msg} /></span>}
                {r?.state === 'force' && <span className="text-amber-700 dark:text-amber-300">skipped (needs force): <RegText value={r.msg} />. Use the Needs init view for this host.</span>}
              </li>
            );
          })}
        </ul>
      </div>
    </FimModal>
  );
}
