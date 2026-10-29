import { useEffect, useRef, useState } from 'react';
import { Gauge } from 'lucide-react';
import { getFimRegMeasure, measureFimRegNode, type FimRegLimits, type FimRegMeasure } from '../../../api/services/fimApi';
import { errMsg } from '../constants';
import { Dropdown, ErrorBanner } from '../ui';
import { btnGhost } from '../styles';
import { fmtBytes, fmtCount } from './safeText';
import { RegText } from './RegUi';

const POLL_MS = 3000;
const POLL_MAX_MS = 120_000;

export interface MeasureOutcome { signature: string; m: FimRegMeasure; overBlock: boolean }

function level(v: number | null, warn?: number, block?: number): 'ok' | 'warn' | 'block' {
  if (v === null) return 'ok';
  if (block !== undefined && v > block) return 'block';
  if (warn !== undefined && v > warn) return 'warn';
  return 'ok';
}
const LVL_CLS = { ok: 'text-emerald-700 dark:text-emerald-300', warn: 'text-amber-700 dark:text-amber-300', block: 'text-red-700 dark:text-red-300' };

/**
 * "Measure on this node": a count-only distributed query (rows and bytes, no data) for a catalog
 * entry key or a custom spec, polled every 3 s for up to 2 min. Rate-limited by the server.
 */
export default function MeasurePanel({ hosts, entry, signature, limits, disabled, onResult }: {
  hosts: { host: string; label: string }[]; entry: string | Record<string, unknown>; signature: string;
  limits?: FimRegLimits | null; disabled?: boolean; onResult: (r: MeasureOutcome | null) => void;
}) {
  const [host, setHost] = useState(hosts[0]?.host ?? '');
  const [m, setM] = useState<FimRegMeasure | null>(null);
  const [measuredSig, setMeasuredSig] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const alive = useRef(true);
  const onResultRef = useRef(onResult);
  onResultRef.current = onResult;

  useEffect(() => { alive.current = true; return () => { alive.current = false; if (timer.current) clearTimeout(timer.current); }; }, []);
  // Inputs changed after a measurement: it no longer applies.
  useEffect(() => { if (measuredSig !== null && measuredSig !== signature) { setM(null); setMeasuredSig(null); onResultRef.current(null); } }, [signature, measuredSig]);

  const finish = (r: FimRegMeasure, sig: string) => {
    setM(r); setPolling(false);
    const over = level(r.rows, undefined, limits?.entryRowsBlock) === 'block' || level(r.bytes, undefined, limits?.entryBytesBlock) === 'block';
    onResultRef.current(r.status === 'done' ? { signature: sig, m: r, overBlock: over } : null);
  };

  const start = async () => {
    if (!host) return;
    setErr(null); setM(null); onResultRef.current(null);
    const sig = signature;
    try {
      const res = await measureFimRegNode(host, [entry]);
      const first = res.items?.[0];
      if (!first) { setErr('The server returned no measurement.'); return; }
      setMeasuredSig(sig); setM(first);
      if (first.status !== 'pending') { finish(first, sig); return; }
      setPolling(true);
      const t0 = Date.now();
      const tick = async () => {
        if (!alive.current) return;
        try {
          const r = await getFimRegMeasure(first.id);
          if (!alive.current) return;
          if (r.status !== 'pending') { finish(r, sig); return; }
          setM(r);
          if (Date.now() - t0 >= POLL_MAX_MS) { setPolling(false); setErr('No answer from the agent within 2 minutes (it may be offline). Try again later.'); return; }
          timer.current = setTimeout(tick, POLL_MS);
        } catch (e) { if (alive.current) { setPolling(false); setErr(errMsg(e, 'Measurement failed')); } }
      };
      timer.current = setTimeout(tick, POLL_MS);
    } catch (e) { setErr(errMsg(e, 'Measurement request failed')); }
  };

  const rowsLvl = level(m?.rows ?? null, limits?.entryRowsWarn, limits?.entryRowsBlock);
  const bytesLvl = level(m?.bytes ?? null, limits?.entryBytesWarn, limits?.entryBytesBlock);

  return (
    <div className="space-y-2 rounded-lg border border-slate-200 p-3 dark:border-white/10">
      <div className="flex flex-wrap items-center gap-2">
        {hosts.length > 1 && <Dropdown aria-label="Measure on host" value={host} onChange={setHost} options={hosts.map((h) => ({ value: h.host, label: h.label }))} className="w-56" />}
        <button type="button" className={btnGhost} disabled={disabled || polling || !host} onClick={start}><Gauge className="h-4 w-4" />{polling ? 'Measuring...' : hosts.length > 1 ? 'Measure on selected node' : 'Measure on this node'}</button>
        {hosts.length === 1 && <span className="text-xs text-slate-500">on <RegText value={hosts[0].label} /></span>}
      </div>
      <p className="text-xs text-slate-500">Runs a count-only query on the agent: it returns two numbers (rows, bytes) and no registry data. Limited to a few requests per host every 10 minutes.</p>
      {err && <ErrorBanner message={err} />}
      {m && (
        <div aria-live="polite" className="text-sm">
          {m.status === 'pending' && <p className="text-slate-500">Waiting for the agent...</p>}
          {m.status === 'failed' && <p className="text-red-700 dark:text-red-300">Measurement failed: <RegText value={m.error ?? 'unknown error'} /></p>}
          {m.status === 'done' && (
            <p>
              <span className={LVL_CLS[rowsLvl]}>{fmtCount(m.rows)} rows</span>
              {limits && <span className="text-xs text-slate-500"> (warn &gt; {fmtCount(limits.entryRowsWarn)}, block &gt; {fmtCount(limits.entryRowsBlock)})</span>}
              {' · '}
              <span className={LVL_CLS[bytesLvl]}>{fmtBytes(m.bytes)}</span>
              {limits && <span className="text-xs text-slate-500"> (warn &gt; {fmtBytes(limits.entryBytesWarn)}, block &gt; {fmtBytes(limits.entryBytesBlock)})</span>}
              {(rowsLvl === 'block' || bytesLvl === 'block') && <span className="block text-xs text-red-700 dark:text-red-300">Over the per-entry limit: osquery drops result lines over about 1 MiB. Narrow the key or the values.</span>}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
