import { useCallback, useEffect, useState } from 'react';
import { ackFimRegHygiene, getFimRegHygiene, type FimRegHygieneFinding } from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { errMsg, fmtTime, shortHash } from '../constants';
import { Drawer, EmptyBox, ErrorBanner, LoadingRows, SeverityBadge } from '../ui';
import { btnGhost } from '../styles';
import { RegText } from './RegUi';
import NoteModal from './NoteModal';

/** Baseline hygiene findings (possible persistence adopted at Initialize), acknowledged with a note. */
export default function HygieneDrawer({ host, hostLabel, canAck, onClose }: { host: string; hostLabel: string; canAck: boolean; onClose: () => void }) {
  const { showToast } = useToast();
  const [items, setItems] = useState<FimRegHygieneFinding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ack, setAck] = useState<FimRegHygieneFinding | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    try { setItems((await getFimRegHygiene(host)).items ?? []); } catch (e) { setErr(errMsg(e, 'Failed to load hygiene findings')); }
  }, [host]);
  useEffect(() => { load(); }, [load]);

  return (
    <Drawer title={`Baseline hygiene: ${hostLabel}`} onClose={onClose}>
      <div className="space-y-3">
        <p className="text-sm text-slate-600 dark:text-slate-300">Rows that look like persistence already present when the baseline was initialised (user-writable autostart paths, IFEO debuggers, non-default LSA packages, Defender exclusions, values rare in the fleet...). They are flagged, not blocked: review each one and acknowledge it with a note.</p>
        {err && <ErrorBanner message={err} onRetry={load} stale={!!items} />}
        {!items ? (!err && <LoadingRows />) : items.length === 0 ? <EmptyBox title="No hygiene findings" /> : (
          <ul className="space-y-2">
            {items.map((f) => (
              <li key={`${f.itemPath}-${f.sha256}`} className="rounded-lg border border-slate-200 p-3 text-sm dark:border-white/10">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><RegText value={f.rule} className="font-semibold" /></span>
                  {f.acked ? <span className="text-xs text-emerald-700 dark:text-emerald-300">acknowledged by <RegText value={f.ackedBy ?? '?'} /> {fmtTime(f.ackedAt)}</span>
                    : canAck && <button className={btnGhost} onClick={() => setAck(f)}>Acknowledge</button>}
                </div>
                <RegText value={f.itemPath} mono className="block text-xs" />
                <p className="text-xs text-slate-600 dark:text-slate-300"><RegText value={f.detail} /></p>
                <p className="font-mono text-[11px] text-slate-400">{shortHash(f.sha256)}</p>
                {f.note && <p className="text-xs text-slate-500">Note: <RegText value={f.note} /></p>}
              </li>
            ))}
          </ul>
        )}
      </div>
      {ack && (
        <NoteModal title="Acknowledge hygiene finding" confirmLabel="Acknowledge" description={<>Confirm you reviewed <RegText value={ack.itemPath} mono /> and it is legitimate.</>}
          onClose={() => setAck(null)}
          onSubmit={async (note) => { await ackFimRegHygiene(host, { itemPath: ack.itemPath, sha256: ack.sha256, note }); showToast('Finding acknowledged', 'success'); setAck(null); load(); }} />
      )}
    </Drawer>
  );
}
