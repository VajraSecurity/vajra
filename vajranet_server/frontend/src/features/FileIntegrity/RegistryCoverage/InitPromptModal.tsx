import { useState } from 'react';
import { useConfirm } from '../../../context/useConfirm';
import { useToast } from '../../../context/useToast';
import { errMsg } from '../constants';
import { initWithForce } from './regActions';
import { ErrorBanner, FimModal } from '../ui';
import { btnGhost, btnPrimary } from '../styles';
import { safeText } from './safeText';
import { NoteField } from './RegUi';

export default function InitPromptModal({ policyId, host, hostLabel, slots, headline, full, onClose }: {
  policyId: number; host: string; hostLabel: string; slots: number[]; headline?: string; full?: boolean; onClose: (initialized: boolean) => void;
}) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const n = slots.length;
  const label = safeText(hostLabel);

  const later = () => {
    showToast(`${label} stays in the Needs init queue; the new entries are not monitored until initialised.`, 'info');
    onClose(false);
  };
  const now = async () => {
    const ok = await confirm({
      title: full ? `Initialize all entries on ${label}?` : `Initialize ${n} entr${n === 1 ? 'y' : 'ies'} on ${label}?`,
      variant: 'danger',
      confirmLabel: 'Initialize now',
      description: 'The agent is asked for an immediate scan and the result becomes the baseline. Only do this on a host you trust: anything malicious already present becomes the new normal.',
    });
    if (!ok) return;
    setBusy(true); setErr(null);
    try {
      const r = await initWithForce(confirm, policyId, host, slots, note.trim());
      if (!r) { setBusy(false); return; }
      showToast(r.requests > 0 ? `Initialisation requested for ${n} entr${n === 1 ? 'y' : 'ies'} on ${label}` : 'Nothing to request', r.requests > 0 ? 'success' : 'info');
      onClose(true);
    } catch (e) { setErr(errMsg(e, 'Initialisation request failed')); setBusy(false); }
  };

  return (
    <FimModal title={full ? `Initialize all entries on ${label} now?` : `Initialize ${n} new entr${n === 1 ? 'y' : 'ies'} on ${label} now?`} onClose={later}
      footer={<><button className={btnGhost} onClick={later} disabled={busy}>Initialize later</button><button className={btnPrimary} disabled={busy || !note.trim() || note.trim().length > 2000} onClick={now}>{busy ? 'Requesting...' : 'Initialize now'}</button></>}>
      <div className="space-y-3">
        {headline && <p className="text-sm font-semibold text-emerald-700 dark:text-emerald-300">{headline}</p>}
        {err && <ErrorBanner message={err} />}
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The agent is asked for an immediate scan of {full ? 'every entry' : `slot${n === 1 ? '' : 's'} ${slots.join(', ')}`} and the result becomes the baseline. Only these slots are initialised; drift on other entries is untouched.
          Only do this on a host you trust: anything malicious already present becomes the new normal (it is still checked by the baseline hygiene rules).
        </p>
        <p className="text-xs text-slate-500">Initialize later: the node stays in the Needs init queue and the new entries are not monitored until then.</p>
        <NoteField id="reg-init-note" value={note} onChange={setNote} maxLength={2000} hint="Recorded with the baseline version and in the audit trail." />
      </div>
    </FimModal>
  );
}
