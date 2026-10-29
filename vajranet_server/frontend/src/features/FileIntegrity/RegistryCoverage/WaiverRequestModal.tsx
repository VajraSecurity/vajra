import { useMemo, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { requestFimRegWaiver, type FimRegLayer, type FimRegWaiver, type FimRegWaiverAction, type FimRegWaiverRule } from '../../../api/services/fimApi';
import { errMsg } from '../constants';
import { ErrorBanner, Field, FimModal } from '../ui';
import { btnGhost, btnPrimary, inputCls } from '../styles';
import { NoteField, RegText } from './RegUi';
import { WAIVER_ACTION_LABEL, WAIVER_FLOW_TEXT, WAIVER_MAX_DAYS_DEFAULT, dateInputValue, type WaiverDraft } from './regModel';

/**
 * Waiver request for a reduction of a protected entry (§4.3). A waiver is bound to ONE exact rule
 * and is single use; the rule is created only from the APPROVED waiver ("Apply approved change").
 *  - mode 'submit' (group / profile views): the waiver is requested now (POST) and handed back.
 *  - mode 'collect' (node view): nothing is sent; the form data is kept with the pending change and
 *    the waiver is requested when the user clicks Apply.
 */
export default function WaiverRequestModal({ entryKey, entryPath, action, scopeType, scopeValue, changeText, rule, mode, maxDays = WAIVER_MAX_DAYS_DEFAULT, onCreated, onCollected, onClose }: {
  entryKey: string; entryPath: string; action: FimRegWaiverAction; scopeType: FimRegLayer; scopeValue: string; changeText: string;
  rule: FimRegWaiverRule; mode: 'submit' | 'collect'; maxDays?: number;
  onCreated?: (w: FimRegWaiver) => Promise<void> | void; onCollected?: (w: WaiverDraft) => Promise<void> | void; onClose: () => void;
}) {
  const days = Math.max(1, Math.min(maxDays, WAIVER_MAX_DAYS_DEFAULT));
  const { min, max, def } = useMemo(() => {
    const now = new Date();
    const tomorrow = new Date(now.getTime() + 86400_000);
    const last = new Date(now.getTime() + days * 86400_000);
    const d7 = new Date(now.getTime() + Math.min(7, days) * 86400_000);
    return { min: dateInputValue(tomorrow), max: dateInputValue(last), def: dateInputValue(d7) };
  }, [days]);
  const [reason, setReason] = useState('');
  const [expiry, setExpiry] = useState(def);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const expiresAt = useMemo(() => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(expiry);
    if (!m) return null;
    // End of the chosen local day, capped at now + maxDays.
    const t = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 0).getTime();
    const cap = Date.now() + days * 86400_000;
    return Math.floor(Math.min(t, cap) / 1000);
  }, [expiry, days]);
  const expiryErr = !expiresAt ? 'Choose an expiry date' : expiry < min || expiry > max ? `Expiry must be within ${days} days` : null;
  const reasonTrim = reason.trim();
  const reasonErr = reasonTrim.length < 10 || reasonTrim.length > 2000;

  const submit = async () => {
    if (!expiresAt) return;
    setBusy(true); setErr(null);
    try {
      if (mode === 'collect') {
        await onCollected?.({ entryKey, action, reason: reasonTrim, expiresAt });
      } else {
        const w = await requestFimRegWaiver({ entryKey, scopeType, scopeValue, action, reason: reasonTrim, expiresAt, rule });
        await onCreated?.(w);
      }
    } catch (e) { setErr(errMsg(e, 'Waiver request failed')); } finally { setBusy(false); }
  };

  return (
    <FimModal title="Request a waiver for a protected entry" onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>Cancel</button><button className={btnPrimary} disabled={busy || reasonErr || !!expiryErr} onClick={submit}>{busy ? 'Requesting...' : mode === 'collect' ? 'Add to pending changes' : 'Request waiver'}</button></>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        <div className="flex gap-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
          <ShieldAlert aria-hidden className="h-5 w-5 shrink-0" />
          <div>
            <p><RegText value={entryKey} mono /> is protected. <b>{WAIVER_ACTION_LABEL[action] ?? action}</b> needs a waiver bound to exactly this change.</p>
            <p className="mt-1">A different Super Admin (or a designated approver) must approve it; you cannot approve your own request. Coverage is restored automatically when the waiver expires, and you are alerted.</p>
            {mode === 'collect'
              ? <p className="mt-1"><b>Nothing is sent yet: the waiver is requested when you click Apply.</b> {WAIVER_FLOW_TEXT}</p>
              : <p className="mt-1"><b>The waiver is requested now.</b> {WAIVER_FLOW_TEXT}</p>}
          </div>
        </div>
        <dl className="text-sm">
          <dt className="text-xs font-semibold text-slate-500">Key</dt><dd><RegText value={entryPath} mono className="text-xs" /></dd>
          <dt className="mt-2 text-xs font-semibold text-slate-500">Change</dt><dd><RegText value={changeText} /></dd>
          <dt className="mt-2 text-xs font-semibold text-slate-500">Scope</dt><dd>{scopeType} <RegText value={scopeValue} mono className="text-xs" /></dd>
        </dl>
        <NoteField id="reg-waiver-reason" value={reason} onChange={setReason} minLength={10} maxLength={2000} rows={3} label="Reason (required, at least 10 characters)" hint="Why this protected coverage must be reduced, e.g. a change ticket." />
        <Field label={`Expires (at most ${days} days)`} htmlFor="reg-waiver-expiry" error={expiryErr}>
          <input id="reg-waiver-expiry" type="date" className={inputCls} min={min} max={max} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
        </Field>
      </div>
    </FimModal>
  );
}
