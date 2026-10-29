import { useState, type ReactNode } from 'react';
import { errMsg } from '../constants';
import { ErrorBanner, FimModal } from '../ui';
import { btnGhost, btnPrimary } from '../styles';
import { NoteField } from './RegUi';

/**
 * Generic "do something that needs a note" modal. `onSubmit` may throw: the server's message is
 * shown verbatim (as text). The parent closes the modal (usually inside onSubmit).
 */
export default function NoteModal({ title, description, confirmLabel, danger, minLength = 1, maxLength = 2000, noteLabel, noteHint, onSubmit, onClose, children, disabled }: {
  title: string; description?: ReactNode; confirmLabel: string; danger?: boolean; minLength?: number; maxLength?: number; noteLabel?: string; noteHint?: string;
  onSubmit: (note: string) => Promise<void>; onClose: () => void; children?: ReactNode; disabled?: boolean;
}) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ok = note.trim().length >= minLength && note.trim().length <= maxLength && !disabled;
  const submit = async () => {
    setBusy(true); setErr(null);
    try { await onSubmit(note.trim()); } catch (e) { setErr(errMsg(e, 'Request failed')); } finally { setBusy(false); }
  };
  return (
    <FimModal title={title} onClose={onClose}
      footer={<>
        <button className={btnGhost} onClick={onClose}>Cancel</button>
        <button className={danger ? `${btnPrimary} bg-red-600 hover:bg-red-700` : btnPrimary} disabled={busy || !ok} onClick={submit}>{busy ? 'Working...' : confirmLabel}</button>
      </>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        {description && <div className="text-sm text-slate-600 dark:text-slate-300">{description}</div>}
        {children}
        <NoteField id="reg-note-modal" value={note} onChange={setNote} minLength={minLength} maxLength={maxLength} label={noteLabel} hint={noteHint ?? 'Recorded in the audit trail.'} />
      </div>
    </FimModal>
  );
}
