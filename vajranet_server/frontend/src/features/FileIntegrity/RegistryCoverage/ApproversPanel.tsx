import { useEffect, useState } from 'react';
import { listFimRegApproverCandidates, putFimRegApprovers, type FimRegApproverCandidate, type FimRegSettings } from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { errMsg } from '../constants';
import { ErrorBanner, LoadingRows } from '../ui';
import { btnGhost } from '../styles';
import { RegText } from './RegUi';
import NoteModal from './NoteModal';

/** Super Admin: designated waiver approvers (two-person rule when there is a single Super Admin). */
export default function ApproversPanel({ settings, onSaved }: { settings: FimRegSettings; onSaved: (s: FimRegSettings) => void }) {
  const { showToast } = useToast();
  const [editing, setEditing] = useState(false);
  const approvers = settings.approvers ?? [];
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 text-sm dark:border-white/10 dark:bg-slate-900" aria-label="Waiver approvers">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="font-semibold text-slate-800 dark:text-slate-100">Waiver approvers</h3>
          <p className="text-xs text-slate-500">Super Admins and these designated approvers can approve waivers; nobody can approve their own request.</p>
        </div>
        <button className={btnGhost} onClick={() => setEditing(true)}>Edit approvers</button>
      </div>
      <p className="mt-2 text-xs">{approvers.length === 0 ? 'No designated approvers (Super Admins only).' : approvers.map((a, i) => <span key={a.userId}>{i > 0 && ', '}<RegText value={a.email} /></span>)}</p>
      {editing && <EditApprovers current={approvers.map((a) => a.userId)} onClose={() => setEditing(false)}
        onSaved={(s) => { setEditing(false); onSaved(s); showToast('Waiver approvers saved', 'success'); }} />}
    </section>
  );
}

function EditApprovers({ current, onClose, onSaved }: { current: number[]; onClose: () => void; onSaved: (s: FimRegSettings) => void }) {
  const [items, setItems] = useState<FimRegApproverCandidate[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<Set<number>>(() => new Set(current));
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancel = false;
    setLoading(true); setErr(null);
    listFimRegApproverCandidates().then((r) => { if (!cancel) setItems(r.items ?? []); })
      .catch((e) => { if (!cancel) setErr(errMsg(e, 'Failed to load approver candidates')); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [tick]);
  const toggle = (id: number) => setSel((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  return (
    <NoteModal title="Designated waiver approvers" confirmLabel="Save approvers" onClose={onClose} disabled={!items} noteLabel="Reason (required)"
      description={<p>Approvers can approve waivers requested by someone else. Choose admins you trust with protected-coverage reductions.</p>}
      onSubmit={async (note) => { onSaved(await putFimRegApprovers({ userIds: [...sel], note })); }}>
      {err && <ErrorBanner message={err} onRetry={() => setTick((t) => t + 1)} />}
      {!items ? (loading ? <LoadingRows label="Loading candidates" /> : null) : items.length === 0 ? <p className="text-sm text-slate-500">No eligible admins.</p> : (
        <ul className="max-h-64 space-y-1 overflow-y-auto">
          {items.map((c) => (
            <li key={c.userId}><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={sel.has(c.userId)} onChange={() => toggle(c.userId)} /><RegText value={c.email} /> <span className="text-xs text-slate-500"><RegText value={c.role} /></span></label></li>
          ))}
        </ul>
      )}
    </NoteModal>
  );
}
