import { useState } from 'react';
import { createFimRegProfile, updateFimRegProfile, type FimMode, type FimRegProfile, type FimRegTier } from '../../../api/services/fimApi';
import { useToast } from '../../../context/useToast';
import { MODE_HELP, MODE_LABEL, errMsg, errStatus, humanInterval } from '../constants';
import { Dropdown, ErrorBanner, Field, FimModal } from '../ui';
import { btnGhost, btnPrimary, inputCls } from '../styles';
import { Banner, NoteField } from './RegUi';
import { TIERS, TIER_HELP, TIER_LABEL } from './regModel';
import { safeText } from './safeText';

const MIN_INTERVAL = 300;
const MAX_INTERVAL = 86400;

/** Create or edit a profile (Super Admin). Updates carry `version`; a 409 means someone else saved first. */
export default function ProfileFormModal({ profile, onClose, onSaved, onConflict }: {
  profile?: FimRegProfile; onClose: () => void; onSaved: () => void; onConflict: () => void;
}) {
  const { showToast } = useToast();
  const [name, setName] = useState(profile?.name ?? '');
  const [description, setDescription] = useState(profile?.description ?? '');
  const [tier, setTier] = useState<FimRegTier>(profile?.tier ?? 'essential');
  const [interval, setIntervalSecs] = useState(String(profile?.scanIntervalSecs ?? 3600));
  const [mode, setMode] = useState<FimMode>(profile?.mode ?? 'enforce');
  const [isDefault, setIsDefault] = useState(profile?.isDefault ?? false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const secs = Number(interval);
  const intervalErr = !Number.isInteger(secs) || secs < MIN_INTERVAL || secs > MAX_INTERVAL ? `Between ${MIN_INTERVAL} and ${MAX_INTERVAL} seconds` : null;
  const nameErr = name.trim().length === 0 ? 'Name is required' : name.length > 120 ? 'At most 120 characters' : null;
  const affected = profile?.affectedNodes ?? 0;
  const downgrade = !!profile && TIERS.indexOf(tier) < TIERS.indexOf(profile.tier);
  const ok = !intervalErr && !nameErr && reason.trim().length >= 3;

  const submit = async () => {
    setBusy(true); setErr(null);
    const body = { name: name.trim(), description: description.trim(), tier, isDefault, scanIntervalSecs: secs, mode, reason: reason.trim() };
    try {
      if (profile) await updateFimRegProfile(profile.id, { ...body, version: profile.version });
      else await createFimRegProfile(body);
      showToast(profile ? 'Profile saved' : 'Profile created', 'success');
      onSaved();
    } catch (e) {
      if (errStatus(e) === 409) { showToast(`Someone else changed this profile; reloaded. ${safeText(errMsg(e, ''))}`, 'error'); onConflict(); return; }
      setErr(errMsg(e, 'Save failed'));
    } finally { setBusy(false); }
  };

  return (
    <FimModal title={profile ? `Edit profile` : 'New profile'} onClose={onClose}
      footer={<><button className={btnGhost} onClick={onClose}>Cancel</button><button className={btnPrimary} disabled={busy || !ok} onClick={submit}>{busy ? 'Saving...' : 'Save'}</button></>}>
      <div className="space-y-3">
        {err && <ErrorBanner message={err} />}
        {profile && <p className="text-sm font-semibold">Affected nodes: {affected.toLocaleString()}</p>}
        <Field label="Name" htmlFor="reg-prof-name" error={name ? nameErr : null}><input id="reg-prof-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} maxLength={120} /></Field>
        <Field label="Description" htmlFor="reg-prof-desc"><textarea id="reg-prof-desc" rows={2} className={inputCls} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={1000} /></Field>
        <Field label="Tier" htmlFor="reg-prof-tier" hint={TIER_HELP[tier]}>
          <Dropdown aria-label="Tier" value={tier} onChange={(v) => setTier(v as FimRegTier)} options={TIERS.map((t) => ({ value: t, label: TIER_LABEL[t] }))} />
        </Field>
        {downgrade && (
          <Banner tone={affected > 10 ? 'error' : 'warn'}>
            Tier downgrade ({TIER_LABEL[profile.tier]} to {TIER_LABEL[tier]}): entries of the higher tier are removed from {affected} node(s) at their next Apply (baseline rows soft-retired, open drift closed as ignored).
            {affected > 10 && ' This profile is used by more than 10 nodes: saving raises a configuration alert.'}
          </Banner>
        )}
        <Field label="Scan interval (seconds)" htmlFor="reg-prof-int" error={intervalErr} hint={!intervalErr ? humanInterval(secs) : undefined}>
          <input id="reg-prof-int" type="number" min={MIN_INTERVAL} max={MAX_INTERVAL} step={60} className={inputCls} value={interval} onChange={(e) => setIntervalSecs(e.target.value)} />
        </Field>
        <Field label="Mode" htmlFor="reg-prof-mode" hint={MODE_HELP[mode]}>
          <Dropdown aria-label="Mode" value={mode} onChange={(v) => setMode(v as FimMode)} options={(['enforce', 'learn'] as FimMode[]).map((m) => ({ value: m, label: MODE_LABEL[m] }))} />
        </Field>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
          <span>Default profile<span className="block text-xs text-slate-500">Used by every node with no node or group assignment. Only one profile is the default.</span></span></label>
        <NoteField id="reg-prof-reason" value={reason} onChange={setReason} minLength={3} label="Reason (required)" hint="Recorded in the audit trail." />
        <p className="text-xs text-slate-500">Saving does not publish: affected nodes become Pending publish until you publish them.</p>
      </div>
    </FimModal>
  );
}
