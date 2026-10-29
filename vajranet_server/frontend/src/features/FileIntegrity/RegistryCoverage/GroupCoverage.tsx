import { useCallback, useEffect, useMemo, useState } from 'react';
import { Plus, RefreshCw, Upload } from 'lucide-react';
import {
  createFimRegRule, getFimRegGroup, listFimRegProfiles, putFimRegAssignment, revokeFimRegRule,
  type FimRegEntry, type FimRegGroupCoverage, type FimRegLimits, type FimRegProfile, type FimRegPublishResult, type FimRegRule, type FimRegTier, type FimRegWaiver,
} from '../../../api/services/fimApi';
import { useConfirm } from '../../../context/useConfirm';
import { useToast } from '../../../context/useToast';
import { errMsg, errStatus, fmtTime } from '../constants';
import { Dropdown, EmptyBox, ErrorBanner, LoadingRows } from '../ui';
import { btnGhost, btnPrimary, cardCls, tdCls, thCls } from '../styles';
import { useFimNodes } from '../useFimNodes';
import { fmtBytes, fmtCount, safeText } from './safeText';
import { Banner, RegText, StatusChip, TierBadge } from './RegUi';
import { TIERS, TIER_LABEL, draftSummary, ruleSummary, waiverRequestedText, type RowAction, type RuleDraft } from './regModel';
import WaiverList from './WaiverList';
import EntriesTable from './EntriesTable';
import RulesList from './RulesList';
import RuleActionModal from './RuleActionModal';
import AddKeyModal from './AddKeyModal';
import NoteModal from './NoteModal';
import BulkInitModal, { type BulkInitTarget } from './BulkInitModal';
import HistoryDrawer from './HistoryDrawer';
import { groupPublishBody, publishReviewed } from './regActions';

type Assign = { profileId: number | null; tier: FimRegTier | null };

export function GroupView({ groupId, groupName, isSuperAdmin, limits }: { groupId: string; groupName: string; isSuperAdmin: boolean; limits: FimRegLimits | null }) {
  const confirm = useConfirm();
  const { showToast } = useToast();
  const [data, setData] = useState<FimRegGroupCoverage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<FimRegProfile[]>([]);
  const [assignDraft, setAssignDraft] = useState<Assign | null>(null);
  const [saveAssign, setSaveAssign] = useState(false);
  const [action, setAction] = useState<{ entry: FimRegEntry; action: RowAction } | null>(null);
  const [adding, setAdding] = useState(false);
  const [revoke, setRevoke] = useState<FimRegRule | null>(null);
  const [publishOpen, setPublishOpen] = useState(false);
  const [bigConfirm, setBigConfirm] = useState(false);
  const [summary, setSummary] = useState<{ published: number; failed: number; results: FimRegPublishResult[] } | null>(null);
  const [bulkInit, setBulkInit] = useState<BulkInitTarget[] | null>(null);
  const [history, setHistory] = useState(false);

  const [loading, setLoading] = useState(true);
  const [profilesErr, setProfilesErr] = useState<string | null>(null);
  const load = useCallback(async () => {
    setErr(null); setLoading(true);
    try { setData(await getFimRegGroup(groupId)); } catch (e) { setErr(errMsg(e, 'Failed to load the group coverage')); } finally { setLoading(false); }
  }, [groupId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { listFimRegProfiles().then((r) => { setProfiles(r.items ?? []); setProfilesErr(null); }).catch((e) => { setProfiles([]); setProfilesErr(errMsg(e, 'Could not load profiles')); }); }, []);
  const measureHosts = useMemo(() => (data?.members ?? []).slice(0, 200).map((m) => ({ host: m.host, label: m.hostname || m.host })), [data]);

  if (err && !data) return <ErrorBanner message={err} onRetry={load} />;
  if (!data) return loading ? <LoadingRows label="Loading group coverage" /> : <ErrorBanner message="The group coverage could not be loaded." onRetry={load} />;
  const stale = !!err;

  const canEdit = data.canManage;
  const current: Assign = { profileId: data.assignment?.profileId ?? null, tier: data.assignment?.tier ?? null };
  const shown = assignDraft ?? current;
  const assignChanged = shown.profileId !== current.profileId || shown.tier !== current.tier;
  const members = data.members;
  const big = members.length > (limits?.publishConfirmAbove ?? 200);
  const hostLabel = (h: string) => { const m = members.find((x) => x.host === h); return m?.hostname || h; };

  const waiverRequested = (w: FimRegWaiver) => {
    showToast(waiverRequestedText(w.id), 'success');
    setAction(null); setAdding(false); load();
  };

  const createRule = async (d: RuleDraft) => {
    const ok = await confirm({
      title: 'Create group rule?',
      description: `${safeText(draftSummary(d))} - applies to every member of ${safeText(groupName)} that has no more specific node rule. Members become Pending publish until you click "Apply to all members".`,
      confirmLabel: 'Create rule',
    });
    if (!ok) return;
    await createFimRegRule({ layer: 'group', scopeValue: groupId, ...d });
    showToast('Group rule created', 'success');
    setAction(null); setAdding(false); load();
  };

  const tierLabel = (t: FimRegTier) => {
    const o = data.tierOptions[t];
    return o ? `${TIER_LABEL[t]} - ${fmtCount(o.entries)} entries, ${fmtCount(o.rows)} rows, ${fmtBytes(o.bytes)}` : TIER_LABEL[t];
  };

  return (
    <div className="space-y-3">
      {err && <ErrorBanner message={err} onRetry={load} stale />}
      <header className={`${cardCls} p-4`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold"><RegText value={groupName} /></h3>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-violet-100 px-2 py-0.5 text-xs font-semibold text-violet-700 dark:bg-violet-500/15 dark:text-violet-300">Profile: <RegText value={data.profile.name} /> ({safeText(data.profile.source)})</span>
              <TierBadge tier={data.tier.value} suffix={`from ${data.tier.source}`} />
              <span className="text-xs text-slate-500">{fmtCount(data.totals.entries)} entries, {fmtCount(data.totals.rows)} rows, {fmtBytes(data.totals.bytes)} per member without node rules</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className={btnGhost} onClick={load} disabled={loading}><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />{loading ? 'Reloading...' : 'Reload'}</button>
            <button className={btnGhost} onClick={() => setHistory(true)}>History</button>
            {canEdit && <button className={btnPrimary} disabled={members.length === 0 || stale} title={stale ? 'Reload first: this view may be out of date' : undefined} onClick={() => { setBigConfirm(false); setPublishOpen(true); }}><Upload className="h-4 w-4" />Apply to all members ({members.length})</button>}
          </div>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-[1fr_1fr_auto] items-end">
          <div>
            <p className="mb-1 text-xs font-semibold text-slate-600 dark:text-slate-300">Group tier</p>
            <Dropdown aria-label="Group tier" value={shown.tier ?? ''} disabled={!canEdit} placeholder="Inherit from profile" onChange={(v) => setAssignDraft({ ...shown, tier: v ? (v as FimRegTier) : null })} options={TIERS.map((t) => ({ value: t, label: tierLabel(t) }))} />
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold text-slate-600 dark:text-slate-300">Group profile</p>
            <Dropdown aria-label="Group profile" value={shown.profileId === null ? '' : String(shown.profileId)} disabled={!canEdit} placeholder="Default profile" onChange={(v) => setAssignDraft({ ...shown, profileId: v ? Number(v) : null })}
              options={profiles.map((p) => ({ value: String(p.id), label: `${safeText(p.name)}${p.isDefault ? ' (default)' : ''} - ${TIER_LABEL[p.tier]}` }))} />
            {profilesErr && <p className="mt-1 text-xs text-red-600 dark:text-red-400">Profiles unavailable: {safeText(profilesErr)}</p>}
          </div>
          {canEdit && <div className="flex gap-2"><button className={btnPrimary} disabled={!assignChanged || stale} onClick={() => setSaveAssign(true)}>Save assignment</button>{assignChanged && <button className={btnGhost} onClick={() => setAssignDraft(null)}>Undo</button>}</div>}
        </div>
      </header>

      {data.errors.length > 0 && <Banner tone="error"><ul className="list-disc pl-4">{data.errors.map((e, i) => <li key={i}><RegText value={e} /></li>)}</ul></Banner>}
      {data.blocked.length > 0 && <Banner tone="warn"><b>Blocked rules ({data.blocked.length})</b>: not applied until an approved waiver exists.<ul className="list-disc pl-4 text-xs">{data.blocked.map((b, i) => <li key={`${b.ruleId}-${i}`}>{safeText(b.layer)} rule #{b.ruleId} {safeText(b.op)} <RegText value={b.entryKey || b.target} mono />: <RegText value={b.reason} /></li>)}</ul></Banner>}
      {data.warnings.length > 0 && <Banner tone="warn"><ul className="list-disc pl-4 text-xs">{data.warnings.map((w, i) => <li key={i}><RegText value={w} /></li>)}</ul></Banner>}

      {summary && (
        <Banner tone={summary.failed ? 'warn' : 'info'}>
          <b>Last publish:</b> {summary.published} published, {summary.failed} failed, {summary.results.filter((r) => r.needsInit.length > 0).length} node(s) with new entries needing Initialize.
          {summary.results.some((r) => r.error) && <ul className="mt-1 list-disc pl-4 text-xs">{summary.results.filter((r) => r.error).map((r) => <li key={r.host}><RegText value={hostLabel(r.host)} />: <RegText value={r.error} /></li>)}</ul>}
        </Banner>
      )}

      <div className={cardCls}>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 p-3 dark:border-white/10">
          <h4 className="text-sm font-semibold">Effective entries for a member without node rules ({data.entries.length})</h4>
          {canEdit && <button className={btnGhost} onClick={() => setAdding(true)}><Plus className="h-4 w-4" />Add key</button>}
        </div>
        <EntriesTable entries={data.entries} canManage={canEdit} onAction={(entry, a) => setAction({ entry, action: a })} />
      </div>

      <div className={`${cardCls} space-y-4 p-4`}>
        <RulesList title="Group rules" rules={data.rules.group} onRevoke={canEdit ? setRevoke : undefined} emptyText="No group rules." />
        <RulesList title="Profile rules (edit in Profiles)" rules={data.rules.profile} />
        {data.waivers.length > 0 && (
          <WaiverList title={`Waivers for this group (${data.waivers.length})`} waivers={data.waivers} isSuperAdmin={isSuperAdmin} onApplied={load} />
        )}
      </div>

      <div className={cardCls}>
        <h4 className="border-b border-slate-200 p-3 text-sm font-semibold dark:border-white/10">Members ({members.length})</h4>
        {members.length === 0 ? <EmptyBox title="No Windows members" /> : (
          <div className="max-h-[50vh] overflow-auto">
            <table className="w-full min-w-[760px]">
              <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800"><tr><th className={thCls}>Host</th><th className={thCls}>Status</th><th className={thCls}>Profile</th><th className={thCls}>Tier</th><th className={thCls}>Entries</th><th className={thCls}>Node overrides</th><th className={thCls}>Real-time</th><th className={thCls}>Published</th></tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                {members.map((m) => (
                  <tr key={m.host}>
                    <td className={tdCls}><RegText value={m.hostname || m.host} /></td>
                    <td className={tdCls}><StatusChip status={m.status} needsInit={m.needsInit} stale={stale} /></td>
                    <td className={tdCls}><RegText value={m.profileName ?? '-'} /></td>
                    <td className={tdCls}>{m.tier ? TIER_LABEL[m.tier] : '-'}</td>
                    <td className={`${tdCls} tabular-nums`}>{m.entries}</td>
                    <td className={`${tdCls} tabular-nums ${m.nodeRules ? 'font-semibold text-indigo-700 dark:text-indigo-300' : ''}`}>{m.nodeRules}</td>
                    <td className={tdCls}>{m.realtimeAvailable ? 'yes' : 'no'}</td>
                    <td className={`${tdCls} whitespace-nowrap text-xs`}>{fmtTime(m.publishedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {action && (
        <RuleActionModal entry={action.entry} action={action.action} layer="group" scopeValue={groupId} limits={limits} allowRecursive={isSuperAdmin}
          submitLabel="Create group rule" onClose={() => setAction(null)} onSubmit={createRule} waiverMode="submit" onWaiverRequested={waiverRequested} />
      )}
      {adding && (
        <AddKeyModal measureHosts={measureHosts} existing={new Set(data.entries.map((e) => e.entryKey))} existingPaths={data.entries.map((e) => ({ entryKey: e.entryKey, path: e.path }))}
          isSuperAdmin={isSuperAdmin} submitLabel="Create group rule" onClose={() => setAdding(false)} onSubmit={createRule}
          waiverScope={{ scopeType: 'group', scopeValue: groupId, maxDays: limits?.waiverMaxDays, onRequested: waiverRequested }} />
      )}
      {revoke && (
        <NoteModal title={`Revoke group rule #${revoke.id}?`} confirmLabel="Revoke rule" danger noteLabel="Reason (required)"
          description={<><RegText value={ruleSummary(revoke)} />. Members become Pending publish until you Apply.</>}
          onClose={() => setRevoke(null)}
          onSubmit={async (reason) => { await revokeFimRegRule(revoke.id, reason); showToast('Rule revoked', 'success'); setRevoke(null); load(); }} />
      )}
      {saveAssign && (
        <NoteModal title="Save group assignment?" confirmLabel="Save" noteLabel="Reason (required)"
          description={<>Profile {shown.profileId === null ? 'default' : <RegText value={profiles.find((p) => p.id === shown.profileId)?.name ?? `#${shown.profileId}`} />}, tier {shown.tier ? TIER_LABEL[shown.tier] : 'inherit from profile'}. Members whose node assignment does not override it become Pending publish until you click &quot;Apply to all members&quot;.</>}
          onClose={() => setSaveAssign(false)}
          onSubmit={async (reason) => {
            try {
              await putFimRegAssignment('group', groupId, { ...shown, reason, ...(data.assignment ? { version: data.assignment.version } : {}) });
            } catch (e) {
              if (errStatus(e) === 409) { setSaveAssign(false); setAssignDraft(null); showToast(`Someone else changed this assignment; reloaded. (${safeText(errMsg(e, 'conflict'))})`, 'error'); load(); return; }
              throw e;
            }
            showToast('Group assignment saved', 'success'); setSaveAssign(false); setAssignDraft(null); load();
          }} />
      )}
      {publishOpen && (
        <NoteModal title={`Apply to all ${members.length} members of ${safeText(groupName)}?`} confirmLabel="Publish" disabled={big && !bigConfirm} onClose={() => setPublishOpen(false)}
          description={<>Re-resolves and publishes the managed registry policy of every member (in batches on the server). Members whose configuration did not change are not touched. New entries are offered for Initialize afterwards; nothing is initialised automatically.</>}
          onSubmit={async (note) => {
            const out = await publishReviewed(groupPublishBody(groupId, data, note, big));
            if (out.stale) { setPublishOpen(false); showToast(safeText(out.message), 'error'); load(); return; }
            const r = out.res;
            const results = Array.isArray(r?.results) ? r.results : [];
            setPublishOpen(false); setSummary({ published: r?.published ?? 0, failed: r?.failed ?? 0, results }); load();
            const bad = results.filter((x) => x.error || x.status === 'invalid').length;
            if (results.length === 0) showToast('The server returned no per-node publish results: treat the members as NOT published, review and publish again.', 'error');
            else showToast(`${r.published} published, ${r.failed} failed${bad && !r.failed ? `, ${bad} invalid` : ''}`, r.failed || bad ? 'error' : 'success');
            const targets = results.filter((x) => !x.error && x.needsInit.length > 0 && x.policyId !== null)
              .map((x) => ({ host: x.host, hostLabel: hostLabel(x.host), policyId: x.policyId as number, slots: x.needsInit }));
            if (targets.length) setBulkInit(targets);
          }}>
          {big && (
            <label className="flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
              <input type="checkbox" className="mt-1" checked={bigConfirm} onChange={(e) => setBigConfirm(e.target.checked)} />
              <span>I confirm publishing to {members.length} nodes. Bulk publishes over {limits?.publishConfirmAbove ?? 200} hosts raise an audit alert.</span>
            </label>
          )}
          <p className="text-xs text-slate-500">Publishes the group coverage exactly as shown here: if it changed since this view was loaded, the server refuses and the view is reloaded for review.</p>
        </NoteModal>
      )}
      {bulkInit && <BulkInitModal targets={bulkInit} title={`Initialize new entries on ${bulkInit.length} node(s) now?`} onClose={() => { setBulkInit(null); load(); }} />}
      {history && <HistoryDrawer scopeType="group" scopeValue={groupId} title={`History: ${safeText(groupName)}`} canRollback={canEdit} onClose={() => setHistory(false)} onRolledBack={load} />}
    </div>
  );
}

/** Groups sub-view: group picker plus the group's coverage, rules, assignment and members. */
export default function GroupCoverage({ isSuperAdmin, limits }: { isSuperAdmin: boolean; limits: FimRegLimits | null }) {
  const { groups, loading, error } = useFimNodes();
  const [groupId, setGroupId] = useState('');
  const g = groups.find((x) => x.groupId === groupId);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Dropdown aria-label="Group" value={groupId} onChange={setGroupId} placeholder={loading ? 'Loading groups...' : 'Choose a group'} className="w-72"
          options={groups.map((x) => ({ value: x.groupId, label: `${safeText(x.name)} (${x.nodeCount} hosts)` }))} />
        {error && <span className="text-xs text-red-600">{error}</span>}
      </div>
      {!groupId ? <div className={cardCls}><EmptyBox title="Choose a group" description="Group rules and the group's profile/tier apply to every member without a more specific node setting." /></div>
        : <GroupView key={groupId} groupId={groupId} groupName={g?.name ?? groupId} isSuperAdmin={isSuperAdmin} limits={limits} />}
    </div>
  );
}
