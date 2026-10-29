import { useCallback, useEffect, useState } from 'react';
import { getFimRegSettings, updateFimRegSettings, type FimRegSettings } from '../../api/services/fimApi';
import { useToast } from '../../context/useToast';
import { errMsg, fmtTime } from './constants';
import { ErrorBanner, LoadingRows, SegmentedControl } from './ui';
import { btnGhost, btnPrimary } from './styles';
import { Banner, HistoryKeyWarning, RegText } from './RegistryCoverage/RegUi';
import { historyUnkeyed } from './RegistryCoverage/regModel';
import NoteModal from './RegistryCoverage/NoteModal';
import RegistryHelp from './RegistryCoverage/RegistryHelp';
import NodeCoverage from './RegistryCoverage/NodeCoverage';
import GroupCoverage from './RegistryCoverage/GroupCoverage';
import ProfileEditor from './RegistryCoverage/ProfileEditor';
import WaiversView from './RegistryCoverage/WaiversView';
import NeedsInitView from './RegistryCoverage/NeedsInitView';
import MigrationView from './RegistryCoverage/MigrationView';
import ApproversPanel from './RegistryCoverage/ApproversPanel';

type View = 'nodes' | 'groups' | 'profiles' | 'waivers' | 'needs_init' | 'migration';

/** Per-node Windows registry coverage (managed registry policies). */
export default function RegistryTab() {
  const { showToast } = useToast();
  const [settings, setSettings] = useState<FimRegSettings | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<View>('nodes');
  const [toggle, setToggle] = useState<'enable' | 'disable' | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setErr(null); setLoading(true);
    try { setSettings(await getFimRegSettings()); } catch (e) { setErr(errMsg(e, 'Failed to load registry coverage settings')); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (err && !settings) return <ErrorBanner message={err} onRetry={load} />;
  if (!settings) return loading ? <LoadingRows label="Loading registry coverage" /> : <ErrorBanner message="Registry coverage settings could not be loaded." onRetry={load} />;

  const sa = settings.isSuperAdmin;
  const healthWarnings = (Array.isArray(settings.healthWarnings) ? settings.healthWarnings : []).filter((w) => typeof w === 'string' && w.trim() !== '');
  const views: { value: View; label: string }[] = [
    { value: 'nodes', label: 'Nodes' }, { value: 'groups', label: 'Groups' }, { value: 'profiles', label: 'Profiles' },
    { value: 'waivers', label: 'Waivers' }, { value: 'needs_init', label: 'Needs init' },
    ...(sa ? [{ value: 'migration' as View, label: 'Migration' }] : []),
  ];

  return (
    <div className="h-full overflow-y-auto pb-6 space-y-3">
      {err && <ErrorBanner message={err} onRetry={load} stale />}
      {settings.registryDisabledReason && (
        <div role="alert" data-testid="fim-registry-disabled" className="rounded-lg border-2 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:border-red-500/70 dark:bg-red-500/15 dark:text-red-100">
          <p className="font-semibold">Registry coverage changes are disabled by the server: <RegText value={settings.registryDisabledReason} /></p>
          <p className="text-xs">Existing managed policies keep running, but no rule, assignment, waiver, publish or rollback can be saved until this is fixed (set FIM_HISTORY_HMAC_KEY, at least 32 characters, and restart the backend).</p>
        </div>
      )}
      {healthWarnings.length > 0 && (
        <div role="status" data-testid="fim-health-warnings" className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
          <p className="font-semibold">Registry health warnings ({healthWarnings.length})</p>
          <ul className="mt-1 list-disc pl-5 text-xs">
            {healthWarnings.map((w, i) => <li key={i}><RegText value={w} /></li>)}
          </ul>
        </div>
      )}
      {historyUnkeyed(settings) && <HistoryKeyWarning detail={<>Registry history rows and rollbacks are chained with a plain SHA-256 instead of an HMAC, so someone with database access could rewrite history undetected. Set FIM_HISTORY_HMAC_KEY (at least 32 characters) on the server and remove FIM_HISTORY_ALLOW_UNKEYED.</>} />}
      {!settings.managedEnabled ? (
        <Banner tone="warn">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span><b>Registry coverage is not enabled.</b> Windows nodes have no managed registry policy. {sa ? '' : 'A Super Admin can enable it.'}</span>
            {sa && <button className={btnPrimary} onClick={() => setToggle('enable')}>Enable registry coverage</button>}
          </div>
        </Banner>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span className={err ? 'opacity-60' : ''}>Registry coverage enabled · catalog v{settings.catalogVersion}{settings.updatedBy ? <> · last changed by <RegText value={settings.updatedBy} /> {fmtTime(settings.updatedAt)}</> : null}</span>
          <span className="flex gap-2"><button className={`${btnGhost} px-2 py-1 text-xs`} onClick={load} disabled={loading}>{loading ? 'Refreshing...' : 'Refresh'}</button>{sa && <button className={`${btnGhost} px-2 py-1 text-xs text-red-600`} onClick={() => setToggle('disable')}>Disable registry coverage</button>}</span>
        </div>
      )}
      <RegistryHelp />
      {sa && <ApproversPanel settings={settings} onSaved={setSettings} />}
      <div className="overflow-x-auto"><SegmentedControl value={view} onChange={setView} size="sm" options={views} /></div>
      {view === 'nodes' && <NodeCoverage isSuperAdmin={sa} limits={settings.limits} />}
      {view === 'groups' && <GroupCoverage isSuperAdmin={sa} limits={settings.limits} />}
      {view === 'profiles' && <ProfileEditor isSuperAdmin={sa} limits={settings.limits} />}
      {view === 'waivers' && <WaiversView isSuperAdmin={sa} />}
      {view === 'needs_init' && <NeedsInitView />}
      {view === 'migration' && sa && <MigrationView isSuperAdmin={sa} />}

      {toggle === 'enable' && (
        <NoteModal title="Enable registry coverage?" confirmLabel="Enable and publish" onClose={() => setToggle(null)}
          description={<>
            <p>This creates and publishes a managed registry policy with <b>Essential</b> coverage (or each node's assigned profile) for <b>every Windows node</b>. New Windows nodes get it automatically.</p>
            <p className="mt-1"><b>No baselines are created.</b> Nodes appear in the Needs init queue and are not monitored until someone clicks Initialize.</p>
            <p className="mt-1">Hand-made Windows policies with registry entries keep running; see Migration to avoid double alerts.</p>
          </>}
          onSubmit={async (note) => { setSettings(await updateFimRegSettings({ managedEnabled: true, note, confirm: true })); showToast('Registry coverage enabled', 'success'); setToggle(null); }} />
      )}
      {toggle === 'disable' && (
        <NoteModal title="Disable registry coverage?" confirmLabel="Disable" danger onClose={() => setToggle(null)}
          description={<>
            <p>All managed registry policies are <b>disabled</b> (not deleted) in one step, so Windows nodes stop scanning managed registry keys.</p>
            <p className="mt-1">Drift history and baselines are kept. Turning it back on restores the policies; Initialize may be needed if more than 7 days have passed.</p>
          </>}
          onSubmit={async (note) => { setSettings(await updateFimRegSettings({ managedEnabled: false, note, confirm: true })); showToast('Registry coverage disabled', 'success'); setToggle(null); }} />
      )}
    </div>
  );
}
