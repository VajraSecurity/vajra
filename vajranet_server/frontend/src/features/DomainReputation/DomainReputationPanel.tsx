import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { isAxiosError } from 'axios';
import {
  Search, ListChecks, Settings2, ShieldOff, Globe2, Network, AlertCircle,
  Plus, Play, Trash2, PauseCircle, PlayCircle, Inbox, Info, Users,
} from 'lucide-react';
import { InlineSpinner, DuoSpinner } from '@/components/ui/loading';
import {
  checkDomainReputation, deleteDomainReputationTarget, getDomainReputationTargets,
  runDomainReputationTargetNow, updateDomainReputationTarget,
} from '../../api/api';
import type {
  DomainReputationGlobalProviderStatus, DomainReputationGroupScopedProviderStatus, DomainReputationProviderName,
  DomainReputationProviderStatus, DomainReputationResult, DomainReputationTarget, DomainReputationTargetType,
} from '../../api/api';
import VerdictBadge from './VerdictBadge';
import HistoryTable from './HistoryTable';
import GroupScopedProviderSettings from './GroupScopedProviderSettings';
import ManualServerSettings from './ManualServerSettings';
import WatchlistModal from './WatchlistModal';
import { SegmentedControl, CheckboxChip, FancySelect } from './ui';
import { useConfirm } from '../../context/useConfirm';
import { useDomainReputationMyGroups } from './useMyGroups';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

type SubTab = 'check' | 'watchlist' | 'settings';
const SUB_TAB_VALUES: readonly string[] = ['check', 'watchlist', 'settings'];

const ACCENT = 'rgb(9, 121, 112)';
const ALL_PROVIDERS: DomainReputationProviderName[] = ['manual', 'virustotal', 'abuseipdb'];
const CRON_LABEL: Record<string, string> = {
  '0 * * * *': 'Every hour',
  '0 */6 * * *': 'Every 6 hours',
  '0 */12 * * *': 'Every 12 hours',
  '0 0 * * *': 'Daily at midnight',
  '0 0 * * 0': 'Weekly (Sunday midnight)',
};
function formatCronSchedule(cronExpression: string): string {
  return CRON_LABEL[cronExpression] ?? cronExpression;
}
const PROVIDER_LABEL: Record<DomainReputationProviderName, string> = {
  manual: 'Vajra Reputation Engine',
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
};

function isGlobalStatus(s: DomainReputationProviderStatus | undefined): s is DomainReputationGlobalProviderStatus {
  return !!s && s.scope === 'global';
}
function isGroupScopedStatus(s: DomainReputationProviderStatus | undefined): s is DomainReputationGroupScopedProviderStatus {
  return !!s && s.scope === 'per_group';
}

interface DomainReputationPanelProps {
  providerStatuses: DomainReputationProviderStatus[];
  onConfigChange: () => void;
}

const DomainReputationPanel = ({ providerStatuses, onConfigChange }: DomainReputationPanelProps) => {
  // Active sub-tab lives in the URL (?subtab=...) rather than plain component state so
  // that a browser refresh lands back on the same sub-tab (e.g. Settings, Watchlist)
  // instead of always resetting to the default "check" view.
  const [searchParams, setSearchParams] = useSearchParams();
  const subTabParam = searchParams.get('subtab');
  const subTab: SubTab = SUB_TAB_VALUES.includes(subTabParam ?? '') ? (subTabParam as SubTab) : 'check';

  const setSubTab = (tab: SubTab) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('subtab', tab);
        return next;
      },
      { replace: true },
    );
  };

  const manualStatus = providerStatuses.find((s): s is DomainReputationGlobalProviderStatus => s.provider === 'manual' && isGlobalStatus(s));
  const virustotalStatus = providerStatuses.find((s): s is DomainReputationGroupScopedProviderStatus => s.provider === 'virustotal' && isGroupScopedStatus(s));
  const abuseipdbStatus = providerStatuses.find((s): s is DomainReputationGroupScopedProviderStatus => s.provider === 'abuseipdb' && isGroupScopedStatus(s));

  const anyConfigured = !!manualStatus?.configured
    || !!virustotalStatus?.configs.some((c) => c.configured)
    || !!abuseipdbStatus?.configs.some((c) => c.configured);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 mb-4 shrink-0">
        <SegmentedControl
          value={subTab}
          onChange={setSubTab}
          layoutId="domainReputationSubTabBg"
          accent={ACCENT}
          size="sm"
          options={[
            { value: 'check', label: 'Check Now', icon: <Search className="h-3.5 w-3.5" /> },
            { value: 'watchlist', label: 'Watchlist', icon: <ListChecks className="h-3.5 w-3.5" /> },
            { value: 'settings', label: 'Settings', icon: <Settings2 className="h-3.5 w-3.5" /> },
          ]}
        />
      </div>

      {subTab === 'settings' && (
        // Same white-card shell the Check Now / Watchlist tabs use (bg-white
        // rounded-2xl border shadow-sm) so Settings reads as one consistent
        // panel instead of cards floating directly on the page background.
        <div className="flex-1 min-h-0">
          <div className="h-full flex flex-col bg-white rounded-2xl border border-slate-200 shadow-sm">
            <div className="flex-1 min-h-0 overflow-y-auto scrollbar-hide p-6">
              <div className="grid items-stretch grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-x-6 gap-y-10">
                <ManualServerSettings status={manualStatus ?? null} onConfigChange={onConfigChange} />
                <GroupScopedProviderSettings
                  title="VirusTotal"
                  description="70+ AV engines & blocklists for domain/IP reputation."
                  status={virustotalStatus ?? null}
                  onConfigChange={onConfigChange}
                />
                <GroupScopedProviderSettings
                  title="AbuseIPDB"
                  description="Community-reported IP abuse confidence score."
                  status={abuseipdbStatus ?? null}
                  onConfigChange={onConfigChange}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {subTab === 'check' && (
        <div className="flex-1 min-h-0 flex flex-col">
          {!anyConfigured ? (
            <div className="bg-white rounded-2xl border border-dashed border-slate-300 p-10 text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-400">
                <ShieldOff className="h-5 w-5" />
              </div>
              <p className="text-sm font-semibold text-slate-700">No reputation providers configured</p>
              <p className="mt-1 text-sm text-slate-500 max-w-sm mx-auto">
                Configure your Vajra Reputation Engine, VirusTotal, or AbuseIPDB to run checks.
              </p>
              <button
                onClick={() => setSubTab('settings')}
                className="mt-5 inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg text-white shadow-sm transition-transform hover:-translate-y-0.5 active:translate-y-0"
                style={{ background: ACCENT }}
              >
                <Settings2 className="h-4 w-4" />
                Configure Providers
              </button>
            </div>
          ) : (
            <CheckNow manualStatus={manualStatus} virustotalStatus={virustotalStatus} abuseipdbStatus={abuseipdbStatus} />
          )}
        </div>
      )}

      {subTab === 'watchlist' && (
        <div className="flex-1 min-h-0 flex flex-col">
          <Watchlist virustotalStatus={virustotalStatus} abuseipdbStatus={abuseipdbStatus} />
        </div>
      )}
    </div>
  );
};

interface CheckNowProps {
  manualStatus: DomainReputationGlobalProviderStatus | undefined;
  virustotalStatus: DomainReputationGroupScopedProviderStatus | undefined;
  abuseipdbStatus: DomainReputationGroupScopedProviderStatus | undefined;
}

const CheckNow = ({ manualStatus, virustotalStatus, abuseipdbStatus }: CheckNowProps) => {
  const { myGroups, actableGroups } = useDomainReputationMyGroups();
  const [selectedGroupId, setSelectedGroupId] = useState('');

  // Shown only when there's a real choice to make: Super Admin picking among
  // the org default + every group, or a Group Admin who administers more
  // than one group (exactly one is auto-inferred server-side, so no picker
  // is needed for the common case).
  const showGroupPicker = !!myGroups && (myGroups.unrestricted ? myGroups.groups.length > 0 : actableGroups.length > 1);
  const groupPickerOptions = myGroups?.unrestricted
    ? [{ value: '', label: 'Organization Default' }, ...myGroups.groups.map((g) => ({ value: g.group_id, label: g.name }))]
    : actableGroups.map((g) => ({ value: g.group_id, label: g.name }));

  // Mirrors resolveWriteGroupId's server-side inference: explicit picker
  // choice first, then the lone actable group, then the org default. When
  // ambiguous (2+ actable groups) and nothing picked yet, this stays null so
  // the "configured" chips below correctly show nothing until a group is chosen.
  const resolvedGroupId: string | null = showGroupPicker
    ? (selectedGroupId || null)
    : (myGroups && !myGroups.unrestricted && actableGroups.length === 1 ? actableGroups[0].group_id : null);
  const groupUnresolved = showGroupPicker && !myGroups?.unrestricted && !selectedGroupId;

  const configuredFor = useCallback((p: DomainReputationProviderName): boolean => {
    if (p === 'manual') return !!manualStatus?.configured;
    const status = p === 'virustotal' ? virustotalStatus : abuseipdbStatus;
    return !!status?.configs.find((c) => c.group_id === resolvedGroupId)?.configured;
  }, [manualStatus, virustotalStatus, abuseipdbStatus, resolvedGroupId]);

  const [value, setValue] = useState('');
  const [type, setType] = useState<DomainReputationTargetType>('domain');
  const [selectedProviders, setSelectedProviders] = useState<DomainReputationProviderName[]>(
    ALL_PROVIDERS.filter((p) => (p === 'manual' ? manualStatus?.configured : (p === 'virustotal' ? virustotalStatus : abuseipdbStatus)?.configs.some((c) => c.configured))),
  );
  const [results, setResults] = useState<DomainReputationResult[]>([]);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const toggleProvider = (p: DomainReputationProviderName) => {
    setSelectedProviders((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]));
  };

  const handleCheck = async () => {
    if (!value.trim() || selectedProviders.length === 0) return;
    if (groupUnresolved && selectedProviders.some((p) => p !== 'manual')) {
      setError('Choose which group to run this check as');
      return;
    }
    setChecking(true);
    setError(null);
    setResults([]);
    try {
      const resp = await checkDomainReputation({
        value: value.trim(), type, providers: selectedProviders,
        ...(resolvedGroupId ? { group_id: resolvedGroupId } : {}),
      });
      setResults(resp.data);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(getErrorMessage(err, 'Check failed'));
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="h-full flex flex-col gap-4">
      <div className="shrink-0 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
        <div className="flex flex-col sm:flex-row gap-3 mb-4">
          <SegmentedControl
            value={type}
            onChange={setType}
            layoutId="domainReputationTargetType"
            accent={ACCENT}
            size="sm"
            options={[
              { value: 'domain', label: 'Domain', icon: <Globe2 className="h-3.5 w-3.5" /> },
              { value: 'ip', label: 'IP', icon: <Network className="h-3.5 w-3.5" /> },
            ]}
          />
          <div className="relative flex-1">
            {type === 'domain'
              ? <Globe2 className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              : <Network className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />}
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleCheck(); }}
              placeholder={type === 'domain' ? 'example.com' : '8.8.8.8'}
              className="w-full text-sm border border-slate-200 rounded-lg pl-9 pr-3 py-2 focus:outline-none focus:ring-2 focus:ring-emerald-200 focus:border-transparent"
            />
          </div>
          <button
            onClick={handleCheck}
            disabled={checking || !value.trim() || selectedProviders.length === 0}
            className="inline-flex items-center justify-center gap-2 px-5 py-2 text-sm font-semibold rounded-lg text-white shadow-sm transition-transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50 disabled:pointer-events-none disabled:translate-y-0"
            style={{ background: ACCENT }}
          >
            {checking ? <DuoSpinner size="sm" /> : <Search className="h-4 w-4" />}
            {checking ? 'Checking…' : 'Check'}
          </button>
        </div>

        {showGroupPicker && (
          <div className="mb-3 max-w-xs">
            <label className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">
              <Users className="h-3 w-3" /> Run VirusTotal/AbuseIPDB as
            </label>
            <FancySelect
              value={selectedGroupId}
              onChange={setSelectedGroupId}
              placeholder="Choose a group…"
              focusRing="focus-visible:ring-emerald-200"
              items={groupPickerOptions}
            />
          </div>
        )}

        <div className="flex flex-wrap gap-2.5">
          {ALL_PROVIDERS.map((p) => {
            const configured = configuredFor(p);
            return (
              <CheckboxChip
                key={p}
                checked={selectedProviders.includes(p)}
                disabled={!configured}
                onChange={() => toggleProvider(p)}
                label={PROVIDER_LABEL[p]}
                hint={!configured ? '(not configured)' : undefined}
                accent={ACCENT}
              />
            );
          })}
        </div>

        {error && (
          <div className="mt-3 flex items-center gap-2 text-sm text-red-600 bg-red-50 rounded-lg px-3 py-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {results.length > 0 && (
          <div className="mt-4 space-y-2">
            {results.map((r) => (
              <div key={r.provider} className="border border-slate-200 rounded-xl p-4 flex items-start gap-3 bg-slate-50/60">
                <span className="text-xs font-semibold text-slate-500 uppercase w-24 pt-0.5">{r.provider}</span>
                <VerdictBadge verdict={r.verdict} resolvedFromDomain={type === 'domain' && !!r.summary?.includes('(resolved to ')} />
                <p className="text-sm text-slate-600 flex-1">{r.summary}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex-1 min-h-0">
        <HistoryTable providers={ALL_PROVIDERS} refreshKey={refreshKey} />
      </div>
    </div>
  );
};

interface WatchlistProps {
  virustotalStatus: DomainReputationGroupScopedProviderStatus | undefined;
  abuseipdbStatus: DomainReputationGroupScopedProviderStatus | undefined;
}

const Watchlist = ({ virustotalStatus, abuseipdbStatus }: WatchlistProps) => {
  const [targets, setTargets] = useState<DomainReputationTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [runningId, setRunningId] = useState<number | null>(null);
  const confirm = useConfirm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getDomainReputationTargets();
      setTargets(resp.data);
      setLoadError(null);
    } catch (err) {
      setLoadError(getErrorMessage(err, 'Failed to load watchlist'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggleActive = async (target: DomainReputationTarget) => {
    await updateDomainReputationTarget(target.id, { isActive: !target.isActive });
    load();
  };

  const handleDelete = async (target: DomainReputationTarget) => {
    const confirmed = await confirm({
      title: `Remove ${target.value} from the watchlist?`,
      description: 'Its scheduled reputation checks will stop running and its check history will no longer be updated.',
      confirmLabel: 'Remove',
      variant: 'danger',
    });
    if (!confirmed) return;
    await deleteDomainReputationTarget(target.id);
    load();
  };

  const handleRunNow = async (target: DomainReputationTarget) => {
    setRunningId(target.id);
    try {
      await runDomainReputationTargetNow(target.id);
      await load();
    } finally {
      setRunningId(null);
    }
  };

  return (
    <div className="h-full flex flex-col gap-4">
      <div className="shrink-0 flex items-center justify-between gap-3">
        <p className="flex items-center gap-1.5 text-xs text-slate-400">
          <Info className="h-3.5 w-3.5 shrink-0" />
          Scheduled checks run against VirusTotal &amp; AbuseIPDB — Vajra Reputation Engine isn't schedulable, use Check Now instead.
        </p>
        <button
          onClick={() => setShowModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg text-white shadow-sm shrink-0 transition-transform hover:-translate-y-0.5 active:translate-y-0"
          style={{ background: ACCENT }}
        >
          <Plus className="h-4 w-4" />
          Add to Watchlist
        </button>
      </div>

      {loadError && (
        <div className="shrink-0 flex items-center justify-between gap-3 text-sm text-red-600 bg-red-50 rounded-lg px-3 py-2">
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {loadError}
          </span>
          <button onClick={() => void load()} className="font-semibold underline shrink-0">
            Try again
          </button>
        </div>
      )}

      {/* Outer div only carries the height budget (invisible, no chrome);
          the visible card below is max-h-full so it sizes to content — a
          short watchlist stays compact instead of stretching — while still
          capping at the budget and scrolling internally once it doesn't fit. */}
      <div className="flex-1 min-h-0">
        <div className="max-h-full flex flex-col bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="min-h-0 flex-1 overflow-auto scrollbar-auto-hide hover:scrollbar-auto-show">
            <table className="w-full text-sm border-separate border-spacing-0">
              <thead>
                <tr>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Value</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Group</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Providers</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Schedule</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Verdict</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Checked</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Active</th>
                  <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Actions</th>
                </tr>
              </thead>
              <tbody className={`divide-y divide-slate-100 transition-opacity ${loading && targets.length > 0 ? 'opacity-60 pointer-events-none' : ''}`}>
                {loading && targets.length === 0 && (
                  <tr><td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                    <InlineSpinner text="Loading…" size="sm" />
                  </td></tr>
                )}
                {!loading && !loadError && targets.length === 0 && (
                  <tr><td colSpan={8} className="px-4 py-12 text-center text-slate-400">
                    <Inbox className="h-6 w-6 mx-auto mb-2 text-slate-300" />
                    Watchlist is empty
                  </td></tr>
                )}
                {targets.length > 0 && targets.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-slate-800">{t.value} <span className="text-slate-400 font-normal">({t.type})</span></td>
                    <td className="px-4 py-2.5 text-slate-500">{t.group_name ?? 'Organization-wide'}</td>
                    <td className="px-4 py-2.5 text-slate-500">
                      {t.providers.map((p) => PROVIDER_LABEL[p as DomainReputationProviderName] ?? p).join(', ')}
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 text-xs" title={t.cronExpression}>{formatCronSchedule(t.cronExpression)}</td>
                    <td className="px-4 py-2.5">{t.lastVerdict ? <VerdictBadge verdict={t.lastVerdict} /> : <span className="text-slate-400">—</span>}</td>
                    <td className="px-4 py-2.5 text-slate-500">{t.lastCheckedAt ? new Date(t.lastCheckedAt).toLocaleString() : 'Never'}</td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => handleToggleActive(t)}
                        disabled={!t.canManage}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                          t.isActive ? 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100' : 'bg-slate-100 text-slate-500 hover:bg-slate-200'
                        }`}
                      >
                        {t.isActive ? <PlayCircle className="h-3 w-3" /> : <PauseCircle className="h-3 w-3" />}
                        {t.isActive ? 'Active' : 'Paused'}
                      </button>
                    </td>
                    <td className="px-4 py-2.5">
                      {t.canManage ? (
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => handleRunNow(t)}
                            disabled={runningId === t.id}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-blue-700 hover:underline disabled:opacity-50"
                          >
                            {runningId === t.id ? <DuoSpinner size="xs" className="size-3" /> : <Play className="h-3 w-3" />}
                            {runningId === t.id ? 'Running…' : 'Run Now'}
                          </button>
                          <button
                            onClick={() => handleDelete(t)}
                            className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 hover:underline"
                          >
                            <Trash2 className="h-3 w-3" />
                            Delete
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs text-slate-400">View only</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {showModal && (
        <WatchlistModal
          virustotalStatus={virustotalStatus}
          abuseipdbStatus={abuseipdbStatus}
          onClose={() => setShowModal(false)}
          onCreated={load}
        />
      )}
    </div>
  );
};

export default DomainReputationPanel;
