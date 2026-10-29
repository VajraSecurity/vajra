import { useState, useEffect, useMemo } from 'react';
import { Search, X, GitCompare, ShieldCheck, ShieldX, ListChecks, ShieldOff } from 'lucide-react';
import type { NodeData } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { nodesViewApi } from './nodesViewApi';
import { sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import Pagination from '../../../components/ui/pagination';

interface NodesViewFirewallRulesProps {
  node: NodeData;
}

interface FirewallRule {
  id: string;
  host_identifier: string;
  unixtime: string;
  name: string;
  app_name: string;
  action: string;
  enabled: number;
  grouping: string;
  direction: string;
  protocol: string;
  local_addresses: string;
  remote_addresses: string;
  local_ports: string;
  remote_ports: string;
  icmp_types_codes: string;
  profile_domain: number;
  profile_private: number;
  profile_public: number;
  service_name: string;
}

/** Diff entry shape (added/deleted rows and modified-row changesets from the diff endpoint). */
interface FirewallRuleDiffEntry {
  id?: string;
  name?: string;
  direction?: string;
  protocol?: string;
  action?: string;
  grouping?: string;
  app_name?: string;
  service_name?: string;
  local_addresses?: string;
  remote_addresses?: string;
  local_ports?: string;
  remote_ports?: string;
  icmp_types_codes?: string;
  profile_domain?: number;
  profile_private?: number;
  profile_public?: number;
  at_unixtime?: string;
  unixtime?: string;
  rule_identifier?: string;
  changes?: {
    old_state?: Record<string, unknown>;
    new_state?: Record<string, unknown>;
    from_unixtime?: string;
    to_unixtime?: string;
  };
}

interface FirewallRuleDiffData {
  added?: FirewallRuleDiffEntry[];
  deleted?: FirewallRuleDiffEntry[];
  modified?: FirewallRuleDiffEntry[];
  summary: {
    added_count: number;
    deleted_count: number;
    modified_count: number;
  };
  meta?: {
    actual_start?: string;
    actual_end?: string;
    snapshots_compared?: number;
  };
}

const toLocalISO = (unix: string) => {
  if (!unix) return '';
  const date = new Date(parseInt(unix) * 1000);
  // This adjusts the UTC time to the user's local timezone for the input display
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
};

// --- Diff Modal Component ---
const FirewallDiffModal = ({ hostId, availableTimes, onClose }: { hostId: string, availableTimes: string[], onClose: () => void }) => {
  // Initialize with the most recent and second-most recent snapshots from your data
  const [startTime, setStartTime] = useState(availableTimes[1] || availableTimes[0] || '');
  const [endTime, setEndTime] = useState(availableTimes[0] || '');
  const [diffData, setDiffData] = useState<FirewallRuleDiffData | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'added' | 'deleted' | 'modified'>('added');

  const formatUnixTime = (unix?: string) => {
    if (!unix) return 'N/A';
    const ts = Number(unix);
    if (!Number.isFinite(ts)) return 'N/A';
    return new Date(ts * 1000).toLocaleString();
  };

  const safeAscii = (value: unknown, maxLen = 220) => {
    const s = sanitizeAsciiSingleLine(String(value ?? ''), maxLen, false);
    return s && s.trim().length > 0 ? s : 'none';
  };

  const handleFetchDiff = async () => {
    if (!startTime || !endTime) return;
    setLoading(true);
    try {
      const res = await nodesViewApi.getFirewallRulesDiff(hostId, startTime, endTime);
      if (res.data.status === 'Success') {
        setDiffData(res.data.data);
      }
    } catch (err) {
      console.error("Failed to fetch diff:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
      <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col border border-slate-200/60 dark:border-slate-700">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-white dark:bg-slate-800">
          <div>
            <h3 className="text-lg font-bold text-slate-800 dark:text-slate-100">Firewall Rules Comparison</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Identify rule changes between specific dates and times.</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-full text-slate-400 dark:text-slate-500 transition-colors">
            <X className="size-4" />
          </button>
        </div>

        {/* Date & Time Selection */}
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900/40 border-b border-slate-200 dark:border-slate-700 grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            <label className="block text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase mb-1 tracking-wider">Start Date & Time</label>
            <input
              type="datetime-local"
              className="w-full h-9 px-3 border border-slate-200 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-800 dark:text-slate-200 focus:ring-3 focus:ring-blue-500/10 focus:border-blue-300 focus:outline-none transition-colors"
              value={toLocalISO(startTime)}
              onChange={(e) => {
                const dateVal = e.target.value;
                if (!dateVal) return;
                const unix = Math.floor(new Date(dateVal).getTime() / 1000);
                setStartTime(String(unix));
              }}
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase mb-1 tracking-wider">End Date & Time</label>
            <input
              type="datetime-local"
              className="w-full h-9 px-3 border border-slate-200 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-800 dark:text-slate-200 focus:ring-3 focus:ring-blue-500/10 focus:border-blue-300 focus:outline-none transition-colors"
              value={toLocalISO(endTime)}
              onChange={(e) => {
                const dateVal = e.target.value;
                if (!dateVal) return;
                const unix = Math.floor(new Date(dateVal).getTime() / 1000);
                setEndTime(String(unix));
              }}
            />
          </div>
          <button
            onClick={handleFetchDiff}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 bg-slate-800 dark:bg-blue-600 text-white rounded-lg h-9 px-4 text-sm font-semibold hover:bg-slate-700 dark:hover:bg-blue-500 disabled:opacity-50 transition-all shadow-sm active:scale-[0.98]"
          >
            <GitCompare className="size-4" />
            {loading ? 'Comparing…' : 'Generate Difference'}
          </button>
        </div>

        {/* Results Body */}
        <div className="p-6 overflow-y-auto flex-1 bg-white dark:bg-slate-800">
          {!diffData && !loading && (
            <div className="text-center py-20 text-slate-400 dark:text-slate-500 italic">
              Select dates and times above to compare firewall snapshots.
            </div>
          )}
          {loading && (
            <div className="flex items-center justify-center py-20">
              <DuoSpinner size="lg" className="text-slate-500" />
            </div>
          )}

          {diffData && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-3 items-center justify-between">
                <div>
                  <p className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wide">
                    Snapshot Range
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {formatUnixTime(diffData.meta?.actual_start)} → {formatUnixTime(diffData.meta?.actual_end)}
                    {' '}({diffData.meta?.snapshots_compared ?? 'N/A'} snapshots compared)
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30">
                    Added: {diffData.summary.added_count}
                  </span>
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-500/10 dark:text-rose-400 dark:border-rose-500/30">
                    Deleted: {diffData.summary.deleted_count}
                  </span>
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/30">
                    Modified: {diffData.summary.modified_count}
                  </span>
                </div>
              </div>

              {/* Tabs */}
              <div className="inline-flex gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-900/60">
                <button
                  type="button"
                  onClick={() => setActiveTab('added')}
                  className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${activeTab === 'added'
                      ? 'bg-white dark:bg-slate-700 text-emerald-700 dark:text-emerald-400 shadow-sm'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                    }`}
                >
                  Added ({diffData.summary.added_count})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('deleted')}
                  className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${activeTab === 'deleted'
                      ? 'bg-white dark:bg-slate-700 text-rose-700 dark:text-rose-400 shadow-sm'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                    }`}
                >
                  Deleted ({diffData.summary.deleted_count})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('modified')}
                  className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${activeTab === 'modified'
                      ? 'bg-white dark:bg-slate-700 text-amber-700 dark:text-amber-400 shadow-sm'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                    }`}
                >
                  Modified ({diffData.summary.modified_count})
                </button>
              </div>

              {/* Content */}
              {activeTab === 'added' && (
                <div className="space-y-3">
                  {diffData.added?.length ? (
                    diffData.added.map((r: FirewallRuleDiffEntry, i: number) => (
                      <div
                        key={r.id ? `${r.id}-${i}` : i}
                        className="p-3 rounded-lg border border-emerald-200 dark:border-emerald-500/30 bg-emerald-50/40 dark:bg-emerald-500/5 text-xs break-words shadow-sm"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-bold text-slate-800 dark:text-slate-100 truncate">{safeAscii(r.name, 240)}</div>
                            <div className="mt-1 text-slate-600 dark:text-slate-400 text-[11px] truncate">
                              {safeAscii(r.direction, 60)} | {safeAscii(r.protocol, 60)} | {safeAscii(r.action, 60)}
                            </div>
                          </div>
                          <div className="text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap">
                            {formatUnixTime(r.at_unixtime || r.unixtime)}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-slate-500 dark:text-slate-400 italic py-4">
                      No added rules found for this range.
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'deleted' && (
                <div className="space-y-3">
                  {diffData.deleted?.length ? (
                    diffData.deleted.map((r: FirewallRuleDiffEntry, i: number) => (
                      <div
                        key={r.id ? `${r.id}-${i}` : i}
                        className="p-3 rounded-lg border border-rose-200 dark:border-rose-500/30 bg-rose-50/40 dark:bg-rose-500/5 text-xs break-words shadow-sm"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-bold text-slate-800 dark:text-slate-100 truncate">{safeAscii(r.name, 240)}</div>
                            <div className="mt-1 text-slate-600 dark:text-slate-400 text-[11px] truncate">
                              {safeAscii(r.direction, 60)} | {safeAscii(r.protocol, 60)} | {safeAscii(r.action, 60)}
                            </div>
                          </div>
                          <div className="text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap">
                            {formatUnixTime(r.at_unixtime || r.unixtime)}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-slate-500 dark:text-slate-400 italic py-4">
                      No deleted rules found for this range.
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'modified' && (
                <div className="space-y-3">
                  {diffData.modified?.length ? (
                    diffData.modified.map((mod: FirewallRuleDiffEntry, i: number) => {
                      const oldState: Record<string, unknown> = mod.changes?.old_state ?? {};
                      const newState: Record<string, unknown> = mod.changes?.new_state ?? {};
                      const fromTs = mod.changes?.from_unixtime;
                      const toTs = mod.changes?.to_unixtime;

                      // Only compare / display fields that are relevant to firewall rule changes.
                      const fieldsToShow: string[] = [
                        'action',
                        'enabled',
                        'local_addresses',
                        'remote_addresses',
                        'local_ports',
                        'remote_ports',
                        'icmp_types_codes',
                        'app_name',
                        'service_name',
                        'grouping',
                        'profile_domain',
                        'profile_private',
                        'profile_public',
                      ];

                      const changedKeys = fieldsToShow.filter((key) => {
                        return String(oldState[key] ?? '') !== String(newState[key] ?? '');
                      });

                      const initialKeys = changedKeys.slice(0, 3);
                      const remainingKeys = changedKeys.slice(3);

                      const renderField = (key: string) => {
                        const oldVal = oldState[key];
                        const newVal = newState[key];
                        const label = key.replace(/_/g, ' ');
                        return (
                          <div key={key} className="flex items-center gap-2">
                            <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase w-[90px] shrink-0">
                              {safeAscii(label, 60)}
                            </span>
                            <span className="text-[11px] text-rose-600 dark:text-rose-400 line-through decoration-rose-300 dark:decoration-rose-500/50 min-w-0 truncate flex-1" title={safeAscii(oldVal, 320)}>
                              {safeAscii(oldVal, 110)}
                            </span>
                            <span className="text-[11px] text-slate-400 dark:text-slate-500 shrink-0">→</span>
                            <span className="text-[11px] text-emerald-700 dark:text-emerald-400 font-bold min-w-0 truncate flex-1" title={safeAscii(newVal, 320)}>
                              {safeAscii(newVal, 110)}
                            </span>
                          </div>
                        );
                      };

                      return (
                        <div
                          key={mod.rule_identifier ? String(mod.rule_identifier) : i}
                          className="p-3 rounded-lg border border-amber-200 dark:border-amber-500/30 bg-amber-50/30 dark:bg-amber-500/5 text-[11px] shadow-sm break-words"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-bold text-slate-800 dark:text-slate-100 truncate">{safeAscii(mod.name, 240)}</div>
                              <div className="mt-1 text-slate-600 dark:text-slate-400 text-[11px] truncate">
                                From {formatUnixTime(fromTs)} → {formatUnixTime(toTs)}
                              </div>
                            </div>
                            <div className="text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap">
                              {changedKeys.length} change(s)
                            </div>
                          </div>

                          <div className="mt-3 space-y-2">
                            {initialKeys.length ? initialKeys.map(renderField) : (
                              <div className="text-sm text-slate-500 dark:text-slate-400 italic">No field changes detected.</div>
                            )}
                            {remainingKeys.length > 0 && (
                              <details className="mt-1">
                                <summary className="cursor-pointer text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white">
                                  +{remainingKeys.length} more fields
                                </summary>
                                <div className="mt-2 space-y-2">
                                  {remainingKeys.map(renderField)}
                                </div>
                              </details>
                            )}
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-sm text-slate-500 dark:text-slate-400 italic py-4">
                      No modified rules found for this range.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};



const NodesViewFirewallRules = ({ node }: NodesViewFirewallRulesProps) => {
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [filterDirection, setFilterDirection] = useState<string>('all');
  const [filterEnabled, setFilterEnabled] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [isDiffModalOpen, setIsDiffModalOpen] = useState(false);
  const hostId = node.host_identifier || String(node.id);

  // Unique unixtimes for the diff dropdown. Memoised because building the Set walks
  // every firewall rule (thousands on a Windows host) and would otherwise re-run on
  // every keystroke in the search box and every pagination click.
  const availableTimes = useMemo(
    () =>
      Array.from(new Set(firewallRules.map((r) => String(r.unixtime))))
        .sort((a, b) => parseInt(b) - parseInt(a)),
    [firewallRules],
  );

  useEffect(() => {
    let cancelled = false;
    const loadFirewallRules = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await nodesViewApi.getFirewallRules(hostId);
        if (!cancelled) {
          if (res.data.status === 'Success' && res.data.data) {
            setFirewallRules(res.data.data);
          } else {
            setError(res.data.message || 'No firewall rules found');
          }
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err && typeof err === 'object' && 'response' in err
            ? (err as { response?: { data?: { message?: string } } }).response?.data?.message
            : undefined;
          setError(msg || 'Failed to fetch firewall rules');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadFirewallRules();
    return () => { cancelled = true; };
  }, [hostId]);

  // Memoised so expanding a single row does not re-filter every rule, with
  // searchTerm.toLowerCase() lifted out of the per-rule callback rather than
  // recomputed for each one.
  const filteredRules = useMemo(() => {
    const normalizedSearch = searchTerm.toLowerCase();
    return firewallRules.filter((rule) => {
      const matchesSearch =
        searchTerm === '' ||
        (rule.name || '').toLowerCase().includes(normalizedSearch) ||
        (rule.grouping || '').toLowerCase().includes(normalizedSearch) ||
        (rule.app_name || '').toLowerCase().includes(normalizedSearch) ||
        (rule.service_name || '').toLowerCase().includes(normalizedSearch);

      const matchesAction = filterAction === 'all' || rule.action === filterAction;
      const matchesDirection = filterDirection === 'all' || rule.direction === filterDirection;
      const matchesEnabled =
        filterEnabled === 'all' ||
        (filterEnabled === 'enabled' && rule.enabled === 1) ||
        (filterEnabled === 'disabled' && rule.enabled === 0);

      return matchesSearch && matchesAction && matchesDirection && matchesEnabled;
    });
  }, [firewallRules, searchTerm, filterAction, filterDirection, filterEnabled]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filterAction, filterDirection, filterEnabled]);

  const totalPages = Math.max(1, Math.ceil(filteredRules.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedRules = filteredRules.slice(startIndex, endIndex);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const renderBadge = (value: number, trueLabel: string = 'Yes', falseLabel: string = 'No') => {
    const isActive = value === 1;
    return (
      <span
        className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${isActive
          ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30'
          : 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-700/60 dark:text-slate-400 dark:border-slate-600'
          }`}
      >
        {isActive ? trueLabel : falseLabel}
      </span>
    );
  };

  const renderActionBadge = (action: string) => {
    const isAllow = action.toLowerCase() === 'allow';
    return (
      <span
        className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${isAllow
          ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30'
          : 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-500/10 dark:text-rose-400 dark:border-rose-500/30'
          }`}
      >
        {action}
      </span>
    );
  };

  const renderDirectionBadge = (direction: string) => {
    const isInbound = direction.toLowerCase() === 'in';
    return (
      <span
        className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${isInbound
          ? 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-500/10 dark:text-sky-400 dark:border-sky-500/30'
          : 'bg-violet-50 text-violet-700 border-violet-200 dark:bg-violet-500/10 dark:text-violet-400 dark:border-violet-500/30'
          }`}
      >
        {isInbound ? 'Inbound' : 'Outbound'}
      </span>
    );
  };

  const renderProfiles = (rule: FirewallRule) => (
    <div className="flex flex-wrap gap-1">
      {rule.profile_domain === 1 && (
        <span className="px-2 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-700/60 dark:text-slate-300 dark:border-slate-600 rounded text-xs">Domain</span>
      )}
      {rule.profile_private === 1 && (
        <span className="px-2 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-700/60 dark:text-slate-300 dark:border-slate-600 rounded text-xs">Private</span>
      )}
      {rule.profile_public === 1 && (
        <span className="px-2 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-700/60 dark:text-slate-300 dark:border-slate-600 rounded text-xs">Public</span>
      )}
      {rule.profile_domain !== 1 && rule.profile_private !== 1 && rule.profile_public !== 1 && (
        <span className="text-xs text-slate-400 dark:text-slate-500">Any</span>
      )}
    </div>
  );

  const renderPorts = (rule: FirewallRule) => (
    <div className="text-xs space-y-1 text-slate-600 dark:text-slate-400 min-w-0">
      {rule.local_ports && rule.local_ports !== '' && (
        <div className="truncate" title={`Local: ${rule.local_ports}`}>
          <span className="text-slate-500 dark:text-slate-500">Local:</span>{' '}
          <span className="text-slate-700 dark:text-slate-300">{rule.local_ports}</span>
        </div>
      )}
      {rule.remote_ports && rule.remote_ports !== '' && (
        <div className="truncate" title={`Remote: ${rule.remote_ports}`}>
          <span className="text-slate-500 dark:text-slate-500">Remote:</span>{' '}
          <span className="text-slate-700 dark:text-slate-300">{rule.remote_ports}</span>
        </div>
      )}
      {(!rule.local_ports || rule.local_ports === '') &&
        (!rule.remote_ports || rule.remote_ports === '') && (
          <span className="text-slate-400 dark:text-slate-500">Any</span>
        )}
    </div>
  );

  const uniqueActions = Array.from(new Set(firewallRules.map((r) => r.action)));
  const uniqueDirections = Array.from(new Set(firewallRules.map((r) => r.direction)));

  if (loading) {
    return (
      <div className="p-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40">
            <h6 className="font-semibold text-slate-800 dark:text-slate-100">Windows Firewall Rules</h6>
          </div>
          <div className="flex items-center justify-center py-12">
            <DuoSpinner size="lg" className="text-slate-500" />
          </div>
        </div>
      </div>
    );
  }

  if (error || firewallRules.length === 0) {
    return (
      <div className="p-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40">
            <h6 className="font-semibold text-slate-800 dark:text-slate-100">Windows Firewall Rules</h6>
          </div>
          <div className="p-5">
            <div className="text-sm p-3 rounded-lg bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/30">
              {error || 'No firewall rules available'}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const isFiltering =
    searchTerm !== '' || filterAction !== 'all' || filterDirection !== 'all' || filterEnabled !== 'all';

  const clearFilters = () => {
    setSearchTerm('');
    setFilterAction('all');
    setFilterDirection('all');
    setFilterEnabled('all');
  };

  const stats = [
    { label: 'Total Rules', value: firewallRules.length, icon: ListChecks, tone: 'text-slate-700 dark:text-slate-200' },
    { label: 'Enabled', value: firewallRules.filter((r) => r.enabled === 1).length, icon: ShieldCheck, tone: 'text-emerald-600 dark:text-emerald-400' },
    { label: 'Allow', value: firewallRules.filter((r) => r.action.toLowerCase() === 'allow').length, icon: ShieldCheck, tone: 'text-sky-600 dark:text-sky-400' },
    { label: 'Block', value: firewallRules.filter((r) => r.action.toLowerCase() === 'block').length, icon: ShieldX, tone: 'text-rose-600 dark:text-rose-400' },
  ];

  return (
    <div className="p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
        {/* Header: title + stat rail + search/filters + primary action, all in one row */}
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-700 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            <div className="relative w-full sm:w-56">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Search rules, apps, groups…"
                value={searchTerm}
                onChange={(e) => setSearchTerm(sanitizeAsciiSingleLine(e.target.value, 200, false))}
                aria-label="Search firewall rules"
                className="h-9 w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 pl-9 pr-8 text-sm text-slate-700 dark:text-slate-200 outline-none transition-colors placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-blue-300 dark:focus:border-blue-500 focus:ring-3 focus:ring-blue-500/10"
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={() => setSearchTerm('')}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-0.5 text-slate-400 dark:text-slate-500 transition-colors hover:bg-slate-200/70 dark:hover:bg-slate-600 hover:text-slate-600 dark:hover:text-slate-300"
                >
                  <X className="size-3.5" />
                </button>
              )}
            </div>
            <div className="hidden h-6 w-px bg-slate-200 dark:bg-slate-700 sm:block" />
            <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
              {stats.map(({ label, value, icon: Icon, tone }) => (
                <div key={label} className="flex items-center gap-1.5">
                  <Icon className={`size-3.5 ${tone}`} />
                  <span className={`text-sm font-semibold tabular-nums ${tone}`}>{value}</span>
                  <span className="text-xs text-slate-400 dark:text-slate-500">{label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="w-full shrink-0 sm:w-[150px]">
              <Select value={filterAction} onValueChange={(value) => setFilterAction(value as string)}>
                <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by action">
                  <SelectValue placeholder="All Actions">
                    {(value: string) => (value === 'all' ? 'All Actions' : value)}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Actions</SelectItem>
                  {uniqueActions.map((action) => <SelectItem key={action} value={action}>{action}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="w-full shrink-0 sm:w-[150px]">
              <Select value={filterDirection} onValueChange={(value) => setFilterDirection(value as string)}>
                <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by direction">
                  <SelectValue placeholder="All Directions">
                    {(value: string) => (value === 'all' ? 'All Directions' : value === 'In' ? 'Inbound' : 'Outbound')}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Directions</SelectItem>
                  {uniqueDirections.map((dir) => <SelectItem key={dir} value={dir}>{dir === 'In' ? 'Inbound' : 'Outbound'}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="w-full shrink-0 sm:w-[150px]">
              <Select value={filterEnabled} onValueChange={(value) => setFilterEnabled(value as string)}>
                <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by status">
                  <SelectValue placeholder="All Status">
                    {(value: string) => (value === 'enabled' ? 'Enabled Only' : value === 'disabled' ? 'Disabled Only' : 'All Status')}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="enabled">Enabled Only</SelectItem>
                  <SelectItem value="disabled">Disabled Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {isFiltering && (
              <button
                type="button"
                onClick={clearFilters}
                className="inline-flex h-9 items-center gap-1 rounded-lg px-2.5 text-sm font-medium text-blue-600 dark:text-blue-400 transition-colors hover:bg-blue-50 dark:hover:bg-blue-500/10"
              >
                <X className="size-3.5" /> Clear filters
              </button>
            )}
            <button
              onClick={() => setIsDiffModalOpen(true)}
              className="inline-flex shrink-0 items-center justify-center gap-2 h-9 px-4 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-600 hover:border-slate-400 dark:hover:border-slate-500 transition-all shadow-sm"
            >
              <GitCompare className="size-3.5 text-slate-500 dark:text-slate-400" />
              View Changes
            </button>
          </div>
        </div>

        <div className="hidden md:block w-full overflow-x-auto">
          <table className="min-w-[1100px] w-full table-fixed text-sm border-separate border-spacing-0">
            <colgroup>
              <col className="w-[43%]" />
              <col className="w-[8%]" />
              <col className="w-[10%]" />
              <col className="w-[7%]" />
              <col className="w-[9%]" />
              <col className="w-[10%]" />
              <col className="w-[13%]" />
            </colgroup>
            <thead>
              <tr>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Rule Name</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Action</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Direction</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Protocol</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Enabled</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Profiles</th>
                <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Ports</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/60">
              {paginatedRules.map((rule, index) => (
                <tr
                  key={`${rule.id}-${startIndex + index}`}
                  className="transition-colors hover:bg-slate-50/70 dark:hover:bg-slate-700/30"
                >
                  <td className="py-3 px-3">
                    <div className="min-w-0">
                      <div className="font-medium text-slate-800 dark:text-slate-100 truncate" title={rule.name}>{rule.name}</div>
                      {(rule.grouping || rule.app_name) && (
                        <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 truncate" title={rule.grouping || rule.app_name}>
                          {rule.grouping || rule.app_name}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">{renderActionBadge(rule.action)}</td>
                  <td className="py-3 px-3 whitespace-nowrap">{renderDirectionBadge(rule.direction)}</td>
                  <td className="py-3 px-3 text-slate-700 dark:text-slate-300 whitespace-nowrap">{rule.protocol || 'Any'}</td>
                  <td className="py-3 px-3 whitespace-nowrap">{renderBadge(rule.enabled, 'Enabled', 'Disabled')}</td>
                  <td className="py-3 px-3">
                    {renderProfiles(rule)}
                  </td>
                  <td className="py-3 px-3">
                    {renderPorts(rule)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Mobile fallback: stacked cards so Action/Direction/Enabled status is visible without horizontal scrolling */}
        <div className="space-y-3 p-4 md:hidden">
          {paginatedRules.map((rule, index) => (
            <div
              key={`m-${rule.id}-${startIndex + index}`}
              className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 space-y-2"
            >
              <div className="min-w-0">
                <div className="font-medium text-slate-800 dark:text-slate-100 truncate" title={rule.name}>{rule.name}</div>
                {(rule.grouping || rule.app_name) && (
                  <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400 truncate" title={rule.grouping || rule.app_name}>
                    {rule.grouping || rule.app_name}
                  </div>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {renderActionBadge(rule.action)}
                {renderDirectionBadge(rule.direction)}
                {renderBadge(rule.enabled, 'Enabled', 'Disabled')}
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs text-slate-600 dark:text-slate-400">
                <div>
                  <span className="block mb-1 font-medium text-slate-600 dark:text-slate-400 uppercase tracking-wide text-[10px]">Protocol</span>
                  {rule.protocol || 'Any'}
                </div>
                <div>
                  <span className="block mb-1 font-medium text-slate-600 dark:text-slate-400 uppercase tracking-wide text-[10px]">Profiles</span>
                  {renderProfiles(rule)}
                </div>
              </div>
              <div>
                <span className="block mb-1 font-medium text-slate-600 dark:text-slate-400 uppercase tracking-wide text-[10px]">Ports</span>
                {renderPorts(rule)}
              </div>
            </div>
          ))}
        </div>

        {filteredRules.length > 0 && (
          <Pagination
            page={safeCurrentPage}
            totalPages={totalPages}
            total={filteredRules.length}
            pageSize={pageSize}
            onPageChange={(p) => setCurrentPage(p)}
            onPageSizeChange={(size) => { setPageSize(size); setCurrentPage(1); }}
            pageSizeOptions={[10, 25, 50]}
          />
        )}

        {filteredRules.length === 0 && (
          <div className="flex flex-col items-center gap-3 py-14 text-center">
            <ShieldOff className="size-8 text-slate-300 dark:text-slate-600" />
            <div>
              <p className="text-sm font-medium text-slate-600 dark:text-slate-300">No firewall rules match your filters</p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Try adjusting or clearing the filters above.</p>
            </div>
            {isFiltering && (
              <button
                type="button"
                onClick={clearFilters}
                className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-500/10 transition-colors"
              >
                <X className="size-3.5" /> Clear filters
              </button>
            )}
          </div>
        )}
        {isDiffModalOpen && (
          <FirewallDiffModal
            hostId={hostId}
            availableTimes={availableTimes}
            onClose={() => setIsDiffModalOpen(false)}
          />
        )}
      </div>
    </div>
  );
};

export default NodesViewFirewallRules;
