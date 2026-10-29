/**
 * NodesView Update History tab: Windows Update History.
 * API: nodesViewApi.getUpdateHistory (server dedupes repeated sync snapshots).
 * Refreshes when the agent comes online, when the tab regains visibility, or manually.
 */

import { useCallback, useEffect, useRef, useState, Fragment, useMemo } from 'react';
import type { NodeData } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import { nodesViewApi } from './nodesViewApi';
import { sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import { useLiveData } from '../../../context/useLiveData';
import { useToast } from '../../../context/useToast';
import { useConfirm } from '../../../context/useConfirm';
import Pagination from '../../../components/ui/pagination';

interface NodesViewUpdateHistoryProps {
  node: NodeData;
  wsConnected: boolean;
  wsSendMessage: (message: unknown, options?: { timeoutMs?: number }) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

interface PSResult {
  command_key: string;
  output?: string;
  error?: string;
  warning?: string;
}

interface PendingUpdateRow {
  index: number;
  update_id: string;
  revision: number;
  title: string;
  kb: string[];
  downloaded: boolean;
  mandatory: boolean;
  eula_accepted: boolean;
}

interface ScheduledTaskStatusRow {
  task_name: string;
  state: string;
  last_run_time: string | null;
  next_run_time: string | null;
  last_task_result: number | null;
}

interface UpdateHistoryRow {
  id: string;
  host_identifier: string;
  unixtime: string;
  client_app_id: string;
  date: string;
  description: string;
  hresult: string;
  operation: string;
  result_code: string;
  server_selection: string;
  service_id: string | null;
  support_url: string;
  title: string;
  update_id: string;
  update_revision: string;
}

const formatUnixTime = (value: string): string => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1000000000 || parsed > 4102444800) {
    return 'N/A';
  }
  return new Date(parsed * 1000).toLocaleString();
};

const getStatusBadge = (resultCode: string) => {
  const code = resultCode.toLowerCase();
  if (code.includes('succeed')) {
    return <span className="px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700">Succeeded</span>;
  } else if (code.includes('fail')) {
    return <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-700">Failed</span>;
  } else if (code.includes('progress') || code.includes('pending')) {
    return <span className="px-2 py-1 rounded text-xs font-medium bg-yellow-100 text-yellow-700">In Progress</span>;
  }
  return <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-700">{resultCode}</span>;
};

const NodesViewUpdateHistory = ({ node, wsConnected, wsSendMessage }: NodesViewUpdateHistoryProps) => {
  const WS_UPDATE_TIMEOUT_MS = 75_000;
  const { showToast } = useToast();
  const confirm = useConfirm();
  const [updates, setUpdates] = useState<UpdateHistoryRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wsActionLoading, setWsActionLoading] = useState<string | null>(null);
  const [pendingUpdates, setPendingUpdates] = useState<PendingUpdateRow[]>([]);
  const [selectedIndexes, setSelectedIndexes] = useState<Set<number>>(new Set());
  const [scheduledTasks, setScheduledTasks] = useState<ScheduledTaskStatusRow[]>([]);
  const [lastScheduleOutput, setLastScheduleOutput] = useState<unknown>(null);
  const hasLoadedOnceRef = useRef(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const hostId = node.host_identifier || String(node.id);
  const { nodeStatus } = useLiveData();
  const agentOnline = nodeStatus?.agentOnline?.includes(hostId) ?? false;
  const prevAgentOnline = useRef<boolean | null>(null);

  useEffect(() => {
    hasLoadedOnceRef.current = false;
    prevAgentOnline.current = null;
    setPendingUpdates([]);
    setScheduledTasks([]);
    setSelectedIndexes(new Set());
    setLastScheduleOutput(null);
  }, [hostId]);

  const sendPS = useCallback(
    async (keys: string[], arg1?: string): Promise<PSResult[]> => {
      const response = await wsSendMessage({
        type: 'agent',
        params: {
          agent: 'powershell',
          action: 'run',
          command_keys: keys,
          ...(arg1 !== undefined ? { arg1 } : {}),
        },
        host_identifier: hostId,
      }, { timeoutMs: WS_UPDATE_TIMEOUT_MS });
      const parsed = JSON.parse(String(response?.response ?? '[]'));
      return Array.isArray(parsed) ? (parsed as PSResult[]) : [];
    },
    [hostId, wsSendMessage],
  );

  const getErrors = (results: PSResult[]): string[] =>
    results.filter((r) => r.error && String(r.error).trim() !== '').map((r) => `${r.error}`);

  const getWarnings = (results: PSResult[]): string[] =>
    results.filter((r) => r.warning && String(r.warning).trim() !== '').map((r) => `${r.warning}`);

  const fetchPendingUpdates = useCallback(async () => {
    if (!wsConnected) return;
    setWsActionLoading('56');
    try {
      const results = await sendPS(['56']);
      const k56 = results.find((r) => r.command_key === '56');
      const parsed = JSON.parse(String(k56?.output ?? '[]'));
      setPendingUpdates(Array.isArray(parsed) ? (parsed as PendingUpdateRow[]) : []);
      setSelectedIndexes(new Set());
      const errs = getErrors(results);
      const warns = getWarnings(results);
      if (errs.length > 0) {
        showToast(`Pending updates fetch partial failure: ${errs.join(' | ')}`, 'error');
      } else if (warns.length > 0) {
        showToast(`Pending updates warning: ${warns.join(' | ')}`, 'error');
      }
    } catch (err: unknown) {
      showToast((err instanceof Error && err.message) || 'Failed to fetch pending updates.', 'error');
    } finally {
      setWsActionLoading(null);
    }
  }, [sendPS, showToast, wsConnected]);

  const fetchTaskStatus = useCallback(async () => {
    if (!wsConnected) return;
    setWsActionLoading('59');
    try {
      const results = await sendPS(['59']);
      const k59 = results.find((r) => r.command_key === '59');
      // key 59 may return empty string when no tasks exist; normalize to []
      const raw = String(k59?.output ?? '').trim();
      const parsed = JSON.parse(raw === '' ? '[]' : raw);
      setScheduledTasks(Array.isArray(parsed) ? (parsed as ScheduledTaskStatusRow[]) : []);
      const errs = getErrors(results);
      const warns = getWarnings(results);
      if (errs.length > 0) {
        showToast(`Task status partial failure: ${errs.join(' | ')}`, 'error');
      } else if (warns.length > 0) {
        showToast(`Task status warning: ${warns.join(' | ')}`, 'error');
      }
    } catch (err: unknown) {
      showToast((err instanceof Error && err.message) || 'Failed to fetch update task status.', 'error');
    } finally {
      setWsActionLoading(null);
    }
  }, [sendPS, showToast, wsConnected]);

  const scheduleInstallAll = useCallback(async () => {
    if (!wsConnected) return;
    const confirmed = await confirm({
      title: 'Schedule installation of all pending updates?',
      description: 'This may include cumulative or feature updates and can force a reboot during work hours on this endpoint.',
      confirmLabel: 'Schedule',
      variant: 'danger',
    });
    if (!confirmed) return;
    setWsActionLoading('57');
    try {
      const results = await sendPS(['57']);
      const k57 = results.find((r) => r.command_key === '57');
      const parsed = JSON.parse(String(k57?.output ?? '{}'));
      setLastScheduleOutput(parsed);
      const errs = getErrors(results);
      const warns = getWarnings(results);
      if (errs.length === 0) {
        showToast('Install-all task scheduled successfully.', 'success');
      } else {
        showToast(`Install-all partial failure: ${errs.join(' | ')}`, 'error');
      }
      if (warns.length > 0) {
        showToast(`Install-all warning: ${warns.join(' | ')}`, 'error');
      }
      await fetchTaskStatus();
    } catch (err: unknown) {
      showToast((err instanceof Error && err.message) || 'Failed to schedule install-all task.', 'error');
    } finally {
      setWsActionLoading(null);
    }
  }, [confirm, fetchTaskStatus, sendPS, showToast, wsConnected]);

  const selectedIndexesArray = useMemo(() => Array.from(selectedIndexes).sort((a, b) => a - b), [selectedIndexes]);

  const scheduleInstallSelected = useCallback(async () => {
    if (!wsConnected) return;
    setWsActionLoading('58');
    try {
      if (selectedIndexesArray.length === 0) {
        throw new Error('Select at least one update to schedule.');
      }

      const results = await sendPS(['58'], JSON.stringify(selectedIndexesArray));
      const k58 = results.find((r) => r.command_key === '58');
      const parsed = JSON.parse(String(k58?.output ?? '{}'));
      setLastScheduleOutput(parsed);
      const errs = getErrors(results);
      const warns = getWarnings(results);
      if (errs.length === 0) {
        showToast('Selected update install task scheduled.', 'success');
      } else {
        showToast(`Selected schedule partial failure: ${errs.join(' | ')}`, 'error');
      }
      if (warns.length > 0) {
        showToast(`Selected schedule warning: ${warns.join(' | ')}`, 'error');
      }
      await fetchTaskStatus();
    } catch (err: unknown) {
      showToast((err instanceof Error && err.message) || 'Failed to schedule selected update task.', 'error');
    } finally {
      setWsActionLoading(null);
    }
  }, [fetchTaskStatus, selectedIndexesArray, sendPS, showToast, wsConnected]);

  const load = useCallback(async () => {
    const isBackground = hasLoadedOnceRef.current;
    if (isBackground) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const res = await nodesViewApi.getUpdateHistory(hostId);
      const data = res.data?.data || [];
      setUpdates(Array.isArray(data) ? data : []);
      hasLoadedOnceRef.current = true;
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch update history');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hostId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!wsConnected) return;
    fetchPendingUpdates();
    fetchTaskStatus();
  }, [fetchPendingUpdates, fetchTaskStatus, wsConnected]);

  // Refetch when this host transitions from offline → online (new sync likely).
  useEffect(() => {
    if (prevAgentOnline.current === null) {
      prevAgentOnline.current = agentOnline;
      return;
    }
    if (agentOnline && prevAgentOnline.current === false) {
      load();
    }
    prevAgentOnline.current = agentOnline;
  }, [agentOnline, load]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === 'visible') load();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [load]);

  // Memoised, and the search term lower-cased once instead of four times per row. This ran
  // over the full update history on every render, including row expand/collapse.
  const filteredUpdates = useMemo(() => {
    if (!searchTerm) return updates;
    const needle = searchTerm.toLowerCase();
    return updates.filter(
      (row) =>
        row.title?.toLowerCase().includes(needle) ||
        row.description?.toLowerCase().includes(needle) ||
        row.operation?.toLowerCase().includes(needle) ||
        row.result_code?.toLowerCase().includes(needle)
    );
  }, [updates, searchTerm]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm]);

  const toggleRow = (id: string) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  const totalUpdates = filteredUpdates.length;
  const totalPages = Math.max(1, Math.ceil(totalUpdates / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedUpdates = filteredUpdates.slice(startIndex, endIndex);

  useEffect(() => {
    if (!expandedRow) return;
    const stillVisible = paginatedUpdates.some((r) => r.id === expandedRow);
    if (!stillVisible) setExpandedRow(null);
  }, [expandedRow, paginatedUpdates]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-8">
        <DuoSpinner size="lg" className="text-blue-600 mb-4" />
        <p className="text-gray-600">Loading update history...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-700 text-sm font-medium">Error loading update history:</p>
          <p className="text-red-600 text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 space-y-4">
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-center justify-between gap-4">
          <div>
            <h6 className="font-semibold text-gray-800">Windows Update Operations</h6>
            <p className="text-xs text-gray-600 mt-0.5">Pending updates, scheduling, and task status</p>
          </div>
          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
          </span>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={fetchPendingUpdates}
              disabled={!wsConnected || wsActionLoading != null}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-50"
            >
              {wsActionLoading === '56' ? 'Loading…' : 'Refresh Pending'}
            </button>
            <button
              type="button"
              onClick={scheduleInstallAll}
              disabled={!wsConnected || wsActionLoading != null}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-emerald-200 text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"
            >
              {wsActionLoading === '57' ? 'Scheduling…' : 'Schedule Install All'}
            </button>
            <button
              type="button"
              onClick={scheduleInstallSelected}
              disabled={!wsConnected || wsActionLoading != null}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-amber-200 text-amber-700 hover:bg-amber-50 disabled:opacity-50"
            >
              {wsActionLoading === '58' ? 'Scheduling…' : 'Schedule Selected'}
            </button>
            <button
              type="button"
              onClick={fetchTaskStatus}
              disabled={!wsConnected || wsActionLoading != null}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-purple-200 text-purple-700 hover:bg-purple-50 disabled:opacity-50"
            >
              {wsActionLoading === '59' ? 'Loading…' : 'Refresh Task Status'}
            </button>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="rounded-lg border border-gray-200 overflow-hidden">
              <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
                <p className="text-sm font-semibold text-gray-800">Pending Updates</p>
                <span className="text-xs text-gray-500">{pendingUpdates.length} item(s)</span>
              </div>
              <div className="max-h-80 overflow-auto">
                {pendingUpdates.length === 0 ? (
                  <p className="text-sm text-gray-500 p-3">No pending updates payload.</p>
                ) : (
                  <table className="w-full text-xs border-separate border-spacing-0">
                    <thead>
                      <tr>
                        <th className="text-left px-2 py-2 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Sel</th>
                        <th className="text-left px-2 py-2 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Index</th>
                        <th className="text-left px-2 py-2 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Title</th>
                        <th className="text-left px-2 py-2 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">KB</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pendingUpdates.map((u) => (
                        <tr key={`${u.update_id}-${u.revision}-${u.index}`} className="border-b last:border-0">
                          <td className="px-2 py-2">
                            <input
                              type="checkbox"
                              checked={selectedIndexes.has(u.index)}
                              onChange={(e) => {
                                setSelectedIndexes((prev) => {
                                  const next = new Set(prev);
                                  if (e.target.checked) next.add(u.index);
                                  else next.delete(u.index);
                                  return next;
                                });
                              }}
                            />
                          </td>
                          <td className="px-2 py-2 font-mono">{u.index}</td>
                          <td className="px-2 py-2 text-gray-700 max-w-[260px] truncate" title={u.title}>{u.title}</td>
                          <td className="px-2 py-2">{Array.isArray(u.kb) ? u.kb.join(', ') : ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            <div className="rounded-lg border border-gray-200 p-3 space-y-3">
              <div>
                <p className="text-sm font-semibold text-gray-800 mb-1">Task Status</p>
                {scheduledTasks.length === 0 ? (
                  <p className="text-xs text-gray-500">No scheduled tasks payload.</p>
                ) : (
                  <div className="space-y-2 max-h-40 overflow-auto">
                    {scheduledTasks.map((t) => (
                      <div key={t.task_name} className="rounded border border-gray-200 p-2 text-xs">
                        <p className="font-medium text-gray-800 break-all">{t.task_name}</p>
                        <p className="text-gray-600">State: {t.state || 'N/A'}</p>
                        <p className="text-gray-600">Last result: {t.last_task_result ?? 'N/A'}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <p className="text-sm font-semibold text-gray-800 mb-1">Last Schedule Output</p>
                <pre className="bg-gray-50 border border-gray-200 rounded p-2 text-[11px] overflow-auto max-h-36 whitespace-pre-wrap">
                  {lastScheduleOutput != null ? JSON.stringify(lastScheduleOutput, null, 2) : 'No output yet'}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        {/* Header */}
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-center justify-between gap-4">
          <h6 className="font-semibold text-gray-800">Windows Update History</h6>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-600">{filteredUpdates.length} updates</span>
            <button
              type="button"
              onClick={() => load()}
              disabled={refreshing}
              className="text-sm font-medium text-brand-700 hover:text-brand-900 disabled:opacity-50 px-2 py-1 rounded border border-brand-200 bg-white/80"
            >
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Search Bar */}
        <div className="px-4 py-3 border-b border-gray-200">
          <div className="relative">
            <i className="fa fa-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
            <input
              type="text"
              placeholder="Search by title, description, operation, or status..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(sanitizeAsciiSingleLine(e.target.value, 200, false))}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            />
          </div>
        </div>

        {/* Updates List */}
        <div className="overflow-x-auto">
          {filteredUpdates.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <i className="fa fa-info-circle text-3xl mb-2"></i>
              <p>No update history found{searchTerm ? ' for your search' : ''}.</p>
            </div>
          ) : (
            <table className="min-w-full divide-y divide-gray-200 border-separate border-spacing-0">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Date
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Title
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Operation
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {paginatedUpdates.map((row) => (
                  <Fragment key={row.id}>
                    <tr
                      className="hover:bg-gray-50 transition-colors cursor-pointer"
                      onClick={() => toggleRow(row.id)}
                    >
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                        {formatUnixTime(row.date || row.unixtime)}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900 max-w-md">
                        <div className="truncate" title={row.title}>
                          {row.title || 'N/A'}
                        </div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-700">
                        {row.operation || 'N/A'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm">
                        {getStatusBadge(row.result_code || 'Unknown')}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm">
                        <button
                          className="text-blue-600 hover:text-blue-800 font-medium rounded-lg"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleRow(row.id);
                          }}
                        >
                          {expandedRow === row.id ? (
                            <>
                              <i className="fa fa-chevron-up mr-1"></i> Hide
                            </>
                          ) : (
                            <>
                              <i className="fa fa-chevron-down mr-1"></i> Show
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                    {expandedRow === row.id && (
                      <tr>
                        <td colSpan={5} className="px-4 py-4 bg-gray-50">
                          <div className="space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Description</label>
                                <p className="text-sm text-gray-900 mt-1">{row.description || 'N/A'}</p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Client App ID</label>
                                <p className="text-sm text-gray-900 mt-1 font-mono">{row.client_app_id || 'N/A'}</p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Update ID</label>
                                <p className="text-sm text-gray-900 mt-1 font-mono break-all">
                                  {row.update_id || 'N/A'}
                                </p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Update Revision</label>
                                <p className="text-sm text-gray-900 mt-1">{row.update_revision || 'N/A'}</p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Server Selection</label>
                                <p className="text-sm text-gray-900 mt-1">{row.server_selection || 'N/A'}</p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Service ID</label>
                                <p className="text-sm text-gray-900 mt-1 font-mono break-all">
                                  {row.service_id || 'N/A'}
                                </p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">HResult</label>
                                <p className="text-sm text-gray-900 mt-1 font-mono">{row.hresult || 'N/A'}</p>
                              </div>
                              <div>
                                <label className="text-xs font-medium text-gray-500 uppercase">Support URL</label>
                                {row.support_url && /^https?:\/\//i.test(row.support_url) ? (
                                  <a
                                    href={row.support_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-sm text-blue-600 hover:text-blue-800 mt-1 block break-all"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {row.support_url} <i className="fa fa-external-link-alt text-xs"></i>
                                  </a>
                                ) : (
                                  <p className="text-sm text-gray-900 mt-1 break-all">{row.support_url || 'N/A'}</p>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          )}

          {filteredUpdates.length > 0 && (
            <Pagination
              page={safeCurrentPage}
              totalPages={totalPages}
              total={totalUpdates}
              pageSize={pageSize}
              onPageChange={(p) => setCurrentPage(p)}
              onPageSizeChange={(size) => { setPageSize(size); setCurrentPage(1); }}
              pageSizeOptions={[10, 25, 50]}
              itemLabel="updates"
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default NodesViewUpdateHistory;
