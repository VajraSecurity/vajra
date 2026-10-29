import { useMemo, useState, useEffect, useCallback, useRef, isValidElement, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import api from '../../api/axiosInstance';
import { invalidateSessions, invalidateUserSessions } from '../../api/api';
import { DuoSpinner } from '@/components/ui/loading';
import { sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import { motion } from 'motion/react';
import { Meteors } from '@/components/ui/meteors';
import Pagination from '@/components/ui/pagination';
import { Usb, Network, Shield, History, Activity, SearchX, AlertTriangle } from 'lucide-react';
import EmptyState from '@/components/ui/EmptyState';
import type { AuditTrailEntry, SessionEntry, SortBy, SessionSortBy, SortOrder, TabId, AuditUserLite } from './types';
import { AuditUserRef } from './components/AuditUserRef';
import {
  ROWS_PER_PAGE, SEARCH_DEBOUNCE_MS, initialsFrom, timeAgo, formatDuration, formatAuditAction,
  WEBSOCKET_ACTIONS_CSV, ALERT_ACTIONS_CSV, isWebsocketLog, isAlertLog,
} from './utils/auditFormatters';













type AgentSortBy = 'user' | 'node' | 'type' | 'agent_action' | 'created_at';

// These three are pure functions of a log row, so they live at module scope: defined in
// the component body they get a fresh identity per render and nothing consuming them
// could be memoised.
const renderAgentType = (log: AuditTrailEntry) => {
  switch (log.action) {
    case 'PORT_BLOCK':
      return 'Port';
    case 'IP_BLOCK':
      return 'IP';
    case 'COMPLIANCE':
      return 'Compliance';
    case 'WIFI':
      return 'WiFi';
    case 'BLUETOOTH':
      return 'Bluetooth';
    case 'DEFENDER':
      return 'Defender';
    case 'USB':
      return 'USB';
    case 'CLAMAV':
      return 'ClamAV';
    default:
      return log.action;
  }
};

const renderAgentAction = (log: AuditTrailEntry) => {
  const d = log.details as Record<string, unknown> | null | undefined;
  const subAction = typeof d?.sub_action === 'string' ? (d.sub_action as string) : undefined;

  switch (log.action) {
    case 'PORT_BLOCK': {
      return subAction === 'allow' ? 'Allow' : 'Block';
    }
    case 'IP_BLOCK': {
      return subAction === 'allow' ? 'Allow' : 'Block';
    }
    case 'COMPLIANCE':
      return subAction ? subAction : 'Status';
    case 'WIFI':
      return subAction ? subAction : 'Status';
    case 'BLUETOOTH':
      return subAction ? subAction : 'Status';
    case 'DEFENDER':
      return subAction ? subAction : 'Status';
    case 'USB':
      return subAction ? subAction : 'Status';
    case 'CLAMAV':
      return subAction ? subAction : 'Status';
    default:
      return subAction ? subAction : 'Status';
  }
};

const agentSortKey = (log: AuditTrailEntry, column: AgentSortBy): string | number => {
  const d = (log.details ?? null) as Record<string, unknown> | null;
  const hostname = typeof d?.hostname === 'string' ? (d.hostname as string) : '';
  const hostId =
    typeof d?.host_identifier === 'string'
      ? (d.host_identifier as string)
      : typeof d?.host_identifier === 'number'
        ? String(d.host_identifier)
        : '';

  const user = [log.user_name ?? '', log.user_email ?? ''].filter(Boolean).join(' ').trim().toLowerCase();
  const node = [hostname, hostId].filter(Boolean).join(' ').trim().toLowerCase();

  switch (column) {
    case 'created_at': {
      const t = Date.parse(log.created_at);
      return Number.isFinite(t) ? t : 0;
    }
    case 'user':
      return user;
    case 'node':
      return node;
    case 'type':
      return renderAgentType(log).toLowerCase();
    case 'agent_action':
      return renderAgentAction(log).toLowerCase();
    default:
      return '';
  }
};

// One cached formatter and one pair of reference labels per grouping pass, rather than
// three Date objects and three toLocaleDateString() calls per log row. The keys are
// identical either way — toLocaleDateString with options is Intl.DateTimeFormat underneath.
const DAY_LABEL_FORMAT = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' });

const groupLogsByDay = <T extends { created_at: string }>(logs: T[]): [string, T[]][] => {
  const now = Date.now();
  const todayLabel = DAY_LABEL_FORMAT.format(now);
  const yesterdayLabel = DAY_LABEL_FORMAT.format(now - 86400000);
  const grouped: Record<string, T[]> = {};
  for (const log of logs) {
    // Intl.DateTimeFormat.format() THROWS RangeError on an invalid date, where
    // the toLocaleDateString() call this replaced returned the string
    // "Invalid Date" and let the page render with an oddly-titled group. One
    // bad created_at would otherwise crash the whole Notification Logs tab.
    // This file already treats created_at as untrustworthy — see agentSortKey's
    // Number.isFinite(Date.parse(...)) guard.
    const parsed = new Date(log.created_at);
    let key = Number.isNaN(parsed.getTime())
      ? 'Invalid Date'
      : DAY_LABEL_FORMAT.format(parsed);
    if (key === todayLabel) key = 'Today';
    else if (key === yesterdayLabel) key = 'Yesterday';
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(log);
  }
  return Object.entries(grouped);
};

// Must stay at module scope. DrawerRow is rendered in nine places plus a .map(), and as
// an inline declaration it gets a fresh function identity every render, so React sees a
// new element type and remounts every one of those rows instead of updating them.
const DrawerRow = ({ k, v }: { k: string; v: unknown }) => {
  const value =
    v == null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
      ? String(v ?? '—')
      : isValidElement(v)
        ? v
        : null;
  return (
    <div className="flex items-start justify-between gap-4 rounded-2xl border border-slate-200 bg-white px-3.5 py-2.5 shadow-[0_10px_26px_rgba(15,23,42,0.05)]">
      <div className="min-w-0">
        <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">{k}</div>
        <div className="mt-1 break-words text-sm font-semibold text-slate-900">
          {value ?? <span className="text-slate-500">Complex value</span>}
        </div>
      </div>
    </div>
  );
};

// Same reason as DrawerRow above: declared inside renderAuditActionCell, every call
// produces a new component type and React rebuilds the <a> elements rather than
// updating them.
const NameLink = ({ to, children }: { to: string; children: string }) => (
  <Link
    to={to}
    state={{ fromAuditTrail: true }}
    className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
  >
    {children}
  </Link>
);

const TAB_IDS: TabId[] = ['user', 'agent', 'alerts', 'sessions'];

const NotificationLogs = () => {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const [searchParams, setSearchParams] = useSearchParams();
  // activeTab is seeded from the ?tab= URL param (validated against the known tab
  // set) so a refresh lands back on whichever tab the admin was reviewing instead
  // of always resetting to "User activity". handleTabChange keeps the URL in sync
  // going forward.
  const [activeTab, setActiveTab] = useState<TabId>(() => {
    const tabParam = searchParams.get('tab');
    return TAB_IDS.includes(tabParam as TabId) ? (tabParam as TabId) : 'user';
  });
  const [selectedLog, setSelectedLog] = useState<AuditTrailEntry | null>(null);

  const [logs, setLogs] = useState<AuditTrailEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  // `null` = unknown, rendered as an em dash. A failed count must not fall back
  // to 0, which on an audit trail reads as "nothing was logged".
  const [totalByTab, setTotalByTab] = useState<Record<TabId, number | null>>({
    user: null,
    agent: null,
    alerts: null,
    sessions: null,
  });
  // Keeps "couldn't load" distinguishable from "nothing logged" in the table.
  const [logsError, setLogsError] = useState(false);
  const [sessionsError, setSessionsError] = useState(false);
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy] = useState<SortBy>('created_at');
  const [sortOrder] = useState<SortOrder>('desc');

  const [agentSortBy, setAgentSortBy] = useState<AgentSortBy>('created_at');
  const [agentSortOrder, setAgentSortOrder] = useState<SortOrder>('desc');

  const [sessions, setSessions] = useState<SessionEntry[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessionsPage, setSessionsPage] = useState(1);
  const [sessionsTotal, setSessionsTotal] = useState(0);
  const [sessionsTotalPages, setSessionsTotalPages] = useState(0);
  const [sessionSortBy, setSessionSortBy] = useState<SessionSortBy>('login_time');
  const [sessionSortOrder, setSessionSortOrder] = useState<SortOrder>('desc');
  const [expandedSessionId, setExpandedSessionId] = useState<number | null>(null);
  const [sessionActionsBySessionId, setSessionActionsBySessionId] = useState<Record<number, AuditTrailEntry[]>>({});
  const [sessionActionsLoadingBySessionId, setSessionActionsLoadingBySessionId] = useState<Record<number, boolean>>({});
  const [selectedSessionIds, setSelectedSessionIds] = useState<Set<number>>(new Set());
  const [isInvalidating, setIsInvalidating] = useState(false);

  // Monotonic request counters so a slow, stale fetchLogs/fetchSessions response
  // can't land after a newer one and overwrite fresher table state.
  const logsRequestId = useRef(0);
  const sessionsRequestId = useRef(0);

  const handleInvalidateSelected = async () => {
    if (selectedSessionIds.size === 0) return;
    const confirmed = await confirm({
      title: `Log out ${selectedSessionIds.size} session${selectedSessionIds.size === 1 ? '' : 's'}?`,
      confirmLabel: 'Log out',
      variant: 'danger',
    });
    if (!confirmed) return;

    setIsInvalidating(true);
    try {
      await invalidateSessions(Array.from(selectedSessionIds));
      setSelectedSessionIds(new Set());
      fetchSessions(sessionsPage, searchQuery, sessionSortBy, sessionSortOrder);
    } catch (error) {
      console.error('Failed to invalidate sessions:', error);
      showToast('Failed to log out selected sessions.', 'error');
    } finally {
      setIsInvalidating(false);
    }
  };

  const handleInvalidateUser = async (email: string) => {
    const confirmed = await confirm({
      title: `Log out all active sessions for ${email}?`,
      confirmLabel: 'Log out',
      variant: 'danger',
    });
    if (!confirmed) return;

    setIsInvalidating(true);
    try {
      await invalidateUserSessions(email);
      setSelectedSessionIds(new Set());
      fetchSessions(sessionsPage, searchQuery, sessionSortBy, sessionSortOrder);
    } catch (error) {
      console.error('Failed to invalidate user sessions:', error);
      showToast('Failed to log out all sessions for user.', 'error');
    } finally {
      setIsInvalidating(false);
    }
  };

  const handleInvalidateSingleSession = async (id: number) => {
    const confirmed = await confirm({
      title: 'Log out this session?',
      confirmLabel: 'Log out',
      variant: 'danger',
    });
    if (!confirmed) return;

    setIsInvalidating(true);
    try {
      await invalidateSessions([id]);
      setSelectedSessionIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      fetchSessions(sessionsPage, searchQuery, sessionSortBy, sessionSortOrder);
    } catch (error) {
      console.error('Failed to invalidate session:', error);
      showToast('Failed to log out session.', 'error');
    } finally {
      setIsInvalidating(false);
    }
  };

  const toggleSessionSelection = (id: number, e: React.MouseEvent | React.ChangeEvent | React.KeyboardEvent) => {
    e.stopPropagation();
    setSelectedSessionIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAllSelection = () => {
    const activeSessionIds = sessions.filter(s => s.is_active).map(s => s.id);
    if (selectedSessionIds.size === activeSessionIds.length && activeSessionIds.length > 0) {
      setSelectedSessionIds(new Set());
    } else {
      setSelectedSessionIds(new Set(activeSessionIds));
    }
  };

  const handleTabChange = useCallback(
    (tabId: TabId) => {
      if (tabId !== activeTab) setPage(1);
      setActiveTab(tabId);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set('tab', tabId);
          return next;
        },
        { replace: true }
      );
    },
    [activeTab, setSearchParams]
  );

  const fetchLogs = useCallback(
    async (pageNum: number, search: string, sort: SortBy, order: SortOrder, tabId: TabId) => {
      const requestId = ++logsRequestId.current;
      setLoading(true);
      setLogsError(false);
      try {
        const endpoint = tabId === 'alerts' ? '/users/audit-trail/alerts' : '/users/audit-trail';
        const params: Record<string, string | number | boolean> = {
          all_users: true,
          limit: ROWS_PER_PAGE,
          page: pageNum,
          sort_by: sort,
          order,
        };
        if (search.trim()) params.search = search.trim();
        if (tabId === 'user') {
          // User activity excludes both alert and websocket/agent actions.
          params.exclude_actions = `${ALERT_ACTIONS_CSV},${WEBSOCKET_ACTIONS_CSV}`;
        } else if (tabId === 'agent') {
          params.only_actions = WEBSOCKET_ACTIONS_CSV;
        }
        const res = await api.get<{
          status: string;
          data?: {
            logs: AuditTrailEntry[];
            pagination: { page: number; limit: number; total: number; total_pages: number };
          };
        }>(endpoint, { params });
        // A newer fetchLogs call started while this one was in flight — its own
        // result already won, so applying this stale one now would overwrite it.
        if (logsRequestId.current !== requestId) return;
        if (res.data?.status === 'Success' && res.data?.data) {
          const { logs: nextLogs, pagination } = res.data.data;
          setLogs(nextLogs);
          setTotal(pagination.total);
          setTotalPages(pagination.total_pages);
          setTotalByTab((prev) => ({ ...prev, [tabId]: pagination.total }));
        } else {
          // 200 with an unusable body is a failure, not an empty audit trail.
          setLogsError(true);
          setLogs([]);
          setTotal(0);
          setTotalPages(0);
          setTotalByTab((prev) => ({ ...prev, [tabId]: null }));
        }
      } catch {
        if (logsRequestId.current !== requestId) return;
        setLogsError(true);
        setLogs([]);
        setTotal(0);
        setTotalPages(0);
        setTotalByTab((prev) => ({ ...prev, [tabId]: null }));
      } finally {
        if (logsRequestId.current === requestId) setLoading(false);
      }
    },
    []
  );

  const fetchSessions = useCallback(async (pageNum: number, search: string, sort: SessionSortBy, order: SortOrder) => {
    const requestId = ++sessionsRequestId.current;
    setSessionsLoading(true);
    setSessionsError(false);
    try {
      const params: Record<string, string | number | boolean> = {
        all_users: true,
        limit: ROWS_PER_PAGE,
        page: pageNum,
        sort_by: sort,
        order,
      };
      if (search.trim()) params.search = search.trim();
      const res = await api.get<{
        status: string;
        data?: {
          sessions: SessionEntry[];
          pagination: { page: number; limit: number; total: number; total_pages: number };
        };
      }>('/users/session-history', { params });
      // A newer fetchSessions call started while this one was in flight — its own
      // result already won, so applying this stale one now would overwrite it.
      if (sessionsRequestId.current !== requestId) return;
      if (res.data?.status === 'Success' && res.data?.data) {
        const { pagination } = res.data.data;
        setSessions(res.data.data.sessions);
        setSessionsTotal(pagination.total);
        setSessionsTotalPages(pagination.total_pages);
        setTotalByTab((prev) => ({ ...prev, sessions: pagination.total }));
      } else {
        setSessionsError(true);
        setSessions([]);
        setSessionsTotal(0);
        setSessionsTotalPages(0);
        setTotalByTab((prev) => ({ ...prev, sessions: null }));
      }
    } catch {
      if (sessionsRequestId.current !== requestId) return;
      setSessionsError(true);
      setSessions([]);
      setSessionsTotal(0);
      setSessionsTotalPages(0);
      setTotalByTab((prev) => ({ ...prev, sessions: null }));
    } finally {
      if (sessionsRequestId.current === requestId) setSessionsLoading(false);
    }
  }, []);

  const fetchSessionActions = useCallback(
    async (sessionId: number) => {
      setSessionActionsLoadingBySessionId((prev) => ({ ...prev, [sessionId]: true }));
      try {
        const res = await api.get<{
          status: string;
          data?: {
            logs: AuditTrailEntry[];
          };
        }>('/users/session-actions', {
          params: {
            session_id: sessionId,
            all_users: true,
            limit: 200,
            order: 'asc',
          },
        });

        if (res.data?.status === 'Success' && res.data?.data) {
          setSessionActionsBySessionId((prev) => ({ ...prev, [sessionId]: res.data.data!.logs ?? [] }));
        } else {
          setSessionActionsBySessionId((prev) => ({ ...prev, [sessionId]: [] }));
        }
      } catch {
        setSessionActionsBySessionId((prev) => ({ ...prev, [sessionId]: [] }));
      } finally {
        setSessionActionsLoadingBySessionId((prev) => ({ ...prev, [sessionId]: false }));
      }
    },
    []
  );

  const fetchAllTabCounts = useCallback(async () => {
    const baseParams = { all_users: true, limit: 1, page: 1 };
    try {
      const [userRes, agentRes, alertsRes, sessionsRes] = await Promise.all([
        api.get<{ status: string; data?: { pagination: { total: number } } }>('/users/audit-trail', {
          params: { ...baseParams, sort_by: 'created_at', order: 'desc', exclude_actions: `${ALERT_ACTIONS_CSV},${WEBSOCKET_ACTIONS_CSV}` },
        }),
        api.get<{ status: string; data?: { pagination: { total: number } } }>('/users/audit-trail', {
          params: { ...baseParams, sort_by: 'created_at', order: 'desc', only_actions: WEBSOCKET_ACTIONS_CSV },
        }),
        api.get<{ status: string; data?: { pagination: { total: number } } }>('/users/audit-trail/alerts', {
          params: { ...baseParams, sort_by: 'created_at', order: 'desc' },
        }),
        api.get<{ status: string; data?: { pagination: { total: number } } }>('/users/session-history', {
          params: { ...baseParams, sort_by: 'login_time', order: 'desc' },
        }),
      ]);
      setTotalByTab((prev) => ({
        ...prev,
        user: userRes.data?.status === 'Success' && userRes.data?.data?.pagination ? userRes.data.data.pagination.total : prev.user,
        agent: agentRes.data?.status === 'Success' && agentRes.data?.data?.pagination ? agentRes.data.data.pagination.total : prev.agent,
        alerts: alertsRes.data?.status === 'Success' && alertsRes.data?.data?.pagination ? alertsRes.data.data.pagination.total : prev.alerts,
        sessions: sessionsRes.data?.status === 'Success' && sessionsRes.data?.data?.pagination ? sessionsRes.data.data.pagination.total : prev.sessions,
      }));
    } catch {
      // Leave totalByTab unchanged on error
    }
  }, []);

  useEffect(() => {
    fetchAllTabCounts();
  }, [fetchAllTabCounts]);

  // Debounce search: update searchQuery after user stops typing
  useEffect(() => {
    const t = setTimeout(() => {
      setSearchQuery(searchInput);
      setPage(1);
      setSessionsPage(1);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    if (activeTab !== 'sessions') {
      fetchLogs(page, searchQuery, sortBy, sortOrder, activeTab);
    }
  }, [page, searchQuery, sortBy, sortOrder, fetchLogs, activeTab]);

  useEffect(() => {
    if (activeTab === 'sessions') {
      fetchSessions(sessionsPage, searchQuery, sessionSortBy, sessionSortOrder);
    }
  }, [activeTab, sessionsPage, searchQuery, sessionSortBy, sessionSortOrder, fetchSessions]);

  useEffect(() => {
    // Reset expanded state when switching tabs or paging/sorting sessions.
    if (activeTab !== 'sessions') setExpandedSessionId(null);
  }, [activeTab]);

  useEffect(() => {
    // Agent logs sorting is client-side; reset when leaving the tab.
    if (activeTab !== 'agent') {
      setAgentSortBy('created_at');
      setAgentSortOrder('desc');
    }
  }, [activeTab]);


  const handleSessionSort = (column: SessionSortBy) => {
    if (sessionSortBy === column) {
      setSessionSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSessionSortBy(column);
      setSessionSortOrder('desc');
    }
    setSessionsPage(1);
    setExpandedSessionId(null);
  };



  const toggleSessionExpanded = async (sessionId: number) => {
    setExpandedSessionId((prev) => (prev === sessionId ? null : sessionId));
    const alreadyLoaded = Array.isArray(sessionActionsBySessionId[sessionId]);
    const alreadyLoading = sessionActionsLoadingBySessionId[sessionId] === true;
    if (!alreadyLoaded && !alreadyLoading) {
      await fetchSessionActions(sessionId);
    }
  };




  const renderUserCell = (name?: string | null, email?: string | null) => {
    const hasName = Boolean(name && name.trim());
    const hasEmail = Boolean(email && email.trim());
    if (!hasName && !hasEmail) return <span>—</span>;
    const primary = (hasName ? String(name) : String(email)).trim();
    const secondary = hasName && hasEmail ? String(email).trim() : '';
    const initials = initialsFrom(primary);
    return (
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-gradient-to-b from-white to-slate-50 text-xs font-bold text-slate-700 shadow-sm">
          {initials}
        </div>
        <div className="flex min-w-0 flex-col leading-tight">
          <span className="truncate font-semibold text-slate-900">{primary}</span>
          {secondary ? <span className="truncate text-xs text-slate-500">{secondary}</span> : null}
        </div>
      </div>
    );
  };

  const renderNodeCell = (details: Record<string, unknown> | null | undefined) => {
    const d = details as Record<string, unknown> | null | undefined;
    const hostname = typeof d?.hostname === 'string' ? (d.hostname as string) : '';
    const hostId =
      typeof d?.host_identifier === 'string'
        ? (d.host_identifier as string)
        : typeof d?.host_identifier === 'number'
          ? String(d.host_identifier)
          : '';

    if (!hostname && !hostId) return <span>—</span>;
    return (
      <div className="flex flex-col leading-tight">
        {hostname && <span className="text-slate-800">{hostname}</span>}
        {hostId && <span className="text-xs text-slate-500">{hostId}</span>}
      </div>
    );
  };

  const renderAgentValue = (log: AuditTrailEntry) => {
    const d = log.details as Record<string, unknown> | null | undefined;
    if (!d) return <span className="text-slate-500">NA</span>;

    const port = d?.port != null ? String(d.port) : undefined;
    const protocol = typeof d?.protocol === 'string' ? (d.protocol as string) : undefined;
    const ip = d?.ip != null ? String(d.ip) : undefined;

    if (log.action === 'PORT_BLOCK') {
      if (!port && !protocol) return <span className="text-slate-500">NA</span>;
      return <span className="font-medium text-slate-800">{[port, protocol].filter(Boolean).join('/')}</span>;
    }

    if (log.action === 'IP_BLOCK') {
      if (!ip && !port) return <span className="text-slate-500">NA</span>;
      return <span className="font-medium text-slate-800">{[ip, port ? `:${port}` : null].filter(Boolean).join('')}</span>;
    }

    if (log.action === 'CLAMAV') {
      const path = typeof d?.path === 'string' ? (d.path as string) : undefined;
      if (!path) return <span className="text-slate-500">NA</span>;
      return <span className="font-medium text-slate-800 break-all" title={path}>{path}</span>;
    }

    return <span className="text-slate-500">NA</span>;
  };

  const renderAgentReason = (log: AuditTrailEntry) => {
    const d = log.details as Record<string, unknown> | null | undefined;
    const reason =
      (typeof d?.reason === 'string' ? d.reason.trim() : '');
    if (!reason) return <span className="text-slate-500">—</span>;
    return <span className="text-slate-700">{reason}</span>;
  };







  const countMeta = useMemo(
    () => ({
      userCount: totalByTab.user,
      agentCount: totalByTab.agent,
      alertCount: totalByTab.alerts,
      sessionsCount: totalByTab.sessions,
    }),
    [totalByTab]
  );


  const visibleLogs = useMemo(() => {
    if (activeTab === 'agent') return logs.filter(isWebsocketLog);
    if (activeTab === 'alerts') return logs.filter(isAlertLog);
    return logs.filter((log) => !isWebsocketLog(log) && !isAlertLog(log));
  }, [activeTab, logs]);

  // Sorted here rather than inline in the JSX: the comparator runs localeCompare and
  // rebuilds an agentSortKey() per comparison, and inline it would re-run on every search
  // keystroke and every drawer open. The day-grouping that consumes this stays in the
  // render body on purpose — it derives the "Today"/"Yesterday" labels from the current
  // clock, so caching it could leave a long-lived tab showing stale labels after midnight.
  const agentSortedLogs = useMemo(
    () =>
      visibleLogs.slice().sort((a, b) => {
        const ka = agentSortKey(a, agentSortBy);
        const kb = agentSortKey(b, agentSortBy);
        if (typeof ka === 'number' && typeof kb === 'number') {
          return agentSortOrder === 'asc' ? ka - kb : kb - ka;
        }
        const sa = String(ka);
        const sb = String(kb);
        const cmp = sa.localeCompare(sb, undefined, { numeric: true, sensitivity: 'base' });
        return agentSortOrder === 'asc' ? cmp : -cmp;
      }),
    [visibleLogs, agentSortBy, agentSortOrder],
  );

  // The select-all checkbox reads this count several times per render, and the card list
  // below needs a sorted copy — compute both once per `sessions` change.
  const activeSessionCount = useMemo(() => sessions.filter((s) => s.is_active).length, [sessions]);

  // Active sessions first; Array.prototype.sort is stable, so the original order is
  // preserved within each half.
  const sessionsActiveFirst = useMemo(
    () =>
      [...sessions].sort((a, b) => {
        if (a.is_active && !b.is_active) return -1;
        if (!a.is_active && b.is_active) return 1;
        return 0;
      }),
    [sessions],
  );

  const titleMeta = useMemo(() => {
    switch (activeTab) {
      case 'user':
        return {
          label: 'User activity',
          blurb: 'A tamper-evident record of who did what, and when.',
        };
      case 'agent':
        return {
          label: 'Agent actions',
          blurb: 'A verifiable log of every command pushed to your endpoints, from port and network changes to compliance, WiFi, Defender, and USB actions.',
        };
      case 'sessions':
        return {
          label: 'Session timeline',
          blurb: 'A complete timeline of every session — sign-in, sign-out, duration, and the actions taken while logged in.',
        };
      case 'alerts':
        return {
          label: 'Alert logs',
          blurb: "A full history of every alert's lifecycle, from detection through closure and assignment.",
        };
      default:
        return { label: 'Activity', blurb: '' };
    }
  }, [activeTab]);



  const renderUserActivityDetailsBody = (log: AuditTrailEntry, details: Record<string, unknown> | null) => {
    const reason = typeof details?.reason === 'string' ? details.reason.trim() : '';
    const actor = [log.user_name, log.user_email].filter(Boolean).join(' · ') || '—';
    const hostIdentifier =
      typeof details?.host_identifier === 'string'
        ? details.host_identifier
        : typeof details?.host_identifier === 'number'
          ? String(details.host_identifier)
          : '';
    const oldHostname = typeof details?.old_hostname === 'string' ? details.old_hostname : '';
    const newHostname = typeof details?.new_hostname === 'string' ? details.new_hostname : '';
    const detailEntries = details ? Object.entries(details) : [];

    return (
      <div className="space-y-3">
        <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_14px_34px_rgba(15,23,42,0.06)]">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Summary</p>
          <div className="mt-2 text-sm text-slate-700">{renderAuditActionCell(log)}</div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <DrawerRow k="activity type" v={log.action} />
          <DrawerRow k="status" v={log.status} />
          <DrawerRow k="user" v={actor} />
          <DrawerRow k="time" v={new Date(log.created_at).toLocaleString()} />
          {reason && <DrawerRow k="reason" v={reason} />}
          {hostIdentifier && <DrawerRow k="host id" v={hostIdentifier} />}
          {log.action === 'RENAME_NODE' && (
            <>
              <DrawerRow k="old hostname" v={oldHostname || '—'} />
              <DrawerRow k="new hostname" v={newHostname || '—'} />
            </>
          )}
        </div>

        {detailEntries.length > 0 ? (
          <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_10px_26px_rgba(15,23,42,0.05)]">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400 mb-2">Extra Context</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {detailEntries.slice(0, 8).map(([k, v]) => (
                <DrawerRow key={k} k={k.replace(/_/g, ' ')} v={v} />
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_10px_26px_rgba(15,23,42,0.05)]">
            <p className="text-sm text-slate-500">No extra payload fields were recorded for this activity.</p>
          </div>
        )}

        <div className="rounded-3xl border border-slate-200 bg-slate-50/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Raw JSON</p>
            <button
              type="button"
              onClick={() => {
                try {
                  void navigator.clipboard?.writeText(JSON.stringify(details ?? {}, null, 2));
                } catch {
                  // ignore
                }
              }}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50"
            >
              Copy JSON
            </button>
          </div>
          <pre className="mt-2 max-h-[220px] overflow-auto rounded-2xl border border-slate-200 bg-white p-3 text-xs leading-relaxed text-slate-800">
            {JSON.stringify(details ?? {}, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  const renderAgentActionDetailsBody = (log: AuditTrailEntry, details: Record<string, unknown> | null) => {
    const actor = [log.user_name, log.user_email].filter(Boolean).join(' · ') || '—';
    const hostIdentifier =
      typeof details?.host_identifier === 'string'
        ? details.host_identifier
        : typeof details?.host_identifier === 'number'
          ? String(details.host_identifier)
          : '';
    const hostname = typeof details?.hostname === 'string' ? details.hostname : '';
    const wsAgent = typeof details?.ws_agent === 'string' ? details.ws_agent : '';
    const wsAction = typeof details?.ws_action === 'string' ? details.ws_action : '';
    const subAction = typeof details?.sub_action === 'string' ? details.sub_action : '';
    const reason = typeof details?.reason === 'string' ? details.reason.trim() : '';
    const commandKeys = Array.isArray(details?.command_keys) ? details.command_keys.map((k) => String(k)).join(', ') : '';
    const arg1 = details?.arg1 != null ? String(details.arg1) : '';
    const arg2 = details?.arg2 != null ? String(details.arg2) : '';
    const ip = details?.ip != null ? String(details.ip) : '';
    const port = details?.port != null ? String(details.port) : '';
    const protocol = details?.protocol != null ? String(details.protocol) : '';

    return (
      <div className="space-y-3">
        <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_14px_34px_rgba(15,23,42,0.06)]">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Summary</p>
          <div className="mt-2 text-sm text-slate-700">{renderAuditActionCell(log)}</div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <DrawerRow k="agent category" v={renderAgentType(log)} />
          <DrawerRow k="action" v={renderAgentAction(log)} />
          <DrawerRow k="status" v={log.status} />
          <DrawerRow k="requested by" v={actor} />
          <DrawerRow k="time" v={new Date(log.created_at).toLocaleString()} />
          <DrawerRow k="target node" v={hostname || hostIdentifier || '—'} />
          {hostIdentifier && <DrawerRow k="host id" v={hostIdentifier} />}
          {wsAgent && <DrawerRow k="agent module" v={wsAgent} />}
          {(wsAction || subAction) && <DrawerRow k="operation" v={subAction || wsAction} />}
          {reason && <DrawerRow k="reason" v={reason} />}
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_10px_26px_rgba(15,23,42,0.05)]">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400 mb-2">Action Data</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {(ip || port || protocol) ? (
              <>
                {ip && <DrawerRow k="ip" v={ip} />}
                {port && <DrawerRow k="port" v={port} />}
                {protocol && <DrawerRow k="protocol" v={protocol} />}
              </>
            ) : (
              <>
                {arg1 && <DrawerRow k="arg1" v={arg1} />}
                {arg2 && <DrawerRow k="arg2" v={arg2} />}
              </>
            )}
            {commandKeys && <DrawerRow k="command keys" v={commandKeys} />}
          </div>
        </div>

        <div className="rounded-3xl border border-slate-200 bg-slate-50/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Raw JSON</p>
            <button
              type="button"
              onClick={() => {
                try {
                  void navigator.clipboard?.writeText(JSON.stringify(details ?? {}, null, 2));
                } catch {
                  // ignore
                }
              }}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50"
            >
              Copy JSON
            </button>
          </div>
          <pre className="mt-2 max-h-[220px] overflow-auto rounded-2xl border border-slate-200 bg-white p-3 text-xs leading-relaxed text-slate-800">
            {JSON.stringify(details ?? {}, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  const renderAlertDetailsBody = (log: AuditTrailEntry, details: Record<string, unknown> | null) => {
    const ids = extractAlertIds(details);
    const reason = typeof details?.reason === 'string' ? details.reason.trim() : '';
    const assignmentType =
      typeof details?.assignment_type === 'string' ? details.assignment_type.toLowerCase() : '';
    const assignmentChanges = Array.isArray(details?.assignment_changes)
      ? (details.assignment_changes as Array<Record<string, unknown>>)
      : [];
    const usersMap =
      details?.users && typeof details.users === 'object'
        ? (details.users as Record<string, { id?: number; name?: string | null; email?: string | null }>)
        : {};
    const alerts = Array.isArray(details?.alerts) ? (details.alerts as Array<Record<string, unknown>>) : [];
    const statusLabel =
      log.action === 'ALERT_STATUS_UPDATE'
        ? details?.is_open === true
          ? 'Opened'
          : details?.is_open === false
            ? 'Closed'
            : 'Updated'
        : log.action === 'ALERT_MARK_UPDATE'
          ? details?.mark === 'true_positive'
            ? 'True Positive'
            : details?.mark === 'false_positive'
              ? 'False Positive'
              : details?.mark === 'unmarked'
                ? 'Unmarked'
                : 'Marked'
          : assignmentType === 'reassigned'
            ? 'Reassigned'
            : assignmentType === 'mixed'
              ? 'Assigned/Reassigned'
              : assignmentType === 'unassigned'
                ? 'Unassigned'
                : 'Assigned';

    const eventToChange = new Map(
      assignmentChanges.map((change) => [String(change?.event_id ?? ''), change] as const),
    );
    const actor = [log.user_name, log.user_email].filter(Boolean).join(' · ') || '—';
    const assigneeId =
      typeof details?.assignee_id === 'number' || typeof details?.assignee_id === 'string'
        ? String(details.assignee_id)
        : '';
    const primaryTransition = assignmentChanges.length === 1 ? assignmentChanges[0] : null;
    const fromAssigneeId =
      primaryTransition &&
        (typeof primaryTransition.from_assignee_id === 'number' || typeof primaryTransition.from_assignee_id === 'string')
        ? String(primaryTransition.from_assignee_id)
        : '';
    const toAssigneeId =
      primaryTransition &&
        (typeof primaryTransition.to_assignee_id === 'number' || typeof primaryTransition.to_assignee_id === 'string')
        ? String(primaryTransition.to_assignee_id)
        : assigneeId;
    const fromUserPrimary =
      (primaryTransition?.from_assignee as AuditUserLite) ?? (fromAssigneeId ? usersMap[fromAssigneeId] : null);
    const toUserPrimary =
      (primaryTransition?.to_assignee as AuditUserLite) ?? (toAssigneeId ? usersMap[toAssigneeId] : null);

    return (
      <div className="space-y-3">
        <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_14px_34px_rgba(15,23,42,0.06)]">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Summary</p>
          <div className="mt-2 text-sm text-slate-700">{renderAuditActionCell(log)}</div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <DrawerRow k="log type" v={log.action} />
          <DrawerRow k="operation" v={statusLabel} />
          <DrawerRow k="performed by" v={actor} />
          <DrawerRow k="time" v={new Date(log.created_at).toLocaleString()} />
          <DrawerRow k="affected alerts" v={ids.length} />
          {log.action === 'ALERT_ASSIGN_UPDATE' ? (
            assignmentType === 'reassigned' && fromAssigneeId && toAssigneeId ? (
              <DrawerRow
                k="reassignment"
                v={
                  <span className="inline-flex flex-wrap items-center gap-x-1 font-semibold text-slate-900">
                    <AuditUserRef user={fromUserPrimary} fallbackId={fromAssigneeId} />
                    <span className="text-slate-400">→</span>
                    <AuditUserRef user={toUserPrimary} fallbackId={toAssigneeId} />
                  </span>
                }
              />
            ) : (
              <DrawerRow
                k="assignee"
                v={
                  toAssigneeId ? (
                    <AuditUserRef user={toUserPrimary} fallbackId={toAssigneeId} />
                  ) : (
                    '—'
                  )
                }
              />
            )
          ) : log.action === 'ALERT_MARK_UPDATE' ? null : (
            <DrawerRow
              k="status change"
              v={details?.is_open === true ? 'Open' : details?.is_open === false ? 'Closed' : 'Updated'}
            />
          )}
          <DrawerRow k="reason" v={reason || '—'} />
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_10px_26px_rgba(15,23,42,0.05)]">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Affected Alerts</p>
            <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-700">
              {ids.length} item{ids.length === 1 ? '' : 's'}
            </span>
          </div>

          {ids.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No alert identifiers in payload.</p>
          ) : (
            <div className="table-scrollbar mt-3 overflow-x-auto">
              <table className="w-full min-w-[520px] border-separate border-spacing-0">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/80">
                    <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Alert</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Host</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Host ID</th>
                    {log.action === 'ALERT_ASSIGN_UPDATE' && (
                      <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Assignment</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {ids.map((id, idx) => {
                    const idText = String(id);
                    const alertMeta =
                      alerts.find((a) => String(a?.id ?? '') === idText) ??
                      ({ id: idText } as Record<string, unknown>);
                    const hostname =
                      typeof alertMeta.hostname === 'string' && alertMeta.hostname.trim()
                        ? alertMeta.hostname
                        : typeof alertMeta.host_identifier === 'string' && alertMeta.host_identifier.trim()
                          ? alertMeta.host_identifier
                          : '—';
                    const hostIdentifier =
                      typeof alertMeta.host_identifier === 'string' ? alertMeta.host_identifier : '—';
                    const change = eventToChange.get(idText);
                    const rowFrom =
                      change &&
                        (typeof change.from_assignee_id === 'number' || typeof change.from_assignee_id === 'string')
                        ? String(change.from_assignee_id)
                        : '';
                    const rowTo =
                      change &&
                        (typeof change.to_assignee_id === 'number' || typeof change.to_assignee_id === 'string')
                        ? String(change.to_assignee_id)
                        : assigneeId;
                    const rowFromUser =
                      (change?.from_assignee as AuditUserLite) ?? (rowFrom ? usersMap[rowFrom] : null);
                    const rowToUser =
                      (change?.to_assignee as AuditUserLite) ?? (rowTo ? usersMap[rowTo] : null);
                    return (
                      <tr key={`${idText}-${idx}`} className="border-b border-slate-100">
                        <td className="px-3 py-2 text-sm font-medium text-blue-700">
                          <Link
                            to="/alerts/view"
                            state={{ ...log.details, id, fromAuditTrail: true }}
                            className="underline underline-offset-2 hover:text-blue-800"
                          >
                            #{idText}
                          </Link>
                        </td>
                        <td className="px-3 py-2 text-sm text-slate-700">{hostname}</td>
                        <td className="px-3 py-2 text-sm text-slate-600">{hostIdentifier}</td>
                        {log.action === 'ALERT_ASSIGN_UPDATE' && (
                          <td className="px-3 py-2 text-sm text-slate-700">
                            {assignmentType === 'reassigned' && rowFrom && rowTo ? (
                              <span className="inline-flex flex-wrap items-center gap-x-1">
                                <AuditUserRef user={rowFromUser} fallbackId={rowFrom} />
                                <span className="text-slate-400">→</span>
                                <AuditUserRef user={rowToUser} fallbackId={rowTo} />
                              </span>
                            ) : rowTo ? (
                              <span className="inline-flex flex-wrap items-center gap-x-1">
                                <span className="text-slate-500">to</span>
                                <AuditUserRef user={rowToUser} fallbackId={rowTo} />
                              </span>
                            ) : (
                              '—'
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="rounded-3xl border border-slate-200 bg-slate-50/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Raw JSON</p>
            <button
              type="button"
              onClick={() => {
                try {
                  void navigator.clipboard?.writeText(JSON.stringify(details ?? {}, null, 2));
                } catch {
                  // ignore
                }
              }}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50"
            >
              Copy JSON
            </button>
          </div>
          <pre className="table-scrollbar mt-2 max-h-[260px] overflow-auto rounded-2xl border border-slate-200 bg-white p-3 text-xs leading-relaxed text-slate-800">
            {JSON.stringify(details ?? {}, null, 2)}
          </pre>
        </div>
      </div>
    );
  };

  const renderAuditActionHeading = (log: AuditTrailEntry): ReactNode => {
    if (log.action !== 'ALERT_ASSIGN_UPDATE') {
      return formatAuditAction(log);
    }
    const details = (log.details ?? null) as Record<string, unknown> | null | undefined;
    const assignmentTypeRaw =
      typeof details?.assignment_type === 'string' ? details.assignment_type.toLowerCase() : '';
    const assigneeId =
      typeof details?.assignee_id === 'string' || typeof details?.assignee_id === 'number'
        ? String(details?.assignee_id)
        : '';
    const assignmentChanges = Array.isArray(details?.assignment_changes)
      ? (details?.assignment_changes as Array<Record<string, unknown>>)
      : [];
    const usersMap =
      details?.users && typeof details.users === 'object'
        ? (details.users as Record<string, { id?: number; name?: string | null; email?: string | null }>)
        : {};
    const singleChange = assignmentChanges.length === 1 ? assignmentChanges[0] : null;
    const fromAssigneeId =
      singleChange && (typeof singleChange.from_assignee_id === 'number' || typeof singleChange.from_assignee_id === 'string')
        ? String(singleChange.from_assignee_id)
        : '';
    const toAssigneeId =
      singleChange && (typeof singleChange.to_assignee_id === 'number' || typeof singleChange.to_assignee_id === 'string')
        ? String(singleChange.to_assignee_id)
        : assigneeId;
    const fromUser =
      (singleChange?.from_assignee as AuditUserLite) ?? (fromAssigneeId ? usersMap[fromAssigneeId] : null);
    const toUser = (singleChange?.to_assignee as AuditUserLite) ?? (toAssigneeId ? usersMap[toAssigneeId] : null);
    const eventIds =
      Array.isArray(details?.event_ids) ? details?.event_ids.map((v) => String(v)).join(', ') : '';

    if (assignmentTypeRaw === 'reassigned' && fromAssigneeId && toAssigneeId) {
      return (
        <span className="inline-flex flex-wrap items-center gap-x-1 gap-y-0.5">
          <span>Reassigned alert(s) from</span>
          <AuditUserRef user={fromUser} fallbackId={fromAssigneeId} />
          <span>to</span>
          <AuditUserRef user={toUser} fallbackId={toAssigneeId} />
          {eventIds ? <span className="text-slate-600">(alerts: {eventIds})</span> : null}
        </span>
      );
    }
    if (assignmentTypeRaw === 'mixed') {
      return eventIds ? `Assigned/Reassigned alert(s) (${eventIds})` : 'Assigned/Reassigned alert(s)';
    }
    if (assignmentTypeRaw === 'unassigned') {
      return fromAssigneeId ? (
        <span className="inline-flex flex-wrap items-center gap-x-1 gap-y-0.5">
          <span>Unassigned alert(s) from</span>
          <AuditUserRef user={fromUser} fallbackId={fromAssigneeId} />
          {eventIds ? <span className="text-slate-600">(alerts: {eventIds})</span> : null}
        </span>
      ) : eventIds ? (
        `Unassigned alert(s) (${eventIds})`
      ) : (
        'Unassigned alert(s)'
      );
    }
    return toAssigneeId ? (
      <span className="inline-flex flex-wrap items-center gap-x-1 gap-y-0.5">
        <span>Assigned alert(s) to</span>
        <AuditUserRef user={toUser} fallbackId={toAssigneeId} />
        {eventIds ? <span className="text-slate-600">(alerts: {eventIds})</span> : null}
      </span>
    ) : eventIds ? (
      `Assigned alert(s) (${eventIds})`
    ) : (
      'Assigned alert(s)'
    );
  };

  const renderDetailsPanel = (log: AuditTrailEntry) => {
    const details = (log.details ?? null) as Record<string, unknown> | null;
    const keys = details ? Object.keys(details).sort((a, b) => a.localeCompare(b)) : [];
    const hasDetails = keys.length > 0;

    return (
      <div className="flex h-full flex-col bg-[#f8f9fb] text-slate-900">
        <div className="border-b border-slate-200 bg-white px-6 py-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-blue-700">
                  Log details
                </span>
                <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${log.status === 'success' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-rose-200 bg-rose-50 text-rose-700'}`}>
                  {log.status}
                </span>
              </div>
              <h3 className="mt-4 text-xl font-bold tracking-tight text-slate-900">
                {renderAuditActionHeading(log)}
              </h3>
              <p className="mt-1.5 text-sm text-slate-500 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                {new Date(log.created_at).toLocaleString()}
              </p>
            </div>

            <button
              type="button"
              onClick={() => setSelectedLog(null)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 text-slate-500 transition-all duration-200 hover:bg-slate-200 hover:text-slate-900"
              aria-label="Close details"
            >
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-3 text-sm">
            <div className="flex items-center gap-2 rounded-lg bg-white border border-slate-200 px-3 py-2 shadow-sm">
              <span className="font-semibold text-slate-500">User</span>
              <span className="font-medium text-slate-900">{[log.user_name, log.user_email].filter(Boolean).join(' · ') || '—'}</span>
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-white border border-slate-200 px-3 py-2 shadow-sm">
              <span className="font-semibold text-slate-500">Action</span>
              <span className="font-medium text-slate-900">{log.action}</span>
            </div>
          </div>
        </div>

        <div className="table-scrollbar flex-1 overflow-y-auto px-6 py-6">
          <div className="space-y-4">
            {isAlertLog(log) ? (
              renderAlertDetailsBody(log, details)
            ) : isWebsocketLog(log) ? (
              renderAgentActionDetailsBody(log, details)
            ) : log.action !== 'ALERT_STATUS_UPDATE' && log.action !== 'ALERT_ASSIGN_UPDATE' ? (
              renderUserActivityDetailsBody(log, details)
            ) : hasDetails ? (
              <>
                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Summary</p>
                  <div className="mt-2 text-sm text-slate-700">{renderAuditActionHeading(log)}</div>
                </div>
                <div className="flex items-center justify-between pt-4">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-500">
                    Payload ({keys.length})
                  </p>
                  <button
                    type="button"
                    onClick={() => {
                      try {
                        void navigator.clipboard?.writeText(JSON.stringify(details, null, 2));
                      } catch {
                        // ignore
                      }
                    }}
                    className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 shadow-sm"
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                    </svg>
                    Copy JSON
                  </button>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  {keys.slice(0, 10).map((k) => (
                    <DrawerRow key={k} k={k} v={details?.[k]} />
                  ))}
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-5 mt-4 shadow-sm">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Raw JSON</p>
                  <pre className="mt-3 max-h-[320px] overflow-auto rounded-xl bg-slate-900 p-4 text-xs leading-relaxed text-blue-300">
                    {JSON.stringify(details, null, 2)}
                  </pre>
                </div>
              </>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center shadow-sm">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-slate-500">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M12 20a8 8 0 100-16 8 8 0 000 16z" />
                  </svg>
                </div>
                <p className="mt-3 text-base font-semibold text-slate-900">No payload attached</p>
                <p className="mt-1 text-sm text-slate-500">This entry doesn’t include a details object.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const extractAlertIds = (details: Record<string, unknown> | null | undefined): Array<number | string> => {
    if (!details) return [];
    const any = details as Record<string, unknown>;
    const candidates = [
      any.event_id,
      any.event_ids,
      any.alert_id,
      any.alert_ids,
      any.id,
      any.ids,
    ];

    const out: Array<number | string> = [];
    for (const c of candidates) {
      if (c == null) continue;
      if (Array.isArray(c)) {
        for (const v of c) {
          if (v == null) continue;
          out.push(typeof v === 'number' || typeof v === 'string' ? v : String(v));
        }
      } else {
        out.push(typeof c === 'number' || typeof c === 'string' ? c : String(c));
      }
    }

    // De-dupe while preserving order
    const seen = new Set<string>();
    return out.filter((v) => {
      const k = String(v);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  };

  const renderAuditActionCell = (log: AuditTrailEntry) => {
    // Opened alert(s): show alert id(s) as link(s) to alert sheet
    if (log.action === 'ALERT_STATUS_UPDATE' && log.details?.is_open === true) {
      const ids = extractAlertIds(log.details);
      if (ids.length === 0) return 'Opened alert(s)';

      const host_identifier =
        typeof log.details?.host_identifier === 'string' ? (log.details.host_identifier as string) : undefined;
      const hostname = typeof log.details?.hostname === 'string' ? (log.details.hostname as string) : undefined;

      const reason = typeof log.details?.reason === 'string' ? log.details.reason.trim() : '';
      return (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <span>Opened alert</span>
          {ids.map((id, idx) => (
            <span key={`${String(id)}-${idx}`} className="inline-flex items-center gap-1">
              <Link
                to="/alerts/view"
                state={{ ...log.details, id, host_identifier, hostname, fromAuditTrail: true }}
                className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
              >
                #{String(id)}
              </Link>
              {idx < ids.length - 1 && <span className="text-slate-400">,</span>}
            </span>
          ))}
          {reason && <span className="text-gray-500 text-xs">— {reason}</span>}
        </span>
      );
    }

    // Closed alert(s): show alert id(s) as link(s) to alert sheet
    if (log.action === 'ALERT_STATUS_UPDATE' && log.details?.is_open === false) {
      const ids = extractAlertIds(log.details);
      if (ids.length === 0) return 'Closed alert(s)';

      const host_identifier =
        typeof log.details?.host_identifier === 'string' ? (log.details.host_identifier as string) : undefined;
      const hostname = typeof log.details?.hostname === 'string' ? (log.details.hostname as string) : undefined;

      const reason = typeof log.details?.reason === 'string' ? log.details.reason.trim() : '';
      return (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <span>Closed alert</span>
          {ids.map((id, idx) => (
            <span key={`${String(id)}-${idx}`} className="inline-flex items-center gap-1">
              <Link
                to="/alerts/view"
                state={{ ...log.details, id, host_identifier, hostname, fromAuditTrail: true }}
                className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
              >
                #{String(id)}
              </Link>
              {idx < ids.length - 1 && <span className="text-slate-400">,</span>}
            </span>
          ))}
          {reason && <span className="text-gray-500 text-xs">— {reason}</span>}
        </span>
      );
    }

    // Assigned alert(s): show alert id(s) as link(s) to alert sheet.
    if (log.action === 'ALERT_ASSIGN_UPDATE') {
      const ids = extractAlertIds(log.details);
      if (ids.length === 0) return 'Assigned alert(s)';

      const assignmentTypeRaw =
        typeof log.details?.assignment_type === 'string' ? log.details.assignment_type.toLowerCase() : '';
      const assignmentChanges = Array.isArray(log.details?.assignment_changes)
        ? (log.details.assignment_changes as Array<Record<string, unknown>>)
        : [];
      const usersMap =
        log.details?.users && typeof log.details.users === 'object'
          ? (log.details.users as Record<string, { id?: number; name?: string | null; email?: string | null }>)
          : {};
      const singleChange = assignmentChanges.length === 1 ? assignmentChanges[0] : null;
      const fromAssigneeId =
        singleChange && (typeof singleChange.from_assignee_id === 'number' || typeof singleChange.from_assignee_id === 'string')
          ? String(singleChange.from_assignee_id)
          : '';
      const assigneeId =
        typeof log.details?.assignee_id === 'string'
          ? log.details.assignee_id
          : typeof log.details?.assignee_id === 'number'
            ? String(log.details.assignee_id)
            : '';
      const toAssigneeId =
        singleChange && (typeof singleChange.to_assignee_id === 'number' || typeof singleChange.to_assignee_id === 'string')
          ? String(singleChange.to_assignee_id)
          : assigneeId;
      const fromUser =
        (singleChange?.from_assignee as AuditUserLite) ?? (fromAssigneeId ? usersMap[fromAssigneeId] : null);
      const toUser =
        (singleChange?.to_assignee as AuditUserLite) ?? (toAssigneeId ? usersMap[toAssigneeId] : null);
      const reason = typeof log.details?.reason === 'string' ? log.details.reason.trim() : '';

      return (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <span>
            {assignmentTypeRaw === 'reassigned'
              ? 'Reassigned alert'
              : assignmentTypeRaw === 'mixed'
                ? 'Assigned/Reassigned alert'
                : assignmentTypeRaw === 'unassigned'
                  ? 'Unassigned alert'
                  : 'Assigned alert'}
          </span>
          {ids.map((id, idx) => (
            <span key={`${String(id)}-${idx}`} className="inline-flex items-center gap-1">
              <Link
                to="/alerts/view"
                state={{ ...log.details, id, fromAuditTrail: true }}
                className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
              >
                #{String(id)}
              </Link>
              {idx < ids.length - 1 && <span className="text-slate-400">,</span>}
            </span>
          ))}
          {assignmentTypeRaw === 'reassigned' && fromAssigneeId && toAssigneeId ? (
            <span className="text-gray-500 text-xs">
              — from <AuditUserRef user={fromUser} fallbackId={fromAssigneeId} /> to{' '}
              <AuditUserRef user={toUser} fallbackId={toAssigneeId} />
            </span>
          ) : assignmentTypeRaw === 'unassigned' && fromAssigneeId ? (
            <span className="text-gray-500 text-xs">
              — from <AuditUserRef user={fromUser} fallbackId={fromAssigneeId} />
            </span>
          ) : (
            toAssigneeId && (
              <span className="text-gray-500 text-xs">
                — to <AuditUserRef user={toUser} fallbackId={toAssigneeId} />
              </span>
            )
          )}
          {reason && <span className="text-gray-500 text-xs">— {reason}</span>}
        </span>
      );
    }

    // Marked alert(s): show id(s) and reason.
    if (log.action === 'ALERT_MARK_UPDATE') {
      const ids = extractAlertIds(log.details);
      const markRaw = typeof log.details?.mark === 'string' ? log.details.mark : '';
      const markLabel =
        markRaw === 'true_positive'
          ? 'True Positive'
          : markRaw === 'false_positive'
            ? 'False Positive'
            : markRaw === 'unmarked'
              ? 'Unmarked'
              : 'Marked';
      const reason = typeof log.details?.reason === 'string' ? log.details.reason.trim() : '';

      const host_identifier =
        typeof log.details?.host_identifier === 'string'
          ? (log.details.host_identifier as string)
          : typeof log.details?.host_identifier === 'number'
            ? String(log.details.host_identifier)
            : undefined;
      const hostname = typeof log.details?.hostname === 'string' ? (log.details.hostname as string) : undefined;

      if (ids.length === 0) return `Marked alert(s) as ${markLabel}`;

      return (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <span>Marked alert(s) as {markLabel}</span>
          {ids.map((id, idx) => (
            <span key={`${String(id)}-${idx}`} className="inline-flex items-center gap-1">
              <Link
                to="/alerts/view"
                state={{ ...log.details, id, host_identifier, hostname, fromAuditTrail: true }}
                className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
              >
                #{String(id)}
              </Link>
              {idx < ids.length - 1 && <span className="text-slate-400">,</span>}
            </span>
          ))}
          {reason && <span className="text-gray-500 text-xs">— {reason}</span>}
        </span>
      );
    }

    // Isolate / re-enroll node: show node + reason (both clickable back to Audit Trail)
    if (log.action === 'ISOLATE_NODE' || log.action === 'REENROLL_NODE') {
      const isReenroll = log.action === 'REENROLL_NODE';
      const hostId =
        typeof log.details?.host_identifier === 'string'
          ? (log.details.host_identifier as string)
          : typeof log.details?.host_identifier === 'number'
            ? String(log.details.host_identifier)
            : undefined;

      const hostname = typeof log.details?.hostname === 'string' ? (log.details.hostname as string) : '';
      const displayName = hostname || hostId || '';
      const reason = typeof log.details?.reason === 'string' ? log.details.reason.trim() : '';

      const to = hostId ? `/nodes/view/${encodeURIComponent(hostId)}` : undefined;
      if (!to) {
        const base = isReenroll ? 'Re-enrolled node' : 'Isolated node';
        return reason ? `${base} — ${reason}` : base;
      }

      return (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <span>{isReenroll ? 'Re-enrolled node' : 'Isolated node'}</span>
          {displayName && (
            <Link
              to={to}
              state={{ fromAuditTrail: true }}
              className="text-blue-600 hover:text-blue-800 underline underline-offset-2 font-medium"
            >
              {displayName}
            </Link>
          )}
          {reason && <span className="text-gray-500 text-xs">— {reason}</span>}
        </span>
      );
    }

    // Rename node: show old + new name, both clickable to node sheet
    if (log.action === 'RENAME_NODE') {
      const hostId =
        typeof log.details?.host_identifier === 'string'
          ? (log.details.host_identifier as string)
          : typeof log.details?.host_identifier === 'number'
            ? String(log.details.host_identifier)
            : undefined;

      const oldName =
        log.details?.old_hostname != null ? String(log.details.old_hostname) : log.details?.old_name != null ? String(log.details.old_name) : '';
      const newName =
        log.details?.new_hostname != null ? String(log.details.new_hostname) : log.details?.new_name != null ? String(log.details.new_name) : '';

      const to = hostId ? `/nodes/view/${encodeURIComponent(hostId)}` : undefined;

      if (!to) {
        if (oldName && newName) return `Renamed node from ${oldName} to ${newName}`;
        if (newName) return `Renamed node to ${newName}`;
        return 'Node renamed';
      }

      if (oldName && newName) {
        return (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <span>Renamed node</span>
            <span className="text-slate-500">from</span>
            <NameLink to={to}>{oldName}</NameLink>
            <span className="text-slate-500">to</span>
            <NameLink to={to}>{newName}</NameLink>
          </span>
        );
      }

      if (newName) {
        return (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <span>Renamed node to</span>
            <NameLink to={to}>{newName}</NameLink>
          </span>
        );
      }

      return 'Node renamed';
    }

    return formatAuditAction(log);
  };

  return (
    <div className="min-h-screen bg-[#f8f9fb] pb-8 md:pb-6">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 text-white mb-5"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0 max-w-xl shrink-0">
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center">
                <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                Audit trail
              </h1>
              <p className="mt-1 text-sm text-blue-100 min-h-[2.5em]">{titleMeta.blurb}</p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center lg:justify-end">
              <div className="relative w-full sm:w-64">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-white/50 pointer-events-none">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </span>
                <input
                  type="text"
                  value={searchInput}
                  onChange={(e) => setSearchInput(sanitizeAsciiSingleLine(e.target.value, 200, false))}
                  placeholder="Search users, emails, hostnames, IDs…"
                  className="h-10 w-full rounded-xl border border-white/20 bg-white/10 pl-10 pr-10 text-sm text-white placeholder-white/50 outline-none backdrop-blur-sm transition focus:border-white/40 focus:bg-white/20 focus:ring-2 focus:ring-white/20"
                  aria-label="Search logs"
                />
                {searchInput && (
                  <button
                    type="button"
                    onClick={() => setSearchInput('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex h-6 w-6 items-center justify-center rounded-lg text-white/70 hover:text-white hover:bg-white/10 transition"
                    aria-label="Clear search"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>

              {/* Tab switcher — same pill-nav treatment used on Compliance */}
              <div className="relative inline-flex items-center gap-0.5 rounded-full border border-white/20 bg-white/10 backdrop-blur-sm p-1 overflow-x-auto scrollbar-hide max-w-full">
                {([
                  { id: 'user', label: 'User activity', count: countMeta.userCount },
                  { id: 'agent', label: 'Agent actions', count: countMeta.agentCount },
                  { id: 'alerts', label: 'Alert logs', count: countMeta.alertCount },
                  { id: 'sessions', label: 'Sessions', count: countMeta.sessionsCount },
                ] as Array<{ id: TabId; label: string; count: number | null }>).map((t) => {
                  const active = activeTab === t.id;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => handleTabChange(t.id)}
                      aria-pressed={active}
                      className={`relative z-10 inline-flex items-center gap-1.5 rounded-full font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${active ? 'text-[rgb(4,34,119)]' : 'text-blue-100 hover:text-white'
                        }`}
                      style={{ transformStyle: 'preserve-3d' }}
                    >
                      {active && (
                        <motion.div
                          layoutId="auditTrailTabBackground"
                          transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
                          className="absolute inset-0 bg-white rounded-full shadow-sm"
                          style={{ zIndex: -1 }}
                        />
                      )}
                      <span>{t.label}</span>
                      <span
                        className={`inline-flex items-center justify-center rounded-full px-1.5 py-0.5 text-[10px] font-bold transition-colors ${active ? 'bg-[rgb(4,34,119)]/10 text-[rgb(4,34,119)]' : 'bg-white/10 text-blue-100'
                          }`}
                        title={t.count === null ? 'Count unavailable' : undefined}
                      >
                        {t.count === null ? '—' : Math.max(0, t.count).toLocaleString()}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </motion.div>

        {searchQuery && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 shadow-sm mb-4">
            <p className="text-sm text-slate-600">
              Showing results for <span className="font-semibold text-slate-800">“{searchQuery}”</span>
            </p>
            <button
              type="button"
              onClick={() => setSearchInput('')}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
            >
              Clear
            </button>
          </div>
        )}

        {activeTab === 'sessions' ? (
          <div className={!sessionsLoading && sessions.length > 0 ? "px-0 sm:px-2" : "bg-white border border-slate-200 rounded-2xl shadow-[0_16px_44px_rgba(15,23,42,0.07)] overflow-hidden"}>
            {sessionsLoading ? (
              <div className="flex flex-col items-center justify-center py-24 gap-4">
                <DuoSpinner size="lg" className="text-blue-500" />
                <p className="text-sm text-slate-500">Loading session history…</p>
              </div>
            ) : sessionsError ? (
              <EmptyState
                icon={AlertTriangle}
                title="Couldn't load session history"
                description="The request failed, so this list is not a record of no sessions. Retry to load it."
                action={{ label: 'Retry', onClick: () => fetchSessions(sessionsPage, searchQuery, sessionSortBy, sessionSortOrder) }}
              />
            ) : sessions.length === 0 ? (
              <EmptyState
                icon={History}
                title="No sessions found"
                description="Logins and logouts will appear here with duration and actions."
              />
            ) : (
              <>
                {/* Sticky Action Bar */}
                <div className="sticky top-[104px] sm:top-[88px] z-20 bg-[#f8f9fb]/90 backdrop-blur-md py-3 px-4 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-slate-200/60 shadow-sm transition-all">
                  <div className="flex items-center gap-4">
                    <div
                      className="flex items-center gap-2"
                      onClick={toggleAllSelection}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleAllSelection();
                        }
                      }}
                      title="Select all active sessions"
                      role="button"
                      tabIndex={0}
                    >
                      <div className={`w-5 h-5 shrink-0 rounded-md border flex items-center justify-center transition-all shadow-sm cursor-pointer ${
                          activeSessionCount > 0 && selectedSessionIds.size === activeSessionCount
                            ? 'bg-blue-600 border-blue-600 text-white'
                            : 'border-slate-300 bg-white hover:border-blue-400'
                        }`}>
                        {activeSessionCount > 0 && selectedSessionIds.size === activeSessionCount && (
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                        )}
                      </div>
                      <span className="text-sm font-semibold text-slate-700 select-none cursor-pointer">Select All Active</span>
                    </div>

                    {selectedSessionIds.size > 0 && (
                      <>
                        <div className="h-4 w-px bg-slate-300 hidden sm:block" />
                        <span className="text-sm text-slate-600 font-medium">
                          {selectedSessionIds.size} selected
                        </span>
                        <button
                          onClick={handleInvalidateSelected}
                          disabled={isInvalidating}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-rose-700 bg-rose-50 border border-rose-200 rounded-lg hover:bg-rose-100 disabled:opacity-50 transition shadow-sm"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                          </svg>
                          {isInvalidating ? 'Logging out...' : 'Logout Selected'}
                        </button>
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-xs font-semibold text-slate-600 uppercase tracking-wider overflow-x-auto no-scrollbar pb-1 sm:pb-0">
                    <span className="shrink-0 text-slate-400">Sort by:</span>
                    <button
                      type="button"
                      onClick={() => handleSessionSort('login_time')}
                      className={`inline-flex shrink-0 items-center gap-1.5 hover:text-slate-900 transition ${sessionSortBy === 'login_time' ? 'text-blue-600 bg-blue-50 px-2 py-1 rounded-md' : 'px-2 py-1'}`}
                    >
                      Login Time
                      {sessionSortBy === 'login_time' && (
                        <span className="text-blue-500 font-bold">{sessionSortOrder === 'asc' ? '↑' : '↓'}</span>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleSessionSort('logout_time')}
                      className={`inline-flex shrink-0 items-center gap-1.5 hover:text-slate-900 transition ${sessionSortBy === 'logout_time' ? 'text-blue-600 bg-blue-50 px-2 py-1 rounded-md' : 'px-2 py-1'}`}
                    >
                      Logout Time
                      {sessionSortBy === 'logout_time' && (
                        <span className="text-blue-500 font-bold">{sessionSortOrder === 'asc' ? '↑' : '↓'}</span>
                      )}
                    </button>
                  </div>
                </div>

                {/* Session Cards List */}
                <div className="flex flex-col gap-3">
                  {sessionsActiveFirst.map((s) => {
                      const expanded = expandedSessionId === s.id;
                      const actionsLoading = sessionActionsLoadingBySessionId[s.id] === true;
                      const actions = sessionActionsBySessionId[s.id] ?? null;

                      return (
                        <div key={s.id} className={`flex flex-col rounded-2xl bg-white border ${s.is_active ? 'border-slate-200/80 shadow-[0_4px_20px_rgba(15,23,42,0.04)]' : 'border-slate-200/40 opacity-90'} overflow-hidden transition-all duration-300 ${expanded ? 'shadow-md' : 'hover:shadow-[0_8px_30px_rgba(15,23,42,0.06)] hover:-translate-y-0.5'}`}>
                          {/* Card Row */}
                          <div
                            className={`group relative flex flex-col lg:flex-row lg:items-center gap-3 lg:gap-4 px-4 py-3 ${expanded ? 'bg-slate-50/50' : 'hover:bg-slate-50/30'} cursor-pointer`}
                            onClick={() => void toggleSessionExpanded(s.id)}
                            role="button"
                            aria-expanded={expanded}
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                void toggleSessionExpanded(s.id);
                              }
                            }}
                          >
                            <div className={`absolute left-0 top-0 bottom-0 w-1 transition-colors ${s.is_active ? 'bg-emerald-400' : 'bg-slate-200'}`} />

                            <div className="flex items-center gap-3 w-full lg:w-auto shrink-0 pl-1">
                              <div
                                onClick={(e) => { e.stopPropagation(); if (s.is_active) toggleSessionSelection(s.id, e); }}
                                onKeyDown={(e) => {
                                  if (!s.is_active) return;
                                  if (e.key === 'Enter' || e.key === ' ') {
                                    e.preventDefault();
                                    toggleSessionSelection(s.id, e);
                                  }
                                }}
                                role="checkbox"
                                aria-checked={selectedSessionIds.has(s.id)}
                                aria-label={s.is_active ? "Select session" : "Inactive sessions cannot be selected"}
                                tabIndex={s.is_active ? 0 : -1}
                                className={`shrink-0 flex items-center justify-center p-2 -m-2 ${s.is_active ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}`}
                                title={s.is_active ? "Select session" : "Inactive sessions cannot be selected"}
                              >
                                <div className={`w-5 h-5 rounded-md border flex items-center justify-center transition-all shadow-sm ${selectedSessionIds.has(s.id) ? 'bg-blue-600 border-blue-600 text-white' : 'border-slate-300 bg-white hover:border-blue-400'
                                  }`}>
                                  {selectedSessionIds.has(s.id) && (
                                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                                  )}
                                </div>
                              </div>
                              <div className="min-w-0 flex-1 lg:w-[180px]">
                                {renderUserCell(s.user_name, s.user_email)}
                              </div>
                            </div>

                            <div className="flex flex-1 min-w-0 flex-col sm:flex-row sm:items-center justify-between gap-3">
                              <div className="flex flex-col min-w-0 gap-1 text-sm">
                                <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5">
                                  <div className="flex flex-col">
                                    <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1">
                                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" /></svg>
                                      Logged in
                                    </span>
                                    <span className="font-semibold text-slate-800 text-[13px]">{new Date(s.login_time).toLocaleString()}</span>
                                  </div>

                                  <div className="w-px h-6 bg-slate-100 hidden sm:block"></div>

                                  <div className="flex flex-col min-w-[120px]">
                                    <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1">
                                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
                                      Logged out
                                    </span>
                                    {!s.is_active ? (
                                      <div className="flex flex-col">
                                        <span className={`font-bold text-[13px] ${s.logout_reason === 'admin_forced_logout' ? 'text-rose-600' : 'text-slate-800'}`}>
                                          {s.logout_reason === 'admin_forced_logout'
                                            ? 'Forced Logout'
                                            : s.logout_time
                                              ? 'Logged Out'
                                              : 'Expired'}
                                        </span>
                                        {s.logout_time && (
                                          <span className="text-[10px] text-slate-500 font-medium">
                                            {new Date(s.logout_time).toLocaleString()}
                                          </span>
                                        )}
                                      </div>
                                    ) : (
                                      <div className="flex items-center gap-1.5">
                                        <span className="inline-flex items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-bold text-emerald-700">
                                          <span className="relative flex h-1.5 w-1.5" title="Active">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                                          </span>
                                          Active
                                        </span>
                                        {s.ip_address && (
                                          <span className="text-[10px] font-medium text-slate-500 truncate max-w-[90px]" title={s.ip_address}>{s.ip_address}</span>
                                        )}
                                      </div>
                                    )}
                                  </div>

                                  <div className="w-px h-6 bg-slate-100 hidden sm:block"></div>

                                  <div className="flex flex-col">
                                    <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1">
                                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                      Duration
                                    </span>
                                    <span className="font-semibold text-slate-800 text-[13px]">
                                      {s.is_active ? '—' : formatDuration(
                                        s.duration_seconds ?? (
                                          s.logout_time
                                            ? Math.floor((new Date(s.logout_time).getTime() - new Date(s.login_time).getTime()) / 1000)
                                            : null
                                        )
                                      )}
                                    </span>
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-3 shrink-0 mt-2 lg:mt-0 justify-between lg:justify-end">
                                {s.is_active && s.user_email && (
                                  <div className="flex items-center gap-1.5 opacity-100 lg:opacity-0 lg:group-hover:opacity-100 lg:group-focus-within:opacity-100 [@media(hover:none)]:opacity-100 transition-opacity" onClick={(e) => e.stopPropagation()}>
                                    <button
                                      type="button"
                                      onClick={() => handleInvalidateSingleSession(s.id)}
                                      disabled={isInvalidating}
                                      className="px-2.5 py-1 text-[11px] font-bold text-slate-600 hover:text-rose-600 border border-slate-200 hover:border-rose-200 bg-white hover:bg-rose-50 rounded-md transition disabled:opacity-50"
                                      title="Logout this specific session"
                                    >
                                      Logout
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => s.user_email && handleInvalidateUser(s.user_email)}
                                      disabled={isInvalidating}
                                      className="px-2.5 py-1 text-[11px] font-bold text-rose-600 border border-rose-200 bg-rose-50 hover:bg-rose-100 rounded-md transition shadow-sm disabled:opacity-50"
                                      title="Logout ALL active sessions for this user"
                                    >
                                      Logout All
                                    </button>
                                  </div>
                                )}

                                <div className={`flex items-center justify-center h-6 w-6 rounded-full transition-all duration-300 ${expanded ? 'rotate-180 bg-blue-100 text-blue-600 shadow-inner' : 'bg-slate-50 text-slate-400 group-hover:bg-slate-100 group-hover:text-blue-500 border border-slate-100'}`}>
                                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 9l-7 7-7-7" /></svg>
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Expanded Section */}
                          {expanded && (
                            <div className="border-t border-slate-100 bg-slate-50/50 p-4 sm:p-6">
                              <div className="rounded-xl border border-slate-200/80 bg-white shadow-sm overflow-hidden">
                                <div className="px-5 py-3 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-white flex items-center justify-between">
                                  <p className="text-sm font-bold text-slate-800">Actions in this session</p>
                                  <span className="text-xs font-semibold text-slate-400 px-2.5 py-1 rounded-full bg-white border border-slate-200">{actions?.length || 0} items</span>
                                </div>

                                {actionsLoading ? (
                                  <div className="flex flex-col items-center justify-center gap-3 py-10">
                                    <DuoSpinner size="md" className="text-blue-500" />
                                    <p className="text-sm font-medium text-slate-500">Loading actions…</p>
                                  </div>
                                ) : actions && actions.length === 0 ? (
                                  <div className="py-10 text-center">
                                    <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 text-slate-400 mb-3">
                                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" /></svg>
                                    </div>
                                    <p className="text-sm font-medium text-slate-600">No actions recorded in this session.</p>
                                  </div>
                                ) : actions ? (
                                  <div className="max-h-[300px] overflow-y-auto table-scrollbar">
                                    <ul className="divide-y divide-slate-100">
                                      {actions.map((log) => (
                                        <li
                                          key={log.id}
                                          className="px-5 py-3.5 hover:bg-[#f8f9fb] transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 group/item"
                                          onClick={() => setSelectedLog(log)}
                                        >
                                          <div className="flex items-center gap-3.5 min-w-0">
                                            <span className={`shrink-0 inline-flex items-center justify-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border ${log.status === 'success' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-700 border-rose-200'}`}>
                                              {log.status}
                                            </span>
                                            <div className="text-sm text-slate-700 truncate font-medium group-hover/item:text-blue-600 transition-colors">
                                              {renderAuditActionCell(log)}
                                            </div>
                                          </div>
                                          <div className="text-xs text-slate-500 shrink-0 font-medium flex items-center gap-1.5">
                                            {new Date(log.created_at).toLocaleString()}
                                            <svg className="w-3.5 h-3.5 opacity-0 group-hover/item:opacity-100 text-blue-500 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                                          </div>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                ) : (
                                  <div className="py-10 text-center">
                                    <p className="text-sm font-medium text-slate-500">Click to load actions for this session.</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                </div>
                {sessionsTotalPages > 1 && (
                  <Pagination
                    page={sessionsPage}
                    totalPages={sessionsTotalPages}
                    total={sessionsTotal}
                    pageSize={ROWS_PER_PAGE}
                    onPageChange={(p) => setSessionsPage(p)}
                  />
                )}
              </>
            )}
          </div>
        ) : (
          <div className={(activeTab === 'user' || activeTab === 'alerts' || activeTab === 'agent') && !loading && visibleLogs.length > 0 ? "" : "bg-white border border-slate-200 rounded-2xl shadow-[0_16px_44px_rgba(15,23,42,0.07)] overflow-hidden"}>
            {loading ? (
              <div className="flex flex-col items-center justify-center py-24 gap-4">
                <DuoSpinner size="lg" className="text-blue-500" />
                <p className="text-sm text-slate-500">Loading audit trail…</p>
              </div>
            ) : logsError ? (
              <EmptyState
                icon={AlertTriangle}
                title="Couldn't load the audit trail"
                description="The request failed, so this view is not a record of no activity. Retry to load it."
                action={{ label: 'Retry', onClick: () => fetchLogs(page, searchQuery, sortBy, sortOrder, activeTab) }}
              />
            ) : visibleLogs.length === 0 ? (
              <EmptyState
                icon={searchQuery ? SearchX : Activity}
                title={activeTab === 'alerts' ? 'No alert logs found' : 'No activity found'}
                description={
                  searchQuery
                    ? `No results match “${searchQuery}”. Try a different search term or clear it to see all results.`
                    : 'Nothing has been logged for this view yet.'
                }
                action={searchQuery ? { label: 'Clear filters', onClick: () => setSearchInput('') } : undefined}
              />
            ) : activeTab === 'agent' ? (
              <>
                <div className="px-0 sm:px-2">
                  {groupLogsByDay(agentSortedLogs).map(([dateLabel, logsInGroup]) => (
                      <div key={dateLabel} className="mb-8 last:mb-2 relative">
                        <div className="sticky top-[104px] sm:top-[88px] z-20 bg-[#f8f9fb]/90 backdrop-blur-md py-2 mb-4 flex items-center gap-4">
                          <span className="inline-flex items-center rounded-full bg-white px-4 py-1.5 text-xs font-bold text-slate-700 uppercase tracking-widest shadow-sm border border-slate-200">
                            {dateLabel}
                          </span>
                          <div className="h-px flex-1 bg-gradient-to-r from-slate-200 to-transparent"></div>
                        </div>
                        <div className="flex flex-col gap-3">
                          {logsInGroup.map((log) => {
                            const isSuccess = log.status === 'success';
                            const type = renderAgentType(log);
                            const actionText = renderAgentAction(log);

                            let Icon = <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M12 20a8 8 0 100-16 8 8 0 000 16z" /></svg>;
                            let iconBg = 'bg-slate-100 border-slate-200';

                            if (log.action === 'BLUETOOTH') {
                              Icon = <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="m7 7 10 10-5 5V2l5 5L7 17" /></svg>;
                              iconBg = 'bg-blue-50 border-blue-100';
                            } else if (log.action === 'WIFI') {
                              Icon = <svg className="w-5 h-5 text-sky-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" /></svg>;
                              iconBg = 'bg-sky-50 border-sky-100';
                            } else if (log.action === 'USB') {
                              Icon = <Usb className="w-5 h-5 text-amber-600" />;
                              iconBg = 'bg-amber-50 border-amber-100';
                            } else if (log.action === 'PORT_BLOCK') {
                              Icon = <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>;
                              iconBg = 'bg-indigo-50 border-indigo-100';
                            } else if (log.action === 'IP_BLOCK') {
                              Icon = <svg className="w-5 h-5 text-rose-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>;
                              iconBg = 'bg-rose-50 border-rose-100';
                            } else if (log.action === 'DEFENDER') {
                              Icon = <Shield className="w-5 h-5 text-emerald-600" />;
                              iconBg = 'bg-emerald-50 border-emerald-100';
                            } else if (log.action === 'COMPLIANCE') {
                              Icon = <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg>;
                              iconBg = 'bg-purple-50 border-purple-100';
                            }

                            return (
                              <div
                                key={log.id}
                                onClick={() => setSelectedLog(log)}
                                className={`group relative flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl bg-white py-3 px-4 border border-slate-200/60 shadow-[0_4px_20px_rgba(15,23,42,0.03)] transition-all duration-300 overflow-hidden hover:shadow-[0_8px_30px_rgba(15,23,42,0.08)] hover:-translate-y-0.5 cursor-pointer`}
                                role="button"
                                tabIndex={0}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter' || e.key === ' ') {
                                    e.preventDefault();
                                    setSelectedLog(log);
                                  }
                                }}
                              >
                                <div className={`absolute left-0 top-0 bottom-0 w-1 ${isSuccess ? 'bg-emerald-400' : 'bg-rose-400'} opacity-0 transition-opacity group-hover:opacity-100`} />

                                <div className={`flex shrink-0 h-10 w-10 items-center justify-center rounded-xl border ${iconBg}`}>
                                  {Icon}
                                </div>

                                <div className="flex flex-1 min-w-0 flex-col sm:flex-row sm:items-center justify-between gap-4">
                                  <div className="flex flex-col min-w-0 gap-1.5">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-[15px] font-semibold text-slate-900 truncate">
                                        {type}
                                      </span>
                                      {isSuccess ? (
                                        <span className="inline-flex items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-bold text-emerald-700">
                                          <span className="relative flex h-1.5 w-1.5">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                                          </span>
                                          Success
                                        </span>
                                      ) : (
                                        <span className="inline-flex items-center gap-1 rounded-md border border-rose-200 bg-rose-50 px-2 py-0.5 text-[10px] font-bold text-rose-700">
                                          <span className="relative flex h-1.5 w-1.5">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-rose-500"></span>
                                          </span>
                                          Failed
                                        </span>
                                      )}
                                      <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600">
                                        {actionText}
                                      </span>
                                      <div className="flex items-center text-sm ml-1 text-slate-500">
                                        Value: <span className="ml-1 text-slate-800 font-medium">{renderAgentValue(log)}</span>
                                      </div>
                                    </div>

                                    <div className="text-sm text-slate-600 flex flex-wrap items-center gap-x-2 gap-y-1">
                                      <div className="flex items-center gap-1.5 bg-slate-50 px-2 py-0.5 rounded-md border border-slate-100">
                                        <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                        <span className="font-medium text-slate-700 truncate max-w-[120px] sm:max-w-none">{renderUserCell(log.user_name, log.user_email)}</span>
                                      </div>
                                      <span className="text-slate-300 hidden sm:inline">•</span>
                                      <div className="flex items-center gap-1.5 bg-slate-50 px-2 py-0.5 rounded-md border border-slate-100">
                                        <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                                        <span className="font-medium text-slate-700 truncate max-w-[120px] sm:max-w-none">{renderNodeCell(log.details)}</span>
                                      </div>
                                      <span className="text-slate-300 hidden md:inline">•</span>
                                      <div className="flex-1 min-w-0 flex items-center gap-1.5 text-slate-500 truncate mt-1 sm:mt-0 w-full sm:w-auto">
                                        Reason: <span className="truncate">{renderAgentReason(log)}</span>
                                      </div>
                                    </div>
                                  </div>

                                  <div className="flex shrink-0 flex-row sm:flex-col items-center sm:items-end justify-between sm:justify-start gap-1 w-full sm:w-auto mt-2 sm:mt-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-slate-100">
                                    <div className="text-sm font-semibold text-slate-800">
                                      {new Date(log.created_at).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}
                                    </div>
                                    <div className="text-xs font-medium text-slate-400">
                                      {timeAgo(log.created_at)}
                                    </div>
                                  </div>
                                </div>
                                <div className="hidden sm:flex shrink-0 items-center justify-center pl-2 text-slate-300 group-hover:text-blue-500 transition-colors">
                                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                </div>

                {totalPages > 1 && (
                  <Pagination
                    page={page}
                    totalPages={totalPages}
                    total={total}
                    pageSize={ROWS_PER_PAGE}
                    onPageChange={(p) => setPage(p)}
                  />
                )}
              </>
            ) : (
              <>
                <div className="px-0 sm:px-2">
                  {groupLogsByDay(visibleLogs).map(([dateLabel, logsInGroup]) => (
                      <div key={dateLabel} className="mb-8 last:mb-2 relative">
                        <div className="sticky top-[104px] sm:top-[88px] z-20 bg-[#f8f9fb]/90 backdrop-blur-md py-2 mb-4 flex items-center gap-4">
                          <span className="inline-flex items-center rounded-full bg-white px-4 py-1.5 text-xs font-bold text-slate-700 uppercase tracking-widest shadow-sm border border-slate-200">
                            {dateLabel}
                          </span>
                          <div className="h-px flex-1 bg-gradient-to-r from-slate-200 to-transparent"></div>
                        </div>
                        <div className="flex flex-col gap-3">
                          {logsInGroup.map((log) => {
                            const isSuccess = log.status === 'success';
                            const detailsIp = log.details?.ip_address;
                            const ip = log.ip_address?.replace(/^::ffff:/, '') || (typeof detailsIp === 'string' ? detailsIp : '') || '';

                            let Icon = <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M12 20a8 8 0 100-16 8 8 0 000 16z" /></svg>;
                            let iconBg = 'bg-slate-100 border-slate-200';
                            if (log.action === 'LOGIN') { Icon = <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" /></svg>; iconBg = 'bg-blue-50 border-blue-100'; }
                            else if (log.action === 'USER_REGISTER') { Icon = <svg className="w-5 h-5 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" /></svg>; iconBg = 'bg-emerald-50 border-emerald-100'; }
                            else if (log.action === 'PASSWORD_UPDATE') { Icon = <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>; iconBg = 'bg-purple-50 border-purple-100'; }
                            else if (log.action === 'RENAME_NODE') { Icon = <svg className="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>; iconBg = 'bg-amber-50 border-amber-100'; }
                            else if (log.action === 'ISOLATE_NODE' || log.action === 'REENROLL_NODE') { Icon = <svg className="w-5 h-5 text-rose-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m0 0v2m0-2h2m-2 0H9m3-10V4m0 0L8 8m4-4l4 4" /></svg>; iconBg = 'bg-rose-50 border-rose-100'; }
                            else if (log.action === 'NETWORK_SCAN') { Icon = <Network className="w-5 h-5 text-sky-600" />; iconBg = 'bg-sky-50 border-sky-100'; }

                            const isClickable = activeTab !== 'user';

                            return (
                              <div
                                key={log.id}
                                onClick={isClickable ? () => setSelectedLog(log) : undefined}
                                className={`group relative flex items-center gap-3 rounded-2xl bg-white py-2.5 px-4 border border-slate-200/60 shadow-[0_4px_20px_rgba(15,23,42,0.03)] transition-all duration-300 overflow-hidden ${isClickable ? 'hover:shadow-[0_8px_30px_rgba(15,23,42,0.08)] hover:-translate-y-0.5 cursor-pointer' : ''
                                  }`}
                                role={isClickable ? "button" : undefined}
                                tabIndex={isClickable ? 0 : undefined}
                                onKeyDown={isClickable ? (e) => {
                                  if (e.key === 'Enter' || e.key === ' ') {
                                    e.preventDefault();
                                    setSelectedLog(log);
                                  }
                                } : undefined}
                              >
                                <div className={`absolute left-0 top-0 bottom-0 w-1 ${isSuccess ? 'bg-emerald-400' : 'bg-rose-400'} opacity-0 transition-opacity group-hover:opacity-100`} />

                                <div className={`flex shrink-0 h-10 w-10 items-center justify-center rounded-xl border ${iconBg}`}>
                                  {Icon}
                                </div>

                                <div className="flex flex-1 min-w-0 flex-col sm:flex-row sm:items-center justify-between gap-4">
                                  <div className="flex flex-col min-w-0 gap-1">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-[15px] font-semibold text-slate-900 truncate">
                                        {log.action.replace(/_/g, ' ')}
                                      </span>
                                      {isSuccess ? (
                                        <span className="inline-flex items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-bold text-emerald-700">
                                          <span className="relative flex h-1.5 w-1.5">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                                          </span>
                                          Success
                                        </span>
                                      ) : (
                                        <span className="inline-flex items-center gap-1 rounded-md border border-rose-200 bg-rose-50 px-2 py-0.5 text-[10px] font-bold text-rose-700">
                                          <span className="relative flex h-1.5 w-1.5">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-rose-500"></span>
                                          </span>
                                          Failed
                                        </span>
                                      )}
                                      {ip && (
                                        <span className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 border border-slate-200/80">
                                          <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>
                                          {ip}
                                        </span>
                                      )}
                                    </div>
                                    <div className="text-sm text-slate-600 flex flex-wrap items-center gap-x-2 gap-y-1">
                                      <span className="font-medium text-slate-800">{[log.user_name, log.user_email].filter(Boolean).join(' · ') || '—'}</span>
                                      <span className="text-slate-300 hidden sm:inline">•</span>
                                      <span className="flex-1 min-w-0">
                                        {log.action === 'LOGIN' ? (isSuccess ? 'Logged in securely' : 'Failed login attempt') :
                                          log.action === 'USER_REGISTER' ? 'Created an account' :
                                            renderAuditActionHeading(log)}
                                      </span>
                                    </div>
                                  </div>

                                  <div className="flex shrink-0 flex-col items-start sm:items-end gap-1">
                                    <div className="text-sm font-semibold text-slate-800">
                                      {new Date(log.created_at).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}
                                    </div>
                                    <div className="text-xs font-medium text-slate-400">
                                      {timeAgo(log.created_at)}
                                    </div>
                                  </div>
                                </div>
                                {isClickable && (
                                  <div className="hidden sm:flex shrink-0 items-center justify-center pl-4 text-slate-300 group-hover:text-blue-500 transition-colors">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                </div>

                {totalPages > 1 && (
                  <Pagination
                    page={page}
                    totalPages={totalPages}
                    total={total}
                    pageSize={ROWS_PER_PAGE}
                    onPageChange={(p) => setPage(p)}
                  />
                )}
              </>
            )}
          </div>
        )}

        {selectedLog && (
          <div
            className="fixed inset-0 z-50 bg-slate-950/45 backdrop-blur-sm transition-opacity"
            onClick={() => setSelectedLog(null)}
            role="dialog"
            aria-modal="true"
            aria-label="Log details"
          >
            <div className="absolute inset-y-0 right-0 flex max-w-full">
              <div
                className="w-screen max-w-lg transform bg-white shadow-2xl transition-transform border-l border-slate-200/70 overflow-hidden flex flex-col"
                onClick={(e) => e.stopPropagation()}
              >
                {renderDetailsPanel(selectedLog)}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NotificationLogs;
