import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useState, useEffect, useCallback, useMemo, useRef, type ChangeEvent, type PointerEvent as ReactPointerEvent } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'motion/react';
import { getProfile } from '../../api/api';
import api from '../../api/axiosInstance';
import { ALERTS_URLS, NODES_URLS, USERS_URLS, getApiUrl } from '../../api/urls';
import { csrfHeadersJson, fetchWithCsrf } from '../../api/csrfClient';
import { useToast } from '../../context/useToast';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { useModalA11y } from '../../hooks/useModalA11y';
import { useAuthStatus } from '../../context/useAuthStatus';
import { useAlertsPolling } from '../../context/useAlertsPolling';
import { sanitizeAsciiMultiLine, sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import type { UserProfile } from '../../api/api';
import type { AlertData } from './AlertsView/types';
import { alertsViewApi } from './AlertsView/alertsViewApi';
import { Checkbox } from '../../components/ui/checkbox';
import { Meteors } from '../../components/ui/meteors';
import { AlertsIcon } from '../../components/icons/navIcons';
import Pagination from '../../components/ui/pagination';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select';
import SearchIcon from '@mui/icons-material/Search';
import DownloadIcon from '@mui/icons-material/Download';
import { UnmanagedHostsAlertDetails } from './UnmanagedHostsAlertDetails';
import type { UnmanagedHost } from './UnmanagedHostsAlertDetails';
import { CertInModal } from './CertInModal';
import { initialCertinFormData } from './CertInTypes';
import type { CertinFormDataType } from './CertInTypes';
import certinDraftApi from '../../api/certinDraft';
import { DuoSpinner, InlineSpinner } from '../../components/ui/loading';
import type {
  Tab, SeverityFilter, AssigneeFilter, PositiveFilter, MarkAction, UserOption,
  AlertItem, CertinDraft, CertinDraftHistoryEntry, NodePrefillData,
} from './types';
import {
  getDraftTimestampMs, isDraftWithin24Hours, isCertinDraftComplete,
  formatRelativeDuration, fmtAlertAge, normalizeSev, SEV_LABEL, MARK_ACTION_LABEL, SEV_BADGE_NEW,
  SEV_ICON_COLOR, getAlertIcon, toolbarVariants, fmtTime, getAlertAssigneeId, getBulkAssignMode,
  classifyMetaKey, ALERTS_UPDATE_URL, ALERTS_MY_LIST_URL, ALERTS_ASSIGN_URL,
  ALERTS_ASSIGNEE_URL, ROWS_PER_PAGE,
} from './utils/alertsHelpers';

// certinDraftApi removed temporarily to avoid hook ordering issues

// Types




/** Shape of a saved/loaded CERT-In draft (backend `certin-draft` endpoint). */



/** Fields consumed from `GET /nodes/:id` when prefilling CERT-In report data — the endpoint returns much more, this is just what's read here. */








// Formatters (pure, no component-scope dependencies)

const formatValue = (v: unknown): string => {
  if (v === null || v === undefined) return '';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') {
    if (v > 946684800 && v < 2147483647) return new Date(v * 1000).toLocaleString();
    return v.toLocaleString();
  }
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.map(formatValue).join(', ');
  if (typeof v === 'object') return JSON.stringify(v, null, 2);
  return String(v);
};

const formatKey = (k: string): string =>
  k.replace(/_/g, ' ')
    .split(' ')
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');

// Component

const VALID_TABS: Tab[] = ['open', 'closed', 'my'];
const VALID_ASSIGNEE_FILTERS: AssigneeFilter[] = ['assigned', 'unassigned'];
const VALID_POSITIVE_FILTERS: PositiveFilter[] = ['true_positive', 'false_positive'];
const VALID_SEVERITY_FILTERS: SeverityFilter[] = ['critical', 'high', 'medium', 'low'];

const Alerts = () => {
  const location = useLocation();
  const navigate = useNavigate();
  // Investigation filters are URL-synced (read on mount, written on change, via
  // the effect below) so a bookmarked/shared/refreshed link reproduces the same
  // filtered view instead of silently resetting to the "open" tab with no filters.
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<Tab>(() => {
    const t = searchParams.get('tab');
    return (VALID_TABS as string[]).includes(t ?? '') ? (t as Tab) : 'open';
  });
  const [search, setSearch] = useState(() => searchParams.get('search') ?? '');
  const { showToast } = useToast();
  const { newAlertIds, newMyAlertIds, markAlertInteracted } = useAlertsPolling();
  const [viewedAlertIds, setViewedAlertIds] = useState<Set<string>>(new Set());

  // Calculate unseen count: new alerts in "My Alerts" that haven't been viewed yet
  const unseenMyAlertsCount = Array.from(newMyAlertIds).filter(id => !viewedAlertIds.has(String(id))).length;

  // Calculate unseen count: new open alerts that haven't been viewed yet
  const unseenOpenAlertsCount = Array.from(newAlertIds).filter(id => !viewedAlertIds.has(String(id))).length;
  const [applied, setApplied] = useState(() => searchParams.get('search') ?? '');
  const [startDate, setStartDate] = useState(() => searchParams.get('start') ?? '');
  const [endDate, setEndDate] = useState(() => searchParams.get('end') ?? '');
  const [assigneeFilter, setAssigneeFilter] = useState<AssigneeFilter | null>(() => {
    const v = searchParams.get('assignee');
    return (VALID_ASSIGNEE_FILTERS as string[]).includes(v ?? '') ? (v as AssigneeFilter) : null;
  });
  const [positiveFilter, setPositiveFilter] = useState<PositiveFilter | null>(() => {
    const v = searchParams.get('positive');
    return (VALID_POSITIVE_FILTERS as string[]).includes(v ?? '') ? (v as PositiveFilter) : null;
  });
  const [positiveMarkPending, setPositiveMarkPending] = useState<Record<string, MarkAction>>({});
  const [page, setPage] = useState(() => {
    const p = Number(searchParams.get('page'));
    return Number.isFinite(p) && p > 0 ? Math.floor(p) : 1;
  });
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter | null>(() => {
    const v = searchParams.get('severity');
    return (VALID_SEVERITY_FILTERS as string[]).includes(v ?? '') ? (v as SeverityFilter) : null;
  });
  const [rowsPerPage, setRowsPerPage] = useState(ROWS_PER_PAGE);

  const [allAlerts, setAllAlerts] = useState<AlertItem[]>([]);
  const [severityTotals, setSeverityTotals] = useState<Record<SeverityFilter, number>>({
    critical: 0, high: 0, medium: 0, low: 0,
  });
  const [apiSeverityCounts, setApiSeverityCounts] = useState<Record<SeverityFilter, number> | null>(null);
  const [apiTotal, setApiTotal] = useState<number | null>(null);
  const [tabTotals, setTabTotals] = useState<Record<Tab, number | null>>({ open: null, closed: null, my: null });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [togglingIds, setTogglingIds] = useState<Set<string>>(new Set());

  const [statusModal, setStatusModal] = useState<{ alerts: AlertItem[]; nextOpen: boolean } | null>(null);
  const [statusReason, setStatusReason] = useState('');
  const [statusReasonError, setStatusReasonError] = useState<string | null>(null);
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  const [markModal, setMarkModal] = useState<{ alerts: AlertItem[]; mark: MarkAction } | null>(null);
  const [markReason, setMarkReason] = useState('');
  const [markReasonError, setMarkReasonError] = useState<string | null>(null);
  const [markSubmitting, setMarkSubmitting] = useState(false);

  const [exporting, setExporting] = useState(false);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportMode, setExportMode] = useState<'date' | 'pages'>('date');
  const [exportFromDate, setExportFromDate] = useState('');
  const [exportToDate, setExportToDate] = useState('');
  const [exportNumPages, setExportNumPages] = useState(5);
  const [exportModalError, setExportModalError] = useState<string | null>(null);

  const [assignModal, setAssignModal] = useState<{ alerts: AlertItem[] } | null>(null);
  const [assignUsers, setAssignUsers] = useState<UserOption[]>([]);
  const [assignUsersLoading, setAssignUsersLoading] = useState(false);
  const [assignUsersError, setAssignUsersError] = useState<string | null>(null);
  const [selectedAssigneeId, setSelectedAssigneeId] = useState<number | null>(null);
  const [assignSubmitting, setAssignSubmitting] = useState(false);
  const [assignModalError, setAssignModalError] = useState<string | null>(null);
  const [assignSearch, setAssignSearch] = useState('');
  const [assignReason, setAssignReason] = useState('');
  const [assignReasonError, setAssignReasonError] = useState<string | null>(null);

  const [unassignModal, setUnassignModal] = useState<{ alerts: AlertItem[] } | null>(null);
  const [unassignReason, setUnassignReason] = useState('');
  const [unassignReasonError, setUnassignReasonError] = useState<string | null>(null);
  const [unassignSubmitting, setUnassignSubmitting] = useState(false);

  const [selectedAlertModal, setSelectedAlertModal] = useState<AlertData | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectedQueueAlertId, setSelectedQueueAlertId] = useState<string | null>(null);
  const [metadataPanelOpen, setMetadataPanelOpen] = useState(false);
  const [metaSearch, setMetaSearch] = useState('');
  const headerSelectRef = useRef<HTMLInputElement>(null);

  // Alert Details panel resize (drag left edge)
  const ALERT_PANEL_MIN_WIDTH = 380;
  const ALERT_PANEL_MAX_WIDTH = 650;
  const [alertPanelWidth, setAlertPanelWidth] = useState<number>(ALERT_PANEL_MIN_WIDTH);
  const [isResizingAlertPanel, setIsResizingAlertPanel] = useState(false);
  const alertPanelResizeStartRef = useRef<{ startX: number; startWidth: number } | null>(null);
  // Below this, the fixed 380-650px panel would squeeze the alert table to
  // near-zero width — render as a full-screen overlay instead of an inline
  // resizable sidebar.
  const isNarrowViewport = useMediaQuery('(max-width: 1023px)');

  // Uses Pointer Capture (not document mousemove/mouseup) so the drag keeps
  // tracking — and reliably ends — even if the pointer leaves the panel or
  // the browser window before it's released.
  const handleAlertPanelResizeStart = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    alertPanelResizeStartRef.current = { startX: e.clientX, startWidth: alertPanelWidth };
    setIsResizingAlertPanel(true);
  }, [alertPanelWidth]);

  const handleAlertPanelResizeMove = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    const start = alertPanelResizeStartRef.current;
    if (!start) return;
    const delta = start.startX - e.clientX;
    const nextWidth = Math.min(ALERT_PANEL_MAX_WIDTH, Math.max(ALERT_PANEL_MIN_WIDTH, start.startWidth + delta));
    setAlertPanelWidth(nextWidth);
  }, [ALERT_PANEL_MAX_WIDTH, ALERT_PANEL_MIN_WIDTH]);

  const handleAlertPanelResizeEnd = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    if (!alertPanelResizeStartRef.current) return;
    alertPanelResizeStartRef.current = null;
    setIsResizingAlertPanel(false);
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  }, []);

  useEffect(() => {
    if (!isResizingAlertPanel) return;
    const prevUserSelect = document.body.style.userSelect;
    const prevCursor = document.body.style.cursor;
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    return () => {
      document.body.style.userSelect = prevUserSelect;
      document.body.style.cursor = prevCursor;
    };
  }, [isResizingAlertPanel]);

  const [assignedMetaLoading, setAssignedMetaLoading] = useState(false);
  const [assignedMetaError, setAssignedMetaError] = useState<string | null>(null);
  const [assignedMeta, setAssignedMeta] = useState<{
    assignedBy: { name: string; email: string } | null;
    assignee: { name: string; email: string } | null;
    assignedAt: string | null;
    status: string | null;
  } | null>(null);

  const [assigneeModalOpen, setAssigneeModalOpen] = useState(false);
  const [assigneeModalLoading, setAssigneeModalLoading] = useState(false);
  const [assigneeModalError, setAssigneeModalError] = useState<string | null>(null);
  const [assigneeModalUser, setAssigneeModalUser] = useState<{ name: string; email: string } | null>(null);


  // Report to CERT-IN
  const [reportMode, setReportMode] = useState(false);
  const [reportSelectedIds, setReportSelectedIds] = useState<Set<string>>(new Set());
  // Snapshot of which alerts the currently-open CERT-In report/draft was built from.
  // Kept separate from reportSelectedIds, which is cleared immediately after the modal
  // opens so the alert-list checkboxes reset — losing that link would break the
  // audit trail from a saved/downloaded draft back to its source alerts.
  const [reportSourceAlertIds, setReportSourceAlertIds] = useState<string[]>([]);
  const [certinModalOpen, setCertinModalOpen] = useState(false);
  const [certinFormData, setCertinFormData] = useState<CertinFormDataType>(initialCertinFormData);
  const [certinDraft, setCertinDraft] = useState<CertinDraft | null>(null);
  const [certinHistory, setCertinHistory] = useState<Array<{ id: string; actionLabel: string; userLabel: string; storedAt: string; formData: CertinFormDataType }>>([]);
  const [, setCertinDraftLoading] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const { isValid: authIsValid, loading: authLoading, refetch: refetchAuthStatus } = useAuthStatus();


  const abortRef = useRef<AbortController | null>(null);
  const fetchSeqRef = useRef(0);
  const prevNewOpenIdsRef = useRef<Set<string>>(new Set());
  const prevNewMyIdsRef = useRef<Set<string>>(new Set());

  // Copy to clipboard


  // Debounced search

  useEffect(() => {
    const t = window.setTimeout(() => { setApplied(search); }, 400);
    return () => window.clearTimeout(t);
  }, [search]);

  // URL builders

  // Only used by the bulk CSV export flow (runExportByPages), which deliberately
  // walks multiple pages of a fixed size independent of the table's rowsPerPage.
  const EXPORT_BATCH_SIZE = 100;

  const buildUrl = useCallback((p: number, rows: number = rowsPerPage) => {
    const params = new URLSearchParams();
    params.set('rows', String(rows));
    params.set('pageno', String(p));
    if (tab !== 'my') params.set('is_open', tab === 'open' ? 'true' : 'false');
    if (applied.trim()) params.set('search', applied.trim());
    if (startDate) params.set('start_time', String(Math.floor(new Date(`${startDate}T00:00:00`).getTime() / 1000)));
    if (endDate) params.set('end_time', String(Math.floor(new Date(`${endDate}T23:59:59`).getTime() / 1000)));
    if (severityFilter) params.set('severity', severityFilter);
    if (assigneeFilter && tab !== 'my') params.set('assignee', assigneeFilter);
    if (positiveFilter) params.set('positive', positiveFilter);
    const baseUrl = tab === 'my' ? ALERTS_MY_LIST_URL : ALERTS_URLS.ALERTS_LIST;
    return `${baseUrl}?${params}`;
  }, [tab, applied, startDate, endDate, severityFilter, assigneeFilter, positiveFilter, rowsPerPage]);

  // Server-side pagination: fetches exactly the current page (with all active
  // filters applied server-side via buildUrl), never the whole tab's alert set.

  const fetchPage = useCallback(async () => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const seq = ++fetchSeqRef.current;
    setLoading(true); setError(null);
    try {
      const res = await fetch(buildUrl(page), { credentials: 'include', signal: ctrl.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (seq !== fetchSeqRef.current) return;

      const pageItems: AlertItem[] = Array.isArray(data?.alerts) ? data.alerts : [];
      setAllAlerts(pageItems);
      if (data?.severity_counts) {
        setApiSeverityCounts({
          critical: data.severity_counts.critical ?? 0,
          high: data.severity_counts.high ?? 0,
          medium: data.severity_counts.medium ?? 0,
          low: data.severity_counts.low ?? 0,
        });
      }
      if (typeof data?.total === 'number') {
        setApiTotal(data.total);
        setTabTotals(prev => ({ ...prev, [tab]: data.total }));
      }
    } catch (e: unknown) {
      if (seq !== fetchSeqRef.current) return;
      const name = typeof e === 'object' && e !== null && 'name' in e ? (e as { name?: unknown }).name : undefined;
      if (name !== 'AbortError') setError('Failed to load alerts. Please try again.');
    } finally {
      if (seq === fetchSeqRef.current && !ctrl.signal.aborted) setLoading(false);
    }
  }, [buildUrl, page, tab]);

  useEffect(() => { void fetchPage(); }, [fetchPage]);
  useEffect(() => { setPage(1); }, [tab, applied, startDate, endDate, severityFilter, assigneeFilter, positiveFilter]);

  // Keep the URL in sync with the current investigation view (tab/filters/page)
  // so a browser refresh — or a bookmarked/shared link — restores it instead of
  // silently resetting to the default "open" tab with no filters. `replace:
  // true` avoids spamming browser history on every keystroke/filter click.
  useEffect(() => {
    const params = new URLSearchParams();
    if (tab !== 'open') params.set('tab', tab);
    if (applied.trim()) params.set('search', applied.trim());
    if (startDate) params.set('start', startDate);
    if (endDate) params.set('end', endDate);
    if (severityFilter) params.set('severity', severityFilter);
    if (assigneeFilter) params.set('assignee', assigneeFilter);
    if (positiveFilter) params.set('positive', positiveFilter);
    if (page > 1) params.set('page', String(page));
    setSearchParams(params, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, applied, startDate, endDate, severityFilter, assigneeFilter, positiveFilter, page]);

  useEffect(() => {
    const st = location.state as { initialAlertsTab?: Tab } | undefined;
    if (st?.initialAlertsTab === 'my') {
      setTab('my');
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, location.pathname, navigate]);

  // Clear row selection when tab or page changes (avoids stale ids across views)
  useEffect(() => {
    setSelectedIds(new Set());
    setReportSelectedIds(new Set());
    setReportMode(false);
  }, [tab, page]);

  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const valid = new Set(allAlerts.map((a) => String(a.id)));
      const next = new Set<string>();
      prev.forEach((id) => { if (valid.has(id)) next.add(id); });
      return next.size === prev.size ? prev : next;
    });
  }, [allAlerts]);

  useEffect(() => {
    const prevOpen = prevNewOpenIdsRef.current;
    const prevMy = prevNewMyIdsRef.current;
    const addedOpen: string[] = [];
    newAlertIds.forEach((id) => { if (!prevOpen.has(id)) addedOpen.push(id); });
    const addedMy: string[] = [];
    newMyAlertIds.forEach((id) => { if (!prevMy.has(id)) addedMy.push(id); });
    prevNewOpenIdsRef.current = new Set(newAlertIds);
    prevNewMyIdsRef.current = new Set(newMyAlertIds);
    const hasNewOpenForCurrentTab = tab === 'open' && addedOpen.length > 0;
    const hasNewMyForCurrentTab = tab === 'my' && (addedMy.length > 0 || addedOpen.length > 0);
    if (!hasNewOpenForCurrentTab && !hasNewMyForCurrentTab) return;
    // A new alert landed for the current tab — refresh the current page so its
    // total/severity counts stay accurate (and the new alert appears if the
    // user is on page 1, where newest-first sort would place it).
    void fetchPage();
  }, [newAlertIds, newMyAlertIds, tab, fetchPage]);

  const alertItemToAlertData = useCallback((a: AlertItem): AlertData => {
    const sev = normalizeSev(a.severity);
    const title = a.alert_type || 'Unknown Alert';
    const eventCode = a.event_code ?? '';
    const description = eventCode || '—';
    const meta = a.metadata && typeof a.metadata === 'object' ? (a.metadata as Record<string, unknown>) : null;
    const techniqueRaw = meta?.technique ?? meta?.techniques ?? meta?.type;
    const technique = typeof techniqueRaw === 'string' ? techniqueRaw : undefined;
    const timestampRaw = meta?.timestamp;
    const timestamp = typeof timestampRaw === 'string' ? timestampRaw : undefined;
    return {
      id: a.id, severity: sev, title, description, event_code: a.event_code,
      source: a.hostname, host_identifier: a.host_identifier, hostname: a.hostname,
      os_name: a.os_name, unixtime: a.unixtime, timestamp, technique,
      is_open: a.is_open, metadata: a.metadata,
      assignee_id: a.assignee_id, assignee_name: a.assignee_name, assignee_email: a.assignee_email,
      mark_type: a.mark_type ?? undefined,
    };
  }, []);

  useEffect(() => {
    if (!selectedAlertModal) return;
    const onKeyDown = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelectedAlertModal(null); };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectedAlertModal]);

  useEffect(() => {
    if (!selectedAlertModal) return;
    const selectedId = String(selectedAlertModal.id);
    const updated = allAlerts.find((a) => String(a.id) === selectedId);
    if (!updated) return;
    const next = alertItemToAlertData(updated);
    setSelectedAlertModal((prev) => {
      if (!prev) return prev;
      const p = prev as unknown as Record<string, unknown>;
      const n = next as unknown as Record<string, unknown>;
      const same =
        String(p.id) === String(n.id) && p.severity === n.severity && p.title === n.title &&
        p.description === n.description && p.event_code === n.event_code && p.source === n.source &&
        p.host_identifier === n.host_identifier && p.hostname === n.hostname && p.os_name === n.os_name &&
        String(p.unixtime ?? '') === String(n.unixtime ?? '') && p.timestamp === n.timestamp &&
        p.technique === n.technique && p.is_open === n.is_open &&
        String(p.assignee_id ?? '') === String(n.assignee_id ?? '') &&
        p.assignee_name === n.assignee_name && p.assignee_email === n.assignee_email &&
        p.mark_type === n.mark_type;
      return same ? prev : next;
    });
    // Only `selectedAlertModal.id` is read reactively (to find the matching
    // alert); the rest of `selectedAlertModal` is read via the functional
    // `prev` updater above, which must not be a dependency or this effect
    // would re-run on every field-level update it itself makes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allAlerts, selectedAlertModal?.id, alertItemToAlertData]);

  const selectedEventId = useMemo(() => {
    if (!selectedAlertModal) return null;
    const maybeNum = typeof selectedAlertModal.id === 'number'
      ? selectedAlertModal.id
      : parseInt(String(selectedAlertModal.id), 10);
    if (!Number.isFinite(maybeNum) || maybeNum <= 0) return null;
    return maybeNum;
  }, [selectedAlertModal]);

  useEffect(() => {
    if (!selectedEventId) {
      setAssignedMetaLoading(false); setAssignedMetaError(null); setAssignedMeta(null); return;
    }
    let cancelled = false;
    setAssignedMetaLoading(true); setAssignedMetaError(null); setAssignedMeta(null);
    void alertsViewApi.getAssignee(selectedEventId).then((res) => {
      if (cancelled) return;
      const data = res?.data?.data;
      const assignee = data?.assignee && (data.assignee.id != null || data.assignee.name != null || data.assignee.email != null)
        ? { name: String(data.assignee.name ?? (data.assignee.id ? `User #${data.assignee.id}` : '')), email: String(data.assignee.email ?? '') }
        : null;
      const assignedBy = data?.assignedBy && (data.assignedBy.id != null || data.assignedBy.name != null || data.assignedBy.email != null)
        ? { name: String(data.assignedBy.name ?? (data.assignedBy.id ? `User #${data.assignedBy.id}` : '')), email: String(data.assignedBy.email ?? '') }
        : null;
      const assignedAt = data?.assignedAt != null ? String(data.assignedAt) : null;
      const status = typeof data?.status === 'string' ? data.status : null;
      setAssignedMeta({ assignedBy, assignee, assignedAt, status });
    }).catch(() => { if (cancelled) return; setAssignedMetaError('Failed to load assignment details.'); })
      .finally(() => { if (cancelled) return; setAssignedMetaLoading(false); });
    return () => { cancelled = true; };
  }, [selectedEventId]);

  // Fetch assignment data when table alert is clicked

  const selectedQueueAlertId_EventId = useMemo(() => {
    if (!selectedQueueAlertId) return null;
    const maybeNum = typeof selectedQueueAlertId === 'number'
      ? selectedQueueAlertId
      : parseInt(String(selectedQueueAlertId), 10);
    if (!Number.isFinite(maybeNum) || maybeNum <= 0) return null;
    return maybeNum;
  }, [selectedQueueAlertId]);

  useEffect(() => {
    if (!selectedQueueAlertId_EventId) {
      setAssignedMetaLoading(false); setAssignedMetaError(null); setAssignedMeta(null); return;
    }
    let cancelled = false;
    setAssignedMetaLoading(true); setAssignedMetaError(null); setAssignedMeta(null);
    void alertsViewApi.getAssignee(selectedQueueAlertId_EventId).then((res) => {
      if (cancelled) return;
      const data = res?.data?.data;
      const assignee = data?.assignee && (data.assignee.id != null || data.assignee.name != null || data.assignee.email != null)
        ? { name: String(data.assignee.name ?? (data.assignee.id ? `User #${data.assignee.id}` : '')), email: String(data.assignee.email ?? '') }
        : null;
      const assignedBy = data?.assignedBy && (data.assignedBy.id != null || data.assignedBy.name != null || data.assignedBy.email != null)
        ? { name: String(data.assignedBy.name ?? (data.assignedBy.id ? `User #${data.assignedBy.id}` : '')), email: String(data.assignedBy.email ?? '') }
        : null;
      const assignedAt = data?.assignedAt != null ? String(data.assignedAt) : null;
      const status = typeof data?.status === 'string' ? data.status : null;
      setAssignedMeta({ assignedBy, assignee, assignedAt, status });
    }).catch(() => { if (cancelled) return; setAssignedMetaError('Failed to load assignment details.'); })
      .finally(() => { if (cancelled) return; setAssignedMetaLoading(false); });
    return () => { cancelled = true; };
  }, [selectedQueueAlertId_EventId]);

  // Status modal

  const openStatusModal = (alert: AlertItem) => {
    setStatusModal({ alerts: [alert], nextOpen: !alert.is_open });
    setStatusReason(''); setStatusReasonError(null);
  };
  const closeStatusModal = () => { setStatusModal(null); setStatusReason(''); setStatusReasonError(null); };

  // Mark modal

  const openMarkModal = useCallback((input: AlertItem | AlertItem[], mark: MarkAction) => {
    const alertsToMark = (Array.isArray(input) ? input : [input]).filter((a) => {
      const idNum = typeof a.id === 'number' ? a.id : Number(a.id);
      return Number.isFinite(idNum) && idNum > 0;
    });
    if (alertsToMark.length === 0) { showToast('Invalid alert id for marking.', 'warning'); return; }
    setMarkModal({ alerts: alertsToMark, mark });
    setMarkReason(''); setMarkReasonError(null);
  }, [showToast]);

  const closeMarkModal = () => {
    const keys = markModal ? markModal.alerts.map((a) => String(a.id)) : [];
    setMarkModal(null); setMarkReason(''); setMarkReasonError(null);
    if (keys.length > 0) {
      setPositiveMarkPending(prev => {
        const hasAnyPending = keys.some((k) => prev[k] != null);
        if (!hasAnyPending) return prev;
        const next = { ...prev };
        keys.forEach((k) => delete next[k]);
        return next;
      });
    }
  };

  const handleMarkSubmit = async () => {
    if (!markModal) return;
    const { alerts, mark } = markModal;
    const eventIds = alerts.map((a) => (typeof a.id === 'number' ? a.id : Number(a.id))).filter((n) => Number.isFinite(n) && n > 0);
    const keys = alerts.map((a) => String(a.id));
    const trimmedReason = markReason.trim();
    if (eventIds.length === 0) { setMarkReasonError('Invalid alert selection for marking.'); return; }
    if (!trimmedReason) { setMarkReasonError('Reason is required.'); return; }
    setMarkSubmitting(true); setMarkReasonError(null);
    setTogglingIds(prev => { const s = new Set(prev); keys.forEach((k) => s.add(k)); return s; });
    setPositiveMarkPending((prev) => {
      const next = { ...prev };
      keys.forEach((k) => { next[k] = mark; });
      return next;
    });
    try {
      const res = await fetchWithCsrf(ALERTS_UPDATE_URL, {
        method: 'POST', credentials: 'include', headers: csrfHeadersJson(),
        body: JSON.stringify({ event_id: eventIds, action: mark, reason: trimmedReason }),
      });
      if (!res.ok) { const errBody = await res.json().catch(() => ({})); throw new Error(errBody?.message || `HTTP ${res.status}`); }
      const markedKeys = new Set(keys);
      const storedMark = mark === 'unmarked' ? null : mark;
      setAllAlerts((prev) => prev.map((a) => (markedKeys.has(String(a.id)) ? { ...a, mark_type: storedMark, action: storedMark } : a)));
      // Re-fetch from the server: with server-side filtering, a mark change can
      // move an alert out of the active `positive` filter — the optimistic
      // update above keeps the UI responsive, this corrects the page afterward.
      void fetchPage();
      closeMarkModal();
      if (mark === 'unmarked') {
        showToast(eventIds.length > 1 ? `Removed classification from ${eventIds.length} alerts` : 'Classification removed');
      } else if (eventIds.length > 1) {
        showToast(`Marked ${eventIds.length} alerts as ${MARK_ACTION_LABEL[mark]}`);
      } else {
        showToast(`Marked as ${MARK_ACTION_LABEL[mark]}`);
      }
      clearSelection();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to mark alert. Please try again.';
      setMarkReasonError(msg); showToast('Failed to mark alert', 'error');
      // Roll back the optimistic badge since the request didn't succeed.
      setPositiveMarkPending(prev => {
        const next = { ...prev };
        keys.forEach((k) => delete next[k]);
        return next;
      });
    } finally {
      setMarkSubmitting(false);
      setTogglingIds(prev => { const s = new Set(prev); keys.forEach((k) => s.delete(k)); return s; });
    }
  };

  const handleMarkPositive = useCallback((alert: AlertItem, mark: MarkAction) => { openMarkModal(alert, mark); }, [openMarkModal]);

  // Selection

  const toggleSelectId = (id: number | string) => {
    const key = String(id);
    setSelectedIds((prev) => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; });
  };
  const clearSelection = () => setSelectedIds(new Set());

  const openBulkStatusModal = (alerts: AlertItem[], nextOpen: boolean) => {
    if (alerts.length === 0) return;
    setStatusModal({ alerts, nextOpen }); setStatusReason(''); setStatusReasonError(null);
  };

  // Assign modal

  const closeAssignModal = () => {
    setAssignModal(null); setSelectedAssigneeId(null); setAssignModalError(null);
    setAssignSearch(''); setAssignReason(''); setAssignReasonError(null);
  };

  const fetchAssignUsers = useCallback(async () => {
    if (assignUsersLoading || assignUsers.length > 0) return;
    setAssignUsersLoading(true); setAssignUsersError(null);
    try {
      const res = await fetch(USERS_URLS.LIST, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const users: UserOption[] = Array.isArray(data?.data?.users) ? data.data.users : Array.isArray(data?.users) ? data.users : [];
      setAssignUsers(users);
    } catch { setAssignUsersError('Failed to load users. Please try again.'); }
    finally { setAssignUsersLoading(false); }
  }, [assignUsers, assignUsersLoading]);

  const openAssignModal = useCallback((alert: AlertItem) => {
    setAssignModal({ alerts: [alert] }); setSelectedAssigneeId(null); setAssignModalError(null);
    setAssignSearch(''); setAssignReason(''); setAssignReasonError(null);
    void fetchAssignUsers();
  }, [fetchAssignUsers]);

  const openBulkAssignModal = (items: AlertItem[]) => {
    const openOnly = items.filter((a) => a.is_open);
    if (openOnly.length === 0) { showToast('Select at least one open alert', 'warning'); return; }
    setAssignModal({ alerts: openOnly }); setSelectedAssigneeId(null); setAssignModalError(null);
    setAssignSearch(''); setAssignReason(''); setAssignReasonError(null);
    void fetchAssignUsers();
  };

  const filteredAssignUsers = useMemo(() => {
    const q = assignSearch.trim().toLowerCase();
    if (!q) return assignUsers;
    return assignUsers.filter((u) => `${u.name} ${u.email}`.toLowerCase().includes(q));
  }, [assignUsers, assignSearch]);

  const handleAssignSubmit = async () => {
    if (!assignModal) return;
    if (selectedAssigneeId == null) { setAssignModalError('Please select a user to assign this alert.'); return; }
    const trimmedReason = assignReason.trim();
    if (!trimmedReason) { setAssignReasonError('Reason is required.'); return; }
    const alertIds = assignModal.alerts
      .map((a) => (typeof a.id === 'number' ? a.id : Number(a.id)))
      .filter((n) => Number.isFinite(n) && n > 0);
    if (alertIds.length === 0) { setAssignModalError('Invalid alert id(s).'); return; }
    setAssignSubmitting(true); setAssignModalError(null); setAssignReasonError(null);
    try {
      const res = await fetchWithCsrf(ALERTS_ASSIGN_URL, {
        method: 'POST', credentials: 'include', headers: csrfHeadersJson(),
        body: JSON.stringify({ event_id: alertIds, assignee_id: selectedAssigneeId, reason: trimmedReason }),
      });
      if (!res.ok) { const errBody = await res.json().catch(() => ({})); throw new Error(errBody?.message || `HTTP ${res.status}`); }
      const assignedKeys = new Set(alertIds.map(String));
      const assignedUser = filteredAssignUsers.find((u) => u.id === selectedAssigneeId) ?? assignUsers.find((u) => u.id === selectedAssigneeId);
      setAllAlerts((prev) => prev.map((a) => (assignedKeys.has(String(a.id))
        ? { ...a, assignee_id: selectedAssigneeId, assignee_name: assignedUser?.name ?? a.assignee_name, assignee_email: assignedUser?.email ?? a.assignee_email }
        : a)));
      // An assignment change can move an alert out of the active `assignee`
      // filter (or off the "my" tab entirely) — refetch to correct the page.
      void fetchPage();
      showToast('Alert assigned successfully'); closeAssignModal();
    } catch { setAssignModalError('Failed to assign alert. Please try again.'); showToast('Failed to assign alert', 'error'); }
    finally { setAssignSubmitting(false); }
  };

  // Unassign modal

  const openUnassignModal = (alert: AlertItem) => {
    setUnassignModal({ alerts: [alert] });
    setUnassignReason(''); setUnassignReasonError(null);
  };

  const closeUnassignModal = () => {
    setUnassignModal(null); setUnassignReason(''); setUnassignReasonError(null);
  };

  const handleUnassignSubmit = async () => {
    if (!unassignModal) return;
    const trimmedReason = unassignReason.trim();
    if (!trimmedReason) { setUnassignReasonError('Reason is required.'); return; }
    const alertIds = unassignModal.alerts
      .map((a) => (typeof a.id === 'number' ? a.id : Number(a.id)))
      .filter((n) => Number.isFinite(n) && n > 0);
    if (alertIds.length === 0) { setUnassignReasonError('Invalid alert id(s).'); return; }
    setUnassignSubmitting(true); setUnassignReasonError(null);
    try {
      const res = await fetchWithCsrf(ALERTS_ASSIGN_URL, {
        method: 'POST', credentials: 'include', headers: csrfHeadersJson(),
        body: JSON.stringify({ event_id: alertIds, assignee_id: null, reason: trimmedReason }),
      });
      if (!res.ok) { const errBody = await res.json().catch(() => ({})); throw new Error(errBody?.message || `HTTP ${res.status}`); }
      const unassignedKeys = new Set(alertIds.map(String));
      setAllAlerts((prev) => prev.map((a) => (unassignedKeys.has(String(a.id))
        ? { ...a, assignee_id: null, assignee_name: null, assignee_email: null }
        : a)));
      // An unassign can move an alert out of the active `assignee` filter —
      // refetch to correct the page.
      void fetchPage();
      showToast('Alert unassigned successfully'); closeUnassignModal();
    } catch { setUnassignReasonError('Failed to unassign alert. Please try again.'); showToast('Failed to unassign alert', 'error'); }
    finally { setUnassignSubmitting(false); }
  };

  const closeAssigneeModal = () => {
    setAssigneeModalOpen(false); setAssigneeModalUser(null);
    setAssigneeModalError(null); setAssigneeModalLoading(false);
  };

  const fetchAssigneeModalUser = useCallback(async (eventId: number | string) => {
    setAssigneeModalLoading(true); setAssigneeModalError(null); setAssigneeModalUser(null);
    try {
      const params = new URLSearchParams({ id: String(eventId) });
      const res = await fetch(`${ALERTS_ASSIGNEE_URL}?${params.toString()}`, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const user = data?.data?.assignee;
      if (user && (typeof user.name === 'string' || typeof user.email === 'string')) {
        setAssigneeModalUser({ name: String(user.name ?? ''), email: String(user.email ?? '') });
      } else { setAssigneeModalUser(null); }
    } catch { setAssigneeModalError('Failed to load user info. Please try again.'); }
    finally { setAssigneeModalLoading(false); }
  }, []);

  const openAssigneeModal = (alert: AlertItem) => {
    const idNum = typeof alert.id === 'number' ? alert.id : (() => { const n = Number(alert.id); return Number.isFinite(n) ? n : null; })();
    setAssigneeModalOpen(true); setAssigneeModalError(null); setAssigneeModalUser(null);
    if (idNum != null) void fetchAssigneeModalUser(idNum);
    else setAssigneeModalError('Invalid alert id.');
  };

  const handleStatusSubmit = async () => {
    if (!statusModal) return;
    const trimmedReason = statusReason.trim();
    if (!trimmedReason) { setStatusReasonError('Reason is required.'); return; }
    const { alerts, nextOpen } = statusModal;
    const eventIds = alerts.map((a) => Number(a.id)).filter((n) => Number.isFinite(n));
    if (eventIds.length === 0) { setStatusReasonError('Invalid alert selection.'); return; }
    const keys = alerts.map((a) => String(a.id));
    setStatusSubmitting(true);
    setTogglingIds((prev) => { const s = new Set(prev); keys.forEach((k) => s.add(k)); return s; });
    try {
      const res = await fetchWithCsrf(ALERTS_UPDATE_URL, {
        method: 'POST', credentials: 'include', headers: csrfHeadersJson(),
        body: JSON.stringify({ event_id: eventIds, is_open: nextOpen, reason: trimmedReason }),
      });
      if (!res.ok) { const errBody = await res.json().catch(() => ({})); throw new Error(errBody?.message || `HTTP ${res.status}`); }
      const n = eventIds.length;
      showToast(n === 1 ? 'Alert updated successfully' : `${n} alerts updated successfully`);
      closeStatusModal(); clearSelection();
      // Re-fetch from the server rather than splicing locally — a status change
      // can shrink the current page below its normal size (or empty it out
      // entirely), and only the server knows the correct replacement page
      // contents once affected alerts move between the open/closed/my tabs.
      void fetchPage();
    } catch {
      void fetchPage();
      setError('Failed to update alert(s). Please try again.'); showToast('Failed to update alert(s)', 'error');
    } finally {
      setStatusSubmitting(false);
      setTogglingIds((prev) => { const s = new Set(prev); keys.forEach((k) => s.delete(k)); return s; });
    }
  };

  // Filters / search

  const handleSearch = (e: React.FormEvent) => { e.preventDefault(); setApplied(search); };

  const clearFilters = () => {
    setSearch(''); setApplied(''); setStartDate(''); setEndDate('');
    setSeverityFilter(null); setAssigneeFilter(null); setPositiveFilter(null);
  };

  // Export

  const openExportModal = () => { setExportFromDate(startDate); setExportToDate(endDate); setExportModalError(null); setExportModalOpen(true); };
  const closeExportModal = () => { setExportModalOpen(false); setExportFromDate(''); setExportToDate(''); setExportMode('date'); setExportNumPages(5); setExportModalError(null); };

  // Modal accessibility (Tab focus-trap, Escape-to-close, focus restore on close)
  const exportModalContainerRef = useModalA11y<HTMLDivElement>(exportModalOpen, closeExportModal);
  const statusModalContainerRef = useModalA11y<HTMLDivElement>(!!statusModal, closeStatusModal);
  const markModalContainerRef = useModalA11y<HTMLDivElement>(!!markModal, closeMarkModal);
  const assignModalContainerRef = useModalA11y<HTMLDivElement>(!!assignModal, closeAssignModal);
  const unassignModalContainerRef = useModalA11y<HTMLDivElement>(!!unassignModal, closeUnassignModal);
  const assigneeModalContainerRef = useModalA11y<HTMLDivElement>(assigneeModalOpen, closeAssigneeModal);

  const buildAlertsCsv = (list: AlertItem[]): string => {
    const headers = ['Host ID', 'Hostname', 'Time', 'Event Code', 'Alert Type', 'Severity', 'Status', 'OS'];
    const rows = list.map(a => {
      const time = a.unixtime ?? (a as unknown as { unixTime?: string | number }).unixTime;
      return [a.host_identifier ?? '', a.hostname ?? '', fmtTime(time), a.event_code ?? '', a.alert_type ?? '', normalizeSev(a.severity), a.is_open ? 'Open' : 'Closed', a.os_name ?? ''];
    });
    return [headers.join(','), ...rows.map(r => r.map(cell => {
      let str = String(cell);
      if (/^[=+\-@]/.test(str)) str = "'" + str;
      return `"${str.replace(/"/g, '""')}"`;
    }).join(','))].join('\n');
  };

  const runExportByDate = async (fromDate: string, toDate: string) => {
    setExportModalError(null);
    const startUnix = fromDate ? Math.floor(new Date(`${fromDate}T00:00:00`).getTime() / 1000) : null;
    const endUnix = toDate ? Math.floor(new Date(`${toDate}T23:59:59`).getTime() / 1000) : null;
    if (startUnix == null || endUnix == null) { setExportModalError('Please select both From and To dates'); return; }
    if (startUnix > endUnix) { setExportModalError('From date cannot be after To date'); return; }
    const todayStr = new Date().toISOString().slice(0, 10);
    if (toDate > todayStr) { setExportModalError('To date cannot be beyond today'); return; }
    setExporting(true);
    try {
      const exportUrl = `${getApiUrl(ALERTS_URLS.EXPORT)}?start_time=${startUnix}&end_time=${endUnix}`;
      const res = await fetch(exportUrl, { credentials: 'include' });
      const data = await res.json();
      if (!res.ok) { setExportModalError(data?.message || 'Export failed'); return; }
      const list = Array.isArray(data) ? data : null;
      if (!list || list.length === 0) { setExportModalError('No alerts in the selected date range'); return; }
      const csvContent = buildAlertsCsv(list);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `alerts-export-${fromDate}-${toDate}.csv`; link.click();
      URL.revokeObjectURL(url); showToast(`Exported ${list.length} alert(s)`); closeExportModal();
    } catch { setExportModalError('Export failed'); }
    finally { setExporting(false); }
  };

  const runExportByPages = async (numPages: number) => {
    setExportModalError(null);
    if (numPages < 1 || numPages > 100) { setExportModalError('Please enter a number of pages between 1 and 100'); return; }
    setExporting(true);
    try {
      const allAlerts: AlertItem[] = [];
      for (let p = 1; p <= numPages; p++) {
        const listUrl = buildUrl(p, EXPORT_BATCH_SIZE);
        const res = await fetch(listUrl, { credentials: 'include' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const pageAlerts = data.alerts ?? [];
        if (pageAlerts.length === 0) break;
        allAlerts.push(...pageAlerts);
      }
      if (allAlerts.length === 0) { setExportModalError('No alerts to export for the selected pages'); return; }
      const csvContent = buildAlertsCsv(allAlerts);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `alerts-export-latest-${numPages}-pages.csv`; link.click();
      URL.revokeObjectURL(url); showToast(`Exported ${allAlerts.length} alert(s) from latest ${numPages} page(s)`); closeExportModal();
    } catch { setExportModalError('Export failed'); }
    finally { setExporting(false); }
  };

  const handleExportSubmit = () => {
    if (exportMode === 'date') runExportByDate(exportFromDate, exportToDate);
    else runExportByPages(exportNumPages);
  };

  // Derived lists

  const hasFilters = !!(applied || startDate || endDate || severityFilter || assigneeFilter || positiveFilter);

  // Search/date/severity/assignee/positive filtering now all happens server-side
  // (via buildUrl, in fetchPage) — allAlerts already IS the current, filtered page.
  // The only client-side work left is the "my" tab's new-alerts-first resort,
  // which is cheap since it only ever operates on one page's worth of rows.
  const filteredAlertsAll = useMemo(() => {
    if (tab !== 'my') return allAlerts;
    const isNewMy = (a: AlertItem) => { const key = String(a.id); return newMyAlertIds.has(key) || newAlertIds.has(key); };
    return [...allAlerts].sort((a, b) => {
      const aNew = isNewMy(a) ? 1 : 0; const bNew = isNewMy(b) ? 1 : 0;
      if (aNew !== bNew) return bNew - aNew;
      const ta = typeof a.unixtime === 'string' ? Number(a.unixtime) : Number(a.unixtime ?? 0);
      const tb = typeof b.unixtime === 'string' ? Number(b.unixtime) : Number(b.unixtime ?? 0);
      if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return tb - ta;
      return String(b.id).localeCompare(String(a.id));
    });
  }, [allAlerts, tab, newAlertIds, newMyAlertIds]);

  // apiTotal is server-authoritative (filters are applied server-side now).
  const total = apiTotal ?? allAlerts.length;
  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));

  // allAlerts already IS the current page (fetched with rows=rowsPerPage,
  // pageno=page) — no client-side slicing needed, just the "my" tab resort above.
  const pageAlerts = filteredAlertsAll;

  // Clamp page back into range if a bulk status change (or filter change) shrinks totalPages below it.
  useEffect(() => {
    setPage((prev) => Math.min(Math.max(prev, 1), totalPages));
  }, [totalPages]);

  useEffect(() => {
    // Always calculate severity counts from filteredAlertsAll
    const counts = allAlerts.reduce((acc, a) => {
      const k = normalizeSev(a.severity);
      if (k === 'critical' || k === 'high' || k === 'medium' || k === 'low') acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
    setSeverityTotals(counts);
  }, [allAlerts]);

  const selectAllOnPage = useCallback(() => { setSelectedIds(new Set(pageAlerts.map((a) => String(a.id)))); }, [pageAlerts]);
  const selectedAlertsOnPage = useMemo(() => pageAlerts.filter((a) => selectedIds.has(String(a.id))), [pageAlerts, selectedIds]);

  const bulkSelectionMeta = useMemo(() => {
    const sel = selectedAlertsOnPage;
    const openRows = sel.filter((a) => a.is_open);
    const closedRows = sel.filter((a) => !a.is_open);
    const assignMode = getBulkAssignMode(openRows);
    return { total: sel.length, openCount: openRows.length, closedCount: closedRows.length, openRows, closedRows, closableOpenRows: openRows, reopenableClosedRows: closedRows, bulkAssignMode: assignMode };
  }, [selectedAlertsOnPage]);

  const selectionActive = bulkSelectionMeta.total > 0;

  const allOnPageSelected = pageAlerts.length > 0 && pageAlerts.every((a) => selectedIds.has(String(a.id)));
  const someOnPageSelected = pageAlerts.some((a) => selectedIds.has(String(a.id)));
  const allOnPageSelectedReport = pageAlerts.length > 0 && pageAlerts.every((a) => reportSelectedIds.has(String(a.id)));
  const someOnPageSelectedReport = pageAlerts.some((a) => reportSelectedIds.has(String(a.id)));

  useEffect(() => {
    const el = headerSelectRef.current;
    if (!el) return;
    el.indeterminate = reportMode ? (someOnPageSelectedReport && !allOnPageSelectedReport) : (someOnPageSelected && !allOnPageSelected);
  }, [someOnPageSelected, allOnPageSelected, someOnPageSelectedReport, allOnPageSelectedReport, reportMode]);


  const onHeaderSelectChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) selectAllOnPage(); else clearSelection();
  };

  const runBulkClose = () => {
    const items = bulkSelectionMeta.closableOpenRows;
    if (items.length === 0) { showToast('No open alerts in selection. Only open alerts can be closed.'); return; }
    const skipped = bulkSelectionMeta.closedCount;
    if (skipped > 0) showToast(`${skipped} resolved alert(s) skipped · closing ${items.length} open alert(s)`);
    openBulkStatusModal(items, false);
  };

  const runBulkReopen = () => {
    const items = bulkSelectionMeta.reopenableClosedRows;
    if (items.length === 0) { showToast('No closed alerts in selection. Only closed alerts can be reopened.'); return; }
    const skipped = bulkSelectionMeta.openCount;
    if (skipped > 0) showToast(`${skipped} open alert(s) skipped · reopening ${items.length} closed alert(s)`);
    openBulkStatusModal(items, true);
  };

  const runBulkAssign = () => {
    const items = bulkSelectionMeta.openRows;
    if (items.length === 0) { showToast('No open alerts in selection. Assignment applies to open alerts only.'); return; }
    const skipped = bulkSelectionMeta.closedCount;
    if (skipped > 0) showToast(`${skipped} closed alert(s) skipped · ${items.length} open alert(s) will be updated`);
    openBulkAssignModal(items);
  };

  const handleDownloadPDF = async () => {
    try {
      const [{ pdf }, { CertInPDFDocument }] = await Promise.all([
        import('@react-pdf/renderer'),
        import('./CertInPDFDocument'),
      ]);
      const blob = await pdf(<CertInPDFDocument data={certinFormData} />).toBlob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cert-in-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      try {
        const saveRes = await certinDraftApi.saveCertinDraft(certinFormData, reportSourceAlertIds);
        const draftId = saveRes?.data?.draftId;
        if (draftId) await certinDraftApi.markCertinDraftDownloaded(draftId);
        await loadCertinDraft();
      } catch (e) {
        console.warn('Failed to persist CERT-In download audit metadata', e);
        showToast('Report downloaded, but the audit-trail link to its source alerts may not have been saved.', 'error');
      }
      setCertinModalOpen(false);
      showToast('CERT-In report PDF generated successfully.', 'success');
    } catch (error) {
      console.error('Failed to generate CERT-In PDF', error);
      showToast('Failed to generate CERT-In report PDF.', 'error');
    }
  };

  const handleDownloadPDFForData = async (formData: CertinFormDataType) => {
    try {
      const [{ pdf }, { CertInPDFDocument }] = await Promise.all([
        import('@react-pdf/renderer'),
        import('./CertInPDFDocument'),
      ]);
      const blob = await pdf(<CertInPDFDocument data={formData} />).toBlob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cert-in-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      showToast('CERT-In report PDF generated successfully.', 'success');
    } catch (error) {
      console.error('Failed to generate CERT-In PDF', error);
      showToast('Failed to generate CERT-In report PDF.', 'error');
    }
  };

  const loadCertinDraft = useCallback(async () => {
    setCertinDraftLoading(true);
    try {
      // Ensure auth status is fresh — this may renew access token via refresh token on the server.
      try {
        await refetchAuthStatus?.({ silent: true });
      } catch {
        // ignore — we'll handle auth failure below when calling the draft endpoint
      }
      const res = await certinDraftApi.getCertinDraft();
      // backend may return { draft } or draft directly
      const draft = res?.data?.draft ?? res?.data ?? null;
      if (draft) {
        setCertinDraft(draft);
      } else {
        setCertinDraft(null);
      }
    } catch {
      setCertinDraft(null);
    } finally {
      setCertinDraftLoading(false);
    }
  }, [refetchAuthStatus]);

  const loadCertinHistory = async () => {
    try {
      const res = await certinDraftApi.getCertinDraftHistory();
      const history: CertinDraftHistoryEntry[] = Array.isArray(res?.data?.history) ? res.data.history : [];
      const mapped = history
        .filter((h) => h?.formData)
        .map((h, idx: number) => {
          const eventType = String(h?.eventType ?? '').toLowerCase();
          const actionLabel = eventType === 'started'
            ? 'Started draft'
            : eventType === 'completed'
              ? 'Completed draft'
              : eventType === 'downloaded'
                ? 'Downloaded draft'
                : 'Edited draft';
          const userLabel = h?.actor?.name || h?.actor?.email || (h?.actor?.userId ? `User #${h.actor.userId}` : 'Unknown user');
          return {
            id: `${h?.filename ?? 'item'}-${idx}`,
            actionLabel,
            userLabel,
            storedAt: String(h?.storedAt ?? new Date().toISOString()),
            formData: h.formData as CertinFormDataType,
          };
        });
      setCertinHistory(mapped);
    } catch {
      setCertinHistory([]);
    }
  };

  useEffect(() => {
    // Only attempt to load drafts when the session is confirmed valid.
    if (authLoading) return; // wait until auth check completes
    if (!authIsValid) {
      setCertinDraft(null);
      return;
    }
    loadCertinDraft();
  }, [authIsValid, authLoading, loadCertinDraft]);

  const handleSaveDraftApi = async () => {
    try {
      // Ensure auth status is refreshed (may renew access token via refresh token)
      try { await refetchAuthStatus?.({ silent: true }); } catch { /* ignore */ }
      await certinDraftApi.saveCertinDraft(certinFormData, reportSourceAlertIds);
      await loadCertinDraft();
      showToast('Draft saved for 24 hours.', 'success');
    } catch (e) {
      console.error('Failed to save draft', e);
      showToast('Failed to save draft.', 'error');
    }
  };

  const handleDownloadFromDraft = async () => {
    if (!certinDraft || !certinDraft.formData) return showToast('No draft available', 'error');
    try {
      // Build the PDF from the live form state (certinFormData), not the stale
      // certinDraft.formData snapshot — certinFormData is what's actually bound
      // to the visible form inputs, so this captures any unsaved edits the user
      // made after loading the draft.
      const [{ pdf }, { CertInPDFDocument }] = await Promise.all([
        import('@react-pdf/renderer'),
        import('./CertInPDFDocument'),
      ]);
      const blob = await pdf(<CertInPDFDocument data={certinFormData} />).toBlob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cert-in-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      if (certinDraft?.id) {
        try {
          await certinDraftApi.markCertinDraftDownloaded(certinDraft.id);
        } catch (e) {
          console.warn('Failed to record CERT-In download status', e);
        }
      }
      showToast('CERT-In report PDF generated successfully.', 'success');
    } catch (err) {
      console.error('Failed to generate PDF from draft', err);
      showToast('Failed to generate PDF from draft.', 'error');
    }
  };

  const prefillCertinNewDraft = async () => {
    try {
      const profileRes = await getProfile();
      const profileData: Partial<UserProfile> = profileRes.data || profileRes.user || {};

      let nodeData: NodePrefillData = {};
      const referenceAlert = pageAlerts[0] ?? allAlerts[0] ?? null;
      if (referenceAlert?.host_identifier) {
        try {
          const hostId = String(referenceAlert.host_identifier ?? '');
          const nodeRes = await api.get(`${NODES_URLS.NODE}${encodeURIComponent(hostId)}`);
          if (nodeRes.data?.data) nodeData = nodeRes.data.data;
        } catch (err) {
          console.warn('Failed to fetch node details for new draft prefill', err);
        }
      }

      setCertinFormData({
        ...initialCertinFormData,
        reporterNameTitle: profileData.name || '',
        reporterOrganization: profileData.company || '',
        reporterEmail: profileData.email || '',
        reporterContactNo: profileData.mobile || '',
        reporterAddress: profileData.address || '',
        affectedEntity: profileData.company || '',
        affectedSystemIp: nodeData.osquery_info?.internal_ip || nodeData.host_ip_address || '',
        affectedSystemOs: nodeData.os_name ? `${nodeData.os_name} ${nodeData.os_version || ''}` : '',
        affectedSystemMakeModelCloud: nodeData.system_info?.hardware_model || '',
      });
    } catch (error) {
      console.error('Failed to prefill new CERT-In draft', error);
      setCertinFormData(initialCertinFormData);
    }
  };
  const formatAlertForReport = (alert: AlertItem) => {
    const lines = [
      `Host: ${alert.hostname || alert.host_identifier} (${alert.os_name || 'unknown OS'})`,
      `Alert type: ${alert.alert_type || alert.event_code || 'Unspecified'}`,
      `Severity: ${alert.severity || 'Unspecified'}`,
      `Detected: ${fmtTime(alert.unixtime)}`,
    ];
    return `Alert ${alert.id}\n${lines.join('\n')}`;
  };

  const handleProceedToReport = async () => {
    const selectedAlerts = allAlerts.filter(a => reportSelectedIds.has(String(a.id)));
    if (selectedAlerts.length === 0) {
      showToast('Select at least one alert to report.', 'warning');
      return;
    }

    try {
      // Fetch Profile
      const profileRes = await getProfile();
      const profileData: Partial<UserProfile> = profileRes.data || profileRes.user || {};

      // Fetch Node details for the first alert
      let nodeData: NodePrefillData = {};
      const firstAlert = selectedAlerts[0];
      if (firstAlert?.host_identifier) {
        try {
          const hostId = String(firstAlert.host_identifier ?? '');
          const nodeRes = await api.get(`${NODES_URLS.NODE}${encodeURIComponent(hostId)}`);
          if (nodeRes.data?.data) {
            nodeData = nodeRes.data.data;
          }
        } catch (err) {
          console.warn('Failed to fetch node details', err);
        }
      }

      const brief = selectedAlerts.map(formatAlertForReport).join('\n\n---\n\n');

      const newForm = {
        ...certinFormData,
        reporterNameTitle: profileData.name || '',
        reporterOrganization: profileData.company || '',
        reporterEmail: profileData.email || '',
        reporterContactNo: profileData.mobile || '',
        reporterAddress: profileData.address || '',
        affectedSystemIp: nodeData.osquery_info?.internal_ip || nodeData.host_ip_address || '',
        affectedSystemOs: nodeData.os_name ? `${nodeData.os_name} ${nodeData.os_version || ''}` : '',
        affectedSystemMakeModelCloud: nodeData.system_info?.hardware_model || '',
        incidentBriefDescription: brief,
      } as CertinFormDataType;

      setCertinFormData(newForm);
      setReportSourceAlertIds(Array.from(reportSelectedIds));

      setCertinModalOpen(true);
      setReportMode(false);
      setReportSelectedIds(new Set());
    } catch (error) {
      showToast('Failed to initialize report data', 'error');
      console.error(error);
    }
  };



  const runBulkMark = (mark: PositiveFilter) => {
    const items = selectedAlertsOnPage;
    if (items.length === 0) { showToast('Select at least one alert to mark.', 'warning'); return; }
    openMarkModal(items, mark);
  };

  // Queue context helpers

  const selectedQueueAlert = useMemo(
    () => (selectedQueueAlertId ? filteredAlertsAll.find((a) => String(a.id) === selectedQueueAlertId) ?? null : null),
    [filteredAlertsAll, selectedQueueAlertId],
  );

  useEffect(() => {
    if (selectedQueueAlertId && !filteredAlertsAll.some((a) => String(a.id) === selectedQueueAlertId))
      setSelectedQueueAlertId(null);
  }, [filteredAlertsAll, selectedQueueAlertId]);

  useEffect(() => {
    if (!selectedQueueAlert) { setMetadataPanelOpen(false); setMetaSearch(''); setAlertPanelWidth(ALERT_PANEL_MIN_WIDTH); }
  }, [selectedQueueAlert]);

  // Keyboard shortcuts
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey || event.altKey) return;

      const target = event.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const editable = !!target && (target.isContentEditable || tag === 'input' || tag === 'textarea' || tag === 'select');
      if (editable) return;
      const currentIndex = selectedQueueAlertId ? pageAlerts.findIndex((a) => String(a.id) === selectedQueueAlertId) : -1;
      if (event.key === 'j' && pageAlerts.length > 0) { event.preventDefault(); const nextIndex = Math.min(pageAlerts.length - 1, currentIndex < 0 ? 0 : currentIndex + 1); setSelectedQueueAlertId(String(pageAlerts[nextIndex]!.id)); }
      if (event.key === 'k' && pageAlerts.length > 0) { event.preventDefault(); const prevIndex = Math.max(0, currentIndex < 0 ? 0 : currentIndex - 1); setSelectedQueueAlertId(String(pageAlerts[prevIndex]!.id)); }
      if (event.key === 'x' && selectedQueueAlert) { event.preventDefault(); toggleSelectId(selectedQueueAlert.id); }
      if (event.key === 'a' && selectedQueueAlert && selectedQueueAlert.is_open && tab !== 'my') { event.preventDefault(); openAssignModal(selectedQueueAlert); }
      if (event.key === 'c' && selectedQueueAlert) { event.preventDefault(); openStatusModal(selectedQueueAlert); }
      if (event.key === 'm' && selectedQueueAlert) { event.preventDefault(); const nextMark = selectedQueueAlert.mark_type === 'true_positive' ? 'false_positive' : 'true_positive'; void handleMarkPositive(selectedQueueAlert, nextMark); }
      if (event.key === 'Escape' && metadataPanelOpen) { event.preventDefault(); setMetadataPanelOpen(false); }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [pageAlerts, selectedQueueAlertId, selectedQueueAlert, tab, metadataPanelOpen, handleMarkPositive, openAssignModal]);

  // Metadata panel derived data

  const metadataEntries = useMemo(() => {
    if (!selectedQueueAlert?.metadata || typeof selectedQueueAlert.metadata !== 'object') return [];
    return Object.entries(selectedQueueAlert.metadata as Record<string, unknown>)
      .map(([k, v]) => ({ key: k, label: formatKey(k), value: formatValue(v), raw: v, type: classifyMetaKey(k) }))
      .sort((a, b) => {
        const order = { assignment: 0, primary: 1, system: 2, file: 3, process: 4, network: 5, timestamp: 6, other: 7, empty: 8 };
        if (order[a.type] !== order[b.type]) return order[a.type] - order[b.type];
        return a.label.localeCompare(b.label);
      });
  }, [selectedQueueAlert?.metadata]);

  // Build assignment info from alert itself (not from metadata)
  const assignmentInfo = useMemo(() => {
    const info: Array<{ key: string; label: string; value: string }> = [];
    if (selectedQueueAlert?.assignee_name || selectedQueueAlert?.assignee_email) {
      info.push({
        key: 'assignee',
        label: 'Assigned To',
        value: selectedQueueAlert.assignee_name
          ? `${selectedQueueAlert.assignee_name}${selectedQueueAlert.assignee_email ? ` (${selectedQueueAlert.assignee_email})` : ''}`
          : selectedQueueAlert.assignee_email || 'Unknown',
      });
    }
    // Add assignedMeta info if available
    if (assignedMeta?.assignee) {
      const val = assignedMeta.assignee.name
        ? `${assignedMeta.assignee.name}${assignedMeta.assignee.email ? ` (${assignedMeta.assignee.email})` : ''}`
        : assignedMeta.assignee.email || 'Unknown';
      info.push({ key: 'assigned_to', label: 'Assigned To', value: val });
    }
    if (assignedMeta?.assignedBy) {
      const val = assignedMeta.assignedBy.name
        ? `${assignedMeta.assignedBy.name}${assignedMeta.assignedBy.email ? ` (${assignedMeta.assignedBy.email})` : ''}`
        : assignedMeta.assignedBy.email || 'Unknown';
      info.push({ key: 'assigned_by', label: 'Assigned By', value: val });
    }
    if (assignedMeta?.assignedAt) {
      const dt = new Date(assignedMeta.assignedAt);
      const formatted = !isNaN(dt.getTime()) ? dt.toLocaleString() : String(assignedMeta.assignedAt);
      info.push({ key: 'assigned_at', label: 'Assigned At', value: formatted });
    }
    if (assignedMeta?.status) {
      info.push({ key: 'assignment_status', label: 'Assignment Status', value: assignedMeta.status });
    }
    return info;
  }, [selectedQueueAlert?.assignee_name, selectedQueueAlert?.assignee_email, assignedMeta]);

  const filteredMetaEntries = useMemo(() => {
    if (!metaSearch.trim()) return metadataEntries;
    const q = metaSearch.trim().toLowerCase();
    return metadataEntries.filter(e => (e.label || '').toLowerCase().includes(q) || (e.value || '').toLowerCase().includes(q));
  }, [metadataEntries, metaSearch]);

  const filteredAssignmentInfo = useMemo(() => {
    if (!metaSearch.trim()) return assignmentInfo;
    const q = metaSearch.trim().toLowerCase();
    return assignmentInfo.filter(e => (e.label || '').toLowerCase().includes(q) || (e.value || '').toLowerCase().includes(q));
  }, [assignmentInfo, metaSearch]);

  const metaGroups = useMemo(() => {
    const groups: Record<string, typeof filteredMetaEntries> = {
      assignment: [],
      primary: filteredMetaEntries.filter(e => e.type === 'primary'),
      system: filteredMetaEntries.filter(e => e.type === 'system'),
      file: filteredMetaEntries.filter(e => e.type === 'file'),
      process: filteredMetaEntries.filter(e => e.type === 'process'),
      network: filteredMetaEntries.filter(e => e.type === 'network'),
      timestamp: filteredMetaEntries.filter(e => e.type === 'timestamp'),
      other: filteredMetaEntries.filter(e => e.type === 'other'),
    };
    return groups;
  }, [filteredMetaEntries]);

  const hasDraftInLast24h = useMemo(() => isDraftWithin24Hours(certinDraft), [certinDraft]);
  const latestDraftComplete = useMemo(() => isCertinDraftComplete(certinDraft?.formData), [certinDraft]);
  const draftUpdatedAtMs = useMemo(() => getDraftTimestampMs(certinDraft), [certinDraft]);
  const draftExpiresAtMs = useMemo(() => {
    const raw = certinDraft?.expiresAt;
    if (!raw) return null;
    const ts = new Date(raw).getTime();
    return Number.isFinite(ts) ? ts : null;
  }, [certinDraft]);
  const lastEditedAgoText = useMemo(() => {
    if (!draftUpdatedAtMs) return null;
    return formatRelativeDuration(Math.max(0, nowMs - draftUpdatedAtMs));
  }, [draftUpdatedAtMs, nowMs]);
  const disappearsInText = useMemo(() => {
    const effectiveExpiryMs = draftExpiresAtMs ?? (draftUpdatedAtMs ? draftUpdatedAtMs + 24 * 60 * 60 * 1000 : null);
    if (!effectiveExpiryMs) return null;
    return formatRelativeDuration(Math.max(0, effectiveExpiryMs - nowMs));
  }, [draftExpiresAtMs, draftUpdatedAtMs, nowMs]);

  // `nowMs` only feeds lastEditedAgoText/disappearsInText, which are props of
  // <CertInModal> and render nowhere while it is closed (it returns null on
  // !isOpen). Ticking unconditionally would re-render this entire page — table
  // rows, detail panel and all — every 30s for text nobody is looking at.
  // Resyncing on open keeps the first frame as fresh as an always-on timer.
  useEffect(() => {
    if (!certinModalOpen) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => setNowMs(Date.now()), 30000);
    return () => window.clearInterval(timer);
  }, [certinModalOpen]);


  return (
    <>
      <div className={`h-screen flex flex-col overflow-hidden bg-[#f7f8fa] dark:bg-gray-900`}>
        <div className="flex-1 min-h-0 flex flex-col px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">
          {/* Page Header — same gradient + Meteors treatment used across the dashboard */}
          <motion.header
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="relative shrink-0 overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white flex-shrink-0"
            style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
          >
            <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
            <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                  <AlertsIcon className="w-6 h-6 mr-2" />
                  Alerts Overview
                </h1>
                <p className="mt-1 text-sm text-blue-100">Monitor, triage, and respond to security alerts</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  onClick={() => {
                    setReportMode(true);
                    if (hasDraftInLast24h) {
                      setCertinFormData(certinDraft?.formData ?? initialCertinFormData);
                      const ids = Array.isArray(certinDraft?.selectedAlertIds) ? certinDraft.selectedAlertIds : [];
                      setReportSelectedIds(new Set(ids.map(String)));
                      setReportSourceAlertIds(ids.map(String));
                    } else {
                      void prefillCertinNewDraft();
                      setReportSelectedIds(new Set());
                      setReportSourceAlertIds([]);
                    }
                    setCertinModalOpen(true);
                  }}
                  className="inline-flex h-10 items-center gap-2 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  CERTIn Incident Report
                </button>
              </div>
            </div>
          </motion.header>

          {/* Severity Cards */}
          <div className="grid grid-cols-2 gap-5 mb-6 md:grid-cols-4 flex-shrink-0">
            {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
              const icons = {
                critical: 'M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.657 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z',
                high: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77-1.333.192 3 1.732 3z',
                medium: 'M12 9v3m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
                low: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
              };
              const colors = {
                critical: { num: 'text-red-600 dark:text-red-400', icon: 'text-red-500', bg: 'bg-red-50 dark:bg-red-500/10', accent: 'bg-red-500', ring: 'border-red-300 dark:border-red-500/40 ring-4 ring-red-100 dark:ring-red-500/10', hover: 'hover:border-red-200 dark:hover:border-red-500/30' },
                high: { num: 'text-orange-500 dark:text-orange-400', icon: 'text-orange-500', bg: 'bg-orange-50 dark:bg-orange-500/10', accent: 'bg-orange-500', ring: 'border-orange-300 dark:border-orange-500/40 ring-4 ring-orange-100 dark:ring-orange-500/10', hover: 'hover:border-orange-200 dark:hover:border-orange-500/30' },
                medium: { num: 'text-amber-500 dark:text-amber-400', icon: 'text-amber-500', bg: 'bg-amber-50 dark:bg-amber-500/10', accent: 'bg-amber-400', ring: 'border-amber-300 dark:border-amber-500/40 ring-4 ring-amber-100 dark:ring-amber-500/10', hover: 'hover:border-amber-200 dark:hover:border-amber-500/30' },
                low: { num: 'text-emerald-600 dark:text-emerald-400', icon: 'text-emerald-500', bg: 'bg-emerald-50 dark:bg-emerald-500/10', accent: 'bg-emerald-500', ring: 'border-emerald-300 dark:border-emerald-500/40 ring-4 ring-emerald-100 dark:ring-emerald-500/10', hover: 'hover:border-emerald-200 dark:hover:border-emerald-500/30' },
              };
              const c = colors[sev];
              const count = (apiSeverityCounts && typeof apiSeverityCounts[sev] === 'number') ? apiSeverityCounts[sev] : severityTotals[sev];
              const isActive = severityFilter === sev;

              return (
                <div
                  key={sev}
                  role="button"
                  tabIndex={0}
                  aria-pressed={isActive}
                  aria-label={`Filter by ${sev} severity`}
                  className={`group relative flex h-full flex-col overflow-hidden rounded-xl border bg-white p-5 shadow-sm transition-all duration-200 cursor-pointer hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 dark:bg-[#161b22] ${isActive ? c.ring : `border-gray-200 dark:border-white/10 ${c.hover}`}`}
                  onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSeverityFilter(severityFilter === sev ? null : sev);
                    }
                  }}
                >
                  <span className={`absolute inset-x-0 top-0 h-1 ${c.accent} opacity-90`} />
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-500 dark:text-slate-400 mb-1.5">{sev}</p>
                      <p className={`text-3xl font-bold tabular-nums leading-none ${c.num}`}>{count}</p>
                    </div>
                    <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${c.bg} transition-transform duration-200 group-hover:scale-105`}>
                      <svg className={`h-5 w-5 ${c.icon}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icons[sev]} />
                      </svg>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Main layout */}
          <div className="flex items-start gap-5 flex-1 min-h-0 overflow-hidden">

            {/* ── Alert Table — shrinks to content (few rows = short card) instead of
                always stretching to fill the viewport; max-h-full caps it back to the
                row's height so a long page of results still scrolls internally. ── */}
            <div className="flex-1 min-w-0 max-h-full bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm flex flex-col overflow-hidden">

              {/* Table header */}
              <div className="border-b border-gray-100 dark:border-gray-700 px-5 pt-4 pb-0 flex-shrink-0">
                <nav className="flex items-center gap-1.5 mb-4" role="tablist" aria-label="Alert tabs">
                  {(['open', 'closed', 'my'] as Tab[]).map((t) => {
                    // Use API counts if available, otherwise fallback to local filter (for backwards compat)
                    let tabCount = tabTotals[t] ?? 0;
                    if (tabCount === 0) {
                      if (t === 'open') tabCount = allAlerts.filter(a => a.is_open).length;
                      else if (t === 'closed') tabCount = allAlerts.filter(a => !a.is_open).length;
                      else if (t === 'my') tabCount = allAlerts.filter(a => getAlertAssigneeId(a) !== null).length;
                    }
                    const isActive = tab === t;
                    return (
                      <button
                        key={t}
                        type="button"
                        role="tab"
                        aria-selected={isActive}
                        onClick={() => {
                          setTab(t);
                          setPage(1);
                        }}
                        className={`relative px-3.5 py-2 rounded-full text-sm font-medium whitespace-nowrap flex items-center gap-1.5 transition-colors duration-200 ${isActive
                          ? 'text-white'
                          : 'text-slate-600 dark:text-gray-400 hover:text-slate-900 hover:bg-slate-200/50 dark:hover:text-gray-300'
                          }`}
                        style={{ transformStyle: 'preserve-3d' }}
                      >
                        {isActive && (
                          <motion.div
                            layoutId="activeTabAlerts"
                            transition={{ type: 'spring', bounce: 0.3, duration: 0.6 }}
                            className="absolute inset-0 bg-[rgb(4,34,119)] rounded-full"
                            style={{ zIndex: 0 }}
                          />
                        )}
                        <span className="relative z-10 font-medium">
                          {t === 'my' ? 'My Alerts' : t === 'open' ? 'Open' : 'Closed'}
                        </span>
                        {/* Total badge (only for active tab) */}
                        {isActive && tabCount > 0 && (
                          <span className="relative z-10 rounded-full bg-white/20 text-white text-[10px] font-bold px-1.5 py-0.5">
                            {tabCount}
                          </span>
                        )}

                        {/* Unseen badge for "Open" tab */}
                        {t === 'open' && unseenOpenAlertsCount > 0 && (
                          <span className={`relative z-10 rounded-full text-[10px] font-bold px-1.5 py-0.5 ${isActive ? 'bg-white/20 text-white' : 'bg-blue-600 text-white'}`}>
                            {unseenOpenAlertsCount}
                          </span>
                        )}

                        {/* Unseen badge (only for "my") */}
                        {t === 'my' && unseenMyAlertsCount > 0 && (
                          <span className={`relative z-10 rounded-full text-[10px] font-bold px-1.5 py-0.5 ${isActive ? 'bg-white/20 text-white' : 'bg-blue-600 text-white'}`}>
                            {unseenMyAlertsCount}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </nav>

                <div className="flex flex-wrap items-center gap-2.5 pb-4">
                  <form onSubmit={handleSearch} className="relative order-1 w-full shrink-0 sm:w-64 md:w-72 lg:w-80">
                    <SearchIcon sx={{ fontSize: 16, position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }} />
                    <input
                      type="text"
                      className="h-9 w-full rounded-lg border border-gray-200 bg-gray-50 pl-8 pr-3 text-sm text-gray-800 placeholder:text-gray-400 transition-colors focus:border-blue-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-100 dark:placeholder-gray-400"
                      placeholder="Search alerts..."
                      value={search}
                      onChange={(e) => setSearch(sanitizeAsciiSingleLine(e.target.value, 200, false))}
                    />
                  </form>

                  <div className="order-2 w-full shrink-0 sm:w-[150px]">
                    <Select
                      value={severityFilter ?? 'all'}
                      onValueChange={(value) => setSeverityFilter(value === 'all' ? null : (value as SeverityFilter))}
                    >
                      <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by severity">
                        <SelectValue placeholder="Severity: All">
                          {(value: string) =>
                            value === 'critical' ? 'Critical'
                              : value === 'high' ? 'High'
                                : value === 'medium' ? 'Medium'
                                  : value === 'low' ? 'Low'
                                    : 'Severity: All'
                          }
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Severity: All</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="order-3 w-full shrink-0 sm:w-[150px]">
                    <Select
                      value={assigneeFilter ?? 'all'}
                      onValueChange={(value) => { const v = value as string; setAssigneeFilter(v === 'assigned' || v === 'unassigned' ? v : null); }}
                      disabled={tab === 'my'}
                    >
                      <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by assignment">
                        <SelectValue placeholder="Assignment">
                          {(value: string) => (value === 'assigned' ? 'Assigned' : value === 'unassigned' ? 'Unassigned' : 'Assignment')}
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Assignment</SelectItem>
                        <SelectItem value="assigned">Assigned</SelectItem>
                        <SelectItem value="unassigned">Unassigned</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="order-4 w-full shrink-0 sm:w-[150px]">
                    <Select
                      value={positiveFilter ?? 'all'}
                      onValueChange={(value) => { const v = value as string; setPositiveFilter(v === 'true_positive' || v === 'false_positive' ? v : null); }}
                    >
                      <SelectTrigger size="sm" className="w-full font-normal" aria-label="Filter by status">
                        <SelectValue placeholder="Status">
                          {(value: string) => (value === 'true_positive' ? 'True Positive' : value === 'false_positive' ? 'False Positive' : 'Status')}
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Status</SelectItem>
                        <SelectItem value="true_positive">True Positive</SelectItem>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {hasFilters && (
                    <button type="button" onClick={clearFilters} className="order-5 flex h-9 w-full shrink-0 items-center justify-center gap-1 rounded-lg border border-gray-200 px-3 text-sm text-gray-500 transition-colors hover:bg-gray-50 dark:border-gray-600 dark:text-gray-400 dark:hover:bg-gray-700 sm:w-auto">
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                      Clear
                    </button>
                  )}

                  <div className="order-6 flex w-full items-center gap-2 sm:ml-auto sm:w-auto">
                    <div className="group relative flex flex-1 items-center sm:flex-none">
                      <input type="date" max="9999-12-31" value={startDate} onClick={(e) => (e.target as HTMLInputElement).showPicker?.()} onChange={(e) => setStartDate(e.target.value)} className="h-9 w-full appearance-none rounded-lg border border-gray-200 bg-white pl-8 pr-3 text-xs text-gray-600 shadow-sm transition-colors hover:border-gray-300 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 [&::-webkit-calendar-picker-indicator]:absolute [&::-webkit-calendar-picker-indicator]:inset-0 [&::-webkit-calendar-picker-indicator]:h-full [&::-webkit-calendar-picker-indicator]:w-full [&::-webkit-calendar-picker-indicator]:opacity-0 cursor-pointer sm:w-[130px]" />
                      <svg className="pointer-events-none absolute left-2.5 h-4 w-4 text-gray-400 transition-colors group-hover:text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                    </div>
                    <div className="group relative flex flex-1 items-center sm:flex-none">
                      <input type="date" max="9999-12-31" value={endDate} onClick={(e) => (e.target as HTMLInputElement).showPicker?.()} onChange={(e) => setEndDate(e.target.value)} className="h-9 w-full appearance-none rounded-lg border border-gray-200 bg-white pl-8 pr-3 text-xs text-gray-600 shadow-sm transition-colors hover:border-gray-300 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 [&::-webkit-calendar-picker-indicator]:absolute [&::-webkit-calendar-picker-indicator]:inset-0 [&::-webkit-calendar-picker-indicator]:h-full [&::-webkit-calendar-picker-indicator]:w-full [&::-webkit-calendar-picker-indicator]:opacity-0 cursor-pointer sm:w-[130px]" />
                      <svg className="pointer-events-none absolute left-2.5 h-4 w-4 text-gray-400 transition-colors group-hover:text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                    </div>
                  </div>

                  <div className="order-7 flex w-full items-center gap-2 sm:w-auto">
                    <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} type="button" onClick={() => void fetchPage()} className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-gray-200 text-gray-500 transition-colors hover:bg-gray-50 dark:border-gray-600 dark:text-gray-400 dark:hover:bg-gray-700" title="Refresh">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                    </motion.button>
                    <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} type="button" onClick={openExportModal} className="flex h-9 flex-1 items-center justify-center gap-1.5 rounded-lg border border-gray-200 px-3 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-50 dark:border-gray-600 dark:text-gray-400 dark:hover:bg-gray-700 sm:flex-none">
                      <DownloadIcon sx={{ fontSize: 16 }} /> Export
                    </motion.button>
                  </div>
                </div>
              </div>


              {/* Active filter chips */}
              {(severityFilter || assigneeFilter || positiveFilter) && (
                <div className="flex flex-wrap items-center gap-2 px-5 py-2.5 bg-gray-50/80 dark:bg-gray-700/60 border-b border-gray-100 dark:border-gray-700 flex-shrink-0">
                  {severityFilter && (
                    <span className={`inline-flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full ${SEV_BADGE_NEW[severityFilter]}`}>
                      Severity: {SEV_LABEL[severityFilter]}
                      <button onClick={() => setSeverityFilter(null)} className="ml-1 rounded-lg opacity-60 hover:opacity-100">×</button>
                    </span>
                  )}
                  {assigneeFilter && (
                    <span className="inline-flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                      {assigneeFilter === 'assigned' ? 'Assigned' : 'Unassigned'}
                      <button onClick={() => setAssigneeFilter(null)} className="ml-1 rounded-lg opacity-60 hover:opacity-100">×</button>
                    </span>
                  )}
                  {positiveFilter && (
                    <span className={`inline-flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full ${positiveFilter === 'true_positive' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-rose-50 text-rose-700 border border-rose-200'}`}>
                      {positiveFilter === 'true_positive' ? 'True Positive' : 'False Positive'}
                      <button onClick={() => setPositiveFilter(null)} className="ml-1 rounded-lg opacity-60 hover:opacity-100">×</button>
                    </span>
                  )}
                </div>
              )}

              {error && <div className="mx-5 my-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

              {/* Table */}
              <div className="table-scrollbar scrollbar-auto-hide flex-1 min-h-0 overflow-x-auto overflow-y-auto">
                <table className="w-full text-sm border-separate border-spacing-0">
                  <thead>
                    <tr>
                      <th className="w-10 text-left pl-5 py-3 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                        <Checkbox
                          inputRef={headerSelectRef}
                          checked={reportMode ? allOnPageSelectedReport : allOnPageSelected}
                          onChange={(e) => reportMode ? (e.target.checked ? setReportSelectedIds(new Set(pageAlerts.map(a => String(a.id)))) : setReportSelectedIds(new Set())) : onHeaderSelectChange(e)}
                          indeterminate={reportMode ? (someOnPageSelectedReport && !allOnPageSelectedReport) : (someOnPageSelected && !allOnPageSelected)}
                          inputProps={{ 'aria-label': 'Select all alerts on this page' }}
                          sx={{ color: '#D1D5DB', '&.Mui-checked': { color: '#030303' } }}
                        />
                      </th>
                      <th className="px-5 py-3.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Severity</th>
                      <th className="px-5 py-3.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Alert / Host</th>
                      <th className="px-5 py-3.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Owner</th>
                      <th className="px-5 py-3.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                      <th className="px-5 py-3.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                        <span className="inline-flex items-center gap-1">
                          Age
                        </span>
                      </th>
                    </tr>
                  </thead>
                  <AnimatePresence mode="popLayout">
                    <motion.tbody
                      initial="hidden"
                      animate="visible"
                      variants={{
                        visible: {
                          transition: {
                            staggerChildren: 0.05,
                            delayChildren: 0.1,
                          },
                        },
                      }}
                    >
                      {loading && allAlerts.length === 0 ? (
                        // First load (or a genuinely empty page) only — a background
                        // refetch triggered by a tab/filter/page change keeps the
                        // previously-loaded rows on screen (see the `else` branch
                        // below) instead of blanking the table. This also
                        // deliberately avoids the branded `LoadingScreen` component,
                        // which is the app's full-page/route-level loader — reusing
                        // it here made an in-place data refresh look like a page
                        // reload.
                        <tr>
                          <td colSpan={6} className="px-5 py-16 text-center">
                            <InlineSpinner text="Loading alerts…" size="md" />
                          </td>
                        </tr>
                      ) : !loading && total === 0 ? (
                        <tr>
                          <td colSpan={6} className="px-5 py-16 text-center">
                            <p className="text-base font-medium text-gray-600 dark:text-gray-400">
                              {hasFilters ? 'No alerts match your filters' : tab === 'my' ? 'No alerts assigned to you yet' : `No ${tab} alerts`}
                            </p>
                            {hasFilters && (
                              <button type="button" onClick={clearFilters} className="mt-3 rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700">Clear filters</button>
                            )}
                          </td>
                        </tr>
                      ) : (
                        pageAlerts.map((alert) => {
                          const sev = normalizeSev(alert.severity);
                          const key = String(alert.id);
                          const markValue = alert.mark_type === 'true_positive' ? 'true_positive' : alert.mark_type === 'false_positive' ? 'false_positive' : '';
                          const effectiveMarkValue = positiveMarkPending[key] ?? markValue;
                          const assigneeIdNum = alert.assignee_id == null ? null : typeof alert.assignee_id === 'number' ? alert.assignee_id : Number(alert.assignee_id);
                          const hasAssignee = assigneeIdNum != null && Number.isFinite(assigneeIdNum) && assigneeIdNum > 0;
                          const assignedTo = alert.assignee_name ?? (hasAssignee ? `User #${assigneeIdNum}` : 'Unassigned');
                          const ageLabel = fmtAlertAge(alert.unixtime);
                          const isNew = !viewedAlertIds.has(key) && (tab === 'my' ? newAlertIds.has(key) || newMyAlertIds.has(key) : newAlertIds.has(key));
                          const isSelectedRow = selectedQueueAlertId === key;
                          const openAlertDetails = () => {
                            setSelectedQueueAlertId(key);
                            if (isNew) {
                              setViewedAlertIds(prev => new Set([...prev, key]));
                              markAlertInteracted(key);
                            }
                          };

                          return (
                            <motion.tr
                              key={key}
                              layoutId={key}
                              initial={isNew ? { opacity: 0, x: -20, backgroundColor: '#fef08a' } : { opacity: 0, y: 10 }}
                              // Only drive `backgroundColor` here while the "new alert" flash is
                              // actually animating — Framer Motion applies it as an inline style,
                              // which outranks any Tailwind bg-* class (including the selected-row
                              // and zebra-stripe classes below) for as long as it's present.
                              animate={isNew ? { opacity: 1, x: 0, y: 0, backgroundColor: 'transparent' } : { opacity: 1, x: 0, y: 0 }}
                              exit={{ opacity: 0, x: -20 }}
                              transition={{
                                duration: isNew ? 0.6 : 0.3,
                                ease: isNew ? 'easeOut' : 'easeInOut',
                              }}
                              className={`group border-b cursor-pointer transition-colors duration-150 relative ${isSelectedRow ? '!bg-blue-100 dark:!bg-blue-900/40 border-blue-200 dark:border-blue-900/50' : 'border-gray-100 dark:border-gray-700 odd:bg-white even:bg-slate-50/70 dark:odd:bg-transparent dark:even:bg-slate-800/25 hover:bg-blue-50/60 dark:hover:bg-gray-700/40'}`}
                              onClick={openAlertDetails}
                              role="button"
                              tabIndex={0}
                              aria-label={`Open details for alert ${alert.event_code || alert.alert_type || 'Unknown Alert'}`}
                              onKeyDown={(e) => {
                                // Only handle keys that originate on the row itself — ignore ones
                                // bubbling up from nested interactive controls (selection checkbox,
                                // Assignee button, hostname link) so their own Enter/Space
                                // activation isn't hijacked into re-opening the details panel.
                                if (e.target !== e.currentTarget) return;
                                if (e.key === 'Enter' || e.key === ' ') {
                                  e.preventDefault();
                                  openAlertDetails();
                                }
                              }}
                            >

                              <td className="px-5 py-3.5 relative">
                                {isSelectedRow && (
                                  <motion.div
                                    layoutId="alertRowIndicator"
                                    className="absolute top-0 bottom-[-1px] left-0 w-[3px] bg-blue-600 dark:bg-blue-500 z-10"
                                    transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
                                  />
                                )}
                                <Checkbox
                                  checked={reportMode ? reportSelectedIds.has(key) : selectedIds.has(key)}
                                  onChange={() => reportMode ? setReportSelectedIds(prev => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; }) : toggleSelectId(alert.id)}

                                  onClick={(e) => e.stopPropagation()}
                                  inputProps={{ 'aria-label': `Select alert ${key}` }}
                                  sx={{ color: '#D1D5DB', '&.Mui-checked': { color: '#010101' } }}
                                />
                              </td>
                              <td className="px-5 py-3.5">
                                <div className="flex items-center gap-1.5">
                                  <i className={`${getAlertIcon(sev)} text-xs flex-shrink-0`} style={{ color: SEV_ICON_COLOR[sev] ?? '#6B7280' }} aria-hidden="true" />
                                  <span className="text-sm font-medium text-gray-900 dark:text-gray-100 capitalize">{SEV_LABEL[sev]}</span>
                                </div>
                              </td>
                              <td className="px-5 py-3.5 min-w-0 max-w-[280px]">
                                <p className="font-semibold text-gray-900 dark:text-gray-100 truncate text-sm">
                                  {alert.event_code || alert.alert_type || 'Unknown Alert'}
                                  {isNew && <span className="ml-1.5 rounded bg-[#7C3AED] px-1.5 py-0.5 text-[10px] font-bold text-white align-middle">NEW</span>}
                                </p>
                                <p className="text-xs text-gray-500 dark:text-gray-400 truncate mt-0.5">
                                  {(alert.hostname || alert.host_identifier) ? (
                                    <Link
                                      to={`/my-devices?q=${encodeURIComponent(alert.hostname || alert.host_identifier || '')}`}
                                      onClick={(e) => e.stopPropagation()}
                                      className="hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                                    >
                                      {alert.hostname || alert.host_identifier}
                                    </Link>
                                  ) : '—'}
                                  {alert.alert_type ? ` · ${alert.alert_type}` : ''}
                                </p>
                              </td>
                              <td className="px-5 py-3.5">
                                <button
                                  type="button"
                                  onClick={(e) => { e.stopPropagation(); openAssigneeModal(alert); }}
                                  className={`inline-flex items-center gap-1.5 rounded-lg text-sm font-medium truncate max-w-[140px] transition-colors ${hasAssignee ? 'text-blue-600 hover:text-blue-700 hover:underline dark:text-blue-400' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                >
                                  <svg className="w-4 h-4 shrink-0 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87m6-1.13a4 4 0 100-8 4 4 0 000 8zm6 3c0-1.657-3.134-3-7-3s-7 1.343-7 3" /></svg>
                                  <span className="truncate">{assignedTo}</span>
                                </button>
                              </td>
                              <td className="px-5 py-3.5">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${alert.is_open ? 'bg-green-50 text-green-700 dark:bg-green-500/15 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'}`}>
                                    <span className={`w-1.5 h-1.5 rounded-full ${alert.is_open ? 'bg-green-500' : 'bg-gray-400'}`} />
                                    {alert.is_open ? 'Open' : 'Closed'}
                                  </span>
                                  {effectiveMarkValue === 'true_positive' && (
                                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">TP</span>
                                  )}
                                  {effectiveMarkValue === 'false_positive' && (
                                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200">FP</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-5 py-3.5">
                                <span className="text-sm text-gray-500 dark:text-gray-400 tabular-nums">{ageLabel}</span>
                              </td>
                            </motion.tr>
                          );
                        })
                      )}
                    </motion.tbody>
                  </AnimatePresence>
                </table>
              </div>


              {/* Pagination — stays visible during a background refetch (matches the
                  table body's "keep previous rows while loading" behavior above);
                  only hidden on the true first-load spinner state. */}
              {(allAlerts.length > 0 || !loading) && totalPages > 0 && (
                <Pagination
                  page={page}
                  totalPages={totalPages}
                  total={total}
                  pageSize={rowsPerPage}
                  onPageChange={(p) => setPage(p)}
                  onPageSizeChange={(size) => { setRowsPerPage(size); setPage(1); }}
                  pageSizeOptions={[10, 25, 50]}
                  itemLabel="alerts"
                />
              )}
            </div>

            {/* Right: Context Panel */}
            <AnimatePresence>
              {selectedQueueAlert && (
                <motion.div
                  key="alert-panel"
                  className={isNarrowViewport
                    ? 'fixed inset-0 z-40 overflow-hidden'
                    : 'relative flex-shrink-0 overflow-hidden h-full'}
                  initial={isNarrowViewport ? { opacity: 0 } : { width: 0 }}
                  animate={isNarrowViewport ? { opacity: 1 } : { width: alertPanelWidth }}
                  exit={isNarrowViewport ? { opacity: 0 } : { width: 0 }}
                  transition={isResizingAlertPanel ? { duration: 0 } : { type: 'spring', stiffness: 280, damping: 28 }}
                >
                  {/* Resize handle (drag left edge) — desktop only, a fixed-width drag handle makes no sense on a full-screen overlay */}
                  {!isNarrowViewport && (
                    <div
                      onPointerDown={handleAlertPanelResizeStart}
                      onPointerMove={handleAlertPanelResizeMove}
                      onPointerUp={handleAlertPanelResizeEnd}
                      onPointerCancel={handleAlertPanelResizeEnd}
                      className="group absolute left-0 top-0 bottom-0 w-2 z-30 cursor-col-resize touch-none flex items-center justify-center"
                      title="Drag to resize"
                    >
                      <div className={`w-0.5 h-10 rounded-full transition-colors ${isResizingAlertPanel ? 'bg-blue-500' : 'bg-transparent group-hover:bg-blue-400 dark:group-hover:bg-blue-500'}`} />
                    </div>
                  )}
                  <motion.div
                    className="w-full h-full bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-600 shadow-sm overflow-hidden flex flex-col"
                    initial={{ x: 64, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    exit={{ x: 64, opacity: 0 }}
                    transition={{ type: 'spring', stiffness: 280, damping: 28 }}
                  >
                    <div className="h-14 px-5 bg-[#042277] flex items-center justify-between flex-shrink-0">
                      <h2 className="text-[15px] font-semibold tracking-tight text-white">Alert Details</h2>
                      <div className="flex items-center gap-1">
                        <button type="button" onClick={() => setSelectedQueueAlertId(null)} className="flex h-7 w-7 items-center justify-center rounded-lg text-white/70 transition-colors hover:bg-white/10 hover:text-white">
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                        </button>
                      </div>
                    </div>
                    <div className="flex flex-col flex-1 min-h-0 overflow-hidden relative">

                      {/* Metadata Slide-in Panel (absolute overlay) */}
                      <AnimatePresence>
                        {metadataPanelOpen && selectedQueueAlert && (
                          <motion.div
                            initial={{ x: '100%' }}
                            animate={{ x: 0 }}
                            exit={{ x: '100%' }}
                            transition={{ type: 'spring', stiffness: 320, damping: 32 }}
                            className="absolute inset-0 z-20 flex flex-col bg-white dark:bg-gray-800"
                            style={{ borderRadius: 'inherit' }}
                          >
                            {/* Metadata panel header */}
                            <div className="flex-shrink-0 border-b border-gray-100 dark:border-gray-700">
                              <div className="flex items-center gap-2 px-5 py-3.5">
                                <button
                                  type="button"
                                  onClick={() => setMetadataPanelOpen(false)}
                                  className="flex h-7 w-7 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-600 dark:text-gray-500 dark:hover:bg-gray-700 dark:hover:text-gray-300"
                                  title="Back"
                                >
                                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                                  </svg>
                                </button>
                                <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">Raw Metadata</p>
                              </div>
                            </div>

                            {/* Metadata body */}
                            <div className="table-scrollbar flex-1 overflow-y-auto px-4 py-3.5">
                              {metadataEntries.length === 0 && assignmentInfo.length === 0 ? (
                                <div className="flex flex-col items-center justify-center h-auto px-4 py-12 text-center">
                                  <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center mb-3">
                                    <svg className="w-5 h-5 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                                    </svg>
                                  </div>
                                  <p className="text-sm font-medium text-gray-400 dark:text-gray-500">No metadata available</p>
                                </div>
                              ) : filteredMetaEntries.length === 0 && filteredAssignmentInfo.length === 0 ? (
                                <div className="px-4 py-8 text-center">
                                  <p className="text-sm text-gray-400 dark:text-gray-500">No fields match "<span className="font-medium">{metaSearch}</span>"</p>
                                  <button type="button" onClick={() => setMetaSearch('')} className="mt-2 rounded-lg text-xs text-violet-500 hover:underline">Clear filter</button>
                                </div>
                              ) : (() => {
                                const allMetadata = [
                                  ...metaGroups.primary,
                                  ...metaGroups.system,
                                  ...metaGroups.file,
                                  ...metaGroups.process,
                                  ...metaGroups.network,
                                  ...metaGroups.timestamp,
                                  ...metaGroups.other,
                                ].filter(e => e.value && e.value.toString().trim() !== '');

                                return allMetadata.length === 0 ? (
                                  <div className="flex flex-col items-center justify-center h-auto px-4 py-12 text-center">
                                    <div className="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mb-3">
                                      <svg className="w-5 h-5 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                                      </svg>
                                    </div>
                                    <p className="text-sm font-medium text-gray-400 dark:text-gray-500">No metadata available</p>
                                  </div>
                                ) : (
                                  <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50 p-4">
                                    <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-3">Metadata</p>
                                    <div className="space-y-2.5">
                                      {allMetadata.map(e => (
                                        e.key === 'hosts' && Array.isArray(e.raw) ? (
                                          <div key={e.key} className="text-xs">
                                            <span className="text-gray-500 dark:text-gray-400 font-medium">{e.label} ({(e.raw as UnmanagedHost[]).length}):</span>
                                            <div className="mt-1.5 space-y-1.5">
                                              {(e.raw as UnmanagedHost[]).map((h, i) => (
                                                <div key={h?.ip ?? i} className="rounded-lg border border-gray-200 dark:border-gray-600 px-2 py-1.5">
                                                  <div className="flex items-center justify-between gap-2">
                                                    <span className="font-mono text-xs font-semibold text-gray-900 dark:text-gray-100">{h?.ip ?? '—'}</span>
                                                    <span className={`text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded flex-shrink-0 ${h?.kind === 'reuse' ? 'text-amber-600 bg-amber-100' : 'text-emerald-600 bg-emerald-100'}`}>
                                                      {h?.kind === 'reuse' ? 'Possible IP Reuse' : 'New'}
                                                    </span>
                                                  </div>
                                                  {!!h?.open_ports?.length && (
                                                    <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1">
                                                      {h.open_ports.join(', ')}{h.os_guess ? ` · ${h.os_guess}` : ''}
                                                    </p>
                                                  )}
                                                  {h?.kind === 'reuse' && (
                                                    <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1">
                                                      Previously registered to {h.registered_hostname || h.registered_host_identifier || 'an unidentified host'}
                                                      {' — last seen '}
                                                      {h.registered_last_seen ? new Date(Number(h.registered_last_seen) * 1000).toLocaleString() : 'never'}
                                                    </p>
                                                  )}
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        ) : (
                                          <div key={e.key} className="flex justify-between items-start gap-3 text-xs">
                                            <span className="w-1/3 flex-shrink-0 font-medium text-gray-500 dark:text-gray-400">{e.label}:</span>
                                            <span className="flex-1 break-all text-gray-900 dark:text-gray-100">{e.value}</span>
                                          </div>
                                        )
                                      ))}
                                    </div>
                                  </div>
                                );
                              })()}

                            </div>


                            {/* Metadata panel footer */}
                            <div className="flex-shrink-0 border-t border-gray-100 dark:border-gray-700 px-4 py-2.5">
                              <button
                                type="button"
                                onClick={() => setMetadataPanelOpen(false)}
                                className="h-9 w-full rounded-lg text-xs font-semibold text-gray-500 transition-colors duration-200 hover:bg-gray-50 hover:text-gray-700 dark:text-gray-400 dark:hover:bg-gray-700 dark:hover:text-gray-300"
                              >
                                ← Back to context
                              </button>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>

                      {/* Scrollable content */}
                      <div className="table-scrollbar flex-1 overflow-y-auto min-h-0">
                        <div className="p-5 space-y-5">

                          {/* Severity + Status tiles */}
                          {(() => {
                            const sev = normalizeSev(selectedQueueAlert.severity);
                            const sevCfg = {
                              critical: { grad: 'from-red-500/10', border: 'border-red-200 dark:border-red-500/30', text: 'text-red-600 dark:text-red-400' },
                              high: { grad: 'from-orange-500/10', border: 'border-orange-200 dark:border-orange-500/30', text: 'text-orange-600 dark:text-orange-400' },
                              medium: { grad: 'from-amber-500/10', border: 'border-amber-200 dark:border-amber-500/30', text: 'text-amber-600 dark:text-amber-400' },
                              low: { grad: 'from-emerald-500/10', border: 'border-emerald-200 dark:border-emerald-500/30', text: 'text-emerald-600 dark:text-emerald-400' },
                              info: { grad: 'from-gray-200/40', border: 'border-gray-200 dark:border-gray-700', text: 'text-gray-600 dark:text-gray-300' },
                            }[sev] ?? { grad: 'from-gray-200/40', border: 'border-gray-200 dark:border-gray-700', text: 'text-gray-600 dark:text-gray-300' };
                            return (
                              <div className={`flex items-center gap-3 bg-gradient-to-br ${sevCfg.grad} to-transparent border ${sevCfg.border} rounded-lg p-3`}>
                                <div className="flex-1 min-w-0">
                                  <p className="text-[9px] font-semibold text-[#57606a] dark:text-gray-400 uppercase tracking-wider mb-0.5">Severity</p>
                                  <p className={`text-base font-bold capitalize ${sevCfg.text}`}>{SEV_LABEL[sev]}</p>
                                </div>
                                <div className={`flex items-center gap-1 px-2.5 py-0.5 rounded-full flex-shrink-0 ${selectedQueueAlert.is_open ? 'bg-green-500/20 border border-green-500/30' : 'bg-gray-200/60 border border-gray-200'}`}>
                                  <span className={`w-1.5 h-1.5 rounded-full ${selectedQueueAlert.is_open ? 'bg-green-500' : 'bg-gray-400'}`} />
                                  <span className={`text-xs font-semibold ${selectedQueueAlert.is_open ? 'text-green-700' : 'text-[#57606a]'}`}>
                                    {selectedQueueAlert.is_open ? 'Open' : 'Closed'}
                                  </span>
                                </div>
                              </div>
                            );
                          })()}

                          {/* Alert information */}
                          <div className="rounded-xl border border-gray-200 dark:border-white/5 bg-gray-50 dark:bg-[#1c2432] p-4">
                            <p className="text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wider mb-2">Alert Information</p>
                            <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">{selectedQueueAlert.alert_type || 'Unknown Alert'}</p>
                            <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">{selectedQueueAlert.event_code || '—'}</p>
                            <div className="mt-3 pt-3 border-t border-blue-100 dark:border-white/10 text-xs">
                              <div className="grid grid-cols-[140px_1fr] gap-y-2 items-center">

                                <p className="text-gray-500 dark:text-slate-400">Host Name :</p>
                                <p className="font-semibold text-gray-900 dark:text-slate-100 truncate">
                                  {selectedQueueAlert.hostname || selectedQueueAlert.host_identifier || '—'}
                                </p>

                                <p className="text-gray-500 dark:text-slate-400">Detected :</p>
                                <p className="font-semibold text-gray-900 dark:text-slate-100">
                                  {fmtTime(selectedQueueAlert.unixtime)}
                                </p>

                                <p className="text-gray-500 dark:text-slate-400">Host ID :</p>
                                <p className="font-semibold text-gray-900 dark:text-slate-100 break-all text-left leading-relaxed">
                                  {selectedQueueAlert.host_identifier || '—'}
                                </p>

                                <p className="text-gray-500 dark:text-slate-400">OS Name :</p>
                                <p className="font-semibold text-gray-900 dark:text-slate-100 truncate">
                                  {selectedQueueAlert.os_name || '—'}
                                </p>

                              </div>


                            </div>
                          </div>

                          {selectedQueueAlert.alert_type === 'Unmanaged Hosts Detected' && Array.isArray(selectedQueueAlert.metadata?.hosts) && (
                            <UnmanagedHostsAlertDetails hosts={selectedQueueAlert.metadata.hosts as UnmanagedHost[]} />
                          )}

                          {/* Assignment */}
                          <div className="rounded-xl border border-gray-200 dark:border-white/5 bg-gray-50 dark:bg-[#1c2432] p-4">
                            <div className="flex items-center justify-between">
                              <p className="text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wider mb-2">Assignment</p>
                              {!assignedMetaLoading && getAlertAssigneeId(selectedQueueAlert) && (
                                <button
                                  type="button"
                                  onClick={() => openUnassignModal(selectedQueueAlert)}
                                  disabled={tab === 'my'}
                                  className="rounded-lg text-[11px] font-semibold text-red-500 hover:text-red-600 hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:no-underline dark:text-red-400 dark:hover:text-red-300"
                                >
                                  Unassign
                                </button>
                              )}
                            </div>

                           {assignedMetaLoading ? (
                              <div className="mt-3 pt-3 border-t border-blue-100 dark:border-white/10 text-xs">
                                <InlineSpinner text="Loading..." className="font-medium text-gray-600 dark:text-slate-400" />
                              </div>
                            ) : getAlertAssigneeId(selectedQueueAlert) ? (
                              <div className="mt-3 pt-3 border-t border-blue-100 dark:border-white/10 text-xs">
                                <div className="grid grid-cols-[140px_1fr] gap-y-2 items-center">

                                  <p className="text-gray-500 dark:text-slate-400">Assigned To :</p>
                                  <p className="font-semibold text-gray-900 dark:text-slate-100 truncate">
                                    {assignedMeta?.assignee ?
                                      assignedMeta.assignee.email ?
                                        `${assignedMeta.assignee.name} (${assignedMeta.assignee.email})` :
                                        assignedMeta.assignee.name :
                                      '—'}
                                  </p>

                                  <p className="text-gray-500 dark:text-slate-400">Assigned By :</p>
                                  <p className="font-semibold text-gray-900 dark:text-slate-100">
                                    {assignedMeta?.assignedBy ?
                                      assignedMeta.assignedBy.email ?
                                        `${assignedMeta.assignedBy.name} (${assignedMeta.assignedBy.email})` :
                                        assignedMeta.assignedBy.name :
                                      '—'}
                                  </p>

                                  <p className="text-gray-500 dark:text-slate-400">Assigned At :</p>
                                  <p className="font-semibold text-gray-900 dark:text-slate-100 truncate">
                                    {assignedMeta?.assignedAt ?
                                      new Date(assignedMeta.assignedAt).toLocaleString() :
                                      '—'}
                                  </p>

                                  <p className="text-gray-500 dark:text-slate-400">Status :</p>
                                  <p className="font-semibold text-gray-900 dark:text-slate-100 truncate">
                                    {selectedQueueAlert.is_open ? 'Open' : 'Closed'}
                                  </p>

                                </div>
                              </div>
                            ) : (
                              <div className="mt-3 pt-3 border-t border-blue-100 dark:border-white/10 text-center py-4">
                                <p className="text-xs text-gray-400 dark:text-slate-500 dark:text-slate-400 mt-1">No one has been assigned to this alert yet</p>
                              </div>
                            )}
                          </div>

                          {/* Metadata trigger */}
                          <button
                            type="button"
                            onClick={() => { setMetadataPanelOpen(true); setMetaSearch(''); }}
                            className="group flex w-full items-center justify-between rounded-xl border border-gray-200 dark:border-white/10 bg-gray-50 dark:bg-[#1c2432] px-4 py-3 transition-colors duration-200 hover:bg-gray-100 dark:hover:bg-white/5"
                          >
                            <div className="flex items-center gap-2">
                              <svg className="w-3.5 h-3.5 text-gray-400 dark:text-slate-400 group-hover:text-gray-600 dark:group-hover:text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                              </svg>
                              <span className="text-xs font-semibold text-gray-600 dark:text-slate-400">Inspect Metadata</span>
                            </div>
                            <svg className="w-3.5 h-3.5 text-gray-400 dark:text-slate-400 transition-transform duration-200 group-hover:translate-x-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                          </button>
                        </div>
                      </div>

                      {/* Bottom actions */}
                      <div className="border-t border-gray-200 dark:border-gray-600 p-4 flex-shrink-0 bg-white dark:bg-gray-800">
                        <div className="grid grid-cols-2 gap-2.5">
                          <button
                            type="button"
                            className="h-9 rounded-lg border border-blue-200 bg-blue-50 text-xs font-semibold text-blue-600 transition-all duration-200 hover:bg-blue-100 hover:shadow-sm disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-blue-50 disabled:hover:shadow-none dark:border-blue-500/30 dark:bg-blue-500/10 dark:text-blue-400 dark:hover:bg-blue-500/20"
                            onClick={() => openAssignModal(selectedQueueAlert)}
                            disabled={tab === 'my' || !selectedQueueAlert.is_open}
                          >
                            {getAlertAssigneeId(selectedQueueAlert) ? 'Reassign' : 'Assign'}
                          </button>
                          <button
                            type="button"
                            className="h-9 rounded-lg border border-gray-300 bg-white text-xs font-semibold text-gray-700 transition-all duration-200 hover:bg-gray-50 hover:shadow-sm dark:border-gray-600 dark:bg-gray-700 dark:text-gray-100 dark:hover:bg-gray-600"
                            onClick={() => openStatusModal(selectedQueueAlert)}
                          >
                            {selectedQueueAlert.is_open ? 'Mark Closed' : 'Reopen'}
                          </button>
                          {(() => {
                            const key = String(selectedQueueAlert.id);
                            const rawMark = positiveMarkPending[key] ?? selectedQueueAlert.mark_type ?? null;
                            const currentMark: PositiveFilter | null =
                              rawMark === 'true_positive' || rawMark === 'false_positive' ? rawMark : null;
                            const isTP = currentMark === 'true_positive';
                            const isFP = currentMark === 'false_positive';
                            return (
                              <>
                                <button
                                  type="button"
                                  className={`h-9 rounded-lg border text-xs font-semibold transition-all duration-200 hover:shadow-sm ${isTP
                                    ? 'border-green-600 bg-green-600 text-white hover:bg-green-700'
                                    : 'border-green-200 bg-green-50 text-green-600 hover:bg-green-100 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-400 dark:hover:bg-green-500/20'
                                    }`}
                                  onClick={() => void handleMarkPositive(selectedQueueAlert, isTP ? 'unmarked' : 'true_positive')}
                                >
                                  {isTP ? 'Undo True Positive' : 'True Positive'}
                                </button>
                                <button
                                  type="button"
                                  className={`h-9 rounded-lg border text-xs font-semibold transition-all duration-200 hover:shadow-sm ${isFP
                                    ? 'border-red-600 bg-red-600 text-white hover:bg-red-700'
                                    : 'border-red-200 bg-red-50 text-red-500 hover:bg-red-100 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-400 dark:hover:bg-red-500/20'
                                    }`}
                                  onClick={() => void handleMarkPositive(selectedQueueAlert, isFP ? 'unmarked' : 'false_positive')}
                                >
                                  {isFP ? 'Undo False Positive' : 'False Positive'}
                                </button>
                              </>
                            );
                          })()}
                        </div>
                      </div>

                    </div>
                  </motion.div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Alert Detail Slide-over */}
      <AnimatePresence>
        {
          selectedAlertModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.22, ease: 'easeOut' }}
              className="fixed inset-0 z-50 bg-slate-950/45 backdrop-blur-sm"
              onClick={() => setSelectedAlertModal(null)}
              role="dialog" aria-modal="true" aria-label="Alert details"
            >
              <div className="flex min-h-auto justify-end p-0 sm:p-4">
                <motion.div
                  initial={{ x: '100%', opacity: 0.95 }}
                  animate={{ x: 0, opacity: 1 }}
                  exit={{ x: '100%', opacity: 0.98 }}
                  transition={{ type: 'spring', stiffness: 280, damping: 30 }}
                  className="flex h-screen w-full max-w-[680px] flex-col overflow-hidden bg-white shadow-[0_24px_80px_rgba(15,23,42,0.28)] sm:h-[calc(100vh-2rem)] sm:rounded-3xl sm:border sm:border-slate-200/70"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="border-b border-slate-200/70 bg-gradient-to-b from-white to-slate-50/70 px-4 py-4 sm:px-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-slate-900 text-white shadow-md shadow-slate-300/40">
                          <i className={`${getAlertIcon(normalizeSev(selectedAlertModal.severity))} text-xl`} />
                        </div>
                        <div className="min-w-0 space-y-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="inline-flex items-center rounded-full border border-violet-100 bg-blue-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-600">
                              {SEV_LABEL[normalizeSev(selectedAlertModal.severity)]}
                            </span>
                            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${selectedAlertModal.is_open === true ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-slate-100 text-slate-700'}`}>
                              <span className={`h-2 w-2 rounded-full ${selectedAlertModal.is_open === true ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                              {selectedAlertModal.is_open === true ? 'Open' : 'Resolved'}
                            </span>
                          </div>
                          <div className="min-w-0">
                            <h3 className="truncate text-xl font-semibold tracking-tight text-slate-900 sm:text-2xl">
                              {selectedAlertModal.title ?? `Alert ${selectedAlertModal.id}`}
                            </h3>
                            <p className="truncate text-sm text-slate-500">
                              {selectedAlertModal.hostname ?? selectedAlertModal.source ?? '—'} • {selectedAlertModal.os_name ?? '—'}
                            </p>
                          </div>
                        </div>
                      </div>
                      <button onClick={() => setSelectedAlertModal(null)} className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-500 shadow-sm transition-all duration-200 hover:border-slate-300 hover:text-slate-900 hover:shadow-md" aria-label="Close modal">
                        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                      </button>
                    </div>
                  </div>

                  <div className="flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5">
                    {(() => {
                      const alertIdKey = String(selectedAlertModal.id);
                      const toggling = togglingIds.has(alertIdKey);
                      const assigneeIdRaw = (selectedAlertModal as unknown as Record<string, unknown>).assignee_id;
                      const assigneeIdNum = typeof assigneeIdRaw === 'number' ? assigneeIdRaw : typeof assigneeIdRaw === 'string' ? Number(assigneeIdRaw) : NaN;
                      const hasAssignee = Number.isFinite(assigneeIdNum) && assigneeIdNum > 0;
                      const eventCode = selectedAlertModal.event_code ?? selectedAlertModal.description ?? selectedAlertModal.title ?? `Alert ${selectedAlertModal.id}`;
                      const hostValue = selectedAlertModal.host_identifier ?? selectedAlertModal.hostname ?? selectedAlertModal.source ?? '—';
                      const timeValue = selectedAlertModal.timestamp ?? fmtTime(selectedAlertModal.unixtime);
                      const selectedRecord = selectedAlertModal as unknown as Record<string, unknown>;
                      const assigneeNameRaw = selectedRecord.assignee_name;
                      const assigneeEmailRaw = selectedRecord.assignee_email;
                      const assignedToName = typeof assigneeNameRaw === 'string' && assigneeNameRaw.trim() ? assigneeNameRaw.trim() : hasAssignee ? `User #${assigneeIdNum}` : null;
                      const assignedToEmail = typeof assigneeEmailRaw === 'string' && assigneeEmailRaw.trim() ? assigneeEmailRaw.trim() : null;
                      const alertAsItem = selectedAlertModal as unknown as AlertItem;
                      const modalMarkValue = alertAsItem.mark_type === 'true_positive' ? 'true_positive' : alertAsItem.mark_type === 'false_positive' ? 'false_positive' : '';
                      const modalEffectiveMarkValue = positiveMarkPending[String(alertAsItem.id)] ?? modalMarkValue;

                      return (
                        <div className="space-y-4">
                          <div className="rounded-2xl border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.04)] overflow-hidden">
                            <div className="p-4">
                              <p className="text-xs font-semibold text-slate-500 mb-3 uppercase tracking-wide text-center">Actions</p>
                              {modalEffectiveMarkValue === 'true_positive' && <div className="mb-3 text-center"><span className="inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">True Positive</span></div>}
                              {modalEffectiveMarkValue === 'false_positive' && <div className="mb-3 text-center"><span className="inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">False Positive</span></div>}
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <button type="button" onClick={() => openStatusModal(alertAsItem)} disabled={toggling} className={`w-full px-4 py-2 rounded-lg text-sm font-semibold transition bg-emerald-100 text-emerald-800 hover:bg-emerald-200 ${toggling ? 'opacity-60 cursor-not-allowed' : ''}`}>
                                  {toggling ? '…' : selectedAlertModal.is_open === true ? 'Close Alert' : 'Open Alert'}
                                </button>
                                <button type="button" onClick={() => openAssignModal(alertAsItem)} disabled={assignSubmitting || toggling || tab === 'my'} className={`w-full px-4 py-2 rounded-lg text-sm font-semibold transition bg-indigo-50 text-indigo-800 hover:bg-indigo-100 ${assignSubmitting || toggling || tab === 'my' ? 'opacity-60 cursor-not-allowed' : ''}`}>
                                  {assignSubmitting && (selectedAlertModal.id != null) ? '…' : hasAssignee ? 'Reassign Alert' : 'Assign Alert'}
                                </button>
                                <select value={modalEffectiveMarkValue} disabled={toggling} onChange={(e) => { const v = e.target.value; if (v !== 'true_positive' && v !== 'false_positive') return; void handleMarkPositive(alertAsItem, v); }} className="w-full px-4 py-2 rounded-lg border border-gray-300 text-sm font-semibold bg-white text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500/30 disabled:opacity-50" aria-label="Mark as true/false positive">
                                  <option value="true_positive">True Positive</option>
                                  <option value="false_positive">False Positive</option>
                                </select>
                              </div>
                            </div>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3 md:col-span-2">
                              <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Event</p>
                              <p className="mt-1 text-sm font-semibold text-slate-900 break-all">{eventCode}</p>
                            </div>
                            <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                              <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Host</p>
                              <p className="mt-1 text-sm font-semibold text-slate-900 break-all">{hostValue}</p>
                            </div>
                            <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                              <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Time of alert</p>
                              <p className="mt-1 text-sm font-semibold text-slate-900">{timeValue}</p>
                            </div>
                          </div>

                          <div className="rounded-2xl border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.04)] overflow-hidden">
                            <div className="px-4 py-3 bg-gradient-to-r from-violet-50 to-indigo-50 border-b border-violet-100">
                              <h4 className="font-semibold text-slate-900">Assignment</h4>
                            </div>
                            <div className="p-4">
                              {assignedMetaLoading || hasAssignee || assignedMeta?.assignee != null || assignedMeta?.assignedBy != null ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                  <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-0.5">Assigned by</p>
                                    <p className="mt-1 text-sm font-semibold text-slate-900">{assignedMetaLoading ? 'Loading…' : assignedMetaError ? '—' : assignedMeta?.assignedBy ? assignedMeta.assignedBy.email ? `${assignedMeta.assignedBy.name} (${assignedMeta.assignedBy.email})` : assignedMeta.assignedBy.name : '—'}</p>
                                  </div>
                                  <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-0.5">Assigned to</p>
                                    <p className="mt-1 text-sm font-semibold text-slate-900">{assignedMetaLoading ? 'Loading…' : assignedMetaError ? '—' : assignedMeta?.assignee ? assignedMeta.assignee.email ? `${assignedMeta.assignee.name} (${assignedMeta.assignee.email})` : assignedMeta.assignee.name : assignedToName ? assignedToEmail ? `${assignedToName} (${assignedToEmail})` : assignedToName : '—'}</p>
                                  </div>
                                  <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-0.5">Time of assignment</p>
                                    <p className="mt-1 text-sm font-semibold text-slate-900">{assignedMetaLoading ? '—' : assignedMetaError ? '—' : assignedMeta?.assignedAt ? new Date(assignedMeta.assignedAt).toLocaleString() : timeValue}</p>
                                  </div>
                                  <div className="rounded-2xl border border-slate-200 bg-white/80 px-4 py-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-0.5">Status</p>
                                    <p className="mt-1 text-sm font-semibold text-slate-900">{assignedMetaLoading ? '—' : assignedMetaError ? '—' : assignedMeta?.status ?? (typeof selectedAlertModal.is_open === 'boolean' ? selectedAlertModal.is_open ? 'Open' : 'Closed' : '—')}</p>
                                  </div>
                                </div>
                              ) : (
                                <p className="text-sm text-slate-500">Unassigned</p>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  <div className="border-t border-slate-200/80 bg-white/90 px-5 py-4 backdrop-blur-xl sm:px-7">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:items-center">
                        <button onClick={() => setSelectedAlertModal(null)} className="inline-flex items-center justify-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-slate-300 hover:bg-slate-50" aria-label="Close modal">Close</button>
                        <Link to="/alerts/view" state={selectedAlertModal} className="inline-flex items-center justify-center rounded-2xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-violet-900/15 transition hover:-translate-y-0.5 hover:bg-blue-700" onClick={() => setSelectedAlertModal(null)}>View Alert</Link>
                      </div>
                    </div>
                  </div>
                </motion.div>
              </div>
            </motion.div>
          )
        }
      </AnimatePresence >

      {/* Export Modal */}
      {
        exportModalOpen && typeof document !== 'undefined' && createPortal(
          <div ref={exportModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" aria-labelledby="export-modal-title" onClick={closeExportModal}>
            <div className="bg-white rounded-2xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 id="export-modal-title" className="text-lg font-semibold text-gray-900 mb-3">Export alerts</h3>
              <div className="flex gap-1 mb-4 p-1 bg-gray-100 rounded-lg">
                <button type="button" onClick={() => setExportMode('date')} className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition ${exportMode === 'date' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'}`}>Date range</button>
                <button type="button" onClick={() => setExportMode('pages')} className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition ${exportMode === 'pages' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'}`}>Pages</button>
              </div>
              {exportMode === 'date' ? (
                <div className="space-y-3 mb-5">
                  <div>
                    <label className="block text-xs font-medium text-gray-500 mb-1">From</label>
                    <div className="relative flex items-center group">
                      <input type="date" value={exportFromDate} onChange={(e) => { setExportFromDate(e.target.value); setExportModalError(null); }} onClick={(e) => (e.target as HTMLInputElement).showPicker?.()} max={exportToDate || new Date().toISOString().slice(0, 10)} className="w-full appearance-none pl-10 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 outline-none [&::-webkit-calendar-picker-indicator]:opacity-0 [&::-webkit-calendar-picker-indicator]:absolute [&::-webkit-calendar-picker-indicator]:inset-0 [&::-webkit-calendar-picker-indicator]:w-full [&::-webkit-calendar-picker-indicator]:h-full cursor-pointer text-gray-700 bg-white transition-shadow shadow-sm hover:border-gray-400" />
                      <svg className="w-5 h-5 absolute left-3 text-gray-400 group-hover:text-violet-500 transition-colors pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-500 mb-1">To</label>
                    <div className="relative flex items-center group">
                      <input type="date" value={exportToDate} onChange={(e) => { setExportToDate(e.target.value); setExportModalError(null); }} onClick={(e) => (e.target as HTMLInputElement).showPicker?.()} min={exportFromDate || undefined} max={new Date().toISOString().slice(0, 10)} className="w-full appearance-none pl-10 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 outline-none [&::-webkit-calendar-picker-indicator]:opacity-0 [&::-webkit-calendar-picker-indicator]:absolute [&::-webkit-calendar-picker-indicator]:inset-0 [&::-webkit-calendar-picker-indicator]:w-full [&::-webkit-calendar-picker-indicator]:h-full cursor-pointer text-gray-700 bg-white transition-shadow shadow-sm hover:border-gray-400" />
                      <svg className="w-5 h-5 absolute left-3 text-gray-400 group-hover:text-violet-500 transition-colors pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="mb-5">
                  <label className="block text-xs font-medium text-gray-500 mb-1">Number of pages</label>
                  <input type="number" min={1} max={100} value={exportNumPages} onChange={(e) => { setExportNumPages(Math.max(1, Math.min(100, parseInt(e.target.value, 10) || 1))); setExportModalError(null); }} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 outline-none" />
                  <p className="text-xs text-gray-400 mt-1">1–100 pages · 20 alerts per page</p>
                </div>
              )}
              {exportModalError && <div className="mb-4 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">{exportModalError}</div>}
              <div className="flex justify-end gap-2">
                <button type="button" onClick={closeExportModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200">Cancel</button>
                <button type="button" onClick={handleExportSubmit} disabled={exporting} className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50">{exporting ? 'Exporting…' : 'Export'}</button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Status Modal */}
      {
        statusModal && typeof document !== 'undefined' && createPortal(
          <div ref={statusModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" onClick={closeStatusModal}>
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">{(() => { const n = statusModal.alerts.length; if (n > 1) return statusModal.nextOpen ? `Reopen ${n} alerts` : `Close ${n} alerts`; return statusModal.nextOpen ? 'Reopen alert' : 'Close alert'; })()}</h3>
              <p className="text-sm text-gray-500 mb-3">{(() => { const n = statusModal.alerts.length; const verb = statusModal.nextOpen ? 'reopening' : 'closing'; return n > 1 ? `Add one reason for ${verb} all selected alerts.` : `Add a reason for ${verb} this alert.`; })()}</p>
              <textarea value={statusReason} onChange={(e) => { setStatusReason(sanitizeAsciiMultiLine(e.target.value, 300, false)); if (statusReasonError) setStatusReasonError(null); }} placeholder="e.g. False positive, Resolved after patch…" className={`w-full min-h-[80px] px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 resize-y ${statusReasonError ? 'border-red-300' : 'border-gray-300'}`} autoFocus />
              {statusReasonError && <p className="mt-2 text-xs text-red-600">{statusReasonError}</p>}
              <div className="flex justify-end gap-2 mt-4">
                <button type="button" onClick={closeStatusModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200">Cancel</button>
                <button type="button" onClick={handleStatusSubmit} disabled={statusSubmitting || !statusReason.trim()} className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50">{statusSubmitting ? 'Updating…' : statusModal.nextOpen ? statusModal.alerts.length > 1 ? 'Reopen all' : 'Reopen' : statusModal.alerts.length > 1 ? 'Close all' : 'Close'}</button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Mark Modal */}
      {
        markModal && typeof document !== 'undefined' && createPortal(
          <div ref={markModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" onClick={closeMarkModal}>
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {markModal.mark === 'unmarked'
                  ? (markModal.alerts.length > 1 ? `Undo mark on ${markModal.alerts.length} alerts` : 'Undo mark')
                  : (markModal.alerts.length > 1 ? `Mark ${markModal.alerts.length} alerts as ${MARK_ACTION_LABEL[markModal.mark]}` : `Mark as ${MARK_ACTION_LABEL[markModal.mark]}`)}
              </h3>
              <p className="text-sm text-gray-500 mb-3">
                {markModal.mark === 'unmarked'
                  ? 'Add a short reason for removing this classification.'
                  : (markModal.alerts.length > 1 ? 'Add one reason for this bulk marking.' : 'Add a short reason (stored in the audit trail).')}
              </p>
              <textarea value={markReason} onChange={(e) => { setMarkReason(sanitizeAsciiMultiLine(e.target.value, 300, false)); if (markReasonError) setMarkReasonError(null); }} placeholder="e.g. Confirmed by endpoint logs / Expected false alarm" className={`w-full min-h-[80px] px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 resize-y ${markReasonError ? 'border-red-300' : 'border-gray-300'}`} autoFocus />
              {markReasonError && <p className="mt-2 text-xs text-red-600">{markReasonError}</p>}
              <div className="flex justify-end gap-2 mt-4">
                <button type="button" onClick={closeMarkModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200" disabled={markSubmitting}>Cancel</button>
                <button type="button" onClick={handleMarkSubmit} disabled={markSubmitting || !markReason.trim()} className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50">
                  {markSubmitting
                    ? 'Saving…'
                    : markModal.mark === 'unmarked'
                      ? (markModal.alerts.length > 1 ? 'Undo mark on all' : 'Undo mark')
                      : (markModal.alerts.length > 1 ? `Mark all ${MARK_ACTION_LABEL[markModal.mark].toLowerCase()}` : 'Save')}
                </button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Assign Modal */}
      {
        assignModal && typeof document !== 'undefined' && createPortal(
          <div ref={assignModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" onClick={closeAssignModal}>
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-start justify-between gap-4 mb-3">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{(() => { const n = assignModal.alerts.length; const mode = getBulkAssignMode(assignModal.alerts); if (n > 1) return mode === 'reassign' ? `Reassign ${n} alerts` : `Assign ${n} alerts`; return mode === 'reassign' ? 'Reassign alert' : 'Assign alert'; })()}</h3>
                  <p className="text-sm text-gray-500 mt-1">{(() => { const n = assignModal.alerts.length; const mode = getBulkAssignMode(assignModal.alerts); if (n > 1) return mode === 'reassign' ? 'Some alerts already have an owner. All will be updated.' : 'Choose an owner for all selected alerts.'; return mode === 'reassign' ? 'Choose who should own this alert next.' : 'Choose who should own this alert.'; })()}</p>
                </div>
                <div className="shrink-0 w-10 h-10 rounded-2xl bg-blue-50 border border-violet-100 flex items-center justify-center">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="4" stroke="#7C3AED" strokeWidth="1.8" /><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="#7C3AED" strokeWidth="1.8" strokeLinecap="round" /></svg>
                </div>
              </div>
              {assignUsersError && <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">{assignUsersError}</div>}
              {assignModalError && <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">{assignModalError}</div>}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-xs font-semibold text-gray-600 uppercase">Assignee</label>
                  {selectedAssigneeId != null && <button type="button" onClick={() => { setSelectedAssigneeId(null); setAssignModalError(null); }} className="rounded-lg text-xs text-gray-500 hover:text-gray-800 hover:underline">Clear</button>}
                </div>
                <input type="text" value={assignSearch} onChange={(e) => { setAssignSearch(e.target.value); setAssignModalError(null); }} placeholder="Search by name or email" autoFocus disabled={assignUsersLoading || assignSubmitting} className="w-full px-3 py-2.5 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 outline-none disabled:opacity-50 mb-2" />
                <div className="rounded-2xl border border-gray-200 bg-gray-50 p-2 max-h-52 overflow-y-auto">
                  {assignUsersLoading ? (
                    <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-11 rounded-xl bg-gray-200/70 animate-pulse" />)}</div>
                  ) : filteredAssignUsers.length === 0 ? (
                    <div className="py-8 text-center"><p className="text-sm text-gray-500">No matching users</p></div>
                  ) : (
                    filteredAssignUsers.map((u) => {
                      const alerts = assignModal.alerts; const n = alerts.length;
                      const assigneeIdSet = new Set<number>();
                      alerts.forEach((a) => { const id = getAlertAssigneeId(a); if (id != null) assigneeIdSet.add(id); });
                      const sharedAssigneeAllSame = n > 1 && assigneeIdSet.size === 1 ? [...assigneeIdSet][0]! : null;
                      const isAlreadyAssigned = n === 1 ? getAlertAssigneeId(alerts[0]!) === u.id : sharedAssigneeAllSame != null && u.id === sharedAssigneeAllSame;
                      const isActive = selectedAssigneeId === u.id;
                      return (
                        <button key={u.id} type="button" disabled={isAlreadyAssigned || assignSubmitting} onClick={() => { if (isAlreadyAssigned) return; setSelectedAssigneeId(u.id); setAssignModalError(null); }}
                          className={['w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl border transition mb-1 last:mb-0', isActive ? 'bg-blue-600 text-white border-violet-600' : 'bg-white text-gray-900 border-transparent hover:border-violet-200 hover:bg-blue-50', isAlreadyAssigned && !isActive ? 'opacity-50 cursor-not-allowed' : ''].join(' ')}>
                          <div className="text-left min-w-0"><p className="text-sm font-semibold truncate">{u.name}</p><p className={`text-xs truncate ${isActive ? 'text-violet-100' : 'text-gray-400'}`}>{u.email}</p></div>
                          {isActive && <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M20 6 9 17l-5-5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" /></svg>}
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
              <div className="mb-4">
                <label className="block text-xs font-semibold text-gray-600 uppercase mb-2">Reason</label>
                <textarea value={assignReason} onChange={(e) => { setAssignReason(sanitizeAsciiMultiLine(e.target.value, 300, false)); if (assignReasonError) setAssignReasonError(null); }} placeholder="Why are you assigning this alert?" disabled={assignSubmitting} className={`w-full min-h-[70px] px-3 py-2 border rounded-xl text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 resize-y ${assignReasonError ? 'border-red-300' : 'border-gray-300'}`} />
                {assignReasonError && <p className="mt-2 text-xs text-red-600">{assignReasonError}</p>}
              </div>
              <div className="flex justify-end gap-2">
                <button type="button" onClick={closeAssignModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200" disabled={assignSubmitting}>Cancel</button>
                <button type="button" onClick={handleAssignSubmit} disabled={assignSubmitting || assignUsersLoading || selectedAssigneeId == null || !assignReason.trim()} className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-xl hover:bg-blue-700 disabled:opacity-50">{assignSubmitting ? 'Saving…' : assignModal.alerts.length > 1 ? getBulkAssignMode(assignModal.alerts) === 'reassign' ? 'Reassign all' : 'Assign all' : getBulkAssignMode(assignModal.alerts) === 'reassign' ? 'Reassign' : 'Assign'}</button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Unassign Modal */}
      {
        unassignModal && typeof document !== 'undefined' && createPortal(
          <div ref={unassignModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" onClick={closeUnassignModal}>
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">{unassignModal.alerts.length > 1 ? `Unassign ${unassignModal.alerts.length} alerts` : 'Unassign alert'}</h3>
              <p className="text-sm text-gray-500 mb-3">{unassignModal.alerts.length > 1 ? 'Add one reason for unassigning all selected alerts.' : 'Add a reason for removing the current assignee.'}</p>
              <textarea value={unassignReason} onChange={(e) => { setUnassignReason(sanitizeAsciiMultiLine(e.target.value, 300, false)); if (unassignReasonError) setUnassignReasonError(null); }} placeholder="e.g. Reassigning to another team, no longer applicable…" className={`w-full min-h-[80px] px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-violet-500 focus:border-violet-500 resize-y ${unassignReasonError ? 'border-red-300' : 'border-gray-300'}`} autoFocus />
              {unassignReasonError && <p className="mt-2 text-xs text-red-600">{unassignReasonError}</p>}
              <div className="flex justify-end gap-2 mt-4">
                <button type="button" onClick={closeUnassignModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200" disabled={unassignSubmitting}>Cancel</button>
                <button type="button" onClick={handleUnassignSubmit} disabled={unassignSubmitting || !unassignReason.trim()} className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-50">{unassignSubmitting ? 'Saving…' : unassignModal.alerts.length > 1 ? 'Unassign all' : 'Unassign'}</button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Assignee Info Modal */}
      {
        assigneeModalOpen && typeof document !== 'undefined' && createPortal(
          <div ref={assigneeModalContainerRef} className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" onClick={closeAssigneeModal}>
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-sm mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Assigned to</h3>
              {assigneeModalError && <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">{assigneeModalError}</div>}
              {assigneeModalLoading ? (
                <div className="flex items-center gap-2 text-sm text-gray-500 py-2"><DuoSpinner size="xs" className="text-gray-300" />Loading…</div>
              ) : assigneeModalUser ? (
                <div className="space-y-3 pt-1">
                  <div><p className="text-xs text-gray-400 mb-1">Name</p><p className="text-sm text-gray-900 font-medium">{assigneeModalUser.name || '—'}</p></div>
                  <div><p className="text-xs text-gray-400 mb-1">Email</p><p className="text-sm text-gray-900 font-medium">{assigneeModalUser.email || '—'}</p></div>
                </div>
              ) : (!assigneeModalError && <p className="text-sm text-gray-500 pt-1">No assignee info available.</p>)}
              <div className="flex justify-end mt-5">
                <button type="button" onClick={closeAssigneeModal} className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200" disabled={assigneeModalLoading}>Close</button>
              </div>
            </div>
          </div>,
          document.body
        )
      }

      {/* Bulk Action Toolbar */}
      {
        typeof document !== 'undefined' &&
        createPortal(
          reportMode ? (
            <div
              className="fixed bottom-0 left-0 right-0 z-40 border-t border-gray-200 bg-white/95 shadow-[0_-8px_30px_rgba(15,23,42,0.1)] backdrop-blur-sm md:left-52"
              role="toolbar"
              aria-label="Report selection"
            >
              <div className="mx-auto flex max-w-[100%] flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="text-base font-semibold text-gray-900">
                      {reportSelectedIds.size} selected for report
                    </span>
                    <button
                      type="button"
                      onClick={() => { setReportMode(false); setReportSelectedIds(new Set()); }}
                      className="rounded-lg text-sm font-medium text-blue-600 hover:text-blue-800"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleProceedToReport}
                    disabled={reportSelectedIds.size === 0}
                    className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Proceed to Report
                  </button>
                </div>
              </div>
            </div>
          ) :
            <AnimatePresence>
              {selectionActive && (
                <motion.div
                  variants={toolbarVariants}
                  initial="hidden"
                  animate="visible"
                  exit="exit"
                  className="fixed bottom-0 left-0 right-0 z-40 md:left-52 md:right-82"
                >
                  <div className="mx-10 mb-3 rounded-2xl border border-violet-200 bg-white/95 backdrop-blur-xl shadow-[0_-12px_40px_rgba(15,23,42,0.12)]">
                    <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">

                      {/* Left: selection summary */}
                      <div className="flex flex-wrap items-center gap-3 min-w-0">
                        {/* Checkbox indicator */}
                        <Checkbox
                          checked={true}
                          onChange={() => { }}
                          className="h-6 w-6 shrink-0"
                          sx={{ color: '#D1D5DB', '&.Mui-checked': { color: '#030303' } }}
                        />

                        {/* Count + sub info inline */}
                        <div className="flex items-baseline gap-2">
                          <span className="text-sm font-bold text-slate-900">
                            {bulkSelectionMeta.total} selected
                          </span>
                          <span className="text-xs text-slate-400">
                            {bulkSelectionMeta.openCount} open
                            {bulkSelectionMeta.closedCount > 0 && ` · ${bulkSelectionMeta.closedCount} closed`}
                          </span>
                        </div>

                        {/* Divider */}
                        <div className="h-4 w-px bg-slate-200 shrink-0" />

                        <button
                          onClick={clearSelection}
                          className="text-xs font-semibold text-slate-500 hover:text-slate-800 px-2 py-1 rounded-lg hover:bg-slate-100 transition shrink-0"
                        >
                          Clear
                        </button>
                      </div>

                      {/* Right: action buttons */}
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => runBulkMark('true_positive')}
                          disabled={markSubmitting || bulkSelectionMeta.total === 0}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 text-xs font-semibold text-emerald-700 hover:bg-emerald-100 disabled:opacity-40 transition"
                        >
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                          Mark TP
                        </button>

                        <button
                          onClick={() => runBulkMark('false_positive')}
                          disabled={markSubmitting || bulkSelectionMeta.total === 0}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-200 bg-rose-50 text-xs font-semibold text-rose-700 hover:bg-rose-100 disabled:opacity-40 transition"
                        >
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                          </svg>
                          Mark FP
                        </button>

                        {tab === 'closed' && (
                          <button
                            onClick={runBulkReopen}
                            disabled={statusSubmitting || bulkSelectionMeta.closedCount === 0}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 text-xs font-semibold text-amber-700 hover:bg-amber-100 disabled:opacity-40 transition"
                          >
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                            Reopen
                          </button>
                        )}

                        {(tab === 'open' || tab === 'my') && (
                          <>
                            {/* Vertical separator before close/assign */}
                            <div className="h-4 w-px bg-slate-200" />

                            <button
                              onClick={runBulkClose}
                              disabled={statusSubmitting || bulkSelectionMeta.openCount === 0}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40 transition"
                            >
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                              </svg>
                              Close
                            </button>

                            <button
                              onClick={runBulkAssign}
                              disabled={assignSubmitting || bulkSelectionMeta.openCount === 0}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-blue-200 bg-blue-600 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-40 transition shadow-sm shadow-blue-200"
                            >
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                              </svg>
                              Assign
                            </button>
                          </>
                        )}
                      </div>

                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>,
          document.body
        )
      }
      {/* CERT-In form modal */}
      <CertInModal
        isOpen={certinModalOpen}
        onClose={() => setCertinModalOpen(false)}
        data={certinFormData}
        onChange={setCertinFormData}
        onDownload={handleDownloadPDF}
        onSaveDraft={handleSaveDraftApi}
        onNewDraft={() => {
          void prefillCertinNewDraft();
          setReportSelectedIds(new Set());
          setReportSourceAlertIds([]);
          setCertinModalOpen(false);
          setReportMode(true);
        }}
        onEditDraft={() => {
          if (!hasDraftInLast24h) return;
          setCertinFormData(certinDraft?.formData ?? initialCertinFormData);
          const ids = Array.isArray(certinDraft?.selectedAlertIds) ? certinDraft.selectedAlertIds : [];
          setReportSelectedIds(new Set(ids.map(String)));
          setReportSourceAlertIds(ids.map(String));
        }}
        onDownloadDraft={() => { void handleDownloadFromDraft(); }}
        hasDraft={hasDraftInLast24h}
        canDownloadDraft={hasDraftInLast24h && latestDraftComplete}
        lastEditedAgoText={lastEditedAgoText}
        disappearsInText={disappearsInText}
        historyItems={certinHistory}
        onRefreshHistory={loadCertinHistory}
        onPreviewHistory={(formData) => setCertinFormData(formData)}
        onDownloadHistory={(formData) => { void handleDownloadPDFForData(formData); }}
      />
    </>
  );
};

export default Alerts;
