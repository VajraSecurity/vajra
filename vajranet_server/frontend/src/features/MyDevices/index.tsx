import { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import type { ChangeEvent, ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'motion/react';
import Button from '@mui/material/Button';
import RefreshIcon from '@mui/icons-material/Refresh';
import BrowserUpdatedIcon from '@mui/icons-material/BrowserUpdated';
import CloudQueueIcon from '@mui/icons-material/CloudQueue';
import CloudOffIcon from '@mui/icons-material/CloudOff';
import DevicesIcon from '@mui/icons-material/Devices';
import DoDisturbAltIcon from '@mui/icons-material/DoDisturbAlt';
import StarIcon from '@mui/icons-material/Star';
import StarBorderIcon from '@mui/icons-material/StarBorder';
import CloseIcon from '@mui/icons-material/Close';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import { NODES_URLS, ALERTS_URLS, API_BASE_URL, API_PREFIX } from '../../api/urls';
import { csrfHeadersJson, fetchWithCsrf } from '../../api/csrfClient';
import { formatUnixTimestamp } from '../../lib/utils';
import { useLiveData } from '../../context/useLiveData';
import { Link, useSearchParams } from 'react-router-dom';
import { useToast } from '../../context/useToast';
import { sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import Pagination from '../../components/ui/pagination';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import TextField from '@mui/material/TextField';
import DialogActions from '@mui/material/DialogActions';
import { Checkbox } from '../../components/ui/checkbox';
import { Meteors } from '../../components/ui/meteors';
import { DevicesIcon as DevicesHeroIcon } from '../../components/icons/navIcons';
import { Skeleton } from '../../components/ui/skeleton';
import { DuoSpinner } from '../../components/ui/loading';
import LiveConnectionBadge from '../../components/ui/LiveConnectionBadge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select';
import { DeviceTableRow } from './components/DeviceTableRow';
import { DeviceMobileCard } from './components/DeviceMobileCard';
import { useModalA11y } from '../../hooks/useModalA11y';
import { getDeviceIcon } from './utils/deviceFormatters';
import { CRITICAL_CSS } from './criticalStyles';
import type {
  SecurityProductChange,
  SecurityProduct,
  DeviceGroup,
  DeviceNetworkInterface,
  WifiSnapshot,
  WifiSavedProfile,
  RawNode,
  Device,
} from './types';

/** Row shape returned by GET ALERTS_URLS.CLAMAV_SUMMARY (`{ data: [...] }`). */
interface ClamavSummaryApiRow {
  host_identifier: string | number;
  count?: number | string;
  last_alert_at?: number | string | null;
  daemon_running?: boolean | number | null;
  db_version?: string | null;
  db_date?: string | null;
}

/** Row shape returned by GET NODES_URLS.FIREWALL_STATUS (`{ data: [...] }`). */
interface FirewallStatusApiRow {
  host_identifier: string | number;
  manager?: string;
  active?: boolean;
  enabled_on_boot?: boolean;
}

// Matches the backend's PAGINATION_MAX_ROWS_NODES cap for /nodes/list — without an explicit
// `rows` param the backend only returns PAGINATION_DEFAULT_ROWS (100), silently truncating any
// org with more endpoints. We request the server's actual max and warn the admin if we hit it,
// since this page does its own client-side table pagination on top of whatever is fetched.
const NODE_LIST_FETCH_CAP = 1000;

const MyDevices = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState(() => searchParams.get('q') ?? '');
  const [filterStatus, setFilterStatus] = useState<'all' | 'online' | 'offline'>('all');
  const [filterRisk, setFilterRisk] = useState<'all' | 'isolated' | 'critical'>('all');
  const [filterOs, setFilterOs] = useState<'all' | 'windows' | 'linux' | 'macos'>('all');
  const [filterGroup, setFilterGroup] = useState<string[]>([]);
  const [isGroupDropdownOpen, setIsGroupDropdownOpen] = useState(false);
  const groupDropdownRef = useRef<HTMLDivElement>(null);
  // The dropdown button lives inside the gradient hero header, which needs
  // `overflow-hidden` to clip the Meteors decoration to its rounded corners —
  // that same overflow-hidden would clip this panel too if it weren't
  // portaled out to <body> and positioned via the button's own rect.
  const groupPanelRef = useRef<HTMLDivElement>(null);
  const [groupDropdownPos, setGroupDropdownPos] = useState<{ top: number; left: number } | null>(null);
  const [groupsList, setGroupsList] = useState<DeviceGroup[]>([]);
  const [groupsMap, setGroupsMap] = useState<Record<string, string>>({});
  const [tablePage, setTablePage] = useState(1);
  const [tablePageSize, setTablePageSize] = useState(10);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [criticalBulkMode, setCriticalBulkMode] = useState(false);
  const [bulkActionInFlight, setBulkActionInFlight] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'ips' | 'wifi'>('overview');
  const [themeMode, setThemeMode] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light';
    return localStorage.getItem('dashboard-theme') === 'dark' || localStorage.getItem('my-devices-theme') === 'dark' ? 'dark' : 'light';
  });
  const [rawNodesData, setRawNodesData] = useState<RawNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nodesListMaybeTruncated, setNodesListMaybeTruncated] = useState(false);
  const [deviceIPs, setDeviceIPs] = useState<{ [key: string]: DeviceNetworkInterface[] }>({});
  const [loadingIPs, setLoadingIPs] = useState(false);
  const [deviceWifi, setDeviceWifi] = useState<{ [key: string]: WifiSnapshot | null }>({});
  const [loadingWifi, setLoadingWifi] = useState(false);
  const [complianceLatestByHost, setComplianceLatestByHost] = useState<
    Record<string, { percent: number; unixtime: number } | null>
  >({});
  const [renameOpen, setRenameOpen] = useState(false);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [criticalOpen, setCriticalOpen] = useState(false);
  const [criticalReason, setCriticalReason] = useState("");
  const [criticalNodeId, setCriticalNodeId] = useState<string | null>(null);
  const [criticalModalMode, setCriticalModalMode] = useState<'mark' | 'unmark'>('mark');
  const { liveData, nodeStatus, clamavAlertsByHost, firewallStatusPushByHost } = useLiveData();
  const { showToast } = useToast();

  // ClamAV status (Linux nodes)
  // The alerts table is the source of truth (clamav_push detections are
  // persisted there by the backend, including store-and-forward batches that
  // arrive while no dashboard is open). The live WS clamav_push forward is
  // used only as a refresh trigger — same hydrate-then-stream pattern as the
  // Windows security_products column, but event-driven instead of polled.
  const [clamavSummaryByHost, setClamavSummaryByHost] = useState<
    Record<string, {
      count: number;
      lastAlertAt: number | null;
      /** clamd answered PING on the host. null = no status report received yet. */
      daemonRunning: boolean | null;
      dbVersion: string | null;
      dbDate: string | null;
    }>
  >({});
  const clamavRefetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchClamavSummary = useCallback(async () => {
    try {
      const res = await fetch(ALERTS_URLS.CLAMAV_SUMMARY, {
        method: 'GET',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) return;
      const body = await res.json();
      const rows: ClamavSummaryApiRow[] = Array.isArray(body?.data) ? body.data : [];
      const next: typeof clamavSummaryByHost = {};
      for (const r of rows) {
        next[String(r.host_identifier)] = {
          count: Number(r.count) || 0,
          lastAlertAt: r.last_alert_at != null ? Number(r.last_alert_at) : null,
          daemonRunning: r.daemon_running != null ? Boolean(r.daemon_running) : null,
          dbVersion: r.db_version != null ? String(r.db_version) : null,
          dbDate: r.db_date != null ? String(r.db_date) : null,
        };
      }
      setClamavSummaryByHost(next);
    } catch {
      /* non-fatal — tag falls back to Unknown */
    }
  }, []);

  // Initial hydration on mount.
  useEffect(() => {
    fetchClamavSummary();
  }, [fetchClamavSummary]);

  // A clamav_push on the live channel means new rows just landed in the DB —
  // refetch (debounced: store-and-forward reconnects deliver bursts).
  useEffect(() => {
    if (clamavAlertsByHost.size === 0) return;
    if (clamavRefetchTimerRef.current) clearTimeout(clamavRefetchTimerRef.current);
    clamavRefetchTimerRef.current = setTimeout(fetchClamavSummary, 1000);
    return () => {
      if (clamavRefetchTimerRef.current) clearTimeout(clamavRefetchTimerRef.current);
    };
  }, [clamavAlertsByHost, fetchClamavSummary]);

  // Firewall status (Linux nodes)
  const [firewallSummaryByHost, setFirewallSummaryByHost] = useState<
    Record<string, {
      manager: string;
      active: boolean;
      enabled_on_boot: boolean;
    }>
  >({});
  const firewallRefetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchFirewallStatus = useCallback(async () => {
    try {
      const res = await fetch(NODES_URLS.FIREWALL_STATUS, {
        method: 'GET',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) return;
      const body = await res.json();
      const rows: FirewallStatusApiRow[] = Array.isArray(body?.data) ? body.data : [];
      const next: typeof firewallSummaryByHost = {};
      for (const r of rows) {
        next[String(r.host_identifier)] = {
          manager: String(r.manager ?? 'none'),
          active: Boolean(r.active),
          enabled_on_boot: Boolean(r.enabled_on_boot),
        };
      }
      setFirewallSummaryByHost(next);
    } catch {
      /* non-fatal */
    }
  }, []);

  useEffect(() => {
    fetchFirewallStatus();
  }, [fetchFirewallStatus]);

  useEffect(() => {
    if (firewallStatusPushByHost.size === 0) return;
    if (firewallRefetchTimerRef.current) clearTimeout(firewallRefetchTimerRef.current);
    firewallRefetchTimerRef.current = setTimeout(fetchFirewallStatus, 1000);
    return () => {
      if (firewallRefetchTimerRef.current) clearTimeout(firewallRefetchTimerRef.current);
    };
  }, [firewallStatusPushByHost, fetchFirewallStatus]);

  const POLL_NODES_INTERVAL_MS = 10000;
  const isDarkMode = themeMode === 'dark';
  const darkDialogSx = {
    '& .MuiPaper-root': {
      backgroundColor: '#0f172a',
      color: '#e5edf8',
      border: '1px solid rgba(71, 85, 105, 0.78)',
      boxShadow: '0 24px 80px rgba(0, 0, 0, 0.45)',
    },
    '& .MuiDialogTitle-root': {
      color: '#f8fafc',
    },
    '& .MuiDialogContent-root, & .MuiDialogActions-root': {
      color: '#cbd5e1',
    },
    '& .MuiInputBase-root': {
      backgroundColor: 'rgba(15, 23, 42, 0.92)',
      color: '#e5edf8',
    },
    '& .MuiInputLabel-root': {
      color: '#94a3b8',
    },
    '& .MuiOutlinedInput-notchedOutline': {
      borderColor: 'rgba(71, 85, 105, 0.9)',
    },
    '& .MuiOutlinedInput-root:hover .MuiOutlinedInput-notchedOutline': {
      borderColor: '#60a5fa',
    },
    '& .MuiOutlinedInput-root.Mui-focused .MuiOutlinedInput-notchedOutline': {
      borderColor: '#3b82f6',
    },
    '& .MuiButton-root': {
      color: '#bfdbfe',
    },
  };

  // Polling + visual highlight when security product states change.
  const isMountedRef = useRef(true);
  const fetchNodesInFlightRef = useRef(false);
  const hasFetchedInitialNodesRef = useRef(false);
  const exportNodesInFlightRef = useRef(false);
  const securitySignatureByNodeIdRef = useRef<Map<string, string>>(new Map());
  const hasInitialSecuritySignatureRef = useRef(false);
  const lastRawNodeByIdRef = useRef<Map<string, RawNode>>(new Map());

  const [pendingSecurityChangesByNodeId, setPendingSecurityChangesByNodeId] = useState<
    Record<string, { changes: SecurityProductChange[]; detectedAt: number }>
  >({});

  // Fetch IP list for a specific node
  const fetchNodeIPs = async (hostIdentifier: string) => {
    try {
      const response = await fetchWithCsrf(NODES_URLS.IP_LIST, {
        method: "POST",
        credentials: "include",
        headers: csrfHeadersJson(),
        body: JSON.stringify({ host_identifier: hostIdentifier }),
      });

      if (!response.ok) {
        throw new Error(`Error ${response.status}: Failed to fetch IPs for host ${hostIdentifier}`);
      }

      const ipData = await response.json();

      return ipData?.interfaces || [];
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error(`Error fetching IPs for host ${hostIdentifier}:`, err);
      }
      return [];
    }
  };

  // Fetch latest WiFi snapshot for a node
  const fetchNodeWifi = async (hostIdentifier: string) => {
    try {
      const response = await fetch(`${NODES_URLS.WIFI_LATEST}${encodeURIComponent(hostIdentifier)}`, {
        method: 'GET',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) return null;
      const res = await response.json();
      return res?.success ? (res.data ?? null) : null;
    } catch {
      return null;
    }
  };

  const getSecurityProductsSignature = (products: SecurityProduct[] | undefined): string => {
    if (!Array.isArray(products) || products.length === 0) return '[]';

    // Normalize + sort so the signature stays stable even if backend ordering changes.
    const normalized = products
      .map((p: SecurityProduct) => ({
        name: String(p?.name ?? '').trim().toLowerCase(),
        state: String(p?.state ?? 'N/A').trim().toLowerCase(),
      }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.state.localeCompare(b.state));

    return normalized.map((p) => `${p.name}:${p.state}`).join('|');
  };

  const diffSecurityProducts = (
    prevProducts: SecurityProduct[] | undefined,
    nextProducts: SecurityProduct[] | undefined
  ): SecurityProductChange[] => {
    const toMap = (products: SecurityProduct[] | undefined) => {
      const map = new Map<string, string>();
      if (!Array.isArray(products)) return map;
      for (const p of products) {
        const name = String(p?.name ?? '').trim();
        if (!name) continue;
        const key = name.toLowerCase();
        const state = String(p?.state ?? 'N/A').trim();
        map.set(key, state);
      }
      return map;
    };

    const prevMap = toMap(prevProducts);
    const nextMap = toMap(nextProducts);
    const keys = new Set<string>([...prevMap.keys(), ...nextMap.keys()]);

    const changes: SecurityProductChange[] = [];
    for (const key of keys) {
      const from = prevMap.get(key) ?? 'N/A';
      const to = nextMap.get(key) ?? 'N/A';
      if (String(from).toLowerCase() !== String(to).toLowerCase()) {
        // Prefer original-cased name if available in the "next" payload.
        const displayName =
          (Array.isArray(nextProducts)
            ? nextProducts.find((p) => String(p?.name ?? '').trim().toLowerCase() === key)?.name
            : undefined) ||
          (Array.isArray(prevProducts)
            ? prevProducts.find((p) => String(p?.name ?? '').trim().toLowerCase() === key)?.name
            : undefined) ||
          key;

        changes.push({
          name: String(displayName),
          from: String(from),
          to: String(to),
        });
      }
    }

    return changes.sort((a, b) => a.name.localeCompare(b.name));
  };

  // Fields the table/cards actually render. Two node payloads that agree on all
  // of these are equivalent for rendering even if the backend handed back fresh
  // object instances, which lets us keep the same object reference across polls
  // so unaffected table rows don't re-render.
  const NODE_EQUALITY_KEYS = [
    'host_identifier', 'hostname', 'os_name', 'os_platform', 'address',
    'osquery_version', 'last_seen', 'enrolled_on', 'agent_online', 'status',
    'critical', 'isolated',
  ] as const;

  const areNodesEquivalent = (a: RawNode, b: RawNode): boolean => {
    if (a === b) return true;
    if (!a || !b) return false;
    for (const key of NODE_EQUALITY_KEYS) {
      if (a[key] !== b[key]) return false;
    }

    const aGroups: string[] = Array.isArray(a.group_ids) ? a.group_ids : [];
    const bGroups: string[] = Array.isArray(b.group_ids) ? b.group_ids : [];
    if (aGroups.length !== bGroups.length || aGroups.some((id, i) => id !== bGroups[i])) {
      return false;
    }

    return getSecurityProductsSignature(a.security_products) === getSecurityProductsSignature(b.security_products);
  };

  const fetchNodes = async (): Promise<boolean> => {
    if (fetchNodesInFlightRef.current) return false;
    if (!isMountedRef.current) return false;

    fetchNodesInFlightRef.current = true;
    try {
      if (!hasFetchedInitialNodesRef.current) {
        setLoading(true);
      }
      setError(null);

      const response = await fetch(`${NODES_URLS.NODES_LIST}?rows=${NODE_LIST_FETCH_CAP}&pageno=1`, {
        method: "GET",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Error ${response.status}: Failed to fetch nodes`);
      }

      const res = await response.json();

      let nodesArray: RawNode[] = [];
      if (res?.data) {
        nodesArray = res.data;
      } else if (res?.nodes) {
        nodesArray = res.nodes;
      } else if (Array.isArray(res)) {
        nodesArray = res;
      } else {
        nodesArray = [];
      }

      // The backend silently clamps `rows` at PAGINATION_MAX_ROWS_NODES; hitting that cap means
      // there may be more devices beyond what was fetched (the API doesn't return a true total).
      if (isMountedRef.current) setNodesListMaybeTruncated(nodesArray.length >= NODE_LIST_FETCH_CAP);

      // Diff security products to highlight changed nodes.
      const nextSignatureByNodeId = new Map<string, string>();
      const nextProductsByNodeId = new Map<string, SecurityProduct[]>();
      for (const node of nodesArray) {
        const nodeId = node?.id != null ? String(node.id) : node?.host_identifier != null ? String(node.host_identifier) : '';
        if (!nodeId) continue;
        const products = Array.isArray(node?.security_products) ? node.security_products : [];
        nextProductsByNodeId.set(nodeId, products);
        nextSignatureByNodeId.set(nodeId, getSecurityProductsSignature(products));
      }

      if (!hasInitialSecuritySignatureRef.current) {
        securitySignatureByNodeIdRef.current = nextSignatureByNodeId;
        hasInitialSecuritySignatureRef.current = true;
      } else {
        for (const [nodeId, sig] of nextSignatureByNodeId.entries()) {
          const prevSig = securitySignatureByNodeIdRef.current.get(nodeId);
          if (prevSig !== sig) {
            // lastRawNodeByIdRef (not rawNodesData/state) holds the true
            // previous payload for this node, tracked via ref so it can't go
            // stale even though the polling interval closes over `fetchNodes`
            // from mount time.
            const prevNode = lastRawNodeByIdRef.current.get(nodeId);
            const prevProducts = Array.isArray(prevNode?.security_products) ? prevNode.security_products : [];
            const nextProducts = nextProductsByNodeId.get(nodeId) ?? [];

            const changes = diffSecurityProducts(prevProducts, nextProducts);
            if (changes.length > 0) {
              setPendingSecurityChangesByNodeId((prev) => ({
                ...prev,
                [nodeId]: { changes, detectedAt: Date.now() },
              }));
            }
          }
        }

        securitySignatureByNodeIdRef.current = nextSignatureByNodeId;
      }

      // Reuse the previous node object whenever nothing rendering-relevant
      // changed, so a poll tick only allocates a new object (and therefore
      // only re-renders the memoized row) for the device(s) that actually
      // changed — not the whole table.
      const nextRawNodeByIdMap = new Map<string, RawNode>();
      const preservedNodesArray = nodesArray.map((node) => {
        const nodeId = node?.id != null ? String(node.id) : node?.host_identifier != null ? String(node.host_identifier) : '';
        const prevNode = nodeId ? lastRawNodeByIdRef.current.get(nodeId) : undefined;
        const resolved = prevNode && areNodesEquivalent(prevNode, node) ? prevNode : node;
        if (nodeId) nextRawNodeByIdMap.set(nodeId, resolved);
        return resolved;
      });
      lastRawNodeByIdRef.current = nextRawNodeByIdMap;

      // ...and when nothing changed anywhere — by far the most common poll
      // outcome — reuse the previous array too, so `rawNodesData` keeps its
      // identity and React bails out of the update entirely.
      //
      // Preserving the element identities above is not sufficient on its own: a
      // freshly allocated wrapper array still changes `rawNodesData`'s identity
      // every POLL_NODES_INTERVAL_MS tick, re-rendering the whole page and
      // re-running the `nodesData` useMemo below plus every downstream
      // filter/sort/paginate memo across up to ~1000 devices.
      //
      // Reuse is safe: same length and every element reference-identical, so no
      // consumer can distinguish the two arrays. The three effects keyed on
      // `rawNodesData` (selected-device IPs, WiFi, compliance-latest) all guard
      // on "already fetched" before issuing a request, so running them less
      // often issues no different requests.
      if (isMountedRef.current) {
        setRawNodesData((prev) =>
          prev.length === preservedNodesArray.length &&
          prev.every((node, i) => node === preservedNodesArray[i])
            ? prev
            : preservedNodesArray,
        );
      }
      return true;
    } catch (err) {
      if (import.meta.env.DEV) {
        console.error("Error fetching nodes:", err);
      }
      if (isMountedRef.current) setError("Failed to load devices. Please try again.");
      return false;
    } finally {
      fetchNodesInFlightRef.current = false;
      if (isMountedRef.current) {
        setLoading(false);
        hasFetchedInitialNodesRef.current = true;
      }
    }
  };

  const [manualRefreshing, setManualRefreshing] = useState(false);

  const handleManualRefresh = async () => {
    if (manualRefreshing) return;
    setManualRefreshing(true);
    try {
      const ok = await fetchNodes();
      showToast(ok ? 'Devices refreshed' : 'Failed to refresh devices. Please try again.', ok ? 'success' : 'error');
    } finally {
      setManualRefreshing(false);
    }
  };

  const exportNodes = async () => {
    if (exportNodesInFlightRef.current) return;
    if (!isMountedRef.current) return;

    exportNodesInFlightRef.current = true;
    try {
      const response = await fetch(NODES_URLS.NODES_EXPORT, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        // Try to surface a meaningful backend error (JSON preferred).
        let backendMessage = '';
        try {
          const contentType = response.headers.get('content-type') || '';
          backendMessage = contentType.includes('application/json')
            ? (await response.json()).message
            : await response.text();
        } catch {
          backendMessage = '';
        }
        throw new Error(backendMessage ? `Failed to export nodes: ${backendMessage}` : `Failed to export nodes (HTTP ${response.status})`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const d = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      const filename = `nodes-export-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}.csv`;

      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      showToast('Devices exported successfully');
    } catch (err) {
      console.error('Error exporting devices:', err);
      showToast('Failed to export devices. Please try again.', 'error');
    } finally {
      exportNodesInFlightRef.current = false;
    }
  };

  const renameDevice = async (hostIdentifier: string, newName: string) => {
    try {
      const response = await fetchWithCsrf(NODES_URLS.RENAME, {
        method: "POST",
        credentials: "include",
        headers: csrfHeadersJson(),
        body: JSON.stringify({
          host_identifier: hostIdentifier,
          alias_name: newName
        }),
      });

      if (!response.ok) {
        throw new Error(`Error ${response.status}: Failed to rename device`);
      }

      await fetchNodes();
      showToast("Device renamed successfully");
    } catch (err) {
      console.error(err);
      showToast("Failed to rename device. Please try again.", "error");
    }
  };

  const requestMarkCritical = async (hostIdentifier: string, reason: string) => {
    const response = await fetchWithCsrf(NODES_URLS.CRITICAL, {
      method: "POST",
      credentials: "include",
      headers: csrfHeadersJson(),
      body: JSON.stringify({
        host_identifier: hostIdentifier,
        reason: reason
      }),
    });
    if (!response.ok) {
      throw new Error(`Error ${response.status}: Failed to mark device as critical`);
    }
  };

  const requestMarkNonCritical = async (hostIdentifier: string, reason: string) => {
    const response = await fetchWithCsrf(NODES_URLS.UNCRITICAL, {
      method: "POST",
      credentials: "include",
      headers: csrfHeadersJson(),
      body: JSON.stringify({
        host_identifier: hostIdentifier,
        reason: reason || ""
      }),
    });
    if (!response.ok) {
      throw new Error(`Error ${response.status}: Failed to mark device as non-critical`);
    }
  };

  const markNodeCritical = async (hostIdentifier: string, reason: string) => {
    try {
      await requestMarkCritical(hostIdentifier, reason);
      await fetchNodes();
      showToast("Device marked as critical successfully");
    } catch (err) {
      console.error(err);
      showToast("Failed to mark device as critical. Please try again.", "error");
    }
  };

  const markNodeNonCritical = async (hostIdentifier: string, reason: string) => {
    try {
      await requestMarkNonCritical(hostIdentifier, reason);
      await fetchNodes();
      showToast("Device marked as non-critical successfully");
    } catch (err) {
      console.error(err);
      showToast("Failed to mark device as non-critical. Please try again.", "error");
    }
  };

  const bulkMarkCritical = async (hostIdentifiers: string[], reason: string, mode: 'mark' | 'unmark') => {
    if (hostIdentifiers.length === 0) return;
    setBulkActionInFlight(true);
    try {
      const results = await Promise.allSettled(
        hostIdentifiers.map((hostId) =>
          mode === 'mark' ? requestMarkCritical(hostId, reason) : requestMarkNonCritical(hostId, reason)
        )
      );
      const failed = results.filter((r) => r.status === 'rejected').length;
      const succeeded = results.length - failed;
      await fetchNodes();
      if (failed === 0) {
        showToast(`${succeeded} device${succeeded === 1 ? '' : 's'} ${mode === 'mark' ? 'marked as critical' : 'marked as non-critical'}`);
      } else {
        showToast(`${succeeded} succeeded, ${failed} failed. Please try again for the failed devices.`, 'error');
      }
      setSelectedIds(new Set());
    } finally {
      setBulkActionInFlight(false);
    }
  };



  useEffect(() => {
    const fetchGroups = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}${API_PREFIX}/groups`, {
          method: 'GET',
          credentials: 'include'
        });
        if (res.ok) {
          const data = await res.json();
          if (data.success && data.groups) {
            setGroupsList(data.groups);
            const map: Record<string, string> = {};
            data.groups.forEach((g: DeviceGroup) => {
              map[g.groupId] = g.name;
            });
            setGroupsMap(map);
          }
        }
      } catch (err) {
        console.error('Failed to fetch groups', err);
      }
    };
    fetchGroups();
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      const insideButton = groupDropdownRef.current?.contains(target);
      const insidePanel = groupPanelRef.current?.contains(target);
      if (!insideButton && !insidePanel) {
        setIsGroupDropdownOpen(false);
      }
    };
    const handleGroupDropdownEsc = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsGroupDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleGroupDropdownEsc);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleGroupDropdownEsc);
    };
  }, []);

  // Keeps the portaled group-filter panel aligned to its trigger button —
  // needed since the panel is positioned via viewport coordinates (fixed),
  // not the button's normal DOM flow.
  useEffect(() => {
    if (!isGroupDropdownOpen) return;
    const updatePos = () => {
      const el = groupDropdownRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const PANEL_WIDTH = 224; // matches the panel's w-56
      const maxLeft = window.innerWidth - PANEL_WIDTH - 8;
      const left = Math.min(maxLeft, Math.max(8, rect.right - PANEL_WIDTH));
      setGroupDropdownPos({ top: rect.bottom + 4, left });
    };
    updatePos();
    window.addEventListener('scroll', updatePos, true);
    window.addEventListener('resize', updatePos);
    return () => {
      window.removeEventListener('scroll', updatePos, true);
      window.removeEventListener('resize', updatePos);
    };
  }, [isGroupDropdownOpen]);

  useEffect(() => {
    isMountedRef.current = true;

    const tick = async () => {
      if (!isMountedRef.current) return;
      // Skip while the tab is hidden: this refetches the full 1000-row node
      // list every 10s, and none of it is on screen. Online/offline state is
      // pushed over the live WebSocket regardless, so nothing is missed — and
      // the visibilitychange listener below refetches immediately on
      // foreground, before anything is rendered.
      if (document.hidden) return;
      await fetchNodes();
    };

    // Initial load + polling refresh.
    tick();
    const intervalId = window.setInterval(() => {
      tick().catch(() => undefined);
    }, POLL_NODES_INTERVAL_MS);

    const onVisibility = () => {
      if (!document.hidden) tick().catch(() => undefined);
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      isMountedRef.current = false;
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const handleThemeChange = (event: Event) => {
      const nextTheme = (event as CustomEvent<'light' | 'dark'>).detail;
      if (nextTheme === 'light' || nextTheme === 'dark') {
        setThemeMode(nextTheme);
        return;
      }
      setThemeMode(localStorage.getItem('dashboard-theme') === 'dark' ? 'dark' : 'light');
    };

    window.addEventListener('dashboard-theme-change', handleThemeChange);
    window.addEventListener('storage', handleThemeChange);
    return () => {
      window.removeEventListener('dashboard-theme-change', handleThemeChange);
      window.removeEventListener('storage', handleThemeChange);
    };
  }, []);

  const acknowledgeSecurityChange = useCallback((nodeId: string) => {
    setPendingSecurityChangesByNodeId((prev) => {
      if (!(nodeId in prev)) return prev;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { [nodeId]: _removed, ...rest } = prev;
      return rest;
    });
  }, []);

  // Device drawer <-> URL sync
  // Keeps `?device=<id>&deviceTab=<tab>` in the URL so a refresh (or a shared
  // link) restores which device's drawer was open and which internal tab was
  // active. The device list loads asynchronously, so the initial restore
  // waits for the first fetch to finish before looking the id up; if it's
  // not found (stale link, device deleted, wrong org) it silently no-ops
  // instead of opening an empty/broken drawer.
  const initialUrlDeviceIdRef = useRef<string | null>(searchParams.get('device'));
  const initialUrlDeviceTabRef = useRef<string | null>(searchParams.get('deviceTab'));
  const hasAppliedUrlDeviceRef = useRef(false);

  const openDeviceDrawer = useCallback((id: string, tab: 'overview' | 'ips' | 'wifi' = 'overview') => {
    setSelectedDevice(id);
    setActiveTab(tab);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('device', id);
      next.set('deviceTab', tab);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const closeDeviceDrawer = useCallback(() => {
    setSelectedDevice(null);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('device');
      next.delete('deviceTab');
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const changeDeviceTab = useCallback((tab: 'overview' | 'ips' | 'wifi') => {
    setActiveTab(tab);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('deviceTab', tab);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Traps Tab/Shift+Tab inside the device details drawer and restores focus
  // to the row/button that opened it on close.
  const deviceDrawerRef = useModalA11y<HTMLDivElement>(!!selectedDevice, closeDeviceDrawer);

  // Fetch IPs when device modal is opened
  useEffect(() => {
    let cancelled = false;
    const fetchIPsForDevice = async () => {
      if (!selectedDevice) return;

      if (deviceIPs[selectedDevice]) return;

      try {
        setLoadingIPs(true);
        const device = rawNodesData.find(d => d.id === selectedDevice);
        if (device) {
          const hostIdentifier = device.host_identifier || device.id;
          const interfaces = await fetchNodeIPs(hostIdentifier);
          if (cancelled) return;
          setDeviceIPs(prev => ({ ...prev, [selectedDevice]: interfaces }));
        }
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error('Error fetching IPs for selected device:', err);
        }
      } finally {
        if (!cancelled) setLoadingIPs(false);
      }
    };

    fetchIPsForDevice();
    return () => { cancelled = true; };
  }, [selectedDevice, rawNodesData, deviceIPs]);


  // Helper function to format timestamp to readable date
  const formatDate = (timestamp: string | number) => {
    return formatUnixTimestamp(timestamp);
  };

  const parseCompliancePass = (key: string, output: string): boolean => {
    const v = String(output).trim().toLowerCase();

    // Key 18: numeric output (password length). >0 is pass.
    if (key === '18') {
      const n = parseInt(v, 10);
      return !isNaN(n) && n > 0;
    }

    let rawBool: boolean;
    if (v === 'true' || v === 'pass' || v === 'passed' || v === '1') {
      rawBool = true;
    } else if (v === 'false' || v === 'fail' || v === 'failed' || v === '0') {
      rawBool = false;
    } else {
      return false;
    }

    // Key 2 is inverted in the Windows agent compliance output.
    return key === '2' ? !rawBool : rawBool;
  };

  const calcCompliancePercent = (rows: Array<{ command_key: string; output: string }>): number => {
    if (!Array.isArray(rows) || rows.length === 0) return 0;
    const passCount = rows.filter((r) => parseCompliancePass(String(r.command_key), String(r.output))).length;
    return Math.round((passCount / rows.length) * 100);
  };

  // Map raw node data to display format. Cached per-node (keyed on the raw
  // node object reference) so a poll tick that only changed one device
  // doesn't allocate a brand-new derived object for every other device —
  // those keep their previous reference, letting the memoized table
  // row/card for that device skip re-rendering entirely.
  const derivedNodeCacheRef = useRef<Map<string, { rawNode: RawNode; groupsMap: typeof groupsMap; nodeStatus: typeof nodeStatus; derived: Device }>>(new Map());

  const nodesData = useMemo(() => {
    const prevCache = derivedNodeCacheRef.current;
    const nextCache = new Map<string, { rawNode: RawNode; groupsMap: typeof groupsMap; nodeStatus: typeof nodeStatus; derived: Device }>();

    // `onlineNodeHostIdentifier` and `agentOnline` are fleet-length arrays, and
    // `displayStatus` below needs a membership test on each of them per node.
    // As `.includes()` that is an O(nodes x fleet) scan inside the map — around
    // 2M string comparisons at the NODE_LIST_FETCH_CAP of 1000 devices — and it
    // runs far more often than the poll, because the per-node cache below keys
    // on `cached.nodeStatus === nodeStatus`, so any nodeStatus identity change
    // misses for every node. The backend rebroadcasts the live snapshot
    // whenever the online set changes, i.e. whenever one host crosses the 10s
    // last_seen threshold. Sets make each lookup O(1) and the pass
    // O(nodes + fleet), with identical results — `Set.has` and
    // `Array.includes` agree on the same string elements.
    const onlineHostIds = new Set(nodeStatus?.onlineNodeHostIdentifier ?? []);
    const agentOnlineHostIds = new Set(nodeStatus?.agentOnline ?? []);

    const result = rawNodesData.map((node) => {
      const nodeId = node?.id != null ? String(node.id) : node?.host_identifier != null ? String(node.host_identifier) : '';
      const cached = nodeId ? prevCache.get(nodeId) : undefined;
      if (cached && cached.rawNode === node && cached.groupsMap === groupsMap && cached.nodeStatus === nodeStatus) {
        if (nodeId) nextCache.set(nodeId, cached);
        return cached.derived;
      }

      const derived: Device = {
        ...node,
        name: node.hostname || 'Unknown',
        os: node.os_name || node.os_platform || 'Unknown',
        type: node.os_platform === 'windows' ? 'Desktop' : node.os_platform === 'darwin' ? 'Mac' : 'Server',
        ip: node.address || '0.0.0.0',
        agent: node.osquery_version || 'N/A',
        lastSeen: formatDate(node.last_seen ?? ''),
        enrolledDate: formatDate(node.enrolled_on ?? ''),
        groupNames: Array.isArray(node.group_ids)
          ? (node.group_ids.length > 0 ? node.group_ids.map((id: string) => groupsMap[id] || id).join(', ') : '-')
          : '-',
        groupIds: Array.isArray(node.group_ids) ? node.group_ids : [],
        hygieneScore: node.agent_online ? 85 : 45,
        // Three-state status derived from both live-WS signals:
        //   'Online'  — osquery heartbeating AND extension connected  (green)
        //   'Active'  — osquery heartbeating but extension not connected (yellow)
        //   'Offline' — osquery not heartbeating                      (grey)
        //
        // onlineNodeHostIdentifier is the outer gate (last_seen < 10s threshold).
        // agentOnline is the inner discriminator (agent_online DB flag, set by
        // the /ws/ext extension WebSocket connect/disconnect events).
        //
        // When nodeStatus is null (live WS not yet connected) fall back to the
        // API-fetched status field (SQL CASE on last_seen) plus agent_online.
        displayStatus: nodeStatus != null
          ? (onlineHostIds.has(node.host_identifier)
            ? (agentOnlineHostIds.has(node.host_identifier) ? 'Online' : 'Active')
            : 'Offline')
          : (node.status === 'Online'
            ? (node.agent_online ? 'Online' : 'Active')
            : 'Offline'),
        // Additional properties for modal
        mac: '00:00:00:00:00:00',
        firewallStatus: 'Active',
        antivirusStatus: 'Active',
        diskEncryption: 'Enabled',
        patchStatus: 'Up to date',
        vulnerabilities: 0,
        applications: 0,
      };

      if (nodeId) nextCache.set(nodeId, { rawNode: node, groupsMap, nodeStatus, derived });
      return derived;
    });

    derivedNodeCacheRef.current = nextCache;
    return result;
  }, [rawNodesData, groupsMap, nodeStatus]);

  // Restore the drawer from the URL once the device list has loaded (or
  // gracefully no-op if the referenced device never loads / doesn't exist
  // for this user). Runs at most once.
  useEffect(() => {
    if (hasAppliedUrlDeviceRef.current) return;
    if (!initialUrlDeviceIdRef.current) {
      hasAppliedUrlDeviceRef.current = true;
      return;
    }
    if (loading) return; // wait for the initial nodes fetch to complete

    hasAppliedUrlDeviceRef.current = true;

    const targetId = initialUrlDeviceIdRef.current;
    const device = nodesData.find((d) => d.id === targetId);
    if (!device) return; // unknown/stale device id — leave the drawer closed

    const tabParam = initialUrlDeviceTabRef.current;
    const tab: 'overview' | 'ips' | 'wifi' = tabParam === 'ips' || tabParam === 'wifi' ? tabParam : 'overview';
    setSelectedDevice(device.id);
    setActiveTab(tab);
  }, [loading, nodesData]);

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-amber-600';
    return 'text-red-700';
  };

  const getScoreMeta = (score: number) => {
    if (score >= 90) {
      return {
        tone: 'Excellent posture',
        accent: 'from-emerald-500 to-teal-500',
        surface: 'from-emerald-50 to-teal-50',
        border: 'border-emerald-100',
        badge: 'bg-emerald-100 text-emerald-700',
      };
    }

    if (score >= 70) {
      return {
        tone: 'Needs attention',
        accent: 'from-amber-500 to-orange-500',
        surface: 'from-amber-50 to-orange-50',
        border: 'border-amber-100',
        badge: 'bg-amber-100 text-amber-700',
      };
    }

    return {
      tone: 'High risk posture',
      accent: 'from-red-500 to-rose-600',
      surface: 'from-red-50 to-rose-50',
      border: 'border-red-100',
      badge: 'bg-red-100 text-red-700',
    };
  };

  // Shown whenever there's no real compliance scan result yet — deliberately
  // neutral so an unscanned device never gets a "good" or "bad" colored card
  // just because its agent happens to be online (see hygieneScore below).
  const NOT_SCANNED_SCORE_META = {
    tone: 'Not yet scanned',
    accent: 'from-slate-400 to-slate-500',
    surface: 'from-slate-50 to-slate-100',
    border: 'border-slate-200',
    badge: 'bg-slate-100 text-slate-600',
  };



  const getSecurityProductStatus = (products: { name: string; state: string }[] | undefined, productName: string): string => {
    if (!products || !Array.isArray(products)) return 'N/A';
    const product = products.find((p) => (p.name || '').toLowerCase().includes(productName.toLowerCase()));
    return product ? product.state : 'N/A';
  };

  /** Renders the Windows security-product pills, or the Linux ClamAV/Firewall pills, for a device row/card. */
  const renderSecurityTools = useCallback((device: Device, isWindowsDevice: boolean, isExtConnected: boolean): ReactNode => {
    if (device.security_products && device.security_products.length > 0) {
      return device.security_products.map((product: SecurityProduct, pIdx: number) => {
        const originalName = product.name || '';
        let displayName = originalName;
        if (originalName.toLowerCase().includes('microsoft defender antivirus')) {
          displayName = 'Defender AV';
        } else if (originalName.toLowerCase().includes('windows firewall')) {
          displayName = 'Firewall';
        }
        const isActive = product.state?.toLowerCase() === 'on';
        const stateTitle = `${displayName} is ${isActive ? 'active' : 'not active'}`;
        return (
          <span
            key={pIdx}
            title={stateTitle}
            aria-label={stateTitle}
            className={`inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border shadow-sm ${isActive ? 'bg-green-100 text-green-800 border-green-200' : 'bg-blue-50 text-blue-900 border-blue-200'
              }`}
          >
            {displayName}
          </span>
        );
      });
    }

    if (isWindowsDevice) {
      return (
        <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border border-slate-200 bg-slate-100 text-slate-700 shadow-sm">
          N/A
        </span>
      );
    }

    const clamavEntry = clamavSummaryByHost[String(device.host_identifier || '')];
    const daemon = clamavEntry?.daemonRunning ?? null;
    let clamCls: string; let clamTitle: string;
    if (daemon === false) {
      clamCls = 'bg-red-100 text-red-800 border-red-200';
      clamTitle = 'clamd is not running on this host';
    } else if (daemon === true) {
      clamCls = 'bg-green-100 text-green-800 border-green-200';
      clamTitle = `ClamAV active${clamavEntry?.dbVersion ? ` (signatures v${clamavEntry.dbVersion}${clamavEntry?.dbDate ? `, ${clamavEntry.dbDate}` : ''})` : ''}`;
    } else if (!isExtConnected) {
      clamCls = 'bg-slate-100 text-slate-700 border-slate-200';
      clamTitle = 'Agent offline — ClamAV status unavailable';
    } else {
      clamCls = 'bg-slate-100 text-slate-700 border-slate-200';
      clamTitle = 'No ClamAV status reported by the agent yet';
    }

    const fwEntry = firewallSummaryByHost[String(device.host_identifier || '')];
    let fwCls: string; let fwTitle: string;
    if (fwEntry?.active === true) {
      fwCls = 'bg-green-100 text-green-800 border-green-200';
      fwTitle = `${fwEntry.manager} active${fwEntry.enabled_on_boot ? ' (boot-persistent)' : ''}`;
    } else if (fwEntry?.active === false) {
      fwCls = 'bg-red-100 text-red-800 border-red-200';
      fwTitle = `${fwEntry.manager} inactive`;
    } else if (!isExtConnected) {
      fwCls = 'bg-slate-100 text-slate-700 border-slate-200';
      fwTitle = 'Agent offline — firewall status unavailable';
    } else {
      fwCls = 'bg-slate-100 text-slate-700 border-slate-200';
      fwTitle = 'No firewall status reported yet';
    }

    return (
      <>
        <Link
          to={`/nodes/view/${encodeURIComponent(String(device.host_identifier || ''))}?tab=responsive-actions&subtab=clamav-control`}
          onClick={(e) => e.stopPropagation()}
          title={clamTitle}
          aria-label={clamTitle}
          className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border shadow-sm hover:opacity-80 ${clamCls}`}
        >
          ClamAV
        </Link>
        <Link
          to={`/nodes/view/${encodeURIComponent(String(device.host_identifier || ''))}?tab=responsive-actions&subtab=firewall-status`}
          onClick={(e) => e.stopPropagation()}
          title={fwTitle}
          aria-label={fwTitle}
          className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border shadow-sm hover:opacity-80 ${fwCls}`}
        >
          Firewall
        </Link>
      </>
    );
  }, [clamavSummaryByHost, firewallSummaryByHost]);

  // Filter and sort devices
  const filteredAndSortedDevices = useMemo(() => {
    const filtered = nodesData.filter(device => {
      const matchesSearch =
        device.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        device.ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        device.os?.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesStatus =
        filterStatus === 'all'
          ? true
          : filterStatus === 'online'
            // Online bucket = both fully-online (green) AND active-no-extension (yellow)
            // because both have a live osquery heartbeat — matches nodeStatus.online count.
            ? (device.displayStatus === 'Online' || device.displayStatus === 'Active')
            : device.displayStatus === 'Offline';
      const matchesRisk =
        filterRisk === 'all'
          ? true
          : filterRisk === 'isolated'
            ? device.isolated === true
            : device.critical === true;
      const platform = String(device.os_platform || device.os || '').toLowerCase();
      const isWindows = platform.includes('windows');
      const isMac = platform.includes('darwin') || platform.includes('mac') || platform.includes('os x') || platform.includes('osx');
      const isLinux =
        platform.includes('linux') ||
        platform.includes('ubuntu') ||
        platform.includes('debian') ||
        platform.includes('fedora') ||
        platform.includes('centos') ||
        platform.includes('rhel') ||
        platform.includes('red hat') ||
        platform.includes('redhat') ||
        platform.includes('amazon linux') ||
        platform.includes('amzn') ||
        platform.includes('arch') ||
        platform.includes('suse') ||
        platform.includes('opensuse') ||
        platform.includes('mint') ||
        platform.includes('kali') ||
        (!isWindows && !isMac);
      const matchesOs =
        filterOs === 'all'
          ? true
          : filterOs === 'windows'
            ? isWindows
            : filterOs === 'macos'
              ? isMac
              : isLinux;
      const matchesGroup =
        filterGroup.length === 0
          ? true
          : Array.isArray(device.groupIds) && device.groupIds.some((id: string) => filterGroup.includes(id));

      return matchesSearch && matchesStatus && matchesRisk && matchesOs && matchesGroup;
    });

    const parseLastSeen = (v: unknown): number => {
      if (typeof v === 'number' && Number.isFinite(v)) return v;
      const n = parseInt(String(v ?? ''), 10);
      return Number.isFinite(n) ? n : 0;
    };

    // Deterministic ordering to prevent reshuffle across polling:
    // 1) Critical first
    // 2) Isolated first
    // 3) Online first, Offline last
    // 4) Online: alphabetic by `name`
    // 5) Offline: by `last_seen` (most recent first)
    // 6) Tie-breakers: `host_identifier`, then `id`
    return filtered.sort((a, b) => {
      const criticalA = a.critical === true;
      const criticalB = b.critical === true;
      if (criticalA !== criticalB) {
        return criticalA ? -1 : 1;
      }

      const isolatedA = a.isolated === true;
      const isolatedB = b.isolated === true;
      if (isolatedA !== isolatedB) {
        return isolatedA ? -1 : 1;
      }

      const statusRank = (s: string | null | undefined): number => {
        if (s === 'Online') return 0;
        if (s === 'Active') return 1;
        return 2; // Offline
      };

      const rankA = statusRank(a.displayStatus);
      const rankB = statusRank(b.displayStatus);

      if (rankA !== rankB) return rankA - rankB;

      if (rankA <= 1) {
        const nameA = String(a.name ?? '');
        const nameB = String(b.name ?? '');
        const byName = nameA.localeCompare(nameB, undefined, { sensitivity: 'base' });
        if (byName !== 0) return byName;
      } else {
        const lastA = parseLastSeen(a.last_seen);
        const lastB = parseLastSeen(b.last_seen);
        const byLastSeen = lastB - lastA; // descending
        if (byLastSeen !== 0) return byLastSeen;
      }

      const hostA = String(a.host_identifier ?? '');
      const hostB = String(b.host_identifier ?? '');
      const byHost = hostA.localeCompare(hostB, undefined, { sensitivity: 'base' });
      if (byHost !== 0) return byHost;

      const idA = parseLastSeen(a.id);
      const idB = parseLastSeen(b.id);
      return idA - idB;
    });
  }, [nodesData, searchQuery, filterStatus, filterRisk, filterOs, filterGroup]);

  const tableTotalPages = Math.max(1, Math.ceil(filteredAndSortedDevices.length / tablePageSize));

  const paginatedTableDevices = useMemo(() => {
    const start = (tablePage - 1) * tablePageSize;
    return filteredAndSortedDevices.slice(start, start + tablePageSize);
  }, [filteredAndSortedDevices, tablePage, tablePageSize]);

  useEffect(() => {
    setTablePage(1);
  }, [searchQuery, filterStatus, filterRisk, filterOs, filterGroup, tablePageSize]);

  useEffect(() => {
    setTablePage((prev) => Math.min(Math.max(prev, 1), tableTotalPages));
  }, [tableTotalPages]);

  const activeFilterCount = [filterStatus !== 'all', filterRisk !== 'all', filterOs !== 'all', filterGroup.length > 0].filter(Boolean).length;
  const hasActiveFilters = activeFilterCount > 0 || searchQuery.trim().length > 0;
  const clearAllFilters = () => {
    setSearchQuery('');
    setFilterStatus('all');
    setFilterRisk('all');
    setFilterOs('all');
    setFilterGroup([]);
  };

  const pageDeviceIds = useMemo(() => paginatedTableDevices.map((d) => String(d.id)), [paginatedTableDevices]);
  const allOnPageSelected = pageDeviceIds.length > 0 && pageDeviceIds.every((id) => selectedIds.has(id));
  const someOnPageSelected = pageDeviceIds.some((id) => selectedIds.has(id));

  const toggleSelectAllOnPage = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        pageDeviceIds.forEach((id) => next.delete(id));
      } else {
        pageDeviceIds.forEach((id) => next.add(id));
      }
      return next;
    });
  };

  const toggleSelectDevice = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAllFiltered = () => setSelectedIds(new Set(filteredAndSortedDevices.map((d) => String(d.id))));
  const clearSelection = () => setSelectedIds(new Set());

  const selectedDevicesData = useMemo(
    () => filteredAndSortedDevices.filter((d) => selectedIds.has(String(d.id))),
    [filteredAndSortedDevices, selectedIds]
  );

  const exportSelectedDevices = () => {
    if (selectedDevicesData.length === 0) return;
    const headers = ['Name', 'Host Identifier', 'OS', 'IP Address', 'Status', 'Group', 'Last Seen', 'Enrolled', 'Critical', 'Isolated'];
    const escapeCsv = (v: unknown) => {
      let str = String(v ?? '');
      // Prevent CSV/formula injection: device fields (name, group) can be
      // attacker-influenced and would otherwise be executed as formulas by
      // Excel/Sheets if opened with a leading =, +, -, or @.
      if (/^[=+\-@]/.test(str)) str = "'" + str;
      return `"${str.replace(/"/g, '""')}"`;
    };
    const rows = selectedDevicesData.map((d) =>
      [d.name, d.host_identifier, d.os, d.ip, d.displayStatus, d.groupNames, d.lastSeen, d.enrolledDate, d.critical ? 'Yes' : 'No', d.isolated ? 'Yes' : 'No']
        .map(escapeCsv)
        .join(',')
    );
    const csv = [headers.map(escapeCsv).join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const a = document.createElement('a');
    a.href = url;
    a.download = `devices-selected-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast(`Exported ${selectedDevicesData.length} device${selectedDevicesData.length === 1 ? '' : 's'}`);
  };

  const openBulkCriticalDialog = (mode: 'mark' | 'unmark') => {
    setCriticalBulkMode(true);
    setCriticalModalMode(mode);
    setCriticalReason('');
    setCriticalOpen(true);
  };

  const handleRenameFromMenu = useCallback((device: Device) => {
    setSelectedHost(device.host_identifier);
    setNewName(device.name);
    setRenameOpen(true);
  }, []);

  const handleToggleCriticalFromMenu = useCallback((device: Device) => {
    setCriticalBulkMode(false);
    setCriticalNodeId(device.host_identifier);
    setCriticalReason('');
    setCriticalModalMode(device.critical ? 'unmark' : 'mark');
    setCriticalOpen(true);
  }, []);

  const selectedDeviceData = useMemo(
    () => nodesData.find(d => d.id === selectedDevice) || null,
    [nodesData, selectedDevice]
  );

  const selectedDevicePrimaryIP = selectedDevice
    ? deviceIPs[selectedDevice]?.find(iface => iface.priority === 1)?.address || selectedDeviceData?.ip || 'N/A'
    : 'N/A';

  const selectedDefenderStatus = getSecurityProductStatus(selectedDeviceData?.security_products, 'defender');
  const selectedFirewallStatus = getSecurityProductStatus(selectedDeviceData?.security_products, 'firewall');
  const selectedComplianceHostId = selectedDeviceData
    ? String(selectedDeviceData.host_identifier || selectedDeviceData.id || '')
    : '';
  const selectedIsWindowsForCompliance = selectedDeviceData
    ? String(selectedDeviceData.os_platform || '').toLowerCase().includes('windows')
    : false;
  // Treat missing entries as `null` in the modal so the UI can still offer "Run compliance".
  // The modal is still allowed to optimistically show the CTA while the backend fetch is in flight.
  const selectedComplianceObj =
    selectedIsWindowsForCompliance && selectedComplianceHostId
      ? complianceLatestByHost[selectedComplianceHostId] ?? null
      : null;
  const selectedCompliancePercent: number | null =
    selectedComplianceObj && typeof selectedComplianceObj === 'object'
      ? selectedComplianceObj.percent ?? null
      : null;
  const selectedScoreMeta = selectedDeviceData
    ? (selectedCompliancePercent != null ? getScoreMeta(selectedCompliancePercent) : NOT_SCANNED_SCORE_META)
    : null;

// Fetch latest compliance result per Windows host (used by the Box View widget and Modal)
  useEffect(() => {
    const fetchComplianceLatest = async () => {
      // Only check the selected modal device to prevent fetching beforehand
      const visibleDevices = [];
      if (selectedDeviceData) {
        visibleDevices.push(selectedDeviceData);
      }

      const windowsHosts = Array.from(
        new Set(
          visibleDevices
            .filter((n) => String(n?.os_platform || n?.os || '').toLowerCase().includes('windows'))
            .map((n) => String(n?.host_identifier || n?.id || '').trim())
            .filter(Boolean),
        ),
      );
      const hostsToFetch = windowsHosts.filter((host) => !(host in complianceLatestByHost));
      if (hostsToFetch.length === 0) return;

      const results = await Promise.allSettled(
        hostsToFetch.map(async (hostId) => {
          const res = await fetch(`${NODES_URLS.COMPLIANCE_LATEST}${encodeURIComponent(hostId)}`, {
            credentials: 'include',
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = await res.json();
          const rec = json?.success ? json?.data : null;

          if (!rec || !Array.isArray(rec?.compliance_data)) return { hostId, value: null };

          const percent = calcCompliancePercent(rec.compliance_data);
          const unixtime = Number(rec.unixtime) || 0;
          return { hostId, value: { percent, unixtime } };
        }),
      );

      setComplianceLatestByHost((prev) => {
        const next = { ...prev };
        for (const r of results) {
          if (r.status !== 'fulfilled') continue;
          next[r.value.hostId] = r.value.value;
        }
        return next;
      });
    };

    fetchComplianceLatest().catch((err) => {
      if (import.meta.env.DEV) console.warn('Compliance latest fetch failed:', err);
    });
    // Intentionally keyed to rawNodesData to avoid refetch loops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawNodesData, selectedDevice]);

  useEffect(() => {
    if (!selectedDevice) return;
    setActiveTab('overview');
  }, [selectedDevice]);

  // Fetch WiFi snapshot when device modal is opened
  useEffect(() => {
    let cancelled = false;
    const fetchWifiForDevice = async () => {
      if (!selectedDevice) return;
      const device = rawNodesData.find(d => d.id === selectedDevice);
      if (!device) return;
      const hostIdentifier = device.host_identifier || device.id;
      if (deviceWifi[hostIdentifier] !== undefined) return; // already fetched
      setLoadingWifi(true);
      const data = await fetchNodeWifi(String(hostIdentifier));
      if (cancelled) return;
      setDeviceWifi(prev => ({ ...prev, [hostIdentifier]: data }));
      setLoadingWifi(false);
    };
    fetchWifiForDevice();
    return () => { cancelled = true; };
  }, [selectedDevice, rawNodesData, deviceWifi]);

  useEffect(() => {
    if (!selectedDevice) return;

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeDeviceDrawer();
      }
    };

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleEsc);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleEsc);
    };
  }, [selectedDevice, closeDeviceDrawer]);
  // agentConnectedIds: nodes where the browser extension WS is connected —
  // used to disambiguate ClamAV/firewall "unknown" vs "offline" in the security-tools pills.
  const agentConnectedIds = useMemo(
    () => new Set(liveData?.nodeStatus?.agentOnline || []),
    [liveData]
  );

  return (

    <div className={`my-devices-page flex max-h-[calc(100vh-4rem)] flex-col overflow-hidden bg-[#f8f9fb] md:max-h-screen ${isDarkMode ? 'my-devices-dark' : 'my-devices-light'}`}>
      <style dangerouslySetInnerHTML={{ __html: CRITICAL_CSS }} />

      <div className="mx-auto flex min-h-0 w-full max-w-[100%] flex-1 flex-col px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">

        <motion.section
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08 }}
          className="mb-4 shrink-0 space-y-5"
        >
          {/* Page Header — same gradient + Meteors treatment used across the dashboard */}
          <div
            className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 text-white"
            style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
          >
            <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
            <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div className="min-w-0 shrink-0">
                <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                  <DevicesHeroIcon className="w-6 h-6 mr-2" />
                  My Devices
                </h1>
                <p className="mt-1 text-sm text-blue-100">
                  Monitor and manage devices detected by Vajra Agent
                </p>
                <LiveConnectionBadge className="mt-2" label="Live device status offline" />
              </div>

              {/* Search + filters + actions — all inline with the title on wide screens */}
              <div className="flex flex-1 flex-col gap-2.5 sm:flex-row sm:flex-wrap sm:items-center lg:justify-end">
                <div className="group relative w-full sm:max-w-xs sm:flex-1 lg:flex-none lg:w-56">
                  <svg
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/70 transition-colors group-focus-within:text-white"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>

                  <input
                    type="text"
                    placeholder="Search devices or OS"
                    value={searchQuery}
                    onChange={(e) =>
                      setSearchQuery(sanitizeAsciiSingleLine(e.target.value, 200, false))
                    }
                    className="h-10 w-full rounded-xl border border-white/20 bg-white/10 pl-10 pr-3 text-sm text-white placeholder-blue-200 outline-none backdrop-blur-sm transition focus:border-white/40 focus:bg-white/20 focus:ring-2 focus:ring-white/20"
                  />
                </div>

                <Select
                  value={filterOs}
                  onValueChange={(value) => setFilterOs(value as 'all' | 'windows' | 'linux'| 'macos')}
                >
                  <SelectTrigger
                    size="sm"
                    className="h-10 min-w-[130px] border-white/20 bg-white/10 text-white backdrop-blur-sm hover:border-white/40 focus:border-white/40 focus:ring-white/20 data-[popup-open]:border-white/40 data-[popup-open]:ring-white/20 [&_svg]:text-blue-200"
                  >
                    <SelectValue placeholder="All OS">
                      {(value: string) =>
                        value === 'windows' ? 'Windows' : value === 'linux' ? 'Linux' : value === 'macos' ? 'Mac' : 'All OS'
                      }
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All OS</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="macos">Mac</SelectItem>
                  </SelectContent>
                </Select>

                <div className="relative" ref={groupDropdownRef}>
                  <button
                    type="button"
                    onClick={() => setIsGroupDropdownOpen(!isGroupDropdownOpen)}
                    aria-haspopup="true"
                    aria-expanded={isGroupDropdownOpen}
                    className="flex h-10 min-w-[140px] items-center justify-between rounded-xl border border-white/20 bg-white/10 px-3 text-sm font-semibold text-white shadow-sm outline-none backdrop-blur-sm transition hover:border-white/40 focus:border-white/40 focus:ring-2 focus:ring-white/20"
                  >
                    <span className="truncate max-w-[120px]">
                      {filterGroup.length === 0 ? 'All Groups' : `${filterGroup.length} Selected`}
                    </span>
                    <svg className="w-4 h-4 ml-2 flex-shrink-0 text-blue-200" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path></svg>
                  </button>
                  {isGroupDropdownOpen && groupDropdownPos && createPortal(
                    <div
                      ref={groupPanelRef}
                      className="fixed z-[999] w-56 rounded-lg border shadow-lg bg-white border-slate-200"
                      style={{ top: groupDropdownPos.top, left: groupDropdownPos.left }}
                    >
                      <div className="max-h-60 overflow-y-auto p-2 flex flex-col gap-1">
                        <label className="flex items-center gap-2 px-3 py-1 cursor-pointer rounded hover:bg-slate-50 transition-colors">
                          <Checkbox
                            size="small"
                            checked={filterGroup.length === 0}
                            onChange={() => setFilterGroup([])}
                            sx={{ padding: '4px', '&.Mui-checked': { color: '#2563eb' } }}
                          />
                          <span className="text-sm font-medium text-slate-700">All Groups</span>
                        </label>
                        {groupsList.map(g => (
                          <label key={g.groupId} className="flex items-center gap-2 px-3 py-1 cursor-pointer rounded hover:bg-slate-50 transition-colors">
                            <Checkbox
                              size="small"
                              checked={filterGroup.includes(g.groupId)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setFilterGroup(prev => [...prev, g.groupId]);
                                } else {
                                  setFilterGroup(prev => prev.filter(id => id !== g.groupId));
                                }
                              }}
                              sx={{ padding: '4px', '&.Mui-checked': { color: '#2563eb' } }}
                            />
                            <span className="text-sm font-medium truncate text-slate-700">{g.name}</span>
                          </label>
                        ))}
                      </div>
                    </div>,
                    document.body
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={exportNodes}
                    className="inline-flex h-10 items-center gap-1.5 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
                  >
                    <BrowserUpdatedIcon sx={{ fontSize: 18 }} /> Export
                  </button>

                  <button
                    type="button"
                    onClick={handleManualRefresh}
                    disabled={manualRefreshing}
                    className="inline-flex h-10 items-center gap-1.5 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <RefreshIcon sx={{ fontSize: 18 }} className={manualRefreshing ? 'animate-spin' : undefined} /> Refresh
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Bulk selection action bar */}
          <AnimatePresence>
            {selectedIds.size > 0 && (
              <motion.div
                initial={{ opacity: 0, y: -8, height: 0 }}
                animate={{ opacity: 1, y: 0, height: 'auto' }}
                exit={{ opacity: 0, y: -8, height: 0 }}
                transition={{ duration: 0.18 }}
                className="overflow-hidden"
              >
                <div className="flex flex-wrap items-center gap-3 rounded-xl border border-blue-200 bg-blue-50 px-4 py-2.5">
                  <span className="text-sm font-semibold text-blue-900">
                    {selectedIds.size.toLocaleString()} selected
                  </span>
                  {allOnPageSelected && selectedIds.size < filteredAndSortedDevices.length && (
                    <button type="button" onClick={selectAllFiltered} className="rounded-lg text-sm font-medium text-blue-700 underline-offset-2 hover:underline">
                      Select all {filteredAndSortedDevices.length.toLocaleString()} matching devices
                    </button>
                  )}
                  <div className="ml-auto flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={bulkActionInFlight}
                      onClick={() => openBulkCriticalDialog('mark')}
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-purple-200 bg-white px-2.5 text-xs font-semibold text-purple-700 transition hover:bg-purple-50 disabled:opacity-50"
                    >
                      <StarIcon sx={{ fontSize: 14 }} /> Mark Critical
                    </button>
                    <button
                      type="button"
                      disabled={bulkActionInFlight}
                      onClick={() => openBulkCriticalDialog('unmark')}
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
                    >
                      <StarBorderIcon sx={{ fontSize: 14 }} /> Mark Non-Critical
                    </button>
                    <button
                      type="button"
                      onClick={exportSelectedDevices}
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
                    >
                      <BrowserUpdatedIcon sx={{ fontSize: 14 }} /> Export Selected
                    </button>
                    <button
                      type="button"
                      onClick={clearSelection}
                      className="inline-flex h-8 items-center gap-1 rounded-md px-2 text-xs font-semibold text-slate-500 transition hover:text-slate-800"
                    >
                      <CloseIcon sx={{ fontSize: 14 }} /> Clear
                    </button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
<div>
  <div className="flex gap-3 overflow-x-auto pb-2 pt-3 mb-4 snap-x snap-mandatory sm:grid sm:grid-cols-3 sm:gap-4 sm:overflow-visible sm:pb-0 lg:grid-cols-5 lg:gap-6">

    <motion.div
      role="button"
      tabIndex={0}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      onClick={() => { setFilterStatus('all'); setFilterRisk('all'); }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') { setFilterStatus('all'); setFilterRisk('all'); }
      }}
      className={`bg-white min-w-[150px] snap-center rounded-xl p-4 shadow border-b-2 border-b-blue-500 flex-shrink-0 sm:min-w-0 sm:flex-shrink sm:p-5 lg:p-6 lg:shadow-lg hover:shadow-xl transition-shadow cursor-pointer ${filterStatus === 'all' && filterRisk === 'all' ? 'ring-2 ring-blue-200 shadow-xl' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-gray-500">Total Devices</p>
            {filterStatus === 'all' && filterRisk === 'all' && (
              <span className="text-[10px] font-semibold text-blue-700 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5">
                Selected
              </span>
            )}
          </div>
          <p className="text-3xl font-bold text-blue-500">
            {nodeStatus?.total ?? 0}
          </p>
        </div>
        <div className="w-12 h-12 rounded-lg flex items-center justify-center">
          <DevicesIcon sx={{ fontSize: 26, color: '#3b82f6' }} />
        </div>
      </div>
    </motion.div>

    <motion.div
      role="button"
      tabIndex={0}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      onClick={() => setFilterStatus((prev) => (prev === 'online' ? 'all' : 'online'))}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          setFilterStatus((prev) => (prev === 'online' ? 'all' : 'online'));
        }
      }}
      className={`bg-white min-w-[150px] snap-center rounded-xl p-4 shadow border-b-2 border-b-green-500 flex-shrink-0 sm:min-w-0 sm:flex-shrink sm:p-5 lg:p-6 lg:shadow-lg hover:shadow-xl transition-shadow cursor-pointer ${filterStatus === 'online' ? 'ring-2 ring-green-200 shadow-xl' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-gray-500">Online Devices</p>
            {filterStatus === 'online' && (
              <span className="text-[10px] font-semibold text-green-700 bg-green-50 border border-green-200 rounded-full px-2 py-0.5">
                Selected
              </span>
            )}
          </div>
          <p className="text-3xl font-bold text-green-500">
            {nodeStatus?.online ?? 0}
          </p>
        </div>
        <div className="w-12 h-12 rounded-lg flex items-center justify-center">
          <CloudQueueIcon sx={{ fontSize: 26, color: '#22c55e' }} />
        </div>
      </div>
    </motion.div>

    <motion.div
      role="button"
      tabIndex={0}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 }}
      onClick={() => setFilterStatus((prev) => (prev === 'offline' ? 'all' : 'offline'))}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          setFilterStatus((prev) => (prev === 'offline' ? 'all' : 'offline'));
        }
      }}
      className={`bg-white min-w-[150px] snap-center rounded-xl p-4 shadow border-b-2 border-b-yellow-500 flex-shrink-0 sm:min-w-0 sm:flex-shrink sm:p-5 lg:p-6 lg:shadow-lg hover:shadow-xl transition-shadow cursor-pointer ${filterStatus === 'offline' ? 'ring-2 ring-yellow-200 shadow-xl' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-gray-500">Offline Devices</p>
            {filterStatus === 'offline' && (
              <span className="text-[10px] font-semibold text-yellow-800 bg-yellow-50 border border-yellow-200 rounded-full px-2 py-0.5">
                Selected
              </span>
            )}
          </div>
          <p className="text-3xl font-bold text-yellow-500">
            {nodeStatus?.offline ?? 0}
          </p>
        </div>
        <div className="w-12 h-12 rounded-lg flex items-center justify-center">
          <CloudOffIcon sx={{ fontSize: 26, color: '#94a3b8' }} />
        </div>
      </div>
    </motion.div>

    <motion.div
      role="button"
      tabIndex={0}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4 }}
      onClick={() => setFilterRisk((prev) => (prev === 'isolated' ? 'all' : 'isolated'))}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          setFilterRisk((prev) => (prev === 'isolated' ? 'all' : 'isolated'));
        }
      }}
      className={`bg-white min-w-[150px] snap-center rounded-xl p-4 shadow border-b-2 border-b-red-500 flex-shrink-0 sm:min-w-0 sm:flex-shrink sm:p-5 lg:p-6 lg:shadow-lg hover:shadow-xl transition-shadow cursor-pointer ${filterRisk === 'isolated' ? 'ring-2 ring-red-200 shadow-xl' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-gray-500">Total Isolated</p>
            {filterRisk === 'isolated' && (
              <span className="text-[10px] font-semibold text-red-700 bg-red-50 border border-red-200 rounded-full px-2 py-0.5">
                Selected
              </span>
            )}
          </div>
          <p className="text-3xl font-bold text-red-500">
            {nodesData.filter(d => d.isolated === true).length}
          </p>
        </div>
        <div className="w-12 h-12 rounded-lg flex items-center justify-center">
          <DoDisturbAltIcon sx={{ fontSize: 26, color: '#f87171' }} />
        </div>
      </div>
    </motion.div>

    <motion.div
      role="button"
      tabIndex={0}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.5 }}
      onClick={() => setFilterRisk((prev) => (prev === 'critical' ? 'all' : 'critical'))}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          setFilterRisk((prev) => (prev === 'critical' ? 'all' : 'critical'));
        }
      }}
      className={`bg-white min-w-[150px] snap-center rounded-xl p-4 shadow border-b-2 border-b-purple-500 flex-shrink-0 sm:min-w-0 sm:flex-shrink sm:p-5 lg:p-6 lg:shadow-lg hover:shadow-xl transition-shadow cursor-pointer ${filterRisk === 'critical' ? 'ring-2 ring-purple-200 shadow-xl' : ''}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-gray-500">Total Critical</p>
            {filterRisk === 'critical' && (
              <span className="text-[10px] font-semibold text-purple-700 bg-purple-50 border border-purple-200 rounded-full px-2 py-0.5">
                Selected
              </span>
            )}
          </div>
          <p className="text-3xl font-bold text-purple-500">
            {nodesData.filter(d => d.critical === true).length}
          </p>
        </div>
        <div className="w-12 h-12 rounded-lg flex items-center justify-center">
          <i className="fa fa-star text-2xl" style={{ color: '#a855f7' }} />
        </div>
      </div>
    </motion.div>

  </div>
</div>
        </motion.section>

        {/* Table View */}
        {(() => {
          const isInitialLoading = loading && rawNodesData.length === 0;
          const isEmpty = !isInitialLoading && paginatedTableDevices.length === 0;

          const EmptyState = () => (
            <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
              <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-400">
                <DevicesIcon sx={{ fontSize: 24 }} />
              </div>
              <div className="text-sm font-semibold text-slate-800">
                {hasActiveFilters ? 'No devices match your filters' : 'No devices enrolled yet'}
              </div>
              <div className="mt-1 max-w-xs text-xs text-slate-500">
                {hasActiveFilters
                  ? 'Try adjusting or clearing your search and filters.'
                  : 'Devices will appear here as soon as the Vajra Agent enrolls them.'}
              </div>
              {hasActiveFilters && (
                <button
                  type="button"
                  onClick={clearAllFilters}
                  className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
                >
                  <CloseIcon sx={{ fontSize: 14 }} /> Clear filters
                </button>
              )}
            </div>
          );

          return (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="flex min-h-0 flex-1 flex-col"
            >
              {error && !isInitialLoading && (
                <div className="mb-3 flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                  <ErrorOutlineIcon sx={{ fontSize: 18 }} />
                  <span className="flex-1">{error}</span>
                  <button type="button" onClick={fetchNodes} className="rounded-lg text-xs font-semibold underline underline-offset-2">
                    Retry
                  </button>
                </div>
              )}

              {nodesListMaybeTruncated && !isInitialLoading && (
                <div className="mb-3 flex items-center gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
                  <ErrorOutlineIcon sx={{ fontSize: 18 }} />
                  <span className="flex-1">
                    Showing the first {NODE_LIST_FETCH_CAP.toLocaleString()} devices — your fleet may have more that aren't listed here. Narrow your search or filters to find a specific device.
                  </span>
                </div>
              )}

              {/* Desktop / tablet table */}
              <div className="hidden min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm md:flex">
                <div className="min-h-0 flex-1 overflow-y-auto table-scrollbar scrollbar-auto-hide">
                  <table className="w-full border-separate border-spacing-0 text-sm">
                    <thead>
                    <tr>
                        <th className="w-11 px-4 py-3 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                          <Checkbox
                            size="small"
                            checked={allOnPageSelected}
                            indeterminate={!allOnPageSelected && someOnPageSelected}
                            onChange={toggleSelectAllOnPage}
                            sx={{ padding: '2px', '&.Mui-checked': { color: '#2563eb' }, '&.MuiCheckbox-indeterminate': { color: '#2563eb' } }}
                          />
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 lg:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Group</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Enrolled</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Seen</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                        <th className="hidden px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 xl:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Security</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {isInitialLoading &&
                        Array.from({ length: 8 }).map((_, i) => (
                          <tr key={`skeleton-${i}`}>
                            <td className="px-4 py-4"><Skeleton className="h-4 w-4 rounded" /></td>
                            <td className="px-4 py-4">
                              <div className="flex items-center gap-3">
                                <Skeleton className="h-9 w-9 rounded-lg" />
                                <div className="space-y-1.5">
                                  <Skeleton className="h-3.5 w-32" />
                                  <Skeleton className="h-3 w-20" />
                                </div>
                              </div>
                            </td>
                            <td className="hidden px-4 py-4 lg:table-cell"><Skeleton className="h-4 w-16" /></td>
                            <td className="px-4 py-4"><Skeleton className="h-4 w-20" /></td>
                            <td className="px-4 py-4"><Skeleton className="h-4 w-20" /></td>
                            <td className="px-4 py-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                            <td className="hidden px-4 py-4 xl:table-cell"><Skeleton className="h-4 w-24" /></td>
                            <td className="px-2 py-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                          </tr>
                        ))}

                      {!isInitialLoading &&
                        paginatedTableDevices.map((device, index) => {
                          const isExtConnected = agentConnectedIds.has(device.host_identifier);
                          const isWindowsDevice = String(device.os_platform || '').toLowerCase().includes('windows');
                          const isSelected = selectedIds.has(String(device.id));
                          return (
                            <DeviceTableRow
                              key={device.id}
                              device={device}
                              index={index}
                              isSelected={isSelected}
                              isExtConnected={isExtConnected}
                              isWindowsDevice={isWindowsDevice}
                              openUpward={index >= paginatedTableDevices.length - 2}
                              groupsMap={groupsMap}
                              pendingChange={pendingSecurityChangesByNodeId[String(device.id)]}
                              onSelectRow={openDeviceDrawer}
                              onToggleSelect={toggleSelectDevice}
                              onAcknowledge={acknowledgeSecurityChange}
                              onRename={handleRenameFromMenu}
                              onToggleCritical={handleToggleCriticalFromMenu}
                              renderSecurityTools={renderSecurityTools}
                            />
                          );
                        })}

                      {isEmpty && (
                        <tr>
                          <td colSpan={8}>
                            <EmptyState />
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                <Pagination
                  page={tablePage}
                  totalPages={tableTotalPages}
                  total={filteredAndSortedDevices.length}
                  pageSize={tablePageSize}
                  onPageChange={(p) => setTablePage(p)}
                  onPageSizeChange={(size) => setTablePageSize(size)}
                  pageSizeOptions={[10, 25, 50]}
                  itemLabel="devices"
                />
              </div>

              {/* Mobile card list */}
              <div className="min-h-0 flex-1 space-y-3 overflow-y-auto md:hidden">
                {isInitialLoading &&
                  Array.from({ length: 5 }).map((_, i) => (
                    <div key={`m-skeleton-${i}`} className="rounded-xl border border-slate-200 bg-white p-4">
                      <div className="flex items-center gap-3">
                        <Skeleton className="h-10 w-10 rounded-lg" />
                        <div className="flex-1 space-y-2">
                          <Skeleton className="h-3.5 w-2/3" />
                          <Skeleton className="h-3 w-1/3" />
                        </div>
                      </div>
                    </div>
                  ))}

                {!isInitialLoading && isEmpty && (
                  <div className="rounded-xl border border-slate-200 bg-white">
                    <EmptyState />
                  </div>
                )}

                {!isInitialLoading &&
                  paginatedTableDevices.map((device) => {
                    const isExtConnected = agentConnectedIds.has(device.host_identifier);
                    const isWindowsDevice = String(device.os_platform || '').toLowerCase().includes('windows');
                    const isSelected = selectedIds.has(String(device.id));
                    return (
                      <DeviceMobileCard
                        key={device.id}
                        device={device}
                        isSelected={isSelected}
                        isExtConnected={isExtConnected}
                        isWindowsDevice={isWindowsDevice}
                        groupsMap={groupsMap}
                        onSelectRow={openDeviceDrawer}
                        onToggleSelect={toggleSelectDevice}
                        onQuickView={openDeviceDrawer}
                        onRename={handleRenameFromMenu}
                        onToggleCritical={handleToggleCriticalFromMenu}
                        renderSecurityTools={renderSecurityTools}
                      />
                    );
                  })}

                {!isInitialLoading && !isEmpty && (
                  <Pagination
                    page={tablePage}
                    totalPages={tableTotalPages}
                    total={filteredAndSortedDevices.length}
                    pageSize={tablePageSize}
                    onPageChange={(p) => setTablePage(p)}
                    onPageSizeChange={(size) => setTablePageSize(size)}
                    pageSizeOptions={[10, 25, 50]}
                    itemLabel="devices"
                  />
                )}
              </div>

            </motion.div>
          );
        })()}

        {/* Enhanced Device Details Modal with Tabs */}
        <AnimatePresence>
          {selectedDevice && selectedDeviceData && selectedScoreMeta && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.22, ease: 'easeOut' }}
              className="fixed inset-0 z-[9999] bg-slate-950/45 backdrop-blur-sm"
              onClick={closeDeviceDrawer}
              role="dialog"
              aria-modal="true"
              aria-label="Device details"
            >
              <div className="flex min-h-full justify-end p-0 sm:p-4">
                <motion.div
                  ref={deviceDrawerRef}
                  initial={{ x: '100%', opacity: 0.95 }}
                  animate={{ x: 0, opacity: 1 }}
                  exit={{ x: '100%', opacity: 0.98 }}
                  transition={{ type: 'spring', stiffness: 280, damping: 30 }}
                  className="flex h-screen w-full max-w-[680px] flex-col overflow-hidden bg-white shadow-[0_24px_80px_rgba(15,23,42,0.28)] sm:h-[calc(100vh-2rem)] sm:rounded-3xl sm:border sm:border-slate-200/70"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="border-b border-slate-200/70 bg-[#042277] px-4 py-4 sm:px-6">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0 space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex items-center rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-700">
                            Device profile
                          </span>
                          <span
                            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${selectedDeviceData.displayStatus === 'Online'
                              ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                              : selectedDeviceData.displayStatus === 'Active'
                                ? 'border-amber-200 bg-amber-50 text-amber-700'
                                : 'border-slate-200 bg-slate-100 text-slate-700'
                              }`}
                          >
                            <span className={`h-2 w-2 rounded-full ${selectedDeviceData.displayStatus === 'Online'
                              ? 'bg-emerald-500'
                              : selectedDeviceData.displayStatus === 'Active'
                                ? 'bg-amber-500'
                                : 'bg-slate-400'
                              }`} />
                            {selectedDeviceData.displayStatus}
                          </span>
                        </div>

                        <div className="flex items-start gap-3">
                          <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-slate-900 text-white shadow-md shadow-slate-300/40">
                            {getDeviceIcon(selectedDeviceData.type)}
                          </div>
                          <div className="min-w-0">
                            <h3 className="truncate text-xl font-semibold tracking-tight text-white sm:text-2xl">
                              {selectedDeviceData.name}
                            </h3>
                            <div className="flex items-center gap-2 mt-1">
                              <div className="flex items-center gap-2 text-sm text-slate-400">
                                <p className="mt-0.5 truncate text-sm text-white">
                                  • {selectedDeviceData.os}
                                </p>
                              </div>
                              <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-600">
                                <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1">
                                  <span className="font-semibold text-slate-900">IP</span>
                                  <span className="font-medium text-slate-700">{selectedDevicePrimaryIP}</span>
                                </span>

                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={closeDeviceDrawer}
                        className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-500 shadow-sm transition-all duration-200 hover:border-slate-300 hover:text-slate-900 hover:shadow-md"
                        aria-label="Close modal"
                      >
                        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  <div className="table-scrollbar flex-1 overflow-y-auto px-4 py-4 sm:px-6 sm:py-5">
                    <div className="space-y-5">
                      <div className={`overflow-hidden rounded-3xl border bg-gradient-to-br p-4 shadow-[0_16px_42px_rgba(15,23,42,0.08)] ${selectedScoreMeta.border} ${selectedScoreMeta.surface}`}>
                        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                          <div className="flex items-center gap-4">
                            <div className="flex flex-col items-center">
                              <div className="flex h-[152px] w-[152px] items-center justify-center rounded-3xl shadow-inner shadow-white/60">
                                <div className="relative h-[132px] w-[132px]">
                                  {(() => {
                                    const circleRadius = 56;
                                    const circleCircumference = 2 * Math.PI * circleRadius;
                                    return (
                                      <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 144 144">
                                        <defs>
                                          <linearGradient id="device-score-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                            <stop
                                              offset="0%"
                                              stopColor={selectedCompliancePercent == null
                                                ? '#94a3b8'
                                                : selectedCompliancePercent >= 90
                                                  ? '#10b981'
                                                  : selectedCompliancePercent >= 70
                                                    ? '#f59e0b'
                                                    : '#ef4444'}
                                            />
                                            <stop
                                              offset="100%"
                                              stopColor={selectedCompliancePercent == null
                                                ? '#64748b'
                                                : selectedCompliancePercent >= 90
                                                  ? '#14b8a6'
                                                  : selectedCompliancePercent >= 70
                                                    ? '#f97316'
                                                    : '#be123c'}
                                            />
                                          </linearGradient>
                                        </defs>
                                        <circle cx="72" cy="72" r={circleRadius} stroke="#e2e8f0" strokeWidth="11" fill="none" />
                                        <circle
                                          cx="72"
                                          cy="72"
                                          r={circleRadius}
                                          stroke="url(#device-score-gradient)"
                                          strokeWidth="11"
                                          fill="none"
                                          strokeDasharray={`${circleCircumference}`}
                                          strokeDashoffset={`${circleCircumference * (1 - ((selectedCompliancePercent ?? 0) / 100))}`}
                                          strokeLinecap="round"
                                        />
                                      </svg>
                                    );
                                  })()}
                                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                                    {selectedCompliancePercent == null ? (
                                      <>
                                        <span className="mb-1 h-[3px] w-10 rounded-full bg-slate-400/60" />
                                        <span className="text-xs font-semibold tracking-wide text-slate-500">Compliance</span>
                                      </>
                                    ) : (
                                      <>
                                        <span className={`text-3xl font-semibold tracking-tight ${getScoreColor(selectedCompliancePercent)}`}>
                                          {selectedCompliancePercent}%
                                        </span>
                                        <span className="mt-1 text-[10px] font-medium uppercase text-slate-400">
                                          Compliance
                                        </span>
                                      </>
                                    )}

                                  </div>
                                </div>
                              </div>
                              {selectedIsWindowsForCompliance &&
                                selectedComplianceObj === null && (
                                  <div>
                                    <Link
                                      to={`/nodes/view/${encodeURIComponent(selectedComplianceHostId)}?tab=compliance`}
                                      className="metallic-btn-blue mt-2 inline-flex items-center justify-center rounded-md px-3 py-1.5 text-[11px] font-semibold border-transparent"
                                    >
                                      Run compliance
                                    </Link>
                                  </div>
                                )}
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-3 sm:min-w-[320px]">
                            <div className="rounded-2xl border border-white/90 bg-white/85 p-3 shadow-sm">
                              <p className="text-[10px] font-semibold uppercase text-slate-400">Last seen</p>
                              <p className="mt-1 text-sm font-semibold leading-5 text-slate-900">{selectedDeviceData.lastSeen}</p>
                            </div>
                            <div className="rounded-2xl border border-white/90 bg-white/85 p-3 shadow-sm">
                              <p className="text-[10px] font-semibold uppercase text-slate-400">Enrollment</p>
                              <p className="mt-1 text-sm font-semibold leading-5 text-slate-900">{selectedDeviceData.enrolledDate}</p>
                            </div>
                            <div className="col-span-2 rounded-2xl border border-white/90 bg-white/85 p-3 shadow-sm">
                              <p className="text-[10px] font-semibold uppercase text-slate-400">Host ID</p>
                              <p className="mt-1 break-all text-sm font-semibold leading-5 text-slate-900">{selectedDeviceData.host_identifier}</p>
                            </div>


                          </div>
                        </div>
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-white p-1 shadow-sm">
                        <nav className="grid grid-cols-3 gap-1" role="tablist" aria-label="Tabs">
                          <button
                            role="tab"
                            aria-selected={activeTab === 'overview'}
                            onClick={() => changeDeviceTab('overview')}
                            className={`relative px-3 py-2.5 rounded-2xl text-sm font-semibold whitespace-nowrap flex items-center justify-center gap-2 transition-colors duration-200 ${activeTab === 'overview'
                              ? 'text-white'
                              : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                              }`}
                            style={{ transformStyle: 'preserve-3d' }}
                          >
                            {activeTab === 'overview' && (
                              <motion.div
                                layoutId="myDevicesTabsBackground"
                                transition={{ type: "spring", bounce: 0.3, duration: 0.6 }}
                                className="absolute inset-0 bg-[rgb(4,34,119)] rounded-2xl shadow-md"
                                style={{ zIndex: 0 }}
                              />
                            )}
                            <span className="relative z-10 font-semibold">Overview</span>
                          </button>
                          <button
                            role="tab"
                            aria-selected={activeTab === 'ips'}
                            onClick={() => changeDeviceTab('ips')}
                            className={`relative px-3 py-2.5 rounded-2xl text-sm font-semibold whitespace-nowrap flex items-center justify-center gap-2 transition-colors duration-200 ${activeTab === 'ips'
                              ? 'text-white'
                              : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                              }`}
                            style={{ transformStyle: 'preserve-3d' }}
                          >
                            {activeTab === 'ips' && (
                              <motion.div
                                layoutId="myDevicesTabsBackground"
                                transition={{ type: "spring", bounce: 0.3, duration: 0.6 }}
                                className="absolute inset-0 bg-[rgb(4,34,119)] rounded-2xl shadow-md"
                                style={{ zIndex: 0 }}
                              />
                            )}
                            <span className="relative z-10 font-semibold">IP Addresses</span>
                          </button>
                          <button
                            role="tab"
                            aria-selected={activeTab === 'wifi'}
                            onClick={() => changeDeviceTab('wifi')}
                            className={`relative px-3 py-2.5 rounded-2xl text-sm font-semibold whitespace-nowrap flex items-center justify-center gap-2 transition-colors duration-200 ${activeTab === 'wifi'
                              ? 'text-white'
                              : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                              }`}
                          >
                            {activeTab === 'wifi' && (
                              <motion.div
                                layoutId="myDevicesTabsBackground"
                                transition={{ type: "spring", bounce: 0.3, duration: 0.6 }}
                                className="absolute inset-0 bg-[rgb(4,34,119)] rounded-2xl shadow-md"
                                style={{ zIndex: 0 }}
                              />
                            )}
                            <span className="relative z-10 font-semibold">WiFi</span>
                          </button>
                        </nav>
                      </div>

                      <AnimatePresence mode="wait">
                        {activeTab === 'wifi' ? (
                          <motion.div
                            key="wifi"
                            initial={{ opacity: 0, x: 24 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -24 }}
                            transition={{ duration: 0.22, ease: 'easeOut' }}
                            className="space-y-4"
                          >
                            {(() => {
                              const hostIdentifier = selectedDeviceData?.host_identifier;
                              const snap = hostIdentifier ? deviceWifi[hostIdentifier] : undefined;
                              if (loadingWifi) {
                                return (
                                  <div className="rounded-[28px] border border-slate-200 bg-white p-10 text-center shadow-[0_14px_40px_rgba(15,23,42,0.06)]">
                                    <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
                                      <DuoSpinner size="lg" />
                                    </div>
                                    <p className="mt-4 text-base font-semibold text-slate-900">Loading WiFi data</p>
                                  </div>
                                );
                              }
                              if (!snap) {
                                return (
                                  <div className="rounded-[28px] border border-dashed border-slate-300 bg-white/80 p-10 text-center shadow-[0_14px_40px_rgba(15,23,42,0.04)]">
                                    <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-100 text-slate-400">
                                      <i className="fa fa-wifi text-2xl" />
                                    </div>
                                    <p className="mt-4 text-base font-semibold text-slate-900">No WiFi data recorded yet</p>
                                    <p className="mt-2 text-sm text-slate-500">Data appears here once the agent sends its first WiFi snapshot.</p>
                                  </div>
                                );
                              }

                              // Security risk colours
                              const riskClass: Record<string, string> = {
                                none: 'bg-green-100 text-green-700',
                                low: 'bg-blue-100 text-blue-700',
                                medium: 'bg-amber-100 text-amber-700',
                                high: 'bg-orange-100 text-orange-700',
                                critical: 'bg-red-100 text-red-700',
                              };

                              let savedProfiles: WifiSavedProfile[] = [];
                              if (Array.isArray(snap.saved_profiles)) {
                                savedProfiles = snap.saved_profiles;
                              } else if (typeof snap.saved_profiles === 'string' && snap.saved_profiles) {
                                try {
                                  savedProfiles = JSON.parse(snap.saved_profiles);
                                } catch {
                                  savedProfiles = [];
                                }
                              }

                              return (
                                <>
                                  {/* Current / last seen connection */}
                                  <div className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_14px_40px_rgba(15,23,42,0.06)]">
                                    <p className="text-xs font-semibold uppercase text-slate-400">
                                      {snap.is_connected ? 'Currently Connected' : 'Last Known Connection'}
                                    </p>
                                    {snap.is_connected || snap.connected_ssid ? (
                                      <>
                                        <div className="mt-3 flex items-center gap-3">
                                          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-blue-50 text-blue-500">
                                            <i className="fa fa-wifi text-xl" />
                                          </div>
                                          <div>
                                            <h5 className="font-semibold text-slate-900 text-lg">
                                              {snap.connected_ssid || <span className="italic text-slate-400">Hidden SSID</span>}
                                            </h5>
                                            {snap.connected_bssid && (
                                              <p className="text-xs text-slate-500 font-mono">{snap.connected_bssid}</p>
                                            )}
                                          </div>
                                          {snap.is_connected && (
                                            <span className="ml-auto rounded-full bg-emerald-100 px-3 py-1 text-xs font-semibold text-emerald-700">
                                              Connected
                                            </span>
                                          )}
                                        </div>
                                        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 text-xs">
                                          {[
                                            { label: 'Signal', value: snap.connected_signal ? `${snap.connected_signal}%` : '—' },
                                            { label: 'Frequency', value: snap.connected_frequency || '—' },
                                            { label: 'Channel', value: snap.connected_channel || '—' },
                                            { label: 'Bitrate', value: snap.connected_bitrate || '—' },
                                            { label: 'Security', value: snap.connected_security || '—' },
                                            { label: 'IP Address', value: snap.connected_ip || '—' },
                                          ].map(item => (
                                            <div key={item.label} className="rounded-2xl border border-slate-100 bg-slate-50/80 p-3">
                                              <p className="font-medium uppercase text-slate-400 text-[10px]">{item.label}</p>
                                              <p className="mt-1 font-semibold text-slate-900 break-words">{item.value}</p>
                                            </div>
                                          ))}
                                        </div>
                                        <p className="mt-3 text-[11px] text-slate-400 text-right">
                                          Recorded {snap.recorded_at ? new Date(snap.recorded_at).toLocaleString() : '—'}
                                        </p>
                                      </>
                                    ) : (
                                      <p className="mt-3 text-sm text-slate-500">Not connected to any WiFi network.</p>
                                    )}
                                  </div>

                                  {/* Saved profiles */}
                                  {savedProfiles.length > 0 && (
                                    <div className="rounded-[28px] border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.06)] overflow-hidden">
                                      <div className="px-6 py-4 border-b border-slate-100">
                                        <p className="text-xs font-semibold uppercase text-slate-400">
                                          Saved WiFi Profiles ({savedProfiles.length})
                                        </p>
                                      </div>
                                      <div className="overflow-auto max-h-[280px] table-scrollbar scrollbar-auto-hide">
                                        <table className="w-full text-sm border-separate border-spacing-0">
                                          <thead>
                                            <tr className="text-left">
                                              <th className="px-4 py-2 text-xs font-semibold text-slate-500 uppercase sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">SSID</th>
                                              <th className="px-4 py-2 text-xs font-semibold text-slate-500 uppercase sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Security</th>
                                              <th className="px-4 py-2 text-xs font-semibold text-slate-500 uppercase sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Risk</th>
                                              <th className="px-4 py-2 text-xs font-semibold text-slate-500 uppercase text-center sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Auto</th>
                                            </tr>
                                          </thead>
                                          <tbody>
                                            {[...savedProfiles]
                                              .sort((a, b) => {
                                                const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
                                                return (order[a.security_risk ?? ''] ?? 5) - (order[b.security_risk ?? ''] ?? 5);
                                              })
                                              .map((profile: WifiSavedProfile, i: number) => (
                                                <tr key={profile.uuid || i} className="border-b border-slate-50 last:border-0 hover:bg-slate-50">
                                                  <td className="px-4 py-3">
                                                    <p className="font-medium text-slate-900">{profile.ssid || '—'}</p>
                                                    <p className="text-[11px] text-slate-400 truncate max-w-[160px]" title={profile.security_detail}>
                                                      {profile.security_detail}
                                                    </p>
                                                  </td>
                                                  <td className="px-4 py-3 text-slate-600 text-xs">{profile.security || '—'}</td>
                                                  <td className="px-4 py-3">
                                                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${riskClass[profile.security_risk ?? ''] ?? 'bg-gray-100 text-gray-600'}`}>
                                                      {profile.security_risk?.toUpperCase() ?? '—'}
                                                    </span>
                                                  </td>
                                                  <td className="px-4 py-3 text-center">
                                                    {profile.auto_connect
                                                      ? <i className="fa fa-check text-emerald-600" />
                                                      : <i className="fa fa-xmark text-slate-300" />}
                                                  </td>
                                                </tr>
                                              ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </div>
                                  )}
                                </>
                              );
                            })()}
                          </motion.div>
                        ) : activeTab === 'overview' ? (
                          <motion.div
                            key="overview"
                            initial={{ opacity: 0, x: 24 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -24 }}
                            transition={{ duration: 0.22, ease: 'easeOut' }}
                            className="space-y-5"
                          >
                            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                              {[
                                { label: 'Device type', value: selectedDeviceData.type },
                                { label: 'Operating system', value: selectedDeviceData.os, wide: true },
                                { label: 'Primary IP', value: selectedDevicePrimaryIP },
                              ].map((item) => (
                                <div
                                  key={item.label}
                                  className={`rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_10px_26px_rgba(15,23,42,0.05)]
        ${item.wide ? 'xl:col-span-2' : 'xl:col-span-1'}
      `}
                                >
                                  <p className="text-[10px] font-semibold uppercase text-slate-400">{item.label}</p>
                                  <p className="mt-2 break-words text-[15px] font-semibold leading-6 text-slate-900">{item.value}</p>
                                </div>
                              ))}
                            </div>

                            <div className="grid gap-4 xl:grid-cols-[1.15fr,0.85fr]">
                              <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_14px_34px_rgba(15,23,42,0.06)]">
                                <p className="text-[10px] font-semibold uppercase text-slate-400">Security posture</p>
                                <h4 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Protection controls</h4>

                                <div className="mt-4 space-y-3">
                                  {[
                                    {
                                      label: 'Microsoft Defender',
                                      value: selectedDefenderStatus,
                                      active: selectedDefenderStatus === 'On',
                                    },
                                    {
                                      label: 'Firewall',
                                      value: selectedFirewallStatus,
                                      active: selectedFirewallStatus === 'On',
                                    },
                                    {
                                      label: 'Connection state',
                                      value: selectedDeviceData.displayStatus,
                                      active: selectedDeviceData.displayStatus === 'Online' || selectedDeviceData.displayStatus === 'Active',
                                    },
                                  ].map((item) => (
                                    <div key={item.label} className="flex items-center justify-between rounded-2xl border border-slate-100 bg-slate-50/80 px-4 py-3">
                                      <div>
                                        <p className="text-sm font-semibold text-slate-900">{item.label}</p>
                                        <p className="mt-1 text-xs text-slate-500">Current reported status</p>
                                      </div>
                                      <span
                                        className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${item.active
                                          ? 'border-emerald-200 bg-emerald-100 text-emerald-700'
                                          : 'border-slate-200 bg-slate-100 text-slate-700'
                                          }`}
                                      >
                                        {item.value}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        ) : (
                          <motion.div
                            key="ips"
                            initial={{ opacity: 0, x: 24 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -24 }}
                            transition={{ duration: 0.22, ease: 'easeOut' }}
                            className="space-y-4"
                          >
                            {loadingIPs ? (
                              <div className="rounded-[28px] border border-slate-200 bg-white p-10 text-center shadow-[0_14px_40px_rgba(15,23,42,0.06)]">
                                <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
                                  <DuoSpinner size="lg" />
                                </div>
                                <p className="mt-4 text-base font-semibold text-slate-900">Loading network interfaces</p>
                                <p className="mt-2 text-sm text-slate-500">Gathering the latest interface data for this device.</p>
                              </div>
                            ) : deviceIPs[selectedDevice] && deviceIPs[selectedDevice].length > 0 ? (
                              <div className="overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-[0_14px_40px_rgba(15,23,42,0.06)]">
                                <div className="border-b border-slate-100 px-6 py-4">
                                  <p className="text-xs font-semibold uppercase text-slate-400">
                                    Network Interfaces ({deviceIPs[selectedDevice].length})
                                  </p>
                                </div>
                                <div className="divide-y divide-slate-100">
                                  {deviceIPs[selectedDevice].map((iface: DeviceNetworkInterface, index: number) => {
                                    const isWireless = String(iface.type || '').toLowerCase().includes('wi');
                                    return (
                                      <div
                                        key={index}
                                        className="flex flex-col gap-3 px-6 py-4 transition-colors hover:bg-slate-50/80 sm:flex-row sm:items-center sm:justify-between"
                                      >
                                        <div className="flex min-w-0 items-center gap-3">
                                          <div
                                            className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${isWireless ? 'bg-blue-50 text-blue-600' : 'bg-slate-100 text-slate-600'
                                              }`}
                                          >
                                            <i className={`fa ${isWireless ? 'fa-wifi' : 'fa-network-wired'} text-base`} />
                                          </div>
                                          <div className="min-w-0">
                                            <h5 className="truncate text-sm font-semibold text-slate-900">
                                              {iface.friendly_name || iface.interface || 'Unknown Interface'}
                                            </h5>
                                            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
                                              <span>{iface.type || 'Unknown type'}</span>
                                            </div>
                                          </div>
                                        </div>

                                        <div className="flex shrink-0 items-center gap-5 pl-13 sm:pl-0">
                                          <div className="sm:text-right">
                                            <p className="text-[10px] font-medium uppercase text-slate-400">IP address</p>
                                            <p className="font-mono text-sm font-semibold text-slate-900">{iface.address || 'N/A'}</p>
                                          </div>
                                          <div className="sm:text-right">
                                            <p className="text-[10px] font-medium uppercase text-slate-400">Netmask</p>
                                            <p className="font-mono text-sm font-semibold text-slate-900">{iface.mask || 'N/A'}</p>
                                          </div>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            ) : (
                              <div className="rounded-[28px] border border-dashed border-slate-300 bg-white/80 p-10 text-center shadow-[0_14px_40px_rgba(15,23,42,0.04)]">
                                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-100 text-slate-500">
                                  <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.111 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3.5M9 20h6" />
                                  </svg>
                                </div>
                                <p className="mt-4 text-base font-semibold text-slate-900">No network interfaces available</p>
                                <p className="mt-2 text-sm text-slate-500">This device has not reported any interface details yet.</p>
                              </div>
                            )}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </div>

                  <div className="border-t border-slate-200/80 bg-white/90 px-5 py-4 backdrop-blur-xl sm:px-7">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex flex-col-reverse gap-2 sm:flex-row">
                        <button
                          onClick={closeDeviceDrawer}
                          className="inline-flex items-center justify-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-slate-300 hover:bg-slate-50"
                        >
                          Close
                        </button>
                        <button
                          onClick={() => {
                            setCriticalNodeId(selectedDeviceData?.host_identifier);
                            setCriticalReason("");
                            setCriticalModalMode(selectedDeviceData?.critical ? 'unmark' : 'mark');
                            setCriticalOpen(true);
                          }}
                          className={`metallic-btn-critical text-sm ${selectedDeviceData?.critical ? 'slate' : ''}`}
                        >
                          <span className="relative z-10">{selectedDeviceData?.critical ? 'Mark as Non-Critical' : 'Mark as Critical'}</span>
                        </button>
                        <Link
                          to={`/nodes/view/${selectedDeviceData.host_identifier}`}
                          className="metallic-btn-blue inline-flex items-center justify-center rounded-2xl px-5 py-2.5 text-sm font-semibold border-transparent"
                        >
                          Open full profile
                        </Link>
                      </div>
                    </div>
                  </div>
                </motion.div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>


        <Dialog
          open={renameOpen}
          onClose={() => setRenameOpen(false)}
          maxWidth="xs"
          fullWidth
          sx={isDarkMode ? darkDialogSx : undefined}
          PaperProps={{ sx: { borderRadius: '16px' } }}
        >
          <DialogTitle sx={{ fontWeight: 700 }}>Rename Device</DialogTitle>


          <DialogContent>
            <TextField
              fullWidth
              label="Device Name"
              value={newName}
              onChange={(e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
                const val = e.target.value.replace(/[^a-zA-Z0-9_\- ]/g, '');
                setNewName(val.slice(0, 64));
              }}
              helperText="Only letters, numbers, hyphens, underscores, and spaces are allowed."
              margin="dense"
              autoFocus
            />
          </DialogContent>

          <DialogActions sx={{ px: 3, pb: 3, gap: 1 }}>
            <Button
              type="button"
              className="metallic-btn-white-red px-4 py-2 rounded-lg text-sm font-semibold flex items-center justify-center min-w-[80px]"
              onClick={() => setRenameOpen(false)}
            >
              Cancel
            </Button>

            <Button
              type="button"
              className="metallic-btn-blue px-4 py-2 rounded-lg text-sm font-semibold flex items-center justify-center min-w-[80px]"
              onClick={() => {
                if (selectedHost) {
                  renameDevice(selectedHost, newName);
                }
                setRenameOpen(false);
              }}
            >
              OK
            </Button>
          </DialogActions>
        </Dialog>

        <Dialog open={criticalOpen} onClose={() => setCriticalOpen(false)} maxWidth="xs" fullWidth sx={isDarkMode ? darkDialogSx : undefined}>
          <DialogTitle>
            {criticalBulkMode
              ? `Mark ${selectedDevicesData.length} device${selectedDevicesData.length === 1 ? '' : 's'} as ${criticalModalMode === 'mark' ? 'Critical' : 'Non-Critical'}`
              : criticalModalMode === 'mark' ? 'Mark Device as Critical' : 'Mark Device as Non-Critical'}
          </DialogTitle>

          <DialogContent>
            <div className="mt-4 mb-2 text-sm text-slate-600 dark:text-slate-400">
              {criticalModalMode === 'mark'
                ? `Provide a reason for marking ${criticalBulkMode ? 'these devices' : 'this device'} as critical for audit purposes.`
                : `Provide a reason for unmarking ${criticalBulkMode ? 'these devices' : 'this device'} as critical for audit purposes.`}
            </div>
            <TextField
              fullWidth
              label="Reason"
              value={criticalReason}
              onChange={(e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
                setCriticalReason(sanitizeAsciiSingleLine(e.target.value, 256, true))
              }
              placeholder="e.g., Critical infrastructure, High sensitivity data, etc."
              multiline
              rows={4}
              margin="dense"
              autoFocus
            />
          </DialogContent>

          <DialogActions sx={{ px: 3, pb: 3, gap: 1 }}>
            <button
              type="button"
              className="metallic-btn-white-red px-4 py-2 rounded-lg text-sm font-semibold flex items-center justify-center min-w-[80px]"
              onClick={() => setCriticalOpen(false)}
            >
              Cancel
            </button>

            <button
              type="button"
              disabled={bulkActionInFlight}
              className={`px-4 py-2 rounded-lg text-sm font-semibold flex items-center justify-center min-w-[80px] disabled:opacity-60 ${criticalModalMode === 'mark' ? 'metallic-btn-critical border-transparent' : 'metallic-btn-critical slate border-transparent'}`}
              onClick={() => {
                if (!criticalReason.trim()) {
                  showToast("Please enter a reason", "error");
                  return;
                }
                if (criticalBulkMode) {
                  const hostIds = selectedDevicesData.map((d) => String(d.host_identifier)).filter(Boolean);
                  bulkMarkCritical(hostIds, criticalReason, criticalModalMode);
                } else if (criticalNodeId) {
                  if (criticalModalMode === 'mark') {
                    markNodeCritical(criticalNodeId, criticalReason);
                  } else {
                    markNodeNonCritical(criticalNodeId, criticalReason);
                  }
                }
                setCriticalOpen(false);
                setCriticalReason("");
                setCriticalNodeId(null);
                setCriticalBulkMode(false);
              }}
            >
              {criticalModalMode === 'mark' ? 'Mark Critical' : 'Remove Critical'}
            </button>
          </DialogActions>
        </Dialog>

      </div>
    </div>
  );
};


export default MyDevices;
