/**
 * NodesView: Main container for a single node.
 * Opens from Nodes page "View" button; shows tabbed sub-pages (Details, Graph, etc.).
 * Each tab is a separate file for easier API management and readability.
 */

import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import type { NodeData, NodesViewTabId } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import LiveConnectionBadge from '@/components/ui/LiveConnectionBadge';
import { debugLog } from '@/lib/debugLog';
import { formatUnixTimestamp } from '@/lib/utils';
import { NODES_VIEW_TABS } from './constants';
import NodesViewDetails from './NodesViewDetails';
import NodesViewMemoryGraph from './NodesViewMemoryGraph';
import NodesViewPortControl from './NodesViewPortControl';
import NodesViewIPControl from './NodesViewIPControl';
import NodesViewUsbControl from './NodesViewUsbControl';
import NodesViewBluetoothControl from './NodesViewBluetoothControl';
import NodesViewPrograms from './NodesViewPrograms';
import NodesViewCompliance from './NodesViewCompliance';
import NodesViewProfileCompliance from './NodesViewProfileCompliance';
import NodesViewIRDAIHotCompliance from './NodesViewIRDAIHotCompliance';
import NodesViewFirewallRules from './NodesViewFirewallRules';
import NodesViewBiosInfo from './NodesViewBiosInfo';
import NodesViewStorage from './NodesViewStorage';
import NodesViewSendMessage from './NodesViewSendMessage';
import { useNodeWebSocket } from '../../../hooks/useNodeWebSocket';
import { useModalA11y } from '../../../hooks/useModalA11y';
import { useLiveData } from '../../../context/useLiveData';
import NodesViewUpdateHistory from './NodesViewUpdateHistory';
import NodesViewWifiControl from './NodesViewWifiControl';
import NodesViewDefenderControl from './NodesViewDefenderControl';
import NodesViewClamavControl from './NodesViewClamavControl';
import NodesViewFirewallStatusControl from './NodesViewFirewallStatusControl';
import { NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';
import { sanitizeAsciiMultiLine } from '../../../services/inputSanitizers';
import { useToast } from '../../../context/useToast';
import NodesViewCertInCompliance from './NodesViewCertInCompliance';
import NodesViewSebiHotCompliance from './NodesViewSebiHotCompliance';
import { motion } from 'motion/react';

/** Narrowed view of useNodeWebSocket's sendMessage used by tab components that only need
 * to send a message and read back the generic agent envelope (status/message/response). */
type WsAgentSendMessage = (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
type WsAgentSendMessageWithOptions = (
  message: unknown,
  options?: { timeoutMs?: number },
) => Promise<{ status?: string; message?: string; response?: unknown }>;

const ISOLATE_CSS = `
.isolate-btn-metallic {
  background: linear-gradient(135deg, rgba(220, 38, 38, 0.95) 0%, rgba(185, 28, 28, 1) 100%);
  color: white;
  border: 1px solid rgba(239, 68, 68, 0.4);
  border-bottom-color: rgba(153, 27, 27, 0.6);
  padding: 8px 20px;
  border-radius: 8px;
  font-weight: 600;
  box-shadow: 
    0 2px 8px rgba(220, 38, 38, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.3),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(4px);
  transition: all 0.2s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.isolate-btn-metallic.reenroll {
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.95) 0%, rgba(5, 150, 105, 1) 100%);
  border: 1px solid rgba(52, 211, 153, 0.4);
  border-bottom-color: rgba(6, 78, 59, 0.6);
  box-shadow: 
    0 2px 8px rgba(16, 185, 129, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.3),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
}

.isolate-btn-metallic::before {
  content: '';
  position: absolute;
  top: 0;
  left: -150%;
  width: 150%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.5), transparent);
  transform: skewX(-20deg);
  animation: metallic-shimmer 3.5s infinite;
}

@keyframes metallic-shimmer {
  0% { left: -150%; }
  40% { left: 150%; }
  100% { left: 150%; }
}

.isolate-btn-metallic:hover {
  box-shadow: 
    0 4px 12px rgba(220, 38, 38, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.4),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  background: linear-gradient(135deg, rgba(239, 68, 68, 1) 0%, rgba(185, 28, 28, 1) 100%);
  transform: translateY(-1px);
}

.isolate-btn-metallic.reenroll:hover {
  box-shadow: 
    0 4px 12px rgba(16, 185, 129, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.4),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  background: linear-gradient(135deg, rgba(52, 211, 153, 1) 0%, rgba(5, 150, 105, 1) 100%);
}

.isolate-btn-metallic:active {
  transform: translateY(1px);
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.2),
    inset 0 2px 4px rgba(0, 0, 0, 0.3);
}

.isolate-btn-metallic:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  transform: none;
  filter: grayscale(20%);
}
`;


type ComplianceSubTabId = 'vajra' | 'sebi' | 'profile' | 'irdai' | 'cert-in' | 'iso27001' | 'soc2';

const COMPLIANCE_SUBTABS: Array<{
  id: ComplianceSubTabId;
  label: string;
  icon: string;
  hideOnUbuntu?: boolean;
  disabled?: boolean;
  comingSoon?: boolean;
}> = [
    { id: 'vajra', label: 'Vajra', icon: 'fa-check-circle' },
    { id: 'sebi', label: 'SEBI', icon: 'fa-fire' },
    { id: 'profile', label: 'Profile', icon: 'fa-solid fa-user' },
    { id: 'irdai', label: 'IRDAI', icon: 'fa-solid fa-fire-flame-curved' },
    { id: 'cert-in', label: 'CERT-In', icon: 'fa-solid fa-certificate' },
    { id: 'iso27001', label: 'ISO 27001', icon: 'fa-solid fa-key', disabled: true, comingSoon: true },
    { id: 'soc2', label: 'SOC 2', icon: 'fa-solid fa-lock', disabled: true, comingSoon: true },
  ];

const RESPONSIVE_ACTIONS_SUBTABS = [
  { id: 'port-control' as const, label: 'Port Control', icon: 'fa-solid fa-network-wired', category: 'software' as const, windowsOnly: false as const, linuxOnly: false as const },
  { id: 'ip-control' as const, label: 'IP Control', icon: 'fa-solid fa-shield-alt', category: 'software' as const, windowsOnly: false as const, linuxOnly: false as const },
  { id: 'usb-control' as const, label: 'USB Control', icon: 'fa-brands fa-usb', category: 'hardware' as const, windowsOnly: false as const, linuxOnly: false as const },
  { id: 'bluetooth-control' as const, label: 'Bluetooth Control', icon: 'fa-brands fa-bluetooth-b', category: 'hardware' as const, windowsOnly: false as const, linuxOnly: false as const },
  { id: 'defender-control' as const, label: 'Defender Control', icon: 'fa-solid fa-shield-virus', category: 'software' as const, windowsOnly: true as const, linuxOnly: false as const },
  { id: 'clamav-control' as const, label: 'ClamAV Control', icon: 'fa-solid fa-bug-slash', category: 'software' as const, windowsOnly: false as const, linuxOnly: true as const },
  { id: 'firewall-status' as const, label: 'Firewall Status', icon: 'fa-solid fa-fire-flame-curved', category: 'software' as const, windowsOnly: false as const, linuxOnly: true as const },
];

const formatDate = (timestamp: string | number) => {
  return formatUnixTimestamp(timestamp);
};

type ResponsiveActionsSubTabId = (typeof RESPONSIVE_ACTIONS_SUBTABS)[number]['id'];

/** Map route state node (mock or API shape) to NodeData */
function toNodeData(state: unknown): NodeData | null {
  if (!state || typeof state !== 'object') return null;
  const o = state as Record<string, unknown>;
  return {
    id: Number(o.id) || 0,
    name: String(o.name ?? ''),
    status: (o.status as NodeData['status']) || 'offline',
    cpu: typeof o.cpu === 'number' ? o.cpu : undefined,
    memory: typeof o.memory === 'number' ? o.memory : undefined,
    location: o.location as string | undefined,
    lastSeen:
      typeof o.last_seen === 'number' || typeof o.last_seen === 'string'
        ? formatDate(o.last_seen)
        : undefined,
    host_identifier: o.host_identifier as string | undefined,
    hostname: o.hostname as string | undefined,
    original_hostname: o.original_hostname as string | undefined,
    address: o.address as string | undefined,
    os_platform: o.os_platform as string | undefined,
    os_name: o.os_name as string | undefined,
    os_arch: o.os_arch as string | undefined,
    os_major: o.os_major as string | undefined,
    os_minor: o.os_minor as string | undefined,
    os_build: o.os_build as string | undefined,
    osquery_version: o.osquery_version as string | undefined,
    kernel_version: o.kernel_version as string | undefined,
    hardware_vendor: o.hardware_vendor as string | undefined,
    hardware_version: o.hardware_version as string | undefined,
    hardware_model: o.hardware_model as string | undefined,
    hardware_physical_memory: o.hardware_physical_memory as string | undefined,
    memory_metrics_unavailable_reason: o.memory_metrics_unavailable_reason as string | undefined,
    hardware_cpu_logical_core: o.hardware_cpu_logical_core as string | undefined,
    hardware_cpu_type: o.hardware_cpu_type as string | undefined,
    enrolled_on:
      typeof o.enrolled_on === 'number' || typeof o.enrolled_on === 'string'
        ? formatDate(o.enrolled_on)
        : undefined,
    last_seen:
      typeof o.last_seen === 'number' || typeof o.last_seen === 'string'
        ? Number(o.last_seen)
        : undefined,
    device_group: o.device_group as string | undefined,
    security_products: Array.isArray(o.security_products)
      ? (o.security_products as { name: string; state: string }[])
      : undefined,
    isolated: o.isolated as boolean | undefined,
    view: o.view as NodeData['view'] | undefined,
    agent_online: o.agent_online as boolean | undefined,
  };
}

export default function NodesView() {
  const location = useLocation();
  const navigate = useNavigate();
  const { host_identifier } = useParams<{ host_identifier: string }>();
  const { showToast } = useToast();

  const fromAuditTrailState = location.state as unknown as { fromAuditTrail?: boolean } | undefined;
  const fromAuditTrail = Boolean(fromAuditTrailState?.fromAuditTrail);

  const [nodeFromState] = useState(() => toNodeData(location.state));
  const [nodeFromApi, setNodeFromApi] = useState<NodeData | null>(null);
  const [loading, setLoading] = useState<boolean>(!!host_identifier);
  const [error, setError] = useState<string | null>(null);
  const [nodeDetailFetchWarning, setNodeDetailFetchWarning] = useState<string | null>(null);

  // Determine which node data to use: API fetch takes priority, then location state
  const node = nodeFromApi || nodeFromState;

  const [activeTab, setActiveTab] = useState<NodesViewTabId>('details');
  const [activeResponsiveSubTab, setActiveResponsiveSubTab] = useState<ResponsiveActionsSubTabId>('port-control');

  // Initialize compliance subtab immediately from location.state so first render is correct.
  // os_platform may sit at top level of state or nested under a 'node' key depending on
  // how the Nodes list navigates here.
  // --- Compliance subtab state: robust fallback, debug logging, and banner ---
  const [activeComplianceSubTab, setActiveComplianceSubTab] = useState<ComplianceSubTabId>(() => {
    const state = location.state as Record<string, unknown> | null;
    const platform = String(
      state?.os_platform ??
      (state?.node as Record<string, unknown>)?.os_platform ??
      ''
    ).toLowerCase();
    const initial: ComplianceSubTabId = platform.includes('ubuntu') ? 'profile' : 'vajra';
    return initial;
  });

  // Sync deep-link ?tab= / ?subtab= params and handle back-compat tab ids.
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const requestedTab = searchParams.get('tab');
    if (!requestedTab) return;
    // Retired tab ids keep working, matching the sebi-compliance/sebi-hot
    // back-compat below. 'graph' was removed and its Memory Command View now
    // lives on the Storage tab, so a bookmarked ?tab=graph should land there
    // rather than silently falling through to Details.
    const RETIRED_TAB_REDIRECTS: Record<string, NodesViewTabId> = { graph: 'storage' };
    const redirected = RETIRED_TAB_REDIRECTS[requestedTab];
    if (redirected) {
      setActiveTab(redirected);
      return;
    }

    const tabExists = NODES_VIEW_TABS.some((tab) => tab.id === requestedTab);
    if (tabExists) {
      setActiveTab(requestedTab as NodesViewTabId);
    }

    // Deep-link into a Responsive Actions subtab, e.g. the MyDevices ClamAV
    // pill links to ?tab=responsive-actions&subtab=clamav-control.
    const requestedSubtab = searchParams.get('subtab');
    if (
      requestedTab === 'responsive-actions' &&
      requestedSubtab &&
      RESPONSIVE_ACTIONS_SUBTABS.some((st) => st.id === requestedSubtab)
    ) {
      setActiveResponsiveSubTab(requestedSubtab as ResponsiveActionsSubTabId);
    }

    const ubuntu = (node?.os_platform || '').toLowerCase().includes('ubuntu');

    if (requestedTab === 'sebi-compliance' || requestedTab === 'sebi-hot') {
      setActiveTab('compliance');
      setActiveComplianceSubTab('sebi');
    } else if (requestedTab === 'compliance') {
      if (requestedSubtab && COMPLIANCE_SUBTABS.some((st) => st.id === requestedSubtab)) {
        setActiveComplianceSubTab(requestedSubtab as ComplianceSubTabId);
      } else {
        setActiveComplianceSubTab(ubuntu ? 'profile' : 'vajra');
      }
    }
  }, [location.search, node?.os_platform]);

  // Isolate: null → use API value; set to true/false after a WS action
  const [isolatedOverride, setIsolatedOverride] = useState<boolean | null>(null);

  // Fetch node data from API if host_identifier is available
  useEffect(() => {
    if (!host_identifier) return;
    let cancelled = false;
    // Clear the previous node's data immediately so a fast render between
    // switching nodes never shows node A's compliance/details under node B's
    // identity while the new fetch is still in flight.
    setNodeFromApi(null);
    setLoading(true);
    setError(null);
    setNodeDetailFetchWarning(null);

    api.get(`${NODES_URLS.NODE}${encodeURIComponent(String(host_identifier))}`)
      .then((res) => res.data)
      .then((data) => {
        if (cancelled) return;
        const apiNode = toNodeData(data.data || data);
        setNodeFromApi(apiNode);
        // Once we have real API data, correct the compliance subtab if needed, but do not overwrite if user already selected a subtab
        const platform = (apiNode?.os_platform || '').toLowerCase();
        const isUbuntuFromApi = platform.includes('ubuntu');
        setActiveComplianceSubTab((prev) => {
          // Only auto-switch if user hasn't already picked a subtab manually
          if (prev === 'vajra' && isUbuntuFromApi) {
            debugLog('[NodesView] API fetch: switching compliance subtab to profile due to Ubuntu platform');
            return 'profile';
          }
          return prev;
        });
        setNodeDetailFetchWarning(null);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        console.error('Failed to fetch node details:', err);
        const st = nodeFromState;
        const idMatch =
          st &&
          host_identifier &&
          (st.host_identifier === host_identifier || String(st.id) === host_identifier);
        if (idMatch) {
          setNodeDetailFetchWarning(
            err instanceof Error
              ? `${err.message}. Showing data from navigation; some fields may be incomplete.`
              : 'Could not load latest node details. Showing data from navigation.'
          );
          setError(null);
        } else {
          setError(err instanceof Error ? err.message : 'Failed to fetch node details');
        }
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [host_identifier, nodeFromState]);

  const { nodeStatus } = useLiveData();
  const isWindows = (node?.os_platform || '').toLowerCase().includes('windows');
  // isLinux = pure Linux only (not Windows, not Ubuntu). Compliance tab is hidden only here.
  const isLinux = !isWindows;
  const hostId = node?.host_identifier || (node ? String(node.id) : '');

  // Redirect away from compliance on pure Linux (compliance tab is hidden there).
  useEffect(() => {
    if (!node) return;
    if (!isLinux) return;
    if (
      activeTab === 'compliance' ||
      activeTab === 'sebi-compliance' ||
      activeTab === 'profile-compliance'
    ) {
      setActiveTab('details');
    }
  }, [activeTab, isLinux, node]);

  // Two independent signals from the live WebSocket broadcast:
  //
  // isLastSeenOnline — osquery is actively heartbeating (last_seen < 10s threshold).
  //   Source: nodeStatus.onlineNodeHostIdentifier (built from last_seen in liveWeb.ts).
  //   Used for: the status badge colour/label — is the endpoint running?
  //
  // isExtConnected — the browser extension has an active /ws/ext WebSocket slot.
  //   Source: nodeStatus.agentOnline (built from agent_online DB field, which is
  //   set to true on extension connect and false on clean disconnect or startup reset).
  //   Used for: WS/MCP command gating — can we actually send a command to this node?
  //
  // Do not fall back to the API-fetched agent_online flag for isExtConnected: that
  // field can be stale before the startup reset propagates. We wait for live WS
  // confirmation instead — the snapshot arrives within one round-trip of page load.
  const isLastSeenOnline = nodeStatus != null && node?.host_identifier
    ? nodeStatus.onlineNodeHostIdentifier.includes(node.host_identifier)
    : false;

  const isExtConnected = nodeStatus != null && node?.host_identifier
    ? nodeStatus.agentOnline.includes(node.host_identifier)
    : false;

  // Same three-state presence used by My Devices (StatusBadge/displayStatus): a
  // heartbeat with no extension connection is 'Active', not 'Online' — keeping the
  // label consistent avoids the header pill disagreeing with My Devices/this page's
  // own tab-gating for the same node.
  const presenceStatus: 'Online' | 'Active' | 'Offline' = isLastSeenOnline
    ? (isExtConnected ? 'Online' : 'Active')
    : 'Offline';

  const canAttemptWsConnect = isExtConnected || (isolatedOverride ?? (node?.isolated ?? false));
  const {
    connected: wsConnected,
    sendMessage: wsSendMessage,
    lastMessage: wsLastMessage,
  } = useNodeWebSocket(hostId, canAttemptWsConnect);

  const isIsolated = isolatedOverride ?? (node?.isolated ?? false);
  const nodeIdentity = node?.host_identifier || node?.hostname || `Node-${node?.id}`;

  // Keep the browser tab title distinct per node/tab — an additional wayfinding cue
  // when several node views are open across browser tabs (the URL's ?tab= param is
  // kept in sync too, see updateTabInUrl/handleMainTabClick below).
  useEffect(() => {
    if (!node) return;
    const tabMeta = NODES_VIEW_TABS.find((t) => t.id === activeTab);
    document.title = `${node.hostname || nodeIdentity} · ${tabMeta?.label ?? 'Node'} · Vajra`;
    return () => {
      document.title = 'Vajra';
    };
  }, [node, nodeIdentity, activeTab]);
  const platformLabel = [node?.os_name, node?.os_arch].filter(Boolean).join(' ') || 'Unknown OS';
  const enrolledLabel = node?.enrolled_on || '—';
  const lastSeenLabel =
    node?.lastSeen ||
    (typeof node?.last_seen === 'number'
      ? new Date(node.last_seen * 1000).toLocaleString('en-IN')
      : '—');

  type NetworkManagerReasonAction = 'block' | 'allow';
  const [isolationReasonModal, setIsolationReasonModal] = useState<null | {
    action: NetworkManagerReasonAction;
  }>(null);
  const [isolationReason, setIsolationReason] = useState('');
  const [isolationReasonSubmitting, setIsolationReasonSubmitting] = useState(false);
  const [isolationReasonError, setIsolationReasonError] = useState<string | null>(null);

  const openIsolationReasonModal = (action: NetworkManagerReasonAction) => {
    setIsolationReasonModal({ action });
    setIsolationReason('');
    setIsolationReasonError(null);
  };

  const closeIsolationReasonModal = () => {
    setIsolationReasonModal(null);
    setIsolationReason('');
    setIsolationReasonError(null);
    setIsolationReasonSubmitting(false);
  };

  const isolationReasonModalRef = useModalA11y<HTMLDivElement>(
    Boolean(isolationReasonModal),
    closeIsolationReasonModal
  );

  const submitIsolationReasonModal = async () => {
    if (!isolationReasonModal) return;
    const r = isolationReason.trim();
    if (!r) {
      setIsolationReasonError('Reason is required.');
      return;
    }
    setIsolationReasonSubmitting(true);
    setIsolationReasonError(null);
    const action = isolationReasonModal.action;
    try {
      const response = await wsSendMessage({
        type: 'agent',
        params: {
          agent: 'networkManager',
          action,
          arg1: '1234',
          arg3: r,
          reason: r,
        },
        host_identifier: hostId,
      });
      if (response.status === 'error') {
        throw new Error(response.message || `Agent failed to ${action === 'block' ? 'isolate' : 'reenroll'} device`);
      }
      setIsolatedOverride(action === 'block');
      setIsolationReasonSubmitting(false);
      closeIsolationReasonModal();
    } catch (err) {
      setIsolationReasonSubmitting(false);
      const message =
        err instanceof Error
          ? `Failed to ${action === 'block' ? 'isolate' : 'reenroll'} device: ${err.message}`
          : `Failed to ${action === 'block' ? 'isolate' : 'reenroll'} device. Please try again.`;
      setIsolationReasonError(message);
      showToast(message, 'error');
    }
  };

  const handleIsolate = () => openIsolationReasonModal('block');
  const handleReenroll = () => openIsolationReasonModal('allow');

  const tabs = NODES_VIEW_TABS.filter((t) => {
    if (t.hideOnWindows && isWindows) return false;
    if (t.hideOnLinux && isLinux) return false;

    if (t.requireOnline && !isExtConnected) return true; // show but disabled
    return true;
  });

  // Early returns

  if (loading) {
    return (
      <div className="min-h-screen bg-[#f8f9fb]">
        <div className="flex flex-col items-center justify-center min-h-[50vh] px-4">
          <DuoSpinner size="lg" className="text-blue-600 mb-4" />
          <p className="text-gray-600">Loading node details...</p>
        </div>
      </div>
    );
  }

  if (error || !node) {
    return (
      <div className="min-h-screen bg-[#f8f9fb]">
        <div className="flex flex-col items-center justify-center min-h-[50vh] px-4">
          <p className="text-gray-600 mb-4">
            {error
              ? `Error: ${error}`
              : 'Node data not found. Please select a node from the nodes list.'}
          </p>
          <Link
            to={fromAuditTrail ? '/audit-trail' : '/my-devices'}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700"
          >
            <i className="fa fa-arrow-left" /> Back to {fromAuditTrail ? 'Audit Trail' : 'Nodes'}
          </Link>
        </div>
      </div>
    );
  }

  // Render helpers

  // Write-back half of the deep-link plumbing: keeps the URL's ?tab=/&subtab=
  // params (parsed by the effect above) in sync with in-page tab clicks, so a
  // refresh — or copying the URL — lands back on the same tab/subtab. Mirrors
  // the exact param names/values the read-side effect expects.
  const updateTabInUrl = (tab: NodesViewTabId, subtab?: string) => {
    const params = new URLSearchParams(location.search);
    params.set('tab', tab);
    if (subtab) {
      params.set('subtab', subtab);
    } else {
      params.delete('subtab');
    }
    navigate({ pathname: location.pathname, search: params.toString() }, { replace: true });
  };

  const handleMainTabClick = (tabId: NodesViewTabId) => {
    setActiveTab(tabId);
    if (tabId === 'responsive-actions') {
      updateTabInUrl(tabId, activeResponsiveSubTab);
    } else if (tabId === 'compliance') {
      updateTabInUrl(tabId, activeComplianceSubTab);
    } else {
      updateTabInUrl(tabId);
    }
  };

  const handleComplianceSubTabClick = (subTabId: ComplianceSubTabId) => {
    setActiveComplianceSubTab(subTabId);
    updateTabInUrl('compliance', subTabId);
  };

  const handleResponsiveSubTabClick = (subTabId: ResponsiveActionsSubTabId) => {
    setActiveResponsiveSubTab(subTabId);
    updateTabInUrl('responsive-actions', subTabId);
  };

  const renderResponsiveActionsContent = () => {
    if (!isExtConnected) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] px-4">
          <div className="text-center">
            <div className="mb-4">
              <i className="fa fa-exclamation-circle text-5xl text-amber-500" />
            </div>
            <p className="text-lg font-semibold text-gray-800 mb-2">Agent is Offline</p>
            <p className="text-gray-600">
              This agent is currently offline. Responsive actions are only available when the agent
              is online.
            </p>
          </div>
        </div>
      );
    }

    switch (activeResponsiveSubTab) {
      case 'port-control':
        return <NodesViewPortControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} />;
      case 'ip-control':
        return <NodesViewIPControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} />;
      case 'usb-control':
        return <NodesViewUsbControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} lastMessage={wsLastMessage} />;
      case 'bluetooth-control':
        return <NodesViewBluetoothControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} />;
      case 'defender-control':
        return <NodesViewDefenderControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessageWithOptions} />;
      case 'clamav-control':
        return <NodesViewClamavControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessageWithOptions} lastMessage={wsLastMessage} />;
      case 'firewall-status':
        return <NodesViewFirewallStatusControl node={node} wsConnected={wsConnected} lastMessage={wsLastMessage} />;
      default:
        return <NodesViewPortControl node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} />;
    }
  };

  const renderCompliance = (forcedSubTab?: ComplianceSubTabId) => {
    const rawSubTab = forcedSubTab ?? activeComplianceSubTab;

    // Filter out subtabs that should be hidden on Ubuntu
    // Do not filter out any compliance subtabs, show all including IRDAI HOT
    const subtabsNav = COMPLIANCE_SUBTABS;

    // Safe fallback chain — never lands on 'sebi' accidentally (it navigates away)
    const effectiveSubTab: ComplianceSubTabId =
      subtabsNav.find((s) => s.id === rawSubTab && !s.disabled)?.id ??
      subtabsNav.find((s) => s.id === 'vajra')?.id ??
      subtabsNav.find((s) => !s.disabled)?.id ??
      'vajra';

    const content = (() => {
      switch (effectiveSubTab) {
        case 'vajra':
          return (
            <NodesViewCompliance
              node={node}
              wsConnected={wsConnected}
              wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
              agentOnline={isExtConnected}
            />
          );
        case 'sebi':
          return (
            <NodesViewSebiHotCompliance
              node={node}
              wsConnected={wsConnected}
              wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
              agentOnline={isExtConnected}
            />
          );
        case 'profile':
          return <NodesViewProfileCompliance node={node} />;
        case 'irdai':
          return <NodesViewIRDAIHotCompliance
            node={node}
            wsConnected={wsConnected}
            wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
            agentOnline={isExtConnected}
          />;
        case 'cert-in':
          return <NodesViewCertInCompliance
            node={node}
            wsConnected={wsConnected}
            wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
            agentOnline={isExtConnected}
          />;
        case 'iso27001':
          return (
            <div className="p-4 sm:p-6">
              <div className="bg-white rounded-xl border border-slate-200 p-6">
                <div className="flex items-start gap-3">
                  <i className="fa fa-clock text-amber-500 mt-1" />
                  <div className="min-w-0">
                    <h3 className="text-base sm:text-lg font-semibold text-slate-800">
                      ISO 27001 Compliance
                    </h3>
                    <p className="mt-1 text-sm text-slate-600">
                      Coming soon. This tab will display an IR-ready checklist mapped to ISO 27001
                      controls.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        case 'soc2':
          return (
            <div className="p-4 sm:p-6">
              <div className="bg-white rounded-xl border border-slate-200 p-6">
                <div className="flex items-start gap-3">
                  <i className="fa fa-clock text-amber-500 mt-1" />
                  <div className="min-w-0">
                    <h3 className="text-base sm:text-lg font-semibold text-slate-800">
                      SOC 2 Compliance
                    </h3>
                    <p className="mt-1 text-sm text-slate-600">
                      Coming soon. This tab will display an audit-oriented checklist mapped to SOC 2
                      requirements.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        default:
          // effectiveSubTab's fallback chain above always resolves to a known
          // subtab, so this shouldn't be reachable — kept as a safety net in
          // case that assumption ever breaks, rendered as a normal error
          // state rather than leaking internal variable names to the user.
          return (
            <div className="p-6 text-sm text-slate-600 border border-slate-200 rounded-lg m-4">
              Unable to load this compliance view. Try selecting a different tab, or refresh the page.
            </div>
          );
      }
    })();

    return (
      <div>
        <div className="overflow-x-auto p-3 sm:p-4 lg:p-5 pb-0">
          <div className="flex w-fit gap-1.5 sm:gap-2 whitespace-nowrap min-w-max rounded-xl border border-slate-200/80 bg-slate-50/70 p-1.5" role="tablist" aria-label="Compliance Subtabs">
            {subtabsNav.map((subTab) => {

              const disabled = Boolean(subTab.disabled);
              const isActive = !disabled && effectiveSubTab === subTab.id;
              return (
                <button
                  key={subTab.id}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => !disabled && handleComplianceSubTabClick(subTab.id)}
                  disabled={disabled}
                  className={`relative px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors duration-200 active:scale-95 flex items-center gap-2 ${disabled
                    ? 'text-slate-400 cursor-not-allowed opacity-60'
                    : isActive
                      ? 'text-blue-700'
                      : 'text-slate-600 hover:text-slate-800'
                    }`}
                  style={{ transformStyle: 'preserve-3d' }}
                >
                  {isActive && (
                    <motion.div
                      layoutId="complianceTabsBackground"
                      transition={{ type: 'spring', bounce: 0.3, duration: 0.6 }}
                      className="absolute inset-0 rounded-lg border border-blue-200 bg-white shadow-sm"
                      style={{ zIndex: 0 }}
                    />
                  )}
                  <i className={`fa ${subTab.icon} relative z-10`} />
                  <span className="relative z-10">{subTab.label}</span>
                  {subTab.comingSoon && (
                    <span className="relative z-10 ml-1 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide bg-amber-50 text-amber-700 border border-amber-200">
                      Coming soon
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
        {content}
      </div>
    );
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'details':
        return <NodesViewDetails node={node} />;
      case 'responsive-actions':
        return (
          <div>
            <div className="overflow-x-auto p-3 sm:p-4 lg:p-5 pb-0">
              <div className="flex gap-1.5 sm:gap-2 whitespace-nowrap min-w-max rounded-xl border border-slate-200/80 bg-slate-50/70 p-1.5" role="tablist" aria-label="Device Controls Subtabs">
                {RESPONSIVE_ACTIONS_SUBTABS.filter((st) => (!st.windowsOnly || isWindows) && (!st.linuxOnly || !isWindows)).map(
                  (subTab) => {
                    const disabled = !isExtConnected;
                    const isActive = !disabled && activeResponsiveSubTab === subTab.id;

                    const categoryClass =
                      subTab.category === 'software'
                        ? 'bg-blue-50 text-blue-600'
                        : 'bg-emerald-50 text-emerald-600';
                    return (
                      <button
                        key={subTab.id}
                        type="button"
                        role="tab"
                        aria-selected={isActive}
                        onClick={() => !disabled && handleResponsiveSubTabClick(subTab.id)}
                        disabled={disabled}
                        className={`relative px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors duration-200 active:scale-95 flex items-center gap-2 ${disabled
                          ? 'text-slate-400 cursor-not-allowed'
                          : isActive
                            ? 'text-blue-700'
                            : 'text-slate-600 hover:text-slate-800'
                          }`}
                        style={{ transformStyle: 'preserve-3d' }}
                      >
                        {isActive && (
                          <motion.div
                            layoutId="deviceControlsTabsBackground"
                            transition={{ type: 'spring', bounce: 0.3, duration: 0.6 }}
                            className="absolute inset-0 rounded-lg border border-blue-200 bg-white shadow-sm"
                            style={{ zIndex: 0 }}
                          />
                        )}
                        <i className={`fa ${subTab.icon} relative z-10`} />
                        <span className="relative z-10">{subTab.label}</span>
                        <span
                          className={`relative z-10 px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide ${categoryClass}`}
                        >
                          {subTab.category}
                        </span>
                      </button>
                    );
                  }
                )}
              </div>
            </div>
            {renderResponsiveActionsContent()}
          </div>
        );
      case 'programs':
        return <NodesViewPrograms node={node} />;
      case 'compliance':
        return isLinux ? <NodesViewDetails node={node} /> : renderCompliance();
      case 'sebi-compliance':
        return isLinux ? <NodesViewDetails node={node} /> : renderCompliance('sebi');
      case 'profile-compliance':
        return isLinux ? <NodesViewDetails node={node} /> : renderCompliance('vajra');
      case 'firewall-rules':
        return <NodesViewFirewallRules node={node} />;
      case 'bios-info':
        return <NodesViewBiosInfo node={node} />;
      case 'storage':
        // Memory Command View moved here when the Graph tab was removed. It sits
        // above the storage panel so the node's live resource view is the first
        // thing on the tab; NodesViewStorage itself is unchanged.
        return (
          <div className="space-y-6">
            <NodesViewMemoryGraph node={node} />
            <NodesViewStorage node={node} />
          </div>
        );
      case 'wifi':
        return (
          <NodesViewWifiControl
            node={node}
            wsConnected={wsConnected}
            wsSendMessage={wsSendMessage as WsAgentSendMessage}
            lastMessage={wsLastMessage}
          />
        );
      case 'send-message':
        return (
          <NodesViewSendMessage node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessage} />
        );
      case 'update-history':
        return (
          <NodesViewUpdateHistory node={node} wsConnected={wsConnected} wsSendMessage={wsSendMessage as WsAgentSendMessageWithOptions} />
        );
      default:
        return <NodesViewDetails node={node} />;
    }
  };

  // Main render

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 via-white to-slate-50">
      <style dangerouslySetInnerHTML={{ __html: ISOLATE_CSS }} />
      <div className="max-w-full lg:max-w-[98.2%] mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">
        {nodeDetailFetchWarning && (
          <div
            className="mb-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 flex gap-2 items-start"
            role="status"
          >
            <i className="fa fa-exclamation-triangle mt-0.5 flex-shrink-0" aria-hidden />
            <span>{nodeDetailFetchWarning}</span>
          </div>
        )}

        {/* Node summary card */}
        <div className="bg-white rounded-xl lg:rounded-2xl border border-blue-100 shadow-sm overflow-hidden mb-3 sm:mb-4 lg:mb-5">
          <div className="px-3 sm:px-5 lg:px-6 py-3 sm:py-4 lg:py-5 bg-[#042277] border-b border-blue-100">
            <div className="flex flex-col sm:flex-row sm:flex-wrap items-start justify-between gap-3 sm:gap-4">
              <div className="space-y-2 sm:space-y-2.5 min-w-0 w-full sm:w-auto">
                <div className="flex flex-wrap items-center gap-2 sm:gap-2.5">
                  <h1 className="text-lg sm:text-xl lg:text-2xl font-bold text-white leading-tight break-words">
                    {node.hostname || 'Unnamed Node'}
                  </h1>
                  <span
                    className={`inline-flex items-center gap-1.5 px-2 sm:px-2.5 py-1 rounded-full text-xs font-semibold ${presenceStatus === 'Online'
                      ? 'bg-green-100 text-green-700'
                      : presenceStatus === 'Active'
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-slate-200 text-slate-700'
                      }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${presenceStatus === 'Online'
                        ? 'bg-green-500'
                        : presenceStatus === 'Active'
                          ? 'bg-amber-500'
                          : 'bg-slate-500'
                        }`}
                    />
                    {presenceStatus}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1.5 px-2 sm:px-2.5 py-1 rounded-full text-xs font-semibold ${isIsolated ? 'bg-blue-100 text-blue-700' : 'bg-emerald-100 text-emerald-700'
                      }`}
                  >
                    <i className={`fa ${isIsolated ? 'fa-lock' : 'fa-shield-halved'} text-[11px]`} />
                    {isIsolated ? 'Isolated' : 'Protected'}
                  </span>
                  <LiveConnectionBadge label="Live status offline" />
                </div>

                <div className="flex flex-wrap items-center gap-x-3 sm:gap-x-5 gap-y-1.5 text-xs sm:text-sm text-slate-600">
                  <span className="inline-flex items-center gap-1.5">
                    <i className="fa fa-desktop text-white" />
                    <span className="truncate max-w-[150px] sm:max-w-none text-white">{platformLabel}</span>
                  </span>
                  <span className="inline-flex items-center gap-1.5 font-mono text-[11px] sm:text-[13px] text-slate-700 break-all">
                    <i className="fa fa-fingerprint text-white" />
                    <span className="truncate max-w-[200px] sm:max-w-none text-white">{nodeIdentity}</span>
                  </span>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-2.5 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={isIsolated ? handleReenroll : handleIsolate}
                  disabled={!isExtConnected}
                  title={
                    !isExtConnected
                      ? 'Agent is offline; cannot change isolation state'
                      : isIsolated
                        ? 'Reenroll this machine into the network'
                        : 'Isolate this machine from the network'
                  }
                  className={`isolate-btn-metallic w-full sm:w-auto focus:outline-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${isIsolated ? 'reenroll' : ''}`}

                >
                  <i className={`fa ${isIsolated ? 'fa-plug' : 'fa-ban'} relative z-10`} />
                  <span className="text-sm tracking-wide relative z-10 font-bold">{isIsolated ? 'Reenroll' : 'Isolate'}</span>
                </button>
                <Link
                  to={fromAuditTrail ? '/audit-trail' : '/my-devices'}
                  className="inline-flex items-center justify-center bg-white gap-2 px-4 py-2.5 sm:py-2 border border-blue-300 text-blue-700 rounded-lg text-sm font-medium hover:bg-blue-50 active:bg-blue-100"
                >
                  <i className="fa fa-arrow-left" /> Back to{' '}
                  {fromAuditTrail ? 'Audit Trail' : 'Nodes'}
                </Link>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3 mt-3 sm:mt-4">
              <div className="rounded-lg sm:rounded-xl border border-white/70 bg-white backdrop-blur-sm px-3 sm:px-3.5 py-2 sm:py-2.5">
                <p className="text-[10px] sm:text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Connection
                </p>
                <p
                  className={`mt-1 text-xs sm:text-sm font-semibold truncate ${wsConnected ? 'text-emerald-700' : 'text-amber-700'
                    }`}
                >
                  {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
                </p>
              </div>
              <div className="rounded-lg sm:rounded-xl border border-white/70 bg-white backdrop-blur-sm px-3 sm:px-3.5 py-2 sm:py-2.5">
                <p className="text-[10px] sm:text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Last Seen
                </p>
                <p
                  className="mt-1 text-xs sm:text-sm font-medium text-slate-700 truncate"
                  title={String(lastSeenLabel)}
                >
                  {lastSeenLabel}
                </p>
              </div>
              <div className="rounded-lg sm:rounded-xl border border-white/70 bg-white backdrop-blur-sm px-3 sm:px-3.5 py-2 sm:py-2.5">
                <p className="text-[10px] sm:text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Enrolled On
                </p>
                <p
                  className="mt-1 text-xs sm:text-sm font-medium text-slate-700 truncate"
                  title={String(enrolledLabel)}
                >
                  {enrolledLabel}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mt-4">
          <div className="border-b border-slate-200 bg-slate-50/50 overflow-x-auto scrollbar-hide py-2 px-2">
            <nav className="flex items-center gap-1 min-w-max" role="tablist" aria-label="Tabs">
              {tabs.map((tab) => {
                const disabled = tab.requireOnline && !isExtConnected;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={isActive}
                    onClick={() => !disabled && handleMainTabClick(tab.id)}
                    disabled={disabled}
                    className={`relative px-4 py-2.5 rounded-full text-sm font-medium whitespace-nowrap flex items-center gap-2 transition-colors duration-200 ${disabled
                      ? 'text-slate-400 cursor-not-allowed opacity-60'
                      : isActive
                        ? 'text-white'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                      }`}
                    style={{ transformStyle: 'preserve-3d' }}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="mainTabsBackground"
                        transition={{ type: "spring", bounce: 0.3, duration: 0.6 }}
                        className="absolute inset-0 bg-[rgb(4,34,119)] rounded-full"
                        style={{ zIndex: 0 }}
                      />
                    )}

                    <i
                      className={`fa ${tab.icon} relative z-10 ${isActive ? 'text-white' : 'text-slate-500 group-hover:text-slate-700'
                        }`}
                    />
                    <span className="relative z-10 font-medium">{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="bg-white">{renderTabContent()}</div>
        </div>

        {/* Isolate/Re-enroll reason modal */}
        {isolationReasonModal &&
          typeof document !== 'undefined' &&
          createPortal(
            <div
              className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
              role="dialog"
              aria-modal="true"
              onClick={() => !isolationReasonSubmitting && closeIsolationReasonModal()}
            >
              <div
                ref={isolationReasonModalRef}
                className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4"
                onClick={(e) => e.stopPropagation()}
              >
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  {isolationReasonModal.action === 'block' ? 'Isolate node' : 'Re-enroll node'}
                </h3>
                <p className="text-sm text-gray-600 mb-3">
                  {isolationReasonModal.action === 'block'
                    ? 'This immediately blocks all network traffic to and from this endpoint until it is re-enrolled.'
                    : 'This restores normal network access for this endpoint.'}
                </p>
                <label htmlFor="isolation-reason" className="block text-sm text-gray-600 mb-1">
                  Enter a reason (required)
                </label>
                <textarea
                  id="isolation-reason"
                  value={isolationReason}
                  onChange={(e) =>
                    setIsolationReason(sanitizeAsciiMultiLine(e.target.value, 300, false))
                  }
                  placeholder="e.g. Policy enforcement, Incident response, Temporary exception"
                  className="w-full min-h-[80px] px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-y"
                  autoFocus
                  required
                  aria-required="true"
                />
                {isolationReasonError && (
                  <div className="mt-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                    {isolationReasonError}
                  </div>
                )}
                <div className="flex justify-end gap-2 mt-4">
                  <button
                    type="button"
                    onClick={closeIsolationReasonModal}
                    disabled={isolationReasonSubmitting}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={submitIsolationReasonModal}
                    disabled={isolationReasonSubmitting || !isolationReason.trim()}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {isolationReasonSubmitting ? 'Applying…' : 'Confirm'}
                  </button>
                </div>
              </div>
            </div>,
            document.body
          )}
      </div>
    </div>
  );
}