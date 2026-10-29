/**
 * NodesViewUsbControl
 *
 * Two capabilities:
 *  1. Enable / Disable removable storage on the node via the agent command:
 *       { type:'agent', params:{ agent:'removableDevice', action:'enable'|'disable' } }
 *  2. Live USB storage status:
 *       - Windows: fetched via PowerShell key 54 → {enabled, status, registry_start}
 *       - Linux:   fetched via {agent:'removableDevice', action:'status'}
 *                  → {usb_storage_policy:'Enabled'|'Disabled', connected_devices:[...]}
 *  3. Real-time USB event log populated by unsolicited 'usb_device_push' messages.
 *       - Windows event fields: caption, pnp_device_id, serial_number, size_gb, event_type, detected_at
 *       - Linux event fields:   vendor, product, serial, dev_name, size_gb, event_type, detected_at
 */

import { useState, useEffect, useCallback, useRef, memo } from 'react';
import { createPortal } from 'react-dom';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { sanitizeAsciiMultiLine } from '../../../services/inputSanitizers';
import { useModalA11y } from '../../../hooks/useModalA11y';

// Windows USB event row
interface WindowsUsbEvent {
  caption:       string;
  pnp_device_id: string;
  serial_number: string;
  size_gb:       string;
  event_type:    string;
  detected_at:   string;
}

// Linux USB event row
interface LinuxUsbEvent {
  vendor:     string;
  product:    string;
  serial:     string;
  dev_name:   string;
  size_gb:    string;
  event_type: string;
  detected_at: string;
}

// Windows status (PowerShell key 54)
interface WindowsUsbStatus {
  enabled:        boolean;
  status:         'enabled' | 'disabled' | 'unknown';
  registry_start: number | null;
}

// Linux status (removableDevice action:'status')
interface LinuxConnectedDevice {
  vendor:   string;
  product:  string;
  serial:   string;
  dev_name: string;
  size_gb:  string;
}

interface LinuxUsbStatus {
  usb_storage_policy: 'Enabled' | 'Disabled';
  connected_devices:  LinuxConnectedDevice[];
}

/** Shape of the shared WS envelope pushed to lastMessage (see useNodeWebSocket). */
interface WsPushMessage {
  rid?: string;
  host_identifier?: string;
  response?: unknown;
}

interface NodesViewUsbControlProps {
  node:          NodeData;
  wsConnected:   boolean;
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
  lastMessage:   WsPushMessage | null;
}

// Status badge. Must stay at module scope: inside the parent's render body it gets a
// fresh function identity every render, so React sees a different element type and
// discards the rendered <span> on every state change instead of updating it.
const StatusBadge = ({
  loadingStatus,
  isLinux,
  linuxStatus,
  windowsStatus,
  isEnabled,
  isDisabled,
}: {
  loadingStatus: boolean;
  isLinux: boolean;
  linuxStatus: LinuxUsbStatus | null;
  windowsStatus: WindowsUsbStatus | null;
  isEnabled: boolean;
  isDisabled: boolean;
}) => {
  if (loadingStatus) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
        <DuoSpinner size="xs" /> Fetching…
      </span>
    );
  }
  const hasStatus = isLinux ? !!linuxStatus : !!windowsStatus;
  if (!hasStatus) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-400">
        — Unknown
      </span>
    );
  }
  if (isEnabled) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
        ● Enabled
      </span>
    );
  }
  if (isDisabled) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
        ● Blocked
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">
      ● Unknown
    </span>
  );
};

// Event table (OS-aware). Module scope and memoised: this table is fed by unsolicited
// `usb_device_push` WebSocket messages, and as an inline component its identity changes
// on every parent render, so React rebuilds the whole <table> — losing the scroll
// position inside the max-h-[420px] pane — on any unrelated panel state change.
const EventTable = memo(({
  isLinux,
  linuxEvents,
  windowsEvents,
  onClear,
}: {
  isLinux: boolean;
  linuxEvents: LinuxUsbEvent[];
  windowsEvents: WindowsUsbEvent[];
  onClear: () => void;
}) => {
  const events = isLinux ? linuxEvents : windowsEvents;

  const isConnectEvent = (et: string) =>
    et?.toLowerCase().includes('insert') ||
    et?.toLowerCase().includes('connect') ||
    et?.toLowerCase().includes('arrival');

  return (
    <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
      <div className="px-4 py-3 bg-gray-50 border-b border-blue-100 flex items-center justify-between">
        <div>
          <h6 className="font-semibold text-gray-800">
            USB Device Events{events.length > 0 && ` (${events.length})`}
          </h6>
          <p className="text-xs text-gray-500 mt-0.5">
            Real-time events pushed by the agent on USB insert / removal
          </p>
        </div>
        {events.length > 0 && (
          <button
            type="button"
            onClick={onClear}
            className="text-xs text-gray-500 hover:text-gray-700 font-medium rounded-lg"
          >
            Clear
          </button>
        )}
      </div>

      <div className="p-4 overflow-auto max-h-[420px]">
        {events.length === 0 ? (
          <p className="text-gray-500 text-sm text-center py-10">
            No USB events received yet. Events appear here in real-time when the agent detects
            USB activity on this node.
          </p>
        ) : isLinux ? (
          <table className="w-full text-sm border-separate border-spacing-0">
            <thead>
              <tr className="text-left">
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Vendor / Product</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Serial</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Size</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Event</th>
                <th className="pb-2 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Detected</th>
              </tr>
            </thead>
            <tbody>
              {(linuxEvents).map((ev, idx) => (
                <tr key={idx} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-800">
                    {[ev.vendor, ev.product].filter(Boolean).join(' ') || '—'}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs text-gray-600">
                    {ev.serial || '—'}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs text-gray-600">
                    {ev.dev_name || '—'}
                  </td>
                  <td className="py-2 pr-4 text-gray-600">
                    {ev.size_gb ? `${ev.size_gb} GB` : '—'}
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      isConnectEvent(ev.event_type)
                        ? 'bg-blue-100 text-blue-700'
                        : 'bg-amber-100 text-amber-700'
                    }`}>
                      {ev.event_type || '—'}
                    </span>
                  </td>
                  <td className="py-2 text-gray-500 text-xs whitespace-nowrap">
                    {ev.detected_at || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-sm border-separate border-spacing-0">
            <thead>
              <tr className="text-left">
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Serial</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Size</th>
                <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Event</th>
                <th className="pb-2 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Detected</th>
              </tr>
            </thead>
            <tbody>
              {(windowsEvents).map((ev, idx) => (
                <tr key={idx} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-800">{ev.caption || '—'}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-gray-600">
                    {ev.serial_number || '—'}
                  </td>
                  <td className="py-2 pr-4 text-gray-600">
                    {ev.size_gb ? `${ev.size_gb} GB` : '—'}
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      isConnectEvent(ev.event_type)
                        ? 'bg-blue-100 text-blue-700'
                        : 'bg-amber-100 text-amber-700'
                    }`}>
                      {ev.event_type || '—'}
                    </span>
                  </td>
                  <td className="py-2 text-gray-500 text-xs whitespace-nowrap">
                    {ev.detected_at || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
});
EventTable.displayName = 'EventTable';

const NodesViewUsbControl = ({
  node,
  wsConnected,
  wsSendMessage,
  lastMessage,
}: NodesViewUsbControlProps) => {
  const hostId  = node.host_identifier || String(node.id);
  const isLinux = !(node.os_platform || '').toLowerCase().includes('windows');

  const [actionLoading, setActionLoading] = useState<'enable' | 'disable' | null>(null);
  const [actionMsg, setActionMsg]         = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [reasonModal, setReasonModal] = useState<null | { action: 'enable' | 'disable' }>(null);
  const [reason, setReason] = useState('');
  const [reasonSubmitting, setReasonSubmitting] = useState(false);

  // Windows state
  const [windowsStatus,   setWindowsStatus]   = useState<WindowsUsbStatus | null>(null);
  const [windowsEvents,   setWindowsEvents]   = useState<WindowsUsbEvent[]>([]);

  // Linux state
  const [linuxStatus,     setLinuxStatus]     = useState<LinuxUsbStatus | null>(null);
  const [linuxEvents,     setLinuxEvents]     = useState<LinuxUsbEvent[]>([]);

  const [loadingStatus, setLoadingStatus] = useState(false);

  // Fetch USB status
  const fetchUsbStatus = useCallback(async () => {
    if (!wsConnected) return;
    setLoadingStatus(true);
    try {
      if (isLinux) {
        // Linux: direct removableDevice status call
        const response = await wsSendMessage({
          type: 'agent',
          params: { agent: 'removableDevice', action: 'status' },
          host_identifier: hostId,
        });
        const raw = typeof response.response === 'string'
          ? JSON.parse(response.response)
          : response.response;
        if (raw && raw.usb_storage_policy !== undefined) {
          setLinuxStatus(raw as LinuxUsbStatus);
        }
      } else {
        // Windows: PowerShell key 54
        const response = await wsSendMessage({
          type: 'agent',
          params: { agent: 'powershell', action: 'allow', command_keys: ['54'] },
          host_identifier: hostId,
        });
        const items: Array<{ command_key: string; output: string }> =
          JSON.parse(String(response.response ?? '[]'));
        const item = items.find((i) => i.command_key === '54');
        if (item) setWindowsStatus(JSON.parse(item.output) as WindowsUsbStatus);
      }
    } catch {
      // status is best-effort; do not show error
    } finally {
      setLoadingStatus(false);
    }
  }, [wsConnected, wsSendMessage, hostId, isLinux]);

  // Fire once when WS connects (guard against StrictMode double-fire)
  const hasFetchedRef = useRef(false);
  useEffect(() => {
    if (wsConnected && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchUsbStatus();
    }
    if (!wsConnected) {
      hasFetchedRef.current = false;
    }
  }, [wsConnected, fetchUsbStatus]);

  // Real-time USB event push
  useEffect(() => {
    if (!lastMessage || lastMessage.rid !== 'usb_device_push') return;
    if (lastMessage.host_identifier && lastMessage.host_identifier !== hostId) return;

    try {
      const rows = typeof lastMessage.response === 'string'
        ? JSON.parse(lastMessage.response)
        : lastMessage.response;
      if (!Array.isArray(rows) || rows.length === 0) return;

      if (isLinux) {
        setLinuxEvents((prev) => [...(rows as LinuxUsbEvent[]), ...prev].slice(0, 100));
      } else {
        setWindowsEvents((prev) => [...(rows as WindowsUsbEvent[]), ...prev].slice(0, 100));
      }
    } catch {
      // malformed push — ignore
    }
  }, [lastMessage, hostId, isLinux]);

  // Auto-clear action feedback after 5 s
  useEffect(() => {
    if (!actionMsg) return;
    const t = setTimeout(() => setActionMsg(null), 5000);
    return () => clearTimeout(t);
  }, [actionMsg]);

  const openReasonModal = (action: 'enable' | 'disable') => {
    setReasonModal({ action });
    setReason('');
  };

  const closeReasonModal = () => {
    setReasonModal(null);
    setReason('');
  };

  const reasonModalRef = useModalA11y<HTMLDivElement>(Boolean(reasonModal), closeReasonModal);

  const submitReasonModal = async () => {
    if (!reasonModal) return;
    if (!reason.trim()) {
      setActionMsg({ type: 'error', text: 'Reason is required.' });
      return;
    }
    if (!wsConnected) {
      setActionMsg({ type: 'error', text: 'WebSocket not connected. Please wait or refresh.' });
      return;
    }

    const action = reasonModal.action;
    setActionLoading(action);
    setReasonSubmitting(true);
    setActionMsg(null);
    try {
      const response = await wsSendMessage({
        type: 'agent',
        params: {
          agent: 'removableDevice',
          action,
          arg1: reason.trim(),
          reason: reason.trim(),
        },
        host_identifier: hostId,
      });

      if (response?.status === 'error') {
        throw new Error(response.message || `Failed to ${action} removable device`);
      }
      setActionMsg({
        type: 'success',
        text: `Removable device storage ${action}d successfully.`,
      });
      closeReasonModal();
      fetchUsbStatus();
    } catch (err: unknown) {
      setActionMsg({ type: 'error', text: (err instanceof Error && err.message) || `Failed to ${action} removable device` });
    } finally {
      setActionLoading(null);
      setReasonSubmitting(false);
    }
  };

  // Enable / Disable removable device
  const handleAction = (action: 'enable' | 'disable') => {
    openReasonModal(action);
  };

  // Helpers
  // Stable identity so the memoised EventTable is not re-rendered by a fresh arrow each render.
  const clearUsbEvents = useCallback(() => {
    if (isLinux) setLinuxEvents([]);
    else setWindowsEvents([]);
  }, [isLinux]);

  const hasStatus = isLinux ? !!linuxStatus : !!windowsStatus;

  const isEnabled = isLinux
    ? linuxStatus?.usb_storage_policy === 'Enabled'
    : windowsStatus?.status === 'enabled';

  const isDisabled = isLinux
    ? linuxStatus?.usb_storage_policy === 'Disabled'
    : windowsStatus?.status === 'disabled';


  return (
    <div className="p-4 flex flex-col gap-6">

      {/* Enable / Disable control panel */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h6 className="font-semibold text-gray-800">Removable Device Control</h6>
              <StatusBadge
                loadingStatus={loadingStatus}
                isLinux={isLinux}
                linuxStatus={linuxStatus}
                windowsStatus={windowsStatus}
                isEnabled={isEnabled}
                isDisabled={isDisabled}
              />
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              Enable or disable removable storage (USB drives) on this node.
            </p>
            <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
            </span>
          </div>
          <button
            type="button"
            onClick={fetchUsbStatus}
            disabled={loadingStatus || !wsConnected}
            className="text-xs text-blue-600 hover:text-blue-800 font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1 shrink-0 mt-1 rounded-lg"
          >
            <i className={`fa fa-sync-alt ${loadingStatus ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Status detail row */}
        {isLinux ? (
          linuxStatus && (
            <div className="px-4 py-2 bg-gray-50 border-b border-blue-50 flex flex-col gap-2">
              <div className="flex items-center gap-4 text-xs text-gray-500">
                <span>
                  USB Storage Policy:{' '}
                  <span className={`font-medium ${
                    linuxStatus.usb_storage_policy === 'Enabled' ? 'text-green-700' : 'text-red-700'
                  }`}>
                    {linuxStatus.usb_storage_policy}
                  </span>
                </span>
                <span>
                  Connected Devices:{' '}
                  <span className="font-medium text-gray-700">
                    {linuxStatus.connected_devices.length}
                  </span>
                </span>
              </div>
              {linuxStatus.connected_devices.length > 0 && (
                <div className="overflow-auto">
                  <table className="w-full text-xs border-separate border-spacing-0">
                    <thead>
                      <tr className="text-left text-gray-500 border-b">
                        <th className="pb-1 pr-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Vendor / Product</th>
                        <th className="pb-1 pr-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Serial</th>
                        <th className="pb-1 pr-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                        <th className="pb-1 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {linuxStatus.connected_devices.map((d, i) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="py-1 pr-3 text-gray-800">
                            {[d.vendor, d.product].filter(Boolean).join(' ') || '—'}
                          </td>
                          <td className="py-1 pr-3 font-mono text-gray-600">{d.serial || '—'}</td>
                          <td className="py-1 pr-3 font-mono text-gray-600">{d.dev_name || '—'}</td>
                          <td className="py-1 text-gray-600">{d.size_gb ? `${d.size_gb} GB` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )
        ) : null}

        <div className="p-4 space-y-4">
          <div className="flex gap-3 flex-wrap">
            <button
              type="button"
              onClick={() => handleAction('enable')}
              disabled={!!actionLoading || !wsConnected || !hasStatus || isEnabled === true}
              className="px-5 py-2 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm
                         flex items-center gap-2"
            >
              {actionLoading === 'enable'
                ? <><DuoSpinner size="xs" /> Enabling…</>
                : <><i className="fa fa-unlock-alt" /> Enable</>}
            </button>

            <button
              type="button"
              onClick={() => handleAction('disable')}
              disabled={!!actionLoading || !wsConnected || !hasStatus || isDisabled === true}
              className="px-5 py-2 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm
                         flex items-center gap-2"
            >
              {actionLoading === 'disable'
                ? <><DuoSpinner size="xs" /> Disabling…</>
                : <><i className="fa fa-ban" /> Disable</>}
            </button>
          </div>

          {actionMsg && (
            <div className={`text-sm p-3 rounded-lg ${
              actionMsg.type === 'success'
                ? 'bg-green-50 text-green-700 border border-green-200'
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {actionMsg.text}
            </div>
          )}
        </div>
      </div>

      {/* Real-time USB event log */}
      <EventTable
        isLinux={isLinux}
        linuxEvents={linuxEvents}
        windowsEvents={windowsEvents}
        onClear={clearUsbEvents}
      />

      {/* Reason modal (same pattern as IP/Port control) */}
      {reasonModal &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
            role="dialog"
            aria-modal="true"
            onClick={() => !reasonSubmitting && closeReasonModal()}
          >
            <div
              ref={reasonModalRef}
              className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {reasonModal.action === 'enable' ? 'Enable USB storage' : 'Disable USB storage'}
              </h3>
              <p className="text-sm text-gray-600 mb-3">Enter a reason (required).</p>
              <textarea
                value={reason}
                onChange={(e) => setReason(sanitizeAsciiMultiLine(e.target.value, 300, false))}
                placeholder="e.g. Policy enforcement, Incident response, Temporary exception"
                className="w-full min-h-[80px] px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-y"
                autoFocus
              />
              <div className="flex justify-end gap-2 mt-4">
                <button
                  type="button"
                  onClick={closeReasonModal}
                  disabled={reasonSubmitting}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={submitReasonModal}
                  disabled={reasonSubmitting || !reason.trim()}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {reasonSubmitting ? 'Applying…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
};

export default NodesViewUsbControl;
