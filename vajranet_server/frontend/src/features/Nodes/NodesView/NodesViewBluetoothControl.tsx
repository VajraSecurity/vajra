/**
 * NodesViewBluetoothControl
 *
 * Enable / Disable Bluetooth on the node.
 *
 * Windows:
 *   Enable:  { type:'agent', params:{ agent:'powershell', command_keys:['48'] } }
 *   Disable: { type:'agent', params:{ agent:'powershell', command_keys:['47'] } }
 *   Status:  { type:'agent', params:{ agent:'powershell', action:'allow', command_keys:['55'] } }
 *            → [{ command_key:'55', output: JSON }]
 *            → { fully_locked, radio_state, bthport_start, bthusb_start,
 *                bthserv_state, policy_csp, policy_gpo, device_class_deny }
 *
 * Linux (from agent/bluetooth/main.go):
 *   Enable:  { type:'agent', params:{ agent:'bluetooth', action:'enable' } }
 *            → "[{\"action\":\"enable\",\"message\":\"...\"}]"  (JSON-encoded array string)
 *   Disable: { type:'agent', params:{ agent:'bluetooth', action:'disable' } }
 *            → "[{\"action\":\"disable\",\"message\":\"...\"}]" (JSON-encoded array string)
 *   Status:  { type:'agent', params:{ agent:'bluetooth', action:'status' } }
 *            → "{\"radio_blocked\":bool,\"hard_blocked\":bool,\"service_active\":bool,
 *               \"service_enabled\":bool,\"service_masked\":bool,\"module_loaded\":bool,
 *               \"adapters\":[...]}"  (JSON-encoded object string)
 *
 * Status badge 5-state logic:
 *   service_masked && !module_loaded && radio_blocked  → Fully Disabled  (green)
 *   !service_masked && service_active && !radio_blocked → Fully Enabled  (blue)
 *   service_masked && module_loaded                    → Partial/Rebooting (amber)
 *   radio_blocked && !service_masked                   → Soft Blocked    (amber)
 *   hard_blocked                                       → HW Switch Off   (grey)
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { sanitizeAsciiMultiLine } from '../../../services/inputSanitizers';
import { useModalA11y } from '../../../hooks/useModalA11y';

// Windows status (PowerShell key 55)
interface WindowsBtStatus {
  fully_locked:      boolean;
  radio_state:       'Off' | 'On' | 'Unknown';
  bthport_start:     number | null;
  bthusb_start:      number | null;
  bthserv_state:     string;
  policy_csp:        number | null;
  policy_gpo:        number | null;
  device_class_deny: boolean;
}

// Linux status (agent/bluetooth/main.go → bluetoothStatus struct)
interface LinuxBtStatus {
  radio_blocked:   boolean;  // rfkill soft-blocked
  hard_blocked:    boolean;  // rfkill hard-blocked (physical switch)
  service_active:  boolean;  // bluetooth.service is running
  service_enabled: boolean;  // bluetooth.service starts on boot
  service_masked:  boolean;  // bluetooth.service is masked (cannot be started)
  module_loaded:   boolean;  // bluetooth kernel module is loaded
  adapters:        string[]; // HCI adapter names e.g. ["hci0"]
}

// Linux action response (enable/disable)
// Agent returns: [{ action: "enable"|"disable", message: "..." }]
interface LinuxBtActionResponse {
  action:  'enable' | 'disable';
  message: string;
}

interface NodesViewBluetoothControlProps {
  node:          NodeData;
  wsConnected:   boolean;
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

/**
 * Derive a single summary state from all Linux BT status fields. The condition
 * order matters — see the badge table in this file's header comment.
 */
type LinuxBtState = 'fully_disabled' | 'fully_enabled' | 'partial' | 'soft_blocked' | 'hw_blocked' | 'unknown';

const deriveLinuxState = (s: LinuxBtStatus): LinuxBtState => {
  if (s.hard_blocked) return 'hw_blocked';
  if (s.service_masked && !s.module_loaded && s.radio_blocked) return 'fully_disabled';
  if (!s.service_masked && s.service_active && !s.radio_blocked) return 'fully_enabled';
  if (s.service_masked && s.module_loaded) return 'partial';
  if (s.radio_blocked && !s.service_masked) return 'soft_blocked';
  return 'unknown';
};

// Status badge — the 5 states listed in this file's header comment. Must stay at
// module scope: inside the parent render body it gets a fresh function identity
// every render, so React discards and re-creates the badge on each status poll
// and WebSocket push instead of updating it.
const StatusBadge = ({
  loadingStatus,
  isLinux,
  linuxBtStatus,
  linuxState,
  windowsBtStatus,
}: {
  loadingStatus: boolean;
  isLinux: boolean;
  linuxBtStatus: LinuxBtStatus | null;
  linuxState: LinuxBtState;
  windowsBtStatus: WindowsBtStatus | null;
}) => {
  if (loadingStatus) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
        <DuoSpinner size="xs" /> Fetching…
      </span>
    );
  }

  if (isLinux) {
    if (!linuxBtStatus) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-400">
          — Unknown
        </span>
      );
    }
    switch (linuxState) {
      case 'fully_disabled':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
            ● Fully Disabled
          </span>
        );
      case 'fully_enabled':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
            ● Fully Enabled
          </span>
        );
      case 'partial':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">
            ● Partial / Rebooting
          </span>
        );
      case 'soft_blocked':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">
            ● Soft Blocked
          </span>
        );
      case 'hw_blocked':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">
            ● HW Switch Off
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
            ● Unknown
          </span>
        );
    }
  }

  // Windows
  if (!windowsBtStatus) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-400">
        — Unknown
      </span>
    );
  }
  if (windowsBtStatus.fully_locked) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
        ● Locked
      </span>
    );
  }
  if (windowsBtStatus.radio_state === 'Unknown') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
        ● Not installed
      </span>
    );
  }
  if (windowsBtStatus.radio_state === 'On') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
        ● Active
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">
      ● Partial
    </span>
  );
};

const NodesViewBluetoothControl = ({
  node,
  wsConnected,
  wsSendMessage,
}: NodesViewBluetoothControlProps) => {
  const hostId  = node.host_identifier || String(node.id);
  const isLinux = !(node.os_platform || '').toLowerCase().includes('windows');

  const [actionLoading, setActionLoading] = useState<'enable' | 'disable' | null>(null);
  const [actionMsg, setActionMsg]         = useState<{ type: 'success' | 'warning' | 'error'; text: string } | null>(null);
  const [reasonModal, setReasonModal] = useState<null | { action: 'enable' | 'disable' }>(null);
  const [reason, setReason] = useState('');
  const [reasonSubmitting, setReasonSubmitting] = useState(false);

  const [windowsBtStatus, setWindowsBtStatus] = useState<WindowsBtStatus | null>(null);
  const [linuxBtStatus,   setLinuxBtStatus]   = useState<LinuxBtStatus | null>(null);
  const [loadingStatus, setLoadingStatus]     = useState(false);

  // Fetch Bluetooth status
  const fetchBtStatus = useCallback(async () => {
    if (!wsConnected) return;
    setLoadingStatus(true);
    try {
      if (isLinux) {
        const response = await wsSendMessage({
          type: 'agent',
          params: { agent: 'bluetooth', action: 'status' },
          host_identifier: hostId,
        });
        // Agent returns status as a JSON-encoded object string in response.response
        const raw = typeof response.response === 'string'
          ? JSON.parse(response.response)
          : response.response;
        // Validate by checking a field that is always present in the schema
        if (raw && typeof raw === 'object' && 'service_active' in raw) {
          // Ensure adapters is always an array (agent guarantees this but defensive)
          if (!Array.isArray(raw.adapters)) raw.adapters = [];
          setLinuxBtStatus(raw as LinuxBtStatus);
        }
      } else {
        const response = await wsSendMessage({
          type: 'agent',
          params: { agent: 'powershell', action: 'allow', command_keys: ['55'] },
          host_identifier: hostId,
        });
        const items: Array<{ command_key: string; output: string }> =
          JSON.parse(String(response.response ?? '[]'));
        const item = items.find((i) => i.command_key === '55');
        if (item) setWindowsBtStatus(JSON.parse(item.output) as WindowsBtStatus);
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
      fetchBtStatus();
    }
    if (!wsConnected) {
      hasFetchedRef.current = false;
    }
  }, [wsConnected, fetchBtStatus]);

  // Auto-clear feedback after 6 s
  useEffect(() => {
    if (!actionMsg) return;
    const t = setTimeout(() => setActionMsg(null), 6000);
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
      let response: { status?: string; message?: string; response?: unknown } | undefined;
      if (isLinux) {
        response = await wsSendMessage({
          type: 'agent',
          params: {
            agent: 'bluetooth',
            action,
            arg1: reason.trim(),
            reason: reason.trim(),
          },
          host_identifier: hostId,
        });

        // Agent returns a JSON-encoded array string: [{"action":"...","message":"..."}]
        // Parse response.response to extract the actual message from the agent.
        const rawResponse = response?.response;
        if (typeof rawResponse === 'string') {
          try {
            const parsed: LinuxBtActionResponse[] = JSON.parse(rawResponse);
            if (Array.isArray(parsed) && parsed.length > 0) {
              const { message } = parsed[0];
              // A message containing "warnings" means partial success (caution state).
              if (message.includes('warnings')) {
                setActionMsg({
                  type: 'warning',
                  text: `Partial success: ${message}`,
                });
              } else {
                setActionMsg({
                  type: 'success',
                  text: message,
                });
              }
            } else {
              setActionMsg({ type: 'success', text: `Bluetooth ${action}d successfully.` });
            }
          } catch {
            setActionMsg({ type: 'error', text: rawResponse });
          }
        } else if (response?.status === 'error') {
          throw new Error(response.message || `Failed to ${action} Bluetooth`);
        } else {
          setActionMsg({ type: 'success', text: `Bluetooth ${action}d successfully.` });
        }
      } else {
        // Windows — PowerShell key 47 (disable) / 48 (enable)
        const commandKey = action === 'enable' ? '48' : '47';
        response = await wsSendMessage({
          type: 'agent',
          params: {
            agent: 'powershell',
            command_keys: [commandKey],
            arg1: reason.trim(),
            reason: reason.trim(),
          },
          host_identifier: hostId,
        });
        if (response?.status === 'error') {
          throw new Error(response.message || `Failed to ${action} Bluetooth`);
        }

        // Keys 47/48 return structured JSON: { radio, bthport, bthserv, rmsvc, policy, success }
        // Must check success=false to surface partial failures (e.g. Intune-blocked policy write)
        const psItems: Array<{ command_key: string; output?: string; error?: string }> =
          JSON.parse(String(response?.response ?? '[]'));
        const psItem = psItems.find((i) => i.command_key === commandKey);
        if (psItem?.error) {
          throw new Error(psItem.error);
        }
        let msgType: 'success' | 'warning' = 'success';
        let msgText = `Bluetooth ${action}d successfully.`;
        if (psItem?.output) {
          try {
            const result = JSON.parse(psItem.output) as Record<string, unknown>;
            if (result.success === false) {
              const failedFields = (
                ['radio', 'bthport', 'bthusb', 'bthserv', 'subsidiary', 'policy_csp', 'policy_gpo', 'device_class'] as const
              ).filter((f) => typeof result[f] === 'string' && (result[f] as string).startsWith('error:'));
              msgType = 'warning';
              msgText = failedFields.length > 0
                ? `Partial lockdown: ${failedFields.map((f) => `${f}=${result[f]}`).join(', ')}`
                : `Bluetooth ${action}: one or more steps failed.`;
            }
          } catch { /* non-JSON output — treat as success */ }
        }
        setActionMsg({ type: msgType, text: msgText });
      }

      closeReasonModal();
      fetchBtStatus();
    } catch (err: unknown) {
      setActionMsg({ type: 'error', text: (err instanceof Error && err.message) || `Failed to ${action} Bluetooth` });
    } finally {
      setActionLoading(null);
      setReasonSubmitting(false);
    }
  };

  // Enable / Disable
  const handleAction = (action: 'enable' | 'disable') => {
    openReasonModal(action);
  };

  // Derived Linux state
  const hasBtStatus = isLinux ? !!linuxBtStatus : !!windowsBtStatus;
  const linuxState: LinuxBtState = linuxBtStatus ? deriveLinuxState(linuxBtStatus) : 'unknown';


  return (
    <div className="p-4 flex flex-col gap-6">

      {/* Control panel */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h6 className="font-semibold text-gray-800">Bluetooth Control</h6>
              <StatusBadge
                loadingStatus={loadingStatus}
                isLinux={isLinux}
                linuxBtStatus={linuxBtStatus}
                linuxState={linuxState}
                windowsBtStatus={windowsBtStatus}
              />
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              {isLinux
                ? 'Enable or disable Bluetooth with a 5-layer hardware lockdown (rfkill, systemctl mask, modprobe blacklist).'
                : 'Enable or disable the Bluetooth radio on this node via PowerShell.'}
            </p>
            <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
            </span>
          </div>
          <button
            type="button"
            onClick={fetchBtStatus}
            disabled={loadingStatus || !wsConnected}
            className="rounded-lg text-xs text-blue-600 hover:text-blue-800 font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1 shrink-0 mt-1"
          >
            <i className={`fa fa-sync-alt ${loadingStatus ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Status detail row */}
        {isLinux ? (
          linuxBtStatus && (
            <div className="px-4 py-2 bg-gray-50 border-b border-blue-50 flex flex-wrap items-center gap-x-6 gap-y-1 text-xs text-gray-500">
              <span>
                Radio:{' '}
                <span className={`font-medium ${linuxBtStatus.radio_blocked ? 'text-red-600' : 'text-green-700'}`}>
                  {linuxBtStatus.hard_blocked
                    ? 'Hard blocked (HW switch)'
                    : linuxBtStatus.radio_blocked
                      ? 'Soft blocked (rfkill)'
                      : 'Unblocked'}
                </span>
              </span>
              <span>
                Kernel module:{' '}
                <span className={`font-medium ${linuxBtStatus.module_loaded ? 'text-green-700' : 'text-gray-500'}`}>
                  {linuxBtStatus.module_loaded ? 'Loaded' : 'Not loaded'}
                </span>
              </span>
              <span>
                Service:{' '}
                <span className={`font-medium ${
                  linuxBtStatus.service_masked
                    ? 'text-red-600'
                    : linuxBtStatus.service_active
                      ? 'text-green-700'
                      : 'text-gray-500'
                }`}>
                  {linuxBtStatus.service_masked
                    ? 'Masked'
                    : linuxBtStatus.service_active
                      ? 'Active'
                      : linuxBtStatus.service_enabled
                        ? 'Enabled (inactive)'
                        : 'Inactive'}
                </span>
              </span>
              <span>
                Adapters:{' '}
                {linuxBtStatus.adapters.length > 0 ? (
                  <span className="font-mono font-medium text-gray-700">
                    {linuxBtStatus.adapters.join(', ')}
                  </span>
                ) : linuxState === 'fully_enabled' ? (
                  // BT is enabled but no adapters were found — warn.
                  <span className="font-medium text-amber-600">None detected — hardware may be unsupported</span>
                ) : (
                  <span className="font-medium text-gray-400">None</span>
                )}
              </span>
            </div>
          )
        ) : null}

        <div className="p-4 space-y-4">
          <div className="flex gap-3 flex-wrap">
            <button
              type="button"
              onClick={() => handleAction('enable')}
              disabled={
                !!actionLoading ||
                !wsConnected ||
                !hasBtStatus ||
                (isLinux
                  // Disable enable button when already fully enabled or hw-blocked (can't override physical switch)
                  ? linuxState === 'fully_enabled' || linuxState === 'hw_blocked'
                  : windowsBtStatus?.radio_state === 'Unknown' ||
                    (windowsBtStatus !== null && !windowsBtStatus.fully_locked && windowsBtStatus.radio_state === 'On'))
              }
              className="px-5 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm
                         flex items-center gap-2"
            >
              {actionLoading === 'enable'
                ? <><DuoSpinner size="sm" className="text-white" /> Enabling…</>
                : <><i className="fa fa-bluetooth-b" /> Enable Bluetooth</>}
            </button>

            <button
              type="button"
              onClick={() => handleAction('disable')}
              disabled={
                !!actionLoading ||
                !wsConnected ||
                !hasBtStatus ||
                (isLinux
                  // Disable the disable button when already fully disabled or hw-blocked
                  ? linuxState === 'fully_disabled' || linuxState === 'hw_blocked'
                  : windowsBtStatus?.radio_state === 'Unknown' ||
                    (windowsBtStatus !== null && windowsBtStatus.fully_locked))
              }
              className="px-5 py-2 bg-slate-600 text-white rounded-lg font-medium hover:bg-slate-700
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm
                         flex items-center gap-2"
            >
              {actionLoading === 'disable'
                ? <><DuoSpinner size="sm" className="text-white" /> Disabling…</>
                : <><i className="fa fa-ban" /> Disable Bluetooth</>}
            </button>
          </div>

          {/* Hardware switch notice */}
          {isLinux && linuxState === 'hw_blocked' && (
            <div className="text-xs p-3 rounded-lg bg-gray-50 text-gray-600 border border-gray-200">
              <i className="fa fa-info-circle mr-1" />
              Bluetooth is hard-blocked by a physical hardware switch. The agent cannot override this — toggle the physical switch on the device.
            </div>
          )}

          {actionMsg && (
            <div className={`text-sm p-3 rounded-lg ${
              actionMsg.type === 'success'
                ? 'bg-green-50 text-green-700 border border-green-200'
                : actionMsg.type === 'warning'
                  ? 'bg-amber-50 text-amber-700 border border-amber-200'
                  : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {actionMsg.type === 'warning' && <i className="fa fa-exclamation-triangle mr-1" />}
              {actionMsg.text}
            </div>
          )}
        </div>
      </div>

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
                {reasonModal.action === 'enable' ? 'Enable Bluetooth' : 'Disable Bluetooth'}
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

export default NodesViewBluetoothControl;
