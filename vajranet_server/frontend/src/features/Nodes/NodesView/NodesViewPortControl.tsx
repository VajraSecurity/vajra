/**
 * NodesView Port Control tab: Allow/Block port rules.
 * API/WS: Backend port status and port allow/block actions.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import type { NodeData } from './types';
import { ERROR_MESSAGES, SUCCESS_MESSAGES } from './constants';
import { sanitizeAsciiMultiLine, sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import { useModalA11y } from '../../../hooks/useModalA11y';

/** Shape of each rule item returned by the agent status WS response */
interface AgentPortRule {
  action: string;   // e.g. "BLOCK"
  message: string;  // e.g. "Vajra Port Rule"
  port: string;     // e.g. "5555" or "N/A" for IP rules
  reason: string;   // e.g. "Vajra Port Rule"
}

interface NodesViewPortControlProps {
  node: NodeData;
  /** WebSocket connected state (shared from parent NodesView) */
  wsConnected: boolean;
  /** Send a message over the shared WebSocket */
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

/** Maximum ports allowed in a single range, so a wide range (e.g. "1:65535") can't
 *  expand into tens of thousands of sequential per-port agent WS commands. */
const MAX_PORT_RANGE_SIZE = 1000;

const isValidPort = (value: string): boolean => {
  if (!value.trim()) return false;
  // Only treat as a single port when there's no ':' — otherwise parseInt() on a
  // range like "800:" stops at the first non-digit char and would wrongly match here.
  if (!value.includes(':')) {
    const num = parseInt(value, 10);
    return Number.isInteger(num) && num >= 0 && num <= 65535;
  }
  const range = value.split(':').map((s) => parseInt(s.trim(), 10));
  if (range.length !== 2) return false;
  if (!range.every((n) => Number.isInteger(n) && n >= 0 && n <= 65535)) return false;
  if (range[0] > range[1]) return false;
  return range[1] - range[0] + 1 <= MAX_PORT_RANGE_SIZE;
};

/**
 * Expand a port range (e.g., "5555:5560") into individual ports.
 * Returns an array of port numbers.
 */
const expandPortRange = (portInput: string): number[] => {
  const trimmed = portInput.trim();
  const parts = trimmed.split(':');
  
  if (parts.length === 1) {
    // Single port
    const port = parseInt(parts[0], 10);
    return Number.isInteger(port) && port >= 0 && port <= 65535 ? [port] : [];
  }
  
  if (parts.length === 2) {
    // Port range
    const start = parseInt(parts[0].trim(), 10);
    const end = parseInt(parts[1].trim(), 10);
    
    if (!Number.isInteger(start) || !Number.isInteger(end)) return [];
    if (start < 0 || end > 65535 || start > end) return [];
    if (end - start + 1 > MAX_PORT_RANGE_SIZE) return [];

    const ports: number[] = [];
    for (let i = start; i <= end; i++) {
      ports.push(i);
    }
    return ports;
  }
  
  return [];
};

const NodesViewPortControl = ({ node, wsConnected, wsSendMessage }: NodesViewPortControlProps) => {
  const [port, setPort] = useState('');
  const [action, setAction] = useState<'allow' | 'block'>('block');
  const [trafficType, setTrafficType] = useState<'all' | 'in' | 'out'>('all');
  const [manualEntry, setManualEntry] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [activeRules, setActiveRules] = useState<AgentPortRule[]>([]);
  const [listeningPorts, setListeningPorts] = useState<string[]>([]);
  const [loadingPorts, setLoadingPorts] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingRules, setLoadingRules] = useState(false);
  // "The agent didn't answer" must stay distinguishable from "the host has no
  // open ports" / "no rules are in force" — both are security claims.
  const [portsError, setPortsError] = useState(false);
  const [rulesError, setRulesError] = useState(false);
  const [reasonModal, setReasonModal] = useState<
    | null
    | {
        mode: 'apply' | 'remove';
        port: string;
        nextAction: 'allow' | 'block';
        trafficType?: 'all' | 'in' | 'out';
      }
  >(null);
  const [reason, setReason] = useState('');
  const [reasonSubmitting, setReasonSubmitting] = useState(false);

  const hostId = node.host_identifier || String(node.id);
  
  // Use shared WebSocket from parent NodesView
  const connected = wsConnected;
  const sendMessage = wsSendMessage;

  /**
   * Safely parse a port rules JSON string from the agent.
   * Handles "null" (Go nil-slice serialization), malformed JSON, and non-array shapes.
   * Filters out IP-only rows (port === "N/A" or "Any") and deduplicates by port+action.
   */
  const safeParsePortRules = (raw: string | null | undefined): AgentPortRule[] => {
    try {
      const parsed: unknown = JSON.parse(raw ?? '[]');
      if (!Array.isArray(parsed)) return [];
      const seen = new Set<string>();
      return parsed.filter((r: unknown): r is AgentPortRule => {
        if (!r || typeof r !== 'object') return false;
        const rule = r as { port?: unknown; action?: unknown };
        if (!rule.port || rule.port === 'N/A' || rule.port === 'Any') return false;
        const key = `${rule.port}|${rule.action}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    } catch {
      return [];
    }
  };

  /** Fetch existing blocked ports from the agent via WebSocket */
  const fetchActiveRules = useCallback(async () => {
    if (!connected) return;
    try {
      setLoadingRules(true);
      setRulesError(false);
      const response = await sendMessage({
        type: 'agent',
        params: { agent: 'status', arg1: 'port' },
        host_identifier: hostId,
      });
      setActiveRules(safeParsePortRules(response.response as string | null | undefined));
    } catch (error) {
      console.error('Failed to fetch active port rules via WS:', error);
      setRulesError(true);
      setActiveRules([]);
      setMessage({ type: 'error', text: 'Failed to load active port rules from agent' });
    } finally {
      setLoadingRules(false);
    }
  }, [connected, sendMessage, hostId]);

  /** Fetch listening ports from node via osquery WebSocket */
  const fetchListeningPorts = useCallback(async () => {
    if (!connected) return;
    try {
      setLoadingPorts(true);
      setPortsError(false);
      const response = await sendMessage({
        type: 'osquery',
        params: { arg1: 'SELECT DISTINCT port FROM listening_ports WHERE port <> 0' },
        host_identifier: hostId,
      });

      const parsed = JSON.parse(String(response.response ?? '{"response":[]}'));
      // parsed can be null when Go serializes a nil slice as "null" — guard before accessing .response
      const rows: { port: string }[] = Array.isArray(parsed) ? parsed : (parsed != null ? (parsed.response ?? []) : []);
      const ports = rows
        .map((r) => r.port)
        .filter(Boolean)
        .sort((a, b) => Number(a) - Number(b));
      setListeningPorts(ports);
    } catch (error) {
      console.error('Failed to fetch listening ports:', error);
      setPortsError(true);
      setListeningPorts([]);
    } finally {
      setLoadingPorts(false);
    }
  }, [connected, sendMessage, hostId]);

  // Fetch active port rules & listening ports once when WS connects (guard against double-fire)
  const hasFetchedRef = useRef(false);
  useEffect(() => {
    if (connected && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchActiveRules();
      fetchListeningPorts();
    }
    if (!connected) {
      hasFetchedRef.current = false;
    }
  }, [connected, fetchActiveRules, fetchListeningPorts]);

  // Auto-clear message after 5 seconds
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  const openReasonModal = (payload: NonNullable<typeof reasonModal>) => {
    setReasonModal(payload);
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
      setMessage({ type: 'error', text: 'Reason is required.' });
      return;
    }

    setMessage(null);
    setLoading(true);
    setReasonSubmitting(true);
    try {
      // Expand port range into individual ports
      const ports = expandPortRange(reasonModal.port);
      if (ports.length === 0) {
        throw new Error('Invalid port or port range');
      }

      // Send each port individually to the websocket
      let lastResponse: { status?: string; message?: string; response?: unknown } | null = null;
      for (const singlePort of ports) {
        const response = await sendMessage({
          type: 'agent' as const,
          params: {
            agent: 'port' as const,
            action: reasonModal.nextAction,
            arg1: String(singlePort),
            ...(reasonModal.trafficType ? { arg2: reasonModal.trafficType } : {}),
            arg3: reason.trim(),
            reason: reason.trim(),
          },
          host_identifier: hostId,
        });

        if (response.status === 'error') {
          throw new Error(response.message || 'Agent failed to apply port rule');
        }
        lastResponse = response;
      }

      // Update rules after all ports have been sent
      if (lastResponse) {
        setActiveRules(safeParsePortRules(lastResponse.response as string | null | undefined));
      }
      
      setMessage({
        type: 'success',
        text: reasonModal.mode === 'remove' ? 'Port rule removed successfully' : 
              ports.length === 1 ? SUCCESS_MESSAGES.PORT_UPDATED : 
              `${ports.length} ports updated successfully`,
      });
      if (reasonModal.mode === 'apply') setPort('');
      closeReasonModal();
    } catch (error: unknown) {
      console.error('Port control error:', error);
      setMessage({ type: 'error', text: (error instanceof Error && error.message) || 'Failed to update port rule.' });
    } finally {
      setLoading(false);
      setReasonSubmitting(false);
    }
  };

  const handleSave = async () => {
    if (!port.trim()) {
      setMessage({ type: 'error', text: ERROR_MESSAGES.EMPTY_PORT });
      return;
    }
    if (!isValidPort(port)) {
      setMessage({ type: 'error', text: ERROR_MESSAGES.INVALID_PORT });
      return;
    }
    if (!connected) {
      setMessage({ type: 'error', text: 'WebSocket not connected. Please wait or refresh the page.' });
      return;
    }

    openReasonModal({
      mode: 'apply',
      port: port.trim(),
      nextAction: action,
      trafficType,
    });
  };

  const handleRemoveActiveRule = async (rulePort: string, ruleAction: string) => {
    if (!connected) {
      setMessage({ type: 'error', text: 'WebSocket not connected' });
      return;
    }

    // The agent's port dispatcher only handles 'allow' and 'block'.
    // 'allow' calls AllowPortTraffic() which runs Remove-NetFirewallRule on the
    // matching 'Vajra Port Rule' block entry — this is the correct removal path.
    if (ruleAction.toUpperCase() === 'BLOCK') {
      openReasonModal({
        mode: 'remove',
        port: rulePort,
        nextAction: 'allow',
      });
    } else {
      // Allow-type rows have nothing to remove via this control; surface that
      // instead of silently doing nothing (the button is also disabled for
      // these rows, this is a defensive fallback).
      setMessage({ type: 'error', text: 'Only blocked-port rules can be removed here.' });
    }
  };

  const handlePortChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    let value = sanitizeAsciiSingleLine(e.target.value, 11, false);

    // allow only numbers and colon
    value = value.replace(/[^0-9:]/g, "");

    const parts = value.split(":");

    // allow only one colon (range format)
    if (parts.length > 2) {
      setMessage({
        type: "error",
        text: "Only one ':' allowed for port range",
      });
      return;
    }

    for (const part of parts) {
      if (!part) continue;

      const num = parseInt(part, 10);

      if (num > 65535) {
        setMessage({
          type: "error",
          text: `Invalid port "${part}". Port must be between 0 and 65535.`,
        });
        return;
      }
    }

    // ensure range start <= end
    if (parts.length === 2 && parts[0] && parts[1]) {
      const start = parseInt(parts[0], 10);
      const end = parseInt(parts[1], 10);

      if (start > end) {
        setMessage({
          type: "error",
          text: "Port range start must be less than or equal to end",
        });
        return;
      }

      if (end - start + 1 > MAX_PORT_RANGE_SIZE) {
        setMessage({
          type: "error",
          text: `Port range too large. Maximum ${MAX_PORT_RANGE_SIZE} ports allowed.`,
        });
        return;
      }
    }

    setPort(value);
    setMessage(null);
  };

  const handlePortKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const allowed = [
      "Backspace",
      "Delete",
      "ArrowLeft",
      "ArrowRight",
      "Tab",
      ":"
    ];

    if (!/[0-9]/.test(e.key) && !allowed.includes(e.key)) {
      e.preventDefault();
    }
  };

  return (
    <div className="p-4 flex flex-col lg:flex-row gap-6">
      {/* Left Panel - Add Port Rule */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden shrink-0 w-full max-w-md">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
          <h6 className="font-semibold text-gray-800">Port Control</h6>
          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${connected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            {connected ? 'Agent Connected' : 'Agent Disconnected'}
          </span>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
            <label className="flex items-center gap-2 mb-2">
              <input
                type="checkbox"
                checked={manualEntry}
                onChange={(e) => {
                  setManualEntry(e.target.checked);
                  setPort('');
                }}
                className="rounded border-gray-300 text-blue-600"
                disabled={loading}
              />
              <span className="text-sm text-gray-600">Manual entry</span>
            </label>
            {manualEntry ? (
              <input
              type="text"
              value={port}
              onChange={handlePortChange}
              onKeyDown={handlePortKeyDown}
              placeholder="e.g. 80 or 8080:8090"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
              disabled={loading}

            />
            ) : (
              <>
                <select
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className={`w-full rounded-lg border px-3 py-2 text-sm ${portsError ? 'border-amber-400' : 'border-gray-300'}`}
                  disabled={loading || loadingPorts}
                >
                  <option value="">Select a port</option>
                  {loadingPorts ? (
                    <option disabled>Loading...</option>
                  ) : portsError ? (
                    <option disabled>Couldn&apos;t load listening ports</option>
                  ) : listeningPorts.length === 0 ? (
                    <option disabled>No listening ports</option>
                  ) : (
                    listeningPorts.map((p) => (
                      <option key={p} value={p}>{p}</option>
                    ))
                  )}
                </select>
                {portsError && !loadingPorts && (
                  <p className="mt-1.5 flex items-center gap-2 text-xs text-amber-700" role="alert">
                    <i className="fa fa-triangle-exclamation" aria-hidden="true" />
                    <span>The agent didn&apos;t return the listening ports — this is not an empty list.</span>
                    <button
                      type="button"
                      onClick={fetchListeningPorts}
                      disabled={!connected || loadingPorts}
                      className="font-semibold text-blue-600 hover:text-blue-800 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Retry
                    </button>
                  </p>
                )}
              </>
            )}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Action</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  name="portAction"
                  checked={action === 'allow'}
                  onChange={() => setAction('allow')}
                  className="text-blue-600"
                  disabled={loading}
                />
                <span className="text-sm">Allow</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  name="portAction"
                  checked={action === 'block'}
                  onChange={() => setAction('block')}
                  className="text-blue-600"
                  disabled={loading}
                />
                <span className="text-sm">Block</span>
              </label>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Traffic type</label>
            <div className="flex gap-4 flex-wrap">
              {(['all', 'in', 'out'] as const).map((t) => (
                <label key={t} className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="portTraffic"
                    checked={trafficType === t}
                    onChange={() => setTrafficType(t)}
                    className="text-blue-600"
                    disabled={loading}
                  />
                  <span className="text-sm capitalize">{t}</span>
                </label>
              ))}
            </div>
          </div>
          {message && (
            <div className={`text-sm p-3 rounded-lg ${
              message.type === 'success' 
                ? 'bg-green-50 text-green-700 border border-green-200' 
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {message.text}
            </div>
          )}
          <button
            type="button"
            onClick={handleSave}
            disabled={loading || !connected}
            className="w-full py-2 bg-amber-500 text-white rounded-lg font-medium hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Applying...' : 'Save changes'}
          </button>
        </div>
      </div>

      {/* Right Panel - Active Blocked Ports from Agent */}
      <div className="flex-1 min-w-0 flex flex-col gap-6">
        {/* Active Blocked Ports (fetched from agent via WebSocket) */}
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b border-blue-100 flex items-center justify-between">
            <h6 className="font-semibold text-gray-800">Active Blocked Ports ({rulesError ? '—' : activeRules.length})</h6>
            <button
              type="button"
              onClick={fetchActiveRules}
              disabled={loadingRules || !connected}
              className="text-xs text-blue-600 hover:text-blue-800 font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1 rounded-lg"
            >
              <i className={`fa fa-sync-alt ${loadingRules ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
          <div className="p-4 overflow-auto max-h-[400px]">
            {loadingRules ? (
              <p className="text-gray-500 text-sm text-center py-8">Fetching blocked ports from agent...</p>
            ) : rulesError ? (
              <div className="text-center py-8" role="alert">
                <p className="text-sm font-medium text-amber-700">
                  <i className="fa fa-triangle-exclamation mr-2" aria-hidden="true" />
                  Couldn&apos;t load the port rules from the agent
                </p>
                <p className="mt-1 text-xs text-gray-500">The rules in force on this node are unknown, not absent.</p>
                <button
                  type="button"
                  onClick={fetchActiveRules}
                  disabled={!connected || loadingRules}
                  className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-xs font-semibold text-gray-700 transition-colors hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <i className="fa fa-sync-alt" aria-hidden="true" />
                  Retry
                </button>
              </div>
            ) : activeRules.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No blocked ports detected on this node.</p>
            ) : (
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr className="text-left">
                    <th className="sticky top-0 z-10 py-2 pr-4 pl-0 font-semibold text-gray-700 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Port</th>
                    <th className="sticky top-0 z-10 py-2 pr-4 font-semibold text-gray-700 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Action</th>
                    <th className="sticky top-0 z-10 py-2 pr-4 font-semibold text-gray-700 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Reason</th>
                    <th className="sticky top-0 z-10 py-2 font-semibold text-gray-700 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {activeRules.map((rule, idx) => (
                    <tr key={`${rule.port}-${rule.action}-${idx}`} className="border-b last:border-0 hover:bg-gray-50">
                      <td className="py-3 pr-4 font-mono font-medium">{rule.port}</td>
                      <td className="py-3 pr-4">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          rule.action.toUpperCase() === 'BLOCK'
                            ? 'bg-red-100 text-red-700'
                            : 'bg-green-100 text-green-700'
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                      <td className="py-3 pr-4 text-gray-600">{rule.reason || rule.message}</td>
                      <td className="py-3">
                        <button
                          type="button"
                          onClick={() => handleRemoveActiveRule(rule.port, rule.action)}
                          disabled={loading || !connected || rule.action.toUpperCase() !== 'BLOCK'}
                          title={rule.action.toUpperCase() === 'BLOCK' ? undefined : 'Only blocked-port rules can be removed here'}
                          className="text-red-600 hover:text-red-800 text-xs font-medium hover:underline disabled:opacity-50 disabled:cursor-not-allowed rounded-lg px-2.5 py-1.5 -mx-2.5 -my-1.5"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

      </div>

      {/* Reason modal (replaces window.prompt) */}
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
                {reasonModal.mode === 'remove'
                  ? `Remove port block (${reasonModal.port})`
                  : `${reasonModal.nextAction === 'block' ? 'Block' : 'Allow'} port (${reasonModal.port})`}
              </h3>
              <p className="text-sm text-gray-600 mb-3">Enter a reason (required).</p>
              <textarea
                value={reason}
                onChange={(e) => setReason(sanitizeAsciiMultiLine(e.target.value, 300, false))}
                placeholder="e.g. Temporary exception, Incident response, False positive"
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

export default NodesViewPortControl;
