/**
 * NodesView IP Control tab: Allow/Block IP rules.
 * API/WS: Backend IP status and allow/block actions.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import type { NodeData } from './types';
import { ERROR_MESSAGES, SUCCESS_MESSAGES } from './constants';
import { sanitizeAsciiMultiLine, sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import { useModalA11y } from '../../../hooks/useModalA11y';

/** Shape of each rule item returned by the agent status WS response */
interface AgentIpRule {
  action: string;   // e.g. "BLOCK"
  message: string;  // e.g. "Vajra IP Rule"
  ip: string;       // e.g. "192.168.1.1"
  reason: string;   // e.g. "Vajra IP Rule"
}

interface NodesViewIPControlProps {
  node: NodeData;
  /** WebSocket connected state (shared from parent NodesView) */
  wsConnected: boolean;
  /** Send a message over the shared WebSocket */
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

/** Strip CIDR suffix returned by the agent (e.g. "10.10.10.10/32" → "10.10.10.10") */
const stripCidr = (ip: string): string => ip.split('/')[0];

const isValidIp = (value: string): boolean => {
  const parts = value.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
};

/** Build canonical dotted IP from four octet strings (digits only, 0–255 each). */
const octetsToCanonicalIp = (parts: [string, string, string, string]): string | null => {
  const trimmed = parts.map((p) => p.trim());
  if (trimmed.some((p) => !p || !/^\d{1,3}$/.test(p))) return null;
  const nums = trimmed.map((p) => parseInt(p, 10));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return nums.map((n) => String(n)).join('.');
};

const NodesViewIPControl = ({ node, wsConnected, wsSendMessage }: NodesViewIPControlProps) => {
  /** Each octet: up to 3 digits while typing; padded to 3 chars (e.g. 010) on blur when non-empty. */
  const [octets, setOctets] = useState<[string, string, string, string]>(['', '', '', '']);
  const octetInputRefs = useRef<(HTMLInputElement | null)[]>([null, null, null, null]);
  const [action, setAction] = useState<'allow' | 'block'>('block');
  const [trafficType, setTrafficType] = useState<'all' | 'in' | 'out'>('all');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [activeRules, setActiveRules] = useState<AgentIpRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingRules, setLoadingRules] = useState(false);
  const [reasonModal, setReasonModal] = useState<
    | null
    | {
        mode: 'apply' | 'remove';
        ip: string;
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
   * Safely parse an IP rules JSON string from the agent.
   * Handles "null" (Go nil-slice serialization), malformed JSON, and non-array shapes.
   * Deduplicates by ip+action.
   */
  const safeParseIpRules = (raw: string | null | undefined): AgentIpRule[] => {
    try {
      const parsed: unknown = JSON.parse(raw ?? '[]');
      if (!Array.isArray(parsed)) return [];
      const seen = new Set<string>();
      return parsed.filter((r: unknown): r is AgentIpRule => {
        if (!r || typeof r !== 'object') return false;
        const rule = r as { ip?: unknown; action?: unknown };
        if (!rule.ip) return false;
        const key = `${rule.ip}|${rule.action}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    } catch {
      return [];
    }
  };

  /** Fetch existing blocked IPs from the agent via WebSocket */
  const fetchActiveRules = useCallback(async () => {
    if (!connected) return;
    try {
      setLoadingRules(true);
      const response = await sendMessage({
        type: 'agent',
        params: { agent: 'status', arg1: 'ip' },
        host_identifier: hostId,
      });
      setActiveRules(safeParseIpRules(response.response as string | null | undefined));
    } catch (error) {
      console.error('Failed to fetch active IP rules via WS:', error);
      setMessage({ type: 'error', text: 'Failed to load active IP rules from agent' });
    } finally {
      setLoadingRules(false);
    }
  }, [connected, sendMessage, hostId]);

  // Fetch active IP rules once when WS connects (guard against double-fire)
  const hasFetchedRef = useRef(false);
  useEffect(() => {
    if (connected && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchActiveRules();
    }
    if (!connected) {
      hasFetchedRef.current = false;
    }
  }, [connected, fetchActiveRules]);

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
      const response = await sendMessage({
        type: 'agent' as const,
        params: {
          agent: 'ip' as const,
          action: reasonModal.nextAction,
          arg1: reasonModal.ip,
          ...(reasonModal.trafficType ? { arg2: reasonModal.trafficType } : {}),
          arg3: reason.trim(),
          reason: reason.trim(),
        },
        host_identifier: hostId,
      });

      if (response.status === 'error') {
        throw new Error(response.message || 'Agent failed to apply IP rule');
      }

      setActiveRules(safeParseIpRules(response.response as string | null | undefined));
      setMessage({
        type: 'success',
        text: reasonModal.mode === 'remove' ? 'IP rule removed successfully' : SUCCESS_MESSAGES.IP_ACTION_SUCCESS,
      });
      if (reasonModal.mode === 'apply') setOctets(['', '', '', '']);
      closeReasonModal();
    } catch (error: unknown) {
      console.error('IP control error:', error);
      setMessage({ type: 'error', text: (error instanceof Error && error.message) || 'Failed to update IP rule.' });
    } finally {
      setLoading(false);
      setReasonSubmitting(false);
    }
  };

  const handleSave = async () => {
    const ipCanonical = octetsToCanonicalIp(octets);
    if (!ipCanonical) {
      setMessage({ type: 'error', text: ERROR_MESSAGES.EMPTY_IP });
      return;
    }
    if (!isValidIp(ipCanonical)) {
      setMessage({ type: 'error', text: ERROR_MESSAGES.INVALID_IP });
      return;
    }
    if (!connected) {
      setMessage({ type: 'error', text: 'WebSocket not connected. Please wait or refresh the page.' });
      return;
    }

    openReasonModal({
      mode: 'apply',
      ip: ipCanonical,
      nextAction: action,
      trafficType,
    });
  };

  const handleRemoveActiveRule = async (ruleIp: string, ruleAction: string) => {
    if (!connected) {
      setMessage({ type: 'error', text: 'WebSocket not connected' });
      return;
    }

    // The agent's ip dispatcher only handles 'allow' and 'block'.
    // 'allow' calls AllowIPTraffic() which runs Remove-NetFirewallRule on the
    // matching 'Vajra IP Rule' block entry — this is the correct removal path.
    // There is no equivalent removal path for an existing 'allow' rule, so the
    // Remove control is disabled for those rows (see the table below); this
    // branch only guards against a stray call reaching here regardless.
    if (ruleAction.toUpperCase() === 'BLOCK') {
      openReasonModal({
        mode: 'remove',
        ip: stripCidr(ruleIp),
        nextAction: 'allow',
      });
    } else {
      setMessage({ type: 'error', text: 'Allow rules cannot be removed from this screen.' });
    }
  };

  const handleOctetChange = (index: number, e: React.ChangeEvent<HTMLInputElement>) => {
    const safe = sanitizeAsciiSingleLine(e.target.value, 3, false);
    const digitsOnly = safe.replace(/\D/g, '').slice(0, 3);
    if (digitsOnly === '') {
      setOctets((prev) => {
        const next = [...prev] as [string, string, string, string];
        next[index] = '';
        return next;
      });
      setMessage(null);
      return;
    }
    const n = parseInt(digitsOnly, 10);
    if (n > 255) {
      setMessage({
        type: 'error',
        text: 'Each octet must be between 0 and 255.',
      });
      return;
    }
    setOctets((prev) => {
      const next = [...prev] as [string, string, string, string];
      next[index] = digitsOnly;
      return next;
    });
    setMessage(null);
    if (digitsOnly.length === 3 && index < 3) {
      octetInputRefs.current[index + 1]?.focus();
    }
  };

  const handleOctetBlur = (index: number, e: React.FocusEvent<HTMLInputElement>) => {
    const v = e.target.value.trim();
    if (!v || !/^\d+$/.test(v)) return;
    const n = parseInt(v, 10);
    if (n > 255) return;
    setOctets((prev) => {
      const next = [...prev] as [string, string, string, string];
      next[index] = String(n).padStart(3, '0');
      return next;
    });
  };

  const handleOctetKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    const el = e.currentTarget;
    const pos = el.selectionStart ?? 0;
    const len = el.value.length;

    if (e.key === 'ArrowRight' && pos === len && index < 3) {
      e.preventDefault();
      octetInputRefs.current[index + 1]?.focus();
      return;
    }
    if (e.key === 'ArrowLeft' && pos === 0 && index > 0) {
      e.preventDefault();
      octetInputRefs.current[index - 1]?.focus();
      return;
    }
    if (e.key === '.' || e.key === 'Tab') {
      if (e.key === '.' && index < 3) {
        e.preventDefault();
        octetInputRefs.current[index + 1]?.focus();
      }
      return;
    }
    const nav = ['Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'Tab', 'Home', 'End'];
    if (!/[0-9]/.test(e.key) && !nav.includes(e.key) && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
    }
    if (e.key === 'Backspace' && len === 0 && index > 0) {
      octetInputRefs.current[index - 1]?.focus();
    }
  };

  const handleIpPaste = (e: React.ClipboardEvent) => {
    const text = sanitizeAsciiSingleLine(e.clipboardData.getData('text'), 64, true);
    const rawParts = text.split('.');
    if (rawParts.length !== 4) return;
    const parsed: string[] = [];
    for (const p of rawParts) {
      const d = p.replace(/\D/g, '').slice(0, 3);
      if (!d) return;
      const n = parseInt(d, 10);
      if (n > 255) {
        setMessage({ type: 'error', text: 'Each octet must be between 0 and 255.' });
        e.preventDefault();
        return;
      }
      parsed.push(String(n).padStart(3, '0'));
    }
    e.preventDefault();
    setOctets([parsed[0], parsed[1], parsed[2], parsed[3]] as [string, string, string, string]);
    setMessage(null);
    octetInputRefs.current[3]?.focus();
  };

  return (
    <div className="p-4 flex flex-col lg:flex-row gap-6">
      {/* Left Panel - Add IP Rule */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden shrink-0 w-full max-w-md">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
          <h6 className="font-semibold text-gray-800 flex items-center gap-2">
            <i className="fa fa-shield-alt text-blue-600" /> IP Control
          </h6>
          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${connected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            {connected ? 'Agent Connected' : 'Agent Disconnected'}
          </span>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">IP address</label>
            <div
              className="flex items-center gap-1 flex-wrap rounded-lg border border-gray-300 px-2 py-2 bg-white"
              onPaste={handleIpPaste}
            >
              {([0, 1, 2, 3] as const).map((i) => (
                <span key={i} className="flex items-center gap-1">
                  <input
                    ref={(el) => {
                      octetInputRefs.current[i] = el;
                    }}
                    type="text"
                    inputMode="numeric"
                    autoComplete="off"
                    aria-label={`IP octet ${i + 1} of 4`}
                    placeholder="___"
                    value={octets[i]}
                    onChange={(e) => handleOctetChange(i, e)}
                    onBlur={(e) => handleOctetBlur(i, e)}
                    onKeyDown={(e) => handleOctetKeyDown(i, e)}
                    maxLength={3}
                    disabled={loading}
                    className="w-[2.75rem] text-center font-mono text-sm tracking-widest border border-gray-200 rounded-md py-1.5 px-1 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder:text-gray-400"
                  />
                  {i < 3 && (
                    <span className="text-gray-500 font-mono text-sm select-none" aria-hidden>
                      .
                    </span>
                  )}
                </span>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Four groups of up to 3 digits (0–255). Paste a full IP to fill all fields. Octets pad to 3 digits on blur (e.g. 010).
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Action</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  name="ipAction"
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
                  name="ipAction"
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
                    name="ipTraffic"
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

      {/* Right Panel - Active Blocked IPs from Agent */}
      <div className="flex-1 min-w-0 flex flex-col gap-6">
        {/* Active Blocked IPs (fetched from agent via WebSocket) */}
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b border-blue-100 flex items-center justify-between">
            <h6 className="font-semibold text-gray-800">Active Blocked IPs ({activeRules.length})</h6>
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
              <p className="text-gray-500 text-sm text-center py-8">Fetching blocked IPs from agent...</p>
            ) : activeRules.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No blocked IPs detected on this node.</p>
            ) : (
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr className="text-left">
                    <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">IP Address</th>
                    <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Action</th>
                    <th className="pb-2 pr-4 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Reason</th>
                    <th className="pb-2 font-semibold text-gray-700 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {activeRules.map((rule, idx) => (
                    <tr key={`${rule.ip}-${rule.action}-${idx}`} className="border-b last:border-0 hover:bg-gray-50">
                      <td className="py-3 pr-4 font-mono font-medium">{stripCidr(rule.ip)}</td>
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
                          onClick={() => handleRemoveActiveRule(rule.ip, rule.action)}
                          disabled={loading || !connected || rule.action.toUpperCase() !== 'BLOCK'}
                          title={rule.action.toUpperCase() !== 'BLOCK' ? 'Allow rules cannot be removed from this screen.' : undefined}
                          className="text-red-600 hover:text-red-800 text-xs font-medium hover:underline disabled:opacity-50 disabled:cursor-not-allowed rounded-lg"
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
                  ? `Remove IP block (${reasonModal.ip})`
                  : `${reasonModal.nextAction === 'block' ? 'Block' : 'Allow'} IP (${reasonModal.ip})`}
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

export default NodesViewIPControl;
