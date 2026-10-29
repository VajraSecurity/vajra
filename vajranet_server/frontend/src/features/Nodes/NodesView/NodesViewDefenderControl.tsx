/**
 * NodesViewDefenderControl
 *
 * Production Windows Defender surface:
 * - Structured status + telemetry rendering
 * - Per-service enable actions only when currently off
 * - Signature + scan actions
 * - Firewall profile management with per-profile and master enable actions
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import { useToast } from '../../../context/useToast';

interface PSResult {
  command_key: string;
  output?: string;
  error?: string;
  warning?: string;
  scan_status?: unknown;
}

interface DefenderStatus {
  AMServiceEnabled: boolean;
  AntivirusEnabled: boolean;
  AntivirusSignatureAge: number;
  AntispywareEnabled: boolean;
  AntispywareSignatureAge: number;
  BehaviorMonitorEnabled: boolean;
  IoavProtectionEnabled: boolean;
  IsTamperProtected: boolean | null;
  NISEnabled: boolean;
  OnAccessProtectionEnabled: boolean;
  RealTimeProtectionEnabled: boolean;
  ScriptScanningEnabled?: boolean;
}

interface FirewallProfileDetail {
  Name: string;
  Enabled: boolean;
  DefaultInboundAction?: string;
  DefaultOutboundAction?: string;
}

interface ScanEvent {
  time?: string;
  event_id?: number;
  level?: string;
  message?: string;
}

interface LastScanStatus {
  quick_scan_age?: number;
  quick_scan_end_time?: string;
  full_scan_age?: number;
  full_scan_end_time?: string;
  last_task_name?: string;
  last_task_state?: string;
  last_task_result?: number;
  last_task_last_run_time?: string;
  recent_scan_events?: ScanEvent[];
}

interface SignatureTelemetry {
  AntivirusSignatureVersion?: string;
  AntispywareSignatureVersion?: string;
  AntivirusSignatureLastUpdated?: string;
  AntispywareSignatureLastUpdated?: string;
  QuickScanAge?: number;
  FullScanAge?: number;
  QuickScanEndTime?: string;
  FullScanEndTime?: string;
  [k: string]: unknown;
}

interface NodesViewDefenderControlProps {
  node: NodeData;
  wsConnected: boolean;
  wsSendMessage: (message: unknown, options?: { timeoutMs?: number }) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

function StatusDot({ enabled }: { enabled: boolean | null | undefined }) {
  if (enabled === null || enabled === undefined) {
    return <span className="inline-block w-2 h-2 rounded-full bg-gray-400" title="N/A" />;
  }
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${enabled ? 'bg-green-500' : 'bg-red-500'}`}
      title={enabled ? 'Enabled' : 'Disabled'}
    />
  );
}

function toObj(raw: unknown): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(String(raw ?? ''));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function toArr<T>(raw: unknown): T[] {
  try {
    const parsed = JSON.parse(String(raw ?? '[]'));
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

/**
 * Parses a date string to a localised display value.
 * Handles both ISO-8601 and the .NET WCF JSON date format: /Date(1234567890000)/
 */
function toLocal(value: unknown): string {
  if (!value) return 'N/A';
  const str = String(value);
  // .NET WCF JSON date: /Date(milliseconds)/ or /Date(milliseconds+0530)/
  const dotNet = str.match(/^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/);
  if (dotNet) {
    const ts = parseInt(dotNet[1], 10);
    if (!Number.isNaN(ts)) return new Date(ts).toLocaleString();
    return 'N/A';
  }
  const d = new Date(str);
  if (Number.isNaN(d.getTime())) return str;
  return d.toLocaleString();
}

function extractIssues(results: PSResult[]): string[] {
  const errs = results.filter((r) => r.error && String(r.error).trim() !== '').map((r) => String(r.error));
  const warns = results.filter((r) => r.warning && String(r.warning).trim() !== '').map((r) => String(r.warning));
  return [...errs, ...warns];
}

const BLOCKER_LABELS: Record<string, string> = {
  tamper_protection_enabled: 'Windows Tamper Protection is blocking the write',
  passive_mode:              'Defender is in passive mode (observation-only)',
  disable_antivirus_policy:  'Group Policy DisableAntiVirus is set',
  disable_realtime_policy:   'Group Policy DisableRealtimeMonitoring is set',
  blocked_or_managed:        'MDM/Intune managed — setting is policy-controlled',
};

// Structured capability response panel: renders the post-verification object
// returned by the Defender capability mutations. Showing parsed fields instead
// of raw JSON avoids redundancy with the capability indicators above and
// surfaces actionable blocker info. Must stay at module scope — defined inside
// NodesViewDefenderControl's render body it gets a new identity every render,
// so React unmounts and remounts the whole panel on each status poll. It only
// reads its `output` prop, so no extra plumbing is needed.
const CapabilityResponsePanel = ({ output }: { output: Record<string, unknown> }) => {
  const applied = output.applied as boolean | undefined;
  const capability = String(output.capability ?? '').replace(/_/g, ' ');
  const amMode = output.am_running_mode as string | undefined;
  const tamper = output.is_tamper_protected as boolean | undefined;
  const avPolicy = output.disable_antivirus_policy;
  const rtPolicy = output.disable_realtime_policy;
  const note = output.note as string | undefined;
  const tamperReg = output.tamper_protection_registry as number | null | undefined;

  return (
    <div className="space-y-2 text-xs">
      <div className="flex items-center gap-2 flex-wrap">
        {capability && (
          <span className="text-gray-700 font-semibold capitalize">{capability}</span>
        )}
        {applied !== undefined && (
          <span className={`px-2 py-0.5 rounded font-semibold border text-[11px] ${applied ? 'bg-green-50 text-green-700 border-green-200' : 'bg-red-50 text-red-700 border-red-200'}`}>
            {applied ? '✓ Applied' : '✗ Not Applied'}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-1.5">
        {amMode && (
          <div className="rounded bg-white border border-gray-200 px-2 py-1.5">
            <p className="text-[10px] text-gray-500 font-medium uppercase">AM Running Mode</p>
            <p className="text-gray-800 font-medium mt-0.5">{amMode}</p>
          </div>
        )}
        {tamper !== undefined && (
          <div className="rounded bg-white border border-gray-200 px-2 py-1.5">
            <p className="text-[10px] text-gray-500 font-medium uppercase">Tamper Protected</p>
            <p className={`font-medium mt-0.5 ${tamper ? 'text-green-700' : 'text-amber-600'}`}>{tamper ? 'Yes' : 'No'}</p>
          </div>
        )}
        {avPolicy !== undefined && avPolicy !== null && (
          <div className="rounded bg-white border border-red-200 px-2 py-1.5">
            <p className="text-[10px] text-gray-500 font-medium uppercase">AV Policy Block</p>
            <p className="text-red-700 font-medium mt-0.5">DWORD = {String(avPolicy)}</p>
          </div>
        )}
        {rtPolicy !== undefined && rtPolicy !== null && (
          <div className="rounded bg-white border border-red-200 px-2 py-1.5">
            <p className="text-[10px] text-gray-500 font-medium uppercase">Realtime Policy Block</p>
            <p className="text-red-700 font-medium mt-0.5">DWORD = {String(rtPolicy)}</p>
          </div>
        )}
      </div>
      {capability.includes('tamper') && applied === false && tamperReg === 5 && (
        <div className="flex items-start gap-1.5 rounded bg-amber-50 border border-amber-200 px-2 py-1.5">
          <i className="fa fa-triangle-exclamation text-amber-500 mt-0.5 shrink-0" />
          <p className="text-amber-700">Tamper Protection requires MDM/Intune enrollment — registry change applied but not enforced.</p>
        </div>
      )}
      {note && !(capability.includes('tamper') && applied === false && tamperReg === 5) && (
        <div className="flex items-start gap-1.5 rounded bg-amber-50 border border-amber-200 px-2 py-1.5">
          <i className="fa fa-triangle-exclamation text-amber-500 mt-0.5 shrink-0" />
          <p className="text-amber-700">{BLOCKER_LABELS[note] ?? note}</p>
        </div>
      )}
      {(output.profile_name !== undefined || output.enabled !== undefined) && (
        <div className="grid grid-cols-2 gap-1.5">
          {output.profile_name !== undefined && (
            <div className="rounded bg-white border border-gray-200 px-2 py-1.5">
              <p className="text-[10px] text-gray-500 font-medium uppercase">Profile</p>
              <p className="text-gray-800 font-medium mt-0.5">{String(output.profile_name)}</p>
            </div>
          )}
          {output.enabled !== undefined && (
            <div className="rounded bg-white border border-gray-200 px-2 py-1.5">
              <p className="text-[10px] text-gray-500 font-medium uppercase">Enabled</p>
              <p className={`font-medium mt-0.5 ${output.enabled ? 'text-green-700' : 'text-red-600'}`}>{output.enabled ? 'Yes' : 'No'}</p>
            </div>
          )}
        </div>
      )}
      {Array.isArray(output.profiles) && (output.profiles as FirewallProfileDetail[]).length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] text-gray-500 font-medium uppercase">Profiles</p>
          {(output.profiles as FirewallProfileDetail[]).map((prof) => (
            <div key={prof.Name} className="flex items-center gap-2 rounded bg-white border border-gray-200 px-2 py-1">
              <StatusDot enabled={prof.Enabled} />
              <span className="text-gray-800 font-medium text-xs">{prof.Name}</span>
              {prof.DefaultInboundAction && prof.DefaultInboundAction !== '0' && (
                <span className="text-[10px] text-gray-500">In: {prof.DefaultInboundAction}</span>
              )}
              {prof.DefaultOutboundAction && prof.DefaultOutboundAction !== '0' && (
                <span className="text-[10px] text-gray-500">Out: {prof.DefaultOutboundAction}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const NodesViewDefenderControl = ({ node, wsConnected, wsSendMessage }: NodesViewDefenderControlProps) => {
  const WS_DEFENDER_TIMEOUT_MS = 45_000;
  const hostId = node.host_identifier || String(node.id);
  const { showToast } = useToast();

  const [defenderStatus, setDefenderStatus] = useState<DefenderStatus | null>(null);
  const [firewallProfilesDetail, setFirewallProfilesDetail] = useState<FirewallProfileDetail[]>([]);
  const [signatureTelemetry, setSignatureTelemetry] = useState<SignatureTelemetry | null>(null);
  const [lastScanStatus, setLastScanStatus] = useState<LastScanStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [customScanPath, setCustomScanPath] = useState('C:\\Users\\Public\\Downloads');
  const [lastMutationOutput, setLastMutationOutput] = useState<Record<string, unknown> | null>(null);

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
      }, { timeoutMs: WS_DEFENDER_TIMEOUT_MS });
      const parsed = JSON.parse(String(response?.response ?? '[]'));
      return Array.isArray(parsed) ? (parsed as PSResult[]) : [];
    },
    [hostId, wsSendMessage],
  );

  // Key 22 is a superset of key 21 — no need to fetch key 21 separately
  const parseStatus = (results: PSResult[]): void => {
    const r22 = results.find((r) => r.command_key === '22');
    const r64 = results.find((r) => r.command_key === '64');
    const r65 = results.find((r) => r.command_key === '65');
    const r69 = results.find((r) => r.command_key === '69');

    const s22 = r22?.output ? toObj(r22.output) : null;
    setDefenderStatus(s22 ? (s22 as unknown as DefenderStatus) : null);

    setFirewallProfilesDetail(r69?.output ? toArr<FirewallProfileDetail>(r69.output) : []);

    const s64 = r64?.output ? toObj(r64.output) : null;
    setSignatureTelemetry(s64 ? (s64 as SignatureTelemetry) : null);

    const s65 = r65?.output ? toObj(r65.output) : null;
    setLastScanStatus(s65 ? (s65 as LastScanStatus) : null);
  };

  const refreshStatus = useCallback(async () => {
    if (!wsConnected) return;
    setLoadingStatus(true);
    try {
      const results = await sendPS(['22', '64', '65', '69']);
      parseStatus(results);
      const issues = extractIssues(results);
      if (issues.length > 0) {
        showToast(`Status refresh warning: ${issues.join(' | ')}`, 'error');
      }
    } catch (err: unknown) {
      showToast((err instanceof Error && err.message) || 'Failed to fetch Defender status.', 'error');
    } finally {
      setLoadingStatus(false);
    }
  }, [sendPS, showToast, wsConnected]);

  const hasFetchedRef = useRef(false);
  useEffect(() => {
    if (wsConnected && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      refreshStatus();
    }
    if (!wsConnected) hasFetchedRef.current = false;
  }, [refreshStatus, wsConnected]);

  const runEnableAction = useCallback(async (actionId: string, label: string, commandKey: string) => {
    setActionLoading(actionId);
    try {
      const results = await sendPS([commandKey]);
      const own = results.find((r: PSResult) => r.command_key === commandKey);
      const postCheck = own?.output ? toObj(own.output) : null;
      setLastMutationOutput(postCheck);
      await refreshStatus();

      if (own?.error) {
        showToast(`${label}: ${own.error}`, 'error');
      } else if (postCheck && postCheck.applied === false) {
        showToast(`${label}: ${postCheck.note || 'Change not applied — may be policy-controlled.'}`, 'error');
      } else if (own?.warning) {
        const applied = postCheck?.applied;
        showToast(
          applied === false
            ? `${label}: ${postCheck?.note || 'Change not applied.'}`
            : `${label} enabled (with warning).`,
          applied === false ? 'error' : 'success',
        );
      } else {
        showToast(`${label} enabled successfully.`, 'success');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('job queue full')) {
        showToast('Agent busy — too many concurrent operations. Try again shortly.', 'error');
      } else {
        showToast(msg || `Failed to enable ${label}.`, 'error');
      }
    } finally {
      setActionLoading(null);
    }
  }, [refreshStatus, sendPS, showToast]);

  const refreshFirewallDetail = useCallback(async () => {
    if (!wsConnected) return;
    try {
      const results = await sendPS(['69']);
      const r69 = results.find((r: PSResult) => r.command_key === '69');
      setFirewallProfilesDetail(r69?.output ? toArr<FirewallProfileDetail>(r69.output) : []);
    } catch { /* non-fatal */ }
  }, [sendPS, wsConnected]);

  const runFirewallAction = useCallback(async (actionId: string, label: string, commandKey: string) => {
    setActionLoading(actionId);
    try {
      const results = await sendPS([commandKey]);
      const own = results.find((r: PSResult) => r.command_key === commandKey);
      const postCheck = own?.output ? toObj(own.output) : null;
      setLastMutationOutput(postCheck);
      const issues = extractIssues(results);
      await refreshFirewallDetail();
      if (issues.length > 0) {
        showToast(`${label}: ${issues.join(' | ')}`, 'error');
      } else if (postCheck && postCheck.applied === false) {
        showToast(`${label}: ${postCheck.note || 'Change not applied — may be policy-controlled.'}`, 'error');
      } else {
        showToast(`${label} applied successfully.`, 'success');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('job queue full')) {
        showToast('Agent busy — too many concurrent operations. Try again shortly.', 'error');
      } else {
        showToast(msg || `Failed to apply ${label}.`, 'error');
      }
    } finally {
      setActionLoading(null);
    }
  }, [refreshFirewallDetail, sendPS, showToast]);

  const runScanAction = useCallback(async (actionId: string, label: string, commandKey: string, arg1?: string) => {
    setActionLoading(actionId);
    try {
      const results = await sendPS([commandKey], arg1);
      const own = results.find((r) => r.command_key === commandKey);
      setLastMutationOutput(own?.output ? toObj(own.output) : null);
      if (own?.scan_status && typeof own.scan_status === 'object') {
        setLastScanStatus(own.scan_status as LastScanStatus);
      }
      const issues = extractIssues(results);
      await refreshStatus();
      if (issues.length === 0) {
        showToast(`${label} started successfully.`, 'success');
      } else {
        showToast(`${label}: ${issues.join(' | ')}`, 'error');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('job queue full')) {
        showToast('Agent busy — too many concurrent operations. Try again shortly.', 'error');
      } else {
        showToast(msg || `Failed to run ${label}.`, 'error');
      }
    } finally {
      setActionLoading(null);
    }
  }, [refreshStatus, sendPS, showToast]);

  const statusBadge = useMemo(() => {
    const s = defenderStatus;
    if (!s) return { label: 'Unknown', cls: 'bg-gray-100 text-gray-600' };
    if (!s.AMServiceEnabled) return { label: 'Service Stopped', cls: 'bg-red-100 text-red-700' };
    if (!s.RealTimeProtectionEnabled) return { label: 'Protection Reduced', cls: 'bg-amber-100 text-amber-700' };
    if (s.IsTamperProtected === false) return { label: 'Active (Tamper Off)', cls: 'bg-amber-100 text-amber-700' };
    return { label: 'Protected', cls: 'bg-green-100 text-green-700' };
  }, [defenderStatus]);

  const firewallAllEnabled = firewallProfilesDetail.length > 0 && firewallProfilesDetail.every((p: FirewallProfileDetail) => p.Enabled);

  const serviceRows: Array<{ id: string; label: string; enabled: boolean | null | undefined; enableKey: string }> = [
    { id: 'rtp',      label: 'Real-Time Protection', enabled: defenderStatus?.RealTimeProtectionEnabled,  enableKey: '20' },
    { id: 'behavior', label: 'Behavior Monitoring',  enabled: defenderStatus?.BehaviorMonitorEnabled,     enableKey: '25' },
    { id: 'ioav',     label: 'IOAV Protection',      enabled: defenderStatus?.IoavProtectionEnabled,      enableKey: '27' },
    { id: 'onaccess', label: 'On-Access Protection', enabled: defenderStatus?.OnAccessProtectionEnabled,  enableKey: '29' },
    { id: 'script',   label: 'Script Scanning',      enabled: defenderStatus?.ScriptScanningEnabled,      enableKey: '31' },
    { id: 'antispy',  label: 'Antispyware',           enabled: defenderStatus?.AntispywareEnabled,         enableKey: '33' },
    { id: 'service',  label: 'Defender Service',      enabled: defenderStatus?.AMServiceEnabled,           enableKey: '39' },
    { id: 'tamper',   label: 'Tamper Protection',     enabled: defenderStatus?.IsTamperProtected,          enableKey: '41' },
  ];

  const busy = loadingStatus || !!actionLoading;


  return (
    <div className="p-4 flex flex-col gap-6">
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h6 className="font-semibold text-gray-800 flex items-center gap-2">
                <i className="fa fa-shield-virus text-blue-600" /> Defender Controls
              </h6>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${statusBadge.cls}`}>{statusBadge.label}</span>
            </div>
            <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
            </span>
          </div>
          <button
            type="button"
            onClick={refreshStatus}
            disabled={busy || !wsConnected}
            className="rounded-lg text-xs text-blue-600 hover:text-blue-800 font-medium disabled:opacity-50 flex items-center gap-1"
          >
            <i className={`fa fa-sync-alt ${loadingStatus ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>

        <div className="p-4 grid grid-cols-1 xl:grid-cols-2 gap-4">
          {/* Protection Services */}
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200">
              <h6 className="font-semibold text-gray-800">Protection Services</h6>
              <p className="text-xs text-gray-500 mt-0.5">Enable is available only when a service is currently off.</p>
            </div>
            <div className="p-3 space-y-2">
              {serviceRows.map((row) => {
                const canEnable = row.enabled === false;
                const isUnknown = row.enabled === null || row.enabled === undefined;
                return (
                  <div key={row.id} className="flex items-center justify-between gap-3 py-2 border-b border-gray-100 last:border-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <StatusDot enabled={row.enabled} />
                      <span className="text-sm text-gray-800 truncate">{row.label}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-xs font-medium ${isUnknown ? 'text-gray-400' : row.enabled ? 'text-green-700' : 'text-red-600'}`}>
                        {isUnknown ? 'N/A' : row.enabled ? 'On' : 'Off'}
                      </span>
                      <button
                        type="button"
                        onClick={() => runEnableAction(row.id, row.label, row.enableKey)}
                        disabled={busy || !wsConnected || !canEnable}
                        className="px-2.5 py-1 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        {actionLoading === row.id ? <DuoSpinner size="sm" /> : 'Enable'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Scan & Signature Operations */}
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200">
              <h6 className="font-semibold text-gray-800">Scan & Signature Operations</h6>
            </div>
            <div className="p-3 space-y-2">
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => runScanAction('sig', 'Signature update', '60')}
                  disabled={busy || !wsConnected}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-50"
                >
                  {actionLoading === 'sig' ? <DuoSpinner size="sm" /> : 'Update Signatures'}
                </button>
                <button
                  type="button"
                  onClick={() => runScanAction('quick', 'Quick scan scheduling', '61')}
                  disabled={busy || !wsConnected}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-50"
                >
                  {actionLoading === 'quick' ? <DuoSpinner size="sm" /> : 'Schedule Quick Scan'}
                </button>
                <button
                  type="button"
                  onClick={() => runScanAction('full', 'Full scan scheduling', '62')}
                  disabled={busy || !wsConnected}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-50"
                >
                  {actionLoading === 'full' ? <DuoSpinner size="sm" /> : 'Schedule Full Scan'}
                </button>
              </div>
              <div className="flex flex-wrap gap-2 items-center">
                <input
                  type="text"
                  value={customScanPath}
                  onChange={(e) => setCustomScanPath(sanitizeAsciiSingleLine(e.target.value, 260, false))}
                  placeholder="C:\\Path\\To\\Folder"
                  className="min-w-[260px] px-2 py-1.5 text-xs border border-gray-300 rounded-lg"
                  disabled={busy}
                />
                <button
                  type="button"
                  onClick={() => runScanAction('custom', 'Custom scan scheduling', '63', customScanPath.trim())}
                  disabled={busy || !wsConnected || !customScanPath.trim()}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-50"
                >
                  {actionLoading === 'custom' ? <DuoSpinner size="sm" /> : 'Schedule Custom Scan'}
                </button>
              </div>
            </div>
          </div>

          {/* Signature & Scan Telemetry */}
          <div className="rounded-lg border border-gray-200 p-3">
            <h6 className="font-semibold text-gray-800 mb-2">Signature & Scan Telemetry</h6>
            {signatureTelemetry ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">AV Signature Version</span>
                  <p className="text-gray-800 font-medium">{String(signatureTelemetry.AntivirusSignatureVersion ?? 'N/A')}</p>
                </div>
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">Spyware Signature Version</span>
                  <p className="text-gray-800 font-medium">{String(signatureTelemetry.AntispywareSignatureVersion ?? 'N/A')}</p>
                </div>
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">AV Signature Updated</span>
                  <p className="text-gray-800 font-medium">{toLocal(signatureTelemetry.AntivirusSignatureLastUpdated)}</p>
                </div>
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">Spyware Signature Updated</span>
                  <p className="text-gray-800 font-medium">{toLocal(signatureTelemetry.AntispywareSignatureLastUpdated)}</p>
                </div>
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">Quick Scan Age (days)</span>
                  <p className="text-gray-800 font-medium">{signatureTelemetry.QuickScanAge ?? 'N/A'}</p>
                </div>
                <div className="rounded bg-gray-50 p-2">
                  <span className="text-gray-500 text-xs">Full Scan Age (days)</span>
                  <p className="text-gray-800 font-medium">{signatureTelemetry.FullScanAge ?? 'N/A'}</p>
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-500">No telemetry available yet.</p>
            )}
          </div>

          {/* Last Scan Result */}
          <div className="rounded-lg border border-gray-200 p-3">
            <h6 className="font-semibold text-gray-800 mb-2">Last Scan Result</h6>
            {lastScanStatus ? (
              <div className="space-y-2 text-sm">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div className="rounded bg-gray-50 p-2">
                    <span className="text-gray-500 text-xs">Last Task</span>
                    <p className="text-gray-800 font-medium break-all">{lastScanStatus.last_task_name || 'N/A'}</p>
                  </div>
                  <div className="rounded bg-gray-50 p-2">
                    <span className="text-gray-500 text-xs">Task State</span>
                    <p className="text-gray-800 font-medium">{lastScanStatus.last_task_state || 'N/A'}</p>
                  </div>
                  <div className="rounded bg-gray-50 p-2">
                    <span className="text-gray-500 text-xs">Task Result</span>
                    <p className={`font-medium ${lastScanStatus.last_task_result === 0 ? 'text-green-700' : lastScanStatus.last_task_result != null ? 'text-red-600' : 'text-gray-800'}`}>
                      {lastScanStatus.last_task_result != null ? (lastScanStatus.last_task_result === 0 ? '0 (Success)' : `${lastScanStatus.last_task_result} (Error)`) : 'N/A'}
                    </p>
                  </div>
                  <div className="rounded bg-gray-50 p-2">
                    <span className="text-gray-500 text-xs">Last Run Time</span>
                    <p className="text-gray-800 font-medium">{toLocal(lastScanStatus.last_task_last_run_time)}</p>
                  </div>
                </div>
                {Array.isArray(lastScanStatus.recent_scan_events) && lastScanStatus.recent_scan_events.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-600 mb-1">Recent Scan Events</p>
                    <div className="max-h-36 overflow-auto space-y-1">
                      {lastScanStatus.recent_scan_events.slice(0, 10).map((ev, idx) => (
                        <div key={`${ev.event_id}-${idx}`} className="rounded border border-gray-200 px-2 py-1.5 text-xs">
                          <p className="text-gray-700 font-medium">{toLocal(ev.time)} • Event {ev.event_id ?? 'N/A'} • {ev.level ?? 'N/A'}</p>
                          <p className="text-gray-600">{ev.message || 'No message'}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No scan result available yet.</p>
            )}
          </div>

          {/* Last Capability Response (structured; only when a mutation was run) */}
          {lastMutationOutput && (
            <div className="rounded-lg border border-gray-200 p-3 xl:col-span-2">
              <div className="flex items-center justify-between mb-2">
                <h6 className="font-semibold text-gray-800">Last Capability Response</h6>
                <button
                  type="button"
                  onClick={() => setLastMutationOutput(null)}
                  className="rounded-lg text-xs text-gray-400 hover:text-gray-600"
                >
                  <i className="fa fa-xmark" />
                </button>
              </div>
              <CapabilityResponsePanel output={lastMutationOutput} />
            </div>
          )}

          {/* Firewall Profiles */}
          <div className="rounded-lg border border-gray-200 overflow-hidden xl:col-span-2">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 flex items-center justify-between gap-3">
              <div>
                <h6 className="font-semibold text-gray-800">Firewall Profiles</h6>
                <p className="text-xs text-gray-500 mt-0.5">Per-profile enable actions for Domain, Private, and Public firewall profiles.</p>
              </div>
              <button
                type="button"
                onClick={() => runFirewallAction('fw-all', 'Enable All Firewall Profiles', '37')}
                disabled={busy || !wsConnected || firewallAllEnabled}
                className="px-2.5 py-1 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                {actionLoading === 'fw-all' ? <DuoSpinner size="sm" /> : 'Enable All'}
              </button>
            </div>
            <div className="p-3 space-y-2">
              {firewallProfilesDetail.length === 0 ? (
                <p className="text-sm text-gray-400 text-center py-4">No firewall profile data yet. Click Refresh to load.</p>
              ) : (
                firewallProfilesDetail.map((prof: FirewallProfileDetail) => {
                  const profileKeyMap: Record<string, string> = {
                    Domain:  '66',
                    Private: '67',
                    Public:  '68',
                  };
                  const enableKey = profileKeyMap[prof.Name] ?? '66';
                  const actionId = `fw-${prof.Name.toLowerCase()}`;
                  return (
                    <div key={prof.Name} className="flex items-center justify-between gap-3 py-2 border-b border-gray-100 last:border-0">
                      <div className="flex items-center gap-2 min-w-0">
                        <StatusDot enabled={prof.Enabled} />
                        <span className="text-sm text-gray-800 font-medium">{prof.Name}</span>
                        {prof.DefaultInboundAction && prof.DefaultInboundAction !== '0' && (
                          <span className="text-[10px] text-gray-500 bg-gray-100 rounded px-1 py-0.5">In: {prof.DefaultInboundAction}</span>
                        )}
                        {prof.DefaultOutboundAction && prof.DefaultOutboundAction !== '0' && (
                          <span className="text-[10px] text-gray-500 bg-gray-100 rounded px-1 py-0.5">Out: {prof.DefaultOutboundAction}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`text-xs font-medium ${prof.Enabled ? 'text-green-700' : 'text-red-600'}`}>
                          {prof.Enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <button
                          type="button"
                          onClick={() => runFirewallAction(actionId, `Enable ${prof.Name} Firewall`, enableKey)}
                          disabled={busy || !wsConnected || prof.Enabled}
                          className="px-2.5 py-1 text-xs font-medium rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          {actionLoading === actionId ? <DuoSpinner size="sm" /> : 'Enable'}
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NodesViewDefenderControl;
