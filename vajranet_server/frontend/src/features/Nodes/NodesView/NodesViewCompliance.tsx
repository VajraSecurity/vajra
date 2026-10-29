/**
 * NodesViewCompliance
 *
 * Behaviour:
 *  1. On mount → fetch the latest saved compliance record from the API (DB).
 *  2. When the agent is offline, the Machine Compliance tab still loads that saved
 *     data and history so operators can review the last run (refresh stays disabled).
 *  3. "Refresh Compliance" button → fire a real-time WS compliance check to the agent.
 *     The backend auto-saves the agent response; the UI displays it immediately and
 *     refreshes the history chart after a short delay.
 *  4. Left panel  : numbered guidelines table with Pass/Fail badges and hover tooltips
 *                   (tooltips derived from the actual PowerShell commands in the agent).
 *  5. Right panel : compliance score card + donut pie chart (recharts).
 *  6. Bottom      : historical trend line chart (recharts, last ≤ 30 runs).
 *
 * Pass/Fail logic (derived from agent/powershell/main.go):
 *  - Keys 1,3–17 : True = Pass, False = Fail  (standard boolean output)
 *  - Key 2        : INVERTED — False = Pass (name was changed), True = Fail (still default)
 *  - Key 18       : Numeric output (actual password length). Display raw value; 0 = Fail, >0 = Pass.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  PieChart, Pie, Cell, Tooltip as RTooltip, Legend,
  LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
  Sector
} from 'recharts';
import type { NodeData } from './types';
import { NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';
import { motion } from 'motion/react';
import { Meteors } from '@/components/ui/meteors';
import { LoadingScreen, DuoSpinner } from '@/components/ui/loading';
import { InfoTooltip } from './components/InfoTooltip';

// Types

interface NodesViewComplianceProps {
  node: NodeData;
  wsConnected: boolean;
  wsSendMessage: (message: unknown) => Promise<unknown>;
  /** Live agent reachable (from node presence). When false, UI shows saved DB data only. */
  agentOnline?: boolean;
}

interface GuidelineResult {
  key: string;
  label: string;
  tooltip: string;
  rawOutput: string;
  passed: boolean;
  /** True only for key 18 — display rawOutput instead of True/False badge */
  showRaw: boolean;
}

interface ComplianceRecord {
  id: number;
  host_identifier: string;
  unixtime: number;
  compliance_data: Array<{ command_key: string; output: string }>;
}

// Guideline metadata (label + tooltip)
// Tooltips are written directly from the PowerShell commands in
// wsExtension/WindowsAgent/agent/powershell/main.go — no guesswork.

const GUIDELINES: Record<string, { label: string; tooltip: string }> = {
  '1': {
    label: 'Windows Defender Enabled',
    tooltip: 'Runs: (Get-MpComputerStatus).AntivirusEnabled\nChecks that Windows Defender Antivirus is active and running on this endpoint.',
  },
  '2': {
    label: 'Default Name Changed',
    tooltip: 'Runs: (Get-ComputerInfo).CsName -match "PC-"\nVerifies the computer name was renamed away from the Windows default pattern (PC-XXXXX). NOTE: the agent returns False when the name is properly changed — False here means PASS.',
  },
  '3': {
    label: 'Timezone Set to UTC+5:30 (IST)',
    tooltip: 'Runs: (Get-TimeZone).DisplayName -match "(UTC+05:30)"\nConfirms the system clock is set to Indian Standard Time (UTC+5:30) for consistent log timestamps across the organization.',
  },
  '4': {
    label: 'Secure Boot Enabled',
    tooltip: 'Runs: Confirm-SecureBootUEFI\nVerifies Secure Boot is active in UEFI firmware. Secure Boot blocks bootkits and rootkits from loading before the OS starts.',
  },
  '5': {
    label: 'Audit Special Logon',
    tooltip: 'Runs: auditpol /get /subcategory:"Special Logon"\nChecks that Special Logon events are audited (both Success and Failure). Special Logon fires when a process is started with an elevated or admin token — key for detecting lateral movement.',
  },
  '6': {
    label: 'Audit Credential Validation',
    tooltip: 'Runs: auditpol /get /subcategory:"Credential Validation"\nVerifies NTLM and Kerberos authentication events are logged (Success + Failure). Essential for detecting pass-the-hash and brute-force attacks.',
  },
  '7': {
    label: 'Audit Computer Account Management',
    tooltip: 'Runs: auditpol /get /subcategory:"Computer Account Management"\nChecks that computer account creation, deletion, and modification events are audited. Helps detect rogue machines added to the domain.',
  },
  '8': {
    label: 'Audit Other Account Management Events',
    tooltip: 'Runs: auditpol /get /subcategory:"Other Account Management Events"\nVerifies miscellaneous account management events are logged (e.g. changes to cached credentials, Password Policy Checking API calls).',
  },
  '9': {
    label: 'Audit Security Group Management',
    tooltip: 'Runs: auditpol /get /subcategory:"Security Group Management"\nChecks that security group creation, modification, and membership changes are audited. Detects privilege escalation via group membership abuse.',
  },
  '10': {
    label: 'Audit User Account Management',
    tooltip: 'Runs: auditpol /get /subcategory:"User Account Management"\nVerifies user account creation, deletion, rename, enable/disable, and password change events are logged.',
  },
  '11': {
    label: 'Audit Process Creation',
    tooltip: 'Runs: auditpol /get /subcategory:"Process Creation"\nChecks that new process creation (Event ID 4688) is audited. Critical for detecting malware execution, script-based attacks, and lateral movement tools.',
  },
  '12': {
    label: 'Audit PnP Activity',
    tooltip: 'Runs: auditpol /get /subcategory:"Plug and Play Events"\nVerifies USB and other PnP device plug-in events are logged. Detects insertion of unauthorized storage or input devices.',
  },
  '13': {
    label: 'Audit Account Lockout',
    tooltip: 'Runs: auditpol /get /subcategory:"Account Lockout"\nChecks that account lockout events are audited. Helps identify brute-force password attacks and credential stuffing attempts.',
  },
  '14': {
    label: 'Audit Logon Events',
    tooltip: 'Runs: auditpol /get /subcategory:"Logon"\nVerifies that interactive, network, and remote logon/logoff events are audited (both Success and Failure). Foundation of user activity monitoring.',
  },
  '15': {
    label: 'Audit IPsec Driver',
    tooltip: 'Runs: auditpol /get /subcategory:"IPsec Driver"\nChecks that IPsec driver-level events are audited. Surfaces network security policy failures and tunnel negotiation errors.',
  },
  '16': {
    label: 'Audit Security System Extension',
    tooltip: 'Runs: auditpol /get /subcategory:"Security System Extension"\nVerifies that security system extension events are audited (loading of authentication packages, notification packages, and security support providers into LSA).',
  },
  '17': {
    label: 'Command Line in Process Creation Events',
    tooltip: 'Runs: registry key ProcessCreationIncludeCmdLine_Enabled == 1\nChecks the registry policy that adds full command-line arguments to Event ID 4688. Without this, process audit logs show the executable path but NOT the arguments — attackers exploit this gap.',
  },
  '18': {
    label: 'Minimum Password Length Policy',
    tooltip: 'Runs: net accounts | Select-String "Minimum password length"\nReturns the configured minimum password length (e.g. 8, 12, 14). A value of 0 means no minimum is enforced — shown in red. Any value > 0 means a policy is in place — shown in green.',
  },
};

const COMPLIANCE_COMMAND_KEYS = Object.keys(GUIDELINES); // ['1'..'18']

const PIE_COLORS = ['#136f63', '#ab3428']; // pass = green, fail = red

// Keys where False/0 output means PASS (inverted logic)
// Key 2: CsName -match "PC-" returns True when STILL using default name (FAIL).
const INVERTED_KEYS = new Set(['2']);

// Pass/Fail logic

function parsePassFail(key: string, output: string): boolean {
  const v = String(output).trim().toLowerCase();

  // Key 18: output is the actual minimum password length integer
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
    // Unexpected output — treat as fail
    return false;
  }

  // Invert for keys where the PowerShell returns True when non-compliant
  return INVERTED_KEYS.has(key) ? !rawBool : rawBool;
}

function buildRows(data: Array<{ command_key: string; output: string }>): GuidelineResult[] {
  return data.map((item) => {
    const meta = GUIDELINES[item.command_key] ?? {
      label: `Guideline ${item.command_key}`,
      tooltip: '',
    };
    return {
      key: item.command_key,
      label: meta.label,
      tooltip: meta.tooltip,
      rawOutput: String(item.output).trim(),
      passed: parsePassFail(item.command_key, item.output),
      showRaw: item.command_key === '18',
    };
  });
}

function calcPassPercent(rows: GuidelineResult[]): number {
  if (rows.length === 0) return 0;
  return Math.round((rows.filter((r) => r.passed).length / rows.length) * 100);
}

function fmtDate(unixtime: number) {
  return new Date(unixtime * 1000).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' });
}
function fmtDateTime(unixtime: number) {
  return new Date(unixtime * 1000).toLocaleString('en-IN');
}

// Tooltip icon component
// Portal-based (renders into document.body) so it can't be clipped by an
// ancestor's overflow:hidden/auto. See ./components/InfoTooltip.tsx.

// Custom Tooltip and Active Shape

interface PieTooltipPayloadItem {
  name?: string;
  value?: number | string;
  color?: string;
  payload?: { fill?: string };
}

interface PieTooltipProps {
  active?: boolean;
  payload?: PieTooltipPayloadItem[];
}

function CustomTooltip({ active, payload }: PieTooltipProps) {
  if (!active || !payload?.length) return null;
  const item = payload[0];
  return (
    <div className="bg-white rounded-lg shadow-lg border border-slate-200 px-3 py-2">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: item.payload?.fill || item.color }}
          />
          <span className="text-sm text-slate-600">{item.name}</span>
        </div>
        <span className="font-semibold text-slate-900">
          {item.value} checks
        </span>
      </div>
    </div>
  );
}

interface PieActiveShapeProps {
  cx?: number;
  cy?: number;
  innerRadius?: number;
  outerRadius?: number;
  startAngle?: number;
  endAngle?: number;
  fill?: string;
  cornerRadius?: number;
}

const renderActiveShape = (props: PieActiveShapeProps) => {
  const { cx, cy, innerRadius, outerRadius = 0, startAngle = 0, endAngle = 0, fill, cornerRadius } = props;
  return (
    <Sector
      cx={cx}
      cy={cy}
      innerRadius={innerRadius}
      outerRadius={outerRadius + 4}
      startAngle={startAngle + 1.5}
      endAngle={endAngle - 1.5}
      fill={fill}
      style={{ filter: 'drop-shadow(0 4px 12px rgba(0,0,0,0.12))' }}
      cornerRadius={cornerRadius}
    />
  );
};

// Component

const NodesViewCompliance = ({ node, wsConnected, wsSendMessage, agentOnline = true }: NodesViewComplianceProps) => {
  const hostId = node.host_identifier || String(node.id);

  const [guidelines, setGuidelines] = useState<GuidelineResult[]>([]);
  const [lastChecked, setLastChecked] = useState<number | null>(null);
  const [fetchLoading, setFetchLoading] = useState(false);
  const [, setRunLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [history, setHistory] = useState<ComplianceRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [, setActiveIndex] = useState(0);

  // Fetch latest saved record from API
  const fetchLatest = useCallback(async () => {
    setFetchLoading(true);
    setError(null);
    try {
      const res = await api.get(`${NODES_URLS.COMPLIANCE_LATEST}${encodeURIComponent(hostId)}`);
      const json = res.data;
      if (json.success && json.data) {
        const rec: ComplianceRecord = json.data;
        setGuidelines(buildRows(rec.compliance_data));
        setLastChecked(rec.unixtime);
      }
    } catch (err: unknown) {
      console.warn('Compliance latest fetch:', err instanceof Error ? err.message : String(err));
    } finally {
      setFetchLoading(false);
    }
  }, [hostId]);

  // Fetch history for trend chart
  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await api.get(`${NODES_URLS.COMPLIANCE_HISTORY}${encodeURIComponent(hostId)}`);
      const json = res.data;
      if (json.success) setHistory(json.data ?? []);
    } catch (err: unknown) {
      console.warn('Compliance history fetch:', err instanceof Error ? err.message : String(err));
    } finally {
      setHistoryLoading(false);
    }
  }, [hostId]);

  useEffect(() => {
    fetchLatest();
    fetchHistory();
  }, [fetchLatest, fetchHistory]);

  // Run fresh compliance check via WebSocket
  const handleRefresh = async () => {
    if (!wsConnected) {
      setError('WebSocket not connected. Please wait or refresh the page.');
      return;
    }
    setRunLoading(true);
    setError(null);
    try {
      const response = await wsSendMessage({
        type: 'agent',
        params: { agent: 'powershell', action: 'allow', command_keys: COMPLIANCE_COMMAND_KEYS },
        host_identifier: hostId,
      });

      const raw = (response && typeof response === 'object' && 'response' in response)
        ? (response as { response?: unknown }).response
        : undefined;
      let rows: Array<{ command_key: string; output: string }> = [];
      if (Array.isArray(raw)) {
        rows = raw as Array<{ command_key: string; output: string }>;
      } else if (typeof raw === 'string') {
        const parsed = JSON.parse(raw);
        rows = Array.isArray(parsed)
          ? parsed
          : (Object.values(parsed) as Array<{ command_key: string; output: string }>);
      }

      if (rows.length === 0) {
        setError('No compliance results returned from agent.');
        return;
      }

      setGuidelines(buildRows(rows));
      setLastChecked(Math.floor(Date.now() / 1000));
      // Backend auto-saved the result; refresh history chart after brief delay
      setTimeout(fetchHistory, 600);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to run compliance check.');
    } finally {
      setRunLoading(false);
    }
  };

  // Derived values
  const passCount = guidelines.filter((g) => g.passed).length;
  const failCount = guidelines.length - passCount;
  const percent = calcPassPercent(guidelines);
  const scoreColor = percent >= 80 ? 'text-green-600' : percent >= 50 ? 'text-amber-500' : 'text-red-600';

  const pieData = guidelines.length > 0
    ? [{ name: 'Pass', value: passCount }, { name: 'Fail', value: failCount }]
    : [];

  // Oldest→newest for line chart
  const chartData = [...history].reverse().map((rec) => ({
    label: fmtDate(rec.unixtime),
    tooltip: fmtDateTime(rec.unixtime),
    percent: calcPassPercent(buildRows(rec.compliance_data)),
  }));

  return (
    <div className="px-4 pb-4 space-y-4">

      {error && (
        <div className="text-sm px-4 py-3 rounded-lg bg-red-50 text-red-700 border border-red-200">
          {error}
        </div>
      )}

      {/* Vajra Header Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="relative overflow-hidden rounded-xl shadow-lg p-6 text-white mb-6"
        style={{ background: "rgb(4 34 119)" }}
      >
        <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
        <div className="relative z-10">
          <h2 className="text-xl font-bold mb-4 flex items-center text-white">
            <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            Vajra Compliance
          </h2>
          <div className="flex items-center justify-between">
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Compliance Checks</p>
                <p className="text-sm font-semibold text-white">{COMPLIANCE_COMMAND_KEYS.length} points</p>
              </div>
              {(
                <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                  <p className="text-blue-200 text-xs mb-1">Last Compliance Run</p>
                  <p className="text-sm font-semibold text-white">{lastChecked ? fmtDateTime(lastChecked) : 'Never'}</p>
                </div>
              )}
            </div>
            <div className="flex flex-col gap-2">
              {agentOnline && (
                <button
                  type="button"
                  onClick={handleRefresh}
                  className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition-colors hover:bg-slate-50 disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  <i className="fa fa-rotate-right" />
                  Refresh Vajra Compliance
                </button>
              )}
            </div>
          </div>
        </div>
      </motion.div>

      {!agentOnline && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-clock-rotate-left mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">Agent is offline.</p>
            <p className="mt-1 text-slate-700/90">Latest compliance can only be checked when the agent is online.</p>
          </div>
        </div>
      )}

      {/* Main two-column layout */}
      {fetchLoading && guidelines.length === 0 ? (
        <div className="flex items-center justify-center h-48">
          <LoadingScreen
            title="Calculating Vajra compliance..."
            subtitle="This may take a few moments depending on number of endpoints and network conditions."
            size="md"
            fullScreen={false}
          />
        </div>
      ) : (
        <div className="flex flex-col lg:flex-row gap-4 mt-4 lg:items-stretch">
          <div className="flex-1 min-w-0">

            {/* Left: guidelines table */}
            <div className="flex-1 min-w-0 bg-white rounded-xl border border-gray-200 overflow-hidden h-full flex flex-col">
              <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
                <span className="font-semibold text-white text-base">Security Guidelines</span>
                {guidelines.length > 0 && (
                  <span className="text-xs text-gray-100">{passCount}/{guidelines.length} passed</span>
                )}
              </div>

              {guidelines.length > 0 ? (
                <div className="table-scrollbar overflow-auto max-h-[520px] flex h-full flex-col">
                  <table className="flex-1 w-full text-sm border-separate border-spacing-0">
                    <thead>
                      <tr className="bg-gray-50 border-b border-gray-200">
                        <th className="py-2 px-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide w-8 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">#</th>
                        <th className="py-2 px-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Guideline</th>
                        <th className="py-2 px-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wide w-24 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {guidelines.map((g, i) => (
                        <tr
                          key={g.key}
                          className={`border-b border-gray-100 transition-colors ${g.passed ? 'hover:bg-green-50' : 'hover:bg-red-50'
                            }`}
                        >
                          <td className="py-2.5 px-3 text-gray-400 text-xs">{i + 1}</td>

                          <td className="py-2.5 px-3 text-gray-800">
                            <span className="inline-flex items-center">
                              {g.label}
                              {g.tooltip && <InfoTooltip text={g.tooltip} />}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 text-center">
                            {g.showRaw ? (
                              /* Key 18: show the actual password length value */
                              <span className={`font-semibold text-sm ${g.passed ? 'text-green-600' : 'text-red-600'}`}>
                                {g.rawOutput === '0' ? (
                                  <span title="No minimum password length is enforced">0 (not set)</span>
                                ) : (
                                  <span title={`Minimum password length: ${g.rawOutput} characters`}>{g.rawOutput} chars</span>
                                )}
                              </span>
                            ) : (
                              /* All other keys: Pass/Fail badge */
                              <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${g.passed
                                ? 'bg-green-100 text-green-700'
                                : 'bg-red-100 text-red-700'
                                }`}>
                                <i className={`fa ${g.passed ? 'fa-check' : 'fa-xmark'} text-[9px]`} />
                                {g.passed ? 'Pass' : 'Fail'}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16 text-gray-400">
                  <i className="fa fa-shield-halved text-5xl mb-3 opacity-20" />
                  <p className="text-sm font-medium">No compliance data yet</p>
                  <p className="text-xs mt-1 text-gray-400">
                    {agentOnline && wsConnected
                      ? 'Click "Refresh Compliance" to run the first check'
                      : 'Connect the agent and run a compliance check once; results are saved and shown here even when the agent is offline.'}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Right: score + pie */}

          <div className="w-full lg:w-96 shrink-0 flex flex-col">
            <div className="bg-white rounded-xl border border-slate-200 overflow-hidden h-full flex flex-col">
              <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                <span className="font-semibold text-white text-base">Run Statistics</span>
              </div>

              {/* Score card */}
              <div className="grid grid-cols-1 gap-4 p-4 bg-blue-50 flex-1">
                <div className="bg-white rounded-xl border border-blue-200 p-4">
                  <p className="font-semibold text-gray-700 text-sm mb-3">Compliance Score</p>
                  {guidelines.length > 0 ? (
                    <>
                      <div className={`text-5xl font-bold text-center mb-1 ${scoreColor}`}>
                        {percent}%
                      </div>
                      <div className="grid grid-cols-3 gap-2 text-center text-xs">
                        <div className="bg-green-50 rounded-lg py-2">
                          <div className="font-bold text-[#136f63] text-xl">{passCount}</div>
                          <div className="text-gray-500 mt-0.5">Pass</div>
                        </div>
                        <div className="bg-red-50 rounded-lg py-2">
                          <div className="font-bold text-[#ab3428] text-xl">{failCount}</div>
                          <div className="text-gray-500 mt-0.5">Fail</div>
                        </div>
                        <div className="bg-gray-50 rounded-lg py-2">
                          <div className="font-bold text-gray-700 text-xl">{guidelines.length}</div>
                          <div className="text-gray-500 mt-0.5">Total</div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-gray-400 text-center py-4">Run a check to see score</p>
                  )}
                </div>

                {/* Pie / donut chart */}
                <div className="bg-white rounded-xl border border-blue-200 p-4">
                  <p className="font-semibold text-gray-700 text-sm mb-1">Distribution</p>
                  {pieData.length > 0 ? (
                    <div className="flex justify-center">
                      <ResponsiveContainer width="100%" height={280}>
                        <PieChart>
                          <Pie
                            data={pieData}
                            activeShape={renderActiveShape}
                            onMouseEnter={(_, index) => setActiveIndex(index)}
                            dataKey="value"
                            cx="50%"
                            cy="50%"
                            innerRadius={65}
                            outerRadius={115}
                            stroke="#fff"
                            strokeWidth={4}
                            cornerRadius={6}
                          >
                            {pieData.map((_, idx) => (
                              <Cell
                                key={idx}
                                fill={PIE_COLORS[idx % PIE_COLORS.length]}
                              />
                            ))}
                          </Pie>

                          {/* Center Label */}
                          <text
                            x="50%"
                            y="46%"
                            textAnchor="middle"
                            dominantBaseline="middle"
                          >
                            <tspan
                              fontSize="34"
                              fontWeight="700"
                              fill="#0F172A"
                            >
                              {(
                                ((pieData[0]?.value ?? 0) /
                                  (((pieData[0]?.value ?? 0) +
                                    (pieData[1]?.value ?? 0)) || 1)) *
                                100
                              ).toFixed(1)}
                              %
                            </tspan>

                            <tspan
                              x="50%"
                              dy="22"
                              fontSize="14"
                              fill="#64748B"
                            >
                              Checks Passed
                            </tspan>
                          </text>

                          <RTooltip content={<CustomTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-[280px] text-gray-200">
                      <i className="fa fa-chart-pie text-6xl" />
                    </div>
                  )}
                </div>
              </div>

            </div>
          </div>
        </div>
      )}

      {/* History trend chart */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
          <span className="font-semibold text-white text-base">Compliance History</span>
          {!historyLoading && history.length > 0 && (
            <span className="text-xs text-gray-500">{history.length} records</span>
          )}
        </div>
        <div className="p-4">
          {historyLoading ? (
            <div className="flex items-center justify-center h-[180px]">
              <DuoSpinner size="lg" className="text-blue-400" />
            </div>
          ) : chartData.length >= 2 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={chartData} margin={{ top: 8, right: 20, bottom: 4, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d8d8d8" />
                <XAxis dataKey="label" tick={{ fontSize: 11 }} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} unit="%" width={38} />
                <RTooltip
                  formatter={(value) => [
                    `${Number(Array.isArray(value) ? value[0] : value) || 0}%`,
                    'Pass rate',
                  ]}
                  labelFormatter={(label: React.ReactNode, payload?: unknown) => {
                    const items = Array.isArray(payload) ? payload as Array<{ payload?: { tooltip?: string } }> : [];
                    return items[0]?.payload?.tooltip ?? label;
                  }}
                />
                <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                <Line
                  type="monotone"
                  dataKey="percent"
                  name="Pass rate %"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#3b82f6' }}
                  activeDot={{ r: 5 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : chartData.length === 1 ? (
            <div className="flex items-center justify-center h-[180px] text-gray-400 text-sm text-center">
              Only 1 record — run another compliance check to see the trend.
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-[180px] text-gray-400">
              <i className="fa fa-chart-line text-4xl mb-3 opacity-20" />
              <p className="text-sm font-medium">No history yet</p>
              <p className="text-xs mt-1">History builds as you run compliance checks</p>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default NodesViewCompliance;
