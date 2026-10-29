import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  History, X, AlertCircle, Inbox, FileSearch, Server, ChevronDown,
  Search, AlertTriangle, FileText, User, CalendarClock, Radar,
} from 'lucide-react';
import { useToast } from '../../context/useToast';
import { getNetworkScanHistory } from '../../api/api';
import type { NetworkScanHistory, NucleiFinding, NucleiScanResult } from '../../api/api';
import { parseSessionOutput } from './utils/parseNmapOutput';
import { DuoSpinner } from '@/components/ui/loading';
import { useModalA11y } from '../../hooks/useModalA11y';
import type { ParsedHost, ParsedNmapResult } from './utils/parseNmapOutput';
import NetworkScanCharts from './NetworkScanCharts';

/** Small chevron that flips to indicate an expandable section's open state. */
const ExpandChevron = ({ expanded, className = 'w-5 h-5 text-slate-400' }: { expanded: boolean; className?: string }) => (
  <ChevronDown className={`transition-transform duration-200 ${expanded ? 'rotate-180' : ''} ${className}`} />
);

interface NetworkHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

/** A completed Nuclei vulnerability scan run against a single discovered host. */
export interface VulnScanEntry extends NucleiScanResult {
  target: string;
  status?: string;
}

const HostRow = React.memo<{ host: ParsedHost, isManaged: boolean, childScan?: NetworkScanHistory, vulnScan?: VulnScanEntry }>(({ host, isManaged, childScan, vulnScan }) => {
  const [expanded, setExpanded] = useState(false);
  const [vulnExpanded, setVulnExpanded] = useState(false);
  
  let parsedChildResult: ParsedNmapResult | null = null;
  if (childScan && childScan.output) {
    try {
      parsedChildResult = parseSessionOutput(childScan.output).baseScan;
    } catch { /* no-op */ }
  }

  const nmapVulns: string[] = [];
  if (parsedChildResult) {
    parsedChildResult.ports.forEach(p => {
      p.details.forEach(d => {
        if (d.includes('vulners.com')) {
          nmapVulns.push(d);
        }
      });
    });
  }

  return (
    <>
      <li className={`flex items-center justify-between p-3 hover:bg-slate-50 transition-colors ${expanded || vulnExpanded ? 'bg-slate-50' : 'bg-white'}`}>
        <div className="flex items-center gap-4 flex-1">
          <div
            role="img"
            aria-label={host.isUp ? 'Host is up' : 'Host is down'}
            title={host.isUp ? 'Host is up' : 'Host is down'}
            className={`w-2 h-2 rounded-full ${host.isUp ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-red-500'}`}
          ></div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-[13px] font-medium text-slate-800">{host.ip}</span>
            {isManaged && (
              <span className="px-2 py-0.5 rounded text-[9px] font-bold tracking-wider bg-blue-100 text-blue-700 uppercase">
                Managed by Vajra
              </span>
            )}
          </div>
          {host.hostname && <span className="text-xs text-slate-500 truncate max-w-[200px]">{host.hostname}</span>}
        </div>
        
        <div className="flex items-center gap-3">
          {host.latency && (
            <div className="text-right">
               <span className="font-mono text-[11px] bg-slate-50 px-2 py-1 rounded text-slate-500 border border-slate-200/60">{host.latency}</span>
            </div>
          )}
          {parsedChildResult && (
            <button
              onClick={() => setExpanded(!expanded)}
              aria-expanded={expanded}
              className="text-xs flex items-center gap-1 font-medium px-2 py-1 bg-emerald-50 text-emerald-700 rounded border border-emerald-200 hover:bg-emerald-100 transition-colors"
            >
              Adv Scan
              <ExpandChevron expanded={expanded} className="w-3.5 h-3.5" />
            </button>
          )}

          {(vulnScan || nmapVulns.length > 0) && (
            <button
              onClick={() => setVulnExpanded(!vulnExpanded)}
              aria-expanded={vulnExpanded}
              className="text-xs flex items-center gap-1 font-medium px-2 py-1 bg-purple-50 text-purple-700 rounded border border-purple-200 hover:bg-purple-100 transition-colors"
            >
              Vuln Scan
              <ExpandChevron expanded={vulnExpanded} className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </li>
      {expanded && parsedChildResult && (
        <li className="bg-slate-50/50 p-4 border-t border-slate-100 shadow-inner">
          <AdvancedScanCard targetIp={host.ip} result={parsedChildResult} />
        </li>
      )}
      {vulnExpanded && (vulnScan || nmapVulns.length > 0) && (
        <li className="bg-slate-50/50 p-4 border-t border-slate-100 shadow-inner">
             <div className="text-sm text-slate-700">
               <h4 className="font-semibold mb-3 flex items-center gap-2">
                 <AlertTriangle className="w-4 h-4 text-purple-600" />
                 Vulnerability Scan Results
               </h4>
               
               <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                 <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                   <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Active Exploitation Checks (Nuclei)</p>
                   {vulnScan ? (
                     <>
                       <div className="flex items-center gap-2 mb-3">
                         <span className={`text-xl font-bold ${vulnScan.findings?.length > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
                           {vulnScan.findings?.length || 0}
                         </span>
                         <span className="text-sm font-medium text-slate-600">Findings</span>
                       </div>
                       {vulnScan.findings?.length > 0 && (
                         <div className="max-h-32 overflow-y-auto bg-slate-50 p-2 rounded-lg text-xs font-mono border border-slate-100 table-scrollbar flex flex-col gap-1.5">
                           {vulnScan.findings.map((finding: NucleiFinding, idx: number) => {
                             const severity = finding.severity?.toLowerCase() || 'info';
                             const severityColors: Record<string, string> = {
                               critical: 'text-red-700 bg-red-100',
                               high: 'text-orange-700 bg-orange-100',
                               medium: 'text-amber-700 bg-amber-100',
                               low: 'text-emerald-700 bg-emerald-100',
                               info: 'text-blue-700 bg-blue-100',
                             };
                             const colorClass = severityColors[severity] || severityColors.info;
                             return (
                               <div key={idx} className="flex flex-col gap-0.5 border-b border-slate-200 pb-1.5 last:border-0 last:pb-0">
                                 <div className="flex items-start gap-2">
                                   <span className={`px-1.5 py-0.5 rounded text-[9px] uppercase font-bold tracking-wider ${colorClass} shrink-0 mt-0.5`}>
                                     {severity}
                                   </span>
                                   <span className="text-slate-700 font-semibold truncate" title={finding.name || finding.templateId}>
                                     {finding.name || finding.templateId || 'Unknown'}
                                   </span>
                                 </div>
                               </div>
                             );
                           })}
                         </div>
                       )}
                     </>
                   ) : (
                     <p className="text-slate-400 italic text-xs mt-1">No active scan performed</p>
                   )}
                 </div>

                 {nmapVulns.length > 0 && (
                   <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                     <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Version-based CVEs (Nmap)</p>
                     <div className="flex items-center gap-2 mb-3">
                       <span className="text-xl font-bold text-amber-600">
                         {nmapVulns.length}
                       </span>
                       <span className="text-sm font-medium text-slate-600">Potential CVEs</span>
                     </div>
                     <div className="max-h-32 overflow-y-auto bg-slate-50 p-2 rounded-lg text-xs font-mono border border-slate-100 table-scrollbar">
                       {nmapVulns.map((v, i) => <div key={i} className="truncate text-slate-600 py-0.5" title={v}>{v}</div>)}
                     </div>
                   </div>
                 )}
               </div>
             </div>
        </li>
      )}
    </>
  );
});
HostRow.displayName = 'HostRow';

const DiscoveredHostsCard: React.FC<{ hosts: ParsedHost[], knownIps: Set<string>, childScans?: NetworkScanHistory[], vulnScans?: VulnScanEntry[] }> = ({ hosts, knownIps, childScans = [], vulnScans = [] }) => {
  const [expanded, setExpanded] = useState(true);

  const sortedHosts = useMemo(
    () => [...hosts].sort((a, b) => {
      const aManaged = knownIps.has(a.ip);
      const bManaged = knownIps.has(b.ip);
      if (aManaged && !bManaged) return -1;
      if (!aManaged && bManaged) return 1;
      return 0;
    }),
    [hosts, knownIps],
  );

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mb-4 shrink-0">
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="rounded-lg w-full flex items-center justify-between p-4 bg-slate-50 hover:bg-slate-100 transition-colors border-b border-transparent data-[expanded=true]:border-slate-200"
        data-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center">
            <Server className="w-4 h-4" />
          </div>
          <div className="text-left">
            <span className="font-semibold text-slate-800 block text-sm">Discovered Hosts</span>
            <span className="text-xs text-slate-500 font-mono">
              {hosts.length} Hosts Found
            </span>
          </div>
        </div>
        <ExpandChevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="p-0 border-t border-slate-100">
          <ul className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto table-scrollbar">
            {sortedHosts.map((host) => {
              const isManaged = knownIps.has(host.ip);
              const childScan = childScans.find(c => c.target === host.ip);
              const vulnScan = vulnScans.find(v => v.target === host.ip);
              return <HostRow key={host.ip} host={host} isManaged={isManaged} childScan={childScan} vulnScan={vulnScan} />;
            })}
          </ul>
        </div>
      )}
    </div>
  );
};

export const VulnScanCard: React.FC<{ scan: VulnScanEntry }> = React.memo(({ scan }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mb-4 shrink-0">
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="rounded-lg w-full flex items-center justify-between p-4 bg-slate-50 hover:bg-slate-100 transition-colors border-b border-transparent data-[expanded=true]:border-slate-200"
        data-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-100 text-purple-700 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="text-left flex flex-col">
            <span className="font-semibold text-slate-800 block text-sm">Vuln Scan: {scan.target}</span>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${scan.findings?.length > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-200 text-slate-600'}`}>
                {scan.findings?.length || 0} Findings
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {scan.status}
              </span>
            </div>
          </div>
        </div>
        <ExpandChevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="p-5 bg-white">
          {!scan.findings || scan.findings.length === 0 ? (
            <div className="text-center py-6 text-slate-500 italic text-sm">
              No vulnerabilities found during this scan.
            </div>
          ) : (
            <div className="space-y-4">
              {scan.findings.map((finding: NucleiFinding, idx: number) => {
                const severity = finding.severity?.toLowerCase() || 'info';
                const severityColors: Record<string, string> = {
                  critical: 'bg-red-100 text-red-700 border-red-200',
                  high: 'bg-orange-100 text-orange-700 border-orange-200',
                  medium: 'bg-amber-100 text-amber-700 border-amber-200',
                  low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
                  info: 'bg-blue-100 text-blue-700 border-blue-200',
                };
                const colorClass = severityColors[severity] || severityColors.info;
                
                return (
                  <div key={idx} className="border border-slate-200 rounded-lg overflow-hidden shadow-sm">
                    <div className="bg-slate-50 border-b border-slate-200 p-3 flex justify-between items-start gap-4">
                      <div>
                        <h4 className="font-semibold text-slate-800 text-sm mb-1">{finding.name || finding.templateId || 'Unknown Vulnerability'}</h4>
                        <div className="flex flex-wrap gap-2 text-xs">
                          <span className={`px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide border ${colorClass}`}>
                            {severity}
                          </span>
                          <span className="px-2 py-0.5 bg-slate-200 text-slate-600 rounded-full font-mono">
                            {finding.type || 'unknown'}
                          </span>
                          {finding.cveId && finding.cveId.map((cve: string) => (
                            <span key={cve} className="px-2 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 rounded-full font-mono">
                              {cve}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    
                    <div className="p-4 space-y-3">
                      {finding.description && (
                        <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Description</p>
                          <p className="text-sm text-slate-700">{finding.description}</p>
                        </div>
                      )}
                      
                      {finding.matchedAt && (
                        <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Matched At</p>
                          <p className="text-sm font-mono text-slate-600 bg-slate-50 px-2 py-1 rounded border border-slate-100 inline-block">
                            {finding.matchedAt}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
});
VulnScanCard.displayName = 'VulnScanCard';

export const AdvancedScanCard: React.FC<{ targetIp: string, result: ParsedNmapResult }> = React.memo(({ targetIp, result }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden mb-4 shrink-0">
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="rounded-lg w-full flex items-center justify-between p-4 bg-slate-50 hover:bg-slate-100 transition-colors border-b border-transparent data-[expanded=true]:border-slate-200"
        data-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-100 text-blue-700 flex items-center justify-center">
            <Search className="w-4 h-4" />
          </div>
          <div className="text-left">
            <span className="font-semibold text-slate-800 block text-sm">Advanced Scan: {targetIp}</span>
            <span className="text-xs text-slate-500 font-mono">
              {result.ports.length} Open Ports {result.hostUp ? '· Host Up' : '· Host Down'}
            </span>
          </div>
        </div>
        <ExpandChevron expanded={expanded} />
      </button>

      {expanded && (
        <div className="p-5 text-slate-800">
          {result.hostUp ? (
            <div className="space-y-6">
              {/* Host Summary */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                  <p className="text-slate-500 text-[10px] mb-1 uppercase tracking-wider">Status</p>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                    <span className="font-semibold text-slate-800 text-sm">Host Up</span>
                  </div>
                </div>
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                  <p className="text-slate-500 text-[10px] mb-1 uppercase tracking-wider">Latency</p>
                  <p className="font-semibold text-slate-800 text-sm">{result.latency || 'N/A'}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                  <p className="text-slate-500 text-[10px] mb-1 uppercase tracking-wider">Open Ports</p>
                  <p className="font-semibold text-slate-800 text-sm">{result.ports.length}</p>
                </div>
                {result.osGuess && result.osGuess.length > 0 && (
                  <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                    <p className="text-slate-500 text-[10px] mb-1 uppercase tracking-wider">OS Guess</p>
                    <p className="font-semibold text-slate-800 text-xs truncate" title={result.osGuess.join(', ')}>
                      {result.osGuess[0]}
                    </p>
                  </div>
                )}
              </div>

              {result.notShown && (
                <p className="text-xs text-slate-500 italic">{result.notShown}</p>
              )}

              {/* Ports Table */}
              {result.ports.length > 0 && (
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                  <div className="overflow-x-auto table-scrollbar">
                    <table className="w-full text-left text-sm border-separate border-spacing-0">
                      <thead>
                        <tr>
                          <th className="px-4 py-2 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Port</th>
                          <th className="px-4 py-2 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">State</th>
                          <th className="px-4 py-2 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Service</th>
                          <th className="px-4 py-2 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Version</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {result.ports.map((p, idx) => (
                          <React.Fragment key={`${p.port}-${idx}`}>
                            <tr className="hover:bg-slate-50 transition-colors">
                              <td className="px-4 py-2 font-mono text-xs">
                                <span className="text-blue-700 font-semibold">{p.port}</span>
                                <span className="text-slate-400">/{p.protocol}</span>
                              </td>
                              <td className="px-4 py-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                                  p.state === 'open' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 
                                  'bg-amber-50 text-amber-700 border border-amber-200'
                                }`}>
                                  {p.state}
                                </span>
                              </td>
                              <td className="px-4 py-2 text-slate-700 font-medium text-xs">{p.service}</td>
                              <td className="px-4 py-2 text-slate-500 text-xs">{p.version}</td>
                            </tr>
                            {p.details.length > 0 && (
                              <tr className="bg-slate-50/50">
                                <td colSpan={4} className="px-4 py-2">
                                  <div className="pl-4 border-l-2 border-slate-300 space-y-1">
                                    {p.details.map((d, dIdx) => (
                                      <p key={dIdx} className="text-[10px] font-mono text-slate-600 break-words whitespace-pre-wrap">{d}</p>
                                    ))}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
             <div className="flex flex-col items-center justify-center py-6 text-slate-500">
                <p className="text-sm font-medium text-slate-700">Host appears to be down.</p>
             </div>
          )}
        </div>
      )}
    </div>
  );
});
AdvancedScanCard.displayName = 'AdvancedScanCard';

const NetworkHistoryModal: React.FC<NetworkHistoryModalProps> = ({ isOpen, onClose }) => {
  const { showToast } = useToast();
  const [history, setHistory] = useState<NetworkScanHistory[]>([]);
  const [knownIps, setKnownIps] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedScan, setSelectedScan] = useState<NetworkScanHistory | null>(null);

  // Guards against a stale close->reopen fetch resolving after a newer one and
  // clobbering fresher state (the API calls below have no AbortSignal support).
  const requestIdRef = useRef(0);

  const fetchKnownIps = useCallback(async (requestId: number) => {
    try {
      // Assuming getKnownIps is added to api.ts
      const { getKnownIps } = await import('../../api/api');
      const response = await getKnownIps();
      if (requestIdRef.current !== requestId) return;
      if (response.success && response.data) {
        setKnownIps(new Set(response.data));
      }
    } catch (err) {
      if (requestIdRef.current !== requestId) return;
      console.error('Failed to fetch known IPs', err);
    }
  }, []);

  const fetchHistory = useCallback(async (requestId: number) => {
    setLoading(true);
    setError(null);
    try {
      const response = await getNetworkScanHistory();
      if (requestIdRef.current !== requestId) return;
      if (response.success && response.data) {
        setHistory(response.data);
      } else {
        setError('Failed to fetch history');
        showToast('Failed to fetch history', 'error');
      }
    } catch (err) {
      if (requestIdRef.current !== requestId) return;
      const errorMessage = err instanceof Error ? err.message : 'Error fetching scan history';
      setError(errorMessage);
      showToast(errorMessage, 'error');
    } finally {
      if (requestIdRef.current === requestId) {
        setLoading(false);
      }
    }
  }, [showToast]);

  useEffect(() => {
    if (isOpen) {
      const requestId = ++requestIdRef.current;
      fetchHistory(requestId);
      fetchKnownIps(requestId);
    } else {
      setSelectedScan(null);
    }
  }, [isOpen, fetchHistory, fetchKnownIps]);

  // Recomputed only when the selected scan changes, not on every unrelated re-render
  // (e.g. a child card's own expand/collapse state) that this component might trigger.
  const scanDetail = useMemo(() => {
    if (!selectedScan) return null;
    const parsedSession = parseSessionOutput(selectedScan.output);
    const discoveredHosts = parsedSession.baseScan.discoveredHosts;
    const hasHosts = discoveredHosts.length > 0;
    const hasAdvanced = parsedSession.advancedScans.length > 0;
    const isRawFallback = !hasHosts && !hasAdvanced && !parsedSession.baseScan.ports.length;
    return { parsedSession, discoveredHosts, hasHosts, hasAdvanced, isRawFallback };
  }, [selectedScan]);

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, onClose);

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-slate-900/40 backdrop-blur-sm">
        <motion.div
          ref={modalRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="network-history-modal-title"
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ type: "spring", bounce: 0, duration: 0.4 }}
          className="bg-white rounded-2xl shadow-2xl shadow-blue-950/20 ring-1 ring-white/10 border border-blue-100 w-full max-w-6xl max-h-[90vh] flex flex-col overflow-hidden relative"
        >
          <div
            className="relative overflow-hidden flex justify-between items-center p-6 border-b border-slate-100 z-10 text-white shrink-0"
            style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
          >
            <div className="relative z-10">
              <h2 id="network-history-modal-title" className="text-xl font-bold text-white flex items-center gap-2.5">
                <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-white/15">
                  <History className="w-4 h-4 text-blue-100" />
                </span>
                Scan History
              </h2>
              <p className="text-xs text-blue-200 mt-1.5 ml-[42px]">Review past network scanning activities</p>
            </div>
            <button
              onClick={onClose}
              aria-label="Close scan history"
              className="relative z-10 p-2 text-blue-200 hover:text-white hover:bg-white/10 rounded-xl transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="flex-1 flex flex-col md:flex-row min-h-0 bg-slate-50/50">
            {/* Left side: List of scans */}
            <div className="w-full md:w-[320px] lg:w-[380px] border-r border-slate-200 bg-white overflow-y-auto flex-shrink-0 table-scrollbar">
              {loading ? (
                <div className="p-8 text-center flex flex-col items-center justify-center h-full space-y-3">
                  <DuoSpinner size="lg" className="text-blue-600" />
                  <span className="text-slate-500 text-sm font-medium">Loading history...</span>
                </div>
              ) : error ? (
                <div className="p-8 text-center flex flex-col items-center justify-center h-full text-red-500">
                  <AlertCircle className="w-10 h-10 mb-2 opacity-50" />
                  <span className="text-sm">{error}</span>
                </div>
              ) : history.length === 0 ? (
                <div className="p-8 text-center flex flex-col items-center justify-center h-full text-slate-500">
                  <Inbox className="w-12 h-12 mb-3 opacity-20" />
                  <span className="font-medium text-slate-600">No scans found</span>
                  <p className="text-xs mt-1 text-slate-400">History will appear here once scans are run.</p>
                </div>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {history.map((scan) => {
                    const isSelected = selectedScan?.id === scan.id;
                    return (
                    <li key={scan.id}>
                      <button
                        onClick={() => setSelectedScan(scan)}
                        className={`rounded-lg w-full text-left p-4 pl-5 transition-all relative flex gap-3 ${
                          isSelected ? 'bg-blue-50/50' : 'hover:bg-slate-50'
                        }`}
                      >
                        {isSelected && (
                          <motion.div
                            layoutId="activeScanIndicator"
                            className="absolute left-0 top-0 bottom-0 w-1 bg-blue-600"
                          />
                        )}
                        <div className={`mt-0.5 flex items-center justify-center w-8 h-8 rounded-lg shrink-0 transition-colors ${
                          isSelected ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-500'
                        }`}>
                          <Radar className="w-4 h-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex justify-between items-start mb-1.5">
                            <div className="font-semibold text-slate-900 truncate pr-4 text-sm flex-1">{scan.target}</div>
                            <span className="text-[10px] whitespace-nowrap text-slate-400 font-medium">
                              {new Date(scan.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 mt-1.5">
                            <span className="uppercase text-[10px] font-bold tracking-wider px-2 py-0.5 bg-indigo-50 text-indigo-600 rounded-md border border-indigo-100/50">
                              {scan.scanType}
                            </span>
                            <span className="text-xs text-slate-500 truncate flex-1">
                              {scan.reason}
                            </span>
                          </div>
                        </div>
                      </button>
                    </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* Right side: Scan Details */}
            <div className="w-full md:w-2/3 flex flex-col overflow-hidden bg-slate-50/30">
              {selectedScan ? (
                <div className="flex-1 flex flex-col p-6 overflow-hidden gap-5">
                  <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                    <div className="flex flex-wrap justify-between items-center gap-3">
                      <div className="flex items-center gap-4">
                        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500">Execution Details</h3>
                        <div className="flex items-center gap-2 border-l border-slate-200 pl-4">
                          <span className="text-xs font-medium text-slate-400 flex items-center gap-1">
                            <User className="w-3 h-3" />
                            Initiated By
                          </span>
                          <div className="w-6 h-6 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center text-xs font-bold">
                            {(selectedScan.created_by_name || 'S')[0].toUpperCase()}
                          </div>
                          <span className="text-sm font-medium text-slate-700">{selectedScan.created_by_name || 'System'}</span>
                        </div>
                      </div>
                      <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                        <CalendarClock className="w-3.5 h-3.5" />
                        {new Date(selectedScan.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  <div className="flex-1 flex flex-col min-h-0 overflow-y-auto pr-2 gap-6 pb-6 table-scrollbar">
                    {scanDetail && (
                      <>
                        {scanDetail.hasHosts && (
                          <DiscoveredHostsCard hosts={scanDetail.discoveredHosts} knownIps={knownIps} childScans={selectedScan.childScans} vulnScans={selectedScan.vulnScans} />
                        )}

                        {scanDetail.parsedSession.baseScan.ports.length > 0 && (
                          <AdvancedScanCard targetIp={selectedScan.target} result={scanDetail.parsedSession.baseScan} />
                        )}

                        {scanDetail.hasAdvanced && (
                          <div className="flex flex-col gap-2 mt-2">
                            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 pl-1 mb-1 flex items-center gap-1.5">
                              <Search className="w-3.5 h-3.5 text-blue-600" />
                              Advanced Scans ({scanDetail.parsedSession.advancedScans.length})
                            </h3>
                            {scanDetail.parsedSession.advancedScans.map((scan, idx) => (
                              <AdvancedScanCard key={idx} targetIp={scan.targetIp} result={scan.result} />
                            ))}
                          </div>
                        )}

                        {selectedScan.vulnScans && selectedScan.vulnScans.length > 0 && (
                          <div className="flex flex-col gap-2 mt-2">
                            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 pl-1 mb-1 flex items-center gap-1.5">
                              <AlertTriangle className="w-3.5 h-3.5 text-purple-600" />
                              Vulnerability Scans ({selectedScan.vulnScans.length})
                            </h3>
                            {selectedScan.vulnScans.map((scan, idx) => (
                              <VulnScanCard key={idx} scan={scan} />
                            ))}
                          </div>
                        )}

                        {scanDetail.isRawFallback && (
                          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm flex-1 flex flex-col min-h-[300px]">
                            <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center gap-2">
                              <FileText className="w-4 h-4 text-slate-500" />
                              <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Raw Output</span>
                            </div>
                            <div className="p-5 overflow-x-auto bg-slate-900 flex-1 table-scrollbar">
                              <pre className="text-emerald-400/90 font-mono text-[13px] leading-relaxed whitespace-pre-wrap">
                                {selectedScan.output}
                              </pre>
                            </div>
                          </div>
                        )}

                        {selectedScan.chart_data && selectedScan.chart_data.hasData && (
                          <div className="mt-4">
                            <NetworkScanCharts staticChartData={selectedScan.chart_data} />
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-slate-400">
                  <div className="w-20 h-20 mb-4 rounded-full bg-slate-100 flex items-center justify-center border border-slate-200">
                    <FileSearch className="w-9 h-9 text-slate-300" strokeWidth={1.5} />
                  </div>
                  <span className="text-lg font-medium text-slate-600">Select a scan</span>
                  <p className="text-sm mt-1 text-slate-500">Choose a scan from the sidebar to view its detailed execution output.</p>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

export default NetworkHistoryModal;
