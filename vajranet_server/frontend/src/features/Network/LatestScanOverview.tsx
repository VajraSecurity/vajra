import React, { useEffect, useMemo, useState } from 'react';
import { getNetworkScanHistory, getKnownIps } from '../../api/api';
import type { NetworkScanHistory, NucleiFinding } from '../../api/api';
import NetworkScanCharts from './NetworkScanCharts';
import { parseSessionOutput } from './utils/parseNmapOutput';
import type { ParsedHost, ParsedNmapResult } from './utils/parseNmapOutput';
import { AdvancedScanCard } from './NetworkHistoryModal';
import type { VulnScanEntry } from './NetworkHistoryModal';
import { DuoSpinner } from '@/components/ui/loading';

// Memoised like its twin in NetworkHistoryModal: without it every parent render re-mounts
// and re-parses every row, and the parse below re-runs even when the row's own expand
// toggle is all that changed — a full regex pass over the child-scan output per click.
const HostRowOverview = React.memo<{ host: ParsedHost, isManaged: boolean, childScan?: NetworkScanHistory, vulnScan?: VulnScanEntry }>(({ host, isManaged, childScan, vulnScan }) => {
  const [expanded, setExpanded] = useState(false);
  const [vulnExpanded, setVulnExpanded] = useState(false);

  const parsedChildResult = useMemo<ParsedNmapResult | null>(() => {
    if (childScan && childScan.output) {
      try {
        return parseSessionOutput(childScan.output).baseScan;
      } catch { /* no-op */ }
    }
    return null;
  }, [childScan]);

  const nmapVulns = useMemo<string[]>(() => {
    const vulns: string[] = [];
    if (parsedChildResult) {
      parsedChildResult.ports.forEach(p => {
        p.details.forEach(d => {
          if (d.includes('vulners.com')) {
            vulns.push(d);
          }
        });
      });
    }
    return vulns;
  }, [parsedChildResult]);

  return (
    <>
      <tr className="hover:bg-slate-50/50 transition-colors border-b border-slate-100 last:border-0">
        <td className="px-5 py-3 w-16">
          <div
            className={`w-2.5 h-2.5 rounded-full ${host.isUp ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-red-500'}`}
            role="img"
            aria-label={host.isUp ? 'Host is up' : 'Host is down'}
            title={host.isUp ? 'Up' : 'Down'}
          ></div>
        </td>
        <td className="px-5 py-3 font-medium text-slate-800">
          <div className="flex items-center">
            <span className="font-semibold">{host.ip}</span>
            {isManaged && (
              <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-100 px-1.5 py-0.5 rounded">
                Managed by Vajra
              </span>
            )}
          </div>
          {host.hostname && <span className="text-xs text-slate-500 truncate max-w-[200px] mt-0.5 block">{host.hostname}</span>}
        </td>
        <td className="px-5 py-3 text-right">
          <div className="flex items-center justify-end gap-2">
            {parsedChildResult && (
              <button 
                onClick={() => setExpanded(!expanded)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors shadow-sm border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 hover:border-emerald-300"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7" />
                </svg>
                Adv Scan
                <svg className={`w-3.5 h-3.5 ml-1 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
            )}
            
            {(vulnScan || nmapVulns.length > 0) && (
              <button 
                onClick={() => setVulnExpanded(!vulnExpanded)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-colors shadow-sm border-purple-200 bg-purple-50 text-purple-700 hover:bg-purple-100 hover:border-purple-300"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Vuln Scan
                <svg className={`w-3.5 h-3.5 ml-1 transition-transform ${vulnExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
            )}
            
            {!parsedChildResult && !vulnScan && nmapVulns.length === 0 && (
              <span className="text-xs text-slate-400 italic">None</span>
            )}
          </div>
        </td>
      </tr>
      {expanded && parsedChildResult && (
        <tr>
          <td colSpan={3} className="bg-slate-50/50 p-4 border-b border-slate-100 shadow-inner">
            <AdvancedScanCard targetIp={host.ip} result={parsedChildResult} />
          </td>
        </tr>
      )}
      {vulnExpanded && (vulnScan || nmapVulns.length > 0) && (
        <tr>
          <td colSpan={3} className="bg-slate-50/50 p-4 border-b border-slate-100 shadow-inner">
             <div className="text-sm text-slate-700">
               <h4 className="font-semibold mb-3 flex items-center gap-2">
                 <svg className="w-4 h-4 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                 </svg>
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
                         <div className="max-h-32 overflow-y-auto bg-slate-50 p-2 rounded-lg text-xs font-mono border border-slate-100 custom-scrollbar flex flex-col gap-1.5">
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
                     <div className="max-h-32 overflow-y-auto bg-slate-50 p-2 rounded-lg text-xs font-mono border border-slate-100 custom-scrollbar">
                       {nmapVulns.map((v, i) => <div key={i} className="truncate text-slate-600 py-0.5" title={v}>{v}</div>)}
                     </div>
                   </div>
                 )}
               </div>
             </div>
          </td>
        </tr>
      )}
    </>
  );
});
HostRowOverview.displayName = 'HostRowOverview';

const LatestScanOverview: React.FC = () => {
  const [latestScan, setLatestScan] = useState<NetworkScanHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [knownIpsLocal, setKnownIpsLocal] = useState<string[]>([]);

  useEffect(() => {
    const fetchLatest = async () => {
      try {
        const res = await getNetworkScanHistory();
        if (res.success && res.data && res.data.length > 0) {
          setLatestScan(res.data[0]);
        }
      } catch (err) {
        console.error('Failed to fetch latest scan', err);
      } finally {
        setLoading(false);
      }

      try {
        const ipsRes = await getKnownIps();
        if (ipsRes.success && ipsRes.data) {
          setKnownIpsLocal(ipsRes.data);
        }
      } catch (err) {
        console.error('Failed to fetch known IPs', err);
      }
    };
    fetchLatest();
  }, []);

  // parseSessionOutput() line-scans the whole nmap session (base scan plus every advanced-scan
  // chunk) with ~15 regexes per line, over what can be megabytes of text. It only needs to
  // re-run when latestScan changes, not on every unrelated state change.
  const parsed = useMemo(
    () => (latestScan ? parseSessionOutput(latestScan.output) : null),
    [latestScan],
  );

  // knownIpsLocal is a plain string[] used for two membership tests per sort comparison
  // plus one per row, so index it into a Set. The Array.isArray() guard is required:
  // getKnownIps() feeds this state straight from the API and `new Set(nonIterable)`
  // throws, whereas a membership test on a non-array would simply be false.
  const knownIpSet = useMemo(
    () => new Set(Array.isArray(knownIpsLocal) ? knownIpsLocal : []),
    [knownIpsLocal],
  );

  // Managed hosts first; Array.prototype.sort is stable, so the original scan order is
  // preserved within each half.
  const sortedHosts = useMemo(() => {
    if (!parsed) return [];
    return [...parsed.baseScan.discoveredHosts].sort((a, b) => {
      const aManaged = knownIpSet.has(a.ip);
      const bManaged = knownIpSet.has(b.ip);
      if (aManaged && !bManaged) return -1;
      if (!aManaged && bManaged) return 1;
      return 0;
    });
  }, [parsed, knownIpSet]);

  // Two Array.find() scans per rendered host became two index builds per scan. Only the first
  // entry for a target is kept, which is exactly what .find() returned.
  const childScanByTarget = useMemo(() => {
    const byTarget = new Map<string, NetworkScanHistory>();
    for (const child of latestScan?.childScans || []) {
      if (!byTarget.has(child.target)) byTarget.set(child.target, child);
    }
    return byTarget;
  }, [latestScan]);

  const vulnScanByTarget = useMemo(() => {
    const byTarget = new Map<string, VulnScanEntry>();
    for (const vuln of (latestScan?.vulnScans as VulnScanEntry[] | undefined) || []) {
      if (!byTarget.has(vuln.target)) byTarget.set(vuln.target, vuln);
    }
    return byTarget;
  }, [latestScan]);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center text-slate-400 bg-white rounded-xl border border-slate-200 shadow-sm min-h-[400px]">
        <DuoSpinner size="lg" className="mr-3" />
        Loading recent activity...
      </div>
    );
  }

  if (!latestScan || !parsed) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-slate-400 bg-slate-50 rounded-xl border border-slate-200 shadow-inner min-h-[400px]">
        <svg className="w-16 h-16 mb-4 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
        <span className="font-medium text-slate-500">No Scan History</span>
        <span className="text-sm mt-1">Run a new scan to see insights here</span>
      </div>
    );
  }

  const discoveredHosts = parsed.baseScan.discoveredHosts.length;
  
  const advTargets = new Set([
    ...parsed.advancedScans.map((s) => s.targetIp),
    ...(latestScan.childScans || []).map(s => s.target)
  ]);
  const totalAdvanced = advTargets.size;
  const totalVuln = latestScan.vulnScans?.length || 0;

  return (
    <div className="bg-white rounded-xl lg:rounded-2xl border border-slate-200 shadow-sm overflow-hidden h-full flex flex-col">
      <div className="p-5 bg-slate-50/80 border-b border-slate-200 flex justify-between items-center">
        <h3 className="font-bold text-slate-700 flex items-center gap-2">
          <svg className="w-5 h-5 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Latest Scan Insights
        </h3>
        <span className="text-xs font-medium text-slate-500 bg-white px-3 py-1 rounded-full border border-slate-200 shadow-sm">
          {new Date(latestScan.created_at).toLocaleString()}
        </span>
      </div>
      
      <div className="p-6 flex-1 flex flex-col lg:flex-row gap-6 overflow-y-auto">
        {/* Left Column (Narrower) */}
        <div className="w-full lg:w-1/3 flex flex-col gap-6">
          {latestScan.chart_data && latestScan.chart_data.hasData ? (
            <div className="flex-1">
               <NetworkScanCharts staticChartData={latestScan.chart_data} verticalOnly={true} />
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-400 text-sm bg-slate-50 rounded-xl border border-slate-100 p-8 text-center border-dashed min-h-[300px]">
              <div>
                <svg className="w-10 h-10 mx-auto text-slate-300 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2m0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                No analytical charts available.<br />
                <span className="text-[11px] mt-1 block">Run deep scans on discovered hosts to generate insights.</span>
              </div>
            </div>
          )}
        </div>

        {/* Right Column (Wider) */}
        <div className="w-full lg:w-2/3 flex flex-col gap-6">
          
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm text-center">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Target</p>
              <p className="font-mono text-sm text-slate-800 font-semibold">{latestScan.target}</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm text-center">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Discovered</p>
              <p className="text-lg text-emerald-600 font-bold">{discoveredHosts} <span className="text-[10px] text-slate-400 font-medium">Hosts</span></p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm text-center">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Advance Scans</p>
              <p className="text-lg text-blue-600 font-bold">{totalAdvanced}</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm text-center">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Vuln Scans</p>
              <p className="text-lg text-purple-600 font-bold">{totalVuln}</p>
            </div>
          </div>

          <div className="flex flex-col bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm flex-1">
            <div className="bg-slate-50 px-5 py-4 border-b border-slate-200 flex items-center justify-between">
              <h3 className="font-semibold text-slate-700 text-sm flex items-center gap-2">
                <svg className="w-4 h-4 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                </svg>
                Discovered Hosts Log
              </h3>
              <span className="text-xs text-slate-500 font-medium">{discoveredHosts} nodes</span>
            </div>
            <div className="table-scrollbar flex-1 overflow-y-auto overflow-x-auto max-h-[500px]">
              {discoveredHosts > 0 ? (
                <table className="w-full min-w-[480px] text-left border-separate border-spacing-0">
                  <thead>
                    <tr className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                      <th className="px-5 py-3 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                      <th className="px-5 py-3 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">IP Address</th>
                      <th className="px-5 py-3 text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Advanced Scans</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {sortedHosts.map((host) => {
                      const childScan = childScanByTarget.get(host.ip);
                      const vulnScan = vulnScanByTarget.get(host.ip);
                      const isManaged = knownIpSet.has(host.ip);
                      return (
                        <HostRowOverview
                          key={host.ip}
                          host={host}
                          isManaged={isManaged}
                          childScan={childScan}
                          vulnScan={vulnScan}
                        />
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="flex items-center justify-center h-full text-sm text-slate-400 py-10">
                  No hosts discovered in this scan.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LatestScanOverview;
