import { useState, useMemo, useEffect, useRef } from 'react';
import { History, MapPin, Search, Radar, AlertTriangle, PenLine, PlayCircle, X, Network as NetworkIcon } from 'lucide-react';

import { useNetworkScan } from './context/useNetworkScan';
import { useToast } from '../../context/useToast';
import NetworkHistoryModal from './NetworkHistoryModal';
import AdvancedScanModal from './AdvancedScanModal';
import VulnScanModal from './VulnScanModal';
import VulnResultModal from './VulnResultModal';
import NetworkScanCharts from './NetworkScanCharts';
import LatestScanOverview from './LatestScanOverview';
import { DuoSpinner } from '@/components/ui/loading';
import { Checkbox, FancySelect, CIDR_OPTIONS } from './ui';

const NetworkScanning = () => {
  const { showToast } = useToast();
  const {
    target, setTarget,
    cidr, setCidr,
    reason, setReason,
    loading, progress, result, error,
    knownIps, unknownIps, staleManagedIps, newIps, disappearedIps,
    currentSessionId,
    handleScan, cancelScan,
    isAdvancedScanModalOpen, setIsAdvancedScanModalOpen,
    advancedScanIp, advancedScanLoadingMap, advancedScanErrorMap, startAdvancedScan,
    advancedScanResultsMap, openAdvancedScanModal,

    startVulnScan, vulnScanLoadingMap, vulnScanErrorMap, vulnScanResultsMap,
    openVulnResultModal, isVulnResultModalOpen, setIsVulnResultModalOpen, vulnScanIp
  } = useNetworkScan();

  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState(false);



  const [selectedIps, setSelectedIps] = useState<string[]>([]);
  const [vulnScanModalOpen, setVulnScanModalOpen] = useState(false);
  const [vulnScanTargetIps, setVulnScanTargetIps] = useState<string[]>([]);

  // Toast the scan error once when it transitions from falsy to truthy.
  const prevErrorRef = useRef<string | null>(null);
  useEffect(() => {
    if (error && !prevErrorRef.current) {
      showToast(error, 'error');
    }
    prevErrorRef.current = error;
  }, [error, showToast]);

  // Toast a completion message once when loading finishes without an error.
  const prevLoadingRef = useRef(loading);
  useEffect(() => {
    if (prevLoadingRef.current && !loading && !error) {
      showToast('Scan complete', 'success');
    }
    prevLoadingRef.current = loading;
  }, [loading, error, showToast]);

  const handleVulnScanClick = (ip: string) => {
    setVulnScanTargetIps([ip]);
    setVulnScanModalOpen(true);
  };

  const handleBatchVulnScanClick = (subnetIps: string[]) => {
    // Skip IPs already mid-scan — re-dispatching would orphan the running
    // backend scan and reset its progress bar back to 0%.
    const toScan = subnetIps.filter(ip => selectedIps.includes(ip) && !vulnScanLoadingMap[ip]);
    if (toScan.length === 0) return;
    setVulnScanTargetIps(toScan);
    setVulnScanModalOpen(true);
  };

  const handleVulnScanSelect = (type: 'posture' | 'cve' | 'misconfig' | 'full') => {
    vulnScanTargetIps.forEach(ip => {
      if (vulnScanLoadingMap[ip]) return;
      startVulnScan(ip, type);
    });
  };

  const handleBatchAdvancedScan = (subnetIps: string[]) => {
    const toScan = subnetIps.filter(ip => selectedIps.includes(ip) && !advancedScanLoadingMap[ip]);
    toScan.forEach(ip => {
      startAdvancedScan(ip);
    });
  };

  const toggleSelectAll = (subnetIps: string[]) => {
    const allSelected = subnetIps.every(ip => selectedIps.includes(ip));
    if (allSelected) {
      setSelectedIps(prev => prev.filter(ip => !subnetIps.includes(ip)));
    } else {
      setSelectedIps(prev => {
        const next = Array.from(new Set([...prev, ...subnetIps]));
        if (next.length > 50) {
          showToast('The upper limit is 50 at a time. Selection has been truncated to 50.', 'warning');
          return next.slice(0, 50);
        }
        return next;
      });
    }
  };

  const toggleSelectIp = (ip: string) => {
    setSelectedIps(prev => {
      if (prev.includes(ip)) return prev.filter(i => i !== ip);
      if (prev.length >= 50) {
        showToast('The upper limit is 50 at a time.', 'warning');
        return prev;
      }
      return [...prev, ip];
    });
  };



  const groupedAllIps = useMemo(() => {
    const groups: Record<string, string[]> = {};
    const allIps = Array.from(new Set([...knownIps, ...unknownIps, ...(staleManagedIps || []), ...(disappearedIps || [])]));
    allIps.forEach(ip => {
      const parts = ip.split('.');
      const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'Other';
      if (!groups[subnet]) groups[subnet] = [];
      groups[subnet].push(ip);
    });
    return groups;
  }, [knownIps, unknownIps, staleManagedIps, disappearedIps]);

  // result !== null (not truthiness) — a completed scan with empty output
  // ('') is a real result and must not be treated as "never scanned".
  const hasResults = result !== null || loading;

  return (
    <div className="pb-6 flex flex-col gap-6">
      {/* Page Header */}
      <div className="px-5 py-4 rounded-xl lg:rounded-2xl border border-teal-100 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shadow-sm" style={{ background: 'linear-gradient(135deg, rgb(9, 121, 112) 0%, rgb(13, 148, 136) 100%)' }}>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/15 rounded-lg">
            <Radar className="w-5 h-5 text-teal-100" strokeWidth={2} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Network Scanning</h1>
            <p className="text-sm text-teal-100">Run advanced network scans directly from the server.</p>
          </div>
        </div>

        <button
          onClick={() => setIsHistoryModalOpen(true)}
          className="px-4 py-2 bg-white hover:bg-slate-50 text-sm font-semibold rounded-lg transition-all shadow-sm flex items-center gap-2 hover:-translate-y-0.5 active:translate-y-0"
          style={{ color: 'rgb(9, 121, 112)' }}
        >
          <History className="w-4 h-4" style={{ color: 'rgb(9, 121, 112)' }} />
          History
        </button>
      </div>

      <div className={`flex flex-col ${hasResults ? 'xl:flex-row' : ''} gap-6 items-start`}>
        {/* Left Column */}
        <div className={`w-full ${hasResults ? 'xl:w-[400px] shrink-0' : ''} flex flex-col gap-6`}>
          {/* Main Content Area */}
          <div className="bg-white rounded-xl lg:rounded-2xl border border-teal-100 shadow-sm overflow-hidden">
            {/* Form Area */}
            <div className="p-5 sm:p-6">
              <form onSubmit={handleScan} className="flex flex-col gap-5">
                <div className={`flex flex-col ${!hasResults ? 'md:flex-row' : ''} gap-5 items-start`}>
                  <div className={`w-full ${!hasResults ? 'md:flex-[3]' : ''}`}>
                    <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Target IP</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <MapPin className="h-4 w-4 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        required
                        placeholder="e.g., 10.0.5.0, 192.168.1.0"
                        value={target}
                        onChange={(e) => {
                          const raw = e.target.value;
                          const isDeleting = raw.length < target.length;

                          let val = raw.replace(/[^0-9.,\s]/g, '');
                          val = val.replace(/\.{2,}/g, '.');
                          val = val.replace(/,{2,}/g, ',');

                          const ips = val.split(/([,\s]+)/);
                          const cleaned = ips.map(segment => {
                            if (/^[,\s]+$/.test(segment)) return segment;
                            const octets = segment.split('.');
                            const capped = octets.map(o => {
                              if (o === '') return '';
                              const n = parseInt(o, 10);
                              if (isNaN(n)) return '';
                              return String(Math.min(n, 255));
                            });
                            if (capped.length > 4) capped.length = 4;
                            return capped.join('.');
                          });

                          let result = cleaned.join('');

                          if (!isDeleting) {
                            const lastIp = result.split(/[,\s]/).pop() || '';
                            const lastOctets = lastIp.split('.');
                            const currentOctet = lastOctets[lastOctets.length - 1];
                            if (currentOctet && currentOctet.length === 3 && lastOctets.length < 4) {
                              result += '.';
                            }
                          }

                          setTarget(result);
                        }}
                        className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 focus:bg-white rounded-lg focus:ring-2 focus:ring-blue-100 focus:border-blue-500 transition-all text-sm font-mono text-slate-700 placeholder-slate-400"
                        disabled={loading}
                      />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">Private IPs only (10.x, 172.16-31.x, 192.168.x). Comma-separated for multiple.</p>
                  </div>

                  <div className={`w-full ${!hasResults ? 'md:w-auto' : ''}`}>
                    <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">CIDR</label>
                    <FancySelect
                      value={cidr}
                      onChange={setCidr}
                      items={CIDR_OPTIONS}
                      disabled={loading}
                      mono
                    />
                  </div>
                </div>

                <div className={`flex flex-col ${!hasResults ? 'md:flex-row md:items-end' : ''} gap-5 items-start`}>
                  <div className="w-full flex-1">
                    <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Reason for Scan</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <PenLine className="h-4 w-4 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        required
                        placeholder="e.g., Routine audit, verifying open ports"
                        value={reason}
                        maxLength={200}
                        onChange={(e) => setReason(e.target.value.replace(/[^a-zA-Z0-9 ,.\-_()]/g, ''))}
                        className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 focus:bg-white rounded-lg focus:ring-2 focus:ring-blue-100 focus:border-blue-500 transition-all text-sm text-slate-700 placeholder-slate-400"
                        disabled={loading}
                      />
                    </div>
                  </div>

                  <div className={`flex gap-3 w-full ${hasResults ? 'mt-2' : 'md:w-auto'}`}>
                    {loading && (
                      <button
                        type="button"
                        onClick={cancelScan}
                        className={`flex-1 px-4 py-2 bg-red-50 hover:bg-red-100 text-red-600 font-medium rounded-lg transition-all border border-red-200 text-sm h-[42px] flex items-center justify-center gap-1.5 hover:-translate-y-0.5 active:translate-y-0 ${!hasResults ? 'md:w-auto' : ''}`}
                      >
                        <X className="w-4 h-4" />
                        Cancel
                      </button>
                    )}
                    <button
                      type="submit"
                      disabled={loading || !target || !reason}
                      className={`flex-1 px-4 py-2 font-medium rounded-lg transition-all flex items-center justify-center gap-2 text-sm h-[42px] disabled:translate-y-0 ${!hasResults ? 'md:w-36' : ''}
                      ${loading || !target || !reason
                          ? 'bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200'
                          : 'bg-[rgb(4,34,119)] text-white hover:bg-blue-900 border border-transparent shadow-sm hover:-translate-y-0.5 active:translate-y-0'
                        }`}
                    >
                      {loading ? (
                        <>
                          <DuoSpinner size="sm" className="text-white/70" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <PlayCircle className="w-4 h-4" />
                          Run Scan
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div> {/* End Left Column */}

        {/* Right Column */}
        {(result !== null || loading) ? (
          <div className="flex-1 min-w-0">
            <div className="bg-white rounded-xl lg:rounded-2xl border border-slate-200 shadow-sm overflow-hidden h-full">
              <div className="p-6 bg-slate-50/50 flex flex-col h-full">
                {loading && (
                  <div className="flex flex-col items-center justify-center flex-1 text-slate-500 gap-4 py-20">
                    <DuoSpinner size="lg" className="text-[rgb(4,34,119)]" />
                    <div className="text-center w-full max-w-md">
                      <span className="font-medium text-lg block mb-2">Running Scan...</span>
                      <div className="w-full bg-slate-200 rounded-full h-2.5 mb-1 overflow-hidden">
                        <div className="bg-[rgb(4,34,119)] h-2.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }}></div>
                      </div>
                      <span className="text-xs text-slate-400">{progress}% Complete</span>
                    </div>
                  </div>
                )}
                {!loading && (
                  <div className="flex-1 w-full flex flex-col gap-6">
                    <NetworkScanCharts advancedScanResultsMap={advancedScanResultsMap} sessionId={currentSessionId} />
                    {(knownIps.length > 0 || unknownIps.length > 0 || (staleManagedIps && staleManagedIps.length > 0) || (disappearedIps && disappearedIps.length > 0)) ? (
                      Object.entries(groupedAllIps).map(([subnet, ips]) => (
                        <div key={subnet} className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
                          <div className="flex items-center justify-between mb-4">
                            <h3 className="text-sm font-bold text-slate-700 flex items-center gap-2">
                              <NetworkIcon className="w-4 h-4 text-slate-400" />
                              Subnet: {subnet}
                              <span className="text-xs font-normal text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">{ips.length} IPs</span>
                            </h3>

                            {ips.some(ip => selectedIps.includes(ip)) && (
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => handleBatchAdvancedScan(ips)}
                                  className="px-3 py-1.5 bg-white text-slate-600 border border-slate-200 text-xs font-medium rounded-md transition-all hover:bg-[rgb(4,34,119)] hover:text-white hover:border-transparent flex items-center gap-1.5 shadow-sm hover:-translate-y-0.5 active:translate-y-0"
                                >
                                  <Search className="w-3.5 h-3.5" />
                                  Batch Advanced Scan
                                </button>
                                <button
                                  onClick={() => handleBatchVulnScanClick(ips)}
                                  className="px-3 py-1.5 bg-white text-slate-600 border border-slate-200 text-xs font-medium rounded-md transition-all hover:bg-rose-600 hover:text-white hover:border-transparent flex items-center gap-1.5 shadow-sm hover:-translate-y-0.5 active:translate-y-0"
                                >
                                  <AlertTriangle className="w-3.5 h-3.5" />
                                  Batch Vuln Scan
                                </button>
                              </div>
                            )}
                          </div>
                          <div className="max-h-[470px] overflow-y-auto overflow-x-auto">
                            <table className="w-full min-w-[720px] border-separate border-spacing-0">
                              <thead>
                                <tr
                                  className="text-left text-xs font-semibold uppercase tracking-wide"
                                  style={{
                                    background: "linear-gradient(135deg, rgb(9, 121, 112) 0%, rgb(13, 148, 136) 100%)",
                                  }}
                                >
                                  <th className="sticky top-0 z-20 px-5 py-3 w-14 text-center bg-teal-600 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                                    {(() => {
                                      const selectableIps = ips.filter(ip => !disappearedIps?.includes(ip));
                                      return (
                                        <div className="flex justify-center">
                                          <Checkbox
                                            checked={selectableIps.length > 0 && selectableIps.every(ip => selectedIps.includes(ip))}
                                            indeterminate={
                                              selectableIps.some(ip => selectedIps.includes(ip)) &&
                                              !selectableIps.every(ip => selectedIps.includes(ip))
                                            }
                                            onChange={() => toggleSelectAll(selectableIps)}
                                            aria-label="Select all IPs in subnet"
                                          />
                                        </div>
                                      );
                                    })()}
                                  </th>

                                  <th className="sticky top-0 z-20 px-5 py-3 text-white bg-teal-600 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                                    IP Address
                                  </th>

                                  <th className="sticky top-0 z-20 px-5 py-3 text-white text-right bg-teal-600 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                                    Action
                                  </th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-100">
                                {ips.map((ip) => {
                                  const isDisappeared = disappearedIps?.includes(ip);
                                  const isNew = newIps?.includes(ip);
                                  const isManaged = knownIps?.includes(ip);
                                  const isStaleManaged = staleManagedIps?.includes(ip);

                                  const advResult = advancedScanResultsMap[ip];
                                  const isAdvScanning = !!advancedScanLoadingMap[ip];
                                  const hasAdvResult = !!advResult;
                                  const hasAdvError = !!advancedScanErrorMap[ip];

                                  const vulnResult = vulnScanResultsMap[ip];
                                  const isVulnScanning = !!vulnScanLoadingMap[ip];
                                  const hasVulnResult = !!vulnResult;
                                  const hasVulnError = !!vulnScanErrorMap[ip];

                                  return (
                                    <tr key={ip} className={`hover:bg-slate-50/50 transition-colors ${isNew ? 'bg-emerald-50/50' : isStaleManaged ? 'bg-amber-50/50' : isDisappeared ? 'bg-rose-50/50 opacity-80' : 'bg-white'}`}>
                                      <td className="px-5 py-3 text-center w-14">
                                        <div className="flex justify-center">
                                          <Checkbox
                                            checked={selectedIps.includes(ip)}
                                            onChange={() => {
                                              if (!selectedIps.includes(ip) && selectedIps.length >= 50) {
                                                showToast('You can only select up to 50 items at a time.', 'warning');
                                                return;
                                              }
                                              toggleSelectIp(ip);
                                            }}
                                            disabled={isDisappeared}
                                            aria-label={`Select ${ip}`}
                                          />
                                        </div>
                                      </td>
                                      <td className="px-5 py-3 font-medium text-slate-800">
                                        <div className="flex items-center flex-wrap gap-y-1">
                                          <span className="font-semibold">{ip}</span>
                                          {isManaged && <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-100 px-1.5 py-0.5 rounded">Managed by Vajra</span>}
                                          {isNew && <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-emerald-600 bg-emerald-100 px-1.5 py-0.5 rounded">New</span>}
                                          {isStaleManaged && <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-amber-600 bg-amber-100 px-1.5 py-0.5 rounded" title="This IP is registered to a Vajra device that is currently offline — it may have been reassigned to a different machine.">Possible IP Reuse</span>}
                                          {isDisappeared && <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-rose-600 bg-rose-100 px-1.5 py-0.5 rounded">Disappeared</span>}
                                        </div>
                                      </td>
                                      <td className="px-5 py-3 text-right">
                                        <div className="flex items-center justify-end gap-2">
                                          {isDisappeared ? (
                                            <span className="text-[10px] text-slate-400 font-medium italic px-2">Offline</span>
                                          ) : (
                                            <>
                                              <button
                                                onClick={() => (hasAdvResult || isAdvScanning || hasAdvError) ? openAdvancedScanModal(ip) : startAdvancedScan(ip)}
                                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-all shadow-sm hover:-translate-y-0.5 active:translate-y-0 ${hasAdvError
                                                  ? "border-red-200 bg-red-50 text-red-700 hover:bg-red-100 hover:border-red-300"
                                                  : hasAdvResult
                                                  ? "border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 hover:border-emerald-300"
                                                  : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                                                  }`}>
                                                {isAdvScanning ? (
                                                  <>
                                                    <DuoSpinner size="xs" />
                                                    Scanning...
                                                  </>
                                                ) : (
                                                  <>
                                                    <Search className="w-3.5 h-3.5" />
                                                    {hasAdvError ? 'Scan Failed' : hasAdvResult ? 'View Result' : 'Advanced Scan'}
                                                  </>
                                                )}
                                              </button>
                                              <button
                                                onClick={() => (hasVulnResult || isVulnScanning || hasVulnError) ? openVulnResultModal(ip) : handleVulnScanClick(ip)}
                                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-all shadow-sm hover:-translate-y-0.5 active:translate-y-0 ${hasVulnError
                                                  ? "border-red-200 bg-red-50 text-red-700 hover:bg-red-100 hover:border-red-300"
                                                  : hasVulnResult
                                                  ? "border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 hover:border-emerald-300"
                                                  : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                                                  }`} title="Run Vulnerability Scan"
                                              >
                                                {isVulnScanning ? (
                                                  <>
                                                    <DuoSpinner size="xs" />
                                                    Scanning...
                                                  </>
                                                ) : (
                                                  <>
                                                    <AlertTriangle className="w-3.5 h-3.5" />
                                                    {hasVulnError ? 'Scan Failed' : hasVulnResult ? 'View Result' : 'Vuln Scan'}
                                                  </>
                                                )}
                                              </button>
                                            </>
                                          )}
                                        </div>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 text-center py-20 flex flex-col justify-center items-center h-full">
                        <svg className="w-12 h-12 text-slate-300 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p>{result ? 'No hosts found in this scan.' : 'Run a scan to discover hosts on the network.'}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="w-full flex-1 min-w-0">
             <LatestScanOverview />
          </div>
        )}
      </div>


      <NetworkHistoryModal
        isOpen={isHistoryModalOpen}
        onClose={() => setIsHistoryModalOpen(false)}
      />

      <AdvancedScanModal
        isOpen={isAdvancedScanModalOpen}
        onClose={() => setIsAdvancedScanModalOpen(false)}
        targetIp={advancedScanIp}
        sessionId={currentSessionId}
      />

      <VulnScanModal
        isOpen={vulnScanModalOpen}
        onClose={() => setVulnScanModalOpen(false)}
        targetIp={vulnScanTargetIps.length === 1 ? vulnScanTargetIps[0] : `${vulnScanTargetIps.length} IPs`}
        onSelect={handleVulnScanSelect}
      />

      <VulnResultModal
        isOpen={isVulnResultModalOpen}
        onClose={() => setIsVulnResultModalOpen(false)}
        targetIp={vulnScanIp}
        sessionId={currentSessionId}
      />
    </div>
  );
};

export default NetworkScanning;
