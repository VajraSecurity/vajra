import React, { useState, useEffect, useRef } from 'react';
import { useNetworkScan } from './context/useNetworkScan';
import { useToast } from '../../context/useToast';
import { DuoSpinner } from '@/components/ui/loading';
import { useModalA11y } from '../../hooks/useModalA11y';

interface AdvancedScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetIp: string | null;
  sessionId: number | null;
}

const AdvancedScanModal: React.FC<AdvancedScanModalProps> = ({ isOpen, onClose, targetIp }) => {
  const {
    advancedScanLoadingMap,
    advancedScanProgressMap,
    advancedScanResult: result,
    advancedScanParsedResult: parsedResult,
    advancedScanErrorMap,
    cancelAdvancedScan
  } = useNetworkScan();
  const { showToast } = useToast();

  const [expandedPorts, setExpandedPorts] = useState<Set<string>>(new Set());

  const togglePort = (portId: string) => {
    setExpandedPorts(prev => {
      const newSet = new Set(prev);
      if (newSet.has(portId)) {
        newSet.delete(portId);
      } else {
        newSet.add(portId);
      }
      return newSet;
    });
  };

  const loading = targetIp ? !!advancedScanLoadingMap[targetIp] : false;
  const progress = targetIp ? advancedScanProgressMap[targetIp] || 0 : 0;
  const error = targetIp ? advancedScanErrorMap[targetIp] : null;

  // Toast the advanced-scan error/completion once per transition, tracked per target IP
  // so switching between IPs (or re-scanning the same one) doesn't re-fire stale toasts.
  const prevAdvErrorRef = useRef<Record<string, boolean>>({});
  const prevAdvResultRef = useRef<Record<string, boolean>>({});

  useEffect(() => {
    if (!targetIp) return;
    const hasError = !!error;
    const hadError = !!prevAdvErrorRef.current[targetIp];
    if (hasError && !hadError) {
      showToast(error as string, 'error');
    }
    prevAdvErrorRef.current[targetIp] = hasError;
  }, [targetIp, error, showToast]);

  useEffect(() => {
    if (!targetIp) return;
    const hasResult = !!parsedResult;
    const hadResult = !!prevAdvResultRef.current[targetIp];
    if (hasResult && !hadResult && !error) {
      showToast(`Advanced scan on ${targetIp} complete`, 'success');
    }
    prevAdvResultRef.current[targetIp] = hasResult;
  }, [targetIp, parsedResult, error, showToast]);

  const modalTitle = 'Advanced Deep Scan Results';

  const handleClose = () => {
    if (loading && targetIp) {
      cancelAdvancedScan(targetIp);
    }
    onClose();
  };

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, handleClose);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="advanced-scan-modal-title"
        className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200"
      >

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b bg-slate-50 border-slate-200">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-100 text-blue-700">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            </div>
            <div>
              <h2 id="advanced-scan-modal-title" className="text-lg font-bold text-slate-900">{modalTitle}</h2>
              <p className="text-xs font-mono mt-0.5 text-slate-500">Target: {targetIp}</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            aria-label={loading ? 'Cancel scan and close' : 'Close'}
            title={loading ? 'Cancel scan and close' : 'Close'}
            className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-200/50 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-0 bg-slate-50">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500 gap-4">
              <DuoSpinner size="lg" className="text-blue-600" />
              <div className="text-center w-full max-w-sm">
                <span className="font-medium block mb-2 text-blue-700">
                  Executing advanced deep scan...
                </span>
                <div className="w-full bg-slate-200 rounded-full h-2 mb-1 overflow-hidden">
                  <div className="h-2 rounded-full transition-all duration-500 bg-blue-600" style={{ width: `${progress}%` }}></div>
                </div>
                <span className="text-xs text-slate-500 block mb-1">{progress}% Complete</span>
                <p className="text-slate-400 text-xs">This may take several minutes depending on the host.</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center h-64 text-center gap-3 px-6">
              <div className="w-12 h-12 rounded-full bg-red-50 flex items-center justify-center">
                <svg className="w-6 h-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <p className="text-sm font-semibold text-slate-800">Scan failed</p>
              <p className="text-sm text-slate-500 max-w-sm">{error}</p>
            </div>
          ) : parsedResult ? (
            <div className="p-6 text-slate-800">
              {parsedResult.hostUp ? (
                <div className="space-y-6">
                  {/* Host Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                    <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                      <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Status</p>
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                        <span className="font-semibold text-slate-800">Host Up</span>
                      </div>
                    </div>
                    <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                      <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Latency</p>
                      <p className="font-semibold text-slate-800">{parsedResult.latency || 'N/A'}</p>
                    </div>
                    <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                      <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Open Ports</p>
                      <p className="font-semibold text-slate-800">{parsedResult.ports.length}</p>
                    </div>
                    {parsedResult.osGuess && parsedResult.osGuess.length > 0 && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">OS Guess</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.osGuess.join(', ')}>
                          {parsedResult.osGuess[0]}
                        </p>
                      </div>
                    )}
                    {parsedResult.deviceType && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Device Type</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.deviceType}>
                          {parsedResult.deviceType}
                        </p>
                      </div>
                    )}
                    {parsedResult.running && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Running (OS Family)</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.running}>
                          {parsedResult.running}
                        </p>
                      </div>
                    )}
                    {parsedResult.ipIdSequence && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">IP ID Sequence</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.ipIdSequence}>
                          {parsedResult.ipIdSequence}
                        </p>
                      </div>
                    )}
                    {parsedResult.networkDistance && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Network Distance</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.networkDistance}>
                          {parsedResult.networkDistance}
                        </p>
                      </div>
                    )}
                    {parsedResult.macAddress && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm col-span-2">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">MAC Address</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.macAddress}>
                          {parsedResult.macAddress}
                        </p>
                      </div>
                    )}
                    {parsedResult.cpe && parsedResult.cpe.length > 0 && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm col-span-2 ">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">CPE</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.cpe.join(', ')}>
                          {parsedResult.cpe[0]}
                        </p>
                      </div>
                    )}
                    {parsedResult.uptime && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm col-span-2 lg:col-span-2">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">Uptime</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.uptime}>
                          {parsedResult.uptime}
                        </p>
                      </div>
                    )}

                    {parsedResult.tcpSequence && (
                      <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm col-span-2 lg:col-span-2">
                        <p className="text-slate-500 text-xs mb-1 uppercase tracking-wider">TCP Sequence</p>
                        <p className="font-semibold text-slate-800 text-sm truncate" title={parsedResult.tcpSequence}>
                          {parsedResult.tcpSequence}
                        </p>
                      </div>
                    )}

                  </div>

                  {parsedResult.notShown && (
                    <p className="text-sm text-slate-500 italic">{parsedResult.notShown}</p>
                  )}

                  {/* Pre-scan Scripts */}
                  {parsedResult.preScanScripts && parsedResult.preScanScripts.length > 0 && (
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden p-4">
                      <h3 className="text-sm font-semibold text-slate-800 mb-2 border-b border-slate-100 pb-2">Pre-scan Scripts</h3>
                      <div className="space-y-1">
                        {parsedResult.preScanScripts.map((scriptLine, idx) => (
                          <p key={idx} className="text-xs font-mono text-slate-600 whitespace-pre-wrap">{scriptLine}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Ports Table */}
                  {parsedResult.ports.length > 0 && (
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm border-separate border-spacing-0">
                          <thead>
                            <tr>
                              <th className="px-4 py-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Port</th>
                              <th className="px-4 py-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">State</th>
                              <th className="px-4 py-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Service</th>
                              <th className="px-4 py-3 font-medium sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Version</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {parsedResult.ports.map((p, idx) => {
                              const portId = `${p.port}-${idx}`;
                              const hasDetails = p.details.length > 0;
                              const isExpanded = expandedPorts.has(portId);

                              return (
                                <React.Fragment key={portId}>
                                  <tr 
                                    className={`hover:bg-slate-50 transition-colors ${hasDetails ? 'cursor-pointer' : ''}`}
                                    onClick={() => hasDetails && togglePort(portId)}
                                  >
                                    <td className="px-4 py-3 font-mono flex items-center gap-2">
                                      {hasDetails ? (
                                        <svg 
                                          className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} 
                                          fill="none" 
                                          viewBox="0 0 24 24" 
                                          stroke="currentColor"
                                        >
                                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                        </svg>
                                      ) : (
                                        <span className="w-4 h-4 inline-block"></span>
                                      )}
                                      <div>
                                        <span className="text-blue-700 font-semibold">{p.port}</span>
                                        <span className="text-slate-400">/{p.protocol}</span>
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${p.state === 'open' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                                        'bg-amber-50 text-amber-700 border border-amber-200'
                                        }`}>
                                        {p.state}
                                      </span>
                                    </td>
                                    <td className="px-4 py-3 text-slate-700 font-medium">{p.service}</td>
                                    <td className="px-4 py-3 text-slate-500">{p.version}</td>
                                  </tr>
                                  {hasDetails && isExpanded && (
                                    <tr className="bg-slate-50/50">
                                      <td colSpan={4} className="px-4 py-3">
                                        <div className="pl-4 border-l-2 space-y-1 border-slate-300">
                                          {p.details.map((d, dIdx) => (
                                            <p key={dIdx} className="text-xs font-mono break-words whitespace-pre-wrap text-slate-600">
                                              {d}
                                            </p>
                                          ))}
                                        </div>
                                      </td>
                                    </tr>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Summary Footer */}
                  {parsedResult.scanSummary && (
                    <div className="text-xs text-slate-500 font-mono text-right">
                      {parsedResult.scanSummary}
                    </div>
                  )}

                  {parsedResult.ports.length === 0 && (
                    <div className="mt-8 w-full max-w-3xl text-left bg-white border border-slate-200 rounded-lg p-4 shadow-sm overflow-x-auto">
                      <p className="text-xs text-amber-600 mb-2 uppercase tracking-wider font-semibold">No Open Ports Found (Raw Output)</p>
                      <pre className="text-xs font-mono text-slate-600">{result}</pre>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                  <svg className="w-12 h-12 mb-4 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <p className="text-lg font-medium text-slate-700">Host appears to be down.</p>
                  <p className="text-sm mt-1 text-slate-500">Or the Nmap output was not recognized.</p>

                  <div className="mt-8 w-full max-w-3xl text-left bg-white border border-slate-200 rounded-lg p-4 shadow-sm overflow-x-auto">
                    <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Raw Output Fallback</p>
                    <pre className="text-xs font-mono text-slate-600">{result}</pre>
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex justify-end">
          <button
            onClick={handleClose}
            className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? 'Cancel & Close' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AdvancedScanModal;
