import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNetworkScan } from './context/useNetworkScan';
import { useToast } from '../../context/useToast';
import type { NucleiFinding } from '../../api/api';
import { DuoSpinner } from '@/components/ui/loading';
import { useModalA11y } from '../../hooks/useModalA11y';

interface VulnResultModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetIp: string | null;
  sessionId: number | null;
}

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string; dot: string; label: string }> = {
  critical: { bg: 'bg-rose-50', text: 'text-rose-700', border: 'border-rose-200', dot: 'bg-rose-500', label: 'Critical' },
  high:     { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', dot: 'bg-orange-500', label: 'High' },
  medium:   { bg: 'bg-yellow-50', text: 'text-yellow-700', border: 'border-yellow-200', dot: 'bg-yellow-500', label: 'Medium' },
  low:      { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', dot: 'bg-blue-500', label: 'Low' },
  info:     { bg: 'bg-slate-50', text: 'text-slate-600', border: 'border-slate-200', dot: 'bg-slate-400', label: 'Info' },
};

const SCAN_TYPE_LABELS: Record<string, string> = {
  posture: 'Security Posture Assessment',
  cve: 'CVE Vulnerability Scan',
  misconfig: 'Misconfiguration Scan',
  full: 'Full Scan',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function getSeverityConfig(severity: string) {
  return SEVERITY_CONFIG[severity?.toLowerCase()] || SEVERITY_CONFIG.info;
}

const FindingRow: React.FC<{ finding: NucleiFinding; index: number }> = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(false);
  const sev = getSeverityConfig(finding.severity);

  return (
    <div className={`border ${sev.border} rounded-lg overflow-hidden ${index > 0 ? 'mt-2' : ''}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className={`w-full text-left p-3 flex items-start gap-3 hover:bg-slate-50/50 transition-colors rounded-lg`}
      >
        <span className={`mt-0.5 shrink-0 px-2 py-0.5 rounded text-xs font-bold uppercase ${sev.bg} ${sev.text} border ${sev.border}`}>
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm text-slate-800 truncate">{finding.name}</div>
          <div className="text-xs text-slate-500 font-mono truncate mt-0.5">{finding.matchedAt || finding.host}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.cvssScore != null && (
            <span className="text-xs font-mono text-slate-500">CVSS {finding.cvssScore}</span>
          )}
          <svg className={`w-4 h-4 text-slate-400 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-3 pt-1 border-t border-slate-100 bg-slate-50/30 space-y-2">
          {finding.description && (
            <p className="text-xs text-slate-600 leading-relaxed">{finding.description}</p>
          )}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span className="text-slate-500">Template: <span className="font-mono text-slate-700">{finding.templateId}</span></span>
            <span className="text-slate-500">Type: <span className="text-slate-700">{finding.type}</span></span>
            {finding.ip && <span className="text-slate-500">IP: <span className="font-mono text-slate-700">{finding.ip}</span></span>}
          </div>
          {finding.cveId.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {finding.cveId.map(cve => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded text-xs font-mono hover:bg-rose-100 transition-colors"
                >
                  {cve}
                </a>
              ))}
            </div>
          )}
          {finding.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.tags.map(tag => (
                <span key={tag} className="px-1.5 py-0.5 bg-slate-100 text-slate-500 rounded text-[10px] font-mono">{tag}</span>
              ))}
            </div>
          )}
          {finding.reference.length > 0 && (
            <details className="text-xs">
              <summary className="text-slate-500 cursor-pointer hover:text-slate-700">References ({finding.reference.length})</summary>
              <div className="mt-1 space-y-0.5 pl-2">
                {finding.reference.filter(ref => /^https?:\/\//i.test(ref)).map((ref, i) => (
                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="block text-blue-600 hover:underline truncate font-mono">{ref}</a>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
};

const VulnResultModal: React.FC<VulnResultModalProps> = ({ isOpen, onClose, targetIp }) => {
  const {
    vulnScanLoadingMap,
    vulnScanProgressMap,
    vulnScanResult: scanResult,
    vulnScanErrorMap,
    vulnScanTypeMap,
    cancelVulnScan,
  } = useNetworkScan();
  const { showToast } = useToast();

  const loading = targetIp ? !!vulnScanLoadingMap[targetIp] : false;
  const progress = targetIp ? vulnScanProgressMap[targetIp] || 0 : 0;
  const error = targetIp ? vulnScanErrorMap[targetIp] : null;
  const nucleiScanType = targetIp ? vulnScanTypeMap[targetIp] || 'posture' : 'posture';
  const modalTitle = SCAN_TYPE_LABELS[nucleiScanType] || 'Vulnerability Scan Results';

  // Memoised so `findings` keeps one identity while no result has arrived, and so the
  // severity sort below does not re-run on every render of the open modal — which
  // includes every progress tick while a scan is still streaming.
  const findings = useMemo(() => scanResult?.findings || [], [scanResult]);
  const summary = scanResult?.summary;

  // Toast the vuln-scan error/completion once per transition, tracked per target IP.
  const prevVulnErrorRef = useRef<Record<string, boolean>>({});
  const prevVulnResultRef = useRef<Record<string, boolean>>({});

  useEffect(() => {
    if (!targetIp) return;
    const hasError = !!error;
    const hadError = !!prevVulnErrorRef.current[targetIp];
    if (hasError && !hadError) {
      showToast(error as string, 'error');
    }
    prevVulnErrorRef.current[targetIp] = hasError;
  }, [targetIp, error, showToast]);

  useEffect(() => {
    if (!targetIp) return;
    const hasResult = !!scanResult;
    const hadResult = !!prevVulnResultRef.current[targetIp];
    if (hasResult && !hadResult && !error) {
      showToast('Vulnerability scan complete', 'success');
    }
    prevVulnResultRef.current[targetIp] = hasResult;
  }, [targetIp, scanResult, error, showToast]);

  const sortedFindings = useMemo(
    () =>
      [...findings].sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.severity?.toLowerCase());
        const bi = SEVERITY_ORDER.indexOf(b.severity?.toLowerCase());
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      }),
    [findings],
  );

  const handleClose = () => {
    if (loading && targetIp) {
      cancelVulnScan(targetIp);
    }
    onClose();
  };

  const modalRef = useModalA11y<HTMLDivElement>(isOpen, handleClose);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="vuln-result-modal-title"
        className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200"
      >

        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-4 border-b border-rose-900/50"
          style={{ backgroundColor: 'oklch(0.25 0.11 25.23)' }}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-white/10 text-white">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h2 id="vuln-result-modal-title" className="text-lg font-bold text-white">{modalTitle}</h2>
              <p className="text-xs font-mono mt-0.5" style={{ color: 'oklch(0.83 0 0)' }}>Target: {targetIp}</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            aria-label="Close"
            className="p-2 text-white/60 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-0 bg-slate-50">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500 gap-4">
              <DuoSpinner size="lg" className="text-rose-600" />
              <div className="text-center w-full max-w-sm">
                <span className="font-medium block mb-2 text-rose-700">Executing vulnerability scan...</span>
                <div className="w-full bg-slate-200 rounded-full h-2 mb-1 overflow-hidden">
                  <div className="h-2 rounded-full transition-all duration-500 bg-rose-600" style={{ width: `${progress}%` }}></div>
                </div>
                <span className="text-xs text-slate-500 block mb-1">{progress}% Complete</span>
                <p className="text-slate-400 text-xs">This may take several minutes depending on the host and scan profile.</p>
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
          ) : scanResult ? (
            <div className="p-6 space-y-5">

              {/* Summary Cards */}
              {summary && (
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  <div className="bg-white rounded-lg p-3 border border-slate-200 shadow-sm text-center">
                    <p className="text-2xl font-bold text-slate-800">{summary.totalFindings}</p>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Total</p>
                  </div>
                  {SEVERITY_ORDER.map(sev => {
                    const config = SEVERITY_CONFIG[sev];
                    const count = summary.severity[sev as keyof typeof summary.severity] || 0;
                    return (
                      <div key={sev} className={`${config.bg} rounded-lg p-3 border ${config.border} shadow-sm text-center`}>
                        <p className={`text-2xl font-bold ${config.text}`}>{count}</p>
                        <p className={`text-xs uppercase tracking-wider mt-0.5 ${config.text} opacity-70`}>{config.label}</p>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* CVE Summary */}
              {summary && summary.uniqueCveCount > 0 && (
                <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-sm">
                  <h3 className="text-sm font-semibold text-slate-700 mb-2">CVEs Detected ({summary.uniqueCveCount})</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {summary.uniqueCves.map(cve => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded text-xs font-mono hover:bg-rose-100 transition-colors"
                      >
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Findings List */}
              {sortedFindings.length > 0 ? (
                <div>
                  <h3 className="text-sm font-semibold text-slate-700 mb-3">Findings ({sortedFindings.length})</h3>
                  <div>
                    {sortedFindings.map((finding, idx) => (
                      <FindingRow key={`${finding.templateId}-${finding.host}-${idx}`} finding={finding} index={idx} />
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                  <svg className="w-12 h-12 mb-4 text-emerald-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <p className="text-lg font-medium text-slate-700">No vulnerabilities detected</p>
                  <p className="text-sm mt-1 text-slate-500">The scan completed without finding any issues on this host.</p>
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

export default VulnResultModal;
