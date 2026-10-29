import type { NucleiScanType } from '../../api/api';
import { useModalA11y } from '../../hooks/useModalA11y';

interface VulnScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetIp: string | null;
  onSelect: (type: NucleiScanType) => void;
}

const VulnScanModal = ({ isOpen, onClose, targetIp, onSelect }: VulnScanModalProps) => {
  const modalRef = useModalA11y<HTMLDivElement>(isOpen, onClose);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="vuln-scan-modal-title"
        className="bg-white rounded-2xl shadow-xl w-full max-w-md overflow-hidden flex flex-col"
      >
        <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <h2 id="vuln-scan-modal-title" className="text-lg font-bold text-slate-800">Vulnerability Scan</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 hover:bg-slate-200 rounded-full transition-colors">
            <svg className="w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 flex flex-col gap-3">
          <p className="text-sm text-slate-600 mb-1">Select scan profile for <span className="font-mono font-semibold">{targetIp}</span>:</p>

          <button
            onClick={() => { onSelect('posture'); onClose(); }}
            className="text-left p-4 border border-slate-200 rounded-xl hover:border-blue-500 hover:bg-blue-50 transition-all"
          >
            <div className="font-semibold text-slate-800 mb-1">Security Posture Assessment</div>
            <p className="text-xs text-slate-600">Full assessment — CVEs, misconfigurations, default credentials, and exposures. Recommended for first scan.</p>
          </button>

          <button
            onClick={() => { onSelect('cve'); onClose(); }}
            className="text-left p-4 border border-slate-200 rounded-xl hover:border-orange-500 hover:bg-orange-50 transition-all"
          >
            <div className="font-semibold text-slate-800 mb-1">CVE Scan</div>
            <p className="text-xs text-slate-600">Critical, high, and medium CVEs only. Focused check for known vulnerabilities.</p>
          </button>

          <button
            onClick={() => { onSelect('misconfig'); onClose(); }}
            className="text-left p-4 border border-slate-200 rounded-xl hover:border-yellow-500 hover:bg-yellow-50 transition-all"
          >
            <div className="font-semibold text-slate-800 mb-1">Misconfiguration Scan</div>
            <p className="text-xs text-slate-600">Default credentials, exposed admin panels, open databases, and configuration issues.</p>
          </button>

          <button
            onClick={() => { onSelect('full'); onClose(); }}
            className="text-left p-4 border border-rose-200 rounded-xl hover:border-rose-500 hover:bg-rose-50 transition-all"
          >
            <div className="font-semibold text-rose-800 mb-1">Full Scan</div>
            <p className="text-xs text-slate-600">All templates including info-level findings. Most comprehensive but slowest.</p>
          </button>
        </div>
      </div>
    </div>
  );
};

export default VulnScanModal;
