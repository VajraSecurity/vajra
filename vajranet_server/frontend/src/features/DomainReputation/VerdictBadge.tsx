import { ShieldCheck, ShieldAlert, ShieldX, ShieldQuestion, OctagonX } from 'lucide-react';
import type { DomainReputationVerdict } from '../../api/api';

const STYLES: Record<DomainReputationVerdict, string> = {
  clean: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  suspicious: 'bg-amber-50 text-amber-700 border-amber-200',
  malicious: 'bg-red-50 text-red-700 border-red-200',
  unknown: 'bg-slate-100 text-slate-600 border-slate-200',
  error: 'bg-orange-50 text-orange-700 border-orange-200',
};

const LABELS: Record<DomainReputationVerdict, string> = {
  clean: 'Clean',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
  unknown: 'Unknown',
  error: 'Error',
};

const ICONS: Record<DomainReputationVerdict, typeof ShieldCheck> = {
  clean: ShieldCheck,
  suspicious: ShieldAlert,
  malicious: ShieldX,
  unknown: ShieldQuestion,
  error: OctagonX,
};

interface VerdictBadgeProps {
  verdict: DomainReputationVerdict | string;
  /**
   * True when this verdict is about a domain's resolved IP address rather
   * than the domain itself (manual server & AbuseIPDB only ever see IPs, so
   * a domain check gets resolved first). A shared-hosting/CDN IP commonly
   * reads clean even when the domain sitting behind it is malicious, so
   * that substitution needs to be visible next to the badge, not buried in
   * the summary text.
   */
  resolvedFromDomain?: boolean;
}

const VerdictBadge = ({ verdict, resolvedFromDomain }: VerdictBadgeProps) => {
  const key = (verdict in STYLES ? verdict : 'unknown') as DomainReputationVerdict;
  const Icon = ICONS[key];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${STYLES[key]}`}>
        <Icon className="h-3 w-3" strokeWidth={2.5} />
        {LABELS[key]}
      </span>
      {resolvedFromDomain && (
        <span
          className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-sky-50 text-sky-700 border border-sky-200"
          title="This verdict is about the domain's resolved IP address, not the domain itself — shared hosting/CDN IPs often read clean even for a malicious domain."
        >
          IP-based
        </span>
      )}
    </span>
  );
};

export default VerdictBadge;
