import { useState } from 'react';
import type { FC } from 'react';
import { isAxiosError } from 'axios';
import { getScanStatus } from '../../api/api';
import { parseNmapOutput } from '../Network/utils/parseNmapOutput';
import type { ParsedNmapResult } from '../Network/utils/parseNmapOutput';
import { AdvancedScanCard } from '../Network/NetworkHistoryModal';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

export interface UnmanagedHost {
  ip: string;
  kind: 'new' | 'reuse';
  advanced_scan_id?: number;
  open_ports?: string[];
  os_guess?: string | null;
  registered_host_identifier?: string | null;
  registered_hostname?: string | null;
  registered_last_seen?: number | null;
}

const KIND_BADGE: Record<UnmanagedHost['kind'], { label: string; className: string }> = {
  new: { label: 'New', className: 'text-emerald-600 bg-emerald-100' },
  reuse: { label: 'Possible IP Reuse', className: 'text-amber-600 bg-amber-100' },
};

function formatLastSeen(unixSeconds?: number | null): string {
  if (!unixSeconds) return 'never';
  return new Date(unixSeconds * 1000).toLocaleString();
}

const HostRow: FC<{ host: UnmanagedHost }> = ({ host }) => {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ParsedNmapResult | null>(null);
  const badge = KIND_BADGE[host.kind];

  const handleToggle = async () => {
    if (expanded) {
      setExpanded(false);
      return;
    }
    setExpanded(true);
    if (result || loading || !host.advanced_scan_id) return;

    setLoading(true);
    setError(null);
    try {
      const res = await getScanStatus(host.advanced_scan_id);
      if (res.success && res.data?.output) {
        setResult(parseNmapOutput(res.data.output));
      } else {
        setError('Scan output not available.');
      }
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load scan result.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="border border-gray-100 dark:border-white/5 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-3 py-2 bg-gray-50 dark:bg-[#1c2432]">
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-xs font-semibold text-gray-900 dark:text-slate-100">{host.ip}</span>
          <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${badge.className}`}>{badge.label}</span>
        </div>
        <button
          type="button"
          onClick={handleToggle}
          disabled={!host.advanced_scan_id}
          className="rounded-lg text-[11px] font-semibold text-violet-600 hover:underline disabled:text-gray-300 disabled:no-underline flex-shrink-0"
        >
          {expanded ? 'Hide Scan' : 'View Scan'}
        </button>
      </div>

      {host.kind === 'reuse' && (
        <div className="px-3 py-1.5 text-[11px] text-gray-500 dark:text-slate-400 border-t border-gray-100 dark:border-white/5">
          Previously registered to{' '}
          <span className="font-medium text-gray-700 dark:text-slate-200">
            {host.registered_hostname || host.registered_host_identifier || 'an unidentified host'}
          </span>{' '}
          — last seen {formatLastSeen(host.registered_last_seen)}.
        </div>
      )}

      {!!host.open_ports?.length && (
        <div className="px-3 py-1.5 text-[11px] text-gray-500 dark:text-slate-400 border-t border-gray-100 dark:border-white/5">
          {host.open_ports.join(', ')}
          {host.os_guess ? ` · ${host.os_guess}` : ''}
        </div>
      )}

      {expanded && (
        <div className="p-2 border-t border-gray-100 dark:border-white/5 bg-white dark:bg-transparent">
          {loading && <p className="text-xs text-gray-400 px-2 py-2">Loading scan result...</p>}
          {error && <p className="text-xs text-rose-500 px-2 py-2">{error}</p>}
          {result && <AdvancedScanCard targetIp={host.ip} result={result} />}
        </div>
      )}
    </div>
  );
};

export const UnmanagedHostsAlertDetails: FC<{ hosts: UnmanagedHost[] }> = ({ hosts }) => {
  if (!hosts?.length) return null;
  const newCount = hosts.filter((h) => h.kind === 'new').length;
  const reuseCount = hosts.filter((h) => h.kind === 'reuse').length;

  return (
    <div className="rounded-xl border border-gray-100 dark:border-white/5 bg-gray-50 dark:bg-[#1c2432] p-3">
      <div className=" flex items-center justify-between mb-2">
        <p className="text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide">
          Flagged Hosts ({hosts.length})
        </p>
        <p className="text-[10px] text-gray-400 dark:text-slate-500">
          {newCount} new &middot; {reuseCount} possible reuse
        </p>
      </div>
      <div className="table-scrollbar scrollbar-auto-hide space-y-1.5 max-h-80 overflow-y-auto pr-1">
        {hosts.map((host) => (
          <HostRow key={host.ip} host={host} />
        ))}
      </div>
    </div>
  );
};
