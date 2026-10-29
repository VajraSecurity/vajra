/**
 * NodesView Storage tab: disk inventory, volumes, and encryption status.
 */

import { useEffect, useState } from 'react';
import type { NodeData } from './types';
import { nodesViewApi } from './nodesViewApi';

interface NodesViewStorageProps {
  node: NodeData;
}

interface StorageVolume {
  name: string;
  mount: string;
  fs: string;
  totalBytes: number;
  usedBytes: number;
  availableBytes: number;
  bootPartition?: boolean;
}

interface MountEntry {
  device?: string;
  device_alias?: string;
  path?: string;
  type?: string;
  total_bytes?: number | null;
  available_bytes?: number | null;
  free_bytes?: number | null;
  blocks_size?: number | null;
  blocks?: number | null;
  blocks_free?: number | null;
  blocks_available?: number | null;
  inodes?: number | null;
  inodes_free?: number | null;
  flags?: string;
}

interface DiskInfoEntry {
  disk_id?: string;
  pnp_device_id?: string;
  partitions?: string;
  disk_index?: number;
  type?: string;
  disk_size?: number | null;
  manufacturer?: string;
  hardware_model?: string;
  name?: string;
  serial?: string;
  description?: string;
}

interface BitlockerEntry {
  device_id?: string;
  drive_letter?: string;
  persistent_volume_id?: string;
  conversion_status?: number | null;
  protection_status?: number | null;
  encryption_method?: string;
  version?: number | null;
  percentage_encrypted?: number | null;
  lock_status?: number | null;
}

interface DiskEncryptionEntry {
  name?: string;
  uuid?: string;
  encrypted?: number | null;
  type?: string;
  encryption_status?: string;
  uid?: string;
  user_uuid?: string;
  filevault_status?: string;
}

interface NodeStorageData {
  platform: string;
  volumes: StorageVolume[];
  mounts?: MountEntry[];
  diskInfo?: DiskInfoEntry[];
  bitlocker?: BitlockerEntry[];
  diskEncryption?: DiskEncryptionEntry[];
}

// Formatters

const formatBytes = (bytes: number | null) => {
  if (bytes === null || bytes === undefined) return 'N/A';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const pct = (part: number | null, whole: number | null) => {
  if (!part || !whole || whole === 0) return 0;
  return Math.round((part / whole) * 1000) / 10;
};

// Status decoders

interface StatusDef {
  label: string;
  variant: 'success' | 'danger' | 'warning' | 'neutral';
}

function getBitlockerProtectionStatus(val: number | null | undefined): StatusDef {
  switch (val) {
    case 1:  return { label: 'Protected',   variant: 'success' };
    case 0:  return { label: 'Unprotected', variant: 'danger'  };
    case 2:  return { label: 'Unknown',     variant: 'warning' };
    default: return { label: 'N/A',         variant: 'neutral' };
  }
}

function getBitlockerConversionStatus(val: number | null | undefined): StatusDef {
  switch (val) {
    case 1:  return { label: 'Fully Encrypted',        variant: 'success' };
    case 0:  return { label: 'Fully Decrypted',        variant: 'danger'  };
    case 2:  return { label: 'Encryption in Progress', variant: 'warning' };
    case -1: return { label: 'Not Applicable',         variant: 'neutral' };
    default: return { label: 'N/A',                    variant: 'neutral' };
  }
}

function getBitlockerLockStatus(val: number | null | undefined): StatusDef {
  switch (val) {
    case 0:  return { label: 'Unlocked', variant: 'success' };
    case 1:  return { label: 'Locked',   variant: 'danger'  };
    default: return { label: 'N/A',      variant: 'neutral' };
  }
}

function getEncryptedStatus(val: number | null | undefined): StatusDef {
  switch (val) {
    case 1:  return { label: 'Encrypted',     variant: 'success' };
    case 0:  return { label: 'Not Encrypted', variant: 'danger'  };
    default: return { label: 'N/A',           variant: 'neutral' };
  }
}

// Shared UI primitives

const BADGE_CLASSES: Record<StatusDef['variant'], string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200 ring-emerald-600/10',
  danger:  'bg-red-50    text-red-700    border-red-200    ring-red-600/10',
  warning: 'bg-amber-50  text-amber-700  border-amber-200  ring-amber-600/10',
  neutral: 'bg-slate-50  text-slate-600  border-slate-200  ring-slate-500/10',
};

const DOT_CLASSES: Record<StatusDef['variant'], string> = {
  success: 'bg-emerald-500',
  danger:  'bg-red-500',
  warning: 'bg-amber-500',
  neutral: 'bg-slate-400',
};

const StatusBadge = ({ status }: { status: StatusDef }) => (
  <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${BADGE_CLASSES[status.variant]}`}>
    <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${DOT_CLASSES[status.variant]}`} aria-hidden />
    {status.label}
  </span>
);

const UtilizationTrack = ({ usedFraction, className = '' }: { usedFraction: number; className?: string }) => {
  const p = Math.min(100, Math.max(0, usedFraction * 100));
  return (
    <div
      className={`h-1.5 w-full min-w-[4rem] rounded-full bg-slate-200/80 overflow-hidden ring-1 ring-inset ring-slate-900/5 ${className}`}
      role="progressbar"
      aria-valuenow={Math.round(p)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full rounded-full bg-gradient-to-r from-slate-600 via-slate-700 to-slate-800 shadow-[inset_0_1px_0_rgba(255,255,255,0.15)]"
        style={{ width: `${p}%` }}
      />
    </div>
  );
};

const SectionHeader = ({
  icon, headingId, title, subtitle, badge, isExpanded, onToggle,
}: {
  icon: string; headingId: string; title: string; subtitle: string; badge?: React.ReactNode; isExpanded?: boolean; onToggle?: () => void;
}) => (
  <div className="px-5 sm:px-6 py-4 bg-gradient-to-r from-blue-50 to-cyan-50 flex flex-wrap items-center justify-between gap-3">
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 text-white shadow-sm">
        <i className={`${icon} text-sm`} aria-hidden />
      </div>
      <div>
        <h3 id={headingId} className="text-sm font-semibold text-slate-900">{title}</h3>
        <p className="text-xs text-slate-500">{subtitle}</p>
      </div>
    </div>
    <div className="flex items-center gap-2">
      {badge}
      {onToggle && (
        <button
          type="button"
          onClick={onToggle}
          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-900"
          aria-label={isExpanded ? `Collapse ${title}` : `Expand ${title}`}
          aria-expanded={isExpanded}
          title={isExpanded ? `Collapse ${title}` : `Expand ${title}`}
        >
          <i className={`fa-solid ${isExpanded ? 'fa-chevron-up' : 'fa-chevron-down'} text-xs`} aria-hidden />
        </button>
      )}
    </div>
  </div>
);

// Main component

const NodesViewStorage = ({ node }: NodesViewStorageProps) => {
  const [storage, setStorage] = useState<NodeStorageData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState({
    volumes: false,
    physicalDisks: false,
    mounts: false,
    bitlocker: false,
    diskEncryption: false,
  });

  const toggleSection = (key: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    if (!node?.host_identifier) {
      setStorage(null);
      setError('Node identifier is unavailable.');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    nodesViewApi
      .getStorage(node.host_identifier)
      .then((response) => {
        if (cancelled) return;
        setStorage(response.data?.data ?? null);
      })
      .catch((err) => {
        console.error('Failed to load storage telemetry:', err);
        if (!cancelled) { setError('Failed to load storage telemetry.'); setStorage(null); }
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [node?.host_identifier]);

  const isWindows = (node.os_platform || '').toLowerCase().includes('windows');
  const platformLabel = storage?.platform ? storage.platform : isWindows ? 'Windows' : 'Linux';

  const disks            = storage?.volumes         ?? [];
  const mounts           = storage?.mounts          ?? [];
  const diskInfo         = storage?.diskInfo         ?? [];
  const bitlockerEntries = storage?.bitlocker        ?? [];
  const diskEncryptionEntries = storage?.diskEncryption ?? [];

  const totalDiskBytes = disks.reduce((sum, d) => sum + d.totalBytes, 0);
  const usedDiskBytes  = disks.reduce((sum, d) => sum + d.usedBytes,  0);
  const diskAggFrac    = totalDiskBytes > 0 ? usedDiskBytes / totalDiskBytes : 0;

  return (
    <div className="bg-[#fafbfc] min-h-full">
      <div className="mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-8">

        {/* Header */}
        <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 border-b border-slate-200/80 pb-6">
          <div>
            <h2 className="mt-1.5 text-2xl sm:text-[1.65rem] font-semibold text-slate-900 tracking-tight">
              Storage &amp; memory
            </h2>
            <p className="mt-2 text-sm text-slate-600 max-w-xl leading-relaxed">
              Disk inventory, volume utilization, memory modules, and encryption status for this node.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 shadow-sm">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden />
              {platformLabel}
            </span>
          </div>
        </header>

        {(loading || error) && (
          <div className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] p-6">
            {loading
              ? <p className="text-sm text-slate-600">Loading storage telemetry…</p>
              : <p className="text-sm text-amber-700">{error}</p>}
          </div>
        )}

        {storage && (
          <>
            {/* Volumes */}
            <section
              className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] overflow-hidden"
              aria-labelledby="storage-volumes-heading"
            >
              <SectionHeader
                icon="fa-solid fa-hard-drive"
                headingId="storage-volumes-heading"
                title="Volumes"
                subtitle={`${disks.length} mount${disks.length === 1 ? '' : 's'} · ${pct(usedDiskBytes, totalDiskBytes)}% aggregate use of ${formatBytes(totalDiskBytes)}`}
                isExpanded={expandedSections.volumes}
                onToggle={() => toggleSection('volumes')}
              />
              {expandedSections.volumes && (
                <>
                  {disks.length === 0 ? (
                    <div className="p-8 text-sm text-slate-600">No mounted volumes were found for this node.</div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-sm border-separate border-spacing-0">
                        <thead>
                          <tr className="border-b border-slate-200 bg-slate-50/80">
                            <th scope="col" className="px-5 sm:px-6 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Volume</th>
                            <th scope="col" className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap hidden md:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Mount / Path</th>
                            <th scope="col" className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap hidden lg:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">File system</th>
                            <th scope="col" className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right tabular-nums sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Capacity</th>
                            <th scope="col" className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right tabular-nums hidden sm:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Used</th>
                            <th scope="col" className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right tabular-nums hidden sm:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Available</th>
                            <th scope="col" className="px-5 sm:px-6 py-3 font-semibold text-slate-700 min-w-[8rem] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Utilization</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {disks.map((d) => {
                            const frac = d.totalBytes > 0 ? d.usedBytes / d.totalBytes : 0;
                            return (
                              <tr key={`${d.mount}-${d.name}`} className="bg-white hover:bg-slate-50/60 transition-colors">
                                <td className="px-5 sm:px-6 py-4 align-middle">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-medium text-slate-900">{d.name}</span>
                                    {d.bootPartition && (
                                      <span className="inline-flex items-center rounded-md border border-blue-200 bg-blue-50 px-1.5 py-0.5 text-[10px] font-medium text-blue-700">boot</span>
                                    )}
                                  </div>
                                  <div className="mt-0.5 md:hidden">
                                    <span className="text-xs font-mono text-slate-500">{d.mount}</span>
                                    <span className="text-slate-300 mx-1">·</span>
                                    <span className="text-xs text-slate-500">{d.fs}</span>
                                  </div>
                                </td>
                                <td className="px-4 py-4 align-middle hidden md:table-cell">
                                  <span className="font-mono text-xs text-slate-700">{d.mount}</span>
                                </td>
                                <td className="px-4 py-4 align-middle hidden lg:table-cell">
                                  <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700">{d.fs}</span>
                                </td>
                                <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-800 font-medium">{formatBytes(d.totalBytes)}</td>
                                <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700 hidden sm:table-cell">{formatBytes(d.usedBytes)}</td>
                                <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700 hidden sm:table-cell">{formatBytes(d.availableBytes)}</td>
                                <td className="px-5 sm:px-6 py-4 align-middle">
                                  <div className="flex flex-col gap-1.5">
                                    <UtilizationTrack usedFraction={frac} />
                                    <span className="text-[11px] text-slate-500 tabular-nums">{pct(d.usedBytes, d.totalBytes)}% used</span>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <div className="px-5 sm:px-6 py-3 border-t border-slate-100 bg-slate-50/50">
                    <UtilizationTrack usedFraction={diskAggFrac} className="max-w-md" />
                    <p className="mt-2 text-xs text-slate-500">
                      Combined utilization:{' '}
                      <span className="font-medium text-slate-700 tabular-nums">{formatBytes(usedDiskBytes)}</span>
                      <span className="text-slate-400"> / </span>
                      <span className="tabular-nums">{formatBytes(totalDiskBytes)}</span>
                    </p>
                  </div>
                </>
              )}
            </section>

            {/* Physical Disks (Windows WMI) */}
            {diskInfo.length > 0 && (
              <section
                className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] overflow-hidden"
                aria-labelledby="storage-disk-info-heading"
              >
                <SectionHeader
                  icon="fa-solid fa-server"
                  headingId="storage-disk-info-heading"
                  title="Physical disks"
                  subtitle={`${diskInfo.length} disk${diskInfo.length === 1 ? '' : 's'} from WMI inventory`}
                  isExpanded={expandedSections.physicalDisks}
                  onToggle={() => toggleSection('physicalDisks')}
                />
                {expandedSections.physicalDisks && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-separate border-spacing-0">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50/80">
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Disk</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Interface</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Manufacturer</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Model</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Serial</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Capacity</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Partitions</th>
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {diskInfo.map((disk, index) => (
                          <tr key={`${disk.name}-${disk.disk_id}-${index}`} className="bg-white hover:bg-slate-50/60 transition-colors">
                            <td className="px-5 py-4 align-middle">
                              <span className="font-medium text-slate-900 font-mono text-xs">{disk.name || `Disk ${index}`}</span>
                              {disk.disk_index != null && <div className="text-xs text-slate-500 mt-0.5">Index {disk.disk_index}</div>}
                            </td>
                            <td className="px-4 py-4 align-middle">
                              {disk.type
                                ? <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700">{disk.type}</span>
                                : <span className="text-slate-400">—</span>}
                            </td>
                            <td className="px-4 py-4 align-middle text-slate-700">{disk.manufacturer || '—'}</td>
                            <td className="px-4 py-4 align-middle text-slate-700">{disk.hardware_model || '—'}</td>
                            <td className="px-4 py-4 align-middle text-slate-700 font-mono text-xs">{disk.serial || '—'}</td>
                            <td className="px-4 py-4 align-middle text-right tabular-nums font-medium text-slate-800">{formatBytes(disk.disk_size ?? null)}</td>
                            <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700">{disk.partitions ?? '—'}</td>
                            <td className="px-5 py-4 align-middle text-slate-600 text-xs">{disk.description || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            )}

            {/* Mount Details (Linux) */}
            {mounts.length > 0 && (
              <section
                className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] overflow-hidden"
                aria-labelledby="storage-mounts-heading"
              >
                <SectionHeader
                  icon="fa-solid fa-network-wired"
                  headingId="storage-mounts-heading"
                  title="Mount details"
                  subtitle={`${mounts.length} mount point${mounts.length === 1 ? '' : 's'} from the node`}
                  isExpanded={expandedSections.mounts}
                  onToggle={() => toggleSection('mounts')}
                />
                {expandedSections.mounts && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-separate border-spacing-0">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50/80">
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Mount point</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">FS type</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Total</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Available</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Inodes free</th>
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Flags</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {mounts.map((mount, index) => (
                          <tr key={`${mount.device}-${mount.path}-${index}`} className="bg-white hover:bg-slate-50/60 transition-colors">
                            <td className="px-5 py-4 align-middle text-slate-700 font-mono text-xs">{mount.device || 'n/a'}</td>
                            <td className="px-4 py-4 align-middle font-mono text-xs font-medium text-slate-900">{mount.path || 'n/a'}</td>
                            <td className="px-4 py-4 align-middle">
                              {mount.type
                                ? <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700">{mount.type}</span>
                                : <span className="text-slate-400">—</span>}
                            </td>
                            <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700">{formatBytes(mount.total_bytes ?? null)}</td>
                            <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700">{formatBytes(mount.available_bytes ?? mount.free_bytes ?? null)}</td>
                            <td className="px-4 py-4 align-middle text-right tabular-nums text-slate-700">{mount.inodes_free != null ? mount.inodes_free.toLocaleString() : '—'}</td>
                            <td className="px-5 py-4 align-middle text-slate-500 font-mono text-xs truncate max-w-[16rem]">{mount.flags || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            )}

            {/* BitLocker Encryption (Windows) */}
            {bitlockerEntries.length > 0 && (
              <section
                className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] overflow-hidden"
                aria-labelledby="storage-bitlocker-heading"
              >
                <SectionHeader
                  icon="fa-solid fa-lock"
                  headingId="storage-bitlocker-heading"
                  title="BitLocker encryption"
                  subtitle={`${bitlockerEntries.length} volume${bitlockerEntries.length === 1 ? '' : 's'} — Windows drive encryption state`}
                  badge={(() => {
                    const protected_ = bitlockerEntries.filter((e) => e.protection_status === 1).length;
                    const total = bitlockerEntries.length;
                    const v = protected_ === total ? 'success' : protected_ === 0 ? 'danger' : 'warning';
                    return (
                      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${BADGE_CLASSES[v]}`}>
                        <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${DOT_CLASSES[v]}`} aria-hidden />
                        {protected_}/{total} protected
                      </span>
                    );
                  })()}
                  isExpanded={expandedSections.bitlocker}
                  onToggle={() => toggleSection('bitlocker')}
                />
                {expandedSections.bitlocker && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-separate border-spacing-0">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50/80">
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Drive</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Protection</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Encryption State</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Lock</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Method</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Encrypted</th>
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Version</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {bitlockerEntries.map((entry, index) => {
                          const encPct = entry.percentage_encrypted ?? null;
                          return (
                            <tr key={`${entry.drive_letter}-${entry.device_id}-${index}`} className="bg-white hover:bg-slate-50/60 transition-colors">
                              <td className="px-5 py-4 align-middle">
                                <span className="font-mono text-sm font-semibold text-slate-900">{entry.drive_letter || '—'}</span>
                                {entry.device_id && (
                                  <div className="text-[10px] text-slate-400 font-mono mt-0.5 truncate max-w-[12rem]" title={entry.device_id}>
                                    {entry.device_id}
                                  </div>
                                )}
                              </td>
                              <td className="px-4 py-4 align-middle"><StatusBadge status={getBitlockerProtectionStatus(entry.protection_status)} /></td>
                              <td className="px-4 py-4 align-middle"><StatusBadge status={getBitlockerConversionStatus(entry.conversion_status)} /></td>
                              <td className="px-4 py-4 align-middle"><StatusBadge status={getBitlockerLockStatus(entry.lock_status)} /></td>
                              <td className="px-4 py-4 align-middle">
                                {entry.encryption_method
                                  ? <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700">{entry.encryption_method}</span>
                                  : <span className="text-slate-400">—</span>}
                              </td>
                              <td className="px-4 py-4 align-middle">
                                {encPct !== null ? (
                                  <div className="flex flex-col gap-1.5 min-w-[6rem]">
                                    <UtilizationTrack usedFraction={encPct / 100} />
                                    <span className="text-[11px] text-slate-500 tabular-nums">{encPct}%</span>
                                  </div>
                                ) : <span className="text-slate-400">—</span>}
                              </td>
                              <td className="px-5 py-4 align-middle text-slate-600 tabular-nums">{entry.version ?? '—'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            )}

            {/* Disk Encryption (Linux LUKS) */}
            {diskEncryptionEntries.length > 0 && (
              <section
                className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06),0_8px_24px_rgba(15,23,42,0.04)] overflow-hidden"
                aria-labelledby="storage-encryption-heading"
              >
                <SectionHeader
                  icon="fa-solid fa-shield-halved"
                  headingId="storage-encryption-heading"
                  title="Disk encryption"
                  subtitle={`${diskEncryptionEntries.length} partition${diskEncryptionEntries.length === 1 ? '' : 's'} — block-level encryption status`}
                  badge={(() => {
                    const encCount = diskEncryptionEntries.filter((e) => e.encrypted === 1).length;
                    const total = diskEncryptionEntries.length;
                    const v = encCount === total ? 'success' : encCount === 0 ? 'danger' : 'warning';
                    return (
                      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${BADGE_CLASSES[v]}`}>
                        <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${DOT_CLASSES[v]}`} aria-hidden />
                        {encCount}/{total} encrypted
                      </span>
                    );
                  })()}
                  isExpanded={expandedSections.diskEncryption}
                  onToggle={() => toggleSection('diskEncryption')}
                />
                {expandedSections.diskEncryption && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-separate border-spacing-0">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50/80">
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Device</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Encrypted</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Type</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">UUID</th>
                          <th className="px-4 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Key owner UID</th>
                          <th className="px-5 py-3 font-semibold text-slate-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">FileVault</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {diskEncryptionEntries.map((entry, index) => (
                          <tr key={`${entry.name}-${entry.uuid}-${index}`} className="bg-white hover:bg-slate-50/60 transition-colors">
                            <td className="px-5 py-4 align-middle font-mono text-xs font-medium text-slate-900">{entry.name || '—'}</td>
                            <td className="px-4 py-4 align-middle"><StatusBadge status={getEncryptedStatus(entry.encrypted)} /></td>
                            <td className="px-4 py-4 align-middle">
                              {entry.type
                                ? <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-700 uppercase">{entry.type}</span>
                                : <span className="text-slate-400">—</span>}
                            </td>
                            <td className="px-4 py-4 align-middle text-slate-700">{entry.encryption_status || '—'}</td>
                            <td className="px-4 py-4 align-middle text-slate-500 font-mono text-xs break-all">{entry.uuid || '—'}</td>
                            <td className="px-4 py-4 align-middle text-slate-700 tabular-nums text-xs">{entry.uid || '—'}</td>
                            <td className="px-5 py-4 align-middle text-slate-600">{entry.filevault_status || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default NodesViewStorage;
