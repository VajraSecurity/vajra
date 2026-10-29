/**
 * NodesView Programs tab: Installed packages/programs list.
 * API: nodesViewApi.getProgramsList
 */

import { useCallback, useState, useEffect } from 'react';
import { PackageSearch } from 'lucide-react';
import { motion } from 'motion/react';
import type { NodeData } from './types';
import { nodesViewApi } from './nodesViewApi';
import DynamicDataTable from './DynamicDataTable';
import ProgramDetailsDrawer from './ProgramDetailsDrawer';

interface NodesViewProgramsProps {
  node: NodeData;
}

interface CVEItem {
  cwe?: string;
  severity?: string;
  cvss_score?: number;
  description?: string;
  published?: string;
  exploit_status?: string;
  [key: string]: unknown;
}

export interface ProgramRow {
  name?: string;
  version?: string;
  release?: string;
  publisher?: string;
  install_date?: string;
  install_time?: string | number;
  first_reported_at?: string | number;
  cve_match?: Record<string, CVEItem> | null;
  cve_summary?: string; // New field for the table view
  /** Raw column from programs/deb_packages/rpm_packages: CISA KEV match. */
  has_kev_cve?: boolean | null;
  /** Display-friendly alias of has_kev_cve, set by normalizePrograms. */
  kev?: boolean;
  /** Debian / dpkg */
  maintainer?: string;
  source?: string;
  arch?: string;
  section?: string;
  status?: string;
  size?: string | number;
  revision?: string;
  admindir?: string;
  priority?: string;
  sanitized_name?: string;
  sanitized_version?: string;
  major_release_version?: string;
  unixtime?: string | number;
  /** Formatted dpkg Installed-Size for tables */
  installed_size?: string;
  [key: string]: unknown;
}

type ProgramsPayload = {
  programs?: ProgramRow[];
  deb?: ProgramRow[];
  rpm?: ProgramRow[];
  snap_packages?: ProgramRow[];
  chrome_extensions?: ProgramRow[];
  npm_packages?: ProgramRow[];
  portage_packages?: ProgramRow[];
  firefox_addons?: ProgramRow[];
  choco?: ProgramRow[];
  ie_extensions?: ProgramRow[];
};

const TAB_DEFS = [
  { key: 'programs', label: 'Programs', osType: 'windows' as const },
  { key: 'deb', label: 'Deb', osType: 'linux' as const },
  { key: 'rpm', label: 'Rpm', osType: 'linux' as const },
  { key: 'snap_packages', label: 'Snap', osType: 'ubuntu' as const },
  { key: 'chrome_extensions', label: 'Chrome Extensions', osType: 'all' as const },
  { key: 'npm_packages', label: 'Npm Packages', osType: 'all' as const },
  { key: 'portage_packages', label: 'Portage Packages', osType: 'linux' as const },
  { key: 'firefox_addons', label: 'Firefox Addons', osType: 'all' as const },
  { key: 'choco', label: 'Chocolatey', osType: 'windows' as const },
  { key: 'ie_extensions', label: 'IE Extensions', osType: 'windows' as const },
] as const;

// STRICT columns for the frontend table (Windows / generic)
const TABLE_COLUMNS = [
  'name',
  'version',
  'publisher',
  'cve_summary', // Replaced cve_match with summary
  'cve_count',
  'kev',
  'severity',
];

const RPM_TABLE_COLUMNS = [
  'name',
  'version',
  'release',
  'publisher',
  'arch',
  'cve_summary',
  'cve_count',
  'kev',
  'severity',
];

const SNAP_TABLE_COLUMNS = [
  'name',
  'version',
  'revision',
  'channel',
  'publisher',
  'confinement',
  'snap_type',
];

/** dpkg/deb rows: maintainer, arch, source, installed_size (KB formatted), etc. */
const DEB_TABLE_COLUMNS = [
  'name',
  'version',
  'arch',
  'source',
  'maintainer',
  'section',
  'status',
  'installed_size',
  'cve_summary',
  'cve_count',
  'kev',
  'severity',
];

const isWindowsOS = (osName?: string) => osName && /windows/i.test(osName);
const isLinuxOS = (osName?: string) => osName && !/windows/i.test(osName);
const isUbuntuOS = (osName?: string) => osName && /ubuntu/i.test(osName);

/** dpkg Installed-Size is in kilobytes */
const formatDebInstalledSizeKb = (raw: unknown): string => {
  if (raw === null || raw === undefined || raw === '') return '—';
  const kb = Number(raw);
  if (Number.isNaN(kb)) return String(raw);
  if (kb >= 1048576) return `${(kb / 1048576).toFixed(2)} GB`;
  if (kb >= 1024) return `${(kb / 1024).toFixed(1)} MB`;
  return `${kb} KB`;
};

const severityFromCveMatch = (cveMatch: Record<string, CVEItem> | null | undefined): string => {
  if (!cveMatch || typeof cveMatch !== 'object') return '—';
  const items = Object.values(cveMatch);
  if (items.length === 0) return '—';
  let highest = 'LOW';
  for (const cve of items) {
    const severity = String(cve?.severity ?? '').toUpperCase();
    if (severity === 'CRITICAL' || severity.includes('CRITICAL')) return 'CRITICAL';
    if (severity === 'HIGH' || severity.includes('HIGH')) return 'HIGH';
    if (severity === 'MEDIUM' || severity.includes('MEDIUM')) highest = 'MEDIUM';
  }
  return highest;
};

const normalizePrograms = (programs: ProgramRow[] = []) =>
  programs.map((p) => {
    let count = 0;
    let summary = '—';
    const cveObj =
      p.cve_match && typeof p.cve_match === 'object'
        ? (p.cve_match as Record<string, CVEItem>)
        : undefined;

    // Keep the original cve_match intact, but create a summary string for the table
    if (p.cve_match && typeof p.cve_match === 'object') {
      const cveIds = Object.keys(p.cve_match);
      count = cveIds.length;
      
      if (count > 0) {
        summary = cveIds.slice(0, 2).join(', ');
        if (count > 2) {
          summary += `, +${count - 2} more`;
        }
      }
    } else if (typeof p.cve_match === 'string') {
        // Fallback just in case api returns a string
        summary = p.cve_match;
    }

    const rawCveCount = p.cve_count;
    const parsedRawCveCount =
      typeof rawCveCount === 'number' ? rawCveCount : Number(rawCveCount);
    const cve_count_final = count === 0 && !Number.isNaN(parsedRawCveCount)
      ? parsedRawCveCount
      : count;

    const vendor = (p as Record<string, unknown>)['vendor'];
    const installTime = (p as Record<string, unknown>)['install_time'];
    const unixtime = (p as Record<string, unknown>)['unixtime'];

    return {
      ...p,
      cve_summary: summary,
      cve_count: cve_count_final || 0,
      // has_kev_cve only exists on programs/deb/rpm rows (the tables the
      // vulnexus KEV enrichment writes to) — undefined elsewhere, which the
      // `kev` column renders as a plain dash, same as "no CVEs".
      kev: p.has_kev_cve === true,
      // Many backends call this `vendor` for rpm-like payloads.
      publisher:
        p.publisher ??
        (typeof vendor === 'string' && vendor.trim() ? vendor : undefined),
      // Drawer expects `install_date` and `first_reported_at`.
      install_date:
        p.install_date ??
        (typeof installTime === 'number' || (typeof installTime === 'string' && installTime.trim())
          ? String(installTime)
          : undefined),
      first_reported_at:
        p.first_reported_at ??
        (typeof unixtime === 'number' || (typeof unixtime === 'string' && unixtime.trim())
          ? String(unixtime)
          : undefined),
      severity:
        typeof p.severity === 'string' && p.severity.trim() !== ''
          ? p.severity
          : severityFromCveMatch(cveObj),
    };
  });

const normalizeDebPrograms = (programs: ProgramRow[] = []) =>
  programs.map((p) => {
    const base = normalizePrograms([p])[0];
    const cveObj =
      base.cve_match && typeof base.cve_match === 'object'
        ? (base.cve_match as Record<string, CVEItem>)
        : undefined;
    const severity =
      typeof p.severity === 'string' && p.severity.trim() !== ''
        ? p.severity
        : severityFromCveMatch(cveObj);

    return {
      ...base,
      maintainer: p.maintainer,
      source: p.source,
      arch: p.arch,
      section: p.section,
      status: p.status,
      revision: p.revision === '' ? undefined : p.revision,
      installed_size: formatDebInstalledSizeKb(p.size),
      priority: p.priority,
      admindir: p.admindir,
      sanitized_name: p.sanitized_name,
      sanitized_version: p.sanitized_version,
      major_release_version: p.major_release_version,
      unixtime: p.unixtime,
      severity,
    };
  });

const NodesViewPrograms = ({ node }: NodesViewProgramsProps) => {
  const [programsByTab, setProgramsByTab] = useState<Record<string, ProgramRow[]>>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<string>('programs');
  
  // Drawer state
  const [selectedRow, setSelectedRow] = useState<ProgramRow | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const hostId = node.host_identifier || String(node.id);
  const osName = node.os_platform;

  const loadPrograms = useCallback(
    async (signal?: { cancelled: boolean }) => {
      setLoading(true);
      try {
        const res = await nodesViewApi.getProgramsList(hostId, osName).catch(() => ({ data: { programs: [] } }));
        const data = res.data as ProgramsPayload;
        if (!signal?.cancelled) {
          const nextByTab: Record<string, ProgramRow[]> = {
            programs: normalizePrograms(data?.programs),
            deb: normalizeDebPrograms(data?.deb),
            rpm: normalizePrograms(data?.rpm),
            snap_packages: normalizePrograms(data?.snap_packages),
            chrome_extensions: normalizePrograms(data?.chrome_extensions),
            npm_packages: normalizePrograms(data?.npm_packages),
            portage_packages: normalizePrograms(data?.portage_packages),
            firefox_addons: normalizePrograms(data?.firefox_addons),
            choco: normalizePrograms(data?.choco),
            ie_extensions: normalizePrograms(data?.ie_extensions),
          };
          setProgramsByTab(nextByTab);
          const firstAvailable = TAB_DEFS.find((tab) => (nextByTab[tab.key] || []).length > 0)?.key;
          setActiveTab(
            firstAvailable || (isLinuxOS(osName) ? 'deb' : 'programs')
          );
        }
      } finally {
        if (!signal?.cancelled) setLoading(false);
      }
    },
    [hostId, osName]
  );

  useEffect(() => {
    const signal = { cancelled: false };
    loadPrograms(signal);
    return () => {
      signal.cancelled = true;
    };
  }, [loadPrograms]);

  const activePrograms = programsByTab[activeTab] || [];
  const tableColumns =
    activeTab === 'deb'
      ? DEB_TABLE_COLUMNS
      : activeTab === 'rpm'
        ? RPM_TABLE_COLUMNS
        : activeTab === 'snap_packages'
          ? SNAP_TABLE_COLUMNS
          : TABLE_COLUMNS;

  const handleRowClick = (row: Record<string, unknown>) => {
    setSelectedRow(row as ProgramRow);
    setIsDrawerOpen(true);
  };

  const activeTabLabel = TAB_DEFS.find((tab) => tab.key === activeTab)?.label ?? 'items';

  return (
    <div className="p-3 sm:p-4 lg:p-5 space-y-4 relative">
      {/* Sub-tabs for OS categories */}
      <div className="overflow-x-auto">
        <div className="flex gap-1.5 sm:gap-2 whitespace-nowrap min-w-max rounded-xl border border-slate-200/80 bg-slate-50/70 p-1.5">
          {TAB_DEFS.filter((tab) => {
            if (tab.osType === 'all') return true;
            if (tab.osType === 'windows') return isWindowsOS(osName);
            if (tab.osType === 'ubuntu') return isUbuntuOS(osName);
            if (tab.osType === 'linux') return isLinuxOS(osName);
            return false;
          }).map((tab) => {
            const isActive = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setActiveTab(tab.key)}
                className={`relative px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors duration-200 active:scale-95 ${
                  isActive ? 'text-blue-700' : 'text-slate-600 hover:text-slate-800'
                }`}
                style={{ transformStyle: 'preserve-3d' }}
              >
                {isActive && (
                  <motion.div
                    layoutId="programsTabsBackground"
                    transition={{ type: 'spring', bounce: 0.3, duration: 0.6 }}
                    className="absolute inset-0 rounded-lg border border-blue-200 bg-white shadow-sm"
                    style={{ zIndex: 0 }}
                  />
                )}
                <span className="relative z-10">{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      <DynamicDataTable
        columns={tableColumns}
        data={activePrograms}
        onRowClick={handleRowClick}
        loading={loading}
        onRefresh={() => loadPrograms()}
        searchPlaceholder={`Search ${activeTabLabel.toLowerCase()}…`}
        emptyState={{
          icon: PackageSearch,
          title: `No ${activeTabLabel.toLowerCase()} found`,
          description: `This node hasn't reported any ${activeTabLabel.toLowerCase()} yet. Try refreshing or check back after the next scan.`,
        }}
      />

      {/* Render the Drawer */}
      <ProgramDetailsDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        programData={selectedRow}
      />
    </div>
  );
};

export default NodesViewPrograms;