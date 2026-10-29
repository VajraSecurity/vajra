import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
// Import only the core editor API + SQL grammar (not `monaco-editor`'s barrel,
// which pulls in every bundled language and bloats this chunk by ~3MB).
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api';
import 'monaco-editor/esm/vs/basic-languages/sql/sql.contribution';
import MonacoEditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
import api from '../../api/axiosInstance';
import { NODES_URLS, THREAT_HUNTING_URLS } from '../../api/urls';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import { useNodeWebSocket } from '../../hooks/useNodeWebSocket';
import { DuoSpinner } from '@/components/ui/loading';
import Pagination from '../../components/ui/pagination';
import type { SavedQuery, Platform, PlatformChoice, PlatformSelection } from './types';
import { PLATFORM_COLORS, PLATFORM_LABELS } from './types';

// Self-hosted worker — avoids @monaco-editor/react's default CDN fetch, which
// stalls or drops keystrokes on networks without internet access (on-prem).
(self as unknown as { MonacoEnvironment: monaco.Environment }).MonacoEnvironment = {
  getWorker: () => new MonacoEditorWorker(),
};

// Types

interface NodeOption {
  host_identifier: string;
  hostname: string;
  status: string;
  os_platform: string;
}

type QueryMode = 'historical' | 'live';
type NodeStateTag = 'historic' | 'live' | 'both';
type DefenseKitTag = 'detection' | 'fragments' | 'policy';
type DetectionSubtypeTag =
  | 'c2'
  | 'collection'
  | 'credentials'
  | 'discovery'
  | 'evasion'
  | 'execution'
  | 'exfil'
  | 'impact'
  | 'initial access'
  | 'persistence'
  | 'privesc';

type ResultState =
  | { status: 'idle' }
  | { status: 'running'; cancelFn: () => void }
  | { status: 'success'; rows: Record<string, unknown>[]; truncated: boolean; durationMs: number }
  | { status: 'error'; message: string };

// Helpers

function isSafeSelectQuery(q: string): boolean {
  const t = q.trim();
  return /^SELECT\b/i.test(t) && !/;\s*\S/i.test(t);
}

function splitPlatformString(value: string): PlatformChoice[] {
  return value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item): item is PlatformChoice => item === 'linux' || item === 'windows' || item === 'macos');
}

function parsePlatformSelection(value: string): PlatformSelection {
  if (value === 'all') return 'all';
  const choices = splitPlatformString(value);
  return choices.length === 0 ? 'all' : Array.from(new Set(choices));
}

function platformSelectionToString(selection: PlatformSelection): string {
  if (selection === 'all') return 'all';
  if (!Array.isArray(selection)) return selection;
  return selection.length === 0 ? 'all' : selection.join(',');
}

// OS / table compatibility

type OsType = 'linux' | 'windows' | 'macos';

interface TableEntry {
  name: string;
  platforms: OsType[] | 'all';
  description?: string;
  category: string;
}

const TABLE_CATALOG: TableEntry[] = [
  // Processes
  { category: 'Processes', name: 'processes',            platforms: 'all',                description: 'Currently running processes' },
  { category: 'Processes', name: 'process_open_files',   platforms: ['linux', 'macos'],   description: 'Files opened by each process' },
  { category: 'Processes', name: 'process_memory_map',   platforms: ['linux', 'macos'],   description: 'Process virtual memory regions' },
  { category: 'Processes', name: 'process_envs',         platforms: 'all',                description: 'Process environment variables' },
  { category: 'Processes', name: 'bpf_process_events',   platforms: ['linux'],            description: 'Process create/exit via eBPF' },
  { category: 'Processes', name: 'win_process_events',   platforms: ['windows'],          description: 'Windows process create/exit events' },
  // Network
  { category: 'Network',   name: 'listening_ports',      platforms: 'all',                description: 'Listening TCP/UDP ports' },
  { category: 'Network',   name: 'open_sockets',         platforms: 'all',                description: 'Open network connections' },
  { category: 'Network',   name: 'arp_cache',            platforms: 'all',                description: 'ARP table entries' },
  { category: 'Network',   name: 'interface_addresses',  platforms: 'all',                description: 'Network interface addresses' },
  { category: 'Network',   name: 'dns_resolvers',        platforms: ['linux', 'macos'],   description: 'Configured DNS resolvers' },
  { category: 'Network',   name: 'bpf_socket_events',    platforms: ['linux'],            description: 'Network socket events via eBPF' },
  { category: 'Network',   name: 'win_socket_events',    platforms: ['windows'],          description: 'Windows network socket events' },
  // File System
  { category: 'File System', name: 'file',               platforms: 'all',                description: 'File metadata (requires WHERE path)' },
  { category: 'File System', name: 'hash',               platforms: 'all',                description: 'File MD5/SHA1/SHA256 hashes' },
  { category: 'File System', name: 'bpf_file_events',    platforms: ['linux'],            description: 'File read/write events via eBPF' },
  { category: 'File System', name: 'win_file_events',    platforms: ['windows'],          description: 'Windows file system events' },
  // Users & Auth
  { category: 'Users & Auth', name: 'users',             platforms: 'all',                description: 'Local user accounts' },
  { category: 'Users & Auth', name: 'logged_in_users',   platforms: 'all',                description: 'Currently logged-in users' },
  { category: 'Users & Auth', name: 'user_groups',       platforms: 'all',                description: 'Local groups and members' },
  { category: 'Users & Auth', name: 'shell_history',     platforms: ['linux', 'macos'],   description: 'Shell command history' },
  { category: 'Users & Auth', name: 'last',              platforms: ['linux', 'macos'],   description: 'Recent login records' },
  // Persistence
  { category: 'Persistence', name: 'startup_items',      platforms: ['windows', 'macos'], description: 'Auto-start programs' },
  { category: 'Persistence', name: 'scheduled_tasks',    platforms: ['windows'],          description: 'Windows Task Scheduler entries' },
  { category: 'Persistence', name: 'services',           platforms: ['windows'],          description: 'Windows services' },
  { category: 'Persistence', name: 'autoexec',           platforms: ['windows'],          description: 'Autoexec registry run keys' },
  { category: 'Persistence', name: 'launchd',            platforms: ['macos'],            description: 'macOS launchd services' },
  { category: 'Persistence', name: 'crontab',            platforms: ['linux', 'macos'],   description: 'Scheduled cron jobs' },
  { category: 'Persistence', name: 'kernel_modules',     platforms: ['linux'],            description: 'Loaded kernel modules' },
  // System
  { category: 'System',    name: 'system_info',          platforms: 'all',                description: 'Hardware and OS info' },
  { category: 'System',    name: 'os_version',           platforms: 'all',                description: 'OS name and version' },
  { category: 'System',    name: 'uptime',               platforms: 'all',                description: 'System uptime' },
  { category: 'System',    name: 'drivers',              platforms: ['windows'],          description: 'Loaded Windows drivers' },
  { category: 'System',    name: 'patches',              platforms: ['windows'],          description: 'Windows hotfixes / patches' },
  // Software
  { category: 'Software',  name: 'programs',             platforms: ['windows'],          description: 'Installed Windows programs' },
  { category: 'Software',  name: 'deb_packages',         platforms: ['linux'],            description: 'Installed Debian packages' },
  { category: 'Software',  name: 'rpm_packages',         platforms: ['linux'],            description: 'Installed RPM packages' },
  { category: 'Software',  name: 'python_packages',      platforms: 'all',                description: 'Installed Python packages' },
  { category: 'Software',  name: 'npm_packages',         platforms: 'all',                description: 'Installed npm packages' },
  { category: 'Software',  name: 'chrome_extensions',    platforms: 'all',                description: 'Installed Chrome extensions' },
  // Vajranet
  { category: 'Vajranet',  name: 'nodes',                platforms: 'all',                description: 'Enrolled agent nodes' },
  { category: 'Vajranet',  name: 'alerts',               platforms: 'all',                description: 'Threat detection alerts' },
];

const OS_DISPLAY: Record<OsType, { label: string; short: string; cls: string }> = {
  linux:   { label: 'Linux',   short: 'LNX', cls: 'bg-amber-50 text-amber-700 border-amber-200' },
  windows: { label: 'Windows', short: 'WIN', cls: 'bg-sky-50 text-sky-700 border-sky-200' },
  macos:   { label: 'macOS',   short: 'MAC', cls: 'bg-gray-50 text-gray-600 border-gray-200' },
};

function normalizePlatform(osPlatform: string): OsType | 'unknown' {
  const p = (osPlatform ?? '').toLowerCase();
  if (p === 'linux') return 'linux';
  if (p === 'windows') return 'windows';
  if (p === 'darwin' || p === 'macos') return 'macos';
  return 'unknown';
}

// Index over TABLE_CATALOG so the lookup below is O(1) rather than a find() per
// table name mentioned in the SQL. The detection runs on every render, i.e. on
// every keystroke in the editor.
const TABLE_CATALOG_BY_NAME = new Map(TABLE_CATALOG.map((t) => [t.name, t]));

// TABLE_CATALOG is a module constant, so this grouping never changes and is
// computed once here rather than inline in the JSX on every editor render.
const TABLE_CATALOG_BY_CATEGORY = Object.entries(
  TABLE_CATALOG.reduce<Record<string, TableEntry[]>>((acc, entry) => {
    (acc[entry.category] ??= []).push(entry);
    return acc;
  }, {})
);

function detectIncompatibleTables(sql: string, nodePlatform: OsType): string[] {
  const tableNames = new Set<string>();
  const matches = sql.matchAll(/(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)/gi);
  for (const m of matches) tableNames.add(m[1].toLowerCase());
  return [...tableNames].filter((name) => {
    const entry = TABLE_CATALOG_BY_NAME.get(name);
    if (!entry || entry.platforms === 'all') return false;
    return !entry.platforms.includes(nodePlatform);
  });
}

function cellDisplay(val: unknown): string {
  if (val === null || val === undefined) return '';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

function exportCsv(rows: Record<string, unknown>[], filename: string) {
  if (!rows.length) return;
  const cols = Object.keys(rows[0]);
  const escape = (v: unknown) => {
    let s = v === null || v === undefined
      ? ''
      : typeof v === 'object'
      ? JSON.stringify(v)
      : String(v);
    // Prevent CSV/formula injection: query results can contain attacker-influenced
    // strings (process names, paths) that Excel/Sheets would otherwise execute as
    // formulas if opened with a leading =, +, -, or @.
    if (/^[=+\-@]/.test(s)) s = `'${s}`;
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };
  const csv = [cols.join(','), ...rows.map((r) => cols.map((c) => escape(r[c])).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// Results table

const ResultsTable = ({
  rows,
  truncated,
  durationMs,
  queryName,
}: {
  rows: Record<string, unknown>[];
  truncated: boolean;
  durationMs: number;
  queryName: string;
}) => {
  const [colSearch, setColSearch] = useState('');
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  // Memoised on `rows` alone: page and rows-per-page changes re-render but cannot
  // change the column list, and the filter below lowercases the needle once
  // instead of once per column.
  const cols = useMemo(() => rows.length > 0 ? Object.keys(rows[0]) : [], [rows]);

  const filteredCols = useMemo(() => {
    if (!colSearch) return cols;
    const q = colSearch.toLowerCase();
    return cols.filter((c) => c.toLowerCase().includes(q));
  }, [cols, colSearch]);

  useEffect(() => { setPage(1); }, [rows]);

  const totalPages = Math.max(1, Math.ceil(rows.length / rowsPerPage));
  const pagedRows = rows.slice((page - 1) * rowsPerPage, page * rowsPerPage);

  return (
    <div className="mt-4">
      {/* Results header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold text-gray-900">
            {rows.length.toLocaleString()} {rows.length === 1 ? 'result' : 'results'}
          </span>
          <span className="text-xs text-gray-400">{(durationMs / 1000).toFixed(2)}s</span>
          {truncated && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 text-amber-700 text-xs font-medium rounded-md border border-amber-200">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              Results truncated
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {cols.length > 5 && (
            <input
              type="text"
              value={colSearch}
              onChange={(e) => setColSearch(e.target.value)}
              placeholder="Filter columns…"
              className="text-xs px-2.5 py-1.5 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 w-36"
            />
          )}
          <button
            onClick={() => exportCsv(rows, queryName || 'query-results')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export CSV
          </button>
        </div>
      </div>

      {/* Table or empty state */}
      {rows.length === 0 ? (
        <div className="rounded-xl border border-gray-200 bg-gray-50 p-8 text-center">
          <svg className="w-8 h-8 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <p className="text-sm font-medium text-gray-500">No rows returned</p>
          <p className="text-xs text-gray-400 mt-1">The query executed successfully but matched no records.</p>
        </div>
      ) : filteredCols.length === 0 ? (
        <div className="rounded-xl border border-gray-200 bg-gray-50 p-6 text-center">
          <p className="text-sm text-gray-500">
            No columns match <span className="font-mono text-gray-700">"{colSearch}"</span>
          </p>
          <button
            onClick={() => setColSearch('')}
            className="mt-2 text-xs text-blue-600 hover:underline rounded-lg"
          >
            Clear filter
          </button>
        </div>
      ) : (
        <div className="rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="overflow-auto max-h-[480px]">
          <table className="min-w-full divide-y divide-gray-100 text-sm border-separate border-spacing-0">
            <thead>
              <tr>
                {filteredCols.map((col) => (
                  <th
                    key={col}
                    className="px-4 py-2.5 text-left text-xs font-bold text-gray-600 uppercase tracking-wide whitespace-nowrap border-b border-gray-200 bg-gray-50/95 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50 bg-white">
              {pagedRows.map((row, i) => (
                <tr key={i} className="hover:bg-blue-50/30 transition-colors">
                  {filteredCols.map((col) => {
                    const val = row[col];
                    const isNull = val === null || val === undefined;
                    const display = cellDisplay(val);
                    return (
                      <td
                        key={col}
                        className="px-4 py-2 text-xs text-gray-700 max-w-xs"
                        style={{ fontFamily: '"Roboto Mono", monospace', fontWeight: 500 }}
                        title={display.length > 80 ? display : undefined}
                      >
                        <div className="truncate max-w-[260px]">
                          {isNull ? (
                            <span className="text-gray-300 select-none">null</span>
                          ) : display === '' ? (
                            <span className="text-gray-300 select-none italic">empty</span>
                          ) : (
                            display
                          )}
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          <Pagination
            page={page}
            totalPages={totalPages}
            total={rows.length}
            pageSize={rowsPerPage}
            onPageChange={setPage}
            onPageSizeChange={(size) => { setRowsPerPage(size); setPage(1); }}
            pageSizeOptions={[10, 25, 50]}
            itemLabel="rows"
          />
        </div>
      )}
    </div>
  );
};

// Node selector

const NodeSelector = ({
  nodes,
  value,
  onChange,
  loadingNodes,
  nodesError,
  onRetry,
}: {
  nodes: NodeOption[];
  value: string;
  onChange: (v: string) => void;
  loadingNodes: boolean;
  nodesError?: boolean;
  onRetry?: () => void;
}) => {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  // The dropdown renders every matching node (no cap), and this scan+filter ran
  // on every render of the parent editor — which re-renders on every keystroke
  // in the SQL box, not just when this dropdown's own search changes.
  const selected = useMemo(() => nodes.find((n) => n.host_identifier === value), [nodes, value]);
  const filtered = useMemo(() => {
    if (!search) return nodes;
    const s = search.toLowerCase();
    return nodes.filter((n) =>
      n.hostname?.toLowerCase().includes(s) || n.host_identifier?.toLowerCase().includes(s),
    );
  }, [nodes, search]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Lets keyboard users dismiss the dropdown without tabbing through every
  // filtered node or reaching for the mouse to click outside.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open]);

  const handleButtonClick = () => {
    if (nodesError && onRetry) { onRetry(); return; }
    setOpen((p) => !p);
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={handleButtonClick}
        disabled={loadingNodes}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={`flex items-center gap-2 w-full px-3 py-2 text-sm bg-white border rounded-lg text-left focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors disabled:opacity-50 ${
          nodesError ? 'border-red-300 hover:border-red-400' : 'border-gray-200 hover:border-blue-400'
        }`}
      >
        {loadingNodes ? (
          <span className="text-gray-400 text-xs">Loading nodes…</span>
        ) : nodesError ? (
          <span className="text-red-500 text-xs flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Failed to load nodes — click to retry
          </span>
        ) : selected ? (
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                selected.status === 'Online' ? 'bg-emerald-500' : 'bg-gray-300'
              }`}
            />
            <span className="truncate font-medium text-gray-900">{selected.hostname}</span>
            {(() => {
              const os = normalizePlatform(selected.os_platform);
              return os !== 'unknown' ? (
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border flex-shrink-0 ${OS_DISPLAY[os].cls}`}>
                  {OS_DISPLAY[os].short}
                </span>
              ) : null;
            })()}
          </div>
        ) : (
          <span className="text-gray-400">Select a node…</span>
        )}
        <svg
          className={`w-4 h-4 text-gray-400 ml-auto flex-shrink-0 transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.1 }}
            className="absolute top-full left-0 right-0 mt-1 bg-white rounded-xl border border-gray-200 shadow-xl z-50 overflow-hidden"
          >
            <div className="p-2 border-b border-gray-100 flex items-center justify-between gap-2">
              <input
                autoFocus
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by hostname or identifier…"
                className="flex-1 px-2.5 py-1.5 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <span className="text-[11px] text-gray-400 whitespace-nowrap pr-1">
                {filtered.length} / {nodes.length}
              </span>
            </div>
            <div className="max-h-64 overflow-y-auto" role="listbox">
              {filtered.length === 0 ? (
                <p className="text-xs text-gray-400 text-center py-5">No nodes found</p>
              ) : (
                filtered.map((n) => {
                  const isSelected = n.host_identifier === value;
                  return (
                  <button
                    key={n.host_identifier}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    onClick={() => { onChange(n.host_identifier); setOpen(false); setSearch(''); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-sm text-left transition-colors rounded-lg ${
                      isSelected
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      n.status === 'Online'
                        ? isSelected ? 'bg-white' : 'bg-emerald-500'
                        : isSelected ? 'bg-blue-300' : 'bg-gray-300'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className={`font-semibold truncate ${isSelected ? 'text-white' : ''}`}>{n.hostname}</p>
                      <p className={`text-xs truncate ${isSelected ? 'text-blue-200' : 'text-gray-400'}`}>{n.host_identifier}</p>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      {(() => {
                        const os = normalizePlatform(n.os_platform);
                        return os !== 'unknown' ? (
                          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                            isSelected ? 'bg-blue-500 text-white border-blue-400' : OS_DISPLAY[os].cls
                          }`}>
                            {OS_DISPLAY[os].short}
                          </span>
                        ) : null;
                      })()}
                      {isSelected ? (
                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <span className={`text-xs font-medium ${n.status === 'Online' ? 'text-emerald-600' : 'text-gray-400'}`}>
                          {n.status}
                        </span>
                      )}
                    </div>
                  </button>
                  );
                })
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// SQL editor (vanilla monaco-editor)

const SqlEditor = ({
  value,
  onChange,
  height,
}: {
  value: string;
  onChange: (value: string) => void;
  height: number;
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    if (!containerRef.current) return;

    const editor = monaco.editor.create(containerRef.current, {
      value,
      language: 'sql',
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 13,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      wordWrap: 'on',
      automaticLayout: true,
      padding: { top: 12, bottom: 12 },
      bracketPairColorization: { enabled: true },
      tabSize: 2,
    });
    editorRef.current = editor;

    const subscription = editor.onDidChangeModelContent(() => {
      onChangeRef.current(editor.getValue());
    });

    return () => {
      subscription.dispose();
      editor.dispose();
      editorRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync external value changes (loading a saved query, clicking a table shortcut,
  // "Clear") without clobbering the cursor position on every keystroke.
  useEffect(() => {
    const editor = editorRef.current;
    if (editor && editor.getValue() !== value) {
      editor.setValue(value);
    }
  }, [value]);

  return <div ref={containerRef} style={{ height }} />;
};

// Main component

const QueryEditor = () => {
  const { id } = useParams<{ id?: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const confirm = useConfirm();

  const isNew = !id || id === 'new';

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  // processes is available on every platform, unlike bpf_process_events (Linux-only,
  // and only populated when the agent enables BPF events) — a first query that
  // returns nothing with no explanation is a bad first impression.
  const [sql, setSql] = useState('SELECT pid, name, path, cmdline FROM processes LIMIT 100');
  const [platform, setPlatform] = useState<PlatformSelection>('all');
  const [nodeState, setNodeState] = useState<NodeStateTag>('both');
  const [defenseKit, setDefenseKit] = useState<DefenseKitTag[]>([]);
  const [detectionSubtypes, setDetectionSubtypes] = useState<DetectionSubtypeTag[]>([]);
  const [showDetectionSubtypes, setShowDetectionSubtypes] = useState(false);
  const [detectionSubtypeError, setDetectionSubtypeError] = useState('');

  // UI state
  const [saving, setSaving] = useState(false);
  const [loadingQuery, setLoadingQuery] = useState(!isNew);
  const [isDirty, setIsDirty] = useState(false);
  const [nameError, setNameError] = useState('');

  // Run state
  const [mode, setMode] = useState<QueryMode>('historical');
  const [selectedNode, setSelectedNode] = useState('');
  const [nodes, setNodes] = useState<NodeOption[]>([]);
  const [loadingNodes, setLoadingNodes] = useState(false);
  const [nodesError, setNodesError] = useState(false);
  const [nodesRetry, setNodesRetry] = useState(0);
  const [result, setResult] = useState<ResultState>({ status: 'idle' });
  // Tracks whether the current run was cancelled so stale completions don't overwrite state
  const cancelledRef = useRef(false);

  // Live query WebSocket — only connect when a node is selected
  const { sendMessage: wsSend, connected: wsConnected } = useNodeWebSocket(
    selectedNode,
    mode === 'live' && !!selectedNode,
  );

  // Load existing query
  useEffect(() => {
    if (isNew) return;
    let cancelled = false;
    let autoRunTimer: ReturnType<typeof setTimeout> | undefined;
    setLoadingQuery(true);
    api
      .get<{ success: boolean; data: SavedQuery }>(THREAT_HUNTING_URLS.QUERY(parseInt(id!, 10)))
      .then(({ data }) => {
        if (cancelled) return;
        const q = data.data;
        setName(q.name);
        setDescription(q.description ?? '');
        setSql(q.query);
        setPlatform(parsePlatformSelection(q.platform));
        setNodeState((q.node_state as NodeStateTag) || 'both');
        const parsedDefenseKit = Array.isArray(q.defense_kit) ? (q.defense_kit as DefenseKitTag[]) : [];
        setDefenseKit(parsedDefenseKit);
        setDetectionSubtypes(
          Array.isArray(q.detection_subtypes) ? (q.detection_subtypes as DetectionSubtypeTag[]) : [],
        );
        setShowDetectionSubtypes(parsedDefenseKit.includes('detection'));
        const nextMode = q.node_state === 'live' ? 'live' : 'historical';
        setMode(nextMode);
        // Auto-run if navigated with ?run=1 — but a live query always needs a node
        // selected first, which a fresh navigation never has, so auto-running it
        // would just hit the "select a node" guard. Prompt instead of failing silently.
        if (searchParams.get('run') === '1') {
          if (nextMode === 'live') {
            showToast('Select a node, then click Run to execute this live query.', 'info');
          } else {
            autoRunTimer = setTimeout(() => {
              if (cancelled) return;
              runQuery(q.query, nextMode);
            }, 300);
          }
        }
      })
      .catch(() => {
        if (cancelled) return;
        showToast('Failed to load query', 'error');
        navigate('/threat-hunting');
      })
      .finally(() => { if (!cancelled) setLoadingQuery(false); });
    return () => {
      cancelled = true;
      if (autoRunTimer) clearTimeout(autoRunTimer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // Load node list when switching to live mode (or on retry)
  useEffect(() => {
    if (mode !== 'live') return;
    let cancelled = false;
    setLoadingNodes(true);
    setNodesError(false);
    api
      .get<{ nodes: NodeOption[] }>(NODES_URLS.NODES_IDENTIFIERS + '?rows=200')
      .then(({ data }) => { if (!cancelled) setNodes(data.nodes ?? []); })
      .catch(() => {
        if (!cancelled) {
          setNodesError(true);
          showToast('Failed to load nodes', 'error');
        }
      })
      .finally(() => { if (!cancelled) setLoadingNodes(false); });
    return () => { cancelled = true; };
  }, [mode, showToast, nodesRetry]);

  const runQuery = useCallback(
    async (querySql: string, runMode: QueryMode) => {
      const q = querySql.trim();
      if (!q) { showToast('Query is empty', 'error'); return; }
      if (!isSafeSelectQuery(q)) {
        showToast('Only SELECT queries are permitted', 'error');
        return;
      }
      if (runMode === 'live' && !selectedNode) {
        showToast('Select a node to run a live query', 'error');
        return;
      }

      // Each run gets its own abort controller; cancel button calls its abort.
      const controller = new AbortController();
      cancelledRef.current = false;

      setResult({
        status: 'running',
        cancelFn: () => {
          cancelledRef.current = true;
          controller.abort();
          setResult({ status: 'idle' });
        },
      });

      const t0 = Date.now();

      try {
        if (runMode === 'historical') {
          const { data } = await api.post<{
            success: boolean;
            data: Record<string, unknown>[];
            truncated: boolean;
            message?: string;
          }>(THREAT_HUNTING_URLS.RUN, { query: q }, { signal: controller.signal });

          // Ignore if the user cancelled while the request was in flight
          if (cancelledRef.current) return;

          if (!data.success) throw new Error(data.message ?? 'Query failed');

          setResult({
            status: 'success',
            rows: data.data ?? [],
            truncated: data.truncated ?? false,
            durationMs: Date.now() - t0,
          });
        } else {
          // Live query via WebSocket — no abort controller (WS doesn't support it),
          // but we check cancelledRef after the promise resolves.
          const response = await wsSend(
            { type: 'osquery', params: { arg1: q }, host_identifier: selectedNode },
            { timeoutMs: 30_000 },
          );

          if (cancelledRef.current) return;

          // Agent returned an explicit error (e.g. table not found on that OS)
          if (response?.status === 'error') {
            throw new Error(response.message ?? 'Agent returned an error');
          }

          // Parse agent response — the agent wraps rows in one of several shapes:
          //   { response: "<JSON string>" }  where the JSON is { response: [...rows] } or [...rows]
          //   { data: [...rows] }            flat array on response.data
          let rows: Record<string, unknown>[] = [];
          if (response?.response) {
            // An unreadable payload is a failed query, not a query that matched
            // nothing — an empty success would claim "no hits" for a host that
            // was never actually searched.
            let parsed: unknown;
            try {
              parsed =
                typeof response.response === 'string'
                  ? JSON.parse(response.response)
                  : response.response;
            } catch {
              throw new Error('The agent returned a response that could not be parsed. No results were read from this host.');
            }
            const container =
              parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
                ? (parsed as { response?: unknown }).response
                : parsed;
            if (Array.isArray(container)) {
              rows = container as Record<string, unknown>[];
            } else if (container == null) {
              // Go serializes a nil result slice as null.
              rows = [];
            } else {
              throw new Error('The agent returned a response in an unrecognised format. No results were read from this host.');
            }
          } else if (Array.isArray(response?.data)) {
            rows = response.data;
          }

          setResult({
            status: 'success',
            rows,
            truncated: rows.length >= 2000,
            durationMs: Date.now() - t0,
          });
        }
      } catch (err: unknown) {
        if (cancelledRef.current) return; // Swallow abort errors silently
        // axios wraps AbortError as a CanceledError
        if (
          err instanceof Error &&
          (err.name === 'CanceledError' || err.name === 'AbortError' || err.message === 'canceled')
        ) return;
        const message = err instanceof Error ? err.message : 'Query failed';
        setResult({ status: 'error', message });
      }
    },
    [selectedNode, wsSend, showToast],
  );

  const handleRun = () => runQuery(sql, mode);

  // Guards the two exits from this screen (breadcrumb + Cancel) against silently
  // discarding unsaved edits — isDirty already tracks this for the Save button
  // label, so reuse it here rather than adding new state.
  const handleNavigateAway = async () => {
    if (isDirty && !(await confirm({
      title: 'Discard unsaved changes to this query?',
      confirmLabel: 'Discard',
      variant: 'danger',
    }))) return;
    navigate('/threat-hunting');
  };

  const handleSave = async () => {
    const trimmedName = name.trim();
    if (!trimmedName) { setNameError('Query name is required'); return; }
    if (!sql.trim()) { showToast('SQL query is required', 'error'); return; }
    if (defenseKit.includes('detection') && detectionSubtypes.length === 0) {
      setDetectionSubtypeError('Select at least one Detection subtype');
      showToast('Select at least one Detection subtype', 'error');
      return;
    }

    setSaving(true);
    try {
      const payloadPlatform = platformSelectionToString(platform);
      const payload = {
        name: trimmedName,
        description: description.trim() || null,
        query: sql,
        platform: payloadPlatform,
        node_state: nodeState,
        defense_kit: defenseKit,
        detection_subtypes: defenseKit.includes('detection') ? detectionSubtypes : [],
      };
      if (isNew) {
        await api.post(THREAT_HUNTING_URLS.QUERIES, payload);
        showToast('Query saved', 'success');
        navigate('/threat-hunting');
      } else {
        await api.put(THREAT_HUNTING_URLS.QUERY(parseInt(id!, 10)), payload);
        showToast('Query updated', 'success');
        setIsDirty(false);
      }
    } catch (err: unknown) {
      const msg = isAxiosError<{ message?: string }>(err) ? err.response?.data?.message : undefined;
      showToast(msg ?? 'Failed to save query', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleSqlChange = (value: string) => {
    setSql(value);
    setIsDirty(true);
  };

  // Derived OS/compatibility state, memoised on what it actually depends on.
  // setSql() fires a render per character typed, and recomputing these means a
  // linear scan of the whole node list plus a matchAll over the query text on
  // every keystroke.
  const selectedNodeData = useMemo(
    () => nodes.find((n) => n.host_identifier === selectedNode),
    [nodes, selectedNode],
  );
  const selectedNodeOs = useMemo(
    () => selectedNodeData ? normalizePlatform(selectedNodeData.os_platform) : 'unknown',
    [selectedNodeData],
  );
  const incompatibleTables = useMemo(
    () => mode === 'live' && selectedNode && selectedNodeOs !== 'unknown'
      ? detectIncompatibleTables(sql, selectedNodeOs as OsType)
      : [],
    [mode, selectedNode, selectedNodeOs, sql],
  );

  const isRunning = result.status === 'running';
  const isRunDisabled =
    isRunning ||
    !sql.trim() ||
    (mode === 'live' && (!selectedNode || !wsConnected));

  if (loadingQuery) {
    return (
      <div className="min-h-screen bg-[#f8f9fb] flex items-center justify-center">
        <DuoSpinner size="lg" className="text-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#f8f9fb]">
      {/* Top bar */}
      <div className="sticky top-0 z-20 bg-white border-b border-gray-200 px-6 py-3">
        <div className="flex items-center gap-4">
          {/* Back */}
          <button
            onClick={handleNavigateAway}
            className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 transition-colors rounded-lg"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Queries
          </button>

          <span className="text-gray-300">/</span>

          {/* Query name inline edit */}
          <input
            type="text"
            value={name}
            onChange={(e) => { setName(e.target.value); setNameError(''); setIsDirty(true); }}
            placeholder="Query name"
            className={`flex-1 min-w-0 bg-transparent text-sm font-medium text-gray-900 placeholder-gray-400 focus:outline-none border-b ${nameError ? 'border-red-400' : 'border-transparent focus:border-blue-400'} pb-0.5 transition-colors`}
          />
          {nameError && <span className="text-xs text-red-500 whitespace-nowrap">{nameError}</span>}

          {/* Actions */}
          <div className="flex items-center gap-2 ml-auto flex-shrink-0">
            <button
              onClick={handleNavigateAway}
              className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="metallic-btn-blue inline-flex items-center gap-2 px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {saving && <DuoSpinner size="xs" />}
              {isNew ? 'Save query' : isDirty ? 'Save changes' : 'Saved'}
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="p-6 grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-6 max-w-[1600px] w-full">

        {/* Left: editor + results */}
        <div className="space-y-4 min-w-0">
          {/* SQL editor card */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
              <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">SQL</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSql('')}
                  className="text-xs text-gray-400 hover:text-gray-600 transition-colors rounded-lg"
                >
                  Clear
                </button>
              </div>
            </div>
            <div className="border-b border-gray-100">
              <SqlEditor value={sql} onChange={handleSqlChange} height={220} />
            </div>

            {/* Run bar */}
            <div className="px-4 py-3 bg-gray-50/60 space-y-2 rounded-b-xl">
            <div className="flex items-center gap-3 flex-wrap">
              {/* Mode toggle */}
              <div className="flex items-center bg-white border border-gray-200 rounded-lg p-0.5">
                <button
                  onClick={() => setMode('historical')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                    mode === 'historical' ? 'bg-gray-900 text-white shadow-sm' : 'text-gray-500 hover:text-gray-800'
                  }`}
                >
                  Historical
                </button>
                <button
                  onClick={() => setMode('live')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-md tracking-wide transition-all ${
                    mode === 'live' ? 'bg-emerald-600 text-white shadow-sm' : 'text-gray-500 hover:text-gray-800'
                  }`}
                >
                  {mode === 'live' ? (
                    <>
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
                      </span>
                      LIVE
                    </>
                  ) : (
                    'Live'
                  )}
                </button>
              </div>

              {/* Node selector (live only) */}
              {mode === 'live' && (
                <div className="flex-1 max-w-sm">
                  <NodeSelector
                    nodes={nodes.filter(n => n.status === 'Online')}
                    value={selectedNode}
                    onChange={setSelectedNode}
                    loadingNodes={loadingNodes}
                    nodesError={nodesError}
                    onRetry={() => setNodesRetry((n) => n + 1)}
                  />
                </div>
              )}

              {/* WS status indicator (live only) */}
              {mode === 'live' && selectedNode && (
                <div className="flex items-center gap-1.5 text-xs">
                  <span
                    className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-amber-400 animate-pulse'}`}
                  />
                  <span className={wsConnected ? 'text-emerald-600' : 'text-amber-600'}>
                    {wsConnected ? 'Connected' : 'Connecting…'}
                  </span>
                </div>
              )}

              <div className="ml-auto flex items-center gap-2">
                {isRunning && result.status === 'running' && (
                  <button
                    onClick={result.cancelFn}
                    className="text-xs text-gray-500 hover:text-red-600 transition-colors rounded-lg"
                  >
                    Cancel
                  </button>
                )}
                <button
                  onClick={handleRun}
                  disabled={isRunDisabled}
                  className={`inline-flex items-center gap-2 px-5 py-2 text-sm font-medium rounded-lg transition-colors shadow-sm ${
                    isRunDisabled
                      ? 'metallic-btn-blue bg-gray-200 text-gray-400 cursor-not-allowed'
                      : mode === 'live'
                      // No metallic-btn-blue here — its !important background would
                      // otherwise hide the emerald "live" color that signals this
                      // run will hit a real agent, not stored data.
                      ? 'bg-emerald-600 text-white hover:bg-emerald-700'
                      : 'metallic-btn-blue bg-blue-600 text-white hover:bg-blue-700'
                  }`}
                >
                  {isRunning ? (
                    <>
                      <DuoSpinner size="sm" />
                      Running…
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      Run query
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* OS incompatibility warning */}
            <AnimatePresence>
              {incompatibleTables.length > 0 && (
                <motion.div
                  key="compat-warn"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.15 }}
                  className="overflow-hidden"
                >
                  <div className="flex items-start gap-2.5 px-3 py-2 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                    <svg className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <span>
                      <span className="font-semibold">OS compatibility: </span>
                      {incompatibleTables.map((t, i) => (
                        <span key={t}>
                          <span className="font-mono">{t}</span>
                          {i < incompatibleTables.length - 1 ? ', ' : ''}
                        </span>
                      ))}
                      {' '}{incompatibleTables.length === 1 ? 'is' : 'are'} not available on{' '}
                      <span className="font-semibold">
                        {selectedNodeOs !== 'unknown' ? OS_DISPLAY[selectedNodeOs as OsType].label : ''}
                      </span>. The query may return no results on this node.
                    </span>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Compatible with — FleetDM style inline row */}
            <div className="px-4 py-2.5 border-t border-gray-100 flex items-center gap-3 flex-wrap">
              <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                Compatible with
              </span>
              <div className="flex items-center gap-1.5 flex-wrap">
                {(['all', 'linux', 'windows', 'macos'] as Platform[]).map((p) => {
                  const currentPlatforms =
                    platform === 'all' ? [] : Array.isArray(platform) ? platform : [platform];
                  const isSelected = p === 'all'
                    ? platform === 'all'
                    : currentPlatforms.includes(p);

                  return (
                    <button
                      key={p}
                      aria-pressed={isSelected}
                      onClick={() => {
                        if (p === 'all') {
                          setPlatform('all');
                          setIsDirty(true);
                          return;
                        }

                        const nextPlatforms = new Set<PlatformChoice>(currentPlatforms as PlatformChoice[]);
                        if (isSelected) {
                          nextPlatforms.delete(p);
                        } else {
                          nextPlatforms.add(p);
                        }

                        const allSpecificSelected =
                          nextPlatforms.has('linux') &&
                          nextPlatforms.has('windows') &&
                          nextPlatforms.has('macos');
                        const next = nextPlatforms.size === 0 || allSpecificSelected
                          ? 'all'
                          : Array.from(nextPlatforms) as PlatformChoice[];
                        setPlatform(next);
                        setIsDirty(true);
                      }}
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all ${
                        isSelected
                          ? `${PLATFORM_COLORS[p]} shadow-sm`
                          : 'bg-gray-50 text-gray-400 border-gray-200 hover:border-gray-300 hover:text-gray-600'
                      }`}
                    >
                      {isSelected && (
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                      {PLATFORM_LABELS[p]}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Node State tags */}
            <div className="px-4 py-2.5 border-t border-gray-100 flex items-center gap-3 flex-wrap">
              <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                Node State
              </span>
              <div className="flex items-center gap-1.5 flex-wrap">
                {(['historic', 'live', 'both'] as NodeStateTag[]).map((stateTag) => {
                  const isSelected = nodeState === stateTag;
                  const label = stateTag === 'historic' ? 'Historic' : stateTag === 'live' ? 'Live' : 'Both';
                  return (
                    <button
                      key={stateTag}
                      aria-pressed={isSelected}
                      onClick={() => {
                        // Node State is single-select only; allow toggle-off to default "both".
                        setNodeState(nodeState === stateTag ? 'both' : stateTag);
                        setIsDirty(true);
                      }}
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all ${
                        isSelected
                          ? 'bg-slate-100 text-slate-800 border-slate-300 shadow-sm'
                          : 'bg-gray-50 text-gray-400 border-gray-200 hover:border-gray-300 hover:text-gray-600'
                      }`}
                    >
                      {isSelected && (
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Defence Kit tags */}
            <div className="px-4 py-2.5 border-t border-gray-100 space-y-2">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Defence Kit
                </span>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {(['detection', 'fragments', 'policy'] as DefenseKitTag[]).map((kitTag) => {
                    const isSelected = defenseKit.includes(kitTag);
                    const label = kitTag === 'detection' ? 'Detection' : kitTag === 'fragments' ? 'Fragments' : 'Policy';
                    return (
                      <button
                        key={kitTag}
                        aria-pressed={isSelected}
                        onClick={() => {
                          const exists = defenseKit.includes(kitTag);
                          if (kitTag === 'detection' && exists) {
                            setDetectionSubtypes([]);
                            setDetectionSubtypeError('');
                          }
                          const next = exists ? defenseKit.filter((k) => k !== kitTag) : [...defenseKit, kitTag];
                          setDefenseKit(next);
                          if (kitTag === 'detection') {
                            setShowDetectionSubtypes(!exists || !showDetectionSubtypes);
                            if (!exists) setDetectionSubtypeError('Select at least one Detection subtype');
                          }
                          setIsDirty(true);
                        }}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all ${
                          isSelected
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 shadow-sm'
                            : 'bg-gray-50 text-gray-400 border-gray-200 hover:border-gray-300 hover:text-gray-600'
                        }`}
                      >
                        {isSelected && (
                          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {defenseKit.includes('detection') && showDetectionSubtypes && (
                <div className="flex items-center gap-1.5 flex-wrap pl-[110px]">
                  {(
                    ['c2', 'collection', 'credentials', 'discovery', 'evasion', 'execution', 'exfil', 'impact', 'initial access', 'persistence', 'privesc'] as DetectionSubtypeTag[]
                  ).map((subtype) => {
                    const isSelected = detectionSubtypes.includes(subtype);
                    return (
                      <button
                        key={subtype}
                        aria-pressed={isSelected}
                        onClick={() => {
                          const next = isSelected
                            ? detectionSubtypes.filter((s) => s !== subtype)
                            : [...detectionSubtypes, subtype];
                          setDetectionSubtypes(next);
                          setDetectionSubtypeError(next.length === 0 ? 'Select at least one Detection subtype' : '');
                          setIsDirty(true);
                        }}
                        className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold border transition-all ${
                          isSelected
                            ? 'bg-blue-50 text-blue-700 border-blue-200 shadow-sm'
                            : 'bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:text-gray-700'
                        }`}
                      >
                        {subtype}
                      </button>
                    );
                  })}
                </div>
              )}
              {defenseKit.includes('detection') && detectionSubtypeError && (
                <p className="pl-[110px] text-[11px] text-red-600 font-medium">
                  {detectionSubtypeError}
                </p>
              )}
            </div>
            </div>
          </div>

          {/* Results area */}
          <AnimatePresence mode="wait">
            {isRunning && (
              <motion.div
                key="running"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="bg-white rounded-xl border border-gray-200 shadow-sm p-8 flex flex-col items-center gap-3"
              >
                <DuoSpinner size="lg" className="text-blue-500" />
                <p className="text-sm text-gray-500">
                  {mode === 'live' ? 'Waiting for agent response…' : 'Querying database…'}
                </p>
              </motion.div>
            )}

            {result.status === 'error' && (
              <motion.div
                key="error"
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="bg-white rounded-xl border border-red-200 shadow-sm p-4"
              >
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-red-800">Query error</p>
                    <p className="text-sm text-red-600 mt-0.5 font-mono">{result.message}</p>
                  </div>
                </div>
              </motion.div>
            )}

            {result.status === 'success' && (
              <motion.div
                key="success"
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="bg-white rounded-xl border border-gray-200 shadow-sm p-4 min-w-0 overflow-hidden"
              >
                <ResultsTable
                  rows={result.rows}
                  truncated={result.truncated}
                  durationMs={result.durationMs}
                  queryName={name || 'query-results'}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right: metadata panel */}
        <div className="space-y-4">
          {/* Description */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
            <label className="block text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => { setDescription(e.target.value); setIsDirty(true); }}
              placeholder="Describe what this query hunts for…"
              rows={4}
              className="w-full text-sm text-gray-700 placeholder-gray-400 resize-none focus:outline-none bg-transparent"
            />
          </div>

          {/* Query info (edit mode only) */}
          {!isNew && (
            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4 space-y-3">
              <p className="text-xs font-bold text-gray-600 uppercase tracking-wider">Info</p>
              <div>
                <p className="text-xs text-gray-400">ID</p>
                <p className="text-sm text-gray-700 font-mono">{id}</p>
              </div>
            </div>
          )}

          {/* Quick reference */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-bold text-gray-600 uppercase tracking-wider">Tables</p>
              {mode === 'live' && selectedNodeOs !== 'unknown' && (
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${OS_DISPLAY[selectedNodeOs as OsType].cls}`}>
                  {OS_DISPLAY[selectedNodeOs as OsType].label}
                </span>
              )}
            </div>
            <div className="table-scrollbar overflow-y-auto max-h-[420px] -mx-1 px-1">
              {TABLE_CATALOG_BY_CATEGORY.map(([category, entries]) => (
                <div key={category} className="mb-1">
                  <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider px-2 py-1 mt-1 sticky top-0 bg-white">
                    {category}
                  </p>
                  {entries.map((entry) => {
                    const isIncompatible =
                      mode === 'live' &&
                      selectedNodeOs !== 'unknown' &&
                      entry.platforms !== 'all' &&
                      !(entry.platforms as OsType[]).includes(selectedNodeOs as OsType);
                    return (
                      <button
                        key={entry.name}
                        onClick={() => { if (!isIncompatible) { setSql(`SELECT * FROM ${entry.name} LIMIT 100`); setIsDirty(true); } }}
                        title={isIncompatible
                          ? `Not available on ${OS_DISPLAY[selectedNodeOs as OsType].label}`
                          : entry.description}
                        className={`flex items-center justify-between w-full text-left px-2 py-1 rounded-md text-xs transition-colors ${
                          isIncompatible
                            ? 'opacity-30 cursor-not-allowed text-gray-400'
                            : 'text-blue-700 hover:bg-blue-50 hover:text-blue-900'
                        }`}
                      >
                        <span className="truncate" style={{ fontFamily: '"Roboto Mono", monospace', fontWeight: 500 }}>{entry.name}</span>
                        {entry.platforms !== 'all' && (
                          <div className="flex items-center gap-0.5 ml-1.5 flex-shrink-0">
                            {(entry.platforms as OsType[]).map((os) => (
                              <span key={os} className={`text-[9px] font-bold px-1 py-0.5 rounded border leading-none ${OS_DISPLAY[os].cls}`}>
                                {OS_DISPLAY[os].short}
                              </span>
                            ))}
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
            {mode === 'live' && selectedNodeOs !== 'unknown' && (
              <p className="mt-2 text-[10px] text-gray-400 leading-snug border-t border-gray-100 pt-2">
                Dimmed tables are not available on {OS_DISPLAY[selectedNodeOs as OsType].label}.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default QueryEditor;