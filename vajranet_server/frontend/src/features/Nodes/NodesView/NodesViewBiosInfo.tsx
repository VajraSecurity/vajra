/**
 * NodesView BIOS tab: Windows BIOS information.
 * API: nodesViewApi.getBiosInfo
 */

import { useEffect, useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import type { NodeData } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import { nodesViewApi } from './nodesViewApi';
import { sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import Pagination from '../../../components/ui/pagination';

interface NodesViewBiosInfoProps {
  node: NodeData;
}

interface BiosInfoRow {
  id: string;
  host_identifier: string;
  unixtime: string;
  name: string;
  value: string;
}

const toTitle = (text: string) =>
  text
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());

const formatUnixTime = (value: string): string | null => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  if (parsed < 1000000000 || parsed > 4102444800) return null;
  return new Date(parsed * 1000).toLocaleString();
};

const isNumeric = (value: string) => /^-?\d+(\.\d+)?$/.test(value);

const parseBraceList = (value: string): string[] => {
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return [];
  const body = trimmed.slice(1, -1).trim();
  if (!body) return [];
  return body
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
};

const renderValue = (row: BiosInfoRow) => {
  const raw = row.value ?? '';
  const trimmed = raw.trim();

  if (!trimmed) {
    return <span className="text-slate-400 dark:text-slate-500">N/A</span>;
  }

  if (/^(true|false)$/i.test(trimmed)) {
    const enabled = trimmed.toLowerCase() === 'true';
    return (
      <span
        className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${
          enabled
            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30'
            : 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-500/10 dark:text-rose-400 dark:border-rose-500/30'
        }`}
      >
        {enabled ? 'True' : 'False'}
      </span>
    );
  }

  const listValues = parseBraceList(trimmed);
  if (listValues.length > 0) {
    return (
      <div className="flex flex-wrap gap-1">
        {listValues.map((item, idx) => (
          <span
            key={`${row.id}-${idx}`}
            className="px-2 py-0.5 bg-sky-50 text-sky-700 border border-sky-200 dark:bg-sky-500/10 dark:text-sky-400 dark:border-sky-500/30 rounded text-xs"
          >
            {item}
          </span>
        ))}
      </div>
    );
  }

  const keyName = row.name.toLowerCase();
  const looksLikeTime =
    keyName.includes('time') ||
    keyName.includes('date') ||
    keyName.includes('unixtime') ||
    keyName.includes('release');

  if (looksLikeTime) {
    const humanDate = formatUnixTime(trimmed);
    if (humanDate) {
      return (
        <div className="space-y-0.5">
          <div className="text-slate-800 dark:text-slate-100">{humanDate}</div>
          <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">{trimmed}</div>
        </div>
      );
    }
  }

  if (isNumeric(trimmed)) {
    return <span className="text-slate-700 dark:text-slate-300 font-mono">{trimmed}</span>;
  }

  return <span className="text-slate-800 dark:text-slate-100 break-words">{trimmed}</span>;
};

const NodesViewBiosInfo = ({ node }: NodesViewBiosInfoProps) => {
  const [biosRows, setBiosRows] = useState<BiosInfoRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const hostId = node.host_identifier || String(node.id);

  useEffect(() => {
    let cancelled = false;

    const loadBiosInfo = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await nodesViewApi.getBiosInfo(hostId);
        if (!cancelled) {
          if (res.data.status === 'Success' && Array.isArray(res.data.data)) {
            setBiosRows(res.data.data);
          } else {
            setError(res.data.message || 'No BIOS information found');
          }
        }
      } catch (err: unknown) {
        if (!cancelled) {
          console.error('Failed to fetch BIOS information:', err);
          const msg = err && typeof err === 'object' && 'response' in err
            ? (err as { response?: { data?: { message?: string } } }).response?.data?.message
            : undefined;
          setError(msg || 'Failed to fetch BIOS information');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    loadBiosInfo();

    return () => {
      cancelled = true;
    };
  }, [hostId]);

  const filteredRows = useMemo(() => {
    if (!searchTerm.trim()) return biosRows;
    const needle = searchTerm.toLowerCase();
    return biosRows.filter(
      (item) => item.name.toLowerCase().includes(needle) || (item.value || '').toLowerCase().includes(needle)
    );
  }, [biosRows, searchTerm]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const paginatedRows = filteredRows.slice(startIndex, startIndex + pageSize);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const latestCollectionTime = useMemo(() => {
    if (biosRows.length === 0) return null;
    const latest = biosRows.reduce((max, row) => {
      const ts = Number(row.unixtime);
      return Number.isFinite(ts) && ts > max ? ts : max;
    }, 0);

    if (!latest) return null;
    return new Date(latest * 1000).toLocaleString();
  }, [biosRows]);

  if (loading) {
    return (
      <div className="p-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40">
            <h6 className="font-semibold text-slate-800 dark:text-slate-100">BIOS Information</h6>
          </div>
          <div className="flex items-center justify-center py-12">
            <DuoSpinner size="lg" className="text-slate-500" />
          </div>
        </div>
      </div>
    );
  }

  if (error || biosRows.length === 0) {
    return (
      <div className="p-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40">
            <h6 className="font-semibold text-slate-800 dark:text-slate-100">BIOS Information</h6>
          </div>
          <div className="p-5">
            <div className="text-sm p-3 rounded-lg bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/30">
              {error || 'No BIOS information available'}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-700 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm min-w-0">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500 shrink-0">Host</span>
              <span className="font-mono text-xs text-slate-700 dark:text-slate-200 truncate max-w-[160px] sm:max-w-[320px]" title={hostId}>
                {hostId}
              </span>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">Last Collected</span>
              <span className="text-slate-700 dark:text-slate-200 whitespace-nowrap">{latestCollectionTime || 'N/A'}</span>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">Settings</span>
              <span className="font-semibold text-slate-700 dark:text-slate-200 whitespace-nowrap">
                {filteredRows.length} / {biosRows.length}
              </span>
            </div>
          </div>

          <div className="relative w-full sm:w-72 lg:w-80 shrink-0">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="Search by setting name or value..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(sanitizeAsciiSingleLine(e.target.value, 200, false))}
              aria-label="Search BIOS settings"
              className="h-9 w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 pl-9 pr-3 text-sm text-slate-700 dark:text-slate-200 outline-none transition-colors placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-blue-300 dark:focus:border-blue-500 focus:ring-3 focus:ring-blue-500/10"
            />
          </div>
        </div>

        {filteredRows.length > 0 && (
          <div className="table-scrollbar max-h-[65vh] overflow-auto">
            <table className="w-full text-sm border-separate border-spacing-0">
              <thead>
                <tr>
                  <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Setting
                  </th>
                  <th className="text-left py-3 px-3 font-medium text-slate-600 dark:text-slate-300 uppercase tracking-wide text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                    Value
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/60">
                {paginatedRows.map((row, index) => (
                  <tr
                    key={`${row.id}-${startIndex + index}`}
                    className="transition-colors hover:bg-slate-50/70 dark:hover:bg-slate-700/30"
                  >
                    <td className="py-3 px-3 align-top">
                      <div className="font-medium text-slate-800 dark:text-slate-100">{toTitle(row.name)}</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">{row.name}</div>
                    </td>
                    <td className="py-3 px-3 align-top">{renderValue(row)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {filteredRows.length > 0 && (
          <Pagination
            page={safeCurrentPage}
            totalPages={totalPages}
            total={filteredRows.length}
            pageSize={pageSize}
            onPageChange={(p) => setCurrentPage(p)}
            onPageSizeChange={(size) => { setPageSize(size); setCurrentPage(1); }}
            pageSizeOptions={[10, 25, 50]}
            itemLabel="settings"
          />
        )}

        {filteredRows.length === 0 && (
          <div className="flex flex-col items-center gap-3 py-14 text-center">
            <p className="text-sm font-medium text-slate-600 dark:text-slate-300">No BIOS settings match your search</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NodesViewBiosInfo;
