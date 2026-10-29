import { useEffect, useState, useCallback, useRef } from 'react';
import {
  Search, History, Inbox, ShieldCheck, ShieldAlert, ShieldX, ShieldQuestion, OctagonX,
  Globe2, Network, ServerCog, MousePointerClick, CalendarClock, Clock,
} from 'lucide-react';
import { InlineSpinner } from '@/components/ui/loading';
import Pagination from '@/components/ui/pagination';
import { getDomainReputationHistory } from '../../api/api';
import type {
  DomainReputationCheckResultRow, DomainReputationProviderName, DomainReputationTargetType, DomainReputationVerdict,
} from '../../api/api';
import VerdictBadge from './VerdictBadge';
import { FancySelect } from './ui';

interface HistoryTableProps {
  providers: DomainReputationProviderName[];
  refreshKey: number;
}

const DEFAULT_ROWS_PER_PAGE = 25;
const ROWS_PER_PAGE_OPTIONS = [10, 25, 50];

const PROVIDER_LABEL: Record<DomainReputationProviderName, string> = {
  manual: 'Vajra Reputation Engine',
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
};

const PROVIDER_ICON: Record<DomainReputationProviderName, typeof ShieldCheck> = {
  manual: ServerCog,
  virustotal: ShieldCheck,
  abuseipdb: ShieldAlert,
};

const TYPE_ICON: Record<DomainReputationTargetType, typeof Globe2> = {
  domain: Globe2,
  ip: Network,
};

const TRIGGERED_LABEL: Record<string, string> = {
  manual: 'Manual',
  schedule: 'Scheduled',
};

const TRIGGERED_ICON: Record<string, typeof MousePointerClick> = {
  manual: MousePointerClick,
  schedule: CalendarClock,
};

// Constructing an Intl.DateTimeFormat is the single most expensive common Intl
// operation (locale + pattern resolution), and this ran once per row: the page
// size goes up to 100, and the table re-renders on every keystroke in the
// search box. Hoisting one instance resolves the locale and timezone exactly
// once. Passing `undefined` for locales still resolves to the runtime default
// at construction time, so the formatted output is unchanged.
const CHECKED_AT_FORMATTER = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

const formatCheckedAt = (iso: string) => CHECKED_AT_FORMATTER.format(new Date(iso));

const HistoryTable = ({ providers, refreshKey }: HistoryTableProps) => {
  const [rows, setRows] = useState<DomainReputationCheckResultRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(DEFAULT_ROWS_PER_PAGE);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<DomainReputationVerdict | ''>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Debounce free-text search so every keystroke doesn't fire a request.
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      setSearch(searchInput.trim());
    }, 350);
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, [searchInput]);

  // Guards against a slower earlier response landing after a newer one and
  // overwriting fresher results.
  const fetchSeqRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const seq = ++fetchSeqRef.current;
    try {
      const result = await getDomainReputationHistory({
        rows: rowsPerPage,
        pageno: page,
        search: search || undefined,
        verdict: verdictFilter || undefined,
        provider: providers,
      });
      if (seq !== fetchSeqRef.current) return; // stale response, a newer request is in flight
      setRows(result.data);
      setTotal(result.total);
    } catch {
      if (seq !== fetchSeqRef.current) return;
      setRows([]);
      setTotal(0);
      setError("Couldn't load history — try again");
    } finally {
      if (seq === fetchSeqRef.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [providers.join(','), page, rowsPerPage, search, verdictFilter, refreshKey]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, verdictFilter, refreshKey, rowsPerPage]);

  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));

  // Only the very first fetch (or one starting from empty, e.g. after an
  // error) shows the in-table spinner row — once rows exist, a background
  // refetch (page/page-size/filter change) keeps the current rows mounted
  // and just dims them, so switching page size doesn't flash the table.
  const showLoadingRow = loading && rows.length === 0;

  return (
    // max-h-full (not h-full) is the point: sizes to content — a handful of
    // rows stays compact instead of stretching to fill the whole available
    // height — but still caps at that height and scrolls internally once
    // there's more content than fits (the budget comes from the flex-1
    // wrapper this renders into, e.g. CheckNow's <HistoryTable> slot).
    <div className="max-h-full flex flex-col bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="shrink-0 p-4 border-b border-slate-200 flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
        <h3 className="flex items-center gap-2 text-sm font-bold text-slate-800">
          <History className="h-4 w-4 text-slate-400" />
          Check History
        </h3>
        <div className="flex gap-2">
          <div className="relative">
            <label htmlFor="history-search" className="sr-only">
              Search domain or IP
            </label>
            <Search className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
            <input
              id="history-search"
              type="text"
              placeholder="Search domain/IP…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="text-sm border border-slate-200 rounded-lg pl-8 pr-3 py-1.5 w-44 sm:w-56 focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-transparent"
            />
          </div>
          <FancySelect
            value={verdictFilter}
            onChange={setVerdictFilter}
            className="w-40 py-1.5 text-sm font-semibold text-slate-700 border border-slate-200 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-transparent"
            items={[
              { value: '', label: 'All verdicts' },
              { value: 'malicious', label: 'Malicious', adornment: <ShieldX className="h-3.5 w-3.5 text-red-500" /> },
              { value: 'suspicious', label: 'Suspicious', adornment: <ShieldAlert className="h-3.5 w-3.5 text-amber-500" /> },
              { value: 'clean', label: 'Clean', adornment: <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /> },
              { value: 'unknown', label: 'Unknown', adornment: <ShieldQuestion className="h-3.5 w-3.5 text-slate-400" /> },
              { value: 'error', label: 'Error', adornment: <OctagonX className="h-3.5 w-3.5 text-slate-400" /> },
            ]}
          />
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto scrollbar-auto-hide hover:scrollbar-auto-show">
        <table className="w-full text-sm border-separate border-spacing-0">
          <thead>
            <tr>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Value</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Type</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Provider</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Verdict</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Summary</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Triggered</th>
              <th className="text-left px-4 py-2.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Checked At</th>
            </tr>
          </thead>
          <tbody className={`divide-y divide-slate-100 transition-opacity ${loading && rows.length > 0 ? 'opacity-60 pointer-events-none' : ''}`}>
            {showLoadingRow && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-slate-400">
                <InlineSpinner text="Loading…" size="sm" />
              </td></tr>
            )}
            {!loading && error && (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-red-500">
                <OctagonX className="h-6 w-6 mx-auto mb-2 text-red-400" />
                {error}
                <div className="mt-3">
                  <button
                    onClick={() => load()}
                    className="inline-flex items-center gap-1 px-3 py-1 rounded-lg border border-red-200 text-red-600 hover:bg-red-50 transition-colors"
                  >
                    Retry
                  </button>
                </div>
              </td></tr>
            )}
            {!loading && !error && rows.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-400">
                <Inbox className="h-6 w-6 mx-auto mb-2 text-slate-300" />
                No checks yet
              </td></tr>
            )}
            {!error && rows.length > 0 && rows.map((row) => {
              const TypeIcon = TYPE_ICON[row.type];
              const ProviderIcon = PROVIDER_ICON[row.provider];
              const TriggeredIcon = TRIGGERED_ICON[row.triggered_by] ?? MousePointerClick;
              return (
                <tr key={`${row.provider}-${row.id}`} className="group hover:bg-slate-50/80 transition-colors">
                  <td className="px-4 py-3 font-semibold text-slate-800 border-l-[3px] border-transparent group-hover:border-blue-500 transition-colors">
                    <span className="inline-flex items-center gap-1.5">
                      <TypeIcon className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                      {row.value}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-500 capitalize">{row.type}</td>
                  <td className="px-4 py-3 text-slate-600">
                    <span className="inline-flex items-center gap-1.5 font-medium">
                      <ProviderIcon className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                      {PROVIDER_LABEL[row.provider]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <VerdictBadge verdict={row.verdict} resolvedFromDomain={row.type === 'domain' && !!row.summary?.includes('(resolved to ')} />
                  </td>
                  <td className="px-4 py-3 text-slate-600 max-w-sm truncate" title={row.summary ?? ''}>{row.summary}</td>
                  <td className="px-4 py-3 text-slate-500">
                    <span className="inline-flex items-center gap-1.5">
                      <TriggeredIcon className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                      {TRIGGERED_LABEL[row.triggered_by] ?? row.triggered_by}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-slate-500 tabular-nums">
                    <span className="inline-flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                      {formatCheckedAt(row.created_at)}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {(rows.length > 0 || !loading) && totalPages > 0 && (
        <div className="shrink-0">
          <Pagination
            page={page}
            totalPages={totalPages}
            total={total}
            pageSize={rowsPerPage}
            onPageChange={setPage}
            onPageSizeChange={setRowsPerPage}
            pageSizeOptions={ROWS_PER_PAGE_OPTIONS}
            itemLabel="checks"
            className="border-slate-200"
          />
        </div>
      )}
    </div>
  );
};

export default HistoryTable;
