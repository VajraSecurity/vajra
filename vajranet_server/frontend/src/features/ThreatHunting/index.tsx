import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Fragment } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
import api from '../../api/axiosInstance';
import { THREAT_HUNTING_URLS } from '../../api/urls';
import { useToast } from '../../context/useToast';
import { useModalA11y } from '../../hooks/useModalA11y';
import { DuoSpinner } from '@/components/ui/loading';
import { Meteors } from '@/components/ui/meteors';
import Pagination from '../../components/ui/pagination';
import { ThreatHuntingIcon } from '@/components/icons/navIcons';
import type { SavedQuery, Platform } from './types';
import { PLATFORM_COLORS, PLATFORM_LABELS } from './types';

// Helpers

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  return err instanceof Error ? err.message : fallback;
}

function formatRelativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

const PLATFORM_FILTER_TABS: Array<{ key: Platform; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'linux', label: 'Linux' },
  { key: 'windows', label: 'Windows' },
  { key: 'macos', label: 'macOS' },
];

// Delete confirmation modal

interface DeleteModalProps {
  query: SavedQuery;
  onConfirm: () => void;
  onCancel: () => void;
  deleting: boolean;
}

const DeleteModal = ({ query, onConfirm, onCancel, deleting }: DeleteModalProps) => {
  const modalRef = useModalA11y<HTMLDivElement>(true, onCancel);

  return (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
    <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" onClick={onCancel} />
    <motion.div
      ref={modalRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-query-modal-title"
      initial={{ scale: 0.96, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      exit={{ scale: 0.96, opacity: 0 }}
      transition={{ duration: 0.15 }}
      className="relative bg-white rounded-xl shadow-2xl w-full max-w-md p-6 z-10"
    >
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 w-10 h-10 rounded-full bg-red-50 flex items-center justify-center">
          <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <h3 id="delete-query-modal-title" className="text-base font-semibold text-gray-900">Delete query</h3>
          <p className="mt-1 text-sm text-gray-500">
            Are you sure you want to delete <span className="font-medium text-gray-700">"{query.name}"</span>?
            This action cannot be undone.
          </p>
        </div>
      </div>
      <div className="mt-6 flex justify-end gap-3">
        <button
          onClick={onCancel}
          disabled={deleting}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          onClick={onConfirm}
          disabled={deleting}
          className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {deleting && <DuoSpinner size="sm" />}
          Delete
        </button>
      </div>
    </motion.div>
  </div>
  );
};

// Platform badge

const PlatformBadge = ({ platform }: { platform: string }) => {
  const values = platform === 'all'
    ? ['all']
    : (platform || '').split(',').map((item) => item.trim().toLowerCase()).filter((item) => item === 'linux' || item === 'windows' || item === 'macos');

  if (values.length === 0) values.push('all');

  return (
    <div className="inline-flex items-center gap-1">
      {values.map((value) => (
        <span
          key={value}
          className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ${PLATFORM_COLORS[value as Platform]}`}
        >
          {PLATFORM_LABELS[value as Platform]}
        </span>
      ))}
    </div>
  );
};

const NodeStateBadge = ({ nodeState }: { nodeState?: string | null }) => {
  const value = (nodeState || 'both').toLowerCase();
  const label = value === 'historic' ? 'Historic' : value === 'live' ? 'Live' : 'Both';
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border bg-slate-100 text-slate-700 border-slate-200">
      {label}
    </span>
  );
};

const DefenseKitBadges = ({
  defenseKit,
  detectionSubtypes,
}: {
  defenseKit?: string[] | null;
  detectionSubtypes?: string[] | null;
}) => {
  const kit = Array.isArray(defenseKit) ? defenseKit : [];
  if (kit.length === 0) return <span className="text-gray-300">—</span>;

  return (
    <div className="inline-flex items-center gap-1 flex-wrap">
      {kit.map((item) => (
        <span
          key={item}
          className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border bg-emerald-50 text-emerald-700 border-emerald-200"
        >
          {item === 'detection' ? 'Detection' : item === 'fragments' ? 'Fragments' : 'Policy'}
        </span>
      ))}
      {kit.includes('detection') && Array.isArray(detectionSubtypes) && detectionSubtypes.length > 0 && (
        <span className="text-[11px] text-gray-500">
          ({detectionSubtypes.length} subtype{detectionSubtypes.length > 1 ? 's' : ''})
        </span>
      )}
    </div>
  );
};

// Empty state

const EmptyState = ({ filtered, onNew }: { filtered: boolean; onNew: () => void }) => (
  <div className="py-16 text-center">
    <div className="mx-auto w-12 h-12 rounded-full bg-blue-50 flex items-center justify-center mb-4">
      <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    </div>
    <p className="text-sm font-medium text-gray-900 mb-1">
      {filtered ? 'No queries match your search' : 'No saved queries yet'}
    </p>
    <p className="text-sm text-gray-500 mb-6">
      {filtered
        ? 'Try adjusting your search or filter.'
        : 'Create your first query to start hunting for threats.'}
    </p>
    {!filtered && (
      <button
        onClick={onNew}
        className="metallic-btn-blue inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border-transparent"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
        </svg>
        New query
      </button>
    )}
  </div>
);

// Main page

const ThreatHunting = () => {
  const navigate = useNavigate();
  const { showToast } = useToast();

  // Search/platform filter/pagination are URL-synced (read on mount, written on
  // change, via the effect below) so a browser refresh — or a shared link —
  // restores the same filtered/paged view instead of silently resetting to the
  // defaults, matching the pattern used elsewhere in the app (Alerts, Network, …).
  const [searchParams, setSearchParams] = useSearchParams();
  const [queries, setQueries] = useState<SavedQuery[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState(() => searchParams.get('search') ?? '');
  const [platformFilter, setPlatformFilter] = useState<Platform | 'all'>(() => {
    const p = searchParams.get('platform');
    return PLATFORM_FILTER_TABS.some((tab) => tab.key === p) ? (p as Platform) : 'all';
  });
  const [deleteTarget, setDeleteTarget] = useState<SavedQuery | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [expandedSubtypeRows, setExpandedSubtypeRows] = useState<Record<number, boolean>>({});
  const [fetchingDefaults, setFetchingDefaults] = useState(false);
  const [page, setPage] = useState(() => {
    const p = Number(searchParams.get('page'));
    return Number.isFinite(p) && p > 0 ? Math.floor(p) : 1;
  });
  const [rowsPerPage, setRowsPerPage] = useState(() => {
    const r = Number(searchParams.get('rows'));
    return [10, 25, 50].includes(r) ? r : 10;
  });
  const searchRef = useRef<HTMLInputElement>(null);
  // Tracks whether the search/platform-reset effect below is running for the
  // very first time (initial mount). React fires effects on mount regardless
  // of their dependency array, so without this guard the effect would reset
  // `page` back to 1 immediately after it was restored from the URL above.
  const isFirstFilterRender = useRef(true);

  const fetchQueries = useCallback(async () => {
    try {
      setLoading(true);
      const { data } = await api.get<{ success: boolean; data: SavedQuery[]; message?: string }>(
        THREAT_HUNTING_URLS.QUERIES,
      );
      if (!data.success) throw new Error(data.message ?? 'Failed to load queries');
      setQueries(data.data ?? []);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Failed to load saved queries'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  const handleFetchDefaultQueries = async () => {
    setFetchingDefaults(true);
    try {
      const { data } = await api.post<{ success: boolean; inserted?: number; message?: string }>(THREAT_HUNTING_URLS.POPULATE_DEFAULT_QUERIES);
      if (data.success) {
        showToast('Successfully fetched default queries', 'success');
        fetchQueries();
      } else {
        throw new Error(data.message ?? 'Failed to fetch default queries');
      }
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Failed to fetch default queries'), 'error');
    } finally {
      setFetchingDefaults(false);
    }
  };

  useEffect(() => { fetchQueries(); }, [fetchQueries]);

  // Keyboard shortcut: Ctrl/Cmd+K to focus search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  // Memoised on the filter inputs only: unmemoised this re-runs on every render,
  // including row-expand toggles and pagination clicks that cannot change the
  // result. The platform split is also skipped entirely when platformFilter is
  // 'all', where its result would be discarded.
  const filtered = useMemo(() => {
    const hasSearch = search.trim().length > 0;
    // Matched against the untrimmed lowercased search on purpose: trimming here
    // would change which rows match for a query like "foo ".
    const s = search.toLowerCase();
    return queries.filter((q) => {
      if (platformFilter !== 'all') {
        const qPlatforms = (q.platform || '').split(',').map((item) => item.trim().toLowerCase());
        if (!qPlatforms.includes('all') && !qPlatforms.includes(platformFilter)) return false;
      }
      if (!hasSearch) return true;
      return (
        (q.name || '').toLowerCase().includes(s) ||
        (q.description ?? '').toLowerCase().includes(s) ||
        (q.query || '').toLowerCase().includes(s)
      );
    });
  }, [queries, platformFilter, search]);

  useEffect(() => {
    // Skip the reset on initial mount so a `page` value restored from the URL
    // (see the lazy `useState` initializer above) survives — only reset to
    // page 1 when the user actually changes the search or platform filter.
    if (isFirstFilterRender.current) {
      isFirstFilterRender.current = false;
      return;
    }
    setPage(1);
  }, [search, platformFilter]);

  // Keep the URL in sync with search/platform filter/pagination so a refresh
  // restores this view instead of resetting to the defaults. `replace: true`
  // avoids spamming browser history on every keystroke/filter click.
  useEffect(() => {
    const params = new URLSearchParams();
    if (search.trim()) params.set('search', search);
    if (platformFilter !== 'all') params.set('platform', platformFilter);
    if (page > 1) params.set('page', String(page));
    if (rowsPerPage !== 10) params.set('rows', String(rowsPerPage));
    setSearchParams(params, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, platformFilter, page, rowsPerPage]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / rowsPerPage));
  const pagedQueries = filtered.slice((page - 1) * rowsPerPage, page * rowsPerPage);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.delete(THREAT_HUNTING_URLS.QUERY(deleteTarget.id));
      setQueries((prev) => prev.filter((q) => q.id !== deleteTarget.id));
      showToast('Query deleted', 'success');
      setDeleteTarget(null);
    } catch {
      showToast('Failed to delete query', 'error');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex max-h-[calc(100vh-4rem)] flex-col overflow-hidden bg-[#f8f9fb] px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 md:max-h-screen">
      {/* Header */}
      <header
        className="relative shrink-0 overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white"
        style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
      >
        <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
        <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
              <ThreatHuntingIcon className="w-6 h-6 mr-2" />
              Queries
            </h1>
            <p className="mt-1 text-sm text-blue-100">
              Run SQL queries against your Vajra nodes — live or from stored data.
            </p>
          </div>
          <div className="flex flex-col sm:items-end gap-3 shrink-0">
            {queries.length === 0 && !loading && (
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleFetchDefaultQueries}
                disabled={fetchingDefaults}
                className="relative inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white text-sm font-semibold rounded-xl shadow-[0_0_15px_rgba(79,70,229,0.4)] transition-all disabled:opacity-70 disabled:cursor-not-allowed group overflow-hidden border border-white/20"
              >
                {/* Shimmer effect */}
                <motion.div
                  className="absolute top-0 bottom-0 left-0 w-[150%] bg-gradient-to-r from-transparent via-white/30 to-transparent skew-x-[-20deg]"
                  initial={{ x: '-100%' }}
                  animate={{ x: '100%' }}
                  transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                />
                <div className="absolute inset-0 bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300 ease-out" />
                <span className="relative flex items-center gap-2 pointer-events-none">
                  {fetchingDefaults ? (
                    <DuoSpinner size="sm" className="text-white" />
                  ) : (
                    <svg className="w-4 h-4 text-indigo-100 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                  )}
                  Fetch default queries
                </span>
              </motion.button>
            )}
            <button
              onClick={() => navigate('/threat-hunting/new')}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New query
            </button>
          </div>
        </div>
      </header>

      {/* Toolbar */}
      <div className="mb-4 flex shrink-0 items-center gap-3 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px] max-w-sm">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none"
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={searchRef}
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search queries…"
            className="w-full pl-9 pr-8 py-2 text-sm bg-white border border-gray-200 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-shadow"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 rounded-lg"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {/* Platform filter tabs */}
        <div className="flex items-center bg-slate-50/50 border border-slate-200 rounded-2xl p-1 shadow-sm overflow-x-auto scrollbar-hide">
          {PLATFORM_FILTER_TABS.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setPlatformFilter(key)}
              className={`relative px-6 py-1 sm:px-8 sm:py-1.5 rounded-2xl text-xs font-semibold whitespace-nowrap flex items-center justify-center transition-colors duration-200 ${platformFilter === key
                ? 'text-white'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              style={{ transformStyle: 'preserve-3d' }}
            >
              {platformFilter === key && (
                <motion.div
                  layoutId="threatHuntingTabsBackground"
                  transition={{ type: "spring", bounce: 0, duration: 0.4 }}
                  className="absolute inset-0 bg-[rgb(4,34,119)] rounded-2xl shadow-md"
                  style={{ zIndex: 0 }}
                />
              )}
              <span className="relative z-10 font-semibold">{label}</span>
            </button>
          ))}
        </div>

        {queries.length > 0 && (
          <span className="text-xs text-gray-400 ml-auto">
            {filtered.length} {filtered.length === 1 ? 'query' : 'queries'}
          </span>
        )}
      </div>

      {/* Table */}
      <div className="flex min-h-0 flex-1 flex-col bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {loading ? (
          <div className="py-16 flex justify-center">
            <DuoSpinner size="lg" className="text-blue-500" />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            filtered={!!(search || platformFilter !== 'all')}
            onNew={() => navigate('/threat-hunting/new')}
          />
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto scrollbar-auto-hide hover:scrollbar-auto-show">
          <table className="min-w-full divide-y divide-gray-100 border-separate border-spacing-0">
            <thead>
              <tr className="bg-gray-50/70">
                <th className="pl-6 pr-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Name
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider hidden lg:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Description
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Platform
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider hidden lg:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Node State
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider hidden xl:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Defence Kit
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider hidden md:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Author
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider hidden sm:table-cell sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Modified
                </th>
                <th className="pl-3 pr-6 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              <AnimatePresence initial={false} mode="wait">
                {pagedQueries.map((q) => (
                  <Fragment key={q.id}>
                    <motion.tr
                      key={`row-${q.id}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                      className="hover:bg-blue-50/40 transition-colors group"
                    >
                      {/* Name */}
                      <td className="pl-6 pr-3 py-3.5">
                        <button
                          onClick={() => navigate(`/threat-hunting/${q.id}`)}
                          className="text-sm font-medium text-blue-600 hover:text-blue-800 hover:underline transition-colors text-left max-w-[200px] truncate block rounded-lg"
                          title={q.name}
                        >
                          {q.name}
                        </button>
                        <p className="mt-0.5 text-xs text-gray-400 font-mono max-w-[200px] truncate">
                          {(q.query || '').trim().split('\n')[0]}
                        </p>
                      </td>

                      {/* Description */}
                      <td className="px-3 py-3.5 hidden lg:table-cell">
                        <p className="text-sm text-gray-600 max-w-xs truncate">
                          {q.description || <span className="text-gray-300">—</span>}
                        </p>
                      </td>

                      {/* Platform */}
                      <td className="px-3 py-3.5">
                        <PlatformBadge platform={q.platform} />
                      </td>

                      {/* Node State */}
                      <td className="px-3 py-3.5 hidden lg:table-cell">
                        <NodeStateBadge nodeState={q.node_state} />
                      </td>

                      {/* Defence Kit */}
                      <td className="px-3 py-3.5 hidden xl:table-cell">
                        <div className="inline-flex items-center gap-1 flex-wrap">
                          <DefenseKitBadges defenseKit={q.defense_kit} detectionSubtypes={[]} />
                          {Array.isArray(q.detection_subtypes) && q.detection_subtypes.length > 0 && (q.defense_kit ?? []).includes('detection') && (
                            q.detection_subtypes.length <= 2 ? (
                              <>
                                {q.detection_subtypes.map(subtype => (
                                  <span
                                    key={`${q.id}-${subtype}`}
                                    className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium border bg-blue-50 text-blue-700 border-blue-200"
                                  >
                                    {subtype}
                                  </span>
                                ))}
                              </>
                            ) : (
                              <button
                                type="button"
                                onClick={() =>
                                  setExpandedSubtypeRows((prev) => ({ ...prev, [q.id]: !prev[q.id] }))
                                }
                                className="text-[11px] text-blue-600 hover:text-blue-800 hover:underline rounded-lg"
                              >
                                ({q.detection_subtypes.length} subtypes)
                              </button>
                            )
                          )}
                        </div>
                      </td>

                      {/* Author */}
                      <td className="px-3 py-3.5 hidden md:table-cell">
                        <p className="text-sm text-gray-500">
                          {q.created_by_name || <span className="text-gray-300">—</span>}
                        </p>
                      </td>

                      {/* Modified */}
                      <td className="px-3 py-3.5 hidden sm:table-cell">
                        <p className="text-sm text-gray-500">{formatRelativeTime(q.updated_at)}</p>
                      </td>

                      {/* Actions */}
                      <td className="pl-3 pr-6 py-3.5">
                        <div className="flex items-center justify-end gap-1 sm:opacity-0 sm:group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity">
                          {/* Run */}
                          <button
                            onClick={() => navigate(`/threat-hunting/${q.id}?run=1`)}
                            title="Run query"
                            className="p-1.5 rounded-lg text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition-colors"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          </button>
                          {/* Edit */}
                          <button
                            onClick={() => navigate(`/threat-hunting/${q.id}`)}
                            title="Edit query"
                            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                          {/* Delete */}
                          <button
                            onClick={() => setDeleteTarget(q)}
                            title="Delete query"
                            className="p-1.5 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                    {expandedSubtypeRows[q.id] && (
                      <tr key={`subtypes-${q.id}`} className="bg-blue-50/20">
                        <td className="pl-6 pr-3 py-2.5" colSpan={8}>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">
                              Detection subtypes
                            </span>
                            {(q.detection_subtypes ?? []).map((subtype) => (
                              <span
                                key={`${q.id}-${subtype}`}
                                className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border bg-blue-50 text-blue-700 border-blue-200"
                              >
                                {subtype}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </AnimatePresence>
            </tbody>
          </table>
          </div>
        )}

        {!loading && filtered.length > 0 && (
          <Pagination
            page={page}
            totalPages={totalPages}
            total={filtered.length}
            pageSize={rowsPerPage}
            onPageChange={setPage}
            onPageSizeChange={(size) => { setRowsPerPage(size); setPage(1); }}
            pageSizeOptions={[10, 25, 50]}
            itemLabel="queries"
          />
        )}
      </div>

      {/* Delete confirmation */}
      <AnimatePresence>
        {deleteTarget && (
          <DeleteModal
            query={deleteTarget}
            onConfirm={handleDelete}
            onCancel={() => !deleting && setDeleteTarget(null)}
            deleting={deleting}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

export default ThreatHunting;
