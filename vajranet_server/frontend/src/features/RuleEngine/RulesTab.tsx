import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Plus, Search, Trash2, Inbox } from 'lucide-react';
import { Dropdown, SeverityBadge, ErrorBanner, StatusToggle } from './ui';
import { InlineSpinner } from '@/components/ui/loading';
import { EVENT_TYPES } from './constants';
import { listRules, setRuleEnabled, deleteRule } from '../../api/api';
import type { DetectionRule, NewDetectionRule } from '../../api/services/ruleEngineApi';
import RuleFormModal from './RuleFormModal';
import { useConfirm } from '../../context/useConfirm';
import { getStoredUser } from '../../services/auth';

// Debounce delay for the search box — mirrors the spec's explicit
// "debounced ... never load 1500+ rules at once" requirement, applied here
// too even though this tab paginates server-side rather than loading
// everything, to avoid firing a request per keystroke against a ~1500-rule
// corpus.
const SEARCH_DEBOUNCE_MS = 350;
const PAGE_SIZE = 25;

export interface RulesTabProps {
  /** Set by FloatingRuleChat's "Load into builder" action on a `propose_rule` card. Consumed once, then cleared. */
  pendingLoadedRule?: Partial<NewDetectionRule> | null;
  onConsumePendingLoadedRule?: () => void;
}

export default function RulesTab({ pendingLoadedRule, onConsumePendingLoadedRule }: RulesTabProps) {
  const [items, setItems] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchInput, setSearchInput] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState<'' | 'true' | 'false'>('');

  const [showForm, setShowForm] = useState(false);
  const [busyRef, setBusyRef] = useState<string | null>(null);
  const confirm = useConfirm();
  // Rules affect fleet-wide detection with no per-group scoping possible
  // (the engine has no group concept) — write access is Super Admin only,
  // same as the backend route gate. See rule-engine.ts's header comment.
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchInput.trim()), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listRules({
        q: debouncedSearch || undefined,
        event_type: eventTypeFilter || undefined,
        enabled: enabledFilter === '' ? undefined : enabledFilter === 'true',
        page,
        page_size: PAGE_SIZE,
      });
      setItems(resp.items);
      setTotal(resp.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules');
    } finally {
      setLoading(false);
    }
  }, [debouncedSearch, eventTypeFilter, enabledFilter, page]);

  useEffect(() => { load(); }, [load]);
  // Reset to page 1 whenever a filter changes, so the user doesn't land on
  // an out-of-range page for a narrower result set.
  useEffect(() => { setPage(1); }, [debouncedSearch, eventTypeFilter, enabledFilter]);

  // A propose_rule chat card's "Load into builder" opens this tab's Add
  // Rule modal pre-filled — consumed once via the parent's callback so
  // re-rendering this tab doesn't reopen the modal repeatedly.
  const consumedPendingRef = useRef(false);
  useEffect(() => {
    if (pendingLoadedRule && !consumedPendingRef.current) {
      consumedPendingRef.current = true;
      setShowForm(true);
    }
    if (!pendingLoadedRule) consumedPendingRef.current = false;
  }, [pendingLoadedRule]);

  const groupSuggestions = useMemo(() => Array.from(new Set(items.flatMap((r) => r.groups ?? []))), [items]);
  const mitreSuggestions = useMemo(() => Array.from(new Set(items.flatMap((r) => r.mitre ?? []))), [items]);

  const refKey = (r: DetectionRule) => `${r.source}:${r.id}`;

  const handleToggle = async (rule: DetectionRule) => {
    setBusyRef(refKey(rule));
    try {
      await setRuleEnabled({ source: rule.source, id: rule.id }, !rule.enabled);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule');
    } finally {
      setBusyRef(null);
    }
  };

  const handleDelete = async (rule: DetectionRule) => {
    const ok = await confirm({
      title: `Delete rule ${rule.id}?`,
      description: rule.description,
      confirmLabel: 'Delete',
      variant: 'danger',
    });
    if (!ok) return;
    setBusyRef(refKey(rule));
    try {
      await deleteRule({ source: rule.source, id: rule.id });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule');
    } finally {
      setBusyRef(null);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex flex-wrap items-center gap-3 shrink-0">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search rules by id, description, MITRE technique…"
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          />
        </div>
        <Dropdown
          value={eventTypeFilter}
          onChange={setEventTypeFilter}
          placeholder="All event types"
          options={EVENT_TYPES.map((t) => ({ value: t, label: t }))}
          className="w-52"
          aria-label="Filter by event type"
        />
        <Dropdown
          value={enabledFilter}
          onChange={(v) => setEnabledFilter(v as '' | 'true' | 'false')}
          placeholder="All statuses"
          options={[{ value: 'true', label: 'Enabled only' }, { value: 'false', label: 'Disabled only' }]}
          className="w-44"
          aria-label="Filter by enabled status"
        />
        {isSuperAdmin && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          >
            <Plus className="h-4 w-4" /> Add Rule
          </button>
        )}
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="flex-1 min-h-0 overflow-auto rounded-2xl border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-900">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-white/10">
            <tr>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">ID</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Source</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Event Type</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Description</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Level</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">MITRE</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Status</th>
              <th className="text-right px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-white/5">
            {loading && items.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-10 text-center text-slate-400"><InlineSpinner text="Loading rules…" size="sm" /></td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-12 text-center text-slate-400">
                <Inbox className="h-6 w-6 mx-auto mb-2 text-slate-300" />
                No rules match these filters
              </td></tr>
            )}
            {items.map((r) => (
              <tr key={refKey(r)} className="hover:bg-slate-50/80 dark:hover:bg-white/5">
                <td className="px-4 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400">{r.id}</td>
                <td className="px-4 py-2.5 text-slate-600 dark:text-slate-300">{r.source}</td>
                <td className="px-4 py-2.5"><code className="text-xs bg-slate-100 dark:bg-white/10 rounded px-1.5 py-0.5">{r.event_type}</code></td>
                <td className="px-4 py-2.5 text-slate-700 dark:text-slate-200 max-w-sm truncate" title={r.description}>{r.description}</td>
                <td className="px-4 py-2.5"><SeverityBadge level={r.level} /></td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-xs">{(r.mitre ?? []).join(', ') || '—'}</td>
                <td className="px-4 py-2.5">
                  {isSuperAdmin ? (
                    <StatusToggle enabled={r.enabled} busy={busyRef === refKey(r)} onToggle={() => handleToggle(r)} />
                  ) : (
                    <span className={`text-xs font-medium ${r.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
                      {r.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-right">
                  {isSuperAdmin && (
                    r.editable ? (
                      <button
                        onClick={() => handleDelete(r)}
                        disabled={busyRef === refKey(r)}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    ) : (
                      <span className="text-xs text-slate-400">Read-only source</span>
                    )
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between shrink-0 text-xs text-slate-500 dark:text-slate-400">
        <span>{total} rule{total === 1 ? '' : 's'} total</span>
        <div className="flex items-center gap-2">
          <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="px-2 py-1 rounded disabled:opacity-40 hover:bg-slate-100 dark:hover:bg-white/10">Prev</button>
          <span>Page {page} / {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="px-2 py-1 rounded disabled:opacity-40 hover:bg-slate-100 dark:hover:bg-white/10">Next</button>
        </div>
      </div>

      {showForm && (
        <RuleFormModal
          initialRule={pendingLoadedRule}
          groupSuggestions={groupSuggestions}
          mitreSuggestions={mitreSuggestions}
          onClose={() => { setShowForm(false); onConsumePendingLoadedRule?.(); }}
          onCreated={load}
        />
      )}
    </div>
  );
}
