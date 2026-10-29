import { useCallback, useEffect, useRef, useState } from 'react';
import { Inbox, GitBranch } from 'lucide-react';
import { ErrorBanner, StatusToggle } from './ui';
import { InlineSpinner } from '@/components/ui/loading';
import { CORRELATION_TYPE_LABELS, ORDERED_CORRELATION_TYPES } from './constants';
import { listCorrelationRules, setCorrelationRuleEnabled } from '../../api/api';
import type { CorrelationRule, NewCorrelationRule } from '../../api/services/ruleEngineApi';
import CorrelationBuilder from './CorrelationBuilder';
import { getStoredUser } from '../../services/auth';

export interface CorrelationRulesTabProps {
  /** Set by FloatingRuleChat's "Load into builder" action on a `propose_correlation_rule` card. Consumed once, then cleared. */
  pendingLoadedCorrelation?: Partial<NewCorrelationRule> | null;
  onConsumePendingLoadedCorrelation?: () => void;
}

export default function CorrelationRulesTab({ pendingLoadedCorrelation, onConsumePendingLoadedCorrelation }: CorrelationRulesTabProps) {
  const [items, setItems] = useState<CorrelationRule[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showBuilder, setShowBuilder] = useState(false);
  const [busyRef, setBusyRef] = useState<string | null>(null);
  // Same fleet-wide-only scoping constraint as RulesTab — see rule-engine.ts's header comment.
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listCorrelationRules({});
      setItems(resp.items);
      setTotal(resp.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load correlation rules');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const consumedPendingRef = useRef(false);
  useEffect(() => {
    if (pendingLoadedCorrelation && !consumedPendingRef.current) {
      consumedPendingRef.current = true;
      setShowBuilder(true);
    }
    if (!pendingLoadedCorrelation) consumedPendingRef.current = false;
  }, [pendingLoadedCorrelation]);

  const refKey = (r: CorrelationRule) => `${r.source}:${r.id}`;

  const handleToggle = async (rule: CorrelationRule) => {
    setBusyRef(refKey(rule));
    try {
      await setCorrelationRuleEnabled({ source: rule.source, id: rule.id }, !rule.enabled);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update correlation rule');
    } finally {
      setBusyRef(null);
    }
  };

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex items-center justify-between shrink-0">
        <p className="text-xs text-slate-500 dark:text-slate-400 max-w-2xl">
          Correlation rules are hot-reloadable via SIGHUP the same as detection rules. Neither Test Event nor this
          list's Validate exercises the correlation engine itself — use the Correlation Simulation tab to prove a
          rule actually fires against a real ordered event sequence.
        </p>
        {isSuperAdmin && (
          <button
            onClick={() => setShowBuilder(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 shrink-0"
          >
            <GitBranch className="h-4 w-4" /> Build Correlation Rule
          </button>
        )}
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="flex-1 min-h-0 overflow-auto rounded-2xl border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-900">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-white/10">
            <tr>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">ID</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Type</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Description</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Rules</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Timespan</th>
              <th className="text-left px-4 py-2.5 font-semibold text-slate-500 dark:text-slate-400">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-white/5">
            {loading && items.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-10 text-center text-slate-400"><InlineSpinner text="Loading correlation rules…" size="sm" /></td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-12 text-center text-slate-400">
                <Inbox className="h-6 w-6 mx-auto mb-2 text-slate-300" />
                No correlation rules yet — build one to connect detection rules into a kill-chain or threshold incident.
              </td></tr>
            )}
            {items.map((r) => (
              <tr key={refKey(r)} className="hover:bg-slate-50/80 dark:hover:bg-white/5">
                <td className="px-4 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400">{r.id}</td>
                <td className="px-4 py-2.5">
                  <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold ${
                    ORDERED_CORRELATION_TYPES.has(r.type) ? 'bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300' : 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300'
                  }`}>
                    {r.type}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-slate-700 dark:text-slate-200 max-w-sm truncate" title={CORRELATION_TYPE_LABELS[r.type] ?? r.type}>{r.description}</td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-xs">{r.rules.join(ORDERED_CORRELATION_TYPES.has(r.type) ? ' → ' : ', ')}</td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 text-xs">{r.timespan}s</td>
                <td className="px-4 py-2.5">
                  {isSuperAdmin ? (
                    <StatusToggle enabled={r.enabled} busy={busyRef === refKey(r)} onToggle={() => handleToggle(r)} />
                  ) : (
                    <span className={`text-xs font-medium ${r.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
                      {r.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="shrink-0 text-xs text-slate-400 dark:text-slate-500">{total} correlation rule{total === 1 ? '' : 's'} total</p>

      {showBuilder && (
        <CorrelationBuilder
          initialCorrelation={pendingLoadedCorrelation}
          onClose={() => { setShowBuilder(false); onConsumePendingLoadedCorrelation?.(); }}
          onCreated={load}
        />
      )}
    </div>
  );
}
