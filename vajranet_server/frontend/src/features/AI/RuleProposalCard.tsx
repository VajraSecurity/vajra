import { useMemo, useState } from 'react';
import { FileJson, CheckCircle2, XCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { RuleProposal } from './useAiChatSession';
import { RULE_ENGINE_ENABLED } from '../../lib/featureFlags';

/**
 * Renders a `propose_rule`/`propose_correlation_rule` tool result as a card.
 * Used on every chat surface (the floating widget on any page, and the
 * full-page AI Assistant) — `onLoadRule`/`onLoadCorrelation` are only passed
 * in while a Rule Engine page is mounted (see `FloatingChatContext`); when
 * they aren't, the card still renders in full (JSON, validation status) with
 * a link to Rule Engine instead of a "Load into builder" button.
 *
 * This used to be gated entirely behind having those handlers, which meant
 * the card — not just the button — vanished the moment the user navigated
 * off Rule Engine, even for a proposal that had already rendered in an
 * earlier message. Nothing here ever saves a rule directly; every save
 * still goes through the builder UI's own validate+save flow.
 */
export default function RuleProposalCard({
  proposal, onLoadRule, onLoadCorrelation,
}: {
  proposal: RuleProposal;
  onLoadRule?: (rule: Record<string, unknown>) => void;
  onLoadCorrelation?: (rule: Record<string, unknown>) => void;
}) {
  const [discarded, setDiscarded] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const canLoad = !!(onLoadRule && onLoadCorrelation);
  // Memoized so re-renders triggered by an unrelated streaming bubble in the
  // same transcript (a setBubbles call per SSE token) don't re-serialize an
  // unchanged rule on every keystroke of the model's response. Must sit
  // above the early returns below — hooks can't be called conditionally.
  const jsonText = useMemo(() => {
    try { return JSON.stringify(proposal.rule, null, 2); } catch { return String(proposal.rule); }
  }, [proposal.rule]);

  if (discarded) {
    return (
      <div className="rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-white/5 px-3 py-2 text-xs text-slate-400 flex items-center gap-2">
        <XCircle className="h-3.5 w-3.5" /> Proposal discarded
      </div>
    );
  }
  if (loaded) {
    return (
      <div className="rounded-xl border border-emerald-200 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400 flex items-center gap-2">
        <CheckCircle2 className="h-3.5 w-3.5" /> Loaded into the builder — review and save it there
      </div>
    );
  }

  const handleLoad = () => {
    if (proposal.kind === 'correlation_rule') onLoadCorrelation?.(proposal.rule);
    else onLoadRule?.(proposal.rule);
    setLoaded(true);
  };

  // On a REJECTED proposal, the confirmed contract carries no `rule` key at
  // all — parseRuleProposal falls back to `{}` in that case. Loading an
  // empty object into the builder isn't useful, so "Load into builder" is
  // hidden and only the engine's exact rejection reason (validation.message)
  // plus a Dismiss button show.
  const hasRuleContent = Object.keys(proposal.rule).length > 0;

  return (
    <div className={`rounded-xl border-2 p-3 ${
      proposal.validation?.ok === false
        ? 'border-red-200 dark:border-red-500/40 bg-red-50/60 dark:bg-red-500/5'
        : 'border-indigo-200 dark:border-indigo-500/40 bg-indigo-50/60 dark:bg-indigo-500/5'
    }`}>
      <div className="flex items-center gap-2 mb-1.5">
        <FileJson className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400 shrink-0" />
        <span className="text-xs font-semibold text-indigo-800 dark:text-indigo-300">
          Proposed {proposal.kind === 'correlation_rule' ? 'correlation rule' : 'detection rule'}
        </span>
        {proposal.validation && (
          <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded-full ${proposal.validation.ok ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400' : 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400'}`}>
            {proposal.validation.ok ? 'engine-validated' : 'rejected by engine'}
          </span>
        )}
      </div>
      {hasRuleContent && (
        // Plain text via a <pre> text node — React escapes text content by
        // default, so this is safe to render without a sanitizer for
        // AI-proposed JSON the same way features/RuleEngine/ui.tsx's
        // RawJsonView is; dangerouslySetInnerHTML is never used here.
        <pre className="max-h-40 overflow-auto rounded-lg bg-white dark:bg-black/30 border border-indigo-100 dark:border-white/10 p-2 text-[10px] font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-words mb-2">
          {jsonText}
        </pre>
      )}
      {proposal.validation && !proposal.validation.ok && proposal.validation.message && (
        <p className="text-[10px] text-red-600 dark:text-red-400 mb-2">{proposal.validation.message}</p>
      )}
      <div className="flex gap-2">
        {hasRuleContent && canLoad && (
          <button
            onClick={handleLoad}
            className="flex-1 rounded-lg bg-indigo-600 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
          >
            Load into builder
          </button>
        )}
        {hasRuleContent && !canLoad && RULE_ENGINE_ENABLED && (
          <Link
            to="/rule-engine"
            className="flex-1 rounded-lg bg-indigo-600 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 text-center"
          >
            Open Rule Engine to load this →
          </Link>
        )}
        <button
          onClick={() => setDiscarded(true)}
          className={`rounded-lg py-1.5 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 border border-slate-200 dark:border-white/10 ${hasRuleContent ? 'px-3' : 'flex-1'}`}
        >
          {hasRuleContent ? 'Discard' : 'Dismiss'}
        </button>
      </div>
    </div>
  );
}
