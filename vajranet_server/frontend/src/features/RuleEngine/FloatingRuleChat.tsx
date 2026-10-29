import { useEffect, useRef, useState } from 'react';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Sparkles, Send as SendIcon, X, FileJson, CheckCircle2, XCircle } from 'lucide-react';
import { useAiChatSession } from '../AI/useAiChatSession';
import type { RuleProposal } from '../AI/useAiChatSession';
import { DuoSpinner } from '@/components/ui/loading';
import type { NewDetectionRule, NewCorrelationRule } from '../../api/services/ruleEngineApi';

// Renderers are hoisted to module scope for the same reason
// `features/AI/index.tsx`'s MD_COMPONENTS are: a fresh object literal per
// render would defeat react-markdown's internal memoization on every
// streamed token. Pure functions of their children, no closed-over state.
const MD_COMPONENTS: Components = {
  p:      ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
  strong: ({ children }) => <strong className="font-bold text-slate-900 dark:text-white">{children}</strong>,
  code:   ({ children, className }) => {
    const isBlock = className?.includes('language-');
    return isBlock
      ? <code className="block bg-slate-100 dark:bg-black/30 rounded-lg px-3 py-2 text-xs font-mono overflow-x-auto mb-2">{children}</code>
      : <code className="bg-slate-100 dark:bg-black/30 rounded px-1.5 py-0.5 text-xs font-mono">{children}</code>;
  },
  ul: ({ children }) => <ul className="list-disc list-inside space-y-0.5 mb-2 pl-1">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal list-inside space-y-0.5 mb-2 pl-1">{children}</ol>,
  a:  ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-indigo-600 dark:text-indigo-400 underline">{children}</a>,
};
const MD_REMARK_PLUGINS = [remarkGfm];

interface FloatingRuleChatProps {
  /** Called when the user clicks "Load into builder" on a propose_rule card — should switch to the Rules tab and open the Add Rule form pre-filled. */
  onLoadRule: (rule: Partial<NewDetectionRule>) => void;
  /** Same, for propose_correlation_rule — switches to Correlation Rules and opens the builder pre-filled. */
  onLoadCorrelation: (rule: Partial<NewCorrelationRule>) => void;
}

/**
 * Floating AI chatbot on the Rule Engine pages. Reuses `useAiChatSession`
 * (the exact same `/api/ai` transport `features/AI/index.tsx` uses — see
 * that hook's doc comment) rather than a forked copy. The only Rule-Engine-
 * specific piece here is rendering a `propose_rule`/`propose_correlation_rule`
 * tool result as a card with "Load into builder"/"Discard" — mirroring the
 * visual language of `features/AI/index.tsx`'s `ActionConfirmCard` (a
 * risk-bordered card in the message stream with two explicit actions), but
 * for a different action shape: nothing here ever saves a rule directly.
 * Every save still goes through the builder UI's own validate+save flow —
 * "Load into builder" only ever populates form fields for a human to review.
 */
export default function FloatingRuleChat({ onLoadRule, onLoadCorrelation }: FloatingRuleChatProps) {
  const [open, setOpen] = useState(false);
  const { bubbles, input, setInput, loading, sendMessage, handleStop } = useAiChatSession();
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [bubbles, open]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        aria-label="Open rule-authoring assistant"
        className="fixed bottom-6 right-6 z-40 flex h-14 w-14 items-center justify-center rounded-full bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 hover:bg-indigo-700 hover:scale-105 transition-all"
      >
        <Sparkles className="h-6 w-6" />
      </button>
    );
  }

  return (
    <div
      role="complementary"
      aria-label="Rule-authoring assistant"
      className="fixed bottom-6 right-6 z-40 flex flex-col w-[380px] max-w-[calc(100vw-2rem)] h-[520px] max-h-[calc(100vh-6rem)] rounded-2xl border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-white/10 bg-indigo-50 dark:bg-indigo-500/10 shrink-0">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
          <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">Rule Assistant</span>
        </div>
        <button onClick={() => setOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-3 py-3 space-y-3">
        {bubbles.length === 0 && (
          <div className="text-xs text-slate-400 text-center py-8 px-4">
            Ask for help writing a detection or correlation rule. I can propose a rule for you to review — you
            always save it yourself from the builder.
          </div>
        )}
        {bubbles.map((b) => (
          <div key={b.id} className={`flex ${b.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`min-w-0 max-w-[90%] ${b.role === 'user' ? '' : 'w-full'}`}>
              {(b.text || (b.role === 'assistant' && !b.isStreaming)) && (
                <div
                  className={`rounded-xl px-3 py-2 text-xs leading-relaxed break-words ${
                    b.role === 'user'
                      ? 'bg-indigo-600 text-white rounded-tr-none whitespace-pre-wrap'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-700 dark:text-slate-200 rounded-tl-none'
                  }`}
                >
                  {b.role === 'user' ? b.text : (
                    <ReactMarkdown remarkPlugins={MD_REMARK_PLUGINS} components={MD_COMPONENTS}>{b.text}</ReactMarkdown>
                  )}
                </div>
              )}
              {b.role === 'assistant' && b.isStreaming && !b.text && (
                <div className="flex items-center gap-2 text-xs text-slate-400 py-1"><DuoSpinner size="xs" /> Thinking…</div>
              )}
              {b.role === 'assistant' && b.ruleProposals && b.ruleProposals.length > 0 && (
                <div className="mt-2 space-y-2">
                  {b.ruleProposals.map((p) => (
                    <RuleProposalCard key={p.id} proposal={p} onLoadRule={onLoadRule} onLoadCorrelation={onLoadCorrelation} />
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="p-3 border-t border-slate-200 dark:border-white/10 shrink-0">
        <div className="flex items-end gap-2 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-white/5 px-3 py-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about rules, operators, or propose one…"
            rows={1}
            disabled={loading}
            className="flex-1 resize-none bg-transparent text-xs text-slate-700 dark:text-slate-200 placeholder:text-slate-400 outline-none max-h-24"
          />
          <button
            onClick={() => (loading ? handleStop() : sendMessage())}
            disabled={!loading && !input.trim()}
            aria-label={loading ? 'Stop' : 'Send'}
            className="shrink-0 flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-600 text-white disabled:opacity-40 hover:bg-indigo-700"
          >
            {loading ? <span className="h-2.5 w-2.5 rounded-sm bg-white" /> : <SendIcon className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>
    </div>
  );
}

function RuleProposalCard({
  proposal, onLoadRule, onLoadCorrelation,
}: {
  proposal: RuleProposal;
  onLoadRule: (rule: Partial<NewDetectionRule>) => void;
  onLoadCorrelation: (rule: Partial<NewCorrelationRule>) => void;
}) {
  const [discarded, setDiscarded] = useState(false);
  const [loaded, setLoaded] = useState(false);

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
    if (proposal.kind === 'correlation_rule') onLoadCorrelation(proposal.rule as Partial<NewCorrelationRule>);
    else onLoadRule(proposal.rule as Partial<NewDetectionRule>);
    setLoaded(true);
  };

  // On a REJECTED proposal, Vajranet-BE's confirmed contract carries no
  // `rule` key at all (docs/team/vajranet-be.md) — parseRuleProposal falls
  // back to `{}` in that case. Loading an empty object into the builder
  // isn't useful, so "Load into builder" is hidden and only the engine's
  // exact rejection reason (validation.message) plus a Dismiss button show.
  const hasRuleContent = Object.keys(proposal.rule).length > 0;
  let jsonText: string;
  try { jsonText = JSON.stringify(proposal.rule, null, 2); } catch { jsonText = String(proposal.rule); }

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
        // RawJsonView is (see that file's comment); dangerouslySetInnerHTML
        // is never used here.
        <pre className="max-h-40 overflow-auto rounded-lg bg-white dark:bg-black/30 border border-indigo-100 dark:border-white/10 p-2 text-[10px] font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-words mb-2">
          {jsonText}
        </pre>
      )}
      {proposal.validation && !proposal.validation.ok && proposal.validation.message && (
        <p className="text-[10px] text-red-600 dark:text-red-400 mb-2">{proposal.validation.message}</p>
      )}
      <div className="flex gap-2">
        {hasRuleContent && (
          <button
            onClick={handleLoad}
            className="flex-1 rounded-lg bg-indigo-600 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
          >
            Load into builder
          </button>
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
