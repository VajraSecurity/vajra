import { useState, useRef, useEffect, useCallback, memo } from 'react';
import { useSearchParams } from 'react-router-dom';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ThinkingOrb } from 'thinking-orbs';
import WebThreads from '../../components/effects/WebThreads';
import vajraLogo from '../../assets/vajra/vajralogo-white.png';
import AiProviderSettings from './AiProviderSettings';
import { getStoredUser } from '../../services/auth';
import { getAiProviderConfigStatus } from '../../api/api';
import { useConfirm } from '../../context/useConfirm';
import { useAiChatSession } from './useAiChatSession';
import type { BubbleMessage, SessionSummary } from './useAiChatSession';
import { ActionConfirmCard, ToolCallBadge, SUGGESTIONS, isSafeMarkdownHref } from './shared';
import RuleProposalCard from './RuleProposalCard';

// Brand tokens for this page — classic magenta (#4b1852/#b83fc2), sampled
// straight off the real Vajra logo artwork, paired with a dark gold accent.
// See docs/team/ (AI page redesign) for how these were landed on.
const MAGENTA = '#4b1852';
const MAGENTA_BRIGHT = '#b83fc2';
const GOLD = '#c69a4a';
const SURFACE = '#150f1a';
const SURFACE_2 = '#1b131f';
const SURFACE_BORDER = 'rgba(255,255,255,0.08)';

function timeAgo(dateStr: string) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

// Thinking indicator — the real thinking-orbs engine (npm, MIT), run at its
// 64px preset for correct dot density/speed but displayed at 56px, in a
// neutral charcoal pill with inset-only shadow. Exact styling lifted from
// the component's own reference usage example, not invented.
function AuroraThinking({ toolName }: { toolName?: string }) {
  return (
    <div
      className="inline-flex items-center gap-3"
      style={{
        height: 74,
        padding: '0 32px 0 9px',
        borderRadius: 999,
        background: 'rgba(29,29,29,0.42)',
        boxShadow: 'inset 0 0 0 1px rgba(44,47,54,0.31), inset 0 0 50px 0 rgba(255,255,255,0.012)',
      }}
    >
      <ThinkingOrb state="composing" size={64} theme="dark" style={{ width: 56, height: 56 }} />
      <span className="text-base leading-6" style={{ color: 'rgba(251,251,251,0.75)' }}>
        {toolName ? `${toolName}…` : 'Thinking…'}
      </span>
    </div>
  );
}

// Streaming cursor

function AuroraCursor() {
  return (
    <span
      className="inline-block w-0.5 h-4 ml-0.5 rounded-full animate-pulse align-middle"
      style={{
        background: `linear-gradient(to bottom, ${MAGENTA_BRIGHT}, ${GOLD})`,
        boxShadow: `0 0 6px rgba(184,63,194,0.8)`,
        animationDuration: '0.8s',
      }}
    />
  );
}

// Message bubble

// Must stay at module scope. Defined inline on <ReactMarkdown components={...}>
// each renderer is a new component type per render, and React compares element
// types by identity, so the whole markdown subtree is torn down and remounted
// instead of diffed. Streaming calls setBubbles once per text_delta SSE chunk —
// tens of times a second on the live bubble. These renderers are pure functions
// of their children and close over no component state, so hoisting is safe.
const MD_COMPONENTS: Components = {
  p:      ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
  strong: ({ children }) => <strong className="font-bold text-white">{children}</strong>,
  em:     ({ children }) => <em className="italic text-[#e0c8e6]/80">{children}</em>,
  h1:     ({ children }) => <h1 className="text-base font-bold text-white mb-2 mt-3 first:mt-0">{children}</h1>,
  h2:     ({ children }) => <h2 className="text-sm font-bold text-white mb-1.5 mt-3 first:mt-0">{children}</h2>,
  h3:     ({ children }) => <h3 className="text-sm font-semibold text-white/90 mb-1 mt-2 first:mt-0">{children}</h3>,
  ul:     ({ children }) => <ul className="list-disc list-inside space-y-0.5 mb-2 pl-1">{children}</ul>,
  ol:     ({ children }) => <ol className="list-decimal list-inside space-y-0.5 mb-2 pl-1">{children}</ol>,
  li:     ({ children }) => <li className="text-white/85">{children}</li>,
  code:   ({ children, className }) => {
    const isBlock = className?.includes('language-');
    return isBlock
      ? <code className="block bg-black/30 rounded-lg px-3 py-2 text-xs font-mono text-[#f0d8f4]/90 overflow-x-auto mb-2 border border-white/8">{children}</code>
      : <code className="bg-black/25 rounded px-1.5 py-0.5 text-xs font-mono text-[#e0a8e8]/90 border border-white/10">{children}</code>;
  },
  pre:  ({ children }) => <pre className="mb-2">{children}</pre>,
  blockquote: ({ children }) => <blockquote className="border-l-2 border-[#b83fc2]/50 pl-3 italic text-white/60 mb-2">{children}</blockquote>,
  hr:   () => <hr className="border-white/10 my-3" />,
  a:    ({ href, children }) => isSafeMarkdownHref(href)
    ? <a href={href} target="_blank" rel="noopener noreferrer" className="text-[#d488de] hover:text-[#e0a8e8] underline underline-offset-2">{children}</a>
    : <span className="underline decoration-dotted" title="Link removed — not a safe http(s) address">{children}</span>,
};

// Same reasoning one level down: a fresh [remarkGfm] literal per render makes
// react-markdown rebuild its unified processor instead of reusing the cached one.
const MD_REMARK_PLUGINS = [remarkGfm];

// memo() is what stops the entire transcript re-rendering on every streamed
// token. Every setBubbles updater in this file is written as
// prev.map((b) => b.id === aiBubbleId ? { ...b, ... } : b), so bubbles other
// than the one currently streaming keep their exact object identity across
// updates. isLatestAssistant is a boolean, and onConfirmAction/onDenyAction are
// useCallback-stable (their only dep, showToast, is itself useCallback-stable
// and ToastContext memoises its provider value), so every prop is
// reference-equal for untouched bubbles and memo short-circuits them. This is
// purely a render skip: every prop that would produce different output still
// changes identity when it changes.
const MessageBubble = memo(function MessageBubble({
  msg,
  isLatestAssistant,
  onConfirmAction,
  onDenyAction,
}: {
  msg: BubbleMessage;
  isLatestAssistant: boolean;
  onConfirmAction: (id: string) => Promise<boolean>;
  onDenyAction: (id: string) => Promise<boolean>;
}) {
  const isUser = msg.role === 'user';
  const liveToolIdx = (msg.toolEvents?.length ?? 0) - 1;

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-5`}>
      <div className={`min-w-0 max-w-[82%] ${isUser ? '' : 'w-full'}`}>
        {/* Tool events */}
        {!isUser && msg.toolEvents && msg.toolEvents.length > 0 && (
          <div className="mb-2 space-y-1.5">
            {msg.toolEvents.map((ev, i) => (
              <ToolCallBadge
                key={i}
                event={ev}
                isLive={isLatestAssistant && msg.isStreaming && i === liveToolIdx && ev.result === undefined}
              />
            ))}
          </div>
        )}

        {/* Thinking state */}
        {!isUser && msg.isStreaming && !msg.text && msg.toolEvents && msg.toolEvents.length === 0 && (
          <AuroraThinking />
        )}

        {/* Text bubble */}
        {(msg.text || (!isUser && !msg.isStreaming)) && (
          <div
            className={`rounded-2xl px-4 py-3 text-sm leading-relaxed break-words
              ${isUser
                ? 'text-white rounded-tr-none whitespace-pre-wrap'
                : 'text-white/90 rounded-tl-none border ai-bubble-md'
              }`}
            style={isUser
              ? {
                  background: 'linear-gradient(135deg, rgba(184,63,194,0.5), rgba(198,154,74,0.35))',
                  backdropFilter: 'blur(12px)',
                  boxShadow: '0 0 20px rgba(184,63,194,0.2)',
                }
              : {
                  background: 'linear-gradient(135deg, rgba(75,24,82,0.35), rgba(198,154,74,0.1))',
                  backdropFilter: 'blur(12px)',
                  borderColor: 'rgba(184,63,194,0.25)',
                  boxShadow: '0 0 20px rgba(75,24,82,0.15)',
                }
            }
          >
            {isUser ? msg.text : (
              <>
                <ReactMarkdown
                  remarkPlugins={MD_REMARK_PLUGINS}
                  components={MD_COMPONENTS}
                >
                  {msg.text}
                </ReactMarkdown>
                {msg.isStreaming && msg.text && <AuroraCursor />}
              </>
            )}
            {isUser && msg.isStreaming && msg.text && <AuroraCursor />}
          </div>
        )}

        {/* Pending actions */}
        {!isUser && msg.pendingActions && msg.pendingActions.length > 0 && (
          <div className="mt-3 space-y-3">
            {msg.pendingActions.map((action) => (
              <ActionConfirmCard
                key={action.id}
                action={action}
                onConfirm={onConfirmAction}
                onDeny={onDenyAction}
              />
            ))}
          </div>
        )}

        {/* Rule proposals — useAiChatSession always parses propose_rule/
            propose_correlation_rule tool results into this field. This page
            has no builder to load one into directly, so RuleProposalCard
            renders its Rule Engine link instead of a "Load into builder"
            button (no onLoadRule/onLoadCorrelation passed) — same shared
            component the floating widget uses in its Rule Engine mode,
            rather than a second hand-maintained copy of the same JSON/
            validation-status rendering with a different accent color. */}
        {!isUser && msg.ruleProposals && msg.ruleProposals.length > 0 && (
          <div className="mt-3 space-y-3">
            {msg.ruleProposals.map((p) => (
              <RuleProposalCard key={p.id} proposal={p} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

// Session history panel

function SessionPanel({
  sessions,
  currentSessionId,
  onLoad,
  onDelete,
  onNewChat,
  onClose,
  onConfirmStateChange,
}: {
  sessions: SessionSummary[];
  currentSessionId: number | null;
  onLoad: (id: number) => void;
  onDelete: (id: number) => void;
  onNewChat: () => void;
  onClose: () => void;
  onConfirmStateChange: (active: boolean) => void;
}) {
  const confirm = useConfirm();

  const handleDelete = async (id: number) => {
    // Suppress the parent's outside-click-closes-history-panel listener while the
    // confirm dialog is open — otherwise the dialog (rendered outside historyPanelRef)
    // is treated as "outside" and the History panel closes on the very click meant
    // to confirm/cancel the deletion.
    onConfirmStateChange(true);
    try {
      const confirmed = await confirm({ title: 'Delete this conversation?', confirmLabel: 'Delete', variant: 'danger' });
      if (confirmed) onDelete(id);
    } finally {
      onConfirmStateChange(false);
    }
  };

  return (
    <div
      className="flex flex-col rounded-2xl overflow-hidden"
      style={{
        width: '280px',
        maxHeight: '420px',
        background: 'rgba(21,15,26,0.95)',
        border: `1px solid ${SURFACE_BORDER}`,
        backdropFilter: 'blur(20px)',
        boxShadow: '0 8px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(184,63,194,0.08)',
      }}
    >
      {/* Panel header */}
      <div
        className="flex items-center justify-between px-4 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}
      >
        <span className="text-xs font-semibold text-white/60 uppercase tracking-wider">Chat History</span>
        <button
          onClick={onClose}
          className="rounded-lg text-white/30 hover:text-white/70 transition-colors text-base leading-none"
        >
          ✕
        </button>
      </div>

      {/* New chat button */}
      <div className="px-3 pt-2.5 pb-2 flex-shrink-0">
        <button
          onClick={onNewChat}
          className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium text-white/80 hover:text-white transition-all hover:scale-[1.01]"
          style={{
            background: 'linear-gradient(135deg, rgba(184,63,194,0.2), rgba(198,154,74,0.15))',
            border: '1px solid rgba(184,63,194,0.3)',
          }}
        >
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Chat
        </button>
      </div>

      {/* Sessions list */}
      <div className="flex-1 overflow-y-auto px-3 pb-3 space-y-1">
        {sessions.length === 0 ? (
          <p className="text-center text-xs text-white/40 py-6">No previous chats</p>
        ) : (
          sessions.map((s) => (
            <div
              key={s.id}
              className={`group flex items-center gap-2 px-3 py-2.5 rounded-xl cursor-pointer transition-all ${
                s.id === currentSessionId
                  ? 'bg-white/12 border border-white/15'
                  : 'hover:bg-white/6 border border-transparent'
              }`}
              onClick={() => onLoad(s.id)}
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white/80 truncate leading-tight">{s.title}</p>
                <p className="text-xs text-white/30 mt-0.5">{timeAgo(s.updatedAt)}</p>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); handleDelete(s.id); }}
                className="flex-shrink-0 sm:opacity-0 sm:group-hover:opacity-100 group-focus-within:opacity-100 text-white/25 hover:text-rose-400 transition-all text-xs p-1 rounded"
                title="Delete"
                aria-label="Delete conversation"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Main component

export default function AIAssistant() {
  const {
    bubbles, input, setInput, loading,
    sessions, currentSessionId,
    loadSession, deleteSession, startNewChat,
    confirmAction, denyAction, sendMessage, handleStop,
  } = useAiChatSession();

  const [historyOpen,      setHistoryOpen]      = useState(false);
  const [settingsOpen,     setSettingsOpen]     = useState(false);
  const [providerConfigured, setProviderConfigured] = useState<boolean | null>(null);
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';
  const providerBlocked = providerConfigured === false;

  const refreshProviderStatus = useCallback(async () => {
    try {
      const res = await getAiProviderConfigStatus();
      setProviderConfigured(res.configured);
    } catch {
      // Fail open — don't block the assistant on a transient status-check error.
    }
  }, []);

  useEffect(() => {
    refreshProviderStatus();
  }, [refreshProviderStatus]);

  const bottomRef        = useRef<HTMLDivElement>(null);
  const textareaRef      = useRef<HTMLTextAreaElement>(null);
  const historyPanelRef  = useRef<HTMLDivElement>(null);
  const historyButtonRef = useRef<HTMLButtonElement>(null);
  // While true, the outside-click handler below is disarmed — used to stop a
  // confirm() dialog (rendered outside historyPanelRef) from being treated as an
  // "outside click" that closes the History panel mid-confirmation.
  const suppressHistoryCloseRef = useRef(false);

  const isFirstMessage = bubbles.length === 0;

  // FloatingChatWidget's "Open full assistant" link carries its current
  // session id as ?session=, so navigating here resumes that conversation
  // instead of dropping it — the widget unmounts on arrival here (Layout.tsx
  // hides it on /ai) and its in-memory bubbles/messages state goes with it;
  // without this, the user landed on a blank page mid-conversation with no
  // indication anything was cut off. Runs once per distinct session id,
  // not on every render (loadSession/searchParams aren't stable-identity).
  const [searchParams, setSearchParams] = useSearchParams();
  const resumedSessionParamRef = useRef<string | null>(null);
  useEffect(() => {
    const sessionParam = searchParams.get('session');
    if (!sessionParam || sessionParam === resumedSessionParamRef.current) return;
    const id = Number(sessionParam);
    if (!Number.isFinite(id)) return;
    resumedSessionParamRef.current = sessionParam;
    loadSession(id);
    // Drop it from the URL once consumed, so a refresh/back-nav doesn't
    // re-trigger it and it doesn't linger as a shareable-looking link.
    setSearchParams((prev) => { prev.delete('session'); return prev; }, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  // loadSession/startNewChat (from useAiChatSession) don't know about this
  // page's own historyOpen UI state — wrap them so the History panel still
  // closes exactly when it did before this logic moved into the shared hook.
  const handleLoadSession = useCallback(async (id: number) => {
    await loadSession(id);
    setHistoryOpen(false);
  }, [loadSession]);

  const handleNewChat = useCallback(() => {
    startNewChat();
    setHistoryOpen(false);
  }, [startNewChat]);

  // Close history panel on click outside
  useEffect(() => {
    if (!historyOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (suppressHistoryCloseRef.current) return;
      if (
        historyPanelRef.current?.contains(e.target as Node) ||
        historyButtonRef.current?.contains(e.target as Node)
      ) return;
      setHistoryOpen(false);
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [historyOpen]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [bubbles]);

  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  }, [input]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  // Was [...bubbles].reverse().find(...): a full copy plus a full reverse of the
  // transcript on every render, and this component re-renders once per streamed
  // token. A backwards scan finds the same element - the last 'assistant' entry -
  // without allocating anything, and typically stops on the first iteration
  // because the streaming bubble is the last one in the list.
  let latestAssistantId: string | undefined;
  for (let i = bubbles.length - 1; i >= 0; i--) {
    if (bubbles[i].role === 'assistant') { latestAssistantId = bubbles[i].id; break; }
  }

  return (
    <div
      className="flex h-full flex-col relative overflow-hidden"
      style={{ background: '#0a0610', fontWeight: 500 }}
    >
      {/* Ambient WebGL background — dim, muted brand tones, never competing
          with the foreground text (see components/effects/WebThreads). */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <WebThreads
          color1={MAGENTA}
          color2="#8A6423"
          color3="#E8D8E4"
          speed={0.09}
          threadCount={5}
          frequency={3.2}
          spread={0.11}
          taper={1.0}
          position={0.46}
          fanMode="center"
          glow={0.016}
          falloff={0.62}
          thickness={1.15}
          brightness={0.3}
          opacity={0.5}
          mirror
          shimmer={false}
          grain
          grainIntensity={0.025}
          mouseInteraction
          mouseStrength={0.15}
          lightMode={false}
        />
        {/* Darkest right where the header/composer text sits, lighter through the
            hero so the threads still show behind the logo — same reasoning as the
            old aurora's frame: the weakest gradient stop must not land behind text. */}
        <div
          className="absolute inset-0"
          style={{
            background: 'linear-gradient(to bottom, rgba(10,6,16,0.95) 0%, rgba(10,6,16,0.55) 22%, rgba(10,6,16,0.4) 55%, rgba(10,6,16,0.65) 78%, rgba(10,6,16,0.97) 100%)',
          }}
        />
      </div>

      {/* Header */}
      <div className="relative z-10 flex items-center gap-4 px-8 py-5 flex-shrink-0">
        {/* History toggle button */}
        <div className="ml-auto flex items-center gap-3">
          {bubbles.length > 0 && (
            <button
              onClick={handleNewChat}
              className="text-xs text-white/30 hover:text-white/60 transition-colors px-3 py-1.5 rounded-lg hover:bg-white/5 flex items-center gap-1.5"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New Chat
            </button>
          )}
          <button
            ref={historyButtonRef}
            onClick={() => setHistoryOpen((p) => !p)}
            className="flex items-center gap-2 text-xs font-semibold text-white/50 hover:text-white/80 transition-colors px-3 py-1.5 rounded-lg hover:bg-white/5"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            History
            {sessions.length > 0 && (
              <span
                className="text-xs px-1.5 py-0.5 rounded-full font-bold"
                style={{ color: GOLD }}
              >
                {sessions.length}
              </span>
            )}
          </button>
          {isSuperAdmin && (
            <button
              onClick={() => setSettingsOpen(true)}
              title="AI Assistant Settings"
              aria-label="AI Assistant Settings"
              className="flex items-center gap-2 text-xs font-semibold text-white/50 hover:text-white/80 transition-colors p-1.5 rounded-lg hover:bg-white/5"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>
          )}
        </div>
      </div>

      {settingsOpen && (
        <AiProviderSettings
          onClose={() => {
            setSettingsOpen(false);
            refreshProviderStatus();
          }}
        />
      )}

      {/* Not-configured banner — makes it obvious *why* the assistant won't respond,
          instead of letting the user find out only after sending a message. Kept
          semantic amber — a warning color, not a brand accent. */}
      {providerBlocked && (
        <div
          className="relative z-10 flex-shrink-0 px-4 py-2.5 md:px-8 flex items-center gap-3 text-xs"
          style={{ background: 'rgba(245,158,11,0.1)', borderBottom: '1px solid rgba(245,158,11,0.25)', color: 'rgba(253,230,138,0.95)' }}
        >
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m0 3.75h.008M10.29 3.86L1.82 18a1.5 1.5 0 001.29 2.25h17.78a1.5 1.5 0 001.29-2.25L13.71 3.86a1.5 1.5 0 00-2.42 0z" />
          </svg>
          <span className="flex-1">
            {isSuperAdmin
              ? 'AI Assistant has no provider configured yet — it cannot respond until you set one up.'
              : 'AI Assistant has no provider configured yet — ask a Super Administrator to set one up.'}
          </span>
          {isSuperAdmin && (
            <button
              onClick={() => setSettingsOpen(true)}
              className="flex-shrink-0 font-semibold px-3 py-1 rounded-lg transition-colors hover:bg-amber-400/10"
              style={{ border: '1px solid rgba(245,158,11,0.4)' }}
            >
              Configure now
            </button>
          )}
        </div>
      )}

      {/* Messages area */}
      <div
        className="relative z-10 flex-1 overflow-y-auto px-4 py-6 md:px-8 scroll-smooth"
        role="log"
        aria-live="polite"
        aria-atomic="false"
        // Suppress announcements while a reply is streaming in (many rapid
        // text_delta updates per response) — most screen readers withhold
        // live-region announcements while aria-busy="true" and read the
        // finished message once it flips back to false, instead of reading
        // every partial chunk as it grows.
        aria-busy={loading}
      >
        {isFirstMessage ? (
          <div className="mx-auto max-w-3xl">
            <div className="flex flex-col items-center justify-center min-h-[60vh] text-center gap-2">
              {/* Brand mark */}
              <div className="relative mb-5" style={{ width: 'min(48vw, 200px)' }}>
                <div
                  className="absolute pointer-events-none"
                  style={{
                    inset: '-30%',
                    background: 'radial-gradient(ellipse 55% 55% at 50% 50%, rgba(184,63,194,0.22) 0%, transparent 70%)',
                    filter: 'blur(20px)',
                  }}
                />
                <img src={vajraLogo} alt="Vajra" className="relative block w-full h-auto" />
              </div>
              <p className="text-xs font-bold uppercase" style={{ letterSpacing: '.36em', color: GOLD }}>
                AI Assistant
              </p>

              <p className="text-[15px] max-w-[480px] leading-relaxed mt-3" style={{ color: 'rgba(230,220,232,0.58)' }}>
                Your intelligent security companion. Ask anything about your organization's
                security posture, nodes, alerts, compliance, and more.
              </p>

              {/* Suggestion chips — plain outlined pills, no icon tiles */}
              <div className="flex flex-col items-center gap-3.5 mt-8">
                <span className="text-[11px] font-bold uppercase" style={{ letterSpacing: '.22em', color: 'rgba(230,220,232,0.34)' }}>
                  Try asking
                </span>
                <div className="flex flex-wrap items-stretch justify-center gap-2.5 max-w-[720px]">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s.text}
                      onClick={() => sendMessage(s.text)}
                      disabled={providerBlocked}
                      className="rounded-[10px] px-[18px] py-2.5 text-[13px] font-medium transition-all duration-150 hover:-translate-y-0.5 disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:translate-y-0"
                      style={{
                        border: `1px solid ${SURFACE_BORDER}`,
                        background: SURFACE,
                        color: 'rgba(230,220,232,0.85)',
                        boxShadow: '0 10px 28px -12px rgba(0,0,0,0.6), 0 2px 6px -2px rgba(0,0,0,0.5)',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = SURFACE_2;
                        e.currentTarget.style.borderColor = 'rgba(198,154,74,0.4)';
                        e.currentTarget.style.color = '#fff';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = SURFACE;
                        e.currentTarget.style.borderColor = SURFACE_BORDER;
                        e.currentTarget.style.color = 'rgba(230,220,232,0.85)';
                      }}
                    >
                      {s.text}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Narrow reading column once a conversation has started */
          <div className="mx-auto max-w-3xl">
            {bubbles.map((msg) => (
              <MessageBubble
                key={msg.id}
                msg={msg}
                isLatestAssistant={msg.id === latestAssistantId}
                onConfirmAction={confirmAction}
                onDenyAction={denyAction}
              />
            ))}

            <div ref={bottomRef} className="h-4" />
          </div>
        )}
      </div>

      {/* History panel — floating bottom-right above input bar */}
      {historyOpen && (
        <div
          ref={historyPanelRef}
          className="fixed z-50 bottom-24 right-6"
          style={{ boxShadow: '0 0 40px rgba(184,63,194,0.25)' }}
        >
          <SessionPanel
            sessions={sessions}
            currentSessionId={currentSessionId}
            onLoad={handleLoadSession}
            onDelete={deleteSession}
            onNewChat={handleNewChat}
            onClose={() => setHistoryOpen(false)}
            onConfirmStateChange={(active) => { suppressHistoryCloseRef.current = active; }}
          />
        </div>
      )}

      {/* Input bar — classic surface with real elevation shadow, gold send
          button, no icon tile (per the approved redesign, not a generic
          "AI sparkle" chatbot bar). */}
      <div className="relative z-10 px-4 py-4 md:px-8 flex-shrink-0">
        <div className="mx-auto max-w-3xl">
          <div
            className="flex items-center gap-3 rounded-2xl pl-5 pr-2 py-2 min-h-[64px] transition-all duration-200"
            style={{
              background: SURFACE,
              border: `1px solid ${loading ? 'rgba(184,63,194,0.5)' : SURFACE_BORDER}`,
              boxShadow: loading
                ? '0 18px 44px -16px rgba(0,0,0,0.65), 0 4px 12px -4px rgba(0,0,0,0.5), 0 0 0 3px rgba(198,154,74,0.16)'
                : '0 18px 44px -16px rgba(0,0,0,0.65), 0 4px 12px -4px rgba(0,0,0,0.5)',
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = 'rgba(198,154,74,0.5)';
              e.currentTarget.style.boxShadow = '0 18px 44px -16px rgba(0,0,0,0.65), 0 4px 12px -4px rgba(0,0,0,0.5), 0 0 0 3px rgba(198,154,74,0.16)';
            }}
            onBlur={(e) => {
              if (loading) return;
              e.currentTarget.style.borderColor = SURFACE_BORDER;
              e.currentTarget.style.boxShadow = '0 18px 44px -16px rgba(0,0,0,0.65), 0 4px 12px -4px rgba(0,0,0,0.5)';
            }}
          >
            <div className="flex-1 min-w-0 flex flex-col justify-center gap-0.5">
              <textarea
                ref={textareaRef}
                className="w-full bg-transparent text-[14px] md:text-[15px] text-white/90 placeholder-white/40 outline-none resize-none leading-snug disabled:cursor-not-allowed"
                placeholder={providerBlocked ? 'AI Assistant is not configured yet…' : 'Ask about nodes, alerts, compliance, actions…'}
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={loading || providerBlocked}
                style={{ maxHeight: '160px' }}
              />
              <span className="text-[11px] text-white/30 leading-none select-none">
                Use natural language or / for quick commands
              </span>
            </div>

            <span
              className="hidden sm:inline-flex flex-shrink-0 items-center gap-1 rounded-full px-2.5 py-1 text-[11px] leading-none"
              style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${SURFACE_BORDER}` }}
            >
              <span className="text-white/60 font-medium">Shift + Enter</span>
              <span className="text-white/30">to new line</span>
            </span>

            <button
              type="button"
              onClick={() => (loading ? handleStop() : sendMessage())}
              disabled={!loading && (!input.trim() || providerBlocked)}
              aria-label={loading ? 'Stop generating' : 'Send message'}
              className="flex-shrink-0 flex items-center justify-center rounded-xl px-5 py-2.5 text-[13px] font-bold transition-all duration-200 hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                color: '#1c1206',
                background: 'linear-gradient(135deg, #e0b968, #a9762b)',
                boxShadow: '0 6px 16px -6px rgba(169,118,43,0.55)',
              }}
            >
              {loading ? <span className="h-3 w-3 rounded-sm bg-[#1c1206]" /> : 'Send'}
            </button>
          </div>
          <p className="mt-2 text-center text-[11px] text-white/25 select-none">
            AI can make mistakes — verify before confirming any agent action
          </p>
        </div>
      </div>
    </div>
  );
}
