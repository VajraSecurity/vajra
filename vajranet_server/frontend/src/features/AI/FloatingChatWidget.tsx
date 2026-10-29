import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Sparkles, Send as SendIcon, Minus, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAiChatSession } from './useAiChatSession';
import type { BubbleMessage } from './useAiChatSession';
import { useFloatingChatRuleHandlers } from './FloatingChatContext';
import type { RuleChatHandlers } from './FloatingChatContext';
import { ActionConfirmCard, ToolCallBadge, SUGGESTIONS, isSafeMarkdownHref } from './shared';
import RuleProposalCard from './RuleProposalCard';
import ThinkingOrb from './ThinkingOrb';

const LAUNCHER_SIZE = 60;
const PANEL_SIZE = { w: 392, h: 576 };
const EDGE_GAP = 16;
// MobileNavbar (components/layout/MobileNavbar.tsx) is a fixed h-16 bar
// below this breakpoint — reserve room so the launcher floats above it
// instead of overlapping it, matching e.g. Intercom/Crisp's mobile bubble.
const MOBILE_BREAKPOINT = 640;
const MOBILE_NAV_RESERVE = 76;

type Point = { x: number; y: number };

function clampToViewport(p: Point, size: { w: number; h: number }): Point {
  const bottomReserve = window.innerWidth < MOBILE_BREAKPOINT ? MOBILE_NAV_RESERVE : 0;
  const maxX = Math.max(EDGE_GAP, window.innerWidth - size.w - EDGE_GAP);
  const maxY = Math.max(EDGE_GAP, window.innerHeight - size.h - EDGE_GAP - bottomReserve);
  return { x: Math.min(Math.max(p.x, EDGE_GAP), maxX), y: Math.min(Math.max(p.y, EDGE_GAP), maxY) };
}

function readStoredPoint(key: string): Point | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (typeof parsed?.x === 'number' && typeof parsed?.y === 'number') return parsed;
  } catch { /* private-mode/blocked storage — fall back to default */ }
  return null;
}

function writeStoredPoint(key: string, p: Point) {
  try { localStorage.setItem(key, JSON.stringify(p)); } catch { /* non-fatal */ }
}

/**
 * Pointer-driven free drag for one element, persisted to localStorage and
 * re-clamped into the viewport on window resize. Distinguishes a drag from a
 * plain click via a small movement threshold — `wasDragged()` reports
 * whether the pointer actually moved past it, so a click handler on the same
 * element can ignore the click that follows a drag's pointerup.
 */
function useDraggablePosition(storageKey: string, size: { w: number; h: number }, defaultPos: () => Point) {
  const [pos, setPos] = useState<Point>(() => clampToViewport(readStoredPoint(storageKey) ?? defaultPos(), size));
  const [isDragging, setIsDragging] = useState(false);
  const posRef = useRef(pos);
  posRef.current = pos;
  const draggedRef = useRef(false);
  const startRef = useRef({ px: 0, py: 0, ox: 0, oy: 0 });
  // Which pointer (finger/mouse) currently owns the drag — without this, a
  // second finger touching down mid-drag on a touchscreen would reset
  // startRef and fight the first finger's own in-flight move handler,
  // corrupting the position (and persisting the corrupted value).
  const activePointerIdRef = useRef<number | null>(null);
  // Set while a drag's window listeners are attached, so the unmount effect
  // below can tear them down if the component unmounts mid-drag (e.g. a
  // route change) instead of leaking them on `window` forever.
  const cleanupDragRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const onResize = () => setPos((p) => clampToViewport(p, size));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [size.w, size.h]);

  useEffect(() => () => cleanupDragRef.current?.(), []);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if (e.button !== 0 && e.pointerType === 'mouse') return;
    if (activePointerIdRef.current !== null) return; // a drag from a different pointer is already in progress
    activePointerIdRef.current = e.pointerId;
    draggedRef.current = false;
    startRef.current = { px: e.clientX, py: e.clientY, ox: posRef.current.x, oy: posRef.current.y };

    const onMove = (ev: PointerEvent) => {
      if (ev.pointerId !== activePointerIdRef.current) return;
      const dx = ev.clientX - startRef.current.px;
      const dy = ev.clientY - startRef.current.py;
      if (!draggedRef.current && Math.hypot(dx, dy) > 5) { draggedRef.current = true; setIsDragging(true); }
      if (draggedRef.current) {
        setPos(clampToViewport({ x: startRef.current.ox + dx, y: startRef.current.oy + dy }, size));
      }
    };
    const onUp = (ev: PointerEvent) => {
      if (ev.pointerId !== activePointerIdRef.current) return;
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      cleanupDragRef.current = null;
      activePointerIdRef.current = null;
      if (draggedRef.current) writeStoredPoint(storageKey, posRef.current);
      setIsDragging(false);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    cleanupDragRef.current = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storageKey, size.w, size.h]);

  return { pos, onPointerDown, wasDragged: () => draggedRef.current, isDragging };
}

function useIsNarrowViewport(breakpointPx = MOBILE_BREAKPOINT) {
  const [narrow, setNarrow] = useState(() => window.innerWidth < breakpointPx);
  useEffect(() => {
    const onResize = () => setNarrow(window.innerWidth < breakpointPx);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [breakpointPx]);
  return narrow;
}

const MD_COMPONENTS: Components = {
  p:      ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
  strong: ({ children }) => <strong className="font-semibold text-slate-900 dark:text-white">{children}</strong>,
  em:     ({ children }) => <em className="italic">{children}</em>,
  ul:     ({ children }) => <ul className="list-disc list-inside space-y-0.5 mb-2 pl-1">{children}</ul>,
  ol:     ({ children }) => <ol className="list-decimal list-inside space-y-0.5 mb-2 pl-1">{children}</ol>,
  code:   ({ children, className }) => {
    const isBlock = className?.includes('language-');
    return isBlock
      ? <code className="block bg-slate-100 dark:bg-black/30 rounded-lg px-3 py-2 text-xs font-mono overflow-x-auto mb-2">{children}</code>
      : <code className="bg-slate-100 dark:bg-black/30 rounded px-1.5 py-0.5 text-xs font-mono">{children}</code>;
  },
  a:  ({ href, children }) => isSafeMarkdownHref(href)
    ? <a href={href} target="_blank" rel="noopener noreferrer" className="text-indigo-600 dark:text-indigo-400 underline">{children}</a>
    : <span className="underline decoration-dotted" title="Link removed — not a safe http(s) address">{children}</span>,
};
const MD_REMARK_PLUGINS = [remarkGfm];

// memo() is what stops the entire transcript re-rendering on every streamed
// token — useAiChatSession's sendMessage calls setBubbles once per SSE
// text_delta, which without this re-executed every bubble's markdown parse
// and JSX, not just the one actively streaming. Mirrors the identical
// pattern (and identical reasoning) already used for `MessageBubble` in
// features/AI/index.tsx. `ruleHandlers` is reference-stable across a
// streaming response (it only changes identity when Rule Engine mounts/
// unmounts, via FloatingChatContext's own useMemo), and confirmAction/
// denyAction are useCallback-stable, so every prop is reference-equal for
// untouched bubbles and memo short-circuits them.
const ChatBubble = memo(function ChatBubble({
  bubble: b, isLatestAssistant, onConfirmAction, onDenyAction, ruleHandlers,
}: {
  bubble: BubbleMessage;
  isLatestAssistant: boolean;
  onConfirmAction: (id: string) => Promise<boolean>;
  onDenyAction: (id: string) => Promise<boolean>;
  ruleHandlers: RuleChatHandlers | null;
}) {
  const liveToolIdx = (b.toolEvents?.length ?? 0) - 1;
  return (
    <div className={`flex ${b.role === 'user' ? 'justify-end' : 'justify-start'}`}>
      <div className={`min-w-0 max-w-[92%] ${b.role === 'user' ? '' : 'w-full'}`}>
        {b.role === 'assistant' && b.toolEvents && b.toolEvents.length > 0 && (
          <div className="mb-2 space-y-1.5">
            {b.toolEvents.map((ev, idx) => (
              <ToolCallBadge key={idx} event={ev} isLive={isLatestAssistant && b.isStreaming && idx === liveToolIdx && ev.result === undefined} />
            ))}
          </div>
        )}

        {b.role === 'assistant' && b.isStreaming && !b.text && (!b.toolEvents || b.toolEvents.length === 0) && (
          <div className="flex items-center gap-2.5 py-1">
            <ThinkingOrb size={22} />
            <span className="text-[12.5px] font-medium text-slate-400 dark:text-slate-500 italic">Thinking…</span>
          </div>
        )}

        {(b.text || (b.role === 'assistant' && !b.isStreaming)) && (
          <div
            className={`rounded-2xl px-3.5 py-2.5 text-[13px] leading-relaxed break-words font-normal ${
              b.role === 'user'
                ? 'text-white rounded-tr-md whitespace-pre-wrap'
                : 'text-slate-700 dark:text-slate-200 rounded-tl-md border border-slate-200 dark:border-white/10'
            }`}
            style={b.role === 'user'
              ? { background: 'linear-gradient(135deg, #7c3aed, #4f46e5)', boxShadow: '0 4px 14px -4px rgba(76,29,149,0.4)' }
              : { background: 'rgba(129,140,248,0.06)' }}
          >
            {b.role === 'user' ? b.text : (
              <ReactMarkdown remarkPlugins={MD_REMARK_PLUGINS} components={MD_COMPONENTS}>{b.text}</ReactMarkdown>
            )}
          </div>
        )}

        {b.role === 'assistant' && b.pendingActions && b.pendingActions.length > 0 && (
          <div className="mt-2 space-y-2">
            {b.pendingActions.map((action) => (
              <ActionConfirmCard key={action.id} action={action} onConfirm={onConfirmAction} onDeny={onDenyAction} />
            ))}
          </div>
        )}

        {/* Renders regardless of ruleHandlers — a proposal that arrived
            while Rule Engine was mounted must stay visible (with a link
            instead of a button) if the user navigates elsewhere before
            acting on it; the card previously vanished entirely in that
            case, not just its button. */}
        {b.role === 'assistant' && b.ruleProposals && b.ruleProposals.length > 0 && (
          <div className="mt-2 space-y-2">
            {b.ruleProposals.map((p) => (
              <RuleProposalCard key={p.id} proposal={p} onLoadRule={ruleHandlers?.onLoadRule} onLoadCorrelation={ruleHandlers?.onLoadCorrelation} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

/**
 * The single floating AI assistant, mounted once in `DashboardLayout` (see
 * that file) so it hovers over every authenticated page except `/ai` itself
 * (which is the same assistant full-page, so a second floating copy there
 * would be redundant). Both the closed launcher and the open panel are
 * freely draggable and remember where they were left, independently of each
 * other, via `useDraggablePosition`.
 *
 * When a Rule Engine page is mounted, it registers `onLoadRule`/
 * `onLoadCorrelation` through `FloatingChatContext` — while that
 * registration is active, `propose_rule`/`propose_correlation_rule` tool
 * results render as `RuleProposalCard`s here. Everywhere else those two
 * tools simply never fire, so nothing rule-specific shows.
 */
export default function FloatingChatWidget() {
  const [open, setOpen] = useState(false);
  const { bubbles, input, setInput, loading, sendMessage, handleStop, confirmAction, denyAction, currentSessionId } = useAiChatSession({ fetchSessions: false });
  const ruleHandlers = useFloatingChatRuleHandlers();
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const narrow = useIsNarrowViewport();

  const launcherDefault = useCallback((): Point => ({
    x: window.innerWidth - LAUNCHER_SIZE - 24,
    y: window.innerHeight - LAUNCHER_SIZE - 24,
  }), []);
  const panelDefault = useCallback((): Point => ({
    x: window.innerWidth - PANEL_SIZE.w - 24,
    y: window.innerHeight - PANEL_SIZE.h - 96,
  }), []);

  const launcherSize = useMemo(() => ({ w: LAUNCHER_SIZE, h: LAUNCHER_SIZE }), []);
  const launcherDrag = useDraggablePosition('vj-floating-chat:launcher-pos', launcherSize, launcherDefault);
  const panelDrag = useDraggablePosition('vj-floating-chat:panel-pos', PANEL_SIZE, panelDefault);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [bubbles, open]);

  // Auto-grow the textarea up to a capped height, then let it scroll
  // internally — this is what keeps a long pasted message from ever
  // widening/overflowing the panel itself.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
  }, [input]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  const closeLauncherClick = () => {
    if (launcherDrag.wasDragged()) return;
    setOpen(true);
  };

  const launcher = (
    <button
      onPointerDown={launcherDrag.onPointerDown}
      onClick={closeLauncherClick}
      aria-label="Open Vajra Assistant"
      className="fixed z-[60] flex items-center justify-center rounded-full text-white transition-transform duration-150 hover:scale-105 active:scale-95 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400"
      style={{
        left: launcherDrag.pos.x,
        top: launcherDrag.pos.y,
        width: LAUNCHER_SIZE,
        height: LAUNCHER_SIZE,
        touchAction: 'none',
        cursor: launcherDrag.isDragging ? 'grabbing' : 'grab',
        userSelect: 'none',
        background: 'radial-gradient(circle at 32% 28%, rgba(255,255,255,0.16), transparent 55%), linear-gradient(135deg, #6d28d9, #4338ca)',
        boxShadow: '0 10px 30px -6px rgba(76,29,149,0.55), 0 0 0 1px rgba(255,255,255,0.08) inset',
      }}
    >
      <span className="absolute inset-0 rounded-full orb-glow" style={{ background: 'radial-gradient(circle, rgba(192,132,252,0.45), transparent 70%)' }} />
      {loading ? <ThinkingOrb size={30} /> : <Sparkles className="h-6 w-6 relative" strokeWidth={2.25} />}
    </button>
  );

  if (!open) return createPortal(launcher, document.body);

  const panelStyle: React.CSSProperties = narrow
    ? { left: 0, right: 0, bottom: 0, width: '100%', height: '82vh', borderRadius: '20px 20px 0 0' }
    : {
        left: panelDrag.pos.x,
        top: panelDrag.pos.y,
        width: PANEL_SIZE.w,
        height: PANEL_SIZE.h,
        maxWidth: 'calc(100vw - 1.5rem)',
        maxHeight: 'calc(100vh - 1.5rem)',
        borderRadius: 20,
      };

  const panel = (
    <div
      role="complementary"
      aria-label="Vajra Assistant"
      className="fixed z-[60] flex flex-col overflow-hidden border border-slate-200 dark:border-white/10 bg-white dark:bg-[#0e0e1a] shadow-2xl"
      style={{ ...panelStyle, fontFamily: '"Inter Variable", Inter, sans-serif', boxShadow: '0 24px 70px -20px rgba(30,20,60,0.45)' }}
    >
      {/* Header — the drag handle when not on a mobile sheet */}
      <div
        onPointerDown={narrow ? undefined : panelDrag.onPointerDown}
        className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-200 dark:border-white/10 shrink-0"
        style={{
          cursor: narrow ? 'default' : (panelDrag.isDragging ? 'grabbing' : 'grab'),
          touchAction: 'none',
          userSelect: narrow ? 'auto' : 'none',
          background: 'linear-gradient(135deg, rgba(109,40,217,0.10), rgba(67,56,202,0.10))',
        }}
      >
        <ThinkingOrb size={26} />
        <div className="min-w-0 flex-1">
          <div className="text-[13.5px] font-semibold text-slate-800 dark:text-slate-100 leading-tight">Vajra Assistant</div>
          <div className="text-[11px] text-slate-400 dark:text-slate-500 leading-tight truncate">
            {ruleHandlers ? 'Rule authoring mode' : 'Ask about your fleet, alerts, compliance'}
          </div>
        </div>
        <Link
          // Carries the in-progress session id (once one exists — created
          // server-side on the first sent message) so navigating there
          // resumes this conversation instead of leaving it behind: the
          // widget unmounts on arrival at /ai (Layout.tsx hides it there),
          // taking its in-memory bubbles/messages with it. AIAssistant reads
          // and consumes this param on mount.
          to={currentSessionId ? `/ai?session=${currentSessionId}` : '/ai'}
          aria-label="Open full assistant"
          title="Open full assistant"
          className="shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10"
          onPointerDown={(e) => e.stopPropagation()}
        >
          <ExternalLink className="h-3.5 w-3.5" />
        </Link>
        <button
          onClick={() => setOpen(false)}
          onPointerDown={(e) => e.stopPropagation()}
          aria-label="Minimize"
          title="Minimize"
          className="shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10"
        >
          <Minus className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Message list — the only internally-scrolling region, so a long
          transcript or a long single message never grows the panel itself. */}
      <div className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden px-3.5 py-3.5 space-y-3.5">
        {bubbles.length === 0 && (
          <div className="pt-2 pb-4">
            <p className="text-[12.5px] font-medium text-slate-400 dark:text-slate-500 text-center px-2 mb-3">
              {ruleHandlers
                ? "Ask for help writing a detection or correlation rule — I'll propose one for you to review, you always save it yourself."
                : "Your intelligent security companion. Ask about nodes, alerts, or compliance."}
            </p>
            {!ruleHandlers && (
              <div className="flex flex-col gap-1.5">
                {SUGGESTIONS.slice(0, 3).map((s) => (
                  <button
                    key={s.text}
                    onClick={() => sendMessage(s.text)}
                    className="flex items-center gap-2.5 rounded-xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-white/[0.03] px-3 py-2 text-left hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors"
                  >
                    <s.icon className="h-3.5 w-3.5 shrink-0" style={{ color: s.accent }} />
                    <span className="text-[12px] font-medium text-slate-600 dark:text-slate-300 truncate">{s.title}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        {bubbles.map((b, i) => (
          <ChatBubble
            key={b.id}
            bubble={b}
            isLatestAssistant={b.role === 'assistant' && i === bubbles.length - 1}
            onConfirmAction={confirmAction}
            onDenyAction={denyAction}
            ruleHandlers={ruleHandlers}
          />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input — auto-growing up to a cap, then it scrolls internally rather
          than pushing the panel taller than the viewport allows. */}
      <div className="p-3 border-t border-slate-200 dark:border-white/10 shrink-0" style={{ paddingBottom: 'max(0.75rem, env(safe-area-inset-bottom, 0px))' }}>
        <div className="flex items-end gap-2 rounded-2xl border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-white/[0.04] px-3 py-2 focus-within:border-indigo-300 dark:focus-within:border-indigo-500/40 transition-colors">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Message Vajra Assistant…"
            rows={1}
            disabled={loading}
            className="flex-1 resize-none bg-transparent text-[13px] font-medium text-slate-700 dark:text-slate-200 placeholder:text-slate-400 placeholder:font-normal outline-none max-h-[120px] overflow-y-auto py-1"
          />
          <button
            onClick={() => (loading ? handleStop() : sendMessage())}
            disabled={!loading && !input.trim()}
            aria-label={loading ? 'Stop' : 'Send'}
            className="shrink-0 flex h-8 w-8 items-center justify-center rounded-xl text-white disabled:opacity-30 transition-all hover:scale-105 active:scale-95"
            style={{ background: 'linear-gradient(135deg, #7c3aed, #4f46e5)' }}
          >
            {loading ? <span className="h-2.5 w-2.5 rounded-sm bg-white" /> : <SendIcon className="h-3.5 w-3.5" strokeWidth={2.25} />}
          </button>
        </div>
      </div>
    </div>
  );

  return createPortal(panel, document.body);
}
