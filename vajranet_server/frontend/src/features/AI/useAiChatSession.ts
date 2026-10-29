import { useCallback, useEffect, useRef, useState } from 'react';
import { isAxiosError } from 'axios';
import api from '../../api/axiosInstance';
import { AI_URLS } from '../../api/urls';
import { csrfHeadersJson, fetchWithCsrf } from '../../api/csrfClient';
import { useToast } from '../../context/useToast';

/**
 * Shared `/api/ai` chat session + SSE-streaming transport, extracted out of
 * `features/AI/index.tsx` so `features/AI/FloatingChatWidget.tsx` (the
 * single app-wide floating assistant, mounted in `DashboardLayout` — see
 * that file) can reuse the exact same session/streaming logic instead of
 * forking a second copy — per docs/RULE_ENGINE_UI_SPEC.md's original
 * instruction to do this for the Rule Engine's own floating chat, which the
 * widget has since superseded (see `FloatingChatContext`).
 *
 * Behavior is intentionally IDENTICAL to what `features/AI/index.tsx` had
 * inline before this extraction — same SSE parsing, same pending-action
 * handling, same session persistence — nothing here changes what the
 * existing AI Assistant page does. `features/AI/index.tsx` now calls this
 * hook instead of holding the logic itself; its JSX/rendering is untouched.
 *
 * Generalization beyond the original: the original only special-cased the
 * `propose_agent_action` tool result into `pendingActions`. This hook adds
 * the same treatment for `propose_rule` / `propose_correlation_rule` (new
 * MCP tools, per Vajranet-BE's parallel work) into `ruleProposals`, so the
 * Rule Engine's floating chat can render "Load into builder" / "Discard"
 * cards without re-parsing the SSE stream itself. The AI Assistant page
 * simply never sees those tool names in practice and ignores the field.
 */

export type Role = 'user' | 'assistant';

export interface ChatMessage {
  role: Role;
  content: string;
}

export interface PendingAction {
  id: string;
  action_type: string;
  host_identifier: string;
  hostname?: string;
  description: string;
  risk: 'low' | 'medium' | 'high';
  expires_at: number;
}

/**
 * A `propose_rule` / `propose_correlation_rule` tool result, parsed into a
 * chat-card-ready shape. Real, confirmed shape per Vajranet-BE's
 * live-verified report (docs/team/vajranet-be.md, "propose_rule/
 * propose_correlation_rule — validated-but-not-saved" section):
 *   success: {proposal_id, status: "pending_proposal", valid: true,
 *             engine_message, rule: {...}, message}
 *   failure: {valid: false, message, engine_status}  (tool_result is_error: true)
 * `parseRuleProposal` below still falls back defensively (a `correlation_rule`
 * key, an older nested `validation.ok` shape) in case the exact key name
 * differs for `propose_correlation_rule`'s own payload — BE's report did not
 * show that tool's full success JSON, only its `engine_message`.
 *
 * Confirmed by the same report: there is deliberately NO server-side
 * pending-action store or confirm/dispatch route for these two tools (unlike
 * `propose_agent_action`) — saving already goes through the real Rule
 * Builder create route's own requireAdmin+CSRF+engine-validate gate, so
 * "Load into builder" is a pure client-side, non-authoritative action. This
 * matches this file's card design: no "save directly" button exists here at all.
 */
export interface RuleProposal {
  id: string;
  kind: 'rule' | 'correlation_rule';
  /** The full proposed rule/correlation JSON, exactly as returned by the tool. */
  rule: Record<string, unknown>;
  validation?: { ok: boolean; message?: string };
}

export interface ToolEvent {
  tool_name: string;
  tool_input?: Record<string, unknown>;
  result?: string;
  is_error?: boolean;
}

export interface BubbleMessage {
  id: string;
  role: Role;
  text: string;
  isStreaming?: boolean;
  toolEvents?: ToolEvent[];
  pendingActions?: PendingAction[];
  ruleProposals?: RuleProposal[];
}

export interface SessionSummary {
  id: number;
  title: string;
  createdAt: string;
  updatedAt: string;
}

type ChatStreamEvent =
  | { type: 'text_delta'; text: string }
  | { type: 'tool_call'; tool_name: string; tool_input?: Record<string, unknown> }
  | { type: 'tool_result'; tool_name: string; result: string; is_error?: boolean }
  | { type: 'done' }
  | { type: 'error'; message?: string };

function genId() {
  return Math.random().toString(36).slice(2);
}

function getActionErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ error?: string }>(err)) {
    return err.response?.data?.error || fallback;
  }
  return fallback;
}

/**
 * A non-ok/non-streaming chat response body is this backend's own CustomError
 * envelope (`{status, message, errorType, errors, errorRaw, errorsValidation,
 * stack}` — see backend/src/utils/response/custom-error/CustomError.ts), not
 * plain text. Surfacing the raw body as-is (as `resp.text()` returns it) would
 * dump internal file paths and a full stack trace straight into the chat
 * transcript — extract just `.message` instead, same as getActionErrorMessage
 * does for axios error responses above.
 */
function extractChatErrorMessage(bodyText: string, fallback: string): string {
  try {
    const parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed.message === 'string' && parsed.message.trim()) return parsed.message;
  } catch { /* not JSON — fall through to the generic fallback below */ }
  return fallback;
}

function isAbortError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'name' in err && (err as { name?: string }).name === 'AbortError';
}

function makeTitleFromMessage(text: string): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > 52 ? clean.slice(0, 52) + '…' : clean;
}

async function saveSession(
  sessionId: number, messages: ChatMessage[], bubbles: BubbleMessage[], onSaveFailed: () => void, title?: string,
) {
  try {
    await api.put(AI_URLS.SESSION(sessionId), {
      messages,
      bubbles: bubbles.map((b) => ({ ...b, isStreaming: false, pendingActions: [], ruleProposals: [] })),
      ...(title !== undefined ? { title } : {}),
    });
  } catch {
    // Non-fatal to the live conversation (it stays fully usable in memory
    // for the rest of this session), but silently swallowing this meant a
    // persistently-failing save gave zero signal — the transcript could be
    // gone on the next reload with no indication anything had gone wrong.
    onSaveFailed();
  }
}

/**
 * Parses a propose_rule/propose_correlation_rule tool result into a
 * RuleProposal — called for BOTH a validated proposal (is_error: false,
 * `valid: true`) and a rejected one (is_error: true, `valid: false`), so a
 * rejection still renders as a card showing the real engine's exact reason
 * instead of silently vanishing (only the assistant's own prose would
 * otherwise explain it). On rejection there is no `rule` key in BE's
 * confirmed shape, so `rule` falls back to an empty object — the card still
 * has `validation.message` to show.
 */
function parseRuleProposal(toolName: string, resultJson: string): RuleProposal | null {
  try {
    const parsed = JSON.parse(resultJson);
    if (!parsed || typeof parsed !== 'object') return null;
    const kind: RuleProposal['kind'] = toolName === 'propose_correlation_rule' ? 'correlation_rule' : 'rule';
    // Defensive key lookup — see the RuleProposal doc comment above.
    const rule = parsed.rule ?? parsed.correlation_rule ?? parsed.proposed_rule ?? {};
    // Confirmed shape uses top-level `valid` + `message` (+ `engine_message`
    // on success); fall back to an older nested `validation.ok` shape or a
    // bare `ok` field defensively, in case either tool's payload ever drifts.
    const validation = typeof parsed.valid === 'boolean'
      ? { ok: parsed.valid, message: typeof parsed.message === 'string' ? parsed.message : (typeof parsed.engine_message === 'string' ? parsed.engine_message : undefined) }
      : (parsed.validation && typeof parsed.validation === 'object'
        ? { ok: !!parsed.validation.ok, message: typeof parsed.validation.message === 'string' ? parsed.validation.message : undefined }
        : (typeof parsed.ok === 'boolean' ? { ok: parsed.ok, message: typeof parsed.message === 'string' ? parsed.message : undefined } : undefined));
    return { id: genId(), kind, rule, validation };
  } catch {
    return null;
  }
}

export function useAiChatSession(opts?: { fetchSessions?: boolean }) {
  // Defaults to true — features/AI/index.tsx's session-history panel needs
  // the list immediately on mount. FloatingChatWidget passes false: it's
  // now mounted globally (Layout.tsx, every authenticated page), and it
  // never renders a session list at all, so that GET fired on every
  // dashboard page load for every user regardless of whether they ever open
  // the launcher — pure wasted network/server load, not a deferred need.
  const fetchSessions = opts?.fetchSessions ?? true;
  const { showToast } = useToast();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [bubbles, setBubbles] = useState<BubbleMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const sessionIdRef = useRef<number | null>(null);

  useEffect(() => {
    if (!fetchSessions) return;
    api.get(AI_URLS.SESSIONS).then((res) => {
      setSessions(res.data.sessions ?? []);
    }).catch(() => {});
  }, [fetchSessions]);

  // Abort any in-flight stream on unmount — e.g. FloatingChatWidget unmounts
  // outright when navigating to /ai (see Layout.tsx's `!isAI` guard), and
  // without this the fetch/SSE loop in sendMessage below just kept running
  // orphaned: its setBubbles/setMessages calls updated state nothing was
  // reading anymore, for a hook instance nothing could still interact with.
  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    sessionIdRef.current = currentSessionId;
  }, [currentSessionId]);

  const loadSession = useCallback(async (id: number) => {
    try {
      const res = await api.get(AI_URLS.SESSION(id));
      setMessages(res.data.messages ?? []);
      setBubbles(res.data.bubbles ?? []);
      setCurrentSessionId(id);
    } catch { /* non-fatal */ }
  }, []);

  const deleteSession = useCallback(async (id: number) => {
    try {
      await api.delete(AI_URLS.SESSION(id));
      setSessions((prev) => prev.filter((s) => s.id !== id));
      if (currentSessionId === id) {
        setMessages([]);
        setBubbles([]);
        setCurrentSessionId(null);
      }
    } catch { /* non-fatal */ }
  }, [currentSessionId]);

  const startNewChat = useCallback(() => {
    abortRef.current?.abort();
    setLoading(false);
    setMessages([]);
    setBubbles([]);
    setCurrentSessionId(null);
    setInput('');
  }, []);

  const confirmAction = useCallback(async (actionId: string): Promise<boolean> => {
    try {
      await api.post(`${AI_URLS.CONFIRM_ACTION}/${actionId}`, {});
      return true;
    } catch (err) {
      showToast(getActionErrorMessage(err, 'Failed to dispatch action'), 'error');
      return false;
    }
  }, [showToast]);

  const denyAction = useCallback(async (actionId: string): Promise<boolean> => {
    try {
      await api.delete(`${AI_URLS.CANCEL_ACTION}/${actionId}`);
      return true;
    } catch (err) {
      showToast(getActionErrorMessage(err, 'Failed to cancel action'), 'error');
      return false;
    }
  }, [showToast]);

  const sendMessage = useCallback(async (overrideText?: string) => {
    const text = (overrideText ?? input).trim();
    if (!text || loading) return;

    setInput('');
    setLoading(true);

    const newUserMsg: ChatMessage = { role: 'user', content: text };
    const updatedMessages = [...messages, newUserMsg];
    setMessages(updatedMessages);

    const userBubble: BubbleMessage = { id: genId(), role: 'user', text };
    const aiBubble: BubbleMessage = {
      id: genId(), role: 'assistant', text: '', isStreaming: true, toolEvents: [], pendingActions: [], ruleProposals: [],
    };
    setBubbles((prev) => [...prev, userBubble, aiBubble]);
    const aiBubbleId = aiBubble.id;

    let activeSessionId = sessionIdRef.current;
    if (activeSessionId === null) {
      try {
        const title = makeTitleFromMessage(text);
        const res = await api.post(AI_URLS.SESSIONS, { title, messages: [], bubbles: [] });
        activeSessionId = res.data.id as number;
        setCurrentSessionId(activeSessionId);
        setSessions((prev) => [
          { id: activeSessionId!, title, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
          ...prev,
        ]);
      } catch { /* proceed without persistence */ }
    }

    const abort = new AbortController();
    abortRef.current = abort;

    let fullText = '';
    let streamError: string | null = null;
    const toolEvents: ToolEvent[] = [];
    const pendingActions: PendingAction[] = [];
    const ruleProposals: RuleProposal[] = [];

    try {
      const resp = await fetchWithCsrf(AI_URLS.CHAT, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeadersJson(),
        body: JSON.stringify({ messages: updatedMessages }),
        signal: abort.signal,
      });

      if (!resp.ok || !resp.body) {
        const bodyText = await resp.text().catch(() => '');
        throw new Error(extractChatErrorMessage(bodyText, 'Request failed'));
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      // Set by the 'done' event below to also stop the outer reader loop —
      // `break` there only exits the inner `for (line of lines)` loop, so
      // without this the outer `while (true)` still awaited one further
      // (harmless but wasted) `reader.read()` after the stream had already
      // logically ended.
      let streamDone = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (!raw) continue;
          let event: ChatStreamEvent;
          try { event = JSON.parse(raw); } catch { continue; }

          if (event.type === 'text_delta') {
            fullText += event.text;
            setBubbles((prev) =>
              prev.map((b) => b.id === aiBubbleId ? { ...b, text: fullText, isStreaming: true } : b),
            );
          } else if (event.type === 'tool_call') {
            toolEvents.push({ tool_name: event.tool_name, tool_input: event.tool_input });
            setBubbles((prev) =>
              prev.map((b) => b.id === aiBubbleId ? { ...b, toolEvents: [...toolEvents] } : b),
            );
          } else if (event.type === 'tool_result') {
            const last = toolEvents[toolEvents.length - 1];
            if (!last) {
              // Should be unreachable (every tool_result is preceded by a
              // tool_call in the stream) — if the paired tool_call's JSON
              // ever failed to parse a few lines above (silently `continue`d)
              // or the buffer otherwise desynced, this result — including a
              // propose_rule/propose_agent_action rejection reason — would
              // otherwise vanish from the chat with zero indication anything
              // happened. Surfaced instead of silently dropped.
              console.warn('useAiChatSession: tool_result with no matching tool_call in this stream', event);
            } else {
              last.result = event.result;
              last.is_error = event.is_error;
              if (event.tool_name === 'propose_agent_action' && !event.is_error) {
                try {
                  const parsed = JSON.parse(event.result);
                  if (parsed.pending_action_id) {
                    pendingActions.push({
                      id: parsed.pending_action_id,
                      action_type: parsed.action_type,
                      host_identifier: parsed.host_identifier,
                      hostname: parsed.hostname,
                      description: parsed.description,
                      risk: (['low', 'medium', 'high'] as const).includes(parsed.risk) ? parsed.risk : 'medium',
                      expires_at: Date.now() + (parsed.expires_in_seconds ?? 300) * 1000,
                    });
                  }
                } catch { /* ignore */ }
              } else if (event.tool_name === 'propose_rule' || event.tool_name === 'propose_correlation_rule') {
                // Parsed on BOTH outcomes (is_error true or false) — a
                // rejected proposal still renders as a card with the real
                // engine's exact rejection reason. See parseRuleProposal's
                // doc comment.
                const proposal = parseRuleProposal(event.tool_name, event.result);
                if (proposal) ruleProposals.push(proposal);
              }
              setBubbles((prev) =>
                prev.map((b) =>
                  b.id === aiBubbleId
                    ? { ...b, toolEvents: [...toolEvents], pendingActions: [...pendingActions], ruleProposals: [...ruleProposals] }
                    : b,
                ),
              );
            }
          } else if (event.type === 'done') {
            streamDone = true;
            break;
          } else if (event.type === 'error') {
            streamError = typeof event.message === 'string' ? event.message : 'The assistant hit an error mid-response.';
            streamDone = true;
            break;
          }
        }
        if (streamDone) break;
      }

      const displayText = streamError
        ? (fullText ? `${fullText}\n\n⚠️ ${streamError}` : `⚠️ ${streamError}`)
        : fullText;
      const finalMessages = [...updatedMessages, { role: 'assistant' as const, content: displayText }];
      setMessages(finalMessages);
      if (streamError) showToast(streamError, 'error');
      setBubbles((prev) => {
        const finalBubbles = prev.map((b) =>
          b.id === aiBubbleId ? { ...b, text: displayText, isStreaming: false, toolEvents, pendingActions, ruleProposals } : b,
        );
        if (activeSessionId !== null) {
          setTimeout(() => saveSession(activeSessionId!, finalMessages, finalBubbles, () => showToast('This conversation could not be saved — it may be gone after a refresh.', 'error')), 0);
          setSessions((prev) => prev.map((s) =>
            s.id === activeSessionId ? { ...s, updatedAt: new Date().toISOString() } : s,
          ));
        }
        return finalBubbles;
      });
    } catch (err) {
      if (isAbortError(err)) return;
      const errorMsg = err instanceof Error ? err.message : 'Something went wrong.';
      setBubbles((prev) =>
        prev.map((b) => b.id === aiBubbleId ? { ...b, text: `⚠️ ${errorMsg}`, isStreaming: false } : b),
      );
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }, [input, loading, messages, showToast]);

  const handleStop = useCallback(() => {
    abortRef.current?.abort();
    setLoading(false);
    setBubbles((prev) => prev.map((b) => b.isStreaming ? { ...b, isStreaming: false } : b));
  }, []);

  return {
    messages, bubbles, input, setInput, loading,
    sessions, currentSessionId,
    loadSession, deleteSession, startNewChat,
    confirmAction, denyAction, sendMessage, handleStop,
  };
}
