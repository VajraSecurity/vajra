import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';

/**
 * Lets a feature page "borrow" the single app-wide `FloatingChatWidget` for
 * its own tool-result affordance without the widget needing to know Rule
 * Engine (or any other specific feature) exists. A rule-authoring feature
 * registers these two callbacks on mount and clears them on unmount (see
 * `useRegisterRuleChatHandlers` below); the widget renders `RuleProposalCard`s
 * with "Load into builder" only while a registration is active, so every
 * other page's chat looks identical to the plain assistant. Deliberately
 * just two function refs, not a general plugin system — add the next
 * feature's hook the same way if one ever needs it, rather than
 * generalizing ahead of a second real use case. The payload shape is left
 * as `Record<string, unknown>` rather than importing a specific feature's
 * rule types here — this file has zero knowledge of what "a rule" actually
 * looks like, only that a registered handler wants the raw proposed JSON.
 */
export interface RuleChatHandlers {
  onLoadRule: (rule: Record<string, unknown>) => void;
  onLoadCorrelation: (rule: Record<string, unknown>) => void;
}

interface FloatingChatContextValue {
  ruleHandlers: RuleChatHandlers | null;
  setRuleHandlers: (handlers: RuleChatHandlers | null) => void;
}

const FloatingChatContext = createContext<FloatingChatContextValue | null>(null);

export function FloatingChatProvider({ children }: { children: React.ReactNode }) {
  const [ruleHandlers, setRuleHandlers] = useState<RuleChatHandlers | null>(null);
  const value = useMemo(() => ({ ruleHandlers, setRuleHandlers }), [ruleHandlers]);
  return <FloatingChatContext.Provider value={value}>{children}</FloatingChatContext.Provider>;
}

/** Consumed by `FloatingChatWidget` — the currently registered Rule Engine handlers, if any. */
// eslint-disable-next-line react-refresh/only-export-components
export function useFloatingChatRuleHandlers(): RuleChatHandlers | null {
  const ctx = useContext(FloatingChatContext);
  return ctx?.ruleHandlers ?? null;
}

/**
 * Consumed by `features/RuleEngine/index.tsx`: registers `handlers` for as
 * long as the calling component stays mounted, clearing them on unmount.
 * Takes the raw callbacks (not a memoized object) and wraps them in a ref so
 * callers don't need to `useMemo` a handlers object just to avoid
 * re-registering on every render.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useRegisterRuleChatHandlers(handlers: RuleChatHandlers) {
  const ctx = useContext(FloatingChatContext);
  const setRuleHandlers = ctx?.setRuleHandlers;

  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;
  const stableOnLoadRule = useCallback((rule: Record<string, unknown>) => handlersRef.current.onLoadRule(rule), []);
  const stableOnLoadCorrelation = useCallback((rule: Record<string, unknown>) => handlersRef.current.onLoadCorrelation(rule), []);

  useEffect(() => {
    setRuleHandlers?.({ onLoadRule: stableOnLoadRule, onLoadCorrelation: stableOnLoadCorrelation });
    return () => setRuleHandlers?.(null);
  }, [setRuleHandlers, stableOnLoadRule, stableOnLoadCorrelation]);
}
