/**
 * Thin event bus for node status change notifications, connecting node.ts
 * (emitter) to liveWeb.ts (subscriber).
 *
 * Must stay a pure leaf with no imports from the rest of the WS layer: it
 * exists to break the cycle node.ts -> liveWeb.ts -> ../index -> ./node.
 */

type Listener = () => void;
let _listener: Listener | null = null;

/** Register the single subscriber (liveWeb.ts). Overwrites any previous registration. */
export function onNodeStatusChange(fn: Listener): void {
  _listener = fn;
}

/** Unregister. Called from stopLiveWeb() so post-shutdown emits are true no-ops. */
export function offNodeStatusChange(): void {
  _listener = null;
}

/**
 * Fire the registered listener.
 * Called by node.ts after UpdateAgentStatus() DB write confirms so the
 * subsequent SELECT in getNodesStatus() always reads committed data.
 */
export function emitNodeStatusChange(): void {
  _listener?.();
}
