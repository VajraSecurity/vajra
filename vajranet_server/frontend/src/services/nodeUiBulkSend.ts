/**
 * Send one or more agent messages on a single /ui WebSocket (same protocol as useNodeWebSocket).
 * Used for bulk hardware actions (USB, Bluetooth) from Responsive admin UI.
 */

import { NODES_WS_BASE } from '../api/urls';
import { secureUUID } from '../lib/utils';

const UI_WS_URL = `${NODES_WS_BASE}/ui`;
const CONNECT_TIMEOUT_MS = 15_000;

export type NodeUiOutbound = {
  type: 'agent';
  params?: Record<string, unknown>;
  host_identifier: string;
};

type WsResponse = {
  rid?: string;
  status?: string;
  message?: string;
  error?: string;
  response?: unknown;
};

function openUiSocket(): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const ws = new WebSocket(UI_WS_URL);
    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      reject(new Error('WebSocket connection timed out'));
    }, CONNECT_TIMEOUT_MS);

    ws.onopen = () => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      resolve(ws);
    };

    ws.onerror = () => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      reject(new Error('WebSocket connection failed'));
    };
  });
}

function sendAndWaitForRid(ws: WebSocket, message: NodeUiOutbound, timeoutMs: number): Promise<WsResponse> {
  return new Promise((resolve, reject) => {
    // secureUUID() (crypto.randomUUID(), falling back to crypto.getRandomValues()
    // on insecure-context/HTTP deployments — see lib/utils.ts): this rid is a live
    // routing key the backend stores (ws:rid:{rid} in Redis) to deliver the
    // response back to this socket — it should be as unguessable as the backend's
    // own generator for the same purpose (websocket/utils.ts's generateUniqueID,
    // crypto.randomBytes(8)) on every deployment, not just HTTPS ones.
    const rid = `${Date.now()}-${secureUUID()}`;
    const full = { ...message, rid };

    const timer = window.setTimeout(() => {
      ws.removeEventListener('message', onMessage);
      reject(new Error(`Request timeout (${timeoutMs}ms)`));
    }, Math.max(1000, timeoutMs));

    const onMessage = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(String(ev.data)) as WsResponse;
        if (data.rid !== rid) return;
        window.clearTimeout(timer);
        ws.removeEventListener('message', onMessage);
        if (data.error) {
          reject(new Error(data.error));
          return;
        }
        resolve(data);
      } catch {
        /* ignore malformed */
      }
    };

    ws.addEventListener('message', onMessage);
    try {
      ws.send(JSON.stringify(full));
    } catch (e) {
      window.clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      reject(e instanceof Error ? e : new Error('Failed to send WebSocket message'));
    }
  });
}

export type BulkAgentResult = { host: string; ok: boolean; message?: string };

// Cap on simultaneously in-flight requests per bulk call. Each request is
// independently correlated by its own rid (see sendAndWaitForRid) and the
// backend (websocket/node.ts) routes purely by rid, not send order, so
// concurrent dispatch on one socket is safe. This cap just avoids firing all
// MAX_BULK_OPERATIONS (2500, responsiveNodeUtils.ts) requests — and their
// rid→uiSlot Redis writes — in one simultaneous burst.
const DEFAULT_CONCURRENCY = 50;

async function sendOne(ws: WebSocket, cmd: NodeUiOutbound, timeoutMs: number): Promise<BulkAgentResult> {
  const host = cmd.host_identifier;
  try {
    const data = await sendAndWaitForRid(ws, cmd, timeoutMs);
    if (data.status === 'error') {
      return { host, ok: false, message: data.message || 'Agent returned error' };
    }
    return { host, ok: true };
  } catch (e) {
    return { host, ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Opens one WebSocket and dispatches messages concurrently (in bounded-size
 * batches), returning per-host results in the same order as `commands`.
 */
export async function runBulkNodeUiCommands(
  commands: NodeUiOutbound[],
  options?: { timeoutMs?: number; concurrency?: number },
): Promise<BulkAgentResult[]> {
  if (commands.length === 0) return [];

  const timeoutMs      = options?.timeoutMs ?? 25_000;
  const rawConcurrency = options?.concurrency ?? DEFAULT_CONCURRENCY;
  // Reject non-finite/non-positive values outright rather than Math.max(1, ...) —
  // NaN propagates through Math.max unchanged, and commands.slice(0, NaN) coerces
  // NaN to 0 (an empty chunk every iteration), while start += NaN immediately
  // fails the loop condition, leaving `results` a hole-filled array of undefined.
  // Infinity would pass Math.max(1, ...) too, silently defeating the whole point
  // of bounding concurrency (one giant unbounded burst).
  const concurrency = Number.isFinite(rawConcurrency) && rawConcurrency > 0
    ? Math.floor(rawConcurrency)
    : DEFAULT_CONCURRENCY;
  const ws = await openUiSocket();
  const results: BulkAgentResult[] = new Array(commands.length);

  try {
    for (let start = 0; start < commands.length; start += concurrency) {
      const chunk = commands.slice(start, start + concurrency);
      const chunkResults = await Promise.all(chunk.map((cmd) => sendOne(ws, cmd, timeoutMs)));
      chunkResults.forEach((r, i) => { results[start + i] = r; });
    }
  } finally {
    try {
      ws.close();
    } catch {
      /* ignore */
    }
  }

  return results;
}
