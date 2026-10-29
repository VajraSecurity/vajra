/**
 * WebSocket message validation and utility helpers
 */

import type { NodeStatus, WebSocRevMessage } from './types';
import { randomBytes } from 'crypto';

export type ParsedWebSocketMessage = WebSocRevMessage & { token?: string; rid?: string };

/**
 * Validate a UI → Extension message.
 * Requires valid JSON, an object, and a string host_identifier.
 * Returns the parsed object (avoids double-parse), or null on failure.
 */
export function ValidateMessage(message: string): ParsedWebSocketMessage | null {
  try {
    const parsed = JSON.parse(message);
    if (typeof parsed !== 'object' || parsed === null || typeof parsed.host_identifier !== 'string') {
      return null;
    }
    return parsed as ParsedWebSocketMessage;
  } catch {
    return null;
  }
}

/**
 * Shape of a message sent from an agent extension back to the server.
 * Only `rid` is required, for routing; everything else is pass-through payload.
 * host_identifier is deliberately not required — agents are not guaranteed to
 * echo it back.
 */
export type ExtensionResponse = Record<string, unknown> & { rid: string };

/**
 * Validate an Extension → UI response message.
 * Requires valid JSON, an object, and a non-empty string rid (used for routing).
 * Returns the parsed object, or null on failure.
 */
export function ValidateExtResponse(message: string): ExtensionResponse | null {
  try {
    const parsed = JSON.parse(message);
    if (typeof parsed !== 'object' || parsed === null || typeof parsed.rid !== 'string' || parsed.rid === '') {
      return null;
    }
    return parsed as ExtensionResponse;
  } catch {
    return null;
  }
}

/**
 * Generates a cryptographically secure unique ID for request/response correlation (e.g. rid)
 */
export function generateUniqueID(): string {
  return `${Date.now()}-${randomBytes(8).toString('hex')}`;
}

/**
 * Deep equality check for generic objects (used to avoid unnecessary broadcasts)
 */
export function isEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
    const va = a[keysA[i]];
    const vb = b[keysB[i]];
    if (Array.isArray(va) && Array.isArray(vb)) {
      if (va.length !== vb.length) return false;
      for (let j = 0; j < va.length; j++) {
        if (va[j] !== vb[j]) return false;
      }
    } else if (va !== vb) {
      return false;
    }
  }
  return true;
}

/**
 * Equality check for NodeStatus (fixed field order, no key sort — avoids extra allocations)
 */
export function isNodeStatusEqual(a: NodeStatus, b: NodeStatus): boolean {
  if (a.online !== b.online || a.offline !== b.offline || a.total !== b.total) return false;
  if (a.onlineNodeHostIdentifier.length !== b.onlineNodeHostIdentifier.length) return false;
  if (a.agentOnline.length !== b.agentOnline.length) return false;
  for (let i = 0; i < a.onlineNodeHostIdentifier.length; i++) {
    if (a.onlineNodeHostIdentifier[i] !== b.onlineNodeHostIdentifier[i]) return false;
  }
  for (let i = 0; i < a.agentOnline.length; i++) {
    if (a.agentOnline[i] !== b.agentOnline[i]) return false;
  }
  return true;
}
