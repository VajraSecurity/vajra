/**
 * HITL (Human-In-The-Loop) pending actions store.
 *
 * When the AI proposes a WS agent action, it is stored here with a TTL.
 * The user sees the proposal in the UI, confirms/denies it.
 * Only on explicit confirmation does the action get dispatched.
 */

import { randomBytes } from 'crypto';
import type { WsActionProposal } from '../mcp/guardrails';
import { buildWsPayload } from '../mcp/guardrails';
import { getLogger } from '../utils/logger';

const logger = getLogger('services.pendingActions');

export interface PendingAction extends WsActionProposal {
  id: string;
  ws_payload: Record<string, unknown>;
  created_at: number; // unix ms
  expires_at: number; // unix ms
  /** hostname for display (resolved at creation time) */
  hostname?: string;
  /** id of the user whose chat session proposed this action — only they may view/confirm/cancel it */
  created_by_user_id: number;
}

const PENDING_ACTION_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_PENDING_ACTIONS = 50;

const store = new Map<string, PendingAction>();

// Cleanup expired entries every minute
setInterval(() => {
  const now = Date.now();
  let expiredCount = 0;
  for (const [id, action] of store) {
    if (action.expires_at < now) {
      store.delete(id);
      expiredCount++;
    }
  }
  if (expiredCount > 0) {
    logger.info({ expiredCount, remaining: store.size }, 'Swept expired pending actions');
  }
}, 60_000).unref();

export function createPendingAction(
  proposal: WsActionProposal,
  hostname: string | undefined,
  createdByUserId: number,
): { id: string; action: PendingAction } {
  // Evict oldest if at capacity
  if (store.size >= MAX_PENDING_ACTIONS) {
    const oldest = [...store.entries()].sort((a, b) => a[1].created_at - b[1].created_at)[0];
    if (oldest) {
      logger.warn(
        { evictedId: oldest[0], evictedActionType: oldest[1].action_type, evictedUserId: oldest[1].created_by_user_id, capacity: MAX_PENDING_ACTIONS },
        'Pending action store at capacity; evicting oldest unconfirmed action',
      );
      store.delete(oldest[0]);
    }
  }

  const id = randomBytes(16).toString('hex');
  const now = Date.now();
  const action: PendingAction = {
    ...proposal,
    id,
    ws_payload: buildWsPayload(proposal),
    created_at: now,
    expires_at: now + PENDING_ACTION_TTL_MS,
    hostname,
    created_by_user_id: createdByUserId,
  };

  store.set(id, action);
  logger.info(
    { id, actionType: action.action_type, hostIdentifier: action.host_identifier, userId: createdByUserId },
    'AI proposed a pending agent action awaiting confirmation',
  );
  return { id, action };
}

/** Returns the action only if it exists, is unexpired, and belongs to `userId`. */
export function getPendingAction(id: string, userId: number): PendingAction | null {
  const action = store.get(id);
  if (!action) {
    logger.warn({ id, requestingUserId: userId }, 'Pending action lookup denied: id not found');
    return null;
  }
  if (action.expires_at < Date.now()) {
    logger.warn({ id, requestingUserId: userId, actionType: action.action_type }, 'Pending action lookup denied: action expired');
    store.delete(id);
    return null;
  }
  if (action.created_by_user_id !== userId) {
    logger.warn({ id, requestingUserId: userId, ownerUserId: action.created_by_user_id }, 'Pending action lookup denied: requester does not own this action');
    return null;
  }
  return action;
}

/** Deletes the action only if it belongs to `userId` — returns false otherwise (including "not found"). */
export function deletePendingAction(id: string, userId: number): boolean {
  const action = store.get(id);
  if (!action) {
    logger.warn({ id, requestingUserId: userId }, 'Pending action delete requested for unknown or already-removed id');
    return false;
  }
  if (action.created_by_user_id !== userId) {
    logger.warn({ id, requestingUserId: userId, ownerUserId: action.created_by_user_id }, 'Pending action delete denied: requester does not own this action');
    return false;
  }
  return store.delete(id);
}

/** Lists only the unexpired actions proposed by `userId`. */
export function listPendingActions(userId: number): PendingAction[] {
  const now = Date.now();
  const result: PendingAction[] = [];
  for (const [id, action] of store) {
    if (action.expires_at < now) {
      store.delete(id);
    } else if (action.created_by_user_id === userId) {
      result.push(action);
    }
  }
  return result.sort((a, b) => b.created_at - a.created_at);
}

export const PENDING_ACTION_TTL_SECONDS = PENDING_ACTION_TTL_MS / 1000;
