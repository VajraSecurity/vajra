/**
 * AI assistant routes.
 *
 * POST /api/ai/chat          — SSE streaming chat with the AI assistant
 * GET  /api/ai/pending       — List pending HITL actions (for UI confirmation panel)
 * POST /api/ai/confirm/:id   — Confirm a pending WS action (dispatches to agent)
 * DELETE /api/ai/pending/:id — Cancel/discard a pending action
 */

import { Router, Request, Response } from 'express';
import { getLogger } from '../../utils/logger';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireAdmin } from '../../middleware/requireAdmin';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import { streamAiResponse, type ChatMessage } from '../../services/aiChat';
import {
  listPendingActions,
  getPendingAction,
  deletePendingAction,
} from '../../services/pendingActions';
import { dbSourceConnection } from '../../index';
import { dispatchToAgent } from '../../websocket/node';
import { getUserNodeScope, assertCanActOnHost } from '../../utils/nodeScope';
import { logAuditTrail, type AuditTrailEntry } from '../../utils/auditTrailLogger';
import type { AuditTrailAction } from '../../orm/entities/audit/AuditTrail';
import type { JwtPayload } from '../../types/JwtPayload';
import { AiConversation } from '../../orm/entities/ai/AiConversation';
import {
  getAiProviderConfigStatus,
  getAiProviderConfig,
  saveAiProviderConfig,
  testAiProviderConfig,
  deleteAiProviderConfig,
} from '../../controllers/ai/aiProviderConfigController';

const ACTION_TO_AUDIT: Record<string, AuditTrailAction> = {
  compliance_check:  'COMPLIANCE',
  isolate_node:      'ISOLATE_NODE',
  reenroll_node:     'REENROLL_NODE',
  block_port:        'PORT_BLOCK',
  unblock_port:      'PORT_BLOCK',
  block_ip:          'IP_BLOCK',
  unblock_ip:        'IP_BLOCK',
  disable_usb:       'USB',
  enable_usb:        'USB',
  disable_bluetooth: 'BLUETOOTH',
  enable_bluetooth:  'BLUETOOTH',
  patch_install:     'WINDOWS_PATCH_INSTALL_DISPATCHED',
  patch_uninstall:   'WINDOWS_PATCH_INSTALL_DISPATCHED',
  patch_check:       'WINDOWS_PATCH_INSTALL_DISPATCHED',
};

const logger = getLogger('routes.ai');

const router = Router();

// All AI endpoints require authentication
router.use(checkAccessJwt);

// ─── Rate limiter specific to AI (more restrictive) ───────────────────────────
// Reuse apiDataLimiter (can configure a dedicated one if needed)

// ─── POST /api/ai/chat ────────────────────────────────────────────────────────

router.post('/chat', [apiDataLimiter], async (req: Request, res: Response) => {
  const messages: ChatMessage[] = req.body?.messages;

  if (!messages || !Array.isArray(messages)) {
    res.status(400).json({ error: 'messages array required' });
    return;
  }

  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  const secondaryDb = dataSources?.[1];
  // Optional: only present once vajra_hunt has been provisioned (see
  // ormconfig-setup.ts setupHuntRole()). Absent, group-scoped callers get a
  // clear "not available yet" tool result instead of the chat request failing.
  const huntDb = dataSources?.[2];
  if (!primaryDb || !secondaryDb) {
    res.status(503).json({ error: 'Database unavailable' });
    return;
  }

  // SSE setup
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // disable nginx buffering
  res.flushHeaders();

  const sendSse = (event: string, data: unknown) => {
    if (res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    (res as any).flush?.();
  };

  try {
    const gen = streamAiResponse(messages, {
      primaryDb,
      secondaryDb,
      huntDb,
      userId: user.id,
    });

    for await (const event of gen) {
      sendSse(event.type, event);
      if (event.type === 'done' || event.type === 'error') break;
    }
  } catch (err) {
    logger.error({ err, userId: user.id }, 'AI chat stream failed');
    sendSse('error', { type: 'error', message: 'Internal server error' });
  } finally {
    if (!res.writableEnded) res.end();
  }
});

// ─── GET /api/ai/sessions ─────────────────────────────────────────────────────
// List all sessions for the current user (id, title, created_at, updated_at)

router.get('/sessions', [apiDataLimiter], async (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb) { res.status(503).json({ error: 'Database unavailable' }); return; }

  const sessions = await primaryDb
    .getRepository(AiConversation)
    .createQueryBuilder('s')
    .select(['s.id', 's.title', 's.createdAt', 's.updatedAt'])
    .where('s.userId = :uid', { uid: user.id })
    .orderBy('s.updatedAt', 'DESC')
    .getMany();

  logger.info({ userId: user.id, count: sessions.length }, 'AI chat sessions listed');
  res.json({ sessions });
});

// ─── GET /api/ai/sessions/:id ─────────────────────────────────────────────────

router.get('/sessions/:id', [apiDataLimiter], async (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb) { res.status(503).json({ error: 'Database unavailable' }); return; }

  const session = await primaryDb
    .getRepository(AiConversation)
    .findOne({ where: { id: Number(req.params['id']), userId: user.id } });

  if (!session) { res.status(404).json({ error: 'Not found' }); return; }

  logger.info({ userId: user.id, sessionId: session.id }, 'AI chat session retrieved');
  res.json({
    id:       session.id,
    title:    session.title,
    messages: session.messages,
    bubbles:  session.bubbles,
  });
});

// ─── POST /api/ai/sessions ────────────────────────────────────────────────────
// Create a new session and return its id

router.post('/sessions', [apiDataLimiter, checkCsrf], async (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const { title, messages, bubbles } = req.body as {
    title?: string; messages?: unknown[]; bubbles?: unknown[];
  };

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb) { res.status(503).json({ error: 'Database unavailable' }); return; }

  const repo = primaryDb.getRepository(AiConversation);
  const session = repo.create({
    userId:   user.id,
    title:    title ?? 'New Chat',
    messages: (messages ?? []) as any,
    bubbles:  (bubbles  ?? []) as any,
  });
  await repo.save(session);

  logger.info({ userId: user.id, sessionId: session.id }, 'AI chat session created');
  res.json({ id: session.id, title: session.title });
});

// ─── PUT /api/ai/sessions/:id ─────────────────────────────────────────────────

router.put('/sessions/:id', [apiDataLimiter, checkCsrf], async (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const { title, messages, bubbles } = req.body as {
    title?: string; messages?: unknown[]; bubbles?: unknown[];
  };

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb) { res.status(503).json({ error: 'Database unavailable' }); return; }

  const repo = primaryDb.getRepository(AiConversation);
  const session = await repo.findOne({
    where: { id: Number(req.params['id']), userId: user.id },
  });
  if (!session) { res.status(404).json({ error: 'Not found' }); return; }

  if (title    !== undefined) session.title    = title;
  if (messages !== undefined) session.messages = messages as any;
  if (bubbles  !== undefined) session.bubbles  = bubbles  as any;
  await repo.save(session);

  logger.info({ userId: user.id, sessionId: session.id }, 'AI chat session updated');
  res.json({ success: true });
});

// ─── DELETE /api/ai/sessions/:id ─────────────────────────────────────────────

router.delete('/sessions/:id', [apiMutationLimiter, checkCsrf], async (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const dataSources = dbSourceConnection();
  const primaryDb = dataSources?.[0];
  if (!primaryDb) { res.status(503).json({ error: 'Database unavailable' }); return; }

  const repo = primaryDb.getRepository(AiConversation);
  const session = await repo.findOne({
    where: { id: Number(req.params['id']), userId: user.id },
  });
  if (!session) { res.status(404).json({ error: 'Not found' }); return; }

  await repo.remove(session);
  logger.info({ userId: user.id, sessionId: session.id }, 'AI chat session deleted');
  res.json({ success: true });
});

// ─── GET /api/ai/pending ──────────────────────────────────────────────────────
// Admin+ only — mirrors the role gate the direct WS agent-command path enforces
// for Viewers, and scoped to the caller's own proposals only.

router.get('/pending', [requireAdmin, apiDataLimiter], (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const actions = listPendingActions(user.id);
  logger.info({ userId: user.id, count: actions.length }, 'Pending AI actions listed');
  res.json({ success: true, count: actions.length, actions });
});

// ─── POST /api/ai/confirm/:id ─────────────────────────────────────────────────
// Admin+ only — dispatchToAgent has no role check of its own, so this route is
// the sole enforcement point standing between the AI's proposal and the agent.

router.post('/confirm/:id', [requireAdmin, apiMutationLimiter, checkCsrf], async (req: Request, res: Response) => {
  const id = req.params['id'] as string;
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const action = getPendingAction(id, user.id);
  if (!action) {
    res.status(404).json({ error: 'Pending action not found or expired' });
    return;
  }

  // mcp/executor.ts's assertCanActOnHost gate at proposal time only reflects
  // scope as of that moment — a pending action can sit for up to
  // PENDING_ACTION_TTL_MS (5 minutes), during which a Super Admin could
  // reassign the host to another group or change this user's group
  // membership. Re-check immediately before dispatch, same as the direct
  // WebSocket agent-command path re-checks scope on every message.
  const currentScope = await getUserNodeScope(user.id);
  if (!(await assertCanActOnHost(currentScope, action.host_identifier))) {
    logger.warn(
      { userId: user.id, host_identifier: action.host_identifier, action_type: action.action_type },
      'AI-proposed action confirm rejected: host no longer in caller scope'
    );
    deletePendingAction(id, user.id);
    res.status(404).json({ error: 'Node not found' });
    return;
  }

  // Dispatch to agent
  const result = dispatchToAgent(action.host_identifier, action.ws_payload);
  if (!result.dispatched) {
    logger.warn(
      { userId: user.id, host_identifier: action.host_identifier, action_type: action.action_type, reason: result.error },
      'AI-proposed action could not be dispatched to agent'
    );
    res.status(503).json({
      error: `Could not dispatch action: ${result.error ?? 'Agent not connected'}`,
      host_identifier: action.host_identifier,
    });
    return;
  }

  // Remove from pending store (one-time-use)
  deletePendingAction(id, user.id);

  // Audit log
  const entry: AuditTrailEntry = {
    action: ACTION_TO_AUDIT[action.action_type] ?? 'COMPLIANCE',
    status: 'success',
    userId: user?.id ?? null,
    email: user?.email ?? null,
    ipAddress: req.ip ?? null,
    userAgent: (Array.isArray(req.headers['user-agent']) ? req.headers['user-agent'][0] : req.headers['user-agent']) ?? null,
    details: {
      action_type: action.action_type,
      host_identifier: action.host_identifier,
      hostname: action.hostname,
      ai_driven: true,
    },
  };
  logAuditTrail(entry).catch((err) => {
    logger.error({ err, userId: user.id, host_identifier: action.host_identifier }, 'Failed to write audit trail for AI-dispatched action');
  });

  logger.info(
    { userId: user.id, host_identifier: action.host_identifier, action_type: action.action_type },
    'AI-proposed action dispatched to agent'
  );
  res.json({
    success: true,
    dispatched: true,
    action_type: action.action_type,
    host_identifier: action.host_identifier,
    hostname: action.hostname,
    message: 'Action dispatched to agent. Check the node view for results.',
  });
});

// ─── DELETE /api/ai/pending/:id ───────────────────────────────────────────────

router.delete('/pending/:id', [requireAdmin, apiMutationLimiter, checkCsrf], (req: Request, res: Response) => {
  const user = (req as Request & { jwtPayload?: JwtPayload }).jwtPayload;
  if (!user?.id) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const deleted = deletePendingAction(req.params['id'] as string, user.id);
  if (!deleted) {
    res.status(404).json({ error: 'Not found or already expired' });
    return;
  }
  logger.info({ userId: user.id }, 'Pending AI action discarded');
  res.json({ success: true });
});

// ─── AI provider configuration (Super Admin only) ─────────────────────────────
// Lets an admin configure the LLM provider/API key from the UI instead of .env.

// Available to any authenticated user — powers the "not configured" banner in
// the chat UI so non-admins know why the assistant isn't responding.
router.get('/config/status', [apiDataLimiter], getAiProviderConfigStatus);

router.get('/config', [requireSuperAdmin, apiDataLimiter], getAiProviderConfig);
router.post('/config', [requireSuperAdmin, apiMutationLimiter, checkCsrf], saveAiProviderConfig);
router.post('/config/test', [requireSuperAdmin, apiMutationLimiter, checkCsrf], testAiProviderConfig);
router.delete('/config', [requireSuperAdmin, apiMutationLimiter, checkCsrf], deleteAiProviderConfig);

export default router;
