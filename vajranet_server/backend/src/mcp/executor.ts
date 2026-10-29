/**
 * Tool executor: runs AI tool calls against the real databases and services. WS
 * actions are only queued as pending actions for human confirmation; they are
 * never dispatched from here.
 *
 * Database access is intended to be read-only, but guardrails.validateSql does
 * not guarantee that. Queries below are issued with an empty parameter array, so
 * node-postgres uses the simple query protocol and stacked statements that slip
 * past the guardrails still reach the server. Only the group-scoped huntDb
 * connection is privilege-limited to SELECT (see setupHuntRole in
 * orm/config/ormconfig-setup.ts); primaryDb and secondaryDb run as table owners.
 * This is a known open defect — do not read the guardrail call below as proof
 * that a query cannot write.
 */

import type { DataSource } from 'typeorm';
import fs from 'fs';
import { randomUUID } from 'crypto';
import { getLogger } from '../utils/logger';
import { validateSql, validateWsAction, validateRuleProposalShape, validateCorrelationProposalShape } from './guardrails';
import type { WsActionProposal } from './guardrails';
import { PRIMARY_SCHEMA, SECONDARY_SCHEMA, COMPLIANCE_KEY_DESCRIPTIONS, WS_PROTOCOL } from './schema/definitions';
import { createPendingAction } from '../services/pendingActions';
import { MAX_RESULT_ROWS_EXPORT } from './guardrails';
import { assertCanActOnHost, scopeGroupIds } from '../utils/nodeScope';
import type { NodeScope } from '../utils/nodeScope';
import { RLS_GROUP_SESSION_VAR } from '../consts/database';
import { validateRule as validateRuleWithEngine, validateCorrelationRule as validateCorrelationRuleWithEngine } from '../services/ruleEngineClient';

const logger = getLogger('mcp.executor');

const DB_QUERY_TIMEOUT_MS = 15_000;
const MAX_ROWS_HARD_CAP = MAX_RESULT_ROWS_EXPORT;

export interface ToolCallInput {
  name: string;
  input: Record<string, unknown>;
}

export interface ToolResult {
  content: string;
  is_error?: boolean;
}

export interface ExecutorContext {
  /** primary DB data source */
  primaryDb: DataSource;
  /** secondary (fleet) DB data source, owner role — used for unrestricted (global) callers */
  secondaryDb: DataSource;
  /**
   * Group-scoped historical-hunting connection (vajra_hunt) — same connection
   * run_query.ts uses. Undefined if the deployment hasn't provisioned the
   * role yet; only consulted when `scope` is restricted.
   */
  huntDb?: DataSource;
  /** id of the authenticated user driving this chat session */
  userId: number;
  /**
   * This caller's node-group access, resolved once per chat turn by
   * aiChat.ts. Every tool call in the turn shares it — execute_db_query uses
   * it to decide which connection to query on, propose_agent_action uses it
   * to reject hosts outside the caller's group(s) before a pending action is
   * ever created (the same check the WebSocket agent-command path applies,
   * so the AI can't reach a node the UI already hides from this caller).
   */
  scope: NodeScope;
}

/**
 * Execute a single tool call from the AI.
 * Returns a JSON string result to feed back to the AI.
 */
export async function executeTool(
  call: ToolCallInput,
  ctx: ExecutorContext,
): Promise<ToolResult> {
  try {
    switch (call.name) {
      case 'execute_db_query':
        return await handleDbQuery(call.input, ctx);
      case 'get_schema_info':
        return handleSchemaInfo(call.input);
      case 'propose_agent_action':
        return await handleProposeAction(call.input, ctx);
      case 'get_rule_engine_reference':
        return handleGetRuleEngineReference();
      case 'propose_rule':
        return await handleProposeRule(call.input, ctx);
      case 'propose_correlation_rule':
        return await handleProposeCorrelationRule(call.input, ctx);
      default:
        logger.warn({ toolName: call.name, userId: ctx.userId }, 'AI requested an unknown tool');
        return { content: `Unknown tool: ${call.name}`, is_error: true };
    }
  } catch (err) {
    logger.error({ err, toolName: call.name, userId: ctx.userId }, 'AI tool execution failed unexpectedly');
    const msg = err instanceof Error ? err.message : String(err);
    return { content: `Tool execution error: ${msg}`, is_error: true };
  }
}

// ─── Handler: execute_db_query ────────────────────────────────────────────────

async function handleDbQuery(
  input: Record<string, unknown>,
  ctx: ExecutorContext,
): Promise<ToolResult> {
  const db = input.db as 'primary' | 'secondary';
  const sql = input.sql as string;
  const params = (input.params as unknown[]) ?? [];

  if (db !== 'primary' && db !== 'secondary') {
    return { content: 'Invalid db parameter: must be "primary" or "secondary"', is_error: true };
  }
  if (typeof sql !== 'string') {
    return { content: 'Invalid sql parameter', is_error: true };
  }
  if (!Array.isArray(params)) {
    return { content: 'params must be an array', is_error: true };
  }

  // The primary database holds users, audit_logs, audit_trail and
  // user_sessions. Free-form SQL over it exposes far more than any single REST
  // endpoint does — routes/api/users.ts gates the audit, session and team
  // readers behind requireSuperAdmin, though GET /list and GET /by-id are
  // checkAccessJwt only — so the AI path is held to the stricter bar. Restrict
  // it to Super Administrators: ctx.scope.unrestricted is true exactly when the
  // caller holds that role (see getUserNodeScope in utils/nodeScope.ts).
  if (db === 'primary' && !ctx.scope.unrestricted) {
    logger.warn({ userId: ctx.userId }, 'AI database query rejected: primary DB requires Super Administrator');
    return { content: 'Primary database access requires Super Administrator privileges.', is_error: true };
  }

  const guard = validateSql(sql, params, db);
  if (!guard.valid) {
    logger.warn({ userId: ctx.userId, db, reason: guard.reason }, 'AI-generated SQL query rejected by guardrails');
    return { content: `SQL rejected by guardrails: ${guard.reason}`, is_error: true };
  }

  // validateSql already requires a LIMIT clause; this clamps its value so a
  // large one can't return more than the hard cap.
  const safeSql = injectMaxLimit(sql, MAX_ROWS_HARD_CAP);

  // Group-scoped callers querying the fleet ("secondary") database run on a
  // separate, lower-privilege connection (vajra_hunt), where row-level security
  // filters every host-keyed table down to the caller's groups no matter how the
  // SQL is phrased. This is the same mechanism the Threat Hunting box uses
  // (run_query.ts), so there is one enforcement path rather than two. Primary-DB
  // queries have no group concept and always use primaryDb.
  if (db === 'secondary' && !ctx.scope.unrestricted) {
    const groupIds = scopeGroupIds(ctx.scope);
    if (groupIds.length === 0) {
      return { content: JSON.stringify({ row_count: 0, rows: [] }) };
    }
    if (!ctx.huntDb) {
      return {
        content: 'Group-scoped historical hunting is not available on this deployment yet.',
        is_error: true,
      };
    }
    const groupsForSession = groupIds.join(',');
    const rows: unknown[] = await withTimeout(
      ctx.huntDb.transaction(async (manager) => {
        await manager.query(`SET LOCAL statement_timeout = '${DB_QUERY_TIMEOUT_MS}ms'`);
        // set_config(), not `SET LOCAL vajra.groups = $1`: SET is a utility
        // statement and Postgres rejects a bind parameter as its value, so that
        // form would fail on every call. set_config() takes real parameters, and
        // its third argument (true) makes it transaction-local, so a later
        // request on this pooled connection never inherits the group list.
        await manager.query('SELECT set_config($1, $2, true)', [RLS_GROUP_SESSION_VAR, groupsForSession]);
        return manager.query(safeSql, params);
      }),
      DB_QUERY_TIMEOUT_MS,
      'Database query timed out',
    );
    logger.debug({ userId: ctx.userId, db, groupScoped: true, rowCount: rows.length }, 'AI database query executed');
    return { content: buildQueryResultJson(rows) };
  }

  // Wrapped in a transaction, like the huntDb branch above, so SET LOCAL
  // statement_timeout bounds the query server-side. withTimeout only abandons
  // the JS promise; it does not cancel the query, so without this a runaway
  // query holds one of the pool's connections until the server finishes it.
  const em = db === 'primary' ? ctx.primaryDb : ctx.secondaryDb;
  const rows: unknown[] = await withTimeout(
    em.transaction(async (manager) => {
      await manager.query(`SET LOCAL statement_timeout = '${DB_QUERY_TIMEOUT_MS}ms'`);
      return manager.query(safeSql, params);
    }),
    DB_QUERY_TIMEOUT_MS,
    'Database query timed out',
  );

  logger.debug({ userId: ctx.userId, db, rowCount: rows.length }, 'AI database query executed');
  return { content: buildQueryResultJson(rows) };
}

function buildQueryResultJson(rows: unknown[]): string {
  return JSON.stringify({
    row_count: rows.length,
    rows,
    note: rows.length === MAX_ROWS_HARD_CAP
      ? `Result capped at ${MAX_ROWS_HARD_CAP} rows. Add a more specific WHERE clause to narrow results.`
      : undefined,
  });
}

/** Replace or enforce LIMIT to never exceed cap. */
function injectMaxLimit(sql: string, cap: number): string {
  const limitMatch = /\bLIMIT\s+(\d+)/i.exec(sql);
  if (limitMatch) {
    const existingLimit = parseInt(limitMatch[1], 10);
    if (existingLimit > cap) {
      return sql.replace(/\bLIMIT\s+\d+/i, `LIMIT ${cap}`);
    }
    return sql;
  }
  // No LIMIT — append one (should not happen after guardrail check)
  return `${sql.trimEnd()} LIMIT ${cap}`;
}

// ─── Handler: get_schema_info ─────────────────────────────────────────────────

function handleSchemaInfo(input: Record<string, unknown>): ToolResult {
  const topic = (input.topic as string) ?? 'all';

  let content: string;
  switch (topic) {
    case 'primary':
      content = PRIMARY_SCHEMA;
      break;
    case 'secondary':
      content = SECONDARY_SCHEMA;
      break;
    case 'compliance_keys':
      content = `18-Point Compliance Check Keys:\n${COMPLIANCE_KEY_DESCRIPTIONS}`;
      break;
    case 'ws_protocol':
      content = WS_PROTOCOL;
      break;
    case 'all':
    default:
      content = [PRIMARY_SCHEMA, SECONDARY_SCHEMA,
        `\n18-POINT COMPLIANCE KEYS:\n${COMPLIANCE_KEY_DESCRIPTIONS}`,
        `\nWEBSOCKET PROTOCOL:\n${WS_PROTOCOL}`,
      ].join('\n');
  }

  return { content };
}

// ─── Handler: propose_agent_action ────────────────────────────────────────────

async function handleProposeAction(
  input: Record<string, unknown>,
  ctx: ExecutorContext,
): Promise<ToolResult> {
  const proposal: WsActionProposal = {
    action_type: input.action_type as WsActionProposal['action_type'],
    host_identifier: input.host_identifier as string,
    params: input.params as Record<string, string> | undefined,
    description: input.description as string,
    risk: input.risk as WsActionProposal['risk'],
  };

  // patch_install/patch_uninstall run script content as SYSTEM, so they may only
  // be created through the Windows Patch Management REST route, which requires
  // Super Administrator plus fresh MFA and sources the script from the reviewed
  // maintained_app_versions catalog. They are absent from the AI tool schema in
  // mcp/tools.ts; reject them here too, because validateWsAction only checks the
  // payload's shape and this path has no Super Admin or MFA gate of its own.
  if (proposal.action_type === 'patch_install' || proposal.action_type === 'patch_uninstall') {
    logger.warn({ userId: ctx.userId, actionType: proposal.action_type }, 'AI-proposed agent action rejected: patch install/uninstall is not permitted via AI chat');
    return {
      content: JSON.stringify({
        error: 'patch_install/patch_uninstall are not available via AI chat. Direct the user to the Windows Patch Management UI (requires Super Administrator role and MFA).',
      }),
      is_error: true,
    };
  }

  const guard = validateWsAction(proposal);
  if (!guard.valid) {
    logger.warn({ userId: ctx.userId, actionType: proposal.action_type, reason: guard.reason }, 'AI-proposed agent action rejected by guardrails');
    return { content: `Action rejected by guardrails: ${guard.reason}`, is_error: true };
  }

  // The same scope check the WebSocket agent-command path applies, so the AI
  // cannot reach a node the UI hides from this caller and a read-only Group
  // Viewer cannot act through it. Runs before the lookup below so an
  // out-of-scope host's hostname and online status are not leaked either.
  if (!(await assertCanActOnHost(ctx.scope, proposal.host_identifier))) {
    logger.warn(
      { userId: ctx.userId, host_identifier: proposal.host_identifier, actionType: proposal.action_type },
      'AI-proposed agent action rejected: host outside caller scope'
    );
    return {
      content: JSON.stringify({
        error: 'You do not have access to this node',
        host_identifier: proposal.host_identifier,
      }),
      is_error: true,
    };
  }

  // Single query: fetch hostname + online status together
  let hostname: string | undefined;
  try {
    const rows = await ctx.secondaryDb.query(
      `SELECT hostname, agent_online, last_seen FROM nodes WHERE host_identifier = $1 LIMIT 1`,
      [proposal.host_identifier],
    );
    if (!rows?.length) {
      logger.info({ userId: ctx.userId, host_identifier: proposal.host_identifier }, 'AI-proposed agent action rejected: node not found');
      return {
        content: JSON.stringify({ error: 'Node not found', host_identifier: proposal.host_identifier }),
        is_error: true,
      };
    }
    const node = rows[0];
    hostname = node.hostname;
    const isOnline = node.agent_online === true || node.agent_online === 'true';
    if (!isOnline) {
      logger.info({ userId: ctx.userId, host_identifier: proposal.host_identifier, hostname }, 'AI-proposed agent action rejected: node offline');
      return {
        content: JSON.stringify({
          error: 'Node is currently offline — agent action cannot be dispatched',
          host_identifier: proposal.host_identifier,
          hostname,
          last_seen: node.last_seen,
        }),
        is_error: true,
      };
    }
  } catch (err) {
    // DB unavailable — block the action; do not proceed blind
    logger.error({ err, userId: ctx.userId, host_identifier: proposal.host_identifier }, 'Could not verify node status before AI-proposed action, blocking for safety');
    return {
      content: JSON.stringify({ error: 'Could not verify node status — action blocked for safety' }),
      is_error: true,
    };
  }

  const { id, action } = createPendingAction(proposal, hostname, ctx.userId);
  logger.info(
    { userId: ctx.userId, pendingActionId: id, host_identifier: action.host_identifier, actionType: action.action_type, risk: action.risk },
    'AI-proposed agent action created, awaiting confirmation'
  );

  return {
    content: JSON.stringify({
      pending_action_id: id,
      status: 'pending_confirmation',
      action_type: action.action_type,
      host_identifier: action.host_identifier,
      hostname,
      description: action.description,
      risk: action.risk,
      expires_in_seconds: Math.round((action.expires_at - Date.now()) / 1000),
      message: 'This action is waiting for your confirmation. Click "Confirm" in the interface to execute it.',
    }),
  };
}

// ─── Handler: get_rule_engine_reference ───────────────────────────────────────

// Source of truth: RULE_AUTHORING_TEMPLATE.md in the engine team's read-only reference repo
// (never written to from here, see docs/RULE_ENGINE_UI_SPEC.md's ground rules). Read live on
// every call rather than embedding a copy in this file, so this tool can never drift from the
// real engine team's maintained document. Unset by default — no deployment has that repo
// checked out at a fixed path, so a deployer must opt in via RULE_ENGINE_TEMPLATE_PATH (see
// .env.example) to get the live read; everyone else gets the embedded fallback below.
const RULE_ENGINE_TEMPLATE_PATH = process.env.RULE_ENGINE_TEMPLATE_PATH;

// Minimal fallback only, used if the live file can't be read (path moved, permissions,
// deployment without that repo checked out). Deliberately short — a stale full copy here
// would be exactly the "second, possibly-drifting schema description" this tool exists to
// avoid. Kept in sync loosely with RULE_AUTHORING_TEMPLATE.md §2/§5/§8 as of 2026-09.
const RULE_ENGINE_REFERENCE_FALLBACK = `
[FALLBACK — RULE_ENGINE_TEMPLATE_PATH is not set, or the live reference file at that path
could not be read. This is a minimal, possibly-stale summary. Treat it with more caution than
the live file.]

Real event_type values (NOT Postgres/osquery table names): win_process, win_socket, win_file,
win_registry, win_dns, win_dns_response, win_ssl, win_http, windows_eventlog, bpf_process,
bpf_socket, bpf_file.

Real condition operators: equals | not_equals | contains | not_contains | regex | exists | gt |
lt | gte | lte | between | in_list | in_list_active | startswith | endswith | cidr |
windash_contains | base64offset_contains. "value" is always a JSON string. There is no OR
primitive — split into multiple rules instead (one per branch, sharing common AND conditions).

Correlation rule types: event_count (needs "threshold"), value_count (needs "threshold" and
"field"), temporal (any order), temporal_ordered (kill-chain order). All four need "timespan"
(seconds) > 0.
`.trim();

function handleGetRuleEngineReference(): ToolResult {
  if (!RULE_ENGINE_TEMPLATE_PATH) {
    return { content: RULE_ENGINE_REFERENCE_FALLBACK };
  }
  try {
    const content = fs.readFileSync(RULE_ENGINE_TEMPLATE_PATH, 'utf8');
    return { content: `Source: ${RULE_ENGINE_TEMPLATE_PATH} (read live)\n\n${content}` };
  } catch (err) {
    logger.warn({ err, path: RULE_ENGINE_TEMPLATE_PATH }, 'Could not read live rule engine reference file; returning embedded fallback');
    return { content: RULE_ENGINE_REFERENCE_FALLBACK };
  }
}

// ─── Handler: propose_rule / propose_correlation_rule ─────────────────────────
//
// Mirrors handleProposeAction's safety shape: validate against the real system first
// (there, node liveness + guardrails; here, the real engine's own /validate endpoint —
// "never let the model's own idea of valid be the only check"), then return a pending
// proposal — NEVER call the real create/save endpoint. Unlike propose_agent_action,
// there is no server-side pending-action store or /confirm dispatch route for these:
// saving a rule is an ordinary authenticated POST a human triggers themselves from the
// Rule Builder UI (already gated by requireAdmin + CSRF on the real create route), not a
// privileged dispatch-to-agent action that needs a separate confirm step to execute. The
// proposal here is consumed entirely client-side (rendered as a card in the chat with
// "Load into builder" / "Discard" — see docs/RULE_ENGINE_UI_SPEC.md), so nothing to persist.

async function handleProposeRule(
  input: Record<string, unknown>,
  ctx: ExecutorContext,
): Promise<ToolResult> {
  const rule = input.rule;
  const shape = validateRuleProposalShape(rule);
  if (!shape.valid) {
    logger.warn({ userId: ctx.userId, reason: shape.reason }, 'AI-proposed rule rejected by shape guardrail');
    return { content: `Rule rejected before engine validation: ${shape.reason}`, is_error: true };
  }

  const result = await validateRuleWithEngine(rule);
  if (result.unreachable) {
    logger.error({ userId: ctx.userId }, 'AI-proposed rule could not be validated: rule engine unreachable');
    return { content: JSON.stringify({ error: 'Rule engine validation service is unreachable', detail: result.errorMessage }), is_error: true };
  }

  const engineResult = result.data as { ok?: boolean; message?: string } | undefined;
  if (result.status >= 400 || !engineResult?.ok) {
    logger.info({ userId: ctx.userId, status: result.status, engineMessage: engineResult?.message }, 'AI-proposed rule failed real engine validation');
    return {
      content: JSON.stringify({ valid: false, message: engineResult?.message ?? 'Rule engine rejected this rule', engine_status: result.status }),
      is_error: true,
    };
  }

  const proposalId = randomUUID();
  logger.info({ userId: ctx.userId, proposalId }, 'AI-proposed rule passed real engine validation; returning proposal, not saved');
  return {
    content: JSON.stringify({
      proposal_id: proposalId,
      proposal_type: 'rule',
      status: 'pending_proposal',
      valid: true,
      engine_message: engineResult.message,
      rule,
      message: 'This rule has been validated by the real engine but NOT saved. Click "Load into builder" in the chat, review it, then Save yourself to persist it.',
    }),
  };
}

async function handleProposeCorrelationRule(
  input: Record<string, unknown>,
  ctx: ExecutorContext,
): Promise<ToolResult> {
  const rule = input.correlation_rule;
  const shape = validateCorrelationProposalShape(rule);
  if (!shape.valid) {
    logger.warn({ userId: ctx.userId, reason: shape.reason }, 'AI-proposed correlation rule rejected by shape guardrail');
    return { content: `Correlation rule rejected before engine validation: ${shape.reason}`, is_error: true };
  }

  const result = await validateCorrelationRuleWithEngine(rule);
  if (result.unreachable) {
    logger.error({ userId: ctx.userId }, 'AI-proposed correlation rule could not be validated: rule engine unreachable');
    return { content: JSON.stringify({ error: 'Rule engine validation service is unreachable', detail: result.errorMessage }), is_error: true };
  }

  const engineResult = result.data as { ok?: boolean; message?: string; warnings?: unknown } | undefined;
  if (result.status >= 400 || !engineResult?.ok) {
    logger.info({ userId: ctx.userId, status: result.status, engineMessage: engineResult?.message }, 'AI-proposed correlation rule failed real engine validation');
    return {
      content: JSON.stringify({ valid: false, message: engineResult?.message ?? 'Rule engine rejected this correlation rule', engine_status: result.status }),
      is_error: true,
    };
  }

  const proposalId = randomUUID();
  logger.info({ userId: ctx.userId, proposalId }, 'AI-proposed correlation rule passed real engine validation; returning proposal, not saved');
  return {
    content: JSON.stringify({
      proposal_id: proposalId,
      proposal_type: 'correlation_rule',
      status: 'pending_proposal',
      valid: true,
      engine_message: engineResult.message,
      warnings: engineResult.warnings,
      correlation_rule: rule,
      message: 'This correlation rule has been validated by the real engine but NOT saved. Click "Load into builder" in the chat, review it, then Save yourself to persist it.',
    }),
  };
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function withTimeout<T>(promise: Promise<T>, ms: number, errorMessage: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(errorMessage)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}
