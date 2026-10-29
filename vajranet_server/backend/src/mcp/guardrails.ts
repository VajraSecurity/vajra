/**
 * Validates AI-generated SQL and WebSocket action proposals before execution.
 *
 * validateSql is a filter over untrusted model output, not a security boundary,
 * and it is known to be bypassable: mcp/executor.ts issues queries with an empty
 * parameter array, which makes node-postgres fall back to the simple query
 * protocol, so stacked statements that slip past the checks below still reach
 * the server. Treat everything here as one layer among several — the connection
 * role's privileges and row-level security are what actually constrain what a
 * query can do. Do not add a caller that relies on validateSql alone.
 */

// ─── SQL Guardrails ──────────────────────────────────────────────────────────

const FORBIDDEN_SQL_KEYWORDS = [
  'DELETE', 'INSERT', 'UPDATE', 'DROP', 'TRUNCATE', 'ALTER', 'CREATE',
  'GRANT', 'REVOKE', 'EXECUTE', 'CALL', 'DO', 'COPY', 'VACUUM', 'REINDEX',
  'CLUSTER', 'REFRESH', 'LOCK', 'COMMENT', 'SECURITY', 'OWNER',
];

// Regex: word boundary match, case-insensitive
const FORBIDDEN_SQL_REGEX = new RegExp(
  `\\b(${FORBIDDEN_SQL_KEYWORDS.join('|')})\\b`,
  'i',
);

// No semicolons after stripping string literals (prevents multi-statement injection)
const MULTI_STATEMENT_REGEX = /;(?!\s*$)/;

const MAX_SQL_LENGTH = 8000;
const MAX_PARAM_COUNT = 20;
const MAX_RESULT_ROWS = 500; // hard cap — AI should always add LIMIT

// vajra_users columns that must never be readable via the AI SQL tool,
// checked anywhere a column can appear (SELECT list, function args, WHERE,
// ORDER BY, subqueries) — not just the top-level SELECT list.
const SENSITIVE_COLUMNS = new Set([
  'password_hash',
  'mfa_secret',
  'recovery_codes',
  'security_question_1',
  'security_answer_1_hash',
  'security_question_2',
  'security_answer_2_hash',
]);

export interface GuardrailResult {
  valid: boolean;
  reason?: string;
}

import { Parser } from 'node-sql-parser';
import { randomUUID } from 'crypto';
import net from 'net';
import {
  RID_PREFIX_PATCH_JOB_ACK,
  RID_PREFIX_PATCH_CHECK,
  COMPLIANCE_KEY_RANGE,
  BLUETOOTH_DISABLE_KEY,
  BLUETOOTH_ENABLE_KEY,
  BLUETOOTH_STATUS_KEY,
} from '../consts/websocket';

/**
 * Validate AI-generated SQL before execution.
 * Returns {valid:true} or {valid:false, reason}.
 */
export function validateSql(
  sql: string,
  params: unknown[],
  db: 'primary' | 'secondary',
): GuardrailResult {
  const trimmed = sql.trim();

  if (!trimmed) return { valid: false, reason: 'SQL is empty' };
  if (trimmed.length > MAX_SQL_LENGTH) return { valid: false, reason: 'SQL too long' };
  if (params.length > MAX_PARAM_COUNT) return { valid: false, reason: 'Too many parameters' };

  // Reject any literal backslash outright. With standard_conforming_strings on
  // (the Postgres default), backslash is not an escape character: a '...' literal
  // ends at the very next quote, and only a doubled '' escapes one. Both the
  // string-stripping regex below and node-sql-parser instead read \' as an
  // escaped quote and keep going, so a payload can fold an entire UNION SELECT
  // into what they believe is string content while Postgres parses it as real
  // SQL — hiding it from every check below. Legitimate SELECTs never need a raw
  // backslash, so rejecting it closes the whole differential rather than one half.
  if (trimmed.includes('\\')) {
    return { valid: false, reason: 'Backslash characters are not allowed in SQL' };
  }

  // Must start with SELECT or WITH (for CTEs)
  if (!/^(SELECT|WITH)\b/i.test(trimmed)) {
    return { valid: false, reason: 'Only SELECT (or WITH ... SELECT) queries are allowed' };
  }

  // Strip string literals first so keywords and ';' inside them don't trip the
  // checks below. Matches Postgres literal syntax: a '...' string ends at the
  // next quote unless doubled. Backslash has no escaping role here, which is why
  // the rejection above is the primary defense; this is a second layer.
  const stripped = trimmed.replace(/'(?:[^']|'')*'/g, "''");

  // No forbidden keywords (checked against string-stripped text so a search term
  // like '%delete%' inside a quoted literal doesn't trigger a false rejection).
  const match = FORBIDDEN_SQL_REGEX.exec(stripped);
  if (match) {
    return { valid: false, reason: `Forbidden SQL keyword detected: ${match[1]}` };
  }

  // No multi-statement (semicolons mid-query)
  if (MULTI_STATEMENT_REGEX.test(stripped)) {
    return { valid: false, reason: 'Multi-statement SQL is not allowed' };
  }

  // No SQL comments (-- or /* */) that could hide injections
  if (/--/.test(stripped) || /\/\*/.test(stripped)) {
    return { valid: false, reason: 'SQL comments are not allowed' };
  }

  // Validate that LIMIT exists (prevent runaway queries). Checked against the
  // string-stripped text — same reasoning as the forbidden-keyword check above —
  // so a quoted literal containing the text "LIMIT 5" can't satisfy this without
  // a real LIMIT clause.
  if (!/\bLIMIT\b/i.test(stripped)) {
    return { valid: false, reason: 'SQL must include a LIMIT clause to bound result size' };
  }

  // Parse the SQL query into an AST to reliably detect table and column usage.
  //
  // node-sql-parser represents identifiers inconsistently depending on context
  // (plain strings, or {value:...}/{expr:{value:...}} wrapper objects), so all
  // identifier extraction goes through getIdentifierName() below rather than
  // assuming one shape.
  try {
    const parser = new Parser();
    const astArray = parser.astify(trimmed, { database: 'Postgresql' });
    const astList = Array.isArray(astArray) ? astArray : [astArray];

    const getIdentifierName = (value: any): string => {
      if (typeof value === 'string') return value;
      if (value && typeof value.value === 'string') return value.value;
      if (value && typeof value.expr?.value === 'string') return value.expr.value;
      return '';
    };

    for (const ast of astList) {
        // `SELECT ... INTO new_table FROM ...` is syntactically a SELECT (passes the
        // prefix check above) but is DDL — it creates and populates a persistent table.
        // Every parsed SELECT carries an `into` node (e.g. `{position: null}` when
        // absent), so check its `expr`, not just presence of the node itself — that's
        // what's actually set (e.g. `evil_table`) when an INTO target is present.
        if ((ast as any)?.into?.expr) {
          return { valid: false, reason: 'SELECT INTO is not allowed — queries may only read data, not create tables' };
        }

        let hasVajraUsers = false;
        let selectsAllColumns = false;
        let sensitiveColumnAccessed = false;
        let wholeRowReference = false;
        // Aliases (and the bare table name) that refer to the vajra_users row —
        // passing one of these bare into a function (row_to_json(u), to_jsonb(vajra_users),
        // json_agg(t)) hands over every column, sensitive or not.
        const vajraUsersAliases = new Set<string>(['vajra_users']);

        // Pass 1: find every `FROM`/`JOIN` table entry for vajra_users and record its alias.
        function collectAliases(node: any) {
          if (!node) return;
          const tableName = typeof node.table === 'string' ? node.table : '';
          if (tableName.toLowerCase() === 'vajra_users') {
            hasVajraUsers = true;
            const alias = getIdentifierName(node.as);
            if (alias) vajraUsersAliases.add(alias.toLowerCase());
          }
          for (const key of Object.keys(node)) {
            const val = node[key];
            if (Array.isArray(val)) val.forEach(collectAliases);
            else if (val && typeof val === 'object') collectAliases(val);
          }
        }
        collectAliases(ast);

        if (hasVajraUsers) {
          // Pass 2: inspect every column reference anywhere in the statement —
          // SELECT list, function/aggregate args, WHERE, GROUP BY, ORDER BY, subqueries —
          // not just the top-level SELECT list.
          function traverse(node: any) {
            if (!node) return;

            if (node.type === 'column_ref') {
              const colName = getIdentifierName(node.column);
              if (colName === '*') {
                selectsAllColumns = true;
              } else if (colName) {
                const lower = colName.toLowerCase();
                const tableQualifier = getIdentifierName(node.table);
                if (!tableQualifier && vajraUsersAliases.has(lower)) {
                  // A bare identifier equal to the table/alias name, used where a
                  // column was expected — e.g. row_to_json(u), to_jsonb(vajra_users).
                  // That hands the whole row (including sensitive columns) to the function.
                  wholeRowReference = true;
                } else if (SENSITIVE_COLUMNS.has(lower)) {
                  sensitiveColumnAccessed = true;
                }
              }
            }

            for (const key of Object.keys(node)) {
              const val = node[key];
              if (Array.isArray(val)) val.forEach(traverse);
              else if (val && typeof val === 'object') traverse(val);
            }
          }
          traverse(ast);

          if (selectsAllColumns) {
            return { valid: false, reason: 'Cannot use SELECT * on table vajra_users to prevent exposing sensitive data' };
          }
          if (wholeRowReference) {
            return { valid: false, reason: 'Cannot pass the entire vajra_users row (e.g. row_to_json(alias), to_jsonb(vajra_users), json_agg(alias)) to a function — select individual non-sensitive columns instead' };
          }
          if (sensitiveColumnAccessed) {
            return { valid: false, reason: 'Query references a protected vajra_users column (password_hash, mfa_secret, recovery_codes, security question/answer). This data is not accessible via the AI tool.' };
          }
        }
    }

  } catch (err) {
    // Unparseable SQL is rejected rather than passed through: the checks below
    // the parse all depend on the AST, so a parse failure means they never ran.
    return { valid: false, reason: 'Invalid SQL syntax or unsupported query structure' };
  }

  // Routing between the primary and secondary databases is enforced by the
  // executor, not here; `db` is part of the signature for future use only.
  void db;

  return { valid: true };
}

// ─── WS Action Guardrails ────────────────────────────────────────────────────

export type WsActionType =
  | 'compliance_check'
  | 'isolate_node'
  | 'reenroll_node'
  | 'block_port'
  | 'unblock_port'
  | 'block_ip'
  | 'unblock_ip'
  | 'disable_usb'
  | 'enable_usb'
  | 'disable_bluetooth'
  | 'enable_bluetooth'
  | 'bluetooth_status'
  | 'disable_usb_mobile'
  | 'enable_usb_mobile'
  | 'disable_usb_all'
  | 'enable_usb_all'
  | 'patch_install'
  | 'patch_uninstall'
  | 'patch_check';

export interface WsActionProposal {
  action_type: WsActionType;
  host_identifier: string;
  /** Extra params depending on action (port, ip, protocol, etc.) */
  params?: Record<string, string>;
  /** Human-readable explanation of what this action does */
  description: string;
  /** Risk level for UI display */
  risk: 'low' | 'medium' | 'high';
}

// patch_check is deliberately absent even though it is a WsActionType with a
// buildWsPayload case below: the agent's reply has nowhere to go. The
// "patch_check:" rid branch in websocket/node.ts only logs it — no persistence,
// broadcast or UI surface — so proposing it would be a silent dead end. Add it
// here only once a delivery path back to the chat session exists.
const ALLOWED_ACTION_TYPES = new Set<WsActionType>([
  'compliance_check', 'isolate_node', 'reenroll_node',
  'block_port', 'unblock_port', 'block_ip', 'unblock_ip',
  'disable_usb', 'enable_usb',
  'disable_bluetooth', 'enable_bluetooth', 'bluetooth_status',
  'disable_usb_mobile', 'enable_usb_mobile',
  'disable_usb_all', 'enable_usb_all',
  'patch_install', 'patch_uninstall',
]);

// Windows maintained-app job ids are woven directly into the agent's
// scheduled-task name and file paths — same charset the agent itself
// enforces (WINDOWS_AGENT_PATCH_MANAGEMENT.md's "Injection safety" section).
const PATCH_JOB_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Structurally valid IPv4/IPv6 address, optionally with a CIDR prefix
 * (e.g. "10.0.0.0/24", "::1/128"). Uses Node's net.isIP() for the address
 * part instead of a bare character-class regex.
 */
function isValidIpOrCidr(value: string): boolean {
  const slashIdx = value.indexOf('/');
  const addr = slashIdx === -1 ? value : value.slice(0, slashIdx);
  const version = net.isIP(addr);
  if (version === 0) return false;
  if (slashIdx === -1) return true;
  const prefix = value.slice(slashIdx + 1);
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const prefixNum = parseInt(prefix, 10);
  const maxPrefix = version === 4 ? 32 : 128;
  return prefixNum >= 0 && prefixNum <= maxPrefix;
}

/**
 * Structural check on a patch_install/patch_uninstall job_payload before it
 * reaches the agent. Defense in depth only: the source of truth is the
 * maintained_app_versions row the caller built the payload from (see
 * controllers/nodes/windows_patch_management.ts), which already enforces the
 * installer_url and sha256 pairing at write time.
 */
function validatePatchJobPayload(raw: string | undefined, action: 'install' | 'uninstall'): GuardrailResult {
  if (!raw) return { valid: false, reason: 'job_payload is required' };
  let payload: any;
  try {
    payload = JSON.parse(raw);
  } catch {
    return { valid: false, reason: 'job_payload must be valid JSON' };
  }
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'job_payload must be a JSON object' };
  }
  if (!payload.app_slug || typeof payload.app_slug !== 'string') {
    return { valid: false, reason: 'job_payload.app_slug is required' };
  }
  if (!payload.display_name_match || typeof payload.display_name_match !== 'string') {
    return { valid: false, reason: 'job_payload.display_name_match is required' };
  }
  if (action === 'install' && (!payload.install_script || typeof payload.install_script !== 'string')) {
    return { valid: false, reason: 'job_payload.install_script is required for install' };
  }
  if (action === 'uninstall' && (!payload.uninstall_script || typeof payload.uninstall_script !== 'string')) {
    return { valid: false, reason: 'job_payload.uninstall_script is required for uninstall' };
  }
  const hasUrl = payload.installer_url != null && payload.installer_url !== '';
  const hasSha = payload.sha256 != null && payload.sha256 !== '';
  if (hasUrl !== hasSha) {
    return { valid: false, reason: 'job_payload.installer_url and sha256 must be supplied together or not at all' };
  }
  return { valid: true };
}

/**
 * Validate a proposed WS action before creating a pending action.
 */
export function validateWsAction(proposal: WsActionProposal): GuardrailResult {
  if (!ALLOWED_ACTION_TYPES.has(proposal.action_type)) {
    return { valid: false, reason: `Unknown action type: ${proposal.action_type}` };
  }

  if (!proposal.host_identifier || typeof proposal.host_identifier !== 'string') {
    return { valid: false, reason: 'host_identifier is required' };
  }

  // host_identifier: UUID format or reasonable alphanumeric
  if (!/^[a-zA-Z0-9_\-.]{1,128}$/.test(proposal.host_identifier)) {
    return { valid: false, reason: 'Invalid host_identifier format' };
  }

  // Port actions need port + protocol
  if (proposal.action_type === 'block_port' || proposal.action_type === 'unblock_port') {
    const port = proposal.params?.port;
    const proto = proposal.params?.protocol;
    if (!port || !/^\d{1,5}$/.test(port) || parseInt(port, 10) < 1 || parseInt(port, 10) > 65535) {
      return { valid: false, reason: 'Valid port (1-65535) required' };
    }
    if (!proto || !['tcp', 'udp'].includes(proto.toLowerCase())) {
      return { valid: false, reason: 'Protocol must be tcp or udp' };
    }
  }

  // IP actions need ip + direction
  if (proposal.action_type === 'block_ip' || proposal.action_type === 'unblock_ip') {
    const ip = proposal.params?.ip;
    const dir = proposal.params?.direction;
    // Structural IPv4/IPv6/CIDR validation
    if (!ip || !isValidIpOrCidr(ip)) {
      return { valid: false, reason: 'Valid IP address required' };
    }
    if (!dir || !['inbound', 'outbound'].includes(dir.toLowerCase())) {
      return { valid: false, reason: 'Direction must be inbound or outbound' };
    }
  }

  // Windows maintained-app install/uninstall need a validated job_id + job_payload.
  if (proposal.action_type === 'patch_install' || proposal.action_type === 'patch_uninstall') {
    const jobId = proposal.params?.job_id;
    if (!jobId || !PATCH_JOB_ID_REGEX.test(jobId)) {
      return { valid: false, reason: 'Valid job_id required (matching ^[A-Za-z0-9_-]{1,64}$)' };
    }
    const payloadCheck = validatePatchJobPayload(
      proposal.params?.job_payload,
      proposal.action_type === 'patch_install' ? 'install' : 'uninstall',
    );
    if (!payloadCheck.valid) return payloadCheck;
  }

  // Windows maintained-app on-demand check needs a check_payload array.
  if (proposal.action_type === 'patch_check') {
    const raw = proposal.params?.check_payload;
    if (!raw) return { valid: false, reason: 'check_payload is required' };
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { valid: false, reason: 'check_payload must be valid JSON' };
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return { valid: false, reason: 'check_payload must be a non-empty JSON array' };
    }
  }

  return { valid: true };
}

/**
 * Build the actual WS payload from a validated action proposal.
 * This is what gets sent to the agent extension.
 */
export function buildWsPayload(
  proposal: WsActionProposal,
): Record<string, unknown> {
  const base = { host_identifier: proposal.host_identifier };

  switch (proposal.action_type) {
    case 'compliance_check':
      return {
        ...base,
        type: 'agent',
        params: {
          agent: 'powershell',
          action: 'allow',
          command_keys: COMPLIANCE_KEY_RANGE,
        },
      };
    case 'isolate_node':
      return { ...base, type: 'agent', params: { agent: 'networkManager', action: 'block', arg1: '1234' } };
    case 'reenroll_node':
      return { ...base, type: 'agent', params: { agent: 'networkManager', action: 'allow', arg1: '1234' } };
    case 'block_port':
      return { ...base, type: 'agent', params: { agent: 'port', action: 'block', arg1: proposal.params!.port, arg2: proposal.params!.protocol } };
    case 'unblock_port':
      return { ...base, type: 'agent', params: { agent: 'port', action: 'unblock', arg1: proposal.params!.port, arg2: proposal.params!.protocol } };
    case 'block_ip':
      return { ...base, type: 'agent', params: { agent: 'ip', action: 'block', arg1: proposal.params!.ip, arg2: proposal.params!.direction } };
    case 'unblock_ip':
      return { ...base, type: 'agent', params: { agent: 'ip', action: 'unblock', arg1: proposal.params!.ip, arg2: proposal.params!.direction } };
    case 'disable_usb':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'disable' } };
    case 'enable_usb':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'enable' } };
    case 'disable_bluetooth':
      return { ...base, type: 'agent', params: { agent: 'powershell', action: 'allow', command_keys: [BLUETOOTH_DISABLE_KEY] } };
    case 'enable_bluetooth':
      return { ...base, type: 'agent', params: { agent: 'powershell', action: 'allow', command_keys: [BLUETOOTH_ENABLE_KEY] } };
    case 'bluetooth_status':
      return { ...base, type: 'agent', params: { agent: 'powershell', action: 'allow', command_keys: [BLUETOOTH_STATUS_KEY] } };
    case 'disable_usb_mobile':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'disable_mobile' } };
    case 'enable_usb_mobile':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'enable_mobile' } };
    case 'disable_usb_all':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'disable_all' } };
    case 'enable_usb_all':
      return { ...base, type: 'agent', params: { agent: 'removableDevice', action: 'enable_all' } };
    // patch_install/patch_uninstall carry a synthetic rid ("patch_job_ack:<job_id>")
    // so the agent's immediate accept/reject reply routes back to this exact
    // windows_patch_jobs row (see the patch_job_ack: branch in websocket/node.ts).
    // Completion arrives later on a separate rid, "patch_job_push".
    case 'patch_install':
      return {
        ...base,
        rid: `${RID_PREFIX_PATCH_JOB_ACK}${proposal.params!.job_id}`,
        type: 'agent',
        params: { agent: 'patchManagement', action: 'install', arg1: proposal.params!.job_id, arg2: proposal.params!.job_payload },
      };
    case 'patch_uninstall':
      return {
        ...base,
        rid: `${RID_PREFIX_PATCH_JOB_ACK}${proposal.params!.job_id}`,
        type: 'agent',
        params: { agent: 'patchManagement', action: 'uninstall', arg1: proposal.params!.job_id, arg2: proposal.params!.job_payload },
      };
    // patch_check needs its own sentinel rid ("patch_check:<uuid>"). The agent
    // echoes back whatever rid it was sent, and websocket/utils.ts's
    // ValidateExtResponse requires a non-empty string rid, so omitting it would
    // get the reply silently rejected.
    case 'patch_check':
      return {
        ...base,
        rid: `${RID_PREFIX_PATCH_CHECK}${randomUUID()}`,
        type: 'agent',
        params: { agent: 'patchManagement', action: 'check', arg1: '', arg2: proposal.params!.check_payload },
      };
  }
}

export const MAX_RESULT_ROWS_EXPORT = MAX_RESULT_ROWS;

// ─── Rule Engine proposal guardrails ─────────────────────────────────────────
//
// Cheap structural checks only, run before propose_rule/propose_correlation_rule
// (mcp/executor.ts) ever spends a network round trip / engine subprocess spawn
// on the model's output. This is NOT the real validation — per
// docs/RULE_ENGINE_UI_SPEC.md, "never let the model's own idea of valid be the
// only check": the actual guardrail is the real engine's own
// POST /rules/validate|/correlation-rules/validate, called via
// services/ruleEngineClient.ts. These checks only reject obviously-malformed
// or oversized input early, with a clear reason, mirroring how validateWsAction
// above is a shape check, not the sole safety boundary.

const MAX_RULE_PROPOSAL_JSON_BYTES = 32_000;
const CORRELATION_TYPES = new Set(['event_count', 'value_count', 'temporal', 'temporal_ordered']);

function jsonByteLength(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
  } catch {
    return Infinity;
  }
}

/** Structural check for a detection-rule proposal (mcp/executor.ts's propose_rule). Mirrors RULE_AUTHORING_TEMPLATE.md §1's required fields. */
export function validateRuleProposalShape(rule: unknown): GuardrailResult {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    return { valid: false, reason: 'rule must be a single JSON object (the rule itself, not a {"rules": [...]} wrapper)' };
  }
  const r = rule as Record<string, unknown>;
  if ('rules' in r || 'correlations' in r) {
    return { valid: false, reason: 'rule must be the bare rule object, not wrapped in {"rules": [...]}' };
  }
  if (typeof r.event_type !== 'string' || !r.event_type.trim()) {
    return { valid: false, reason: 'rule.event_type is required (a real engine wire value, e.g. win_process, bpf_socket — see get_rule_engine_reference)' };
  }
  if (!Array.isArray(r.conditions) || r.conditions.length === 0) {
    return { valid: false, reason: 'rule.conditions must be a non-empty array' };
  }
  if (jsonByteLength(rule) > MAX_RULE_PROPOSAL_JSON_BYTES) {
    return { valid: false, reason: `rule JSON exceeds ${MAX_RULE_PROPOSAL_JSON_BYTES} bytes` };
  }
  return { valid: true };
}

/** Structural check for a correlation-rule proposal (mcp/executor.ts's propose_correlation_rule). Mirrors RULE_AUTHORING_TEMPLATE.md §8's required fields. */
export function validateCorrelationProposalShape(rule: unknown): GuardrailResult {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    return { valid: false, reason: 'correlation_rule must be a single JSON object (the correlation rule itself, not a {"correlations": [...]} wrapper)' };
  }
  const r = rule as Record<string, unknown>;
  if ('rules' in r === false) {
    return { valid: false, reason: 'correlation_rule.rules is required (array of detection-rule ids this correlation references)' };
  }
  if ('correlations' in r) {
    return { valid: false, reason: 'correlation_rule must be the bare correlation object, not wrapped in {"correlations": [...]}' };
  }
  if (typeof r.type !== 'string' || !CORRELATION_TYPES.has(r.type)) {
    return { valid: false, reason: `correlation_rule.type must be one of: ${[...CORRELATION_TYPES].join(', ')}` };
  }
  if (!Array.isArray(r.rules) || r.rules.length === 0) {
    return { valid: false, reason: 'correlation_rule.rules must be a non-empty array of detection-rule ids' };
  }
  if (typeof r.timespan !== 'number' || !(r.timespan > 0)) {
    return { valid: false, reason: 'correlation_rule.timespan must be a positive number of seconds' };
  }
  if (r.type === 'event_count' && typeof r.threshold !== 'number') {
    return { valid: false, reason: 'correlation_rule.threshold (number) is required for type "event_count"' };
  }
  if (r.type === 'value_count' && (typeof r.threshold !== 'number' || typeof r.field !== 'string')) {
    return { valid: false, reason: 'correlation_rule.threshold (number) and .field (string) are required for type "value_count"' };
  }
  if (jsonByteLength(rule) > MAX_RULE_PROPOSAL_JSON_BYTES) {
    return { valid: false, reason: `correlation_rule JSON exceeds ${MAX_RULE_PROPOSAL_JSON_BYTES} bytes` };
  }
  return { valid: true };
}
