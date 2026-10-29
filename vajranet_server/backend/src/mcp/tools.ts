/**
 * MCP-compatible tool definitions in Anthropic tool_use format.
 * These are passed to the Anthropic API on every chat request.
 * The executor (executor.ts) maps tool names to their implementations.
 */

import type Anthropic from '@anthropic-ai/sdk';

export const AI_TOOLS: Anthropic.Tool[] = [
  {
    name: 'execute_db_query',
    description: `Execute a read-only SELECT query against the Vajra database.
Use "primary" for user/auth tables (vajra_users, audit_logs, audit_trail, user_sessions).
Use "secondary" for fleet tables (nodes, alerts, compliance_results, historical_compliance, windows_*, etc.).
Always use parameterized queries ($1, $2 …) — never interpolate values directly.
Always include LIMIT to bound results (max 500 rows).
Never query password_hash from vajra_users.`,
    input_schema: {
      type: 'object' as const,
      properties: {
        db: {
          type: 'string',
          enum: ['primary', 'secondary'],
          description: 'Which database to query. primary=users/auth, secondary=fleet/nodes/alerts.',
        },
        sql: {
          type: 'string',
          description: 'The SELECT SQL statement. Use $1, $2 … for parameters. Must include LIMIT.',
        },
        params: {
          type: 'array',
          items: { type: ['string', 'number', 'boolean', 'null'] },
          description: 'Ordered list of parameter values matching $1, $2 … in the SQL.',
        },
      },
      required: ['db', 'sql', 'params'],
    },
  },
  {
    name: 'get_schema_info',
    description: `Return the full database schema and feature documentation.
Call this when you need to look up table/column names, understand data relationships,
or verify the 18 compliance check key mappings.`,
    input_schema: {
      type: 'object' as const,
      properties: {
        topic: {
          type: 'string',
          enum: ['all', 'primary', 'secondary', 'compliance_keys', 'ws_protocol'],
          description: 'Which part of the schema to return.',
        },
      },
      required: ['topic'],
    },
  },
  {
    name: 'propose_agent_action',
    description: `Propose a WebSocket command to be sent to an agent running on a specific node.
THIS DOES NOT EXECUTE IMMEDIATELY. It creates a pending action that requires
explicit human approval from the user before being dispatched.

IMPORTANT: Always verify the node is online (agent_online=true, or last_seen fresh)
before proposing any action. If the node is offline, tell the user instead.

Use this for: compliance checks, isolation/reenrollment, port/IP blocking, USB/Bluetooth control.

NOTE: Windows maintained-app install/uninstall (patch_install/patch_uninstall) and the on-demand
installed-version check (patch_check) are NOT available through this tool. patch_install/
patch_uninstall run arbitrary script content as SYSTEM on the target host and must go through the
dedicated Windows Patch Management UI, which requires Super Administrator role and a fresh MFA
challenge and sources script content exclusively from the reviewed maintained_app_versions catalog
— never from free-form input. patch_check has no delivery path back to this chat session (the
agent's reply arrives asynchronously over a channel this tool has no way to read), so it would
silently produce no observable answer; the availability list already shown to the user is computed
from already-synced inventory and answers "is X installed" without it. Tell the user to use the
Patch Management UI instead if they ask to install/uninstall or check installed versions of software.`,
    input_schema: {
      type: 'object' as const,
      properties: {
        action_type: {
          type: 'string',
          enum: [
            'compliance_check',
            'isolate_node',
            'reenroll_node',
            'block_port',
            'unblock_port',
            'block_ip',
            'unblock_ip',
            'disable_usb',
            'enable_usb',
            'disable_usb_mobile',
            'enable_usb_mobile',
            'disable_usb_all',
            'enable_usb_all',
            'disable_bluetooth',
            'enable_bluetooth',
            'bluetooth_status',
          ],
          description: `The type of agent action to perform.
disable_usb = block USB mass storage (Tier 1: flash drives/HDDs).
disable_usb_mobile = block phones/cameras via MTP/PTP policy (Tier 2).
disable_usb_all = block ALL USB ports including keyboard/mouse (Tier 3, risk=high — always warn user, RDP required).
enable_usb / enable_usb_mobile / enable_usb_all = restore the corresponding tier.
disable_bluetooth = 9-layer Windows BT lockdown (key 47).
enable_bluetooth = restore Bluetooth (key 48).
bluetooth_status = read-only BT status check (key 55).
patch_install/patch_uninstall/patch_check are intentionally not offered here — see the tool description.`,
        },
        host_identifier: {
          type: 'string',
          description: 'The unique host_identifier (UUID) of the target node.',
        },
        params: {
          type: 'object',
          description: 'Action-specific parameters. For port actions: {port, protocol}. For IP actions: {ip, direction}. For patch actions: see below.',
          properties: {
            port: { type: 'string', description: 'Port number (for block/unblock_port)' },
            protocol: { type: 'string', enum: ['tcp', 'udp'], description: 'Protocol (for port actions)' },
            ip: { type: 'string', description: 'IP address or CIDR (for block/unblock_ip)' },
            direction: { type: 'string', enum: ['inbound', 'outbound'], description: 'Traffic direction (for IP actions)' },
            app_slug: { type: 'string', description: 'maintained_apps.slug (for patch_install/patch_uninstall)' },
            job_id: { type: 'string', description: 'A fresh, unique job id matching ^[A-Za-z0-9_-]{1,64}$ (for patch_install/patch_uninstall)' },
            job_payload: {
              type: 'string',
              description: 'JSON-stringified {app_slug, version, installer_url, sha256, install_script|uninstall_script, display_name_match, fuzzy, timeout_seconds}, built from the app\'s current maintained_app_versions row (for patch_install/patch_uninstall).',
            },
          },
        },
        description: {
          type: 'string',
          description: 'Human-readable explanation of WHY this action is being proposed. Be specific.',
        },
        risk: {
          type: 'string',
          enum: ['low', 'medium', 'high'],
          description: 'Risk level: low=reversible/read-like, medium=disruptive but reversible, high=potentially impactful.',
        },
      },
      required: ['action_type', 'host_identifier', 'description', 'risk'],
    },
  },
  {
    name: 'get_rule_engine_reference',
    description: `Return the detection/correlation rule DSL reference for vajra_engine (the separate
rule engine this platform's Rule Engine section manages): the real event_type list, the real
condition operator list, required fields, worked JSON examples, and the correlation rule types
(event_count, value_count, temporal, temporal_ordered). Sourced live from the engine team's own
authoring template so it never drifts from the real engine's loader.

Call this BEFORE calling propose_rule or propose_correlation_rule so any rule/correlation you build
uses real event_type values and real operators — do not guess or reuse Sigma-style names
(e.g. "win_process_events" and "endswith"-as-typed-in-Sigma are both wrong; the real values are
documented in this tool's output).`,
    input_schema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'propose_rule',
    description: `Propose a new vajra_engine detection rule from a fully-formed rule JSON object.
THIS DOES NOT SAVE THE RULE. It validates the rule against the REAL rule engine (the same
POST /rules/validate call the human-facing Rule Builder uses) and returns a pending proposal for
the user to review in the chat UI. The user must explicitly click "Load into builder" and then
"Save" themselves in the Rule Engine UI for anything to actually be persisted — this tool has no
path to the real create/save endpoint at all.

Always call get_rule_engine_reference first if you have not already in this conversation, so the
rule you build uses real event_type values and real operators. If validation fails, the exact
engine error is returned — fix the rule and call this tool again; do not tell the user it worked
until the tool result says valid.`,
    input_schema: {
      type: 'object' as const,
      properties: {
        rule: {
          type: 'object',
          description: 'The complete detection rule JSON object: {id?, event_type, level?, description, groups?, mitre?, conditions: [{field, op, value, icase?}, ...]}. Not wrapped in {"rules": [...]}.',
        },
      },
      required: ['rule'],
    },
  },
  {
    name: 'propose_correlation_rule',
    description: `Propose a new vajra_engine correlation rule (connects multiple detection rules into one
incident) from a fully-formed correlation rule JSON object. THIS DOES NOT SAVE THE RULE — same
validate-then-propose, human-must-confirm-in-the-UI pattern as propose_rule. Validates against the
REAL engine (POST /correlation-rules/validate) and returns a pending proposal; never calls the real
create/save endpoint.

Always call get_rule_engine_reference first if you have not already in this conversation. The four
real correlation types are event_count (needs "threshold"), value_count (needs "threshold" and
"field"), temporal (any order), and temporal_ordered (kill-chain order, like the ordered graph the
Rule Engine UI's correlation builder draws) — all four need "timespan" (seconds) > 0.`,
    input_schema: {
      type: 'object' as const,
      properties: {
        correlation_rule: {
          type: 'object',
          description: 'The complete correlation rule JSON object: {id?, type, description, rules: [<detection rule ids>], group_by?, timespan, level?, groups?, mitre?, threshold?, field?}. Not wrapped in {"correlations": [...]}.',
        },
      },
      required: ['correlation_rule'],
    },
  },
];
