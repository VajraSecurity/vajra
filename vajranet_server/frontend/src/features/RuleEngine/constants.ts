/**
 * Fixed, bounded vocabularies for the Rule Engine UI — driving every dropdown
 * / multi-select per the explicit UX requirement in docs/RULE_ENGINE_UI_SPEC.md
 * ("minimize free-text entry — use dropdowns / multi-select checkboxes
 * wherever the value comes from a known, bounded vocabulary").
 *
 * Source of truth for each list is cited inline. These are read-only
 * references from the sibling repo `~/Videos/vajra_server` (never edited,
 * per this engagement's ground rules) — re-verify against the cited file if
 * this ever looks stale.
 */

/**
 * Real wire-format event_type values, from
 * `~/Videos/vajra_server/engine_v2/src/Decoder.cpp`'s `alias_table()` (the
 * authoritative list per RULE_AUTHORING_TEMPLATE.md §2 — NOT Postgres/osquery
 * table names, e.g. `win_process` not `win_process_events`). Confirmed via
 * `grep -n '{"' Decoder.cpp` on 2026-09-17: 12 real values.
 */
export const EVENT_TYPES = [
  'bpf_process',
  'bpf_socket',
  'bpf_file',
  'win_process',
  'win_socket',
  'win_file',
  'win_dns',
  'win_dns_response',
  'win_ssl',
  'win_http',
  'win_registry',
  'windows_eventlog',
] as const;
export type EventType = typeof EVENT_TYPES[number];

/** IP Watch Groups default to these two event_types when none are chosen — API_CONTRACT_V2.md §2. */
export const DEFAULT_IP_WATCH_EVENT_TYPES: EventType[] = ['bpf_socket', 'win_socket'];

/**
 * The full real condition operator list — RULE_AUTHORING_TEMPLATE.md §5.
 * Anything not in this list is not just "invalid" — one unrecognized op
 * anywhere in a combined ruleset silently drops the WHOLE ruleset and falls
 * back to 6 built-in rules (RULE_AUTHORING_TEMPLATE.md's "What was actually
 * wrong" #3). Never allow free text here.
 */
export const OPERATORS = [
  'equals', 'not_equals', 'contains', 'not_contains', 'regex', 'exists',
  'gt', 'lt', 'gte', 'lte', 'between', 'in_list', 'in_list_active',
  'startswith', 'endswith', 'cidr', 'windash_contains', 'base64offset_contains',
] as const;

export const OPERATOR_LABELS: Record<string, string> = {
  equals: 'equals',
  not_equals: 'not equals',
  contains: 'contains',
  not_contains: 'does not contain',
  regex: 'matches regex',
  exists: 'field exists',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  between: 'between (min,max)',
  in_list: 'in list',
  in_list_active: 'in list (active only)',
  startswith: 'starts with',
  endswith: 'ends with',
  cidr: 'in CIDR range (IPv4 only)',
  windash_contains: 'contains (Windows-dash aware)',
  base64offset_contains: 'contains (base64-offset aware)',
};

/** Operators that never take a "value" field — RULE_AUTHORING_TEMPLATE.md §1. */
export const OPERATORS_WITHOUT_VALUE = new Set(['exists']);

/**
 * Severity buckets — `~/Videos/vajra_server/engine_v2/src/AlertWriter.cpp`'s
 * `severity_text()`: critical >= 12, high >= 8, medium >= 4, else low.
 */
export const SEVERITY_BUCKETS = [
  { label: 'low', min: 0, max: 3, color: '#64748b' },
  { label: 'medium', min: 4, max: 7, color: '#d97706' },
  { label: 'high', min: 8, max: 11, color: '#ea580c' },
  { label: 'critical', min: 12, max: Infinity, color: '#dc2626' },
] as const;

export function severityBucketFor(level: number): typeof SEVERITY_BUCKETS[number] {
  return SEVERITY_BUCKETS.find((b) => level >= b.min && level <= b.max) ?? SEVERITY_BUCKETS[0];
}

/** A sane default numeric level per named severity, for the dropdown-of-named-severities option. */
export const SEVERITY_DEFAULT_LEVEL: Record<string, number> = {
  low: 2,
  medium: 5,
  high: 9,
  critical: 13,
};

/** The four correlation types — RULE_AUTHORING_TEMPLATE.md §8. */
export const CORRELATION_TYPES = ['event_count', 'value_count', 'temporal', 'temporal_ordered'] as const;

export const CORRELATION_TYPE_LABELS: Record<string, string> = {
  event_count: 'Event Count (≥N matches, order does not matter)',
  value_count: 'Value Count (≥N distinct values of a field, order does not matter)',
  temporal: 'Temporal (all rules matched, any order)',
  temporal_ordered: 'Temporal Ordered (kill-chain — matched in this exact order)',
};

/** Whether a correlation type's member rules are order-sensitive (drives the graph shape: chain vs. threshold-fan-in). */
export const ORDERED_CORRELATION_TYPES = new Set(['temporal_ordered']);

/** ThreatIntelFeedConfig.format — API_CONTRACT_V2.md §3, from `ThreatIntelFeed.h`. */
export const THREAT_INTEL_FORMATS = ['abuseipdb', 'stix'] as const;

/** ThreatIntelFeedConfig.stix_types — API_CONTRACT_V2.md §3. */
export const THREAT_INTEL_STIX_TYPES = ['ip', 'domain', 'hash'] as const;

export const THREAT_INTEL_MAX_ENTRIES_CAP = 500000;
export const THREAT_INTEL_MIN_REFRESH_SECONDS = 60;
