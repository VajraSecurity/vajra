#ifndef VAJRA_ENGINE_RULESET_LOADER_H
#define VAJRA_ENGINE_RULESET_LOADER_H

#include <stdexcept>
#include <string>

#include "../../3rdparty/json.hpp"
#include "vajra_engine/Decoder.h"
#include "vajra_engine/RuleEngine.h"

namespace vajra_engine {

class RulesetError : public std::runtime_error {
public:
    explicit RulesetError(const std::string& what) : std::runtime_error(what) {}
};

// Ruleset document shape:
// {
//   "lists": {
//     "<list_name>": ["value1", "value2", ...],       // existence-only (in_list)
//     "<other_list>": {"key1": "value1", ...}          // CDB key->value (ListStore::get)
//   },
//   "rules": [
//     { "id": 100, "level": 3, "event_type": "bpf_process", "os": "",
//       "description": "...", "groups": ["execution"], "mitre": ["T1059"],
//       "if_sid": 90, "no_log": false, "enabled": true,
//       "event_types": ["bpf_socket", "win_socket"],
//       "conditions": [ { "field": "process.command_line", "op": "contains",
//                          "value": "sh -c", "icase": false } ],
//       "frequency": 3, "timeframe": 60, "same_field": "network.remote_address",
//       "if_matched_sid": [90, 91] }
//   ],
//   "decoders": [
//     { "name": "extract-url", "event_type": "win_process",
//       "source_field": "process.command_line",
//       "prematch": "https?://",
//       "extract": "(https?://[^\\s]+)",
//       "captures": ["decoded.url"] }
//   ],
//   "ip_watch_groups": [
//     { "id": 900, "name": "finance_servers", "list": "watch:finance_servers",
//       "enabled": true, "level": 3, "description": "...",
//       "event_types": ["bpf_socket", "win_socket"], "groups": ["custom_tag"] }
//   ]
// }
// NOTE: unlike "rules", a decoder entry has no "os" field -- only
// "event_type" scopes it. Decoder.h/Decoder.cpp only ever read event_type.
// "op" must be one of equals|not_equals|contains|not_contains|regex|exists|
// gt|lt|gte|lte|between|in_list|in_list_active|startswith|endswith|cidr|
// windash_contains|base64offset_contains ("between"'s value is "min,max";
// "in_list_active" is in_list plus "not disabled" -- see Rule.h). Every op
// except "exists" REQUIRES a "value" -- omitting it (or setting it to null)
// is a RulesetError, not a condition that silently compiles down to
// "field equals empty string"/"field is in list ''" and can never
// legitimately match.
//
// The last five ops are Sigma-parity string/network operators, implemented
// as a load-time rewrite into a "regex" condition (see RulesetLoader.cpp's
// parse_condition) rather than as new FieldCondition::Op values -- this
// keeps RuleEngine.cpp's match switch exhaustive/unchanged while still
// closing real expressiveness gaps vs Sigma/industry EDR field matching:
//   - "startswith"/"endswith": anchored (^/$) literal match, value escaped
//     so it can never be (mis)read as a sub-pattern.
//   - "cidr": IPv4 CIDR ("A.B.C.D/N") membership against the field's whole
//     value (network.remote_address/local_address never carry a port).
//     IPv4 ONLY -- an IPv6 CIDR value ("::1/128" etc.) is a load-time
//     RulesetError (fails loud, never silently accepted as "matches
//     nothing" or "matches everything"), because there is currently NO
//     "cidr" support for IPv6 addresses at all. This is a REAL, live gap,
//     not a moot one: network.remote_address/local_address are populated
//     verbatim from osquery's socket_events/bpf_socket_events/
//     win_socket_events "remote_address"/"local_address" columns
//     (server/request_handler.cpp), which carry a `family` column
//     alongside the address (AF_INET or AF_INET6) and are forwarded to
//     Kafka/this engine with NO family-based filtering anywhere in that
//     path -- confirmed by reading server/request_handler.cpp directly, not
//     assumed. Any monitored host that makes or receives an IPv6
//     connection WILL produce an IPv6-formatted address in this field, and
//     a "cidr" rule targeting an IPv4 range simply never evaluates it (the
//     generated regex requires 4 dotted decimal octets, so an IPv6 string
//     never matches, fails closed rather than silently matching too much --
//     but that also means IPv6 traffic gets ZERO cidr-based coverage,
//     silently, from an operator's perspective, unless they already know
//     this limitation). An operator relying on "cidr" rules for network
//     monitoring must not assume IPv6 traffic is covered. See re-vega.md
//     for the full writeup (Sage's review, finding 4/item-4) and status.
//   - "windash_contains": Sigma's windash modifier -- expands a leading '-'
//     (a Windows CLI switch prefix, e.g. "-enc") into an alternation over
//     '-', '/', and the en/em-dash/horizontal-bar Unicode variants some
//     obfuscated command lines substitute; a value not starting with '-' is
//     matched as a plain literal instead of rejected.
//   - "base64offset_contains": Sigma's base64offset modifier -- matches a
//     plaintext substring appearing base64-encoded at ANY of the 3 possible
//     byte-alignment offsets within a larger encoded blob (a single
//     base64(value) substring search only catches 1 of the 3 real
//     placements).
// Every condition whose op resolves to "regex" (directly, or via one of the
// five rewrites above) is screened at load time against a pattern-length
// cap and a catastrophic-backtracking ("ReDoS") heuristic before it's
// accepted -- a pattern failing either is a RulesetError (see
// JsonSafety.h's kMaxRegexPatternLength/looks_like_catastrophic_regex and
// RulesetLoader.cpp's enforce_regex_pattern_safety). Decoder prematch/
// extract patterns get the equivalent screening at their own compile site,
// Decoder::load_decoder_rules (see Decoder.cpp) -- there, a pattern that
// fails the screen only skips that one decoder rather than rejecting the
// whole ruleset, matching that path's existing invalid-regex posture.
//
// The whole ruleset document (not just condition values) is also bounded
// against resource exhaustion: caps on rule/decoder/ip_watch_groups/list
// counts, conditions per rule, captures per decoder, and general string
// field lengths -- see the kMax* constants in RulesetLoader.cpp. Generous
// relative to any realistic ruleset, but a malformed or corrupted file
// (accidental or malicious) fails to load cleanly instead of letting the
// engine allocate unboundedly.
// "enabled" (default true if absent) lets an operator turn a rule on/off
// without deleting it from the ruleset -- a disabled rule is skipped before
// any condition/regex work, doesn't appear in matched_ids (so if_sid/
// if_matched_sid chains off it never fire either), but is still counted by
// RuleEngine::size(). "event_types" (optional array) is an additive
// alternative to the single "event_type" string: if present and non-empty,
// it takes priority and the event must match one of the listed types;
// "event_type" is only consulted when "event_types" is absent/empty.
//
// "ip_watch_groups" is sugar for a common pattern: monitor connections to a
// named group of remote IPs across bpf_socket/win_socket (osquery's socket
// event tables), without hand-writing the underlying rule/condition. Each
// entry synthesizes exactly one Rule: event_types defaults to
// ["bpf_socket", "win_socket"] (override to narrow further), one condition
// {field: "network.remote_address", op: "in_list_active", value: <list>},
// groups always includes "ip_monitoring" (plus any listed under "groups")
// so these alerts are easy to filter from other detections in the console,
// and "enabled" controls the WHOLE group's monitoring on/off exactly like
// any other rule's "enabled" -- INCLUDING the same default: omitting
// "enabled" on an ip_watch_groups entry activates monitoring immediately
// upon load/reload, the same as any rule with no "enabled" key. There's no
// separate "defined but not yet active" state; write "enabled": false
// explicitly if a group should be staged without going live yet.
// "list" defaults to "watch:<name>" if omitted.
// "id" is required (like "rules") and must be unique across BOTH "rules"
// and "ip_watch_groups" combined -- a synthesized rule is a real rule (it
// can even be the target of another rule's if_matched_sid), not a separate
// parallel mechanism. The named list itself is populated the same way any
// other list is: via the "lists" section (array-form for plain membership,
// object-form for per-IP on/off -- see "in_list_active" above) or a
// ThreatIntelFeed targeting that list name.
// "frequency"/"timeframe" (seconds): this rule must match `frequency` times
// within the trailing `timeframe` seconds (grouped by "same_field", default
// host_identifier) to fire. "if_matched_sid": fires only if at least one of
// the referenced rule ids matched within the same rule's own "timeframe"
// window (also grouped by "same_field") -- cross-event, unlike "if_sid"'s
// same-event-only chaining. Both require "timeframe" > 0 or they fail closed
// (never match) rather than silently behaving as "always"/"never".
// An if_matched_sid referencer and each rule id it references must use the
// SAME "same_field" (both empty/host-grouped counts as matching) -- a
// mismatch means the referencer queries a different grouping key than the
// target recorded under, so the dependency can never match. RuleEngine::load
// logs a warning for this at ruleset-load time; it doesn't reject the
// ruleset (matching this loader's "never block startup" posture elsewhere).
// RuleEngine::load also warns (same posture, still doesn't reject) when an
// "if_sid" or "if_matched_sid" reference resolves to a rule that exists but
// has "enabled": false -- a disabled rule is skipped in eval() before it can
// ever satisfy either dependency, so the dependent rule silently goes dark
// as a side effect of disabling its parent/target unless this is surfaced.
// "decoders" (see DecoderRuleConfig): "event_type" empty applies to every
// event; "prematch" is an optional cheap filter regex run against
// "source_field" before "extract" is attempted; "captures" maps "extract"'s
// capture groups to destination field names positionally (std::regex has no
// named-capture support, so this plays the role Wazuh's <order> tag plays
// for its unnamed captures). Decoders only run if a non-null `decoder` is
// passed to load_ruleset[_file] -- both overloads default it to nullptr so
// existing 2-argument call sites (and any caller that only wants rules/
// lists) are unaffected.
// Reload semantics (e.g. a SIGHUP-triggered reload -- see main.cpp): every
// section of the document is fully parsed and validated before ANY of
// rules_/decoder_rules_/lists are mutated, so a malformed entry anywhere in
// the document leaves the previously loaded ruleset completely untouched --
// this is a true all-or-nothing swap for "rules" and "decoders". "lists" is
// the one exception: entries are additive/overwrite-in-place only (never
// removed), so a key present in an earlier load and absent from a later one
// is NOT retracted by reloading -- e.g. delisting a previously-denied IP
// from "lists" requires a full process restart, not just a reload. This is
// deliberate, not an oversight: a wholesale list replace on every reload
// would risk clobbering entries a concurrently-running ThreatIntelFeed
// worker wrote into the same named list (e.g. "deny_ips") between reloads.
void load_ruleset(const nlohmann::json& doc, RuleEngine& engine, Decoder* decoder = nullptr);
void load_ruleset_file(const std::string& path, RuleEngine& engine, Decoder* decoder = nullptr);

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_RULESET_LOADER_H
