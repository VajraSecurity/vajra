#include "vajra_engine/RulesetLoader.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {
namespace {

// Resource-exhaustion caps on ruleset document shape. A ruleset file is
// operator-authored and not directly network-reachable (see
// RulesetLoader.h/main.cpp -- it's loaded from a local path named by the
// VAJRA_ENGINE_RULES env var, set at deployment time, never from event/Kafka
// data), but a malformed or corrupted file -- accidental (a bad merge, a
// generator bug) or malicious (a compromised deployment pipeline, a
// tampered file on disk) -- must still fail to load cleanly rather than let
// the engine allocate unboundedly. All are generous relative to any
// legitimate ruleset actually shipped with or configured for this engine
// (BuiltinRules.h has 5 rules; a large hand-tuned Sigma-derived ruleset is
// realistically in the hundreds to low thousands of rules).
constexpr std::size_t kMaxRules = 10000;
constexpr std::size_t kMaxConditionsPerRule = 200;
constexpr std::size_t kMaxDecoders = 5000;
constexpr std::size_t kMaxCapturesPerDecoder = 64;
constexpr std::size_t kMaxIpWatchGroups = 5000;
constexpr std::size_t kMaxListsCount = 5000;
constexpr std::size_t kMaxEntriesPerList = 100000;
constexpr std::size_t kMaxStringFieldLength = 8192;   // description, field names, list keys/values, ...
constexpr std::size_t kMaxGroupsOrMitrePerRule = 200;

void check_string_length(const std::string& s, const std::string& what) {
    if (s.size() > kMaxStringFieldLength) {
        throw RulesetError(what + " exceeds the maximum length of " +
                            std::to_string(kMaxStringFieldLength) + " bytes");
    }
}

// Escapes every ECMAScript regex metacharacter in `s` so it can be embedded
// in a generated pattern and only ever match itself literally -- used by
// the Sigma-parity operators below (startswith/endswith/windash_contains/
// base64offset_contains), which all build a `regex` condition out of
// operator-supplied literal text.
std::string regex_escape_literal(const std::string& s) {
    static const std::string kSpecial = R"(\^$.|?*+()[]{})";
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (kSpecial.find(c) != std::string::npos) out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

// Converts "A.B.C.D/N" (IPv4 only -- see RulesetLoader.h) into a regex that
// matches exactly the dotted-decimal addresses inside that CIDR block,
// anchored to the whole field value (network.remote_address/local_address
// never carry a port -- see Decoder.cpp's alias table). Malformed input
// (wrong shape, out-of-range octet, prefix outside 0-32) throws
// RulesetError rather than silently compiling down to an always-false or,
// worse, an unintentionally-broad condition.
//
// Algorithm: split the prefix length into whole fixed octets
// (prefix_len/8) plus, if prefix_len isn't a multiple of 8, one "boundary"
// octet constrained to a CIDR-aligned sub-range of size 2^(8-remainder) --
// emitted as a literal alternation of every integer in that sub-range
// (exact by construction, no leading-zero ambiguity: this wire format never
// emits leading zeros in an octet). Any remaining, fully unconstrained
// octet uses a strict 0-255 decimal matcher.
std::string cidr_to_anchored_regex(const std::string& cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        throw RulesetError("cidr value '" + cidr + "' is not in A.B.C.D/N form");
    }
    const std::string addr_part = cidr.substr(0, slash);
    const std::string prefix_part = cidr.substr(slash + 1);

    std::array<int, 4> octets{};
    {
        std::istringstream in(addr_part);
        std::string token;
        std::size_t idx = 0;
        while (std::getline(in, token, '.')) {
            if (idx >= 4) throw RulesetError("cidr value '" + cidr + "' has more than 4 octets");
            if (token.empty() || token.size() > 3 ||
                token.find_first_not_of("0123456789") != std::string::npos) {
                throw RulesetError("cidr value '" + cidr + "' has a non-numeric octet");
            }
            const long v = std::stol(token);
            if (v < 0 || v > 255) throw RulesetError("cidr value '" + cidr + "' has an out-of-range octet");
            octets[idx++] = static_cast<int>(v);
        }
        if (idx != 4) throw RulesetError("cidr value '" + cidr + "' must have exactly 4 octets");
    }

    if (prefix_part.empty() || prefix_part.size() > 2 ||
        prefix_part.find_first_not_of("0123456789") != std::string::npos) {
        throw RulesetError("cidr value '" + cidr + "' has a non-numeric prefix length");
    }
    const long prefix_len = std::stol(prefix_part);
    if (prefix_len < 0 || prefix_len > 32) {
        throw RulesetError("cidr value '" + cidr + "' prefix length must be 0-32");
    }

    const int full_octets = static_cast<int>(prefix_len / 8);
    const int remainder_bits = static_cast<int>(prefix_len % 8);

    std::string pattern = "^";
    for (int i = 0; i < 4; ++i) {
        if (i > 0) pattern += "\\.";
        if (i < full_octets) {
            pattern += std::to_string(octets[i]);
        } else if (i == full_octets && remainder_bits > 0) {
            const int block = 1 << (8 - remainder_bits);
            const int lo = (octets[i] / block) * block;
            const int hi = lo + block - 1;
            pattern += "(";
            for (int v = lo; v <= hi; ++v) {
                if (v != lo) pattern += "|";
                pattern += std::to_string(v);
            }
            pattern += ")";
        } else {
            pattern += R"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))";
        }
    }
    pattern += "$";
    return pattern;
}

// Sigma's `windash` modifier: expands a leading "-" (a Windows CLI switch
// prefix, e.g. "-enc") into an alternation over the switch-prefix variants
// Windows command-line parsers commonly accept -- hyphen-minus, forward
// slash, en dash (U+2013), em dash (U+2014), horizontal bar (U+2015) -- so
// one rule catches "-enc", "/enc", and the Unicode-dash obfuscated variants
// alike. Unanchored (contains-style), matching the op name
// (`windash_contains`). A value not starting with '-' is returned as a
// plain escaped literal (no dash variants to expand) rather than rejected,
// so this operator degrades gracefully instead of surprising a ruleset
// author who reused it for a non-switch value.
std::string windash_expand_regex(const std::string& raw_value) {
    if (raw_value.empty() || raw_value.front() != '-') {
        return regex_escape_literal(raw_value);
    }
    const std::string rest = raw_value.substr(1);
    return "(-|/|\xE2\x80\x93|\xE2\x80\x94|\xE2\x80\x95)" + regex_escape_literal(rest);
}

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Plain RFC 4648 base64 (with '=' padding), no line wrapping -- the
// building block base64offset_regex_alternation() slices to derive each
// offset variant.
std::string base64_encode(const std::string& bytes) {
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= bytes.size()) {
        const auto b0 = static_cast<unsigned char>(bytes[i]);
        const auto b1 = static_cast<unsigned char>(bytes[i + 1]);
        const auto b2 = static_cast<unsigned char>(bytes[i + 2]);
        out.push_back(kBase64Alphabet[b0 >> 2]);
        out.push_back(kBase64Alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
        out.push_back(kBase64Alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)]);
        out.push_back(kBase64Alphabet[b2 & 0x3F]);
        i += 3;
    }
    const std::size_t remaining = bytes.size() - i;
    if (remaining == 1) {
        const auto b0 = static_cast<unsigned char>(bytes[i]);
        out.push_back(kBase64Alphabet[b0 >> 2]);
        out.push_back(kBase64Alphabet[(b0 & 0x03) << 4]);
        out += "==";
    } else if (remaining == 2) {
        const auto b0 = static_cast<unsigned char>(bytes[i]);
        const auto b1 = static_cast<unsigned char>(bytes[i + 1]);
        out.push_back(kBase64Alphabet[b0 >> 2]);
        out.push_back(kBase64Alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
        out.push_back(kBase64Alphabet[(b1 & 0x0F) << 2]);
        out += "=";
    }
    return out;
}

// Sigma's `base64offset` modifier: a plaintext substring's base64
// representation depends on which of the 3 possible byte-alignment offsets
// (mod 3) it starts at within a larger encoded blob, so a single
// base64(value) substring search misses 2 out of 3 real placements. This
// computes all 3 stable variants: for pad_bytes in {0,1,2} (the number of
// bytes -- from elsewhere in the real, unknown surrounding data -- that
// precede `value` within its first base64 group), base64-encode (pad_bytes
// of filler + value), then trim to exactly the character range that
// depends ONLY on `value`'s own bytes -- NOT on the filler bytes, even
// though the filler's actual byte VALUE is our own arbitrary choice: what
// matters is that in the real embedding, whatever precedes/follows `value`
// is genuinely unknown, so any output character whose bits are influenced
// AT ALL by a neighboring byte (whether our fictional filler stands in for
// it, or it's the real trailing byte after a partial final group) can't be
// trusted to match the real encoding, and must be dropped:
//   - drop ceil(4*pad_bytes/3) chars from the front (every char with any
//     bit contribution from the pad_bytes leading positions)
//   - drop 3 chars from the back if (pad_bytes+len(value)) % 3 == 1, or 2
//     chars if == 2 (the trailing partial group's char(s) that would need
//     bits from an unknown following byte); drop 0 if % 3 == 0
// Verified by exhaustive-style random testing (200k trials, full 0-255
// byte range, value length >= 3, arbitrary surrounding bytes) against a
// reference implementation before landing -- see re-vega.md.
//
// Requires len(value) >= 3: below that, some alignments legitimately have
// NO character left that's fully free of neighboring-byte influence (e.g.
// a 1-byte value can, depending on real alignment, contribute bits to at
// most one char that's also mixed with a genuinely unknown neighbor) --
// not a bug, a structural limit of the technique for very short inputs.
// Returns an unanchored (contains-style) alternation of the up-to-3
// distinct variants, each regex-escaped (base64's alphabet includes '+',
// a regex metacharacter).
std::string base64offset_regex_alternation(const std::string& raw_value) {
    if (raw_value.size() < 3) {
        throw RulesetError(
            "base64offset_contains requires a 'value' of at least 3 bytes to produce a stable match "
            "at every byte alignment");
    }

    std::set<std::string> variants;  // de-duplicate identical variants (common for short values)
    for (int pad_bytes = 0; pad_bytes <= 2; ++pad_bytes) {
        const std::string padded = std::string(static_cast<std::size_t>(pad_bytes), 'A') + raw_value;
        std::string encoded = base64_encode(padded);
        // Standard padding ('=') is never part of a "stable middle" of a
        // larger real encoding -- drop it before trimming ends, exactly
        // like the trailing-partial-group chars it accompanies.
        while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();

        // Ceiling division: every char with ANY bit contribution from the
        // pad_bytes leading positions must go, not just the chars fully
        // determined by them (see the derivation above -- a char mixing
        // filler bits with value bits is still unstable in the real
        // embedding, where "filler" is actually an unknown neighbor byte).
        const std::size_t front_drop = (4 * static_cast<std::size_t>(pad_bytes) + 2) / 3;
        const std::size_t total_bytes = static_cast<std::size_t>(pad_bytes) + raw_value.size();
        const std::size_t remainder = total_bytes % 3;
        const std::size_t back_drop = remainder == 1 ? 3 : (remainder == 2 ? 2 : 0);

        if (front_drop + back_drop >= encoded.size()) continue;  // nothing stable left for this offset
        variants.insert(encoded.substr(front_drop, encoded.size() - front_drop - back_drop));
    }

    if (variants.empty()) {
        throw RulesetError("base64offset_contains: 'value' is too short to produce a stable match");
    }

    std::string pattern = "(";
    bool first = true;
    for (const auto& variant : variants) {
        if (!first) pattern += "|";
        first = false;
        pattern += regex_escape_literal(variant);
    }
    pattern += ")";
    return pattern;
}

FieldCondition::Op parse_op(const std::string& s) {
    if (s == "equals") return FieldCondition::Op::equals;
    if (s == "not_equals") return FieldCondition::Op::not_equals;
    if (s == "contains") return FieldCondition::Op::contains;
    if (s == "regex") return FieldCondition::Op::regex;
    if (s == "exists") return FieldCondition::Op::exists;
    if (s == "not_contains") return FieldCondition::Op::not_contains;
    if (s == "gt") return FieldCondition::Op::gt;
    if (s == "lt") return FieldCondition::Op::lt;
    if (s == "gte") return FieldCondition::Op::gte;
    if (s == "lte") return FieldCondition::Op::lte;
    if (s == "between") return FieldCondition::Op::between;
    if (s == "in_list") return FieldCondition::Op::in_list;
    if (s == "in_list_active") return FieldCondition::Op::in_list_active;
    throw RulesetError("unknown condition op '" + s + "'");
}

// Ops requiring no 'value' at all -- everything else must carry one (see
// the block below): a mistyped/omitted "value" on e.g. "equals" previously
// silently compiled down to "field equals empty string" instead of failing
// to load, a load-time footgun this now rejects loudly instead.
const std::set<std::string>& valueless_ops() {
    static const std::set<std::string> ops = {"exists"};
    return ops;
}

void enforce_regex_pattern_safety(const std::string& pattern, int rule_id, const std::string& field) {
    if (pattern.size() > kMaxRegexPatternLength) {
        throw RulesetError("rule " + std::to_string(rule_id) + " field '" + field +
                            "': regex pattern exceeds " + std::to_string(kMaxRegexPatternLength) +
                            " bytes");
    }
    if (looks_like_catastrophic_regex(pattern)) {
        throw RulesetError("rule " + std::to_string(rule_id) + " field '" + field +
                            "': regex pattern looks like it can catastrophically backtrack "
                            "(nested quantifiers, e.g. '(a+)+') -- rewrite it or split it up");
    }
}

// `rule_id`/`context` are used only to make a RulesetError's message
// actionable; pass 0/"" from a context (e.g. ip_watch_groups' synthesized
// condition) that predates having a rule id yet -- the synthesized
// condition's own value is a plain in_list_active lookup, never user regex,
// so enforce_regex_pattern_safety never actually fires for it.
FieldCondition parse_condition(const nlohmann::json& j, int rule_id) {
    if (!j.is_object() || !j.contains("field") || !j.contains("op")) {
        throw RulesetError("condition requires 'field' and 'op'");
    }
    const std::string op_str = j.at("op").get<std::string>();
    const std::string field = j.at("field").get<std::string>();
    check_string_length(field, "rule " + std::to_string(rule_id) + " condition 'field'");

    FieldCondition cond;
    cond.field = field;
    if (j.contains("icase")) cond.icase = j.at("icase").get<bool>();

    if (valueless_ops().count(op_str) == 0 && (!j.contains("value") || j.at("value").is_null())) {
        throw RulesetError("rule " + std::to_string(rule_id) + " condition on field '" + field +
                            "' (op '" + op_str + "') requires a 'value'");
    }
    const std::string raw_value = j.contains("value") && !j.at("value").is_null()
                                       ? j.at("value").get<std::string>()
                                       : "";
    check_string_length(raw_value, "rule " + std::to_string(rule_id) + " condition 'value' on field '" +
                                        field + "'");

    // Sigma-parity string/network operators, expressed as a load-time
    // rewrite into the existing FieldCondition::Op::regex rather than as
    // new runtime ops -- see RulesetLoader.h's doc comment on why (keeps
    // RuleEngine.cpp's match switch exhaustive and unchanged; every
    // generated pattern still goes through the same
    // enforce_regex_pattern_safety() gate as an operator-hand-written
    // "regex" condition, immediately below).
    if (op_str == "startswith") {
        cond.op = FieldCondition::Op::regex;
        cond.value = "^" + regex_escape_literal(raw_value);
    } else if (op_str == "endswith") {
        cond.op = FieldCondition::Op::regex;
        cond.value = regex_escape_literal(raw_value) + "$";
    } else if (op_str == "cidr") {
        cond.op = FieldCondition::Op::regex;
        cond.value = cidr_to_anchored_regex(raw_value);
    } else if (op_str == "windash_contains") {
        cond.op = FieldCondition::Op::regex;
        cond.value = windash_expand_regex(raw_value);
    } else if (op_str == "base64offset_contains") {
        cond.op = FieldCondition::Op::regex;
        cond.value = base64offset_regex_alternation(raw_value);
    } else {
        cond.op = parse_op(op_str);
        cond.value = raw_value;
    }

    if (cond.op == FieldCondition::Op::regex) {
        enforce_regex_pattern_safety(cond.value, rule_id, field);
    }
    return cond;
}

// Accepts either a single rule id or an array of ids, so a JSON author
// doesn't have to remember to wrap a single reference in brackets.
std::vector<int> parse_if_matched_sid(const nlohmann::json& j) {
    std::vector<int> ids;
    if (j.is_number_integer()) {
        ids.push_back(j.get<int>());
    } else if (j.is_array()) {
        for (const auto& item : j) ids.push_back(item.get<int>());
    } else {
        throw RulesetError("'if_matched_sid' must be a rule id or an array of rule ids");
    }
    return ids;
}

Rule parse_rule(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("id")) {
        throw RulesetError("rule requires an 'id'");
    }
    Rule rule;
    rule.id = j.at("id").get<int>();
    rule.level = j.value("level", 0);
    rule.description = j.value("description", "");
    check_string_length(rule.description, "rule " + std::to_string(rule.id) + " 'description'");
    if (j.contains("groups")) rule.groups = j.at("groups").get<std::vector<std::string>>();
    if (j.contains("mitre")) rule.mitre = j.at("mitre").get<std::vector<std::string>>();
    if (rule.groups.size() > kMaxGroupsOrMitrePerRule || rule.mitre.size() > kMaxGroupsOrMitrePerRule) {
        throw RulesetError("rule " + std::to_string(rule.id) + ": 'groups'/'mitre' exceeds " +
                            std::to_string(kMaxGroupsOrMitrePerRule) + " entries");
    }
    rule.event_type = j.value("event_type", "");
    if (j.contains("event_types")) {
        rule.event_types = j.at("event_types").get<std::vector<std::string>>();
    }
    rule.os = j.value("os", "");
    if (j.contains("if_sid") && !j.at("if_sid").is_null()) {
        rule.if_sid = j.at("if_sid").get<int>();
    }
    rule.no_log = j.value("no_log", false);
    rule.enabled = j.value("enabled", true);
    if (j.contains("conditions")) {
        if (j.at("conditions").size() > kMaxConditionsPerRule) {
            throw RulesetError("rule " + std::to_string(rule.id) + ": 'conditions' exceeds " +
                                std::to_string(kMaxConditionsPerRule) + " entries");
        }
        for (const auto& c : j.at("conditions")) rule.conditions.push_back(parse_condition(c, rule.id));
    }
    rule.frequency = j.value("frequency", 0);
    rule.timeframe_seconds = j.value("timeframe", 0);
    rule.same_field = j.value("same_field", "");
    if (j.contains("if_matched_sid") && !j.at("if_matched_sid").is_null()) {
        rule.if_matched_sid = parse_if_matched_sid(j.at("if_matched_sid"));
    }
    return rule;
}

DecoderRuleConfig parse_decoder(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("source_field") || !j.contains("extract")) {
        throw RulesetError("decoder requires 'source_field' and 'extract'");
    }
    DecoderRuleConfig cfg;
    cfg.name = j.value("name", "");
    cfg.event_type = j.value("event_type", "");
    cfg.source_field = j.at("source_field").get<std::string>();
    cfg.prematch = j.value("prematch", "");
    cfg.extract = j.at("extract").get<std::string>();
    check_string_length(cfg.name, "decoder 'name'");
    check_string_length(cfg.source_field, "decoder '" + cfg.name + "' 'source_field'");
    // Pattern length / catastrophic-backtracking screening for prematch/
    // extract happens in Decoder::load_decoder_rules (see Decoder.cpp) --
    // this is the ONE compile site for decoder regexes, so it's enforced
    // exactly once, there, rather than duplicated here.
    if (j.contains("captures")) cfg.captures = j.at("captures").get<std::vector<std::string>>();
    if (cfg.captures.size() > kMaxCapturesPerDecoder) {
        throw RulesetError("decoder '" + cfg.name + "': 'captures' exceeds " +
                            std::to_string(kMaxCapturesPerDecoder) + " entries");
    }
    for (const auto& capture : cfg.captures) {
        check_string_length(capture, "decoder '" + cfg.name + "' capture destination field name");
    }
    return cfg;
}

// A "lists" entry, validated but not yet applied to a live ListStore --
// either existence-only membership (from a JSON array) or CDB-style
// key->value (from a JSON object), matching ListStore::add/set respectively.
struct StagedList {
    bool is_membership = true;
    std::vector<std::string> membership;
    std::map<std::string, std::string> keyvalue;
};

std::map<std::string, StagedList> parse_lists(const nlohmann::json& lists_doc) {
    if (!lists_doc.is_object()) throw RulesetError("'lists' must be an object");
    if (lists_doc.size() > kMaxListsCount) {
        throw RulesetError("'lists' has more than " + std::to_string(kMaxListsCount) + " named lists");
    }
    std::map<std::string, StagedList> staged;
    for (auto it = lists_doc.begin(); it != lists_doc.end(); ++it) {
        check_string_length(it.key(), "list name");
        const auto& list_doc = it.value();
        StagedList entry;
        if (list_doc.is_array()) {
            if (list_doc.size() > kMaxEntriesPerList) {
                throw RulesetError("list '" + it.key() + "' exceeds " + std::to_string(kMaxEntriesPerList) +
                                    " entries");
            }
            for (const auto& member : list_doc) {
                auto value = member.get<std::string>();
                check_string_length(value, "list '" + it.key() + "' member");
                entry.membership.push_back(std::move(value));
            }
        } else if (list_doc.is_object()) {
            if (list_doc.size() > kMaxEntriesPerList) {
                throw RulesetError("list '" + it.key() + "' exceeds " + std::to_string(kMaxEntriesPerList) +
                                    " entries");
            }
            entry.is_membership = false;
            for (auto kv = list_doc.begin(); kv != list_doc.end(); ++kv) {
                check_string_length(kv.key(), "list '" + it.key() + "' key");
                auto value = kv.value().get<std::string>();
                check_string_length(value, "list '" + it.key() + "' value for key '" + kv.key() + "'");
                entry.keyvalue[kv.key()] = std::move(value);
            }
        } else {
            throw RulesetError("list '" + it.key() +
                                "' must be an array (membership) or an object (key->value)");
        }
        staged[it.key()] = std::move(entry);
    }
    return staged;
}

// Sugar for the common "monitor connections to a named group of remote IPs"
// pattern: synthesizes exactly one real Rule (see RulesetLoader.h's doc
// comment) rather than any parallel mechanism -- it can be hot-reloaded,
// enabled/disabled, and even targeted by another rule's if_matched_sid just
// like a hand-authored one.
Rule parse_ip_watch_group(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("id") || !j.contains("name")) {
        throw RulesetError("ip_watch_groups entry requires 'id' and 'name'");
    }
    const std::string name = j.at("name").get<std::string>();
    if (name.empty()) throw RulesetError("ip_watch_groups entry has an empty 'name'");
    check_string_length(name, "ip_watch_groups entry 'name'");

    Rule rule;
    rule.id = j.at("id").get<int>();
    rule.level = j.value("level", 3);
    rule.description =
        j.value("description", "Monitored connection to IP group '" + name + "'");
    check_string_length(rule.description, "ip_watch_groups entry '" + name + "' 'description'");
    rule.enabled = j.value("enabled", true);

    rule.groups = {"ip_monitoring"};
    if (j.contains("groups")) {
        for (const auto& g : j.at("groups")) {
            auto tag = g.get<std::string>();
            if (tag != "ip_monitoring") rule.groups.push_back(std::move(tag));
        }
    }

    if (j.contains("event_types")) {
        rule.event_types = j.at("event_types").get<std::vector<std::string>>();
        if (rule.event_types.empty()) {
            throw RulesetError("ip_watch_groups entry '" + name + "': 'event_types' must not be empty");
        }
    } else {
        rule.event_types = {"bpf_socket", "win_socket"};
    }

    const std::string list = j.value("list", "watch:" + name);
    check_string_length(list, "ip_watch_groups entry '" + name + "' 'list'");
    rule.conditions.push_back(FieldCondition{"network.remote_address",
                                              FieldCondition::Op::in_list_active, list, false, nullptr});
    return rule;
}

std::vector<Rule> parse_ip_watch_groups(const nlohmann::json& groups_doc) {
    if (!groups_doc.is_array()) throw RulesetError("'ip_watch_groups' must be an array");
    if (groups_doc.size() > kMaxIpWatchGroups) {
        throw RulesetError("'ip_watch_groups' exceeds " + std::to_string(kMaxIpWatchGroups) + " entries");
    }
    std::vector<Rule> rules;
    for (const auto& g : groups_doc) rules.push_back(parse_ip_watch_group(g));
    return rules;
}

}  // namespace

void load_ruleset(const nlohmann::json& doc, RuleEngine& engine, Decoder* decoder) {
    if (!doc.is_object()) throw RulesetError("ruleset document must be a JSON object");

    // Parse and fully validate every section into local staging structures
    // first, and only start mutating engine/decoder once ALL of them have
    // succeeded -- a malformed entry in ANY section (rules, decoders, or
    // lists) must not leave some sections' live state already replaced
    // while the throw makes the caller (main.cpp's SIGHUP handler) believe
    // nothing changed. Previously only rules/decoders were staged this way;
    // "lists" was validated-and-applied inline afterward, so a type error
    // partway through "lists" could fire after rules_/decoder_rules_ had
    // already been replaced, falsely reporting "reload failed, kept the
    // previous ruleset" while part of the new ruleset was actually live.
    std::vector<Rule> rules;
    if (doc.contains("rules")) {
        if (!doc.at("rules").is_array()) throw RulesetError("'rules' must be an array");
        if (doc.at("rules").size() > kMaxRules) {
            throw RulesetError("'rules' exceeds " + std::to_string(kMaxRules) + " entries");
        }
        for (const auto& r : doc.at("rules")) rules.push_back(parse_rule(r));
    }

    // "ip_watch_groups" entries synthesize real Rules (see RulesetLoader.h),
    // merged into the same rules_ vector engine.load() receives -- not a
    // second/parallel matching path. Validated and merged here, before
    // engine.load() runs, so a malformed entry rejects the whole reload
    // exactly like a malformed "rules"/"decoders" entry does.
    if (doc.contains("ip_watch_groups")) {
        auto watch_rules = parse_ip_watch_groups(doc.at("ip_watch_groups"));
        std::set<int> ids;
        for (const auto& r : rules) ids.insert(r.id);
        for (const auto& r : watch_rules) {
            if (!ids.insert(r.id).second) {
                throw RulesetError("ip_watch_groups entry id " + std::to_string(r.id) +
                                    " collides with an existing rule id");
            }
        }
        for (auto& r : watch_rules) rules.push_back(std::move(r));
    }

    std::vector<DecoderRuleConfig> decoders;
    if (decoder && doc.contains("decoders")) {
        if (!doc.at("decoders").is_array()) throw RulesetError("'decoders' must be an array");
        if (doc.at("decoders").size() > kMaxDecoders) {
            throw RulesetError("'decoders' exceeds " + std::to_string(kMaxDecoders) + " entries");
        }
        for (const auto& d : doc.at("decoders")) decoders.push_back(parse_decoder(d));
    }

    std::map<std::string, StagedList> lists;
    if (doc.contains("lists")) lists = parse_lists(doc.at("lists"));

    engine.load(std::move(rules));
    if (decoder) decoder->load_decoder_rules(std::move(decoders));

    // Additive/overwrite-in-place only, same as before -- a key present in
    // an earlier load and absent from this one is NOT removed. This means a
    // SIGHUP reload can add or update list entries but can't retract one
    // (e.g. delisting a previously-denied IP requires a full process
    // restart, not just editing the ruleset file and reloading). Not fixed
    // here because a wholesale replace would also need to interact safely
    // with ThreatIntelFeed, which writes into these same named lists (e.g.
    // "deny_ips") concurrently from its own refresh threads -- replacing a
    // list wholesale from a ruleset reload could clobber live, independently
    // refreshed threat-intel data. See RulesetLoader.h's doc comment.
    for (auto& [name, entry] : lists) {
        if (entry.is_membership) {
            for (auto& member : entry.membership) engine.lists().add(name, std::move(member));
        } else {
            for (auto& [key, value] : entry.keyvalue) {
                engine.lists().set(name, key, std::move(value));
            }
        }
    }
}

void load_ruleset_file(const std::string& path, RuleEngine& engine, Decoder* decoder) {
    if (!std::filesystem::exists(path)) {
        throw RulesetError("ruleset file not found: " + path);
    }
    std::ifstream in(path);
    if (!in.is_open()) {
        throw RulesetError("could not open ruleset file: " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(buf.str());
    } catch (const nlohmann::json::parse_error& e) {
        throw RulesetError(std::string("invalid JSON in ") + path + ": " + e.what());
    }
    load_ruleset(doc, engine, decoder);
}

}  // namespace vajra_engine
