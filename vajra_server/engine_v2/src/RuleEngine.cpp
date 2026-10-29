#include "vajra_engine/RuleEngine.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <set>

#include "../../common/logger.h"
#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {
namespace {

// Sweep OccurrenceHistory every N events rather than every single one, to
// keep the amortized per-event cost low while still bounding memory.
constexpr std::size_t kSweepIntervalEvents = 1000;
// Tracked rules with no valid timeframe (misconfigured -- see
// Rule::correlation_matches' fail-closed handling) can never actually
// correlation-match, but still record occurrences; give them a short fixed
// retention instead of none so a misconfigured rule can't accumulate history
// forever.
constexpr std::int64_t kDefaultSweepWindowMs = 60'000;

// Rule regex PATTERNS are operator-authored (ruleset file, trusted), but the
// STRING they're matched against is a raw event field value -- fully
// attacker/compromised-endpoint-controlled, since it comes straight off the
// Kafka ingest path. std::regex has no built-in catastrophic-backtracking
// protection, and evaluation happens on the single-threaded consumer loop,
// so a pathological pattern (even an accidentally-written one, e.g. nested
// quantifiers) combined with a long crafted field value could stall the
// entire pipeline. This doesn't eliminate catastrophic backtracking (that
// would need a bounded/non-backtracking engine like RE2), but it bounds the
// worst case to a fixed, small input size regardless of how large an
// attacker makes the underlying field. Far above any legitimate field value
// this ruleset's shipped rules actually match against (command lines,
// paths, URLs are realistically well under 4 KiB).
constexpr std::size_t kMaxRegexInputBytes = 16384;

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Only a fully-numeric field value participates in gt/lt/gte/lte/between --
// a value like "10.5.5.5" (an IP address) must never partially parse as the
// number 10.5.
bool parse_full_double(const std::string& s, double& out) {
    if (s.empty()) return false;
    try {
        std::size_t pos = 0;
        out = std::stod(s, &pos);
        return pos == s.size();
    } catch (const std::exception&) {
        return false;
    }
}

// "min,max" -- fails closed (returns false) on anything else, including
// extra commas, missing bounds, or non-numeric bounds.
bool parse_bounds(const std::string& s, double& min_out, double& max_out) {
    const auto comma = s.find(',');
    if (comma == std::string::npos || s.find(',', comma + 1) != std::string::npos) return false;
    return parse_full_double(s.substr(0, comma), min_out) &&
           parse_full_double(s.substr(comma + 1), max_out);
}

}  // namespace

std::int64_t clamp_correlation_now_ms(std::int64_t event_unix_time_seconds,
                                       std::int64_t wall_clock_ms) {
    constexpr std::int64_t kMaxFutureSkewMs = 5 * 60 * 1000;  // 5 minutes of clock drift tolerance
    if (event_unix_time_seconds > 0 &&
        event_unix_time_seconds <= (wall_clock_ms + kMaxFutureSkewMs) / 1000) {
        return event_unix_time_seconds * 1000;
    }
    return wall_clock_ms;
}

bool FieldCondition::matches(const NormalizedEvent& ev, const ListStore& lists) const {
    switch (op) {
        case Op::exists:
            return ev.has(field);
        case Op::equals: {
            if (!ev.has(field)) return false;
            const std::string actual = ev.get(field);
            return icase ? to_lower(actual) == to_lower(value) : actual == value;
        }
        case Op::not_equals: {
            if (!ev.has(field)) return true;
            const std::string actual = ev.get(field);
            return icase ? to_lower(actual) != to_lower(value) : actual != value;
        }
        case Op::contains: {
            if (!ev.has(field)) return false;
            const std::string actual = icase ? to_lower(ev.get(field)) : ev.get(field);
            const std::string needle = icase ? to_lower(value) : value;
            return actual.find(needle) != std::string::npos;
        }
        case Op::not_contains: {
            if (!ev.has(field)) return true;
            const std::string actual = icase ? to_lower(ev.get(field)) : ev.get(field);
            const std::string needle = icase ? to_lower(value) : value;
            return actual.find(needle) == std::string::npos;
        }
        case Op::regex: {
            if (!compiled || !ev.has(field)) return false;
            const std::string& actual = ev.get(field);
            if (actual.size() > kMaxRegexInputBytes) return false;
            // regex_search_bounded(), NOT a bare std::regex_search: the
            // load-time looks_like_catastrophic_regex() screen (Rule
            // loading) only catches classic nested-quantifier shapes and
            // has a confirmed, PoC'd bypass (round-2 adversarial review,
            // Sage, Finding 2 -- e.g. an alternation-under-a-quantifier
            // pattern like "(a|aa)+$" passes the screen but is genuinely
            // exponential-time against std::regex; measured ~1.8s at a
            // 36-byte input, well within kMaxRegexInputBytes). Since this
            // runs on the single Kafka-consumer thread that also runs the
            // SIGHUP reload check, an unbounded regex_search here is a
            // full pipeline-stall DoS from one crafted event. See
            // JsonSafety.h's regex_search_bounded() doc comment (Vega) for
            // the full design -- this condition's field name + pattern are
            // logged on a timeout since FieldCondition::matches() has no
            // access to the owning Rule's id (that would require a
            // signature change to a struct outside this file's ownership;
            // see Rule.h).
            const auto outcome = regex_search_bounded(actual, *compiled);
            if (outcome == RegexSearchOutcome::TimedOut) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: regex condition on field '" << field
                    << "' timed out (>" << kRegexSearchTimeout.count()
                    << "ms) against event data -- treated as non-match; pattern: " << value;
            }
            return outcome == RegexSearchOutcome::Matched;
        }
        case Op::gt: {
            double actual = 0.0, threshold = 0.0;
            if (!ev.has(field) || !parse_full_double(ev.get(field), actual) ||
                !parse_full_double(value, threshold)) {
                return false;
            }
            return actual > threshold;
        }
        case Op::lt: {
            double actual = 0.0, threshold = 0.0;
            if (!ev.has(field) || !parse_full_double(ev.get(field), actual) ||
                !parse_full_double(value, threshold)) {
                return false;
            }
            return actual < threshold;
        }
        case Op::gte: {
            double actual = 0.0, threshold = 0.0;
            if (!ev.has(field) || !parse_full_double(ev.get(field), actual) ||
                !parse_full_double(value, threshold)) {
                return false;
            }
            return actual >= threshold;
        }
        case Op::lte: {
            double actual = 0.0, threshold = 0.0;
            if (!ev.has(field) || !parse_full_double(ev.get(field), actual) ||
                !parse_full_double(value, threshold)) {
                return false;
            }
            return actual <= threshold;
        }
        case Op::between: {
            double actual = 0.0, min_bound = 0.0, max_bound = 0.0;
            if (!ev.has(field) || !parse_full_double(ev.get(field), actual) ||
                !parse_bounds(value, min_bound, max_bound)) {
                return false;
            }
            return actual >= min_bound && actual <= max_bound;
        }
        case Op::in_list:
            if (!ev.has(field)) return false;
            // icase uses ListStore's dedicated case-insensitive lookup
            // (linear scan) rather than lowercasing both sides here, so a
            // list stays keyed by its original-case entries for every OTHER
            // consumer (e.g. ThreatIntelFeed writes, which never lowercase)
            // -- see Rule.h's doc comment on contains_icase/get_icase.
            return icase ? lists.contains_icase(value, ev.get(field)) : lists.contains(value, ev.get(field));
        case Op::in_list_active: {
            if (!ev.has(field)) return false;
            const auto stored = icase ? lists.get_icase(value, ev.get(field)) : lists.get(value, ev.get(field));
            return stored.has_value() && *stored != "disabled";
        }
    }
    return false;
}

bool Rule::base_matches(const NormalizedEvent& ev, const std::set<int>& matched_ids,
                         const ListStore& lists) const {
    if (!event_types.empty()) {
        if (std::find(event_types.begin(), event_types.end(), ev.event_type) == event_types.end()) {
            return false;
        }
    } else if (!event_type.empty() && ev.event_type != event_type) {
        return false;
    }
    if (!os.empty() && ev.os != os) return false;
    if (if_sid.has_value() && matched_ids.count(*if_sid) == 0) return false;
    for (const auto& cond : conditions) {
        if (!cond.matches(ev, lists)) return false;
    }
    return true;
}

bool Rule::correlation_matches(OccurrenceHistory& history, const std::string& group_key,
                                std::int64_t now_ms) const {
    if (frequency > 1) {
        if (timeframe_seconds <= 0) return false;  // fail closed: misconfigured
        const int count = history.count_recent(id, group_key, now_ms,
                                                 static_cast<std::int64_t>(timeframe_seconds) * 1000);
        if (count < frequency) return false;
    }
    if (!if_matched_sid.empty()) {
        if (timeframe_seconds <= 0) return false;  // fail closed: misconfigured
        bool any_matched = false;
        for (int target_id : if_matched_sid) {
            if (history.count_recent(target_id, group_key, now_ms,
                                      static_cast<std::int64_t>(timeframe_seconds) * 1000) > 0) {
                any_matched = true;
                break;
            }
        }
        if (!any_matched) return false;
    }
    return true;
}

void RuleEngine::load(std::vector<Rule> rules) {
    for (auto& rule : rules) {
        for (auto& cond : rule.conditions) {
            if (cond.op != FieldCondition::Op::regex) continue;
            try {
                auto flags = std::regex::ECMAScript | std::regex::optimize;
                if (cond.icase) flags |= std::regex::icase;
                cond.compiled = std::make_shared<std::regex>(cond.value, flags);
            } catch (const std::regex_error& e) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: invalid regex for rule " << rule.id
                    << " field '" << cond.field << "': " << e.what();
                cond.compiled.reset();
            }
        }
    }

    // Stable dependency ordering: a rule is placed once its if_sid parent
    // (if any) has already been placed, has no parent, or its parent isn't
    // in this ruleset at all (a dangling reference must never block
    // startup). Worst case O(n^2) on a genuine if_sid cycle -- acceptable
    // for ruleset sizes in the hundreds; the cycle members are appended in
    // their original order rather than dropped.
    std::set<int> ids;
    for (const auto& r : rules) ids.insert(r.id);

    std::vector<Rule> ordered;
    ordered.reserve(rules.size());
    std::vector<bool> placed(rules.size(), false);
    std::set<int> placed_ids;
    std::size_t remaining = rules.size();

    for (std::size_t pass = 0; pass < rules.size() && remaining > 0; ++pass) {
        for (std::size_t i = 0; i < rules.size(); ++i) {
            if (placed[i]) continue;
            const auto& r = rules[i];
            const bool ready = !r.if_sid.has_value() || placed_ids.count(*r.if_sid) != 0 ||
                                ids.count(*r.if_sid) == 0;
            if (!ready) continue;
            ordered.push_back(r);
            placed[i] = true;
            placed_ids.insert(r.id);
            --remaining;
        }
    }
    for (std::size_t i = 0; i < rules.size(); ++i) {
        if (!placed[i]) ordered.push_back(rules[i]);
    }

    rules_ = std::move(ordered);
    rule_count_.store(rules_.size(), std::memory_order_relaxed);

    // A rule needs its occurrences tracked if it gates on its own frequency,
    // or if some other rule's if_matched_sid references it. Untracked rules
    // never touch OccurrenceHistory in eval() -- bounded cost, not paid by
    // rules with no correlation configured at all.
    tracked_rule_ids_.clear();
    for (const auto& r : rules_) {
        if (r.frequency > 1) tracked_rule_ids_.insert(r.id);
        for (int target_id : r.if_matched_sid) tracked_rule_ids_.insert(target_id);
    }

    // Sweep window per tracked rule id: the longest timeframe any rule
    // actually needs that id's history retained for (its own frequency
    // timeframe, or the longest timeframe among rules that reference it via
    // if_matched_sid).
    max_window_ms_.clear();
    for (const auto& r : rules_) {
        if (r.frequency > 1 && r.timeframe_seconds > 0) {
            auto& w = max_window_ms_[r.id];
            w = std::max(w, static_cast<std::int64_t>(r.timeframe_seconds) * 1000);
        }
        if (!r.if_matched_sid.empty() && r.timeframe_seconds > 0) {
            for (int target_id : r.if_matched_sid) {
                auto& w = max_window_ms_[target_id];
                w = std::max(w, static_cast<std::int64_t>(r.timeframe_seconds) * 1000);
            }
        }
    }
    for (int rule_id : tracked_rule_ids_) {
        max_window_ms_.try_emplace(rule_id, kDefaultSweepWindowMs);
    }
    events_since_sweep_ = 0;

    // A rule whose if_matched_sid references an in-ruleset target with a
    // DIFFERENT same_field will never fire: the lookup key it queries is
    // grouped by its own same_field, but the target recorded its occurrences
    // grouped by the target's same_field -- the keys can never match. This is
    // a silent false negative with no other signal, so warn loudly at load
    // time instead of leaving it undiagnosable.
    std::map<int, const Rule*> by_id;
    for (const auto& r : rules_) by_id[r.id] = &r;
    for (const auto& r : rules_) {
        // A disabled if_sid parent is skipped in eval() before it can ever
        // insert into matched_ids, so this child's if_sid check can never
        // pass -- same silent-false-negative shape as the same_field
        // mismatch below (and the same "warn, don't reject" posture: a
        // disabled rule is a legitimate operator choice, not necessarily a
        // mistake, but a dependent child silently going dark as a side
        // effect of it is worth surfacing).
        if (r.if_sid.has_value()) {
            auto it = by_id.find(*r.if_sid);
            if (it != by_id.end() && !it->second->enabled) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: rule " << r.id << " if_sid references rule "
                    << *r.if_sid << " which is disabled -- rule " << r.id
                    << " can never fire until its parent is re-enabled";
            }
        }
        for (int target_id : r.if_matched_sid) {
            auto it = by_id.find(target_id);
            if (it == by_id.end()) continue;  // dangling reference; tolerated elsewhere
            if (it->second->same_field != r.same_field) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: rule " << r.id
                    << " if_matched_sid references rule " << target_id << " but same_field differs ('"
                    << r.same_field << "' vs '" << it->second->same_field
                    << "') -- this if_matched_sid dependency can never match; both rules must use "
                       "the same same_field";
            }
            if (!it->second->enabled) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: rule " << r.id
                    << " if_matched_sid references rule " << target_id
                    << " which is disabled -- this dependency can never match until the target is "
                       "re-enabled";
            }
        }
    }
}

std::vector<Match> RuleEngine::eval(const NormalizedEvent& ev) {
    std::vector<Match> matches;
    std::set<int> matched_ids;

    // Event-time, not wall-clock, so a Kafka backlog replayed after downtime
    // still correlates correctly instead of bursting every backlogged event
    // into the same window -- but ev.unix_time is attacker-controlled (it
    // comes straight from the osquery client's own JSON), so it's only
    // trusted up to a small forward clock-skew allowance; see
    // clamp_correlation_now_ms's doc comment in RuleEngine.h.
    const std::int64_t wall_clock_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
    const std::int64_t now_ms = clamp_correlation_now_ms(ev.unix_time, wall_clock_ms);

    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        if (!rule.base_matches(ev, matched_ids, lists_)) continue;

        const bool self_tracked = tracked_rule_ids_.count(rule.id) != 0;
        const bool needs_group_key = self_tracked || !rule.if_matched_sid.empty();
        std::string group_key;
        if (needs_group_key) {
            // A same_field that this event doesn't carry must not collapse
            // onto one shared "" bucket across every host lacking that field
            // -- fall back to per-host grouping instead, same as when
            // same_field isn't set on the rule at all.
            group_key = (rule.same_field.empty() || !ev.has(rule.same_field))
                            ? ev.host_identifier
                            : ev.get(rule.same_field);
        }
        if (self_tracked) {
            // Recorded on the base-condition match, not on this rule's own
            // correlation_matches() result: an if_matched_sid referencer is
            // satisfied by the target's underlying condition having
            // occurred, not by the target separately having reached its own
            // frequency threshold (if it has one) -- mirrors Wazuh's
            // if_matched_sid semantics.
            history_.record(rule.id, group_key, now_ms);
        }
        if (!rule.correlation_matches(history_, group_key, now_ms)) continue;

        matched_ids.insert(rule.id);
        matches.push_back(
            Match{rule.id, rule.level, rule.description, rule.groups, rule.mitre, rule.no_log});
    }

    // Independent, volume-agnostic eviction: count_recent() only prunes the
    // exact (rule_id, group_key) it's asked about, so a key that's recorded
    // but never queried again would otherwise sit in memory forever. Sweep
    // periodically instead of on every event to keep the amortized cost low.
    if (++events_since_sweep_ >= kSweepIntervalEvents) {
        events_since_sweep_ = 0;
        for (const auto& [rule_id, window_ms] : max_window_ms_) {
            history_.prune_rule(rule_id, now_ms, window_ms);
        }
    }

    return matches;
}

}  // namespace vajra_engine
