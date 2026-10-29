#include "vajra_engine/CorrelationEngine.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include "../../common/logger.h"

namespace vajra_engine {
namespace {

// ===========================================================================
// Bounded memory -- the explicit bound this correlation layer must never
// exceed (see CorrelationEngine.h's class doc comment and the task that
// prompted this file: "must not introduce unbounded memory growth").
//
// Two independent caps, both enforced regardless of event volume or how
// many distinct entity values (hosts/users/IPs -- all attacker/endpoint
// controlled, since they come straight from event fields) an attacker tries
// to spray at the engine:
//
//   1. kDefaultMaxTrackedGroups: the number of distinct group_keys tracked
//      PER correlation rule. When a genuinely NEW group_key would exceed
//      this, the least-recently-touched existing group is evicted first
//      (see get_or_create_group()) -- so cardinality can never grow past
//      this cap, no matter how many distinct hosts/users/IPs are seen.
//   2. kDefaultMaxEventsPerGroup: the number of contributing events kept
//      PER group. When a push would exceed this, the oldest entry is
//      dropped (see ingest()) -- so a burst of matches within a single
//      still-open window can't grow that group's memory unboundedly either.
//
// Worst-case memory for one correlation rule is therefore:
//     max_tracked_groups * max_events_per_group * sizeof(ContributingEvent)
// sizeof(ContributingEvent) is dominated by its `value` string, which is
// only ever populated for "value_count" rules and capped at
// kMaxValueBytes; for event_count/temporal/temporal_ordered rules it stays
// empty (small-string-optimized, no heap allocation at all on any common
// std::string implementation). With the defaults below:
//     event_count/temporal(_ordered): 2000 * 100 * ~40 bytes  ~= 8 MB / rule
//     value_count (worst case, 128-byte values): 2000*100*~160 bytes ~= 32 MB / rule
// Total engine-wide state is then bounded by (number of correlation rules
// the OPERATOR configured) * (per-rule bound above) -- the rule COUNT is
// trusted config, not attacker input, exactly like RuleEngine's own rule
// count. This is deliberately independent from, and in addition to, the
// periodic sweep (kSweepIntervalEvents below) that reclaims groups whose
// events have all aged out of the timespan window -- the sweep bounds
// LONG-TERM growth (quiet group_keys eventually vanish), the two caps above
// bound WORST-CASE growth even within one still-active window.
constexpr std::size_t kDefaultMaxTrackedGroups = 2000;
constexpr std::size_t kDefaultMaxEventsPerGroup = 100;
constexpr std::size_t kMaxValueBytes = 128;
// Hard ceilings on the PER-RULE overrides above (max_tracked_groups /
// max_events_per_group in the ruleset JSON). Unlike every other cardinality
// knob in this engagement (RulesetLoader.cpp's kMaxRules/
// kMaxConditionsPerRule/kMaxEntriesPerList), these two fields were being
// read straight off ruleset JSON with only a "<=0 -> use default" floor and
// NO upper bound -- group_key values are attacker/endpoint-controlled
// (host/user/IP straight off the Kafka wire, per this file's own comment
// above), so a ruleset entry with e.g. "max_tracked_groups": 100000000 (an
// authoring typo, or a compromised console session) turns directly into
// unbounded-in-practice memory growth. 5x the documented defaults gives
// real operational headroom for high-cardinality deployments while keeping
// worst-case per-rule memory in the hundreds-of-MB range, not unbounded.
constexpr std::size_t kMaxTrackedGroupsCeiling = 10000;
constexpr std::size_t kMaxEventsPerGroupCeiling = 500;
// Sweep every N ingested (event, not just matching) calls, amortizing the
// full-state walk instead of paying it per event -- same strategy and
// rationale as RuleEngine.cpp's kSweepIntervalEvents.
constexpr std::size_t kSweepIntervalEvents = 1000;

std::string truncate_value(std::string v) {
    if (v.size() > kMaxValueBytes) v.resize(kMaxValueBytes);
    return v;
}

std::string resolve_field(const NormalizedEvent& ev, const std::string& field) {
    if (field == "host_identifier") return ev.host_identifier;
    return ev.get(field);
}

CorrelationRule::Type parse_type(const std::string& s) {
    if (s == "event_count") return CorrelationRule::Type::event_count;
    if (s == "value_count") return CorrelationRule::Type::value_count;
    if (s == "temporal") return CorrelationRule::Type::temporal;
    if (s == "temporal_ordered") return CorrelationRule::Type::temporal_ordered;
    throw CorrelationRulesetError("unknown correlation 'type' '" + s + "'");
}

CorrelationRule parse_correlation_rule(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("id")) {
        throw CorrelationRulesetError("correlation rule requires an 'id'");
    }
    if (!j.contains("type")) {
        throw CorrelationRulesetError("correlation rule " + j.at("id").dump() + " requires a 'type'");
    }
    if (!j.contains("rules") || !j.at("rules").is_array() || j.at("rules").empty()) {
        throw CorrelationRulesetError("correlation rule " + j.at("id").dump() +
                                       " requires a non-empty 'rules' array (the detection rule ids it "
                                       "correlates)");
    }

    CorrelationRule rule;
    rule.id = j.at("id").get<int>();
    rule.type = parse_type(j.at("type").get<std::string>());
    rule.description = j.value("description", "");
    rule.level = j.value("level", 0);
    if (j.contains("groups")) rule.groups = j.at("groups").get<std::vector<std::string>>();
    if (j.contains("mitre")) rule.mitre = j.at("mitre").get<std::vector<std::string>>();
    rule.enabled = j.value("enabled", true);

    for (const auto& item : j.at("rules")) rule.rule_ids.push_back(item.get<int>());

    if (j.contains("group_by")) rule.group_by = j.at("group_by").get<std::vector<std::string>>();
    rule.timespan_seconds = j.value("timespan", 0);

    if (rule.type == CorrelationRule::Type::value_count) {
        if (!j.contains("field") || !j.at("field").is_string() || j.at("field").get<std::string>().empty()) {
            throw CorrelationRulesetError("correlation rule " + std::to_string(rule.id) +
                                           " has type 'value_count' but no non-empty 'field'");
        }
        rule.field = j.at("field").get<std::string>();
    }

    // Sigma-style {"condition": {"gte": N}}, with a flat "threshold" as
    // ergonomic shorthand for the common case. Only "gte" is supported
    // (matching frequency's own ">=" semantics) -- lt/lte/eq are a
    // deliberate scope decision, not a missing feature that broke (same
    // posture ThreatIntelFeed.h documents for STIX's simple-equality-only
    // scope).
    if (j.contains("condition") && j.at("condition").is_object()) {
        rule.threshold = j.at("condition").value("gte", 0);
    } else {
        rule.threshold = j.value("threshold", 0);
    }

    rule.max_tracked_groups = j.value("max_tracked_groups", static_cast<std::size_t>(0));
    rule.max_events_per_group = j.value("max_events_per_group", static_cast<std::size_t>(0));
    // Reject (not silently clamp) an out-of-bounds override -- same
    // fail-closed posture RulesetLoader.cpp uses for its own ceilings, so a
    // misconfigured value surfaces as an immediate, actionable load error
    // instead of silently taking effect at a size the engine never intended
    // to allow.
    if (rule.max_tracked_groups > kMaxTrackedGroupsCeiling) {
        throw CorrelationRulesetError("correlation rule " + std::to_string(rule.id) +
                                       ": max_tracked_groups exceeds the " +
                                       std::to_string(kMaxTrackedGroupsCeiling) + " ceiling");
    }
    if (rule.max_events_per_group > kMaxEventsPerGroupCeiling) {
        throw CorrelationRulesetError("correlation rule " + std::to_string(rule.id) +
                                       ": max_events_per_group exceeds the " +
                                       std::to_string(kMaxEventsPerGroupCeiling) + " ceiling");
    }

    return rule;
}

}  // namespace

std::vector<CorrelationRule> parse_correlation_rules(const nlohmann::json& doc) {
    std::vector<CorrelationRule> rules;
    if (!doc.is_object() || !doc.contains("correlations")) return rules;
    const auto& arr = doc.at("correlations");
    if (!arr.is_array()) throw CorrelationRulesetError("'correlations' must be an array");
    for (const auto& item : arr) rules.push_back(parse_correlation_rule(item));
    return rules;
}

std::vector<CorrelationRule> load_correlation_rules_file(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        throw CorrelationRulesetError("ruleset file not found: " + path);
    }
    std::ifstream in(path);
    if (!in.is_open()) {
        throw CorrelationRulesetError("could not open ruleset file: " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(buf.str());
    } catch (const nlohmann::json::parse_error& e) {
        throw CorrelationRulesetError(std::string("invalid JSON in ") + path + ": " + e.what());
    }
    return parse_correlation_rules(doc);
}

void CorrelationEngine::load(std::vector<CorrelationRule> rules) {
    std::map<int, RuleState> new_states;

    for (auto& r : rules) {
        if (!r.enabled) continue;
        if (r.rule_ids.empty()) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: correlation rule " << r.id
                                        << " has an empty 'rules' list -- never active";
            continue;
        }
        if (r.timespan_seconds <= 0) {
            BOOST_LOG_TRIVIAL(warning)
                << __SRCREF__ << "vajra_engine: correlation rule " << r.id
                << " has no valid 'timespan' -- misconfigured, never active (fails closed)";
            continue;
        }
        if ((r.type == CorrelationRule::Type::event_count || r.type == CorrelationRule::Type::value_count) &&
            r.threshold <= 0) {
            BOOST_LOG_TRIVIAL(warning)
                << __SRCREF__ << "vajra_engine: correlation rule " << r.id
                << " has no valid threshold (>=1 required for event_count/value_count) -- "
                   "misconfigured, never active (fails closed, NOT defaulted to 1)";
            continue;
        }

        // Preserve an existing rule id's in-flight group state across a
        // reload IF its shape (type/rule_ids/group_by/timespan/field) is
        // unchanged -- same reasoning as RuleEngine.h's documented history-
        // survives-reload behavior: wiping every group on every reload would
        // truncate a legitimate in-progress multi-stage-attack window just
        // because an operator pushed an unrelated ruleset tweak elsewhere in
        // the same file. A rule whose shape DID change starts with a clean
        // window (old entries would be scored against a condition they were
        // never recorded for).
        auto old_it = rule_states_.find(r.id);
        RuleState state;
        state.rule = r;
        if (old_it != rule_states_.end() && old_it->second.rule.type == r.type &&
            old_it->second.rule.rule_ids == r.rule_ids && old_it->second.rule.group_by == r.group_by &&
            old_it->second.rule.timespan_seconds == r.timespan_seconds &&
            old_it->second.rule.field == r.field) {
            state.groups = std::move(old_it->second.groups);
        }
        new_states.emplace(r.id, std::move(state));
    }

    rule_states_ = std::move(new_states);

    rule_id_to_correlations_.clear();
    std::size_t group_total = 0;
    for (const auto& [cid, state] : rule_states_) {
        for (int rid : state.rule.rule_ids) rule_id_to_correlations_[rid].push_back(cid);
        group_total += state.groups.size();
    }
    events_since_sweep_ = 0;

    // Publish the atomics the metrics-endpoint thread reads (see
    // CorrelationEngine.h's doc comments on rule_count()/
    // tracked_group_count()). load() itself only ever runs on the single
    // Kafka consumer thread (same contract as RuleEngine::load()), so this
    // store has no concurrent writer to race with -- it exists purely to
    // safely PUBLISH the new value to the metrics thread's reads.
    rule_count_.store(rule_states_.size(), std::memory_order_relaxed);
    tracked_group_count_.store(group_total, std::memory_order_relaxed);
}

std::string CorrelationEngine::compute_group_key(const NormalizedEvent& ev,
                                                   const std::vector<std::string>& group_by) const {
    static const std::vector<std::string> kDefaultGroupBy = {"host_identifier"};
    const auto& fields = group_by.empty() ? kDefaultGroupBy : group_by;
    // Length-prefixed (netstring-style) encoding, NOT a bare separator join.
    // A bare '\x1f'-joined scheme is not injective when a field VALUE itself
    // can contain a raw 0x1F byte: with group_by having 2+ fields, tuples
    // like (parent_executable="ab", command_line="\x1fcd") and
    // (parent_executable="ab\x1f", command_line="cd") both join to the
    // identical byte string "ab\x1f\x1fcd\x1f", silently merging two
    // different entities' correlation windows. Event field VALUES come
    // straight off the Kafka wire (Decoder::decode's flatten(), see
    // NormalizedEvent.h) which is unauthenticated plaintext -- any byte,
    // including 0x1F, is attacker/endpoint-reachable in a field like
    // process.command_line or file.path, so this isn't hypothetical. A
    // decimal-length-then-colon prefix per field uniquely determines how
    // many raw bytes follow regardless of their content, so no two distinct
    // field-value tuples can ever produce the same key (the standard
    // netstring construction, used specifically to avoid this class of
    // bug). group_key stays an opaque map key -- nothing parses it back
    // apart (not IncidentWriter, not the `incidents.group_key` column), so
    // this is a drop-in replacement with no behavior change for any
    // single-field (or any collision-free) group_by.
    std::string key;
    for (const auto& field : fields) {
        const std::string v = resolve_field(ev, field);
        key += std::to_string(v.size());
        key += ':';
        key += v;
    }
    return key;
}

CorrelationEngine::GroupWindow& CorrelationEngine::get_or_create_group(RuleState& state,
                                                                        const std::string& group_key,
                                                                        std::int64_t now_ms) {
    auto it = state.groups.find(group_key);
    if (it != state.groups.end()) {
        it->second.last_touched_ms = now_ms;
        return it->second;
    }

    const std::size_t cap =
        state.rule.max_tracked_groups > 0 ? state.rule.max_tracked_groups : kDefaultMaxTrackedGroups;
    if (state.groups.size() >= cap) {
        // Evict the least-recently-touched group to make room -- bounded
        // O(cap) scan, only paid when a genuinely NEW group_key arrives
        // while already at capacity, not on every event. See this file's
        // "Bounded memory" comment.
        auto victim = state.groups.begin();
        for (auto cand = state.groups.begin(); cand != state.groups.end(); ++cand) {
            if (cand->second.last_touched_ms < victim->second.last_touched_ms) victim = cand;
        }
        state.groups.erase(victim);
        tracked_group_count_.fetch_sub(1, std::memory_order_relaxed);
    }

    auto [new_it, inserted] = state.groups.emplace(group_key, GroupWindow{});
    (void)inserted;
    new_it->second.last_touched_ms = now_ms;
    tracked_group_count_.fetch_add(1, std::memory_order_relaxed);
    return new_it->second;
}

void CorrelationEngine::prune_window(GroupWindow& window, std::int64_t now_ms, std::int64_t window_ms) const {
    const std::int64_t cutoff = now_ms - window_ms;
    while (!window.events.empty() && window.events.front().timestamp_ms < cutoff) {
        window.events.pop_front();
    }
}

bool CorrelationEngine::evaluate_condition(const CorrelationRule& rule, const GroupWindow& window) const {
    switch (rule.type) {
        case CorrelationRule::Type::event_count: {
            return static_cast<int>(window.events.size()) >= rule.threshold;
        }
        case CorrelationRule::Type::value_count: {
            std::set<std::string> distinct;
            for (const auto& e : window.events) {
                if (!e.value.empty()) distinct.insert(e.value);
            }
            return static_cast<int>(distinct.size()) >= rule.threshold;
        }
        case CorrelationRule::Type::temporal: {
            std::set<int> seen;
            for (const auto& e : window.events) seen.insert(e.rule_id);
            for (int id : rule.rule_ids) {
                if (seen.count(id) == 0) return false;
            }
            return true;
        }
        case CorrelationRule::Type::temporal_ordered: {
            // Subsequence check over the window in insertion order. Like
            // OccurrenceHistory's own pruning (RuleEngine.cpp), this
            // assumes events are pushed in roughly non-decreasing
            // event-time order per group -- true here because a single
            // group_key is only ever touched from the single Kafka consumer
            // thread, processing messages in delivery order, and
            // now_ms/event timestamps are monotonic-ish per host in
            // practice. A genuinely out-of-order replay could under-detect
            // (miss a true ordered sequence) but never over-detect (falsely
            // claim an order that didn't happen), which is the safe
            // direction for a security detection to be wrong in.
            std::size_t idx = 0;
            for (const auto& e : window.events) {
                if (idx < rule.rule_ids.size() && e.rule_id == rule.rule_ids[idx]) ++idx;
            }
            return idx >= rule.rule_ids.size();
        }
    }
    return false;
}

Incident CorrelationEngine::build_incident(const CorrelationRule& rule, const std::string& group_key,
                                            const GroupWindow& window) const {
    Incident inc;
    inc.correlation_rule_id = rule.id;
    inc.description = rule.description;
    inc.level = rule.level;
    inc.groups = rule.groups;
    inc.mitre = rule.mitre;
    inc.group_by_fields = rule.group_by.empty() ? std::vector<std::string>{"host_identifier"} : rule.group_by;
    inc.group_key = group_key;
    if (!window.events.empty()) {
        inc.first_seen_ms = window.events.front().timestamp_ms;
        inc.last_seen_ms = window.events.back().timestamp_ms;
    }
    inc.contributing.reserve(window.events.size());
    for (const auto& e : window.events) {
        inc.contributing.push_back(IncidentContribution{e.rule_id, e.alert_id, e.timestamp_ms});
    }
    return inc;
}

void CorrelationEngine::sweep_all(std::int64_t now_ms) {
    for (auto& [id, state] : rule_states_) {
        const std::int64_t window_ms = static_cast<std::int64_t>(state.rule.timespan_seconds) * 1000;
        for (auto it = state.groups.begin(); it != state.groups.end();) {
            prune_window(it->second, now_ms, window_ms);
            if (it->second.events.empty()) {
                it = state.groups.erase(it);
                tracked_group_count_.fetch_sub(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }
}

std::vector<Incident> CorrelationEngine::ingest(const NormalizedEvent& ev, const std::vector<Match>& matches,
                                                 const std::vector<AlertWriteResult>& written,
                                                 std::int64_t now_ms) {
    std::vector<Incident> incidents;
    if (matches.empty() || rule_states_.empty()) return incidents;

    // rule_id -> alert_id for THIS event's matches only. A rule_id appears
    // at most once per RuleEngine::eval() call (Match is one-per-rule-per-
    // event), so this is a safe 1:1 map for the duration of this call.
    std::map<int, long long> alert_id_by_rule;
    for (const auto& w : written) alert_id_by_rule[w.rule_id] = w.alert_id;

    for (const auto& m : matches) {
        auto refs_it = rule_id_to_correlations_.find(m.rule_id);
        if (refs_it == rule_id_to_correlations_.end()) continue;  // not referenced by any correlation rule

        for (int correlation_id : refs_it->second) {
            auto state_it = rule_states_.find(correlation_id);
            if (state_it == rule_states_.end()) continue;  // defensive; load() keeps these in sync
            RuleState& state = state_it->second;

            const std::string group_key = compute_group_key(ev, state.rule.group_by);
            GroupWindow& window = get_or_create_group(state, group_key, now_ms);

            ContributingEvent entry;
            entry.rule_id = m.rule_id;
            entry.timestamp_ms = now_ms;
            auto alert_it = alert_id_by_rule.find(m.rule_id);
            entry.alert_id = alert_it != alert_id_by_rule.end() ? alert_it->second : -1;
            if (state.rule.type == CorrelationRule::Type::value_count) {
                entry.value = truncate_value(resolve_field(ev, state.rule.field));
            }

            const std::size_t event_cap = state.rule.max_events_per_group > 0
                                               ? state.rule.max_events_per_group
                                               : kDefaultMaxEventsPerGroup;
            if (window.events.size() >= event_cap) window.events.pop_front();
            window.events.push_back(std::move(entry));

            const std::int64_t window_ms = static_cast<std::int64_t>(state.rule.timespan_seconds) * 1000;
            prune_window(window, now_ms, window_ms);

            if (evaluate_condition(state.rule, window)) {
                incidents.push_back(build_incident(state.rule, group_key, window));
            }
        }
    }

    if (++events_since_sweep_ >= kSweepIntervalEvents) {
        events_since_sweep_ = 0;
        sweep_all(now_ms);
    }

    return incidents;
}

}  // namespace vajra_engine
