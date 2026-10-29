#ifndef VAJRA_ENGINE_OCCURRENCE_HISTORY_H
#define VAJRA_ENGINE_OCCURRENCE_HISTORY_H

#include <cstdint>
#include <deque>
#include <map>
#include <string>

namespace vajra_engine {

// Per-(rule_id, group_key) rolling timestamp window, backing frequency/
// timeframe correlation and if_matched_sid cross-event chaining. Only rules
// that are actually referenced by correlation (self frequency>1, or as an
// if_matched_sid target of some other rule -- see RuleEngine::load()'s
// tracked_rule_ids_) are ever recorded here, so untracked rules cost
// nothing. Entries older than the query window are pruned lazily on
// count_recent(), and an emptied deque's map entry is erased so a group_key
// that goes quiet is eventually reclaimed. count_recent() alone only prunes
// the exact (rule_id, group_key) it's asked about, so a group_key that's
// recorded but never queried again (a high-cardinality same_field value that
// never repeats, or an if_matched_sid target whose referencer rarely
// matches) would otherwise sit in memory forever -- prune_rule() provides an
// independent, volume-agnostic sweep for that case; see RuleEngine::eval().
class OccurrenceHistory {
public:
    // Hard cap on entries retained per (rule_id, group_key), independent of
    // the time-based pruning below -- bounds a DoS shape neither
    // count_recent() nor prune_rule() bounds on their own: sustained
    // high-volume matching against ONE group_key (attacker/endpoint-
    // controlled, since group_key comes straight from event data --
    // same_field's value or the host_identifier fallback) WITHIN a single
    // still-open timeframe window, for a rule with a large `frequency`/long
    // `timeframe_seconds`. Time-based pruning only reclaims entries once
    // the window has fully expired; it does nothing to bound growth while
    // the window is still active. Mirrors CorrelationEngine::ingest()'s own
    // per-group event cap (engine_v2/src/CorrelationEngine.cpp,
    // kDefaultMaxEventsPerGroup) added for the analogous new-layer risk --
    // flagged by round-2 adversarial review (Sage, Finding 5) as a gap
    // inherited from the original engine, not introduced by this
    // engagement, but closed here for consistency now that the pattern
    // exists elsewhere in this codebase. Generous enough that no realistic
    // `frequency` threshold is affected: the built-in/documented examples
    // in this ruleset's own conventions are all well under 100 (e.g. "5
    // failed logins in 60s"-scale, see docs/RULE_ENGINE.md); a rule
    // genuinely configured with frequency > 100,000 would undercount past
    // this cap, which has no existing precedent to accommodate.
    static constexpr std::size_t kMaxEntriesPerKey = 100'000;

    void record(int rule_id, const std::string& group_key, std::int64_t now_ms) {
        auto& timestamps = history_[rule_id][group_key];
        if (timestamps.size() >= kMaxEntriesPerKey) timestamps.pop_front();
        timestamps.push_back(now_ms);
    }

    // Prunes entries older than window_ms as a side effect, then returns the
    // remaining count within [now_ms - window_ms, now_ms].
    int count_recent(int rule_id, const std::string& group_key, std::int64_t now_ms,
                      std::int64_t window_ms) {
        auto rule_it = history_.find(rule_id);
        if (rule_it == history_.end()) return 0;
        auto key_it = rule_it->second.find(group_key);
        if (key_it == rule_it->second.end()) return 0;

        auto& timestamps = key_it->second;
        const std::int64_t cutoff = now_ms - window_ms;
        while (!timestamps.empty() && timestamps.front() < cutoff) timestamps.pop_front();

        const int count = static_cast<int>(timestamps.size());
        if (timestamps.empty()) {
            rule_it->second.erase(key_it);
            if (rule_it->second.empty()) history_.erase(rule_it);
        }
        return count;
    }

    // Prunes every group_key under rule_id older than window_ms, independent
    // of which (if any) group_key is currently being queried by
    // count_recent(). Called periodically from RuleEngine::eval() so history
    // for keys that are never re-queried is still reclaimed.
    void prune_rule(int rule_id, std::int64_t now_ms, std::int64_t window_ms) {
        auto rule_it = history_.find(rule_id);
        if (rule_it == history_.end()) return;
        const std::int64_t cutoff = now_ms - window_ms;
        for (auto key_it = rule_it->second.begin(); key_it != rule_it->second.end();) {
            auto& timestamps = key_it->second;
            while (!timestamps.empty() && timestamps.front() < cutoff) timestamps.pop_front();
            if (timestamps.empty()) {
                key_it = rule_it->second.erase(key_it);
            } else {
                ++key_it;
            }
        }
        if (rule_it->second.empty()) history_.erase(rule_it);
    }

private:
    std::map<int, std::map<std::string, std::deque<std::int64_t>>> history_;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_OCCURRENCE_HISTORY_H
