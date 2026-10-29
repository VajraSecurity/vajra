#ifndef VAJRA_ENGINE_RULE_ENGINE_H
#define VAJRA_ENGINE_RULE_ENGINE_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "vajra_engine/OccurrenceHistory.h"
#include "vajra_engine/Rule.h"

namespace vajra_engine {

// Correlation clock for one event: event_unix_time_seconds (attacker-
// controlled -- it comes straight from the osquery client's own JSON) is
// trusted as-is only up to a small forward clock-skew allowance ahead of
// wall_clock_ms; anything further in the future falls back to wall-clock, so
// a single poisoned/misconfigured timestamp can't pin a frequency/
// if_matched_sid window open indefinitely. A non-positive timestamp (no
// timestamp present) also falls back to wall-clock. Exposed as a free
// function so it's directly unit-testable without depending on real time.
std::int64_t clamp_correlation_now_ms(std::int64_t event_unix_time_seconds,
                                       std::int64_t wall_clock_ms);

struct Match {
    int rule_id = 0;
    int level = 0;
    std::string description;
    std::vector<std::string> groups;
    std::vector<std::string> mitre;
    bool no_log = false;
};

class RuleEngine {
public:
    // Precompiles regex conditions, orders rules so an if_sid parent is
    // always evaluated before its children (stable sort; a cyclic or
    // dangling if_sid reference is left in its original position rather
    // than rejected, matching the tolerant "never block startup" posture
    // used everywhere else in this ruleset), and computes which rule ids
    // need occurrence history tracked (self frequency>1, or referenced as
    // an if_matched_sid target) so untracked rules cost nothing in eval().
    void load(std::vector<Rule> rules);

    ListStore& lists() { return lists_; }
    const ListStore& lists() const { return lists_; }

    // Not const: correlation records each tracked rule's occurrence as a
    // side effect. eval()/load() are not internally locked -- safe only
    // because both are called exclusively from the single Kafka consumer
    // thread (eval() per message; load() on a SIGHUP-triggered reload, via
    // KafkaConsumer::run()'s on_tick callback -- see main.cpp). Never call
    // either from a second thread without adding synchronization.
    //
    // Reload note: load() replaces rules_/tracked_rule_ids_/max_window_ms_
    // wholesale but never touches history_ -- a rule id's prior occurrence
    // timestamps survive a reload even if that id's frequency/timeframe/
    // same_field changed shape, or the id was dropped from the ruleset
    // entirely (in which case its history is simply never queried again,
    // and never swept either, since sweeping only visits tracked_rule_ids_
    // -- a small, bounded per-reload leak, not unbounded growth). This is a
    // known, accepted gap (matches ListStore's lists-don't-retract-on-
    // reload gap in spirit): a hot-reloaded rule that reuses an id with a
    // different frequency/timeframe could see a stale pre-reload occurrence
    // count immediately after reload, producing an early/spurious match
    // instead of a clean new correlation window. Not fixed here because a
    // safe fix needs to distinguish "id reused with the same
    // shape" (should keep counting) from "id reused with new
    // shape" (should reset) rather than clearing all history
    // indiscriminately on every reload, which would itself break
    // legitimate in-progress correlation windows for every UNCHANGED rule.
    std::vector<Match> eval(const NormalizedEvent& ev);

    // rules_.size(), but load() and eval() only ever run on the single
    // consumer thread while this may be read from a metrics-endpoint thread
    // concurrently (see MetricsServer) -- rule_count_ is the only piece of
    // RuleEngine's state safe to read cross-thread for exactly that reason.
    std::size_t size() const { return rule_count_.load(std::memory_order_relaxed); }

private:
    std::vector<Rule> rules_;
    std::atomic<std::size_t> rule_count_{0};
    ListStore lists_;
    OccurrenceHistory history_;
    std::set<int> tracked_rule_ids_;
    // Per tracked rule id, the longest timeframe any rule actually needs its
    // history retained for -- computed once in load(). Used by eval()'s
    // periodic sweep (see OccurrenceHistory::prune_rule) to bound memory
    // independent of query volume.
    std::map<int, std::int64_t> max_window_ms_;
    std::size_t events_since_sweep_ = 0;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_RULE_ENGINE_H
