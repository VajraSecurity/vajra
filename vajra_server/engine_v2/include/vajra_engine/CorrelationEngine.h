#ifndef VAJRA_ENGINE_CORRELATION_ENGINE_H
#define VAJRA_ENGINE_CORRELATION_ENGINE_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "../../3rdparty/json.hpp"
#include "vajra_engine/AlertWriter.h"
#include "vajra_engine/NormalizedEvent.h"
#include "vajra_engine/RuleEngine.h"

namespace vajra_engine {

// ===========================================================================
// WHY THIS FILE EXISTS -- see the Step-1 verdict in .team/mailbox/re-nyx.md
// for the full analysis with citations. Short version: RuleEngine's own
// frequency/if_matched_sid correlation (RuleEngine.cpp, OccurrenceHistory.h)
// operates on raw EVENT occurrences feeding a SINGLE rule's own match
// decision -- it is Wazuh-style, not an alert-to-alert incident graph. It
// has no notion of "incident", no persisted cross-rule entity, and
// if_matched_sid's dependency is a static pairwise reference declared at
// rule-authoring time, not a dynamic graph over already-fired alerts. This
// file adds that missing layer: it consumes RuleEngine::eval()'s output
// (Match, i.e. an already-decided detection) AFTER the fact, the same signal
// AlertWriter turns into `alerts` rows, and groups matches from MULTIPLE,
// DIFFERENT rule ids into one Incident scoped by a shared entity (host,
// user, IP, ...) and a time window -- the same shape as CrowdStrike's IOA
// chaining, SentinelOne's Storyline, Microsoft Defender for Endpoint's
// alert->incident graph, and Elastic Security's sequence/threshold
// correlation rules. See CorrelationEngine.cpp for the full mapping.
// ===========================================================================

class CorrelationRulesetError : public std::runtime_error {
public:
    explicit CorrelationRulesetError(const std::string& what) : std::runtime_error(what) {}
};

// A correlation rule stitches together matches from MULTIPLE, DIFFERENT
// detection rules (already-fired alerts) into one incident. Modeled on
// Sigma's correlation rule spec (event_count / value_count / temporal /
// temporal_ordered, added to Sigma ~2023) -- see CorrelationEngine.cpp for
// the parser and the full industry mapping.
struct CorrelationRule {
    enum class Type {
        // Sigma "event_count" / Elastic "threshold" rule / Splunk ES
        // risk-based alerting's aggregation step: >= `threshold` matches
        // among `rule_ids`, grouped by `group_by`, within `timespan_seconds`.
        // The classic "N low-fidelity signals from the same entity = one
        // high-fidelity incident" pattern.
        event_count,
        // Sigma "value_count": >= `threshold` DISTINCT values of `field`
        // seen across matches of `rule_ids`, grouped by `group_by`, within
        // `timespan_seconds`. E.g. "one user account touching >= 5 distinct
        // hosts in 10 minutes" -- a lateral-movement fan-out shape Elastic's
        // "new_terms" and Splunk's risk-object cardinality checks target.
        value_count,
        // Sigma "temporal": every id in `rule_ids` matched at least once
        // within the window, grouped by `group_by` -- order-independent
        // co-occurrence (Elastic "indicator-match"-style grouping).
        temporal,
        // Sigma "temporal_ordered" / Elastic "sequence" rules / the causal
        // chaining CrowdStrike's IOA graph and SentinelOne's Storyline both
        // do: every id in `rule_ids` matched, IN THAT ORDER (other matches
        // may interleave), within the window. This is the "recon ->
        // credential access -> lateral movement" kill-chain shape.
        temporal_ordered,
    };

    int id = 0;
    Type type = Type::event_count;
    std::string description;
    int level = 0;
    std::vector<std::string> groups;
    std::vector<std::string> mitre;
    bool enabled = true;

    // Which underlying detection rule ids (RuleEngine::Match::rule_id) feed
    // this correlation -- REQUIRED, non-empty. A rule id here may be a
    // no_log anchor rule: it still counts as a required stage for
    // temporal/temporal_ordered even though it never became a standalone
    // `alerts` row (see Incident::contributing's alert_id == -1 case).
    std::vector<int> rule_ids;
    // Entity fields to group occurrences by, e.g. {"host_identifier"} or
    // {"user.name"}. Empty defaults to {"host_identifier"} (same convention
    // as Rule::same_field). "host_identifier" is special-cased to
    // NormalizedEvent::host_identifier; every other name is read from
    // NormalizedEvent::fields using the same canonical dotted names rule
    // conditions already use. Multiple fields form a composite key (AND of
    // all of them), letting a rule correlate by e.g. {host, user} together.
    std::vector<std::string> group_by;
    // REQUIRED > 0; a rule with timespan_seconds <= 0 is logged as
    // misconfigured and never tracked (fails closed) -- same posture as
    // Rule::correlation_matches' "fail closed: misconfigured" for
    // frequency/if_matched_sid with no timeframe.
    int timespan_seconds = 0;
    // value_count only: the field whose distinct values are counted. Same
    // name resolution as group_by ("host_identifier" special-cased).
    std::string field;
    // event_count / value_count only: the count that must be reached
    // (Sigma's condition.gte). REQUIRED >= 1 for these two types -- a
    // missing/zero threshold is logged as misconfigured and never tracked,
    // deliberately NOT defaulted to 1, because defaulting would make the
    // rule fire on the very first contributing match (fail-OPEN), which is
    // the wrong default for a security detection. temporal/temporal_ordered
    // ignore this field -- their "condition" is coverage of every listed
    // rule_id.
    int threshold = 0;

    // Per-rule bound overrides; <= 0 means "use CorrelationEngine's
    // engine-wide default". See CorrelationEngine.cpp's "Bounded memory"
    // comment for what these bound and the worst-case memory formula.
    std::size_t max_tracked_groups = 0;
    std::size_t max_events_per_group = 0;
};

// One contributing match folded into an Incident.
struct IncidentContribution {
    int rule_id = 0;
    long long alert_id = -1;  // -1: no `alerts` row (no_log match, or the write failed)
    std::int64_t timestamp_ms = 0;
};

// A correlation rule's output: a composite, cross-rule detection built from
// several already-fired matches sharing one entity and one time window.
// Persisted by IncidentWriter into the `incidents` / `incident_alerts`
// tables (engine_v2/schema/incidents.sql).
struct Incident {
    int correlation_rule_id = 0;
    std::string description;
    int level = 0;
    std::vector<std::string> groups;
    std::vector<std::string> mitre;
    std::vector<std::string> group_by_fields;
    std::string group_key;  // the actual entity value(s) this incident is scoped to
    std::int64_t first_seen_ms = 0;
    std::int64_t last_seen_ms = 0;
    std::vector<IncidentContribution> contributing;
};

// Tracks, per correlation rule and per entity group_key, a bounded rolling
// window of contributing matches, and emits an Incident every time a
// relevant new match keeps (or newly makes) that window's condition true.
//
// Threading: same single-consumer-thread contract as RuleEngine -- load()
// and ingest() are not internally locked and must only ever be called from
// the Kafka consumer thread (ingest() per message, load() on a
// SIGHUP-triggered reload). See RuleEngine.h's identical note.
class CorrelationEngine {
public:
    // Replaces the active correlation ruleset wholesale. Per-rule validation
    // (empty rule_ids, timespan_seconds <= 0, missing "field" on
    // value_count, threshold <= 0 on event_count/value_count) is
    // warn-and-skip, not reject-the-whole-load -- one misconfigured
    // correlation rule never blocks every other one from loading, matching
    // RuleEngine::load()'s tolerant posture. Rules referencing rule ids not
    // present in the currently loaded RuleEngine ruleset are accepted too
    // (a dangling reference just never contributes anything -- the two
    // rulesets are loaded independently, see CorrelationEngine.cpp's
    // top comment on why).
    //
    // Does NOT clear existing group state for rule ids that keep the same
    // shape across a reload (mirrors RuleEngine::load()'s documented
    // history-survives-reload gap in spirit) -- see .cpp for the exact
    // behavior and why a full state wipe on every reload would itself be
    // wrong (it would silently truncate an in-progress, legitimate
    // multi-stage attack window right as an operator pushes an unrelated
    // ruleset tweak).
    void load(std::vector<CorrelationRule> rules);

    // Number of currently loaded (enabled + valid) correlation rules --
    // callers use this to skip calling ingest() entirely when it's 0, so an
    // operator not using this feature pays nothing per event (same
    // "untracked costs nothing" philosophy as RuleEngine's
    // tracked_rule_ids_). Backed by an atomic, NOT rule_states_.size()
    // directly: like RuleEngine::size()'s rule_count_ (see RuleEngine.h's
    // doc comment), this is read cross-thread from MetricsServer's own
    // accept-loop thread (see main.cpp's render_metrics()) while load()/
    // ingest() run on the single Kafka consumer thread -- reading
    // rule_states_ (a plain std::map, mutated by load()/ingest()) directly
    // from that other thread would be a data race.
    std::size_t rule_count() const { return rule_count_.load(std::memory_order_relaxed); }

    // Sum of tracked entity groups across every correlation rule -- a
    // memory/metrics introspection hook (exposed via render_metrics()) also
    // used directly by tests to prove the bound in "Bounded memory"
    // (CorrelationEngine.cpp) actually holds. Same cross-thread-safety
    // reasoning as rule_count(): backed by an atomic maintained at every
    // group insert/evict, not computed by summing rule_states_ on demand.
    std::size_t tracked_group_count() const {
        return tracked_group_count_.load(std::memory_order_relaxed);
    }

    // Call once per decoded event, after RuleEngine::eval() (and, if any
    // matches were non-empty, after AlertWriter::write()). `written` is
    // AlertWriter's per-match result for THIS event only (rule_id ->
    // alert_id); `now_ms` should be the SAME clamped correlation clock
    // RuleEngine::eval() used (vajra_engine::clamp_correlation_now_ms) so
    // incident windows and rule-level correlation windows agree on "now"
    // and share the same attacker-timestamp clamping. Returns the incidents
    // newly triggered by this event (almost always empty).
    std::vector<Incident> ingest(const NormalizedEvent& ev, const std::vector<Match>& matches,
                                  const std::vector<AlertWriteResult>& written, std::int64_t now_ms);

private:
    struct ContributingEvent {
        int rule_id = 0;
        std::int64_t timestamp_ms = 0;
        long long alert_id = -1;
        std::string value;  // only populated for value_count rules; length-capped
    };
    struct GroupWindow {
        std::deque<ContributingEvent> events;
        std::int64_t last_touched_ms = 0;
    };
    struct RuleState {
        CorrelationRule rule;
        std::map<std::string, GroupWindow> groups;
    };

    std::string compute_group_key(const NormalizedEvent& ev, const std::vector<std::string>& group_by) const;
    GroupWindow& get_or_create_group(RuleState& state, const std::string& group_key, std::int64_t now_ms);
    void prune_window(GroupWindow& window, std::int64_t now_ms, std::int64_t window_ms) const;
    bool evaluate_condition(const CorrelationRule& rule, const GroupWindow& window) const;
    Incident build_incident(const CorrelationRule& rule, const std::string& group_key,
                             const GroupWindow& window) const;
    void sweep_all(std::int64_t now_ms);

    std::map<int, RuleState> rule_states_;         // correlation_rule_id -> state
    std::map<int, std::vector<int>> rule_id_to_correlations_;  // detection rule_id -> correlation_rule_ids
    std::size_t events_since_sweep_ = 0;
    // See rule_count()/tracked_group_count()'s doc comments: these mirror
    // rule_states_' shape but are the only fields of it safe to read from
    // the metrics-endpoint thread. Kept in sync at every mutation point
    // (load(), get_or_create_group()'s eviction, sweep_all()'s reclaim) --
    // never recomputed by summing rule_states_ from outside the consumer
    // thread.
    std::atomic<std::size_t> rule_count_{0};
    std::atomic<std::size_t> tracked_group_count_{0};
};

// Parses a "correlations" array from an already-parsed JSON document -- see
// CorrelationEngine.cpp for the document shape. Never partially applies:
// throws CorrelationRulesetError on a STRUCTURALLY malformed entry (missing
// "id", unrecognized "type", "rules" absent/empty/not-integers, a
// value_count entry with no "field") -- the same "structural requirement ->
// reject the whole reload" vs. "semantic misconfiguration -> warn and skip
// just that rule" split RulesetLoader.cpp already uses. Purely a parse step;
// callers pass the result to CorrelationEngine::load().
std::vector<CorrelationRule> parse_correlation_rules(const nlohmann::json& doc);

// Reads `path` and returns parse_correlation_rules() applied to its
// "correlations" key (empty vector if the key is absent, so a ruleset file
// with no correlations section is valid and simply loads zero correlation
// rules). This is intentionally a SEPARATE, self-contained file-read/parse
// from RulesetLoader::load_ruleset_file (which owns "rules"/"decoders"/
// "lists") -- RulesetLoader.h/.cpp is Vega's owned file for this engagement
// (see .team/charter-rule-engine.md's ownership map), so this engine adds
// its own tiny loader for its own top-level JSON key rather than editing
// his. Both loaders read the SAME ruleset file (set via VAJRA_ENGINE_RULES)
// so an operator maintains one ruleset document with a "rules" section and
// an optional "correlations" section side by side. Throws
// CorrelationRulesetError on a missing file, invalid JSON, or a malformed
// "correlations" entry.
std::vector<CorrelationRule> load_correlation_rules_file(const std::string& path);

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_CORRELATION_ENGINE_H
