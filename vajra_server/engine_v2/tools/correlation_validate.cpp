// vajra_engine_v2_correlation_validate -- offline validator for a
// {"correlations": [...]} ruleset document. Mirrors eval_main.cpp's
// success/failure reporting style (stderr message, non-zero exit on
// failure) but for CORRELATION rules instead of detection rules --
// vajra_engine_v2_eval only loads the "rules" key (Decoder + RuleEngine
// pipeline, no CorrelationEngine involved at all, see its own source), so it
// cannot validate a correlations-only document. See
// rule_engine_ui/API_CONTRACT.md's validation recipe and
// CorrelationEngine.h's load_correlation_rules_file()/CorrelationEngine::load()
// doc comments for the exact two-stage validation this reuses:
//   1. Structural: parse_correlation_rules()/load_correlation_rules_file()
//      throws CorrelationRulesetError on a malformed entry (missing 'id',
//      unknown 'type', empty/non-integer 'rules', missing 'field' on a
//      value_count rule, ...) -- same "reject the whole load" posture as
//      RulesetLoader.cpp's rule/decoder parsing.
//   2. Semantic: CorrelationEngine::load() itself warn-and-skips a
//      structurally-valid-but-misconfigured rule (empty 'rules' array,
//      timespan_seconds <= 0, or threshold <= 0 for event_count/value_count)
//      rather than throwing -- its BOOST_LOG_TRIVIAL(warning) lines are
//      silent here (this tool never calls init_logging(), same as
//      eval_main.cpp), so this duplicates that exact criteria itself to
//      surface a real, specific reason per rule instead of a generic
//      failure.
//
// Usage:
//   VAJRA_ENGINE_RULES=rules.json vajra_engine_v2_correlation_validate

#include <cstdlib>
#include <iostream>
#include <string>

#include "vajra_engine/CorrelationEngine.h"

int main() {
    const char* path = std::getenv("VAJRA_ENGINE_RULES");
    if (!path || !*path) {
        std::cerr << "vajra_engine_v2_correlation_validate: VAJRA_ENGINE_RULES not set\n";
        return 1;
    }

    std::vector<vajra_engine::CorrelationRule> rules;
    try {
        rules = vajra_engine::load_correlation_rules_file(path);
    } catch (const std::exception& e) {
        std::cerr << "vajra_engine_v2_correlation_validate: bad ruleset " << path << ": " << e.what()
                   << "\n";
        return 1;
    }

    // Semantic pre-check -- same criteria as CorrelationEngine::load(), see
    // this file's top comment on why it's duplicated rather than read back
    // from the (silent, uninitialized-logger) engine.
    bool any_misconfigured = false;
    for (const auto& r : rules) {
        if (!r.enabled) continue;
        if (r.rule_ids.empty()) {
            std::cerr << "vajra_engine_v2_correlation_validate: correlation rule " << r.id
                       << " has an empty 'rules' list -- misconfigured, never active\n";
            any_misconfigured = true;
        }
        if (r.timespan_seconds <= 0) {
            std::cerr << "vajra_engine_v2_correlation_validate: correlation rule " << r.id
                       << " has no valid 'timespan' (>0 required) -- misconfigured, never active\n";
            any_misconfigured = true;
        }
        if ((r.type == vajra_engine::CorrelationRule::Type::event_count ||
             r.type == vajra_engine::CorrelationRule::Type::value_count) &&
            r.threshold <= 0) {
            std::cerr << "vajra_engine_v2_correlation_validate: correlation rule " << r.id
                       << " has no valid 'threshold'/'condition.gte' (>=1 required for "
                          "event_count/value_count) -- misconfigured, never active\n";
            any_misconfigured = true;
        }
        if (r.type == vajra_engine::CorrelationRule::Type::value_count && r.field.empty()) {
            std::cerr << "vajra_engine_v2_correlation_validate: correlation rule " << r.id
                       << " has type 'value_count' but no non-empty 'field'\n";
            any_misconfigured = true;
        }
    }

    if (any_misconfigured) {
        std::cerr << "vajra_engine_v2_correlation_validate: bad ruleset " << path
                   << ": one or more correlation rules failed semantic validation (see above)\n";
        return 1;
    }

    // Structural + semantic checks both passed -- also actually load it into
    // a live CorrelationEngine as a final real-engine confirmation (proves
    // e.g. group_by field names etc. don't trip anything at load time
    // either), mirroring eval_main.cpp's "N rule(s) active" confirmation
    // line the backend's validation recipe greps for.
    vajra_engine::CorrelationEngine engine;
    engine.load(rules);
    std::cerr << "vajra_engine_v2_correlation_validate: " << engine.rule_count()
               << " correlation(s) active\n";
    return 0;
}
