// vajra_engine_v2_correlation_simulate -- offline, ORDERED multi-event
// correlation simulator. Closes a real gap neither vajra_engine_v2_eval nor
// vajra_engine_v2_correlation_validate cover: eval_main.cpp only runs
// Decoder+RuleEngine (no CorrelationEngine at all, one process per corpus but
// still stateless w.r.t. incidents), and correlation_validate.cpp only proves
// a correlations document PARSES/LOADS -- neither ever calls
// CorrelationEngine::ingest() or can show an Incident actually firing. A
// correlation rule (event_count/value_count/temporal/temporal_ordered) needs
// MULTIPLE events fed through ONE live CorrelationEngine instance, in order,
// to ever produce an Incident -- this tool is that missing harness.
//
// Pipeline per event, in file order (mirrors main.cpp's real per-message
// handling at src/main.cpp:407-460, and test_correlation_engine.cpp's
// "recon -> credential access -> lateral movement" flagship end-to-end test,
// which is this file's ground-truth reference for exact call shapes):
//   Envelope::from_json_text() -> Decoder::decode() -> RuleEngine::eval()
//   -> (synthetic AlertWriter::write() stand-in, see below)
//   -> CorrelationEngine::ingest()
//
// No DB/Kafka here (same offline posture as vajra_engine_v2_eval), so there
// is no real AlertWriter to produce AlertWriteResult -- this tool synthesizes
// one instead: an incrementing alert-id counter assigns a fresh id to every
// non-no_log match, in encounter order, exactly the shape
// test_correlation_engine.cpp's own `make_result()` test helper and its
// flagship end-to-end test's `next_alert_id` both already use (real
// AlertWriter::write() has additional DB-side dedup-to-one-OPEN-row behavior
// this tool does not attempt to reproduce -- every non-no_log match here
// gets its own synthetic alert id, which is the correct simplification for
// proving CorrelationEngine's own logic since it only consumes rule_id ->
// alert_id, never re-queries the DB itself).
//
// Usage:
//   VAJRA_ENGINE_RULES=ruleset.json vajra_engine_v2_correlation_simulate [events.ndjson]
//   (reads stdin if no file argument given, same convention as
//   vajra_engine_v2_eval)
//
// `ruleset.json` must be a combined document: {"rules": [...], "correlations": [...]}
// -- both loaded from the SAME path (RulesetLoader.h owns "rules"/"decoders"/
// "lists", CorrelationEngine.h owns "correlations", independently, exactly
// as main.cpp itself does at src/main.cpp:270-316).
//
// Unlike vajra_engine_v2_eval, this tool does NOT fall back to builtin rules
// on a bad ruleset -- it is a testing/proof tool for an operator-authored
// ruleset (already expected to have passed /api/rules/validate and
// /api/correlation-rules/validate), so a load failure is reported and fatal,
// matching vajra_engine_v2_correlation_validate's "surface the real reason,
// never fall back silently" posture rather than eval_main.cpp's
// production-robustness fallback.

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "vajra_engine/CorrelationEngine.h"
#include "vajra_engine/Decoder.h"
#include "vajra_engine/Envelope.h"
#include "vajra_engine/RuleEngine.h"
#include "vajra_engine/RulesetLoader.h"

namespace {

std::string correlation_type_name(vajra_engine::CorrelationRule::Type t) {
    switch (t) {
        case vajra_engine::CorrelationRule::Type::event_count:
            return "event_count";
        case vajra_engine::CorrelationRule::Type::value_count:
            return "value_count";
        case vajra_engine::CorrelationRule::Type::temporal:
            return "temporal";
        case vajra_engine::CorrelationRule::Type::temporal_ordered:
            return "temporal_ordered";
    }
    return "unknown";  // unreachable; keeps -Wswitch/-Werror happy without a default case masking new enumerators
}

// correlation_rule_id -> its CorrelationRule (for printing type/description/
// level alongside a fired Incident, which only carries a copy of some of
// these fields -- see CorrelationEngine.h's Incident struct).
std::string incident_line(const vajra_engine::Incident& inc,
                           const std::map<int, vajra_engine::CorrelationRule>& rules_by_id) {
    std::string type_str = "unknown";
    if (auto it = rules_by_id.find(inc.correlation_rule_id); it != rules_by_id.end()) {
        type_str = correlation_type_name(it->second.type);
    }

    std::string line = "INCIDENT id=" + std::to_string(inc.correlation_rule_id) + " type=" + type_str +
                        " level=" + std::to_string(inc.level) + " group=" + inc.group_key +
                        " description=\"" + inc.description + "\" contributing=[";
    for (std::size_t i = 0; i < inc.contributing.size(); ++i) {
        if (i > 0) line += ", ";
        const auto& c = inc.contributing[i];
        line += std::to_string(c.rule_id) + "@" + std::to_string(c.alert_id);
    }
    line += "]";
    return line;
}

}  // namespace

int main(int argc, char** argv) {
    const char* path = std::getenv("VAJRA_ENGINE_RULES");
    if (!path || !*path) {
        std::cerr << "vajra_engine_v2_correlation_simulate: VAJRA_ENGINE_RULES not set -- a combined "
                     "{\"rules\": [...], \"correlations\": [...]} ruleset document is required\n";
        return 1;
    }

    vajra_engine::RuleEngine rules;
    vajra_engine::Decoder decoder;
    try {
        // Pass &decoder so any "decoders" section in the ruleset is honored
        // too -- matches main.cpp's real startup call (src/main.cpp:277),
        // not eval_main.cpp's decoder-less call, since this tool exists to
        // prove real end-to-end behavior as faithfully as possible offline.
        vajra_engine::load_ruleset_file(path, rules, &decoder);
    } catch (const std::exception& e) {
        std::cerr << "vajra_engine_v2_correlation_simulate: bad ruleset " << path << ": " << e.what() << "\n";
        return 1;
    }

    std::vector<vajra_engine::CorrelationRule> correlation_rules;
    try {
        correlation_rules = vajra_engine::load_correlation_rules_file(path);
    } catch (const std::exception& e) {
        std::cerr << "vajra_engine_v2_correlation_simulate: bad correlations in " << path << ": " << e.what()
                   << "\n";
        return 1;
    }
    std::map<int, vajra_engine::CorrelationRule> rules_by_id;
    for (const auto& r : correlation_rules) rules_by_id[r.id] = r;

    vajra_engine::CorrelationEngine correlation;
    correlation.load(correlation_rules);

    std::cerr << "vajra_engine_v2_correlation_simulate: loaded ruleset " << path << "\n";
    std::cerr << "vajra_engine_v2_correlation_simulate: " << rules.size() << " rule(s) active, "
              << decoder.decoder_rule_count() << " decoder(s) active, " << correlation.rule_count()
              << " correlation(s) active\n";

    std::istream* in = &std::cin;
    std::ifstream file;
    if (argc > 1) {
        file.open(argv[1]);
        if (!file.is_open()) {
            std::cerr << "vajra_engine_v2_correlation_simulate: cannot open " << argv[1] << "\n";
            return 1;
        }
        in = &file;
    }

    long long next_alert_id = 1;
    long events = 0, alerts = 0, anchors = 0, incidents_fired = 0, bad = 0;

    std::string line;
    while (std::getline(*in, line)) {
        if (line.empty()) continue;

        vajra_engine::Envelope env;
        try {
            env = vajra_engine::Envelope::from_json_text(line);
        } catch (const std::exception& e) {
            ++bad;
            std::cerr << "vajra_engine_v2_correlation_simulate: bad line: " << e.what() << "\n";
            continue;
        }
        ++events;

        const auto ev = decoder.decode(env);
        const auto matches = rules.eval(ev);

        // Same shape as AlertWriter::write(): one result per non-no_log
        // match, in the same order, no_log matches skipped entirely (see
        // AlertWriter.h's doc comment) -- see this file's top comment for
        // why a synthetic incrementing id is the correct stand-in here.
        std::vector<vajra_engine::AlertWriteResult> written;
        for (const auto& m : matches) {
            if (m.no_log) {
                ++anchors;
                continue;
            }
            ++alerts;
            std::cout << "ALERT rule=" << m.rule_id << " level=" << m.level << " host=" << env.host_identifier
                      << " type=" << env.event_type << " :: " << m.description << "\n"
                      << "      cmdline: " << ev.get("process.command_line") << "\n";

            vajra_engine::AlertWriteResult r;
            r.rule_id = m.rule_id;
            r.alert_id = next_alert_id++;
            r.newly_inserted = true;
            written.push_back(r);
        }

        if (correlation.rule_count() > 0 && !matches.empty()) {
            // Same clamped event-time clock RuleEngine::eval() used
            // internally and main.cpp/the flagship test both reuse for
            // ingest() (see RuleEngine.h's clamp_correlation_now_ms doc
            // comment) -- keeps rule-level and incident-level correlation
            // windows agreeing on "now" and sharing the same
            // attacker-timestamp clamping.
            const std::int64_t wall_clock_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    std::chrono::system_clock::now().time_since_epoch())
                                                    .count();
            const std::int64_t now_ms = vajra_engine::clamp_correlation_now_ms(ev.unix_time, wall_clock_ms);

            const auto incidents = correlation.ingest(ev, matches, written, now_ms);
            for (const auto& inc : incidents) {
                ++incidents_fired;
                std::cout << incident_line(inc, rules_by_id) << "\n";
            }
        }
    }

    std::cerr << "vajra_engine_v2_correlation_simulate: " << events << " event(s), " << alerts << " alert(s), "
              << anchors << " anchor-only match(es), " << incidents_fired << " incident(s), " << bad
              << " bad line(s)\n";
    return 0;
}
