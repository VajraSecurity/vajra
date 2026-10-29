// vajra_engine_eval -- offline rule-engine evaluator.
//
// Reads wire-format NDJSON (one flat JSON event per line, matching what
// KafkaProducerManager actually publishes) from a file or stdin, runs each
// event through the same Decoder + RuleEngine the live vajra_engine uses,
// and prints the alerts that would fire. No Kafka, no DB -- a fast,
// deterministic way to prove the ruleset fires on real captured telemetry
// and to tune rules offline.
//
// Usage:
//   vajra_engine_eval [corpus.ndjson]        # builtin ruleset
//   VAJRA_ENGINE_RULES=rules.json vajra_engine_eval corpus.ndjson

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "vajra_engine/BuiltinRules.h"
#include "vajra_engine/Decoder.h"
#include "vajra_engine/Envelope.h"
#include "vajra_engine/RuleEngine.h"
#include "vajra_engine/RulesetLoader.h"

int main(int argc, char** argv) {
    vajra_engine::RuleEngine rules;
    if (const char* path = std::getenv("VAJRA_ENGINE_RULES"); path && *path) {
        try {
            vajra_engine::load_ruleset_file(path, rules);
            std::cerr << "vajra_engine_eval: loaded ruleset " << path << "\n";
        } catch (const std::exception& e) {
            std::cerr << "vajra_engine_eval: bad ruleset " << path << ": " << e.what()
                      << " -- using builtin rules\n";
            rules.load(vajra_engine::builtin_rules());
        }
    } else {
        rules.load(vajra_engine::builtin_rules());
    }
    std::cerr << "vajra_engine_eval: " << rules.size() << " rule(s) active\n";

    std::istream* in = &std::cin;
    std::ifstream file;
    if (argc > 1) {
        file.open(argv[1]);
        if (!file.is_open()) {
            std::cerr << "vajra_engine_eval: cannot open " << argv[1] << "\n";
            return 1;
        }
        in = &file;
    }

    vajra_engine::Decoder decoder;
    std::string line;
    long events = 0, alerts = 0, anchors = 0, bad = 0;
    while (std::getline(*in, line)) {
        if (line.empty()) continue;
        vajra_engine::Envelope env;
        try {
            env = vajra_engine::Envelope::from_json_text(line);
        } catch (const std::exception& e) {
            ++bad;
            std::cerr << "vajra_engine_eval: bad line: " << e.what() << "\n";
            continue;
        }
        ++events;
        const auto ev = decoder.decode(env);
        for (const auto& m : rules.eval(ev)) {
            if (m.no_log) {
                ++anchors;
                continue;
            }
            ++alerts;
            std::cout << "ALERT rule=" << m.rule_id << " level=" << m.level
                      << " host=" << env.host_identifier << " type=" << env.event_type
                      << " :: " << m.description << "\n"
                      << "      cmdline: " << ev.get("process.command_line") << "\n";
        }
    }

    std::cerr << "vajra_engine_eval: " << events << " event(s), " << alerts << " alert(s), "
              << anchors << " anchor-only match(es), " << bad << " bad line(s)\n";
    return 0;
}
