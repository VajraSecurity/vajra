#ifndef VAJRA_ENGINE_DECODER_H
#define VAJRA_ENGINE_DECODER_H

#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "vajra_engine/Envelope.h"
#include "vajra_engine/NormalizedEvent.h"

namespace vajra_engine {

// One field-extraction decoder rule, in its plain-string (pre-compile) form
// -- the shape RulesetLoader parses from a ruleset's "decoders" section.
// Modeled on Wazuh's decoder prematch/regex/order, adapted to this engine's
// already-structured (JSON, not raw-text-log) event fields and to
// std::regex's lack of named capture groups: `captures` maps capture group
// N (1-based) to a destination field name positionally, playing the role
// Wazuh's <order> tag plays for its unnamed captures.
struct DecoderRuleConfig {
    std::string name;         // for logging only
    std::string event_type;   // empty = applies to every event_type
    std::string source_field; // canonical field to test/extract from, e.g. "process.command_line"
    std::string prematch;     // optional cheap filter regex; empty = always proceed to extract
    std::string extract;      // required capture regex
    std::vector<std::string> captures;  // capture group i (1-based) -> destination field name
};

// Compiled form of DecoderRuleConfig, produced by Decoder::load_decoder_rules.
struct DecoderRule {
    std::string name;
    std::string event_type;
    std::string source_field;
    std::shared_ptr<std::regex> prematch_compiled;  // null if no prematch configured
    std::shared_ptr<std::regex> extract_compiled;   // null if the regex failed to compile
    std::vector<std::string> captures;
};

// Flattens the raw wire JSON into a NormalizedEvent and adds canonical
// dotted-name aliases (process.command_line, network.remote_address, ...)
// for the fields the shipped ruleset and rule authors reference, without
// dropping the original raw keys. The alias table is keyed off the eleven
// event_type values vajra_server's KafkaProducerManager actually publishes
// (server/request_handler.cpp) -- see engine/src/Decoder.cpp.
//
// After alias resolution, decode() also runs any loaded DecoderRules: each
// scoped to an event_type (or all), gated by an optional prematch regex
// against source_field, and on a match, extracts named fields from the
// extract regex's capture groups (positionally, via `captures`). Extracted
// fields are additive only -- like the alias table, a decoder never
// overwrites a field that already exists on the event. Not thread-safe to
// call load_decoder_rules() concurrently with decode() -- see
// RuleEngine::load()'s doc comment for the same single-writer-thread
// assumption this mirrors (main.cpp only ever reloads from the same thread
// that calls decode()).
class Decoder {
public:
    NormalizedEvent decode(const Envelope& env) const;

    // Replaces the active decoder rules wholesale. Invalid regexes (either
    // prematch or extract) are logged and that one decoder rule is skipped
    // entirely -- never blocks the rest of the ruleset load, matching
    // RuleEngine::load()'s posture for malformed rule regex conditions.
    void load_decoder_rules(std::vector<DecoderRuleConfig> configs);

    std::size_t decoder_rule_count() const { return decoder_rules_.size(); }

private:
    std::vector<DecoderRule> decoder_rules_;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_DECODER_H
