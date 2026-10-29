#ifndef VAJRA_ENGINE_ENVELOPE_H
#define VAJRA_ENGINE_ENVELOPE_H

#include <stdexcept>
#include <string>

#include "../../3rdparty/json.hpp"
#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {

class EnvelopeError : public std::runtime_error {
public:
    explicit EnvelopeError(const std::string& what) : std::runtime_error(what) {}
};

// Wraps one Kafka message from vajra_windows_events/vajra_linux_events.
// vajra_server (server/request_handler.cpp, KafkaProducerManager) publishes
// a flat JSON object per event -- no wrapper, no schema_version -- with
// "event_type" and "host_identifier" as top-level keys alongside the rest
// of the (already partly flattened) event fields. This type mirrors that
// real wire format exactly rather than inventing a new one, so the engine
// decodes what vajra_server actually produces.
struct Envelope {
    std::string event_type;
    std::string host_identifier;
    std::string os;  // rarely present on the wire; Decoder derives it when empty
    nlohmann::json payload;  // the full raw JSON object, incl. event_type/host_identifier

    static Envelope from_json_text(const std::string& text) {
        // This is the single most attacker-reachable JSON parse in the
        // engine -- event payloads originate from Kafka messages that can
        // come from a compromised osquery endpoint, or (Kafka currently
        // runs unauthenticated PLAINTEXT, see security-audit-findings)
        // anyone able to publish directly to the ingest topics. A
        // sufficiently deep bracket nesting would otherwise reach
        // nlohmann::json::parse's recursive-descent parser and exhaust the
        // stack -- a crash (SIGSEGV), not a catchable C++ exception, so the
        // caller's try/catch around this function cannot save it. Reject
        // BEFORE parsing, same guard as ThreatIntelFeed's HTTP responses.
        if (exceeds_max_nesting_depth(text, kMaxJsonNestingDepth)) {
            throw EnvelopeError("envelope JSON exceeds maximum nesting depth");
        }

        nlohmann::json doc;
        try {
            doc = nlohmann::json::parse(text);
        } catch (const nlohmann::json::parse_error& e) {
            throw EnvelopeError(std::string("invalid JSON: ") + e.what());
        }
        if (!doc.is_object()) {
            throw EnvelopeError("envelope is not a JSON object");
        }

        Envelope env;
        auto event_type_it = doc.find("event_type");
        if (event_type_it == doc.end() || !event_type_it->is_string()) {
            throw EnvelopeError("missing or non-string 'event_type'");
        }
        env.event_type = event_type_it->get<std::string>();

        if (auto it = doc.find("host_identifier"); it != doc.end() && it->is_string()) {
            env.host_identifier = it->get<std::string>();
        }
        if (auto it = doc.find("os"); it != doc.end() && it->is_string()) {
            env.os = it->get<std::string>();
        }
        env.payload = std::move(doc);
        return env;
    }
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_ENVELOPE_H
