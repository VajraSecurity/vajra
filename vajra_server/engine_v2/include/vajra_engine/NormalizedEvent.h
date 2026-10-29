#ifndef VAJRA_ENGINE_NORMALIZED_EVENT_H
#define VAJRA_ENGINE_NORMALIZED_EVENT_H

#include <cstdint>
#include <map>
#include <string>

namespace vajra_engine {

// A flattened, dotted-key view of one telemetry event, produced by Decoder
// from the raw wire JSON. Rules and correlation logic operate only on this
// type, never on raw JSON, so they stay independent of wire-format details.
struct NormalizedEvent {
    std::string event_type;
    std::string os;
    std::string host_identifier;
    std::int64_t unix_time = 0;
    std::map<std::string, std::string> fields;

    bool has(const std::string& key) const { return fields.find(key) != fields.end(); }

    std::string get(const std::string& key, const std::string& fallback = "") const {
        auto it = fields.find(key);
        return it == fields.end() ? fallback : it->second;
    }
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_NORMALIZED_EVENT_H
