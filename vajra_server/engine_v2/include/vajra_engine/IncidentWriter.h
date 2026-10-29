#ifndef VAJRA_ENGINE_INCIDENT_WRITER_H
#define VAJRA_ENGINE_INCIDENT_WRITER_H

#include <memory>
#include <vector>

#include "vajra_engine/CorrelationEngine.h"

class ConnectionPool;

namespace vajra_engine {

// Persists Incidents (see CorrelationEngine.h) into the `incidents` /
// `incident_alerts` tables defined by engine_v2/schema/incidents.sql -- a
// deliberately NEW schema path, never sql/schema.sql or schema/ (see this
// engagement's charter: those are the live schema and are never touched by
// this workstream). See IncidentWriter.cpp's top comment for the DB-backed
// vs. in-process-only design rationale.
//
// Dedupes like AlertWriter: at most one OPEN incident row per
// (correlation_rule_id, group_key); a later trigger for an already-open
// incident updates last_seen_time and links any newly-seen alert ids rather
// than creating a second row.
class IncidentWriter {
public:
    explicit IncidentWriter(std::shared_ptr<ConnectionPool> pool) : pool_(std::move(pool)) {}

    // Returns how many incidents were actually written/updated. Unlike
    // AlertWriter::write(), this NEVER throws -- see IncidentWriter.cpp's
    // catch clause for why a failure here must stay contained to the
    // correlation layer and never turn into a Kafka retry/redelivery of the
    // underlying message.
    int write(const std::vector<Incident>& incidents);

private:
    std::shared_ptr<ConnectionPool> pool_;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_INCIDENT_WRITER_H
