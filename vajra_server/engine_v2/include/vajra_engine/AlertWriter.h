#ifndef VAJRA_ENGINE_ALERT_WRITER_H
#define VAJRA_ENGINE_ALERT_WRITER_H

#include <memory>
#include <vector>

#include "vajra_engine/NormalizedEvent.h"
#include "vajra_engine/RuleEngine.h"

class ConnectionPool;

namespace vajra_engine {

// 12+ critical, 8+ high, 4+ medium, else low.
std::string severity_text(int level);

// One match's outcome after AlertWriter::write(): which `alerts` row (if
// any) now represents it -- either a freshly inserted row, or the
// pre-existing OPEN row it deduped against. alert_id == -1 means no row
// exists for this match (the match was no_log, so write() never attempted
// one). newly_inserted distinguishes an actual INSERT from a dedup reuse,
// so callers that only care about "how many NEW alert rows landed" (e.g.
// Metrics::record_alerts_written) keep exactly today's semantics.
// CorrelationEngine (engine_v2's alert-to-incident layer, see
// CorrelationEngine.h) consumes the full result set to link an incident
// back to real `alerts` rows even on a repeat/deduped match.
struct AlertWriteResult {
    int rule_id = 0;
    long long alert_id = -1;
    bool newly_inserted = false;
};

// Writes non-anchor (no_log == false) rule matches into the vajra_server
// `alerts` table (sql/schema.sql) -- the same table
// vajranet_server_onprem's console reads directly
// (backend/src/controllers/alerts/alert_list.ts). Dedupes to at most one
// OPEN alert per (host_identifier, alert_type, event_code): a repeat match
// while an existing alert is still open does not create a second row, but
// the pre-existing row's id is still reported back via AlertWriteResult so
// the dedup doesn't break incident linkage.
class AlertWriter {
public:
    explicit AlertWriter(std::shared_ptr<ConnectionPool> pool) : pool_(std::move(pool)) {}

    // One AlertWriteResult per non-no_log match in `matches`, in the same
    // order (no_log matches are skipped entirely -- they never produce a
    // result). Empty if every match was no_log.
    std::vector<AlertWriteResult> write(const NormalizedEvent& ev, const std::vector<Match>& matches);

private:
    std::shared_ptr<ConnectionPool> pool_;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_ALERT_WRITER_H
