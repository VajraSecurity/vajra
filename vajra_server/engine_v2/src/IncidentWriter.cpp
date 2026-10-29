// DB-backed vs. in-process-only: this engine writes Incidents to Postgres
// (a new `incidents`/`incident_alerts` pair, see engine_v2/schema/
// incidents.sql) for the same three reasons `alerts` itself is a Postgres
// table rather than an in-memory structure:
//   1. Survivability -- a vajra_engine restart (deploy, crash, SIGHUP is
//      fine but a hard restart isn't) must not silently drop an
//      already-detected multi-stage incident. An in-process-only store
//      loses everything on restart; Postgres doesn't.
//   2. Visibility -- an EDR incident is only useful if an analyst/console
//      can see it. `alerts` is already read directly by
//      vajranet_server_onprem's console; putting incidents in the same
//      database (linked to real alert ids via incident_alerts) means the
//      console can grow an "incidents" view with zero new infrastructure,
//      the same way it already reads `alerts`.
//   3. Consistency with the existing design -- AlertWriter already
//      established the pattern (dedupe via WHERE NOT EXISTS on an
//      is_open flag, severity_text() vocabulary, technique/technique_id as
//      comma-joined text). Incidents reuse it rather than inventing a
//      second persistence idiom for what is conceptually the same kind of
//      object one layer up.
// The cost is an extra DB round-trip per correlation-rule-satisfying match
// (bounded by how often the underlying detection rules actually fire, same
// cost model AlertWriter already accepted) -- worth it for the above.

#include "vajra_engine/IncidentWriter.h"

#include <sstream>

#include "../../common/ConnectionPool.h"
#include "../../common/logger.h"
#include "vajra_engine/AlertWriter.h"

namespace vajra_engine {
namespace {

std::string join(const std::vector<std::string>& items, const char* sep) {
    std::ostringstream out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i != 0) out << sep;
        out << items[i];
    }
    return out.str();
}

}  // namespace

int IncidentWriter::write(const std::vector<Incident>& incidents) {
    int written = 0;
    if (incidents.empty()) return written;

    std::shared_ptr<pqxx::connection> conn;
    try {
        conn = pool_->GetConnection();
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                  << "vajra_engine: IncidentWriter could not acquire a DB "
                                     "connection: "
                                  << e.what();
        return written;
    }

    for (const auto& inc : incidents) {
        // Per-incident try/catch (not one wrapping the whole loop): a
        // failure on incident N must not silently skip incidents N+1..end
        // in the same batch, matching the per-entry isolation this
        // engagement already applies elsewhere (request_handler.cpp's
        // distributed_write()) for the identical failure class. Safe to
        // retry the loop after an exception: `txn` below is a fresh local
        // per iteration, so an exception unwinding out of one iteration
        // runs that iteration's own pqxx::work destructor (auto-abort of
        // whatever was uncommitted) before the next iteration constructs
        // its own new transaction on the same connection.
        try {
            const std::string severity = severity_text(inc.level);
            const std::string groups_joined = join(inc.groups, ",");
            const std::string mitre_joined = join(inc.mitre, ",");
            const std::string group_by_joined = join(inc.group_by_fields, ",");

            pqxx::work txn(*conn);

            // Dedupe to at most one OPEN incident per (correlation_rule_id,
            // group_key), mirroring AlertWriter's own INSERT ... WHERE NOT
            // EXISTS pattern (and its param-type-casting discipline -- see
            // AlertWriter.cpp's comment on Postgres unnamed-statement type
            // inference; group_key is cast to ::text at every occurrence
            // here for the same reason).
            pqxx::result ins = txn.exec_params(
                "INSERT INTO incidents (correlation_rule_id, description, severity, level, groups, "
                " mitre, group_by_fields, group_key, first_seen_time, last_seen_time, is_open) "
                "SELECT $1, $2, $3, $4, $5, $6, $7, $8::text, $9, $10, true "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM incidents WHERE correlation_rule_id = $1 AND group_key = $8::text "
                "    AND is_open = true"
                ") RETURNING id",
                inc.correlation_rule_id, inc.description, severity, inc.level, groups_joined,
                mitre_joined, group_by_joined, inc.group_key, inc.first_seen_ms, inc.last_seen_ms);

            long long incident_id = -1;
            if (!ins.empty()) {
                incident_id = ins[0]["id"].as<long long>();
            } else {
                pqxx::result existing = txn.exec_params(
                    "SELECT id FROM incidents WHERE correlation_rule_id = $1 AND group_key = $2::text "
                    "  AND is_open = true ORDER BY id DESC LIMIT 1",
                    inc.correlation_rule_id, inc.group_key);
                if (!existing.empty()) {
                    incident_id = existing[0]["id"].as<long long>();
                    txn.exec_params("UPDATE incidents SET last_seen_time = $1 WHERE id = $2",
                                     inc.last_seen_ms, incident_id);
                }
            }

            if (incident_id >= 0) {
                for (const auto& c : inc.contributing) {
                    if (c.alert_id < 0) continue;  // no_log/anchor contribution: no `alerts` row to link
                    txn.exec_params(
                        "INSERT INTO incident_alerts (incident_id, alert_id, rule_id, matched_at) "
                        "VALUES ($1, $2, $3, $4) ON CONFLICT (incident_id, alert_id) DO NOTHING",
                        incident_id, c.alert_id, c.rule_id, c.timestamp_ms);
                }
                txn.commit();
                ++written;
            } else {
                txn.abort();
            }
        } catch (const std::exception& e) {
            // Deliberately NOT rethrown, unlike AlertWriter::write(). Incidents
            // are a best-effort, DERIVED signal built from alerts that are
            // already durably written by the time this runs -- a failure here
            // must never turn into a Kafka redelivery/retry of the underlying
            // message, because CorrelationEngine's in-process window state has
            // no de-duplication against redelivery (see .team/mailbox/
            // re-nyx.md's "open risks" section: replaying an already-processed
            // message would double-push a ContributingEvent into the window).
            // Losing/delaying one incident write is an acceptable, logged
            // degradation; corrupting correlation counts via a retry loop is
            // not. Scoped to just THIS incident -- see the per-entry isolation
            // comment above the loop.
            BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                      << "vajra_engine: IncidentWriter write failed for incident "
                                         "(correlation_rule_id="
                                      << inc.correlation_rule_id
                                      << ", group_key=" << inc.group_key
                                      << ") -- it may be lost/incomplete this cycle; underlying "
                                         "alerts and any other incidents in this batch are unaffected: "
                                      << e.what();
        }
    }

    pool_->ReturnConnection(conn);
    return written;
}

}  // namespace vajra_engine
