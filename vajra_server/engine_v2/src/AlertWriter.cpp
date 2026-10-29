#include "vajra_engine/AlertWriter.h"

#include <optional>
#include <sstream>

#include "../../3rdparty/json.hpp"
#include "../../common/ConnectionPool.h"
#include "../../common/logger.h"

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

std::optional<long long> parse_pid(const NormalizedEvent& ev) {
    const std::string raw = ev.get("process.pid");
    if (raw.empty()) return std::nullopt;
    try {
        return std::stoll(raw);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace

std::string severity_text(int level) {
    if (level >= 12) return "critical";
    if (level >= 8) return "high";
    if (level >= 4) return "medium";
    return "low";
}

std::vector<AlertWriteResult> AlertWriter::write(const NormalizedEvent& ev,
                                                   const std::vector<Match>& matches) {
    std::vector<AlertWriteResult> results;
    if (matches.empty()) return results;

    std::shared_ptr<pqxx::connection> conn;
    try {
        conn = pool_->GetConnection();
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                  << "vajra_engine: AlertWriter could not acquire a DB "
                                     "connection: "
                                  << e.what();
        return results;
    }

    const std::string hostname = ev.get("hostname");
    const std::optional<long long> pid = parse_pid(ev);

    try {
        for (const auto& m : matches) {
            if (m.no_log) continue;

            const std::string alert_type = m.groups.empty() ? "detection" : m.groups.front();
            const std::string technique = join(m.groups, ",");
            const std::string technique_id = join(m.mitre, ",");

            nlohmann::json metadata;
            metadata["rule_id"] = m.rule_id;
            metadata["level"] = m.level;
            metadata["groups"] = m.groups;
            metadata["mitre"] = m.mitre;
            nlohmann::json fields = nlohmann::json::object();
            for (const auto& [key, value] : ev.fields) fields[key] = value;
            metadata["fields"] = std::move(fields);

            pqxx::work txn(*conn);
            // Dedupe to at most one OPEN alert per (host, alert_type,
            // rule_id): a repeat match while an existing alert for the same
            // rule is still open must not create a second row. RETURNING id
            // gives us the new row's id on an actual insert; a dedup (0
            // rows) falls through to the SELECT below so the caller still
            // gets a real alert_id to link a correlated incident to.
            //
            // DEDUP IDENTITY: keyed on m.rule_id (via metadata->>'rule_id'),
            // NOT event_code. Originally this compared event_code directly,
            // which is bound to m.description (free ruleset-authored text,
            // defaulting to "" when omitted -- RulesetLoader.cpp's
            // `j.value("description", "")`). Round-2 adversarial review
            // (Sage, see .team/mailbox/re-sage.md Finding 3) confirmed that
            // was worse than originally flagged: it's not just "two rules
            // that happen to share description text" -- it's the DEFAULT
            // outcome for ANY two rules that both omit `description` and
            // both omit/share `groups` (zero authoring effort), silently
            // swallowing the second rule's detection into the first rule's
            // open `alerts` row. Fixed by matching on m.rule_id instead,
            // which is stable and unique per rule by construction --
            // WITHOUT touching what's actually INSERTED into the event_code
            // COLUMN (still m.description, unchanged, byte-for-byte
            // identical to before this fix): vajranet_server_onprem's
            // console reads event_code's content directly (see this file's
            // header comment), and this fix deliberately only changes the
            // dedup MATCH criteria, not the stored value, so that console
            // contract is untouched. metadata already carries rule_id
            // verbatim (`metadata["rule_id"] = m.rule_id;` above) as part of
            // the JSON blob stored in the TEXT `metadata` column, so no
            // schema migration is needed for this fix -- the cast happens
            // at query time.
            //
            // PERFORMANCE NOTE (Sage): this cast runs on every row scanned
            // by the dedup query. On a large/growing `alerts` table this
            // wants a functional index -- NOT auto-applied here (this
            // engagement never touches the live `sql`/`schema` directories;
            // same posture as engine_v2/schema/incidents.sql), apply
            // manually against the target DB when deploying this fix:
            //   CREATE INDEX IF NOT EXISTS idx_alerts_open_rule_id
            //     ON alerts (host_identifier, alert_type, ((metadata::jsonb ->> 'rule_id')::int))
            //     WHERE is_open = true;
            // CORRECTNESS NOTE (Sage): the INSERT always writes valid
            // metadata.dump() JSON (see above), so `metadata::jsonb` only
            // risks throwing on pre-engine_v2 legacy rows, if any exist in
            // the target DB -- worth `SELECT count(*) FROM alerts WHERE
            // metadata !~ '^\{'` as a pre-deployment sanity check.
            pqxx::result res = txn.exec_params(
                "INSERT INTO alerts "
                "(host_identifier, hostname, unixTime, event_code, metadata, is_alert, "
                " is_open, severity, alert_type, technique, technique_id, pid, action, "
                " os_name, detection_time) "
                "SELECT $1::text, $2, $3, $4::text, $5, true, true, $6, $7::text, $8, $9, $10, "
                "       '', $11, $12 "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM alerts "
                // $1/$7 are cast to ::text at every occurrence for the same
                // Postgres unnamed-statement type-inference reason
                // documented below (host_identifier is varchar(40); casting
                // consistently everywhere avoids "inconsistent types deduced
                // for parameter $N" regardless of which occurrence Postgres
                // happens to type-check first). $13 (rule_id) is a plain
                // integer compared against an explicitly-cast ::int
                // extraction, so no similar ambiguity applies to it.
                "  WHERE host_identifier = $1::text AND alert_type = $7::text "
                "    AND (metadata::jsonb ->> 'rule_id')::int = $13 AND is_open = true"
                ") RETURNING id",
                ev.host_identifier, hostname, ev.unix_time, m.description, metadata.dump(),
                severity_text(m.level), alert_type, technique, technique_id, pid, ev.os,
                ev.unix_time, m.rule_id);

            AlertWriteResult result;
            result.rule_id = m.rule_id;
            if (!res.empty()) {
                result.alert_id = res[0]["id"].as<long long>();
                result.newly_inserted = true;
            } else {
                // Deduped against an already-open alert -- fetch its id in
                // the SAME transaction so this match still resolves to a
                // real `alerts` row for incident linkage, instead of
                // silently losing the association on every repeat match
                // (the common case once an alert is already open). Same
                // rule_id-based match criteria as the INSERT's WHERE NOT
                // EXISTS above -- see this block's comment.
                pqxx::result existing = txn.exec_params(
                    "SELECT id FROM alerts WHERE host_identifier = $1::text AND alert_type = $2::text "
                    "  AND (metadata::jsonb ->> 'rule_id')::int = $3 AND is_open = true "
                    "ORDER BY id DESC LIMIT 1",
                    ev.host_identifier, alert_type, m.rule_id);
                if (!existing.empty()) result.alert_id = existing[0]["id"].as<long long>();
            }
            txn.commit();
            results.push_back(result);
        }
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: AlertWriter insert failed: "
                                  << e.what();
        pool_->ReturnConnection(conn);
        throw;  // let the caller's retry/DLQ policy decide (transient vs permanent)
    }

    pool_->ReturnConnection(conn);
    return results;
}

}  // namespace vajra_engine
