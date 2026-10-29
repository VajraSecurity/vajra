#include "../../3rdparty/json.hpp"
#include "../request_handler.h"
#include "../../common/logger.h"
#include "../../common/HealthMonitor.h"
#include "../../common/InputValidator.h"

#include <boost/beast/http.hpp>
#include <algorithm>
#include <cctype>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;

// Bearer token guarding /health/deadletter. Defined and populated in
// fleet_main.cpp (owner: Rook) from a config key added by Flux. Empty or
// unconfigured means the endpoint is disabled and returns 403 (fail closed).
extern std::string health_api_token;

namespace {

// Case-insensitive header lookup: HTTPMessage stores header names verbatim
// in an unordered_map, so a plain find() would miss casing variants.
std::string get_header(const HTTPMessage& request, const std::string& name)
{
    for (const auto& [key, value] : request.header) {
        if (key.size() == name.size() &&
            std::equal(key.begin(), key.end(), name.begin(),
                       [](unsigned char a, unsigned char b) {
                           return std::tolower(a) == std::tolower(b);
                       })) {
            return value;
        }
    }
    return "";
}

bool bearer_authorized(const HTTPMessage& request)
{
    // No token configured => endpoint disabled. Never fail open.
    if (health_api_token.empty())
        return false;

    const std::string auth = get_header(request, "Authorization");
    static const std::string prefix = "Bearer ";
    if (auth.size() <= prefix.size() || auth.compare(0, prefix.size(), prefix) != 0)
        return false;

    return VajraValidator::constantTimeEquals(auth.substr(prefix.size()), health_api_token);
}

} // namespace

// Public wrapper so the router can gate /health/deadletter before acquiring a
// DB connection. dead_letter_queue() still re-checks internally (defense in depth).
bool health_deadletter_authorized(const HTTPMessage& request)
{
    return bearer_authorized(request);
}

HTTPMessage health_check(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;
    auto* health = HealthMonitor::getInstance();

    try {
        auto health_data = nlohmann::json::parse(health->getHealthReport());
        std::string system_status = health_data["system"]["status"];

        // Unauthenticated liveness only: status + uptime. Internal metrics,
        // component names, queue depths and DB detail stay server-side.
        nlohmann::json body;
        if (system_status == "HEALTHY") {
            body["status"] = "ok";
            response.status = http::status::ok;
        } else if (system_status == "DEGRADED") {
            body["status"] = "degraded";
            response.status = http::status::ok; // 200 but degraded
        } else {
            body["status"] = "unavailable";
            response.status = http::status::service_unavailable;
        }
        body["uptime_seconds"] = health_data["system"]["uptime_seconds"];

        response.body = body.dump();
        response.header["Content-Type"] = "application/json";

        BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Health check requested. Status: " << system_status;

    } catch (const std::exception& e) {
        // Log details server-side only; never echo exception text to clients.
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Health check error: " << e.what();

        response.status = http::status::internal_server_error;
        response.body = "{\"status\":\"error\"}";
        response.header["Content-Type"] = "application/json";
    }

    return response;
}

HTTPMessage dead_letter_queue(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;

    if (!bearer_authorized(request)) {
        // Same 403 for "disabled", "missing token" and "wrong token" so the
        // response is not an oracle. The token itself is never logged.
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Rejected unauthorized /health/deadletter request";
        response.status = http::status::forbidden;
        response.body = "{\"error\":\"forbidden\"}";
        response.header["Content-Type"] = "application/json";
        return response;
    }

    auto* health = HealthMonitor::getInstance();

    try {
        auto entries = health->getDeadLetterEntries();

        nlohmann::json result = nlohmann::json::array();

        for (const auto& entry : entries) {
            nlohmann::json entry_json;
            entry_json["event_id"] = entry.event_id;
            entry_json["table_name"] = entry.table_name;
            entry_json["error_message"] = entry.error_message;
            entry_json["retry_count"] = entry.retry_count;
            entry_json["failed_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                entry.failed_at.time_since_epoch()).count();
            entry_json["last_retry_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                entry.last_retry_at.time_since_epoch()).count();

            result.push_back(entry_json);
        }

        nlohmann::json response_json;
        response_json["dead_letter_queue"] = result;
        response_json["count"] = entries.size();

        // The in-memory queue above only covers this process since startup.
        // Ingest failures (distributed_write) are persisted to the
        // dead_letter_queue table — surface those too.
        try {
            pqxx::work txn{*connection};
            pqxx::result db_rows = txn.exec(
                "select id, event_id, table_name, error_message, "
                "extract(epoch from created_at)::bigint as failed_at "
                "from dead_letter_queue order by id desc limit 500");
            txn.commit();

            nlohmann::json db_entries = nlohmann::json::array();
            for (const auto& row : db_rows) {
                nlohmann::json e;
                e["id"] = row["id"].as<long long>();
                e["event_id"] = row["event_id"].is_null() ? 0LL : row["event_id"].as<long long>();
                e["table_name"] = row["table_name"].is_null() ? "" : row["table_name"].as<std::string>();
                e["error_message"] = row["error_message"].is_null() ? "" : row["error_message"].as<std::string>();
                e["failed_at"] = row["failed_at"].is_null() ? 0LL : row["failed_at"].as<long long>();
                db_entries.push_back(e);
            }
            response_json["dead_letter_queue_db"] = db_entries;
            response_json["db_count"] = db_entries.size();
        } catch (const std::exception& e) {
            // Log details server-side only; the client just learns the DB
            // portion was unavailable.
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Could not read dead_letter_queue table: " << e.what();
            response_json["dead_letter_queue_db_error"] = "unavailable";
        }

        response.status = http::status::ok;
        response.body = response_json.dump(2);
        response.header["Content-Type"] = "application/json";

        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Dead letter queue requested. Entries: " << entries.size();

    } catch (const std::exception& e) {
        // Log details server-side only; never echo exception text to clients.
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Dead letter queue error: " << e.what();

        response.status = http::status::internal_server_error;
        response.body = "{\"error\":\"internal_error\"}";
        response.header["Content-Type"] = "application/json";
    }

    return response;
}
