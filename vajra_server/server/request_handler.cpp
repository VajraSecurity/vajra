#include "../3rdparty/json.hpp"
#include "request_handler.h"
#include "KafkaProducerManager.h"
#include "../common/logger.h"
#include "../common/InputValidator.h"
#include "../common/NodeKeyGenerator.h"
#include "../common/RateLimiter.h"
#include "../common/InMemoryRateLimiter.h"
#include "../common/NodeValidator.h"

#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../common/ConfigurationParser.h"

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// Pre-auth enroll burst limits (in-memory, per IP). Deliberately compile-time
// constants: this gate must keep working even when config or DB access fails.
static constexpr size_t ENROLL_MAX_ATTEMPTS_PER_WINDOW = 10;
static constexpr unsigned ENROLL_WINDOW_SECONDS = 60;

HTTPMessage enroll(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;
    nlohmann::json enrollment_response;

    // Authoritative client IP: X-Vajra-Peer-IP is set by the web server from
    // the TCP peer address and always overwrites any client-supplied value.
    // Never use X-Forwarded-For / X-Real-IP here — they are client-controlled.
    std::string client_ip = "unknown";
    if (request.header.find("X-Vajra-Peer-IP") != request.header.end()) {
        client_ip = request.header.at("X-Vajra-Peer-IP");
    }

    BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Enrollment request from IP: " << client_ip;

    // ========== PRE-AUTH RATE LIMITING (in-memory) ==========
    // Runs before body parsing, secret validation and ANY database access so
    // an unauthenticated flood is cut off without touching the database.
    static VajraRateLimit::InMemoryRateLimiter enroll_ip_limiter(
        ENROLL_MAX_ATTEMPTS_PER_WINDOW, ENROLL_WINDOW_SECONDS);
    if (!enroll_ip_limiter.allow(client_ip))
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Enrollment burst limit exceeded for IP: " << client_ip;
        response.status = http::status::too_many_requests;
        response.body = "{\"node_invalid\":true,\"error\":\"Rate limit exceeded. Too many enrollment attempts.\"}";
        response.header["Content-Type"] = "application/json";
        return response;
    }

    // ========== DB-BACKED RATE LIMITING ==========
    // Second layer with hour/day windows that survive restarts. Runs before
    // secret validation so failed-secret attempts are throttled too.
    if (!VajraRateLimit::checkEnrollmentRateLimit(client_ip, connection, global_node_config))
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Rate limit exceeded for IP: " << client_ip;
        VajraRateLimit::recordEnrollmentAttempt(client_ip, false, "", "Rate limit exceeded", connection);

        enrollment_response["node_invalid"] = true;
        enrollment_response["error"] = "Rate limit exceeded. Too many enrollment attempts.";
        response.body = enrollment_response.dump();
        response.status = http::status::too_many_requests;
        response.header["Content-Type"] = "application/json";
        return response;
    }

    try
    {
        auto enrollment_request = nlohmann::json::parse(request.body);
        // Never log the raw body: it carries the shared enroll_secret (pre-auth
        // credential) and would nullify secret rotation for anyone with log read
        // access. Log only non-secret identifiers.
        {
            std::string log_host_id = enrollment_request.value("host_identifier", std::string("<none>"));
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Enrollment request from IP " << client_ip
                                    << " host_identifier=" << log_host_id;
        }
        
        if (enrollment_request.contains("enroll_secret") && enrollment_request.contains("host_identifier") && enrollment_request.contains("host_details"))
        {
            std::string secret = enrollment_request["enroll_secret"];
            std::string host_identifier = enrollment_request["host_identifier"];

            // Validate host_identifier format
            if (!VajraValidator::isValidHostIdentifier(host_identifier))
            {
                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Invalid host_identifier format: " << host_identifier;
                VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Invalid host identifier format", connection);
                
                enrollment_response["node_invalid"] = true;
                enrollment_response["error"] = "Invalid host identifier format";
                response.body = enrollment_response.dump();
                response.status = boost::beast::http::status::bad_request;
                return response;
            }

            std::cout << "Enroll request " << host_identifier << std::endl;
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Processing enrollment for: " << host_identifier << ", secret match check starting";

            // Validate enrollment secret (constant-time: this is the single
            // pre-auth credential gating enrollment of any node into the
            // whole fleet, so it gets the same timing-safe treatment as the
            // /health/deadletter bearer token).
            if (!VajraValidator::constantTimeEquals(secret, enrollment_secret))
            {
                BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Enrollment of host failed due to bad secret";
                VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Invalid enrollment secret", connection);
                
                response.status = http::status::unauthorized;
                response.body = "{\n"
                                "  \"message\":\"Enrollment failed due to bad secret\",\n"
                                "  \"node_key\":\"\",\n"
                                "  \"node_invalid\":true\n"
                                "}";
                response.header["Content-Type"] = "application/json";
                return response;
            }

            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Secret validated successfully for: " << host_identifier;

            // ========== BLOCKED HOST CHECK ==========
            // Permanently blocked host_identifiers are rejected here so that
            // deletion + re-enrollment is also prevented.
            {
                pqxx::nontransaction nt(*connection);
                pqxx::result blocked = nt.exec_params(
                    "SELECT 1 FROM blocked_host_identifiers WHERE host_identifier = $1",
                    host_identifier);
                if (!blocked.empty())
                {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Enrollment blocked for: " << host_identifier;
                    VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Host identifier is blocked", connection);
                    enrollment_response["node_invalid"] = true;
                    enrollment_response["error"] = "Enrollment is not allowed for this device";
                    response.body = enrollment_response.dump();
                    response.status = http::status::forbidden;
                    return response;
                }
            }

            // ========== DEVICE LIMIT CHECK ==========
            BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Creating database transaction";
            pqxx::work transaction{*connection};
            
            // Check if this is a re-enrollment or new enrollment
            // All statements in this path are prepared once per connection in
            // fleet_main.cpp; per-request prepare/unprepare polluted pooled
            // connections whenever an exception skipped the unprepare.
            BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Checking if node exists: " << host_identifier;
            pqxx::result existing_node_result = transaction.exec_prepared("check_existing_node", host_identifier);

            bool is_reenrollment = (existing_node_result.size() == 1);
            
            // If new enrollment, check device limit
            if (!is_reenrollment)
            {
                pqxx::result count_result = transaction.exec_prepared("count_active_nodes");

                int active_node_count = count_result[0][0].as<int>();
                
                BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Active nodes: " << active_node_count 
                                       << " / Max allowed: " << global_node_config.max_enrolled_devices;
                
                if (active_node_count >= static_cast<int>(global_node_config.max_enrolled_devices))
                {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Device limit reached. Active: " << active_node_count;
                    VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Device limit reached", connection);
                    transaction.commit();
                    
                    enrollment_response["node_invalid"] = true;
                    enrollment_response["error"] = "Device limit reached. Maximum devices: " + std::to_string(global_node_config.max_enrolled_devices);
                    enrollment_response["max_devices"] = global_node_config.max_enrolled_devices;
                    enrollment_response["current_devices"] = active_node_count;
                    response.body = enrollment_response.dump();
                    response.status = http::status::forbidden;
                    return response;
                }
            }
            else
            {
                // Check if re-enrollment is allowed
                bool reenroll_allowed = existing_node_result[0]["reenroll_allowed"].as<bool>();
                if (!reenroll_allowed)
                {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Re-enrollment not allowed for: " << host_identifier;
                    VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Re-enrollment not allowed", connection);
                    transaction.commit();
                    
                    enrollment_response["node_invalid"] = true;
                    enrollment_response["error"] = "Re-enrollment is not allowed for this node";
                    response.body = enrollment_response.dump();
                    response.status = http::status::forbidden;
                    return response;
                }
            }

            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Device/re-enrollment checks passed. Is re-enrollment: " << is_reenrollment;

            // ========== GENERATE SECURE NODE KEY ==========
            BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Generating secure node key";
            std::string node_key;
            bool node_unique = false;
            int max_attempts = 10;
            int attempt = 0;
            
            try {
                while (!node_unique && attempt < max_attempts)
                {
                    node_key = VajraNodeKey::generateSecureNodeKey(global_node_config.node_key_length);
                    
                    // Check if key already exists
                    pqxx::result key_check = transaction.exec_prepared("check_key_exists", node_key);
                    
                    if (key_check.empty())
                    {
                        node_unique = true;
                    }
                    attempt++;
                }

                if (!node_unique)
                {
                    throw std::runtime_error("Failed to generate unique node key after " + std::to_string(max_attempts) + " attempts");
                }
            }
            catch (const std::exception& e)
            {
                BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Node key generation error: " << e.what();
                try { transaction.abort(); } catch (...) {}
                
                response.status = http::status::internal_server_error;
                response.body = "{\"message\":\"Failed to generate secure node key\",\"node_invalid\":true}";
                response.header["Content-Type"] = "application/json";
                return response;
            }

            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Node key generated successfully, length: " << node_key.length();

            // ========== EXTRACT HOST DETAILS ==========
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Extracting host details for: " << host_identifier;

            auto host_details = enrollment_request["host_details"];
            std::string os_arch, os_build, os_major, os_minor, os_name, os_platform, os_codename, osquery_version;
            std::string hardware_vendor, hardware_model, hardware_version, hostname, original_hostname;
            std::string hardware_cpu_logical_core, hardware_cpu_type, hardware_physical_memory;
            long enrolled_on, last_seen;
            std::time_t t = std::time(0);
            enrolled_on = t;
            last_seen = t;
            
            if (host_details.contains("os_version"))
            {
                auto os_version = host_details["os_version"];
                os_arch = os_version.contains("arch") ? os_version["arch"].get<std::string>() : "unknown";
                os_build = os_version.contains("build") ? os_version["build"].get<std::string>() : "unknown";
                os_major = os_version.contains("major") ? os_version["major"].get<std::string>() : "unknown";
                os_minor = os_version.contains("minor") ? os_version["minor"].get<std::string>() : "unknown";
                os_name = os_version.contains("name") ? os_version["name"].get<std::string>() : "unknown";
                os_platform = os_version.contains("platform") ? os_version["platform"].get<std::string>() : "unknown";
                os_codename = os_version.contains("codename") ? os_version["codename"].get<std::string>() : "";
            }
            else
            {
                BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Enrollment request does not contain os_version object. Offending host-identifier: " << host_identifier;
            }

            if (host_details.contains("osquery_info"))
            {
                auto osquery_info = host_details["osquery_info"];
                osquery_version = osquery_info.contains("version") ? osquery_info["version"].get<std::string>() : "unknown";
            }
            else
            {
                BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Enrollment request does not contain osquery_info object. Offending host-identifier: " << host_identifier;
            }

            if (host_details.contains("system_info"))
            {
                auto system_info = host_details["system_info"];
                hardware_model = system_info.contains("hardware_model") ? system_info["hardware_model"].get<std::string>() : "unknown";
                hardware_version = system_info.contains("hardware_version") ? system_info["hardware_version"].get<std::string>() : "unknown";
                hardware_vendor = system_info.contains("hardware_vendor") ? system_info["hardware_vendor"].get<std::string>() : "unknown";
                hostname = system_info.contains("hostname") ? system_info["hostname"].get<std::string>() : "unknown";
                original_hostname = hostname;
                hardware_cpu_logical_core = system_info.contains("cpu_logical_cores") ? system_info["cpu_logical_cores"].get<std::string>() : "unknown";
                hardware_cpu_type = system_info.contains("cpu_type") ? system_info["cpu_type"].get<std::string>() : "unknown";
                hardware_physical_memory = system_info.contains("physical_memory") ? system_info["physical_memory"].get<std::string>() : "unknown";
            }

            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Host details extracted successfully";

            // ========== INSERT/UPDATE NODE IN DATABASE ==========
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Attempting database insert/update for: " << host_identifier;
            try
            {
                std::string node_invalid = "false", reenroll_allowed = "true";
                // Linux default config_id list: config_queries_bulk (fleet_main.cpp)
                // fetches purely by numeric id, with no os_name filter, so every id
                // listed here must actually be a Linux-compatible query.
                // - Removed 37 (patches), 39 (programs), 57 (win_memory_info): all
                //   three are os_name='Windows'-only rows (verified against a live
                //   agent's logs -- "no such table: patches"/"programs"/"win_mem_perf"
                //   on every scheduler cycle).
                // - Added 20 (bpf_socket_events), 21 (bpf_process_events), 22
                //   (bpf_file_events): the actual queries that upload osquery's
                //   locally-captured BPF process/socket/file events -- without them
                //   a Linux node captures this telemetry locally (its own BPF event
                //   publisher buffer) but never uploads any of it, verified live via
                //   a fully-enrolled node with 0 rows in bpf_process_events/
                //   bpf_socket_events despite osquery's own log reporting 950/1078
                //   events captured.
                // config_id below is a comma-separated list of config_queries.id
                // values -- and that column is a plain auto-increment sequence,
                // NOT a stable constant: its numbers only mean anything relative
                // to whatever order sql/schema.sql's `insert into config_queries`
                // statements ran in on THIS database. Ported this literal string
                // from an older, independently-seeded deployment without
                // re-resolving it here, which meant e.g. id 37 quietly became
                // "etc_hosts" on this database instead of "deb_packages" (id 44
                // here) -- so package/extension-inventory queries were silently
                // never assigned to any newly-enrolled Linux node, not because
                // collection failed, but because they were never scheduled.
                // 35=chrome_extensions, 44=deb_packages, 45=rpm_packages,
                // 49=firefox_addons, 50=npm_packages -- verified against this
                // database's actual config_queries table (query_name column),
                // not assumed from the numbers alone. Re-verify by query_name,
                // not by copying digits, if this schema is ever reseeded.
                //
                // Windows list, same database, same caveat: 42=programs and
                // 51=vajra_winprograms were already present (two independent
                // program-inventory sources, both kept -- not touched here).
                // 35=chrome_extensions was already present. Added 48=
                // ie_extensions and 49=firefox_addons so all three browser-
                // extension sources are covered, matching the Linux side's
                // package-manager coverage. Removed 73: that id resolves to
                // "mounts" on this database, which is os_name='Linux'-only --
                // the same wrong-OS-assignment bug as the Linux list's old
                // 37/39/57 entries (see above), just on the Windows side.
                // Removed 59=win_event_log_data: even filtered to just 3
                // sources (Security, TerminalServices-RemoteConnectionManager,
                // OpenSSH/Operational), the Windows Security channel alone
                // produced 118,530 rows for a single node in under a day --
                // confirmed live on a real enrolled Windows node, not
                // estimated. Too high-volume for a default; opt a node in
                // deliberately via its own config_id if this is wanted.
                // Added 30=win_ssl_events, 31=win_http_events, and
                // 29=win_dns_response_events: win_ssl_events/win_http_events
                // were confirmed at 0 rows for a real enrolled Windows node
                // (not a collection failure -- neither id was in this list at
                // all, so osquery was never told to schedule them, same root
                // cause as the deb_packages/chrome_extensions gap above).
                // 28=win_dns_events was already present and confirmed working
                // (1918 rows on that node); 29 is its sibling (DNS answers,
                // vs. 28's DNS queries) -- added alongside it so query and
                // response sides are both covered, not just one half of the
                // DNS picture.
                // Added 25=win_process_events and 26=win_file_events: without them a new
                // Windows node collected both locally (thousands of rows in its own event
                // store) but was never told to schedule them, so the server stored 0 rows
                // and the engine had no process or file events to raise alerts from.
                // Same ids-are-positional caveat as above: verified against the
                // `insert into config_queries` order in sql/schema.sql.
                std::string config_id = (os_platform == "windows") ? "23,35,40,50,51,53,54,55,56,57,58,60,61,63,65,67,68,69,28,42,43,39,41,74,75,3,27,48,49,30,31,29,25,26" : "18,20,21,22,23,36,38,40,64,66,3,35,44,45,49,50";
                std::string status = "ACTIVE";
                bool isolated = false;
                bool agent_online = false;
                
                // Calculate node key expiration
                long node_key_expires_at = 0;
                if (global_node_config.node_key_expiry_days > 0)
                {
                    node_key_expires_at = VajraNodeKey::generateExpirationTimestamp(global_node_config.node_key_expiry_days);
                }
                
                if (is_reenrollment)
                {
                    // Update existing node with new key
                    transaction.exec_prepared("update_node_reenroll", node_key, node_key_expires_at, last_seen, host_identifier, config_id, os_codename, client_ip);

                    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Re-enrolled node: " << host_identifier;
                }
                else
                {
                    // Insert new node
                    transaction.exec_prepared("host_add", host_identifier, os_arch, os_build, os_major, os_minor, os_name, os_platform,
                                            osquery_version, node_key, node_invalid, reenroll_allowed, config_id, hardware_vendor, hardware_model,
                                            hardware_version, hostname, hardware_cpu_logical_core, hardware_cpu_type, hardware_physical_memory,
                                            enrolled_on, last_seen, isolated, original_hostname, agent_online, status, node_key_expires_at, "default", os_codename, client_ip);

                    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "New node enrolled: " << host_identifier;
                }

                // Queue one-time initial snapshot queries on every enrollment
                // (new or re-enrollment) so high-interval tables get data immediately.
                if (os_platform == "windows")
                {
                    static const char* initial_queries[] = {
                        "select * from windows_update_history",
                        "select * from secureboot",
                        "select * from windows_firewall_rules",
                        "select * from tpm_info",
                        "select * from disk_info",
                        "select * from memory_devices",
                        "select * from bitlocker_info",
                        "select * from logical_drives"
                    };
                    for (const auto& q : initial_queries)
                        transaction.exec_prepared("queue_initial_snapshot", host_identifier, q);
                }
                else
                {
                    // Linux: queue initial snapshots for high-interval tables so data
                    // is available immediately after enrollment rather than waiting for
                    // kernel_info (84600s), secureboot (1800s), and 6-hour tables.
                    static const char* linux_initial_queries[] = {
                        "select * from kernel_info",
                        "select * from secureboot",
                        "select * from disk_encryption",
                        "select * from mounts"
                    };
                    for (const auto& q : linux_initial_queries)
                        transaction.exec_prepared("queue_initial_snapshot", host_identifier, q);
                }

                transaction.commit();
                
                // Record successful enrollment
                VajraRateLimit::recordEnrollmentAttempt(client_ip, true, host_identifier, "", connection);
                
                // Build success response
                enrollment_response["node_key"] = node_key;
                enrollment_response["node_invalid"] = false;
                enrollment_response["expires_at"] = node_key_expires_at;
                enrollment_response["is_reenrollment"] = is_reenrollment;
                
                response.status = http::status::ok;
                response.body = enrollment_response.dump();
                response.header["Content-Type"] = "application/json";
                
                BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Successfully enrolled host " << host_identifier
                                       << " with node_key length: " << node_key.length();
                // Do not log the response body: it carries the issued node_key
                // (a per-host credential). The line above is a safe summary.
                std::cout << "ENROLL SUCCESS - host " << host_identifier << std::endl;
                return response;
            }
            catch (pqxx::sql_error const &e)
            {
                BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
                VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, "Database error", connection);
                
                response.status = http::status::internal_server_error;
                response.body = "{\"message\":\"Enrollment failed due to database error.\",\"node_key\":\"\",\"node_invalid\":true}";
                response.header["Content-Type"] = "application/json";
                return response;
            }
            catch (std::exception const &e)
            {
                BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Error: " << e.what();
                VajraRateLimit::recordEnrollmentAttempt(client_ip, false, host_identifier, std::string("Error: ") + e.what(), connection);
                
                response.status = http::status::internal_server_error;
                response.body = "{\"message\":\"Enrollment failed due to error.\",\"node_key\":\"\",\"node_invalid\":true}";
                response.header["Content-Type"] = "application/json";
                return response;
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Could not process enrollment request due to incomplete fields";
            VajraRateLimit::recordEnrollmentAttempt(client_ip, false, "", "Incomplete request fields", connection);
            
            response.status = http::status::bad_request;
            response.body = "{\"message\":\"Enrollment failed due to bad request\",\"node_key\":\"\",\"node_invalid\":true}";
            response.header["Content-Type"] = "application/json";
            return response;
        }
    }
    catch (const nlohmann::json::parse_error &error)
    {
        BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Error: could not parse JSON. Parse error: " << error.what();
        response.status = http::status::bad_request;
        response.body = "{\"message\":\"Enrollment failed due to bad request\",\"node_key\":\"\",\"node_invalid\":true}";
        response.header["Content-Type"] = "application/json";
        return response;
    }
    catch (const nlohmann::json::type_error &error)
    {
        BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Error: invalid type encountered in JSON. Parse error: " << error.what();
        response.status = http::status::bad_request;
        response.body = "{\"message\":\"Enrollment failed due to bad request\",\"node_key\":\"\",\"node_invalid\":true}";
        response.header["Content-Type"] = "application/json";
        return response;
    }
    catch (const std::exception &error)
    {
        // Reached only after the body parsed and the fields validated, so this
        // is a server-side failure (e.g. a database error during enrollment),
        // NOT a client "malformed JSON" problem. Surface it as 500 with the
        // real cause logged, instead of masking a server fault as a 400 bad
        // request (which hides outages and misleads operators).
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Enrollment failed due to server error: " << error.what();
        response.status = http::status::internal_server_error;
        response.body = "{\"message\":\"Enrollment failed due to server error\",\"node_key\":\"\",\"node_invalid\":true}";
        response.header["Content-Type"] = "application/json";
        return response;
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Enrollment failed due to an unknown server error";
        response.status = http::status::internal_server_error;
        response.body = "{\"message\":\"Enrollment failed due to server error\",\"node_key\":\"\",\"node_invalid\":true}";
        response.header["Content-Type"] = "application/json";
        return response;
    }
}

// Merge a config section from one config_id into the accumulated configuration.
// Objects merge key-by-key (recursively), arrays append missing elements,
// scalars keep last-writer-wins (matches the old behaviour for single configs).
static void merge_config_section(nlohmann::json &dst, const nlohmann::json &src)
{
    if (dst.is_null())
    {
        dst = src;
        return;
    }
    if (dst.is_object() && src.is_object())
    {
        for (auto it = src.begin(); it != src.end(); ++it)
        {
            merge_config_section(dst[it.key()], it.value());
        }
        return;
    }
    if (dst.is_array() && src.is_array())
    {
        for (const auto &element : src)
        {
            if (std::find(dst.begin(), dst.end(), element) == dst.end())
            {
                dst.push_back(element);
            }
        }
        return;
    }
    dst = src;
}

HTTPMessage config(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;

    nlohmann::json osquery_configuration, scheduled_queries;
    auto start = std::chrono::high_resolution_clock::now();
    // Set from a catch below on any server/parse failure so the tail code
    // doesn't unconditionally report success (see the matching fix in
    // logger()/distributed_read()/distributed_write() for the full
    // rationale: a silent 200 here would make osquery treat a failed
    // /config fetch as delivered).
    bool request_failed = false;
    http::status failure_status = http::status::internal_server_error;

    try
    {
        auto request_data = nlohmann::json::parse(request.body);

        if (request_data.contains("node_key"))
        {
            std::string key = request_data["node_key"];
            std::string host_identifier;
            bool isKeyValid = false;

            try
            {
                // config_ids / config_queries_bulk / update_last_seen are
                // prepared once per connection in fleet_main.cpp
                pqxx::work transaction{*connection};

                pqxx::result result = transaction.exec_prepared("validate_node_key", key);
                pqxx::result ids;
                if (result.size() == 1)
                {
                    isKeyValid = true;
                    host_identifier = result.at(0)["host_identifier"].as<std::string>();
                        BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Config request " << host_identifier;
                    osquery_configuration["node_invalid"] = false;
                    long last_seen;
                    std::time_t t = std::time(0);
                    last_seen = t;
                    ids = transaction.exec_prepared("config_ids", key);
                    transaction.exec_prepared("update_last_seen", last_seen, host_identifier);
                    transaction.commit();
                }
                else
                {
                    isKeyValid = false;
                    osquery_configuration["node_invalid"] = true;
                    try { transaction.abort(); } catch (...) {}
                }
                std::string node_id;

                if (!ids.empty())
                {
                    node_id = ids.at(0)["config_id"].as<std::string>();
                }
                std::vector<std::string> config_id_list;
                boost::split(config_id_list, node_id, boost::is_any_of(","));

                // Fetch every config row in ONE round trip (previously one
                // query per config id), then merge in the original id order so
                // the response stays byte-identical for the agents.
                std::vector<int> wanted_ids;
                std::string id_array = "{";
                for (size_t i = 0; i < config_id_list.size(); i++)
                {
                    if (config_id_list[i].empty()) continue;
                    int parsed_id;
                    try {
                        parsed_id = std::stoi(config_id_list[i]);
                    } catch (const std::exception &e) {
                        // A malformed/oversized config_id must not 500 the whole
                        // /config poll for the node; skip the bad id and continue.
                        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping invalid config_id '"
                                                   << config_id_list[i] << "': " << e.what();
                        continue;
                    }
                    if (!wanted_ids.empty()) id_array += ",";
                    id_array += std::to_string(parsed_id);
                    wanted_ids.push_back(parsed_id);
                }
                id_array += "}";

                std::unordered_map<int, std::string> queries_by_id;
                if (!wanted_ids.empty())
                {
                    pqxx::nontransaction ntx{*connection};
                    pqxx::result rows = ntx.exec_prepared("config_queries_bulk", id_array);
                    for (const auto &row : rows)
                    {
                        if (!row["query"].is_null())
                        {
                            queries_by_id[row["id"].as<int>()] = row["query"].as<std::string>();
                        }
                    }
                }

                for (size_t i = 0; i < wanted_ids.size(); i++)
                {
                    auto found = queries_by_id.find(wanted_ids[i]);
                    if (found == queries_by_id.end()) continue;
                    std::string node_query = found->second, str_query;
                    if (node_query.empty()) continue;

                    nlohmann::json query = nlohmann::json::parse(node_query);
                    if (query["schedule"].contains("file"))
                    {
                        str_query = query["schedule"]["file"]["query"].get<std::string>();
                        for (char &c : str_query)
                        {
                            if (c == '\"')
                            {
                                c = '\'';
                            }
                        }
                        query["schedule"]["file"]["query"] = str_query;
                    }
                    if (isKeyValid)
                    {
                        // Iterating over the keys in the "schedule" object
                        for (auto it = query["schedule"].begin(); it != query["schedule"].end(); ++it)
                        {
                            std::string scheduleKey = it.key(); // Get the key of the schedule object

                            // Checking if the key exists and if it's not null
                            if (!query["schedule"][scheduleKey].is_null())
                            {
                                scheduled_queries[scheduleKey]["query"] = query["schedule"][scheduleKey]["query"];
                                scheduled_queries[scheduleKey]["interval"] = query["schedule"][scheduleKey]["interval"];
                                // If snapshot key exists, include it in scheduled_queries
                                if (query["schedule"][scheduleKey].contains("snapshot"))
                                {
                                    scheduled_queries[scheduleKey]["snapshot"] = query["schedule"][scheduleKey]["snapshot"];
                                }
                            }
                        }
                        osquery_configuration["schedule"] = scheduled_queries;
                        // Merge sections across config IDs instead of overwriting,
                        // otherwise only the last config defining a section survives.
                        for (const char* section : {"file_paths", "file_accesses", "win_include_paths",
                                                    "plgx_event_filters", "options", "decorators"})
                        {
                            if (query.contains(section))
                            {
                                merge_config_section(osquery_configuration[section], query[section]);
                            }
                        }
                    }
                }
            }
            catch (pqxx::sql_error const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
                // Do NOT set node_invalid=true here — this is a server-side error,
                // not an invalid node key. Returning node_invalid=true on transient
                // DB errors (connection timeout, deadlock, PG restart) forces osquery
                // to drop its key and re-enroll, which can permanently kill its TLS
                // transport (osquery #4433). The node should retry on the next
                // config_refresh cycle instead -- which requires a non-200 status
                // (see request_failed below), not just an unset node_invalid: a 200
                // here would tell osquery this fetch already succeeded.
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (std::exception const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (...)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
        }
        else
        {
            // osquery TLS protocol: a request without a node_key cannot be
            // authenticated — signal node_invalid like an invalid key does.
            osquery_configuration["node_invalid"] = true;
        }
    }
    catch (const nlohmann::json::parse_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: could not parse JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (const nlohmann::json::type_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: invalid type encountered in JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (std::exception const &e)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }

    std::string reply = osquery_configuration.dump();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Endpoint: /config, time taken: " << duration.count() << " microseconds";

    response.status = request_failed ? failure_status : http::status::ok;
    response.body = reply;
    // std::cout<<response.body<<std::endl;
    response.header["Content-Type"] = "application/json";
    return response;
}
std::string sanitize_name(const std::string &name) {
    auto pos = name.find_first_of("-0123456789");
    std::string sanitized = (pos != std::string::npos) ? name.substr(0, pos) : name;

    // Fallback for empty or invalid names
    if (sanitized.empty()) {
        sanitized = "unknown"; // Default fallback value
    }
    return sanitized;
}



std::string sanitize_version(const std::string &version) {
    std::string sanitized;
    size_t start = 0;

    // Identify and retain epoch if present (e.g., "2:1.0.3" -> "2:1.0.3")
    size_t colon_pos = version.find(':');
    if (colon_pos != std::string::npos) {
        sanitized = version.substr(0, colon_pos + 1); // Include the colon
        start = colon_pos + 1;
    }

    // Extract only numeric and period characters after the epoch
    for (size_t i = start; i < version.size(); ++i) {
        if (std::isdigit(version[i]) || version[i] == '.') {
            sanitized += version[i];
        } else {
            break;  // Stop at first non-numeric, non-dot character
        }
    }

    if (sanitized.empty()) {
        throw std::runtime_error("Sanitized version is empty.");
    }

    return sanitized;
}

// ---------------------------------------------------------------------------
// R2-2: buffered multi-row INSERT support for the highest-volume /log event
// tables. The differential-event handler used to issue one exec_prepared()
// round trip per row; LogEventBatch accumulates already-validated rows in
// memory and flushes them as a single "INSERT ... VALUES ($1,...),($n,...)"
// executed inside the caller's existing transaction, so N buffered rows cost
// one round trip instead of N. Only the tables in PendingLogBatches below are
// wired up (process/socket/file events across the generic Linux audit,
// bpf_*, and win_* families -- the dominant EDR volume per Sage's review);
// every other branch keeps its existing per-row exec_prepared call.
// ---------------------------------------------------------------------------
class LogEventBatch
{
public:
    // literal_suffix, if non-empty, is appended verbatim (including its own
    // leading comma) after each row's placeholders. Used for trailing
    // constant columns such as the bpf_*/win_* "is_processed*" flags that
    // are always inserted as 'f' regardless of row content -- the existing
    // prepared statements bake the same literals into their INSERT text
    // rather than binding them as parameters, and this preserves that.
    explicit LogEventBatch(std::string insert_prefix, std::size_t columns_per_row, std::string literal_suffix = std::string())
        : insert_prefix_(std::move(insert_prefix)), columns_per_row_(columns_per_row), literal_suffix_(std::move(literal_suffix))
    {
    }

    template <typename... Args>
    void push_row(Args&&... args)
    {
        static_assert(sizeof...(Args) > 0, "a row must have at least one column");
        rows_.emplace_back();
        pqxx::params& row = rows_.back();
        row.reserve(sizeof...(Args));
        (row.append(std::forward<Args>(args)), ...);
    }

    std::size_t size() const { return rows_.size(); }
    bool empty() const { return rows_.empty(); }

    // Executes ONE multi-row INSERT for all buffered rows inside `transaction`
    // and clears the buffer on success. No-op (no round trip) if empty.
    // Caller owns commit/rollback of `transaction`.
    void flush(pqxx::work& transaction)
    {
        if (rows_.empty())
            return;

        pqxx::placeholders<> ph;
        std::string sql = insert_prefix_;
        sql += " VALUES ";
        pqxx::params merged;
        merged.reserve(rows_.size() * columns_per_row_);
        for (std::size_t r = 0; r < rows_.size(); ++r)
        {
            if (r > 0)
                sql += ", ";
            sql += "(";
            for (std::size_t c = 0; c < columns_per_row_; ++c)
            {
                if (c > 0)
                    sql += ", ";
                sql += std::string(ph.view());
                ph.next();
            }
            sql += literal_suffix_;
            sql += ")";
            merged.append(rows_[r]);
        }
        transaction.exec_params(sql, merged);
        rows_.clear();
    }

    // Drops all buffered rows without executing anything. Used when the
    // owning transaction has already been aborted -- re-flushing them later
    // would just repeat the same failure forever (see the pqxx::sql_error
    // handler in logger()).
    void clear() { rows_.clear(); }

private:
    std::string insert_prefix_;
    std::size_t columns_per_row_;
    std::string literal_suffix_;
    std::vector<pqxx::params> rows_;
};

// Groups the per-table buffers so every commit/abort point in the
// differential-event loop can flush or clear all of them with one call.
struct PendingLogBatches
{
    LogEventBatch process_events{
        "insert into process_events (host_identifier, hostname, unixtime, atime, btime, ctime, mtime, time, uptime, "
        "auid, egid, euid, fsgid, fsuid, gid, mode, owner_gid, owner_uid, pid, ppid, sgid, suid, uid, cwd, cmdline, path, syscall)",
        27};
    LogEventBatch socket_events{
        "insert into socket_events (host_identifier, hostname, unixTime, time, uptime, action, auid, family, fd, "
        "local_address, local_port, remote_address, remote_port, pid, path)",
        15};
    LogEventBatch file_events{
        "insert into file_events (host_identifier, hostname, unixTime, target_path, category, action, transaction_id, inode, "
        "uid, gid, mode, size, atime, mtime, ctime, md5, sha1, sha256, hashed, time, eid)",
        21};
    LogEventBatch bpf_process_events{
        "insert into bpf_process_events (host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, "
        "probe_error, syscall, path, cwd, cmdline, duration, json_cmdline, ntime, time, eid, md5, sha1, sha256, "
        "is_container_process, container_age, container_name, uptime, is_processed, is_processed_rule_builder, is_processed_py)",
        27, ", 'f', 'f', 'f'"};
    LogEventBatch bpf_socket_events{
        "insert into bpf_socket_events (host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, "
        "probe_error, syscall, path, fd, family, type, protocol, local_address, remote_address, local_port, remote_port, "
        "duration, ntime, time, eid, uptime, is_processed, is_processed_rule_builder, is_processed_py)",
        26, ", 'f', 'f', 'f'"};
    LogEventBatch bpf_file_events{
        "insert into bpf_file_events (host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, "
        "probe_error, syscall, path, file_path, flags, ntime, duration, time, uptime, is_processed, is_processed_rule_builder, is_processed_py)",
        19, ", 'f', 'f', 'f'"};
    LogEventBatch win_process_events{
        "insert into win_process_events (host_identifier, hostname, unixTime, action, eid, pid, process_guid, path, cmdline, "
        "parent_pid, parent_process_guid, parent_path, owner_uid, time, uptime, utc_time, eventid, sha256, is_processed, "
        "is_processed_rule_builder, is_processed_py)",
        18, ", 'f', 'f', 'f'"};
    LogEventBatch win_socket_events{
        "insert into win_socket_events (host_identifier, hostname, unixTime, action, eid, time, utc_time, pid, process_guid, "
        "process_name, family, protocol, local_address, remote_address, local_port, remote_port, eventid, parent_pid, uptime, "
        "is_processed, is_processed_rule_builder, is_processed_py)",
        19, ", 'f', 'f', 'f'"};
    LogEventBatch win_file_events{
        "insert into win_file_events (host_identifier, hostname, unixTime, action, eid, target_path, md5, sha256, hashed, "
        "uid, utc_time, time, pe_file, pid, process_guid, process_name, eventid, parent_pid, uptime, is_processed, "
        "is_processed_rule_builder, is_processed_py)",
        19, ", 'f', 'f', 'f'"};

    // R2-2 continuation: lower-volume differential tables, same pattern.
    LogEventBatch user_events{
        "insert into user_events (host_identifier, unixTime, time, uptime, auid, pid, type, uid, "
        "path, address, message, terminal)",
        12};
    LogEventBatch process_envs{
        "insert into process_envs (host_identifier, pid, key, value, action)",
        5};
    LogEventBatch process_open_pipes{
        "insert into process_open_pipes (host_identifier, unixTime, pid, fd, mode, inode, type, partner_pid, partner_fd, partner_mode, action)",
        11};
    LogEventBatch process_open_files{
        "insert into process_open_files (host_identifier, unixTime, pid, fd, path, action)",
        6};
    LogEventBatch listening_ports{
        "insert into listening_ports (host_identifier, unixTime, pid, port, protocol, family, address, fd, socket, path, net_namespace, action)",
        12};
    LogEventBatch routes{
        "insert into routes (host_identifier, destination, netmask, gateway, source, flags, interface, mtu, metric, type, hopcount, action)",
        12};
    LogEventBatch logged_in_users{
        "insert into logged_in_users (host_identifier, unixTime, type, logged_user, tty, host, time, pid, sid, registry_hive, action)",
        11};
    LogEventBatch arp_cache{
        "insert into arp_cache (host_identifier, address, mac, interface, permanent, action)",
        6};
    LogEventBatch process_file_events{
        "insert into process_file_events (host_identifier, operation, pid, ppid, time, executable, partial, cwd, path, dest_path, "
        "uid, gid, auid, euid, egid, fsuid, fsgid, suid, sgid, uptime, eid)",
        21};
    LogEventBatch suid_bin{
        "insert into suid_bin (host_identifier, unixTime, path, username, groupname, permissions, action)",
        7};
    LogEventBatch process_open_sockets{
        "insert into process_open_sockets (host_identifier, unixTime, pid, fd, socket, family, protocol, local_address, "
        "remote_address, local_port, remote_port, path, state, net_namespace, action)",
        15};
    LogEventBatch users{
        "insert into users (host_identifier, uid, gid, uid_signed, gid_signed, is_hidden, username, description, directory, shell, uuid, type, action)",
        13};
    LogEventBatch groups{
        "insert into groups (host_identifier, gid, gid_signed, is_hidden, groupname, group_sid, comment, action)",
        8};
    LogEventBatch cpu_time{
        "insert into cpu_time (host_identifier, unixTime, core, users, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice)",
        13};
    LogEventBatch memory_info{
        "insert into memory_info (host_identifier, unixTime, memory_total, memory_available, memory_free, buffers, cached, "
        "swap_cached, active, inactive, swap_total, swap_free)",
        12};
    LogEventBatch docker_events{
        "insert into docker_events (host_identifier, hostname, action, from_column, status, scope, time, type, path, cmdline, "
        "pid, container_id, container_image, container_name, privileged, added_capabilities, dropped_capabilities, port_binding)",
        18};
    LogEventBatch interface_addresses{
        "insert into interface_addresses (host_identifier, unixtime, interface, address, mask, broadcast, point_to_point, type, friendly_name)",
        9};

    std::size_t total_buffered() const
    {
        return process_events.size() + socket_events.size() + file_events.size() +
               bpf_process_events.size() + bpf_socket_events.size() + bpf_file_events.size() +
               win_process_events.size() + win_socket_events.size() + win_file_events.size() +
               user_events.size() + process_envs.size() + process_open_pipes.size() +
               process_open_files.size() + listening_ports.size() + routes.size() +
               logged_in_users.size() + arp_cache.size() + process_file_events.size() +
               suid_bin.size() + process_open_sockets.size() + users.size() + groups.size() +
               cpu_time.size() + memory_info.size() + docker_events.size() + interface_addresses.size();
    }

    // Flushes every non-empty buffer into `transaction` (one multi-row
    // INSERT per table). Called at every point the loop is about to commit
    // so buffered rows are never silently dropped by a commit triggered
    // while they're still sitting in memory.
    void flush_all(pqxx::work& transaction)
    {
        process_events.flush(transaction);
        socket_events.flush(transaction);
        file_events.flush(transaction);
        bpf_process_events.flush(transaction);
        bpf_socket_events.flush(transaction);
        bpf_file_events.flush(transaction);
        win_process_events.flush(transaction);
        win_socket_events.flush(transaction);
        win_file_events.flush(transaction);
        user_events.flush(transaction);
        process_envs.flush(transaction);
        process_open_pipes.flush(transaction);
        process_open_files.flush(transaction);
        listening_ports.flush(transaction);
        routes.flush(transaction);
        logged_in_users.flush(transaction);
        arp_cache.flush(transaction);
        process_file_events.flush(transaction);
        suid_bin.flush(transaction);
        process_open_sockets.flush(transaction);
        users.flush(transaction);
        groups.flush(transaction);
        cpu_time.flush(transaction);
        memory_info.flush(transaction);
        docker_events.flush(transaction);
        interface_addresses.flush(transaction);
    }

    // Drops every buffered row without executing anything. Used after the
    // owning transaction aborts (see the pqxx::sql_error handler below).
    void clear_all()
    {
        process_events.clear();
        socket_events.clear();
        file_events.clear();
        bpf_process_events.clear();
        bpf_socket_events.clear();
        bpf_file_events.clear();
        win_process_events.clear();
        win_socket_events.clear();
        win_file_events.clear();
        user_events.clear();
        process_envs.clear();
        process_open_pipes.clear();
        process_open_files.clear();
        listening_ports.clear();
        routes.clear();
        logged_in_users.clear();
        arp_cache.clear();
        process_file_events.clear();
        suid_bin.clear();
        process_open_sockets.clear();
        users.clear();
        groups.clear();
        cpu_time.clear();
        memory_info.clear();
        docker_events.clear();
        interface_addresses.clear();
    }
};

HTTPMessage logger(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;
    nlohmann::json log_response;
    auto start = std::chrono::high_resolution_clock::now();
    // Set from a catch below on any server/parse failure so the tail code
    // doesn't unconditionally report success. osquery's TLS logger plugin
    // treats a 200 response as "delivered" and drops its local buffer -- a
    // silent 200 on a DB error or malformed body here would permanently
    // lose that batch of telemetry instead of letting the agent retry it.
    bool request_failed = false;
    http::status failure_status = http::status::internal_server_error;
    try
    {
        auto logger_data = nlohmann::json::parse(request.body);
        // std::cout<<request.body<<std::endl;
        if (logger_data.contains("log_type") && logger_data.contains("node_key"))
        {
            std::string key = logger_data["node_key"];

            // Validate node_key format
            if (!VajraValidator::isValidNodeKey(key))
            {
                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Invalid node_key format";
                log_response["node_invalid"] = true;
                log_response["error"] = "Invalid node key format";
                response.body = log_response.dump();
                response.status = boost::beast::http::status::bad_request;
                return response;
            }

            std::string host_identifier, hostname;
            std::unique_ptr<pqxx::work> transaction = std::make_unique<pqxx::work>(*connection);
            bool isKeyValid = false;

            try
            {
                pqxx::result result = transaction->exec_prepared("validate_node_key", key);
                if (result.size() == 1)
                {
                    isKeyValid = true;
                    host_identifier = result.at(0)["host_identifier"].as<std::string>();
                    log_response["node_invalid"] = false;
                    pqxx::result host = transaction->exec_prepared("get_hostname", key);
                    if (!host.empty())
                        hostname = host.at(0)["hostname"].as<std::string>();
                    long last_seen;
                    std::time_t t = std::time(0);
                    last_seen = t;
                    transaction->exec_prepared("update_last_seen", last_seen, host_identifier);
                    transaction->commit();
                    // Recreate transaction for event processing
                    transaction = std::make_unique<pqxx::work>(*connection);
                }
                else
                {
                    isKeyValid = false;
                    log_response["node_invalid"] = true;
                    try { transaction->abort(); } catch (...) {}
                }

                if (isKeyValid && logger_data["log_type"] == "result" && logger_data.contains("data"))
                {
                    auto entries = logger_data["data"];
                    // std::cout << entries <<std::endl;
                    if (entries.is_array())
                    {
                        // Validate event count
                        if (!VajraValidator::isValidEventCount(entries.size()))
                        {
                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Event count exceeds maximum: " << entries.size();
                            log_response["error"] = "Too many events in single request";
                            response.body = log_response.dump();
                            response.status = boost::beast::http::status::bad_request;
                            return response;
                        }

                        unsigned int batch_count = 0;
                        unsigned int skipped_entries = 0;
                        const unsigned int BATCH_SIZE = 100;
                        // R2-2: rows for the highest-volume event tables are buffered
                        // here and flushed as multi-row INSERTs (see PendingLogBatches)
                        // instead of one exec_prepared() round trip per row. Flushed
                        // at the same commit points BATCH_SIZE already used, so the
                        // commit cadence is unchanged -- only the number of round
                        // trips per commit window drops.
                        PendingLogBatches pending_batches;
                        for (auto entry : entries)
                        {
                            // Per-entry error isolation: a malformed entry is
                            // skipped without aborting the rest of the batch.
                            // (Body intentionally not re-indented.)
                            try
                            {
                            // std::cout << entry["name"] << std::endl;
                            // std::cout << entry << std::endl;
                            // if (entry.contains("hostIdentifier") && entry.contains("name") && entry.contains("columns") && (set_tables.find(entry["name"])!=set_tables.end()))
                            if (entry.contains("hostIdentifier") && entry.contains("name") && entry.contains("columns"))
                            {
                                // std::cout << entry["schedule"] << std::endl;
                                std::string tableName = entry["name"];

                                // Validate table name
                                if (!VajraValidator::isValidTableName(tableName))
                                {
                                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Invalid table name: " << tableName;
                                    continue; // Skip this event
                                }

                                std::string action = "";
                                if (entry.contains("action"))
                                {
                                    action = entry["action"];
                                }
                                if (host_identifier != entry["hostIdentifier"])
                                {
                                    continue;
                                }

                                if (tableName == "process_events")
                                {
                                    long unixTime, time, atime, btime, ctime, mtime, uptime;
                                    long auid, egid, euid, fsgid, fsuid, gid, mode, owner_gid, owner_uid, pid, ppid, sgid, suid, uid;
                                    std::string cwd, cmdline, path, syscall;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    atime = column.contains("atime") ? atol(column["atime"].get<std::string>().c_str()) : 0;
                                    btime = column.contains("btime") ? atol(column["btime"].get<std::string>().c_str()) : 0;
                                    ctime = column.contains("ctime") ? atol(column["ctime"].get<std::string>().c_str()) : 0;
                                    mtime = column.contains("mtime") ? atol(column["mtime"].get<std::string>().c_str()) : 0;
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;

                                    auid = column.contains("auid") ? atol(column["auid"].get<std::string>().c_str()) : 0;
                                    egid = column.contains("egid") ? atol(column["egid"].get<std::string>().c_str()) : 0;
                                    euid = column.contains("euid") ? atol(column["euid"].get<std::string>().c_str()) : 0;
                                    fsgid = column.contains("fsgid") ? atol(column["fsgid"].get<std::string>().c_str()) : 0;
                                    fsuid = column.contains("fsuid") ? atol(column["fsuid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    mode = column.contains("mode") ? atol(column["mode"].get<std::string>().c_str()) : 0;
                                    owner_gid = column.contains("owner_gid") ? atol(column["owner_gid"].get<std::string>().c_str()) : 0;
                                    owner_uid = column.contains("owner_uid") ? atol(column["owner_uid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    ppid = column.contains("parent") ? atol(column["parent"].get<std::string>().c_str()) : 0;
                                    sgid = column.contains("sgid") ? atol(column["sgid"].get<std::string>().c_str()) : 0;
                                    suid = column.contains("suid") ? atol(column["suid"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;

                                    cwd = column.contains("cwd") ? column["cwd"] : "";
                                    cmdline = column.contains("cmdline") ? column["cmdline"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    syscall = column.contains("syscall") ? column["syscall"] : "";

                                    pending_batches.process_events.push_row(host_identifier, hostname, unixTime, atime, btime, ctime, mtime, time, uptime,
                                                              auid, egid, euid, fsgid, fsuid, gid, mode, owner_gid, owner_uid, pid, ppid, sgid, suid, uid,
                                                              cwd, cmdline, path, syscall);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "socket_events")
                                {
                                    long unixTime, time, uptime, auid, family, fd, local_port, remote_port, pid;
                                    std::string action, local_address, remote_address, path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;

                                    auid = column.contains("auid") ? atol(column["auid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    family = column.contains("family") ? atol(column["family"].get<std::string>().c_str()) : 0;
                                    fd = column.contains("fd") ? atol(column["fd"].get<std::string>().c_str()) : 0;
                                    local_port = column.contains("local_port") ? atol(column["local_port"].get<std::string>().c_str()) : 0;
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;

                                    action = column.contains("action") ? column["action"] : "";
                                    local_address = column.contains("local_address") ? column["local_address"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    path = column.contains("path") ? column["path"] : "";

                                    pending_batches.socket_events.push_row(host_identifier, hostname, unixTime, time, uptime, action, auid, family, fd,
                                                              local_address, local_port, remote_address, remote_port, pid, path);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "user_events")
                                {
                                    long unixTime, time, uptime, auid, pid, type, uid;
                                    std::string path, address, message, terminal;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;

                                    auid = column.contains("auid") ? atol(column["auid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    type = column.contains("type") ? atol(column["type"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;

                                    path = column.contains("path") ? column["path"] : "";
                                    address = column.contains("address") ? column["address"] : "";
                                    message = column.contains("message") ? column["message"] : "";
                                    terminal = column.contains("terminal") ? column["terminal"] : "";

                                    pending_batches.user_events.push_row(host_identifier, unixTime, time, uptime, auid, pid, type, uid,
                                                              path, address, message, terminal);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "process_envs")
                                {
                                    long pid;
                                    std::string key, value;

                                    auto column = entry["columns"];

                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    key = column.contains("key") ? column["key"] : "";
                                    value = column.contains("value") ? column["value"] : "";

                                    pending_batches.process_envs.push_row(host_identifier, pid, key, value, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "process_open_pipes")
                                {
                                    long pid, fd, inode, partner_pid, partner_fd, unixTime;
                                    std::string mode, type, partner_mode;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    fd = column.contains("fd") ? atol(column["fd"].get<std::string>().c_str()) : 0;
                                    inode = column.contains("inode") ? atol(column["inode"].get<std::string>().c_str()) : 0;
                                    partner_pid = column.contains("partner_pid") ? atol(column["partner_pid"].get<std::string>().c_str()) : 0;
                                    partner_fd = column.contains("partner_fd") ? atol(column["partner_fd"].get<std::string>().c_str()) : 0;
                                    mode = column.contains("mode") ? column["mode"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    partner_mode = column.contains("partner_mode") ? column["partner_mode"] : "";

                                    pending_batches.process_open_pipes.push_row(host_identifier, unixTime, pid, fd, mode, inode, type, partner_pid, partner_fd, partner_mode, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }

                                else if (tableName == "process_open_files")
                                {
                                    long pid, fd, unixTime;
                                    std::string path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    fd = column.contains("fd") ? atol(column["fd"].get<std::string>().c_str()) : 0;
                                    path = column.contains("path") ? column["path"] : "";

                                    pending_batches.process_open_files.push_row(host_identifier, unixTime, pid, fd, path, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }

                                else if (tableName == "listening_ports")
                                {
                                    long unixTime, pid, port, protocol, family, fd, socket;
                                    std::string address, path, net_namespace;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    port = column.contains("port") ? atol(column["port"].get<std::string>().c_str()) : 0;
                                    protocol = column.contains("protocol") ? atol(column["protocol"].get<std::string>().c_str()) : 0;
                                    family = column.contains("family") ? atol(column["family"].get<std::string>().c_str()) : 0;
                                    socket = column.contains("socket") ? atol(column["socket"].get<std::string>().c_str()) : 0;
                                    fd = column.contains("fd") ? atol(column["fd"].get<std::string>().c_str()) : 0;
                                    path = column.contains("path") ? column["path"] : "";
                                    address = column.contains("address") ? column["address"] : "";
                                    net_namespace = column.contains("net_namespace") ? column["net_namespace"] : "";

                                    pending_batches.listening_ports.push_row(host_identifier, unixTime, pid, port, protocol, family, address, fd, socket, path, net_namespace, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "routes")
                                {
                                    long netmask, flags, mtu, metric, hopcount;
                                    std::string destination, gateway, source, interface, type;

                                    auto column = entry["columns"];

                                    netmask = column.contains("netmask") ? atol(column["netmask"].get<std::string>().c_str()) : 0;
                                    flags = column.contains("flags") ? atol(column["flags"].get<std::string>().c_str()) : 0;
                                    mtu = column.contains("mtu") ? atol(column["mtu"].get<std::string>().c_str()) : 0;
                                    metric = column.contains("metric") ? atol(column["metric"].get<std::string>().c_str()) : 0;
                                    hopcount = column.contains("hopcount") ? atol(column["hopcount"].get<std::string>().c_str()) : 0;
                                    destination = column.contains("destination") ? column["destination"] : "";
                                    gateway = column.contains("gateway") ? column["gateway"] : "";
                                    source = column.contains("source") ? column["source"] : "";
                                    interface = column.contains("interface") ? column["interface"] : "";
                                    type = column.contains("type") ? column["type"] : "";

                                    pending_batches.routes.push_row(host_identifier, destination, netmask, gateway, source, flags, interface, mtu, metric, type, hopcount, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "logged_in_users")
                                {
                                    long time, pid, unixTime;
                                    std::string type, logged_user, tty, host, sid, registry_hive;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    type = column.contains("type") ? column["type"] : "";
                                    logged_user = column.contains("user") ? column["user"] : "";
                                    tty = column.contains("tty") ? column["tty"] : "";
                                    host = column.contains("host") ? column["host"] : "";
                                    sid = column.contains("sid") ? column["sid"] : "";
                                    registry_hive = column.contains("registry_hive") ? column["registry_hive"] : "";

                                    pending_batches.logged_in_users.push_row(host_identifier, unixTime, type, logged_user, tty, host, time, pid, sid, registry_hive, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }

                                else if (tableName == "arp_cache")
                                {
                                    std::string address, mac, interface, permanent;

                                    auto column = entry["columns"];

                                    address = column.contains("address") ? column["address"] : "";
                                    mac = column.contains("mac") ? column["mac"] : "";
                                    interface = column.contains("interface") ? column["interface"] : "";
                                    permanent = column.contains("permanent") ? column["permanent"] : "";

                                    pending_batches.arp_cache.push_row(host_identifier, address, mac, interface, permanent, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "process_file_events")
                                {
                                    long pid, ppid, time, uptime;
                                    std::string operation, executable, partial, cwd, path, dest_path, uid, gid, auid, euid, egid, fsuid, fsgid, suid, sgid, eid;

                                    auto column = entry["columns"];

                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;
                                    ppid = column.contains("ppid") ? atol(column["ppid"].get<std::string>().c_str()) : 0;
                                    operation = column.contains("operation") ? column["operation"] : "";
                                    executable = column.contains("executable") ? column["executable"] : "";
                                    partial = column.contains("partial") ? column["partial"] : "";
                                    cwd = column.contains("cwd") ? column["cwd"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    dest_path = column.contains("dest_path") ? column["dest_path"] : "";
                                    uid = column.contains("uid") ? column["uid"] : "";
                                    gid = column.contains("gid") ? column["gid"] : "";
                                    auid = column.contains("auid") ? column["auid"] : "";
                                    euid = column.contains("euid") ? column["euid"] : "";
                                    egid = column.contains("egid") ? column["egid"] : "";
                                    fsuid = column.contains("fsuid") ? column["fsuid"] : "";
                                    fsgid = column.contains("fsgid") ? column["fsgid"] : "";
                                    suid = column.contains("suid") ? column["suid"] : "";
                                    sgid = column.contains("sgid") ? column["sgid"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";

                                    pending_batches.process_file_events.push_row(host_identifier, operation, pid, ppid, time, executable, partial, cwd, path, dest_path, uid, gid, auid, euid, egid, fsuid, fsgid, suid, sgid, uptime, eid);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "file_events")
                                {
                                    int hashed;
                                    std::string target_path, category, action, md5, sha1, sha256, eid, mode;
                                    long unixTime, transaction_id, inode, uid, gid, size, atime, mtime, ctime, time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    target_path = column.contains("target_path") ? column["target_path"] : "";
                                    category = column.contains("category") ? column["category"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    transaction_id = column.contains("transaction_id") ? atol(column["transaction_id"].get<std::string>().c_str()) : 0;
                                    inode = column.contains("inode") ? atol(column["inode"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    mode = column.contains("mode") ? column["mode"] : "";
                                    size = column.contains("size") ? atol(column["size"].get<std::string>().c_str()) : 0;
                                    atime = column.contains("atime") ? atol(column["atime"].get<std::string>().c_str()) : 0;
                                    mtime = column.contains("mtime") ? atol(column["mtime"].get<std::string>().c_str()) : 0;
                                    ctime = column.contains("ctime") ? atol(column["ctime"].get<std::string>().c_str()) : 0;
                                    md5 = column.contains("md5") ? column["md5"] : "";
                                    sha1 = column.contains("sha1") ? column["sha1"] : "";
                                    sha256 = column.contains("sha256") ? column["sha256"] : "";
                                    hashed = entry.contains("hashed") ? entry["hashed"].get<int>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    eid = column.contains("eid") ? column["eid"] : "";

                                    pending_batches.file_events.push_row(host_identifier, hostname, unixTime, target_path, category, action, transaction_id, inode, uid, gid, mode, size, atime, mtime, ctime, md5, sha1, sha256, hashed, time, eid);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "suid_bin")
                                {
                                    std::string path, username, groupname, permissions;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    path = column.contains("path") ? column["path"] : "";
                                    username = column.contains("username") ? column["username"] : "";
                                    groupname = column.contains("groupname") ? column["groupname"] : "";
                                    permissions = column.contains("permissions") ? column["permissions"] : "";

                                    pending_batches.suid_bin.push_row(host_identifier, unixTime, path, username, groupname, permissions, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "process_open_sockets")
                                {

                                    long pid, unixTime, fd, socket, family, protocol, local_port, remote_port;
                                    std::string local_address, remote_address, path, state, net_namespace;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    fd = column.contains("fd") ? atol(column["fd"].get<std::string>().c_str()) : 0;
                                    socket = column.contains("socket") ? atol(column["socket"].get<std::string>().c_str()) : 0;
                                    family = column.contains("family") ? atol(column["family"].get<std::string>().c_str()) : 0;
                                    protocol = column.contains("protocol") ? atol(column["protocol"].get<std::string>().c_str()) : 0;
                                    local_port = column.contains("local_port") ? atol(column["local_port"].get<std::string>().c_str()) : 0;
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    local_address = column.contains("local_address") ? column["local_address"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    state = column.contains("state") ? column["state"] : "";
                                    net_namespace = column.contains("net_namespace") ? column["net_namespace"] : "";

                                    pending_batches.process_open_sockets.push_row(host_identifier, unixTime, pid, fd, socket, family, protocol, local_address, remote_address, local_port, remote_port, path, state, net_namespace, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "users")
                                {
                                    std::string username, description, directory, shell, uuid, type;
                                    long uid, gid, uid_signed, gid_signed, is_hidden;

                                    auto column = entry["columns"];
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    uid_signed = column.contains("uid_signed") ? atol(column["uid_signed"].get<std::string>().c_str()) : 0;
                                    gid_signed = column.contains("gid_signed") ? atol(column["gid_signed"].get<std::string>().c_str()) : 0;
                                    is_hidden = column.contains("is_hidden") ? atol(column["is_hidden"].get<std::string>().c_str()) : 0;
                                    description = column.contains("description") ? column["description"] : "";
                                    username = column.contains("username") ? column["username"] : "";
                                    directory = column.contains("directory") ? column["directory"] : "";
                                    shell = column.contains("shell") ? column["shell"] : "";
                                    uuid = column.contains("uuid") ? column["uuid"] : "";
                                    type = column.contains("type") ? column["type"] : "";

                                    pending_batches.users.push_row(host_identifier, uid, gid, uid_signed, gid_signed, is_hidden, username, description, directory, shell, uuid, type, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "groups")
                                {
                                    std::string groupname, group_sid, comment;
                                    long gid, gid_signed, is_hidden;

                                    auto column = entry["columns"];
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    gid_signed = column.contains("gid_signed") ? atol(column["gid_signed"].get<std::string>().c_str()) : 0;
                                    is_hidden = column.contains("is_hidden") ? atol(column["is_hidden"].get<std::string>().c_str()) : 0;
                                    groupname = column.contains("groupname") ? column["groupname"] : "";
                                    group_sid = column.contains("group_sid") ? column["group_sid"] : "";
                                    comment = column.contains("comment") ? column["comment"] : "";

                                    pending_batches.groups.push_row(host_identifier, gid, gid_signed, is_hidden, groupname, group_sid, comment, action);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "cpu_time")
                                {
                                    long core, users, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice, unixTime;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    core = column.contains("core") ? atol(column["core"].get<std::string>().c_str()) : 0;
                                    users = column.contains("users") ? atol(column["users"].get<std::string>().c_str()) : 0;
                                    nice = column.contains("nice") ? atol(column["nice"].get<std::string>().c_str()) : 0;
                                    system = column.contains("system") ? atol(column["system"].get<std::string>().c_str()) : 0;
                                    idle = column.contains("idle") ? atol(column["idle"].get<std::string>().c_str()) : 0;
                                    iowait = column.contains("iowait") ? atol(column["iowait"].get<std::string>().c_str()) : 0;
                                    irq = column.contains("irq") ? atol(column["irq"].get<std::string>().c_str()) : 0;
                                    softirq = column.contains("softirq") ? atol(column["softirq"].get<std::string>().c_str()) : 0;
                                    steal = column.contains("steal") ? atol(column["steal"].get<std::string>().c_str()) : 0;
                                    guest = column.contains("guest") ? atol(column["guest"].get<std::string>().c_str()) : 0;
                                    guest_nice = column.contains("guest_nice") ? atol(column["guest_nice"].get<std::string>().c_str()) : 0;

                                    pending_batches.cpu_time.push_row(host_identifier, unixTime, core, users, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "memory_info" || tableName == "win_mem_perf")
                                {
                                    long memory_total = 0, memory_available = 0, memory_free = 0, buffers = 0, cached = 0, swap_cached = 0, active = 0, inactive = 0, swap_total = 0, swap_free = 0, unixTime = 0;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    if(column.contains("total_physical") || column.contains("memory_total")){
                                        memory_total = column.contains("memory_total") ? 
                                        atol(column["memory_total"].get<std::string>().c_str()) : 
                                        atol(column["total_physical"].get<std::string>().c_str());
                                    }
                                    // memory_free = column.contains("memory_free") ? atol(column["memory_free"].get<std::string>().c_str()) : 0;
                                    if(column.contains("available_physical") || column.contains("memory_available")){
                                        memory_available = column.contains("memory_available") ? 
                                        atol(column["memory_available"].get<std::string>().c_str()) : 
                                        atol(column["available_physical"].get<std::string>().c_str());
                                    }
                                    if(column.contains("available_physical") || column.contains("memory_free")){
                                        memory_free = column.contains("memory_free") ? 
                                        atol(column["memory_free"].get<std::string>().c_str()) : 
                                        atol(column["available_physical"].get<std::string>().c_str());
                                    }
                                    buffers = column.contains("buffers") ? atol(column["buffers"].get<std::string>().c_str()) : 0;
                                    cached = column.contains("cached") ? atol(column["cached"].get<std::string>().c_str()) : 0;
                                    swap_cached = column.contains("swap_cached") ? atol(column["swap_cached"].get<std::string>().c_str()) : 0;
                                    active = column.contains("active") ? atol(column["active"].get<std::string>().c_str()) : 0;
                                    inactive = column.contains("inactive") ? atol(column["inactive"].get<std::string>().c_str()) : 0;
                                    swap_total = column.contains("swap_total") ? atol(column["swap_total"].get<std::string>().c_str()) : 0;
                                    swap_free = column.contains("swap_free") ? atol(column["swap_free"].get<std::string>().c_str()) : 0;

                                    pending_batches.memory_info.push_row(host_identifier, unixTime, memory_total, memory_available, memory_free, buffers, cached, swap_cached, active, inactive, swap_total, swap_free);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "bpf_process_events")
                                {
                                    std::string exit_code, syscall, path, cwd, cmdline, json_cmdline, ntime, md5, sha1, sha256, container_name;
                                    long unixTime, tid, pid, parent, uid, gid, cid, probe_error, duration, time, eid, is_container_process, container_age, uptime;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    tid = column.contains("tid") ? atol(column["tid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    parent = column.contains("parent") ? atol(column["parent"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    cid = column.contains("cid") ? atol(column["cid"].get<std::string>().c_str()) : 0;
                                    exit_code = column.contains("exit_code") ? column["exit_code"] : "";
                                    probe_error = column.contains("probe_error") ? atol(column["probe_error"].get<std::string>().c_str()) : 0;
                                    syscall = column.contains("syscall") ? column["syscall"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    cwd = column.contains("cwd") ? column["cwd"] : "";
                                    cmdline = column.contains("cmdline") ? column["cmdline"] : "";
                                    duration = column.contains("duration") ? atol(column["duration"].get<std::string>().c_str()) : 0;
                                    json_cmdline = column.contains("json_cmdline") ? column["json_cmdline"] : "";
                                    ntime = column.contains("ntime") ? column["ntime"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    eid = column.contains("eid") ? atol(column["eid"].get<std::string>().c_str()) : 0;
                                    md5 = column.contains("md5") ? column["md5"] : "";
                                    sha1 = column.contains("sha1") ? column["sha1"] : "";
                                    sha256 = column.contains("sha256") ? column["sha256"] : "";
                                    is_container_process = column.contains("is_container_process") ? atol(column["is_container_process"].get<std::string>().c_str()) : 0;
                                    container_age = column.contains("container_age") ? atol(column["container_age"].get<std::string>().c_str()) : 0;
                                    container_name = column.contains("container_name") ? column["container_name"] : "";
                                    // uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;
                                    long _ntime = ntime.empty() ? 0 : stol(ntime);
                                    uptime = _ntime / 1000000000;
                                    pending_batches.bpf_process_events.push_row(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid,
                                                              exit_code, probe_error, syscall, path, cwd, cmdline, duration, json_cmdline, ntime, time, eid, md5, sha1, sha256, is_container_process, container_age, container_name, uptime);
                                    
                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            // Create flattened JSON with proper field names for EventProcessor
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = parent;
                                            kafka_event["tid"] = tid;
                                            kafka_event["uid"] = uid;
                                            kafka_event["gid"] = gid;
                                            kafka_event["cid"] = cid;
                                            kafka_event["exit_code"] = exit_code;
                                            kafka_event["probe_error"] = probe_error;
                                            kafka_event["syscall"] = syscall;
                                            kafka_event["path"] = path;
                                            kafka_event["cwd"] = cwd;
                                            kafka_event["cmdline"] = cmdline;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["time"] = time;
                                            kafka_event["md5"] = md5;
                                            kafka_event["sha1"] = sha1;
                                            kafka_event["sha256"] = sha256;
                                            kafka_event["event_type"] = "bpf_process";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName 
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }
                                    
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "bpf_socket_events")
                                {

                                    std::string exit_code, syscall, path, fd, local_address, remote_address, cwd, cmdline, ntime;
                                    long unixTime, tid, pid, parent, uid, gid, cid, probe_error, family, type, protocol, local_port, remote_port, duration, time, eid, uptime;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    tid = column.contains("tid") ? atol(column["tid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    parent = column.contains("parent") ? atol(column["parent"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    cid = column.contains("cid") ? atol(column["cid"].get<std::string>().c_str()) : 0;
                                    exit_code = column.contains("exit_code") ? column["exit_code"] : "";
                                    probe_error = column.contains("probe_error") ? atol(column["probe_error"].get<std::string>().c_str()) : 0;
                                    syscall = column.contains("syscall") ? column["syscall"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    fd = column.contains("fd") ? column["fd"] : "";
                                    family = column.contains("family") ? atol(column["family"].get<std::string>().c_str()) : 0;
                                    type = column.contains("type") ? atol(column["type"].get<std::string>().c_str()) : 0;
                                    protocol = column.contains("protocol") ? atol(column["protocol"].get<std::string>().c_str()) : 0;
                                    local_address = column.contains("local_address") ? column["local_address"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    local_port = column.contains("local_port") ? atol(column["local_port"].get<std::string>().c_str()) : 0;
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    duration = column.contains("duration") ? atol(column["duration"].get<std::string>().c_str()) : 0;
                                    ntime = column.contains("ntime") ? column["ntime"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    eid = column.contains("eid") ? atol(column["eid"].get<std::string>().c_str()) : 0;
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;

                                    pending_batches.bpf_socket_events.push_row(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid,
                                                              exit_code, probe_error, syscall, path, fd, family, type, protocol, local_address, remote_address, local_port, remote_port, duration, ntime, time, eid, uptime);
                                    
                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            // Create flattened JSON with proper field names for EventProcessor
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = parent;
                                            kafka_event["tid"] = tid;
                                            kafka_event["uid"] = uid;
                                            kafka_event["gid"] = gid;
                                            kafka_event["cid"] = cid;
                                            kafka_event["path"] = path;
                                            kafka_event["syscall"] = syscall;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["local_address"] = local_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["local_port"] = local_port;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["time"] = time;
                                            kafka_event["event_type"] = "bpf_socket";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName 
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }
                                    
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "bpf_file_events")
                                {

                                    std::string exit_code, syscall, path, file_path, ntime, flags;
                                    long tid, pid, parent, uid, gid, cid, probe_error, duration, time, uptime, unixTime;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    tid = column.contains("tid") ? atol(column["tid"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    parent = column.contains("parent") ? atol(column["parent"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    cid = column.contains("cid") ? atol(column["cid"].get<std::string>().c_str()) : 0;
                                    exit_code = column.contains("exit_code") ? column["exit_code"] : "";
                                    probe_error = column.contains("probe_error") ? atol(column["probe_error"].get<std::string>().c_str()) : 0;
                                    syscall = column.contains("syscall") ? column["syscall"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    duration = column.contains("duration") ? atol(column["duration"].get<std::string>().c_str()) : 0;
                                    ntime = column.contains("ntime") ? column["ntime"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    file_path = column.contains("file_path") ? column["file_path"] : "";
                                    uptime = column.contains("uptime") ? atol(column["uptime"].get<std::string>().c_str()) : 0;
                                    flags = column.contains("flags") ? column["flags"] : "";

                                    pending_batches.bpf_file_events.push_row(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, probe_error, syscall, path, file_path, flags, ntime, duration, time, uptime);
                                    
                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            // Create flattened JSON with proper field names for EventProcessor
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = parent;
                                            kafka_event["tid"] = tid;
                                            kafka_event["uid"] = uid;
                                            kafka_event["gid"] = gid;
                                            kafka_event["cid"] = cid;
                                            kafka_event["path"] = path;
                                            kafka_event["file_path"] = file_path;
                                            kafka_event["syscall"] = syscall;
                                            kafka_event["flags"] = flags;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["time"] = time;
                                            kafka_event["event_type"] = "bpf_file";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName 
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }
                                    
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "docker_events")
                                {

                                    std::string action, from, status, scope, time, type, path, cmdline, pid, container_id, container_image, container_name,
                                        privileged, added_capabilities, dropped_capabilities, port_binding;

                                    auto column = entry["columns"];
                                    action = column.contains("action") ? column["action"] : "";
                                    from = column.contains("from") ? column["from"] : "";
                                    status = column.contains("status") ? column["status"] : "";
                                    scope = column.contains("scope") ? column["scope"] : "";
                                    time = column.contains("time") ? column["time"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    cmdline = column.contains("cmdline") ? column["cmdline"] : "";
                                    pid = column.contains("pid") ? column["pid"] : "";
                                    container_id = column.contains("container_id") ? column["container_id"] : "";
                                    container_image = column.contains("container_image") ? column["container_image"] : "";
                                    container_name = column.contains("container_name") ? column["container_name"] : "";
                                    privileged = column.contains("privileged") ? column["privileged"] : "";
                                    added_capabilities = column.contains("added_capabilities") ? column["added_capabilities"] : "";
                                    dropped_capabilities = column.contains("dropped_capabilities") ? column["dropped_capabilities"] : "";
                                    port_binding = column.contains("port_binding") ? column["port_binding"] : "";

                                    pending_batches.docker_events.push_row(host_identifier, hostname, action, from, status, scope, time, type, path, cmdline, pid, container_id, container_image, container_name, privileged, added_capabilities, dropped_capabilities, port_binding);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "interface_addresses")
                                {

                                    std::string interface, address, mask, broadcast, point_to_point, type, friendly_name;
                                    long unixTime;

                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    interface = column.contains("interface") ? column["interface"] : "";
                                    address = column.contains("address") ? column["address"] : "";
                                    mask = column.contains("mask") ? column["mask"] : "";
                                    broadcast = column.contains("broadcast") ? column["broadcast"] : "";
                                    point_to_point = column.contains("point_to_point") ? column["point_to_point"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    friendly_name = column.contains("friendly_name") ? column["friendly_name"] : "";

                                    pending_batches.interface_addresses.push_row(host_identifier, unixTime, interface, address, mask, broadcast, point_to_point, type, friendly_name);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_process_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, ppid;
                                    std::string cmdline, path, action, eid, process_guid, parent_process_guid, parent_path, owner_uid, utc_time, sha256;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    cmdline = column.contains("cmdline") ? column["cmdline"] : "";
                                    ppid = column.contains("parent_pid") ? atol(column["parent_pid"].get<std::string>().c_str()) : 0;
                                    parent_process_guid = column.contains("parent_process_guid") ? column["parent_process_guid"] : "";
                                    parent_path = column.contains("parent_path") ? column["parent_path"] : "";
                                    owner_uid = column.contains("owner_uid") ? column["owner_uid"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;
                                    sha256 = column.contains("sha256") ? column["sha256"] : "";

                                    pending_batches.win_process_events.push_row(host_identifier, hostname, unixTime, action, eid, pid, process_guid, path, cmdline, ppid,
                                                              parent_process_guid, parent_path, owner_uid, time, uptime, utc_time, eventid, sha256);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = ppid;
                                            kafka_event["path"] = path;
                                            kafka_event["cmdline"] = cmdline;
                                            kafka_event["process_guid"] = process_guid;
                                            kafka_event["parent_process_guid"] = parent_process_guid;
                                            kafka_event["parent_path"] = parent_path;
                                            kafka_event["sha256"] = sha256;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_process";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_socket_events")
                                {
                                    long unixTime, time, eventid, pid, ppid, protocol, local_port, remote_port, uptime;
                                    std::string action, eid, process_guid, process_name, family, local_address, remote_address, utc_time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    ppid = column.contains("parent_pid") ? atol(column["parent_pid"].get<std::string>().c_str()) : 0;
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    process_name = column.contains("process_name") ? column["process_name"] : "";
                                    family = column.contains("family") ? column["family"] : "";
                                    protocol = column.contains("protocol") ? atol(column["protocol"].get<std::string>().c_str()) : 0;
                                    local_address = column.contains("local_address") ? column["local_address"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    local_port = column.contains("local_port") ? atol(column["local_port"].get<std::string>().c_str()) : 0;
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    pending_batches.win_socket_events.push_row(host_identifier, hostname, unixTime, action, eid, time, utc_time, pid, process_guid, process_name, family, protocol,
                                                              local_address, remote_address, local_port, remote_port, eventid, ppid, uptime);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = ppid;
                                            kafka_event["process_name"] = process_name;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["local_address"] = local_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["local_port"] = local_port;
                                            kafka_event["protocol"] = protocol;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_socket";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_file_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, ppid, hashed;
                                    std::string action, eid, process_guid, process_name, utc_time, target_path, md5, sha256, uid, pe_file;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    target_path = column.contains("target_path") ? column["target_path"] : "";
                                    md5 = column.contains("md5") ? column["md5"] : "";
                                    sha256 = column.contains("sha256") ? column["sha256"] : "";
                                    hashed = column.contains("hashed") ? atol(column["hashed"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? column["uid"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    pe_file = column.contains("pe_file") ? column["pe_file"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    ppid = column.contains("parent_pid") ? atol(column["parent_pid"].get<std::string>().c_str()) : 0;
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    process_name = column.contains("process_name") ? column["process_name"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    pending_batches.win_file_events.push_row(host_identifier, hostname, unixTime, action, eid, target_path, md5, sha256, hashed,
                                                              uid, utc_time, time, pe_file, pid, process_guid, process_name, eventid, ppid, uptime);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["ppid"] = ppid;
                                            kafka_event["process_name"] = process_name;
                                            kafka_event["target_path"] = target_path;
                                            kafka_event["md5"] = md5;
                                            kafka_event["sha256"] = sha256;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_file";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_dns_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, request_type, request_class, remote_port;
                                    std::string event_type, action, eid, domain_name, remote_address, utc_time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    event_type = column.contains("event_type") ? column["event_type"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    domain_name = column.contains("domain_name") ? column["domain_name"] : "";
                                    request_type = column.contains("request_type") ? atol(column["request_type"].get<std::string>().c_str()) : 0;
                                    request_class = column.contains("request_class") ? atol(column["request_class"].get<std::string>().c_str()) : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("win_dns_events", host_identifier, hostname, unixTime, event_type, action, eid, domain_name, request_type, request_class, pid,
                                                              remote_address, remote_port, time, utc_time, eventid, uptime);

                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["domain_name"] = domain_name;
                                            kafka_event["request_type"] = request_type;
                                            kafka_event["request_class"] = request_class;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_dns";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_dns_response_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, request_type, request_class, remote_port;
                                    std::string event_type, action, eid, domain_name, resolved_ip, remote_address, utc_time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    event_type = column.contains("event_type") ? column["event_type"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    domain_name = column.contains("domain_name") ? column["domain_name"] : "";
                                    request_type = column.contains("request_type") ? atol(column["request_type"].get<std::string>().c_str()) : 0;
                                    request_class = column.contains("request_class") ? atol(column["request_class"].get<std::string>().c_str()) : 0;
                                    resolved_ip = column.contains("resolved_ip") ? column["resolved_ip"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("win_dns_response_events", host_identifier, hostname, unixTime, event_type, action, eid, domain_name, request_type, request_class, resolved_ip, pid,
                                                              remote_address, remote_port, time, utc_time, eventid, uptime);

                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["domain_name"] = domain_name;
                                            kafka_event["resolved_ip"] = resolved_ip;
                                            kafka_event["request_type"] = request_type;
                                            kafka_event["request_class"] = request_class;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_dns_response";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_ssl_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, remote_port;
                                    std::string event_type, action, eid, subject_name, issuer_name, serial_number, dns_names, server_name, ja3_md5, ja3s_md5, process_guid, process_name, remote_address, utc_time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    event_type = column.contains("event_type") ? column["event_type"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    subject_name = column.contains("subject_name") ? column["subject_name"] : "";
                                    issuer_name = column.contains("issuer_name") ? column["issuer_name"] : "";
                                    serial_number = column.contains("serial_number") ? column["serial_number"] : "";
                                    dns_names = column.contains("dns_names") ? column["dns_names"] : "";
                                    server_name = column.contains("server_name") ? column["server_name"] : "";
                                    ja3_md5 = column.contains("ja3_md5") ? column["ja3_md5"] : "";
                                    ja3s_md5 = column.contains("ja3s_md5") ? column["ja3s_md5"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    process_name = column.contains("process_name") ? column["process_name"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("win_ssl_events", host_identifier, hostname, unixTime, event_type, action, eid, subject_name, issuer_name, serial_number, dns_names, server_name, ja3_md5, ja3s_md5, pid,
                                                              process_guid, process_name, remote_address, remote_port, time, utc_time, eventid, uptime);

                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["process_guid"] = process_guid;
                                            kafka_event["process_name"] = process_name;
                                            kafka_event["dns_names"] = dns_names;
                                            kafka_event["server_name"] = server_name;
                                            kafka_event["subject_name"] = subject_name;
                                            kafka_event["ja3_md5"] = ja3_md5;
                                            kafka_event["ja3s_md5"] = ja3s_md5;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_ssl";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_http_events")
                                {
                                    long unixTime, time, uptime, eventid, pid, remote_port;
                                    std::string event_type, action, eid, url, process_guid, process_name, remote_address, utc_time;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;
                                    event_type = column.contains("event_type") ? column["event_type"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    url = column.contains("url") ? column["url"] : "";
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    process_name = column.contains("process_name") ? column["process_name"] : "";
                                    remote_address = column.contains("remote_address") ? column["remote_address"] : "";
                                    remote_port = column.contains("remote_port") ? atol(column["remote_port"].get<std::string>().c_str()) : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("win_http_events", host_identifier, hostname, unixTime, event_type, action, eid, url, pid, process_guid, process_name,
                                                              remote_address, remote_port, time, utc_time, eventid, uptime);

                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["process_guid"] = process_guid;
                                            kafka_event["process_name"] = process_name;
                                            kafka_event["url"] = url;
                                            kafka_event["remote_address"] = remote_address;
                                            kafka_event["remote_port"] = remote_port;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_http";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "chrome_extensions")
                                {
                                    long unixTime, uid, persistent, referenced, install_timestamp;
                                    std::string browser_type, name, profile, profile_path, referenced_identifier, identifier, version, description, default_locale, current_locale, update_url, author, path, permissions, optional_permissions, manifest_hash, from_webstore, state, install_time, ext_key;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    browser_type = column.contains("browser_type") ? column["browser_type"] : "";
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    profile = column.contains("profile") ? column["profile"] : "";
                                    profile_path = column.contains("profile_path") ? column["profile_path"] : "";
                                    referenced_identifier = column.contains("referenced_identifier") ? column["referenced_identifier"] : "";
                                    identifier = column.contains("identifier") ? column["identifier"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    description = column.contains("description") ? column["description"] : "";
                                    default_locale = column.contains("default_locale") ? column["default_locale"] : "";
                                    current_locale = column.contains("current_locale") ? column["current_locale"] : "";
                                    update_url = column.contains("update_url") ? column["update_url"] : "";
                                    author = column.contains("author") ? column["author"] : "";
                                    persistent = column.contains("persistent") ? atol(column["persistent"].get<std::string>().c_str()) : 0;
                                    path = column.contains("path") ? column["path"] : "";
                                    permissions = column.contains("permissions") ? column["permissions"].get<std::string>() : "";
                                    optional_permissions = column.contains("optional_permissions") ? column["optional_permissions"] : "";
                                    manifest_hash = column.contains("manifest_hash") ? column["manifest_hash"] : "";
                                    referenced = column.contains("referenced") ? atol(column["referenced"].get<std::string>().c_str()) : 0;
                                    from_webstore = column.contains("from_webstore") ? column["from_webstore"] : "";
                                    state = column.contains("state") ? column["state"] : "";
                                    install_time = column.contains("install_time") ? column["install_time"] : "";
                                    install_timestamp = column.contains("install_timestamp") ? atol(column["install_timestamp"].get<std::string>().c_str()) : 0;
                                    ext_key = column.contains("key") ? column["key"] : "";

                                    transaction->exec_prepared("chrome_extensions", host_identifier, hostname, unixTime, browser_type, uid, name, profile, profile_path, referenced_identifier, identifier, version, description, default_locale, current_locale, update_url, author, persistent, path, permissions, optional_permissions, manifest_hash, referenced, from_webstore, state, install_time, install_timestamp, ext_key);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "osquery_schedule")
                                {
                                    std::string last_executed, denylisted, output_size, wall_time, wall_time_ms, last_wall_time_ms, user_time, last_user_time, system_time, last_system_time, average_memory, last_memory;
                                    std::string name, query, interval, executions;

                                    auto column = entry["columns"];
                                    interval = column.contains("interval") ? column["interval"] : "";
                                    executions = column.contains("executions") ? column["executions"] : "";
                                    last_executed = column.contains("last_executed") ? column["last_executed"] : "";
                                    denylisted = column.contains("denylisted") ? column["denylisted"] : "";
                                    output_size = column.contains("output_size") ? column["output_size"] : "";
                                    wall_time = column.contains("wall_time") ? column["wall_time"] : "";
                                    wall_time_ms = column.contains("wall_time_ms") ? column["wall_time_ms"] : "";
                                    last_wall_time_ms = column.contains("last_wall_time_ms") ? column["last_wall_time_ms"] : "";
                                    user_time = column.contains("user_time") ? column["user_time"] : "";
                                    last_user_time = column.contains("last_user_time") ? column["last_user_time"] : "";
                                    system_time = column.contains("system_time") ? column["system_time"] : "";
                                    last_system_time = column.contains("last_system_time") ? column["last_system_time"] : "";
                                    average_memory = column.contains("average_memory") ? column["average_memory"] : "";
                                    last_memory = column.contains("last_memory") ? column["last_memory"] : "";
                                    name = column.contains("name") ? column["name"] : "";
                                    query = column.contains("query") ? column["query"] : "";

                                    transaction->exec_prepared("osquery_schedule", host_identifier, hostname, name, query, interval, executions, last_executed, denylisted, output_size, wall_time, wall_time_ms, last_wall_time_ms, user_time, last_user_time, system_time, last_system_time, average_memory, last_memory);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "etc_hosts")
                                {
                                    long unixTime;
                                    int pid_with_namespace;
                                    std::string hostnames, address;
                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    address = column.contains("address") ? column["address"] : "";
                                    hostnames = column.contains("hostnames") ? column["hostnames"] : "";
                                    pid_with_namespace = entry.contains("pid_with_namespace") ? entry["pid_with_namespace"].get<int>() : 0;

                                    transaction->exec_prepared("etc_hosts", host_identifier, hostname, unixTime, address, hostnames, pid_with_namespace);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "uptime")
                                {
                                    long unixTime, total_seconds;
                                    int days, hours, minutes, seconds;
                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    days = column.contains("days") ? atol(column["days"].get<std::string>().c_str()) : 0;
                                    // days = column.contains("days") ? column["days"].get<long>() : 0;
                                    hours = column.contains("hours") ? atol(column["hours"].get<std::string>().c_str()) : 0;
                                    minutes = column.contains("minutes") ? atol(column["minutes"].get<std::string>().c_str()) : 0;
                                    seconds = column.contains("seconds") ? atol(column["seconds"].get<std::string>().c_str()) : 0;
                                    total_seconds = column.contains("total_seconds") ? atol(column["total_seconds"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("uptime", host_identifier, hostname, unixTime, days, hours, minutes, seconds, total_seconds);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "startup_items")
                                {
                                    long unixTime;
                                    std::string name, path, args, type, source, status, username;
                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    args = column.contains("args") ? column["args"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    source = column.contains("source") ? column["source"] : "";
                                    status = column.contains("status") ? column["status"] : "";
                                    username = column.contains("username") ? column["username"] : "";
                                    transaction->exec_prepared("startup_items", host_identifier, hostname, unixTime, name, path, args, type, source, status, username);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "patches")
                                {
                                    long unixTime;
                                    std::string csname, hotfix_id, caption, description, fix_comments, installed_by, install_date, installed_on;
                                    auto column = entry["columns"];
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    csname = column.contains("csname") ? column["csname"] : "";
                                    hotfix_id = column.contains("hotfix_id") ? column["hotfix_id"] : "";
                                    caption = column.contains("caption") ? column["caption"] : "";
                                    description = column.contains("description") ? column["description"] : "";
                                    fix_comments = column.contains("fix_comments") ? column["fix_comments"] : "";
                                    installed_by = column.contains("installed_by") ? column["installed_by"] : "";
                                    install_date = column.contains("install_date") ? column["install_date"] : "";
                                    installed_on = column.contains("installed_on") ? column["installed_on"] : "";
                                    transaction->exec_prepared("patches", host_identifier, hostname, unixTime, csname, hotfix_id, caption, description, fix_comments, installed_by, install_date, installed_on);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "file")
                                {
                                    long unixTime, uid, inode, gid, device, size, block_size, atime, mtime, ctime, btime, hard_links, symlink, pid_with_namespace;
                                    std::string type, attributes, volume_serial, file_id, file_version, product_version, original_filename, bsd_flags, mount_namespace_id, mode, filename, directory, path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    path = column.contains("path") ? column["path"] : "";
                                    directory = column.contains("directory") ? column["directory"] : "";
                                    filename = column.contains("filename") ? column["filename"] : "";
                                    inode = column.contains("inode") ? atol(column["inode"].get<std::string>().c_str()) : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    mode = column.contains("mode") ? column["mode"] : "";
                                    device = column.contains("device") ? atol(column["device"].get<std::string>().c_str()) : 0;
                                    size = column.contains("size") ? atol(column["size"].get<std::string>().c_str()) : 0;
                                    block_size = column.contains("block_size") ? atol(column["block_size"].get<std::string>().c_str()) : 0;
                                    atime = column.contains("atime") ? atol(column["atime"].get<std::string>().c_str()) : 0;
                                    mtime = column.contains("mtime") ? atol(column["mtime"].get<std::string>().c_str()) : 0;
                                    ctime = column.contains("ctime") ? atol(column["ctime"].get<std::string>().c_str()) : 0;
                                    btime = column.contains("btime") ? atol(column["btime"].get<std::string>().c_str()) : 0;
                                    hard_links = column.contains("hard_links") ? atol(column["hard_links"].get<std::string>().c_str()) : 0;
                                    symlink = column.contains("symlink") ? atol(column["symlink"].get<std::string>().c_str()) : 0;
                                    type = column.contains("type") ? column["type"] : "";
                                    attributes = column.contains("attributes") ? column["attributes"] : "";
                                    volume_serial = column.contains("volume_serial") ? column["volume_serial"] : "";
                                    file_id = column.contains("file_id") ? column["file_id"] : "";
                                    file_version = column.contains("file_version") ? column["file_version"] : "";
                                    product_version = column.contains("product_version") ? column["product_version"] : "";
                                    original_filename = column.contains("original_filename") ? column["original_filename"] : "";
                                    bsd_flags = column.contains("bsd_flags") ? column["bsd_flags"] : "";
                                    pid_with_namespace = column.contains("pid_with_namespace") ? atol(column["pid_with_namespace"].get<std::string>().c_str()) : 0;
                                    mount_namespace_id = column.contains("mount_namespace_id") ? column["mount_namespace_id"] : "";

                                    transaction->exec_prepared("file", host_identifier, hostname, unixTime, path, directory, filename, inode, uid, gid, mode, device, size, block_size, atime, mtime, ctime, btime, hard_links, symlink, type, attributes, volume_serial, file_id, file_version, product_version, original_filename, bsd_flags, pid_with_namespace, mount_namespace_id);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "wmi_cli_event_consumers")
                                {
                                    std::string name, command_line_template, executable_path, class_name, relative_path;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    command_line_template = column.contains("command_line_template") ? column["command_line_template"] : "";
                                    executable_path = column.contains("executable_path") ? column["executable_path"] : "";
                                    class_name = column.contains("class") ? column["class"] : "";
                                    relative_path = column.contains("relative_path") ? column["relative_path"] : "";

                                    transaction->exec_prepared("wmi_cli_event_consumers", host_identifier, hostname, unixTime, name, command_line_template, executable_path, class_name, relative_path);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "processes32")
                                {
                                    int on_disk, threads, nice, virtual_process;
                                    long unixTime, pid, uid, gid, egid, suid, sgid, wired_size, resident_size, total_size, user_time, system_time, disk_bytes_read, disk_bytes_written,
                                        start_time, parent, pgroup, elevated_token, secure_process, elapsed_time, handle_count, percent_processor_time;
                                    std::string name, cmdline, state, cwd, root, protection_type, path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    pid = column.contains("pid") ? atol(column["pid"].get<std::string>().c_str()) : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    cmdline = column.contains("cmdline") ? column["cmdline"] : "";
                                    state = column.contains("state") ? column["state"] : "";
                                    cwd = column.contains("cwd") ? column["cwd"] : "";
                                    root = column.contains("root") ? column["root"] : "";
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    gid = column.contains("gid") ? atol(column["gid"].get<std::string>().c_str()) : 0;
                                    egid = column.contains("egid") ? atol(column["egid"].get<std::string>().c_str()) : 0;
                                    suid = column.contains("suid") ? atol(column["suid"].get<std::string>().c_str()) : 0;
                                    sgid = column.contains("sgid") ? atol(column["sgid"].get<std::string>().c_str()) : 0;
                                    on_disk = column.contains("on_disk") ? atol(column["on_disk"].get<std::string>().c_str()) : 0;
                                    wired_size = column.contains("wired_size") ? atol(column["wired_size"].get<std::string>().c_str()) : 0;
                                    resident_size = column.contains("resident_size") ? atol(column["resident_size"].get<std::string>().c_str()) : 0;
                                    total_size = column.contains("total_size") ? atol(column["total_size"].get<std::string>().c_str()) : 0;
                                    user_time = column.contains("user_time") ? atol(column["user_time"].get<std::string>().c_str()) : 0;
                                    system_time = column.contains("system_time") ? atol(column["system_time"].get<std::string>().c_str()) : 0;
                                    disk_bytes_read = column.contains("disk_bytes_read") ? atol(column["disk_bytes_read"].get<std::string>().c_str()) : 0;
                                    disk_bytes_written = column.contains("disk_bytes_written") ? atol(column["disk_bytes_written"].get<std::string>().c_str()) : 0;
                                    start_time = column.contains("start_time") ? atol(column["start_time"].get<std::string>().c_str()) : 0;
                                    parent = column.contains("parent") ? atol(column["parent"].get<std::string>().c_str()) : 0;
                                    pgroup = column.contains("pgroup") ? atol(column["pgroup"].get<std::string>().c_str()) : 0;
                                    threads = column.contains("threads") ? atol(column["threads"].get<std::string>().c_str()) : 0;
                                    nice = column.contains("nice") ? atol(column["nice"].get<std::string>().c_str()) : 0;
                                    elevated_token = column.contains("elevated_token") ? atol(column["elevated_token"].get<std::string>().c_str()) : 0;
                                    secure_process = column.contains("secure_process") ? atol(column["secure_process"].get<std::string>().c_str()) : 0;
                                    protection_type = column.contains("protection_type") ? column["protection_type"] : "";
                                    virtual_process = column.contains("virtual_process") ? atol(column["virtual_process"].get<std::string>().c_str()) : 0;
                                    elapsed_time = column.contains("elapsed_time") ? atol(column["elapsed_time"].get<std::string>().c_str()) : 0;
                                    handle_count = column.contains("handle_count") ? atol(column["handle_count"].get<std::string>().c_str()) : 0;
                                    percent_processor_time = column.contains("percent_processor_time") ? atol(column["percent_processor_time"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("processes32", host_identifier, hostname, unixTime, pid, name, path, cmdline, state, cwd, root, uid, gid, egid, suid, sgid, on_disk, wired_size,
                                                              resident_size, total_size, user_time, system_time, disk_bytes_read, disk_bytes_written, start_time, parent, pgroup, threads, nice, elevated_token,
                                                              secure_process, protection_type, virtual_process, elapsed_time, handle_count, percent_processor_time);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "programs")
                                {
                                    std::string name, version, install_location, install_source, language, publisher, uninstall_string, install_date, identifying_number;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    install_location = column.contains("install_location") ? column["install_location"] : "";
                                    install_source = column.contains("install_source") ? column["install_source"] : "";
                                    language = column.contains("language") ? column["language"] : "";
                                    publisher = column.contains("publisher") ? column["publisher"] : "";
                                    uninstall_string = column.contains("uninstall_string") ? column["uninstall_string"] : "";
                                    install_date = column.contains("install_date") ? column["install_date"] : "";
                                    identifying_number = column.contains("identifying_number") ? column["identifying_number"] : "";

                                    transaction->exec_prepared("programs", host_identifier, hostname, unixTime, name, version, install_location, install_source, language, publisher, uninstall_string, install_date, identifying_number);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "kernel_info")
                                {
                                    long unixTime;
                                    std::string version, arguments, path, device;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    version = column.contains("version") ? column["version"] : "";
                                    arguments = column.contains("arguments") ? column["arguments"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    device = column.contains("device") ? column["device"] : "";

                                    // Prepared once per connection in fleet_main.cpp; re-preparing here
                                    // polluted pooled connections when an exception skipped the unprepare.
                                    transaction->exec_prepared("update_kernel_to_nodes", version, host_identifier);

                                    transaction->exec_prepared("kernel_info", host_identifier, hostname, unixTime, version, arguments, path, device);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "deb_packages") 
                                {
                                    long unixTime = 0, size = 0;
                                    int pid_with_namespace = 0;
                                    std::string name, major_release_version, sanitized_name, sanitized_version, version, source, arch, revision, status, maintainer, section, priority, admindir, mount_namespace_id;

                                    auto column = entry["columns"];

                                    // Extract values from JSON
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    source = column.contains("source") ? column["source"] : "";
                                    size = column.contains("size") ? atol(column["size"].get<std::string>().c_str()) : 0;
                                    arch = column.contains("arch") ? column["arch"] : "";
                                    revision = column.contains("revision") ? column["revision"] : "";
                                    status = column.contains("status") ? column["status"] : "";
                                    maintainer = column.contains("maintainer") ? column["maintainer"] : "";
                                    section = column.contains("section") ? column["section"] : "";
                                    priority = column.contains("priority") ? column["priority"] : "";
                                    admindir = column.contains("admindir") ? column["admindir"] : "";
                                    pid_with_namespace = column.contains("pid_with_namespace") ? atoi(column["pid_with_namespace"].get<std::string>().c_str()) : 0;
                                    mount_namespace_id = column.contains("mount_namespace_id") ? column["mount_namespace_id"] : "";
                                    major_release_version = column.contains("major_release_version") ? column["major_release_version"] : "";

                                    try {
                                        sanitized_name = sanitize_name(name);
                                        sanitized_version = sanitize_version(version);
                                        // Use a savepoint so a bad row rolls back only itself,
                                        // leaving the outer transaction (and other tables' batched
                                        // events) intact.
                                        pqxx::subtransaction sp(*transaction, "deb_pkg_row");
                                        sp.exec_prepared("deb_packages",
                                                         host_identifier, hostname, unixTime,
                                                         name, version, source, size, arch,
                                                         revision, status, maintainer, section,
                                                         priority, admindir, pid_with_namespace,
                                                         mount_namespace_id, sanitized_name,
                                                         sanitized_version, major_release_version);
                                        sp.commit();
                                        batch_count++;
                                        if (batch_count >= BATCH_SIZE) {
                                            pending_batches.flush_all(*transaction);
                                            transaction->commit();
                                            batch_count = 0;
                                            transaction = std::make_unique<pqxx::work>(*connection);
                                        }
                                    } catch (const std::exception &e) {
                                        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "deb_packages insert error (row skipped): " << e.what();
                                        // savepoint destructor rolls back only this row; outer
                                        // transaction remains valid — no batch_count reset needed.
                                    }
                                }
                                else if (tableName == "rpm_packages")
                                {
                                    long unixTime, size;
                                    int pid_with_namespace, epoch, install_time;
                                    std::string name, version, release, source, sha1, arch, vendor, package_group, mount_namespace_id;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    release = column.contains("release") ? column["release"] : "";
                                    source = column.contains("source") ? column["source"] : "";
                                    size = column.contains("size") ? atol(column["size"].get<std::string>().c_str()) : 0;
                                    sha1 = column.contains("sha1") ? column["sha1"] : "";
                                    arch = column.contains("arch") ? column["arch"] : "";
                                    epoch = column.contains("epoch") ? atoi(column["epoch"].get<std::string>().c_str()) : 0;
                                    install_time = column.contains("install_time") ? atoi(column["install_time"].get<std::string>().c_str()) : 0;
                                    vendor = column.contains("vendor") ? column["vendor"] : "";
                                    package_group = column.contains("package_group") ? column["package_group"] : "";
                                    pid_with_namespace = column.contains("pid_with_namespace") ? atoi(column["pid_with_namespace"].get<std::string>().c_str()) : 0;
                                    mount_namespace_id = column.contains("mount_namespace_id") ? column["mount_namespace_id"] : "";

                                    transaction->exec_prepared("rpm_packages", host_identifier, hostname, unixTime, name, version, release, source, size, sha1, arch, epoch, install_time, vendor, package_group, pid_with_namespace, mount_namespace_id);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "chocolatey_packages")
                                {
                                    long unixTime;
                                    std::string name, version, summary, author, license, path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    summary = column.contains("summary") ? column["summary"] : "";
                                    author = column.contains("author") ? column["author"] : "";
                                    license = column.contains("license") ? column["license"] : "";
                                    path = column.contains("path") ? column["path"] : "";

                                    transaction->exec_prepared("chocolatey_packages", host_identifier, hostname, unixTime, name, version, summary, author, license, path);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "interface_details")
                                {
                                    long unixTime;
                                    int type, mtu, metric, flags, enabled, physical_adapter, speed, dhcp_enabled;
                                    std::string interface, mac, pci_slot, friendly_name, description, manufacturer, connection_id, connection_status, service, dhcp_lease_expires, dhcp_lease_obtained, dhcp_server, dns_domain, dns_domain_suffix_search_order, dns_host_name, dns_server_search_order;
                                    long ipackets, opackets, ibytes, obytes, ierrors, oerrors, idrops, odrops, collisions, last_change, link_speed;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    interface = column.contains("interface") ? column["interface"] : "";
                                    mac = column.contains("mac") ? column["mac"] : "";
                                    type = column.contains("type") ? atoi(column["type"].get<std::string>().c_str()) : 0;
                                    mtu = column.contains("mtu") ? atoi(column["mtu"].get<std::string>().c_str()) : 0;
                                    metric = column.contains("metric") ? atoi(column["metric"].get<std::string>().c_str()) : 0;
                                    flags = column.contains("flags") ? atoi(column["flags"].get<std::string>().c_str()) : 0;
                                    ipackets = column.contains("ipackets") ? atol(column["ipackets"].get<std::string>().c_str()) : 0;
                                    opackets = column.contains("opackets") ? atol(column["opackets"].get<std::string>().c_str()) : 0;
                                    ibytes = column.contains("ibytes") ? atol(column["ibytes"].get<std::string>().c_str()) : 0;
                                    obytes = column.contains("obytes") ? atol(column["obytes"].get<std::string>().c_str()) : 0;
                                    ierrors = column.contains("ierrors") ? atol(column["ierrors"].get<std::string>().c_str()) : 0;
                                    oerrors = column.contains("oerrors") ? atol(column["oerrors"].get<std::string>().c_str()) : 0;
                                    idrops = column.contains("idrops") ? atol(column["idrops"].get<std::string>().c_str()) : 0;
                                    odrops = column.contains("odrops") ? atol(column["odrops"].get<std::string>().c_str()) : 0;
                                    collisions = column.contains("collisions") ? atol(column["collisions"].get<std::string>().c_str()) : 0;
                                    last_change = column.contains("last_change") ? atol(column["last_change"].get<std::string>().c_str()) : 0;
                                    link_speed = column.contains("link_speed") ? atol(column["link_speed"].get<std::string>().c_str()) : 0;
                                    pci_slot = column.contains("pci_slot") ? column["pci_slot"] : "";
                                    friendly_name = column.contains("friendly_name") ? column["friendly_name"] : "";
                                    description = column.contains("description") ? column["description"] : "";
                                    manufacturer = column.contains("manufacturer") ? column["manufacturer"] : "";
                                    connection_id = column.contains("connection_id") ? column["connection_id"] : "";
                                    connection_status = column.contains("connection_status") ? column["connection_status"] : "";
                                    enabled = column.contains("enabled") ? atoi(column["enabled"].get<std::string>().c_str()) : 0;
                                    physical_adapter = column.contains("physical_adapter") ? atoi(column["physical_adapter"].get<std::string>().c_str()) : 0;
                                    speed = column.contains("speed") ? atoi(column["speed"].get<std::string>().c_str()) : 0;
                                    service = column.contains("service") ? column["service"] : "";
                                    dhcp_enabled = column.contains("dhcp_enabled") ? atoi(column["dhcp_enabled"].get<std::string>().c_str()) : 0;
                                    dhcp_lease_expires = column.contains("dhcp_lease_expires") ? column["dhcp_lease_expires"] : "";
                                    dhcp_lease_obtained = column.contains("dhcp_lease_obtained") ? column["dhcp_lease_obtained"] : "";
                                    dhcp_server = column.contains("dhcp_server") ? column["dhcp_server"] : "";
                                    dns_domain = column.contains("dns_domain") ? column["dns_domain"] : "";
                                    dns_domain_suffix_search_order = column.contains("dns_domain_suffix_search_order") ? column["dns_domain_suffix_search_order"] : "";
                                    dns_host_name = column.contains("dns_host_name") ? column["dns_host_name"] : "";
                                    dns_server_search_order = column.contains("dns_server_search_order") ? column["dns_server_search_order"] : "";

                                    transaction->exec_prepared("interface_details", host_identifier, hostname, unixTime, interface, mac, type, mtu, metric, flags, ipackets, opackets, ibytes, obytes, ierrors, oerrors, idrops, odrops, collisions, last_change, link_speed, pci_slot, friendly_name, description, manufacturer, connection_id, connection_status, enabled, physical_adapter, speed, service, dhcp_enabled, dhcp_lease_expires, dhcp_lease_obtained, dhcp_server, dns_domain, dns_domain_suffix_search_order, dns_host_name, dns_server_search_order);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "ie_extensions")
                                {
                                    long unixTime;
                                    std::string name, registry_path, version, path;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    name = column.contains("name") ? column["name"] : "";
                                    registry_path = column.contains("registry_path") ? column["registry_path"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    path = column.contains("path") ? column["path"] : "";

                                    transaction->exec_prepared("ie_extensions", host_identifier, hostname, unixTime, name, registry_path, version, path);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "firefox_addons")
                                {
                                    long unixTime, uid;
                                    std::string name, identifier, creator, type, version, description, source_url, location, path;
                                    int visible, active, disabled, autoupdate;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    uid = column.contains("uid") ? atol(column["uid"].get<std::string>().c_str()) : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    identifier = column.contains("identifier") ? column["identifier"] : "";
                                    creator = column.contains("creator") ? column["creator"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    description = column.contains("description") ? column["description"] : "";
                                    source_url = column.contains("source_url") ? column["source_url"] : "";
                                    visible = column.contains("visible") ? atoi(column["visible"].get<std::string>().c_str()) : 0;
                                    active = column.contains("active") ? atoi(column["active"].get<std::string>().c_str()) : 0;
                                    disabled = column.contains("disabled") ? atoi(column["disabled"].get<std::string>().c_str()) : 0;
                                    autoupdate = column.contains("autoupdate") ? atoi(column["autoupdate"].get<std::string>().c_str()) : 0;
                                    location = column.contains("location") ? column["location"] : "";
                                    path = column.contains("path") ? column["path"] : "";

                                    transaction->exec_prepared("firefox_addons", host_identifier, hostname, unixTime, uid, name, identifier, creator, type, version, description, source_url, visible, active, disabled, autoupdate, location, path);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "npm_packages")
                                {
                                    long unixTime;
                                    std::string name, version, description, author, license, homepage, path, directory, mount_namespace_id;
                                    int pid_with_namespace;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    author = column.contains("author") ? column["author"] : "";
                                    license = column.contains("license") ? column["license"] : "";
                                    homepage = column.contains("homepage") ? column["homepage"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    directory = column.contains("directory") ? column["directory"] : "";
                                    pid_with_namespace = column.contains("pid_with_namespace") ? atoi(column["pid_with_namespace"].get<std::string>().c_str()) : 0;
                                    mount_namespace_id = column.contains("mount_namespace_id") ? column["mount_namespace_id"] : "";

                                    transaction->exec_prepared("npm_packages", host_identifier, hostname, unixTime, name, version, description, author, license, homepage, path, directory, pid_with_namespace, mount_namespace_id);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "portage_packages")
                                {
                                    long unixTime, build_time, eapi, size;
                                    std::string package, version, slot, repository;
                                    int world;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;

                                    package = column.contains("package") ? column["package"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    slot = column.contains("slot") ? column["slot"] : "";
                                    build_time = column.contains("build_time") ? atol(column["build_time"].get<std::string>().c_str()) : 0;
                                    repository = column.contains("repository") ? column["repository"] : "";
                                    eapi = column.contains("eapi") ? atol(column["eapi"].get<std::string>().c_str()) : 0;
                                    size = column.contains("size") ? atol(column["size"].get<std::string>().c_str()) : 0;
                                    world = column.contains("world") ? atoi(column["world"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("portage_packages", host_identifier, hostname, unixTime, package, version, slot, build_time, repository, eapi, size, world);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "vajra_winprograms")
                                {
                                    std::string name, version, install_location, publisher;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    install_location = column.contains("install_location") ? column["install_location"] : "";
                                    publisher = column.contains("publisher") ? column["publisher"] : "";

                                    transaction->exec_prepared("vajra_winprograms", host_identifier, hostname, unixTime, name, version, install_location, publisher);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "windows_eventlog")
                                {
                                    std::string channel, datetime, provider_name, provider_guid, computer_name, keywords, data, time_range, timestamp, xpath;
                                    int task, level, eventid, pid, tid;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    channel = column.contains("channel") ? column["channel"] : "";
                                    datetime = column.contains("datetime") ? column["datetime"] : "";
                                    task = column.contains("task") ? atoi(column["task"].get<std::string>().c_str()) : 0;
                                    level = column.contains("level") ? atoi(column["level"].get<std::string>().c_str()) : 0;
                                    provider_name = column.contains("provider_name") ? column["provider_name"] : "";
                                    provider_guid = column.contains("provider_guid") ? column["provider_guid"] : "";
                                    computer_name = column.contains("computer_name") ? column["computer_name"] : "";
                                    eventid = column.contains("eventid") ? atoi(column["eventid"].get<std::string>().c_str()) : 0;
                                    keywords = column.contains("keywords") ? column["keywords"] : "";
                                    data = column.contains("data") ? column["data"] : "";
                                    pid = column.contains("pid") ? atoi(column["pid"].get<std::string>().c_str()) : 0;
                                    tid = column.contains("tid") ? atoi(column["tid"].get<std::string>().c_str()) : 0;
                                    time_range = column.contains("time_range") ? column["time_range"] : "";
                                    timestamp = column.contains("timestamp") ? column["timestamp"] : "";
                                    xpath = column.contains("xpath") ? column["xpath"] : "";

                                    transaction->exec_prepared("windows_eventlog", host_identifier, hostname, unixTime, channel, datetime, task, level, provider_name, provider_guid, computer_name, eventid, keywords, data, pid, tid, time_range, timestamp, xpath);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "registry")
                                {
                                    std::string key, path, name, type, data;
                                    long unixTime;
                                    long long mtime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    key = column.contains("key") ? column["key"] : "";
                                    path = column.contains("path") ? column["path"] : "";
                                    name = column.contains("name") ? column["name"] : "";
                                    type = column.contains("type") ? column["type"] : "";
                                    data = column.contains("data") ? column["data"] : "";
                                    mtime = column.contains("mtime") ? atol(column["mtime"].get<std::string>().c_str()) : 0;

                                    transaction->exec_prepared("registry", host_identifier, hostname, unixTime, key, path, name, type, data, mtime);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "etc_services")
                                {
                                    std::string name, protocol, aliases, comment;
                                    long unixTime;
                                    int port;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    port = column.contains("port") ? atoi(column["port"].get<std::string>().c_str()) : 0;
                                    protocol = column.contains("protocol") ? column["protocol"] : "";
                                    aliases = column.contains("aliases") ? column["aliases"] : "";
                                    comment = column.contains("comment") ? column["comment"] : "";

                                    transaction->exec_prepared("etc_services", host_identifier, hostname, unixTime, name, port, protocol, aliases, comment);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_registry_events")
                                {
                                    std::string action, eid, process_guid, process_name, target_name, target_new_name, value_type, value_data, owner_uid, utc_time;
                                    long unixTime, time, pid, eventid;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time    = column.contains("time")    ? atol(column["time"].get<std::string>().c_str())    : 0;
                                    pid     = column.contains("pid")     ? atol(column["pid"].get<std::string>().c_str())     : 0;
                                    eventid = column.contains("eventid") ? atol(column["eventid"].get<std::string>().c_str()) : 0;

                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    process_name = column.contains("process_name") ? column["process_name"] : "";
                                    target_name = column.contains("target_name") ? column["target_name"] : "";
                                    target_new_name = column.contains("target_new_name") ? column["target_new_name"] : "";
                                    value_type = column.contains("value_type") ? column["value_type"] : "";
                                    value_data = column.contains("value_data") ? column["value_data"] : "";
                                    owner_uid = column.contains("owner_uid") ? column["owner_uid"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";

                                    transaction->exec_prepared("win_registry_events", host_identifier, hostname, unixTime, action, eid, process_guid, process_name, target_name, target_new_name, value_type, value_data, owner_uid, utc_time, time, pid, eventid);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["process_name"] = process_name;
                                            kafka_event["target_name"] = target_name;
                                            kafka_event["target_new_name"] = target_new_name;
                                            kafka_event["value_type"] = value_type;
                                            kafka_event["value_data"] = value_data;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_registry";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_image_load_events")
                                {
                                    std::string action, eid, process_guid, image_path, md5, uid, utc_time, sign_info, trust_info, cert_type, version, pubkey, pubkey_length, pubkey_signhash_algo, issuer_name, subject_name, serial_number, signature_algo, subject_dn, issuer_dn;
                                    long unixTime, time, pid, num_of_certs, uptime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    pid  = column.contains("pid")  ? atol(column["pid"].get<std::string>().c_str())  : 0;
                                    num_of_certs = column.contains("num_of_certs") ? atol(column["num_of_certs"].get<std::string>().c_str()) : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;

                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    image_path = column.contains("image_path") ? column["image_path"] : "";
                                    md5 = column.contains("md5") ? column["md5"] : "";
                                    uid = column.contains("uid") ? column["uid"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";
                                    sign_info = column.contains("sign_info") ? column["sign_info"] : "";
                                    trust_info = column.contains("trust_info") ? column["trust_info"] : "";
                                    cert_type = column.contains("cert_type") ? column["cert_type"] : "";
                                    version = column.contains("version") ? column["version"] : "";
                                    pubkey = column.contains("pubkey") ? column["pubkey"] : "";
                                    pubkey_length = column.contains("pubkey_length") ? column["pubkey_length"] : "";
                                    pubkey_signhash_algo = column.contains("pubkey_signhash_algo") ? column["pubkey_signhash_algo"] : "";
                                    issuer_name = column.contains("issuer_name") ? column["issuer_name"] : "";
                                    subject_name = column.contains("subject_name") ? column["subject_name"] : "";
                                    serial_number = column.contains("serial_number") ? column["serial_number"] : "";
                                    signature_algo = column.contains("signature_algo") ? column["signature_algo"] : "";
                                    subject_dn = column.contains("subject_dn") ? column["subject_dn"] : "";
                                    issuer_dn = column.contains("issuer_dn") ? column["issuer_dn"] : "";

                                    transaction->exec_prepared("win_image_load_events", host_identifier, hostname, unixTime, action, eid, pid, process_guid, image_path, md5, uid, time, utc_time, sign_info, trust_info, num_of_certs, cert_type, version, pubkey, pubkey_length, pubkey_signhash_algo, issuer_name, subject_name, serial_number, signature_algo, subject_dn, issuer_dn, uptime);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["pid"] = pid;
                                            kafka_event["process_guid"] = process_guid;
                                            kafka_event["image_path"] = image_path;
                                            kafka_event["md5"] = md5;
                                            kafka_event["sign_info"] = sign_info;
                                            kafka_event["trust_info"] = trust_info;
                                            kafka_event["subject_name"] = subject_name;
                                            kafka_event["issuer_name"] = issuer_name;
                                            kafka_event["signature_algo"] = signature_algo;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_image_load";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_image_load_process_map")
                                {
                                    // DB-only (no Kafka publish): this is a pid->loaded-image lookup
                                    // table, not an "event" the rule engine evaluates -- Sigma's
                                    // image_load category maps to win_image_load_events above. Also
                                    // unreachable in practice today since the existing seeded
                                    // 'win_config' filter for this table excludes every row
                                    // (image_path exclude: ["*"]) -- kept ready in case that filter
                                    // is deliberately changed later.
                                    std::string process_guid, image_size, image_path, md5, image_memory_mode, image_base, utc_time;
                                    long unixTime, time, pid, uptime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    pid  = column.contains("pid")  ? atol(column["pid"].get<std::string>().c_str())  : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;

                                    process_guid = column.contains("process_guid") ? column["process_guid"] : "";
                                    image_size = column.contains("image_size") ? column["image_size"] : "";
                                    image_path = column.contains("image_path") ? column["image_path"] : "";
                                    md5 = column.contains("md5") ? column["md5"] : "";
                                    image_memory_mode = column.contains("image_memory_mode") ? column["image_memory_mode"] : "";
                                    image_base = column.contains("image_base") ? column["image_base"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";

                                    transaction->exec_prepared("win_image_load_process_map", host_identifier, hostname, unixTime, pid, process_guid, image_size, image_path, md5, image_memory_mode, image_base, time, utc_time, uptime);

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_process_open_events")
                                {
                                    std::string action, eid, src_process_guid, target_process_guid, src_path, target_path, granted_access, granted_access_value, owner_uid, utc_time;
                                    long unixTime, time, src_pid, target_pid, uptime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    src_pid = column.contains("src_pid") ? atol(column["src_pid"].get<std::string>().c_str()) : 0;
                                    target_pid = column.contains("target_pid") ? atol(column["target_pid"].get<std::string>().c_str()) : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;

                                    action = column.contains("action") ? column["action"] : "";
                                    eid = column.contains("eid") ? column["eid"] : "";
                                    src_process_guid = column.contains("src_process_guid") ? column["src_process_guid"] : "";
                                    target_process_guid = column.contains("target_process_guid") ? column["target_process_guid"] : "";
                                    src_path = column.contains("src_path") ? column["src_path"] : "";
                                    target_path = column.contains("target_path") ? column["target_path"] : "";
                                    granted_access = column.contains("granted_access") ? column["granted_access"] : "";
                                    granted_access_value = column.contains("granted_access_value") ? column["granted_access_value"] : "";
                                    owner_uid = column.contains("owner_uid") ? column["owner_uid"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";

                                    transaction->exec_prepared("win_process_open_events", host_identifier, hostname, unixTime, action, eid, src_pid, src_process_guid, target_pid, target_process_guid, src_path, target_path, granted_access, granted_access_value, owner_uid, time, utc_time, uptime);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["src_pid"] = src_pid;
                                            kafka_event["src_process_guid"] = src_process_guid;
                                            kafka_event["target_pid"] = target_pid;
                                            kafka_event["target_process_guid"] = target_process_guid;
                                            kafka_event["src_path"] = src_path;
                                            kafka_event["target_path"] = target_path;
                                            kafka_event["granted_access"] = granted_access;
                                            kafka_event["granted_access_value"] = granted_access_value;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_process_open";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_remote_thread_events")
                                {
                                    std::string eid, action, src_process_guid, target_process_guid, src_path, target_path, function_name, module_name, owner_uid, utc_time;
                                    long unixTime, time, src_pid, target_pid, uptime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = column.contains("time") ? atol(column["time"].get<std::string>().c_str()) : 0;
                                    src_pid = column.contains("src_pid") ? atol(column["src_pid"].get<std::string>().c_str()) : 0;
                                    target_pid = column.contains("target_pid") ? atol(column["target_pid"].get<std::string>().c_str()) : 0;
                                    uptime = (entry.contains("decorations") && entry["decorations"].contains("uptime")) ? atol(entry["decorations"]["uptime"].get<std::string>().c_str()) : 0;

                                    eid = column.contains("eid") ? column["eid"] : "";
                                    action = column.contains("action") ? column["action"] : "";
                                    src_process_guid = column.contains("src_process_guid") ? column["src_process_guid"] : "";
                                    target_process_guid = column.contains("target_process_guid") ? column["target_process_guid"] : "";
                                    src_path = column.contains("src_path") ? column["src_path"] : "";
                                    target_path = column.contains("target_path") ? column["target_path"] : "";
                                    function_name = column.contains("function_name") ? column["function_name"] : "";
                                    module_name = column.contains("module_name") ? column["module_name"] : "";
                                    owner_uid = column.contains("owner_uid") ? column["owner_uid"] : "";
                                    utc_time = column.contains("utc_time") ? column["utc_time"] : "";

                                    transaction->exec_prepared("win_remote_thread_events", host_identifier, hostname, unixTime, eid, action, src_pid, src_process_guid, target_pid, target_process_guid, src_path, target_path, function_name, module_name, owner_uid, time, utc_time, uptime);

                                    // Publish to Kafka for real-time detection
                                    auto& kafka_producer = KafkaProducerManager::getInstance();
                                    if (kafka_producer.isInitialized()) {
                                        try {
                                            nlohmann::json kafka_event;
                                            kafka_event["host_identifier"] = host_identifier;
                                            kafka_event["hostname"] = hostname;
                                            kafka_event["unixtime"] = unixTime;
                                            kafka_event["src_pid"] = src_pid;
                                            kafka_event["src_process_guid"] = src_process_guid;
                                            kafka_event["target_pid"] = target_pid;
                                            kafka_event["target_process_guid"] = target_process_guid;
                                            kafka_event["src_path"] = src_path;
                                            kafka_event["target_path"] = target_path;
                                            kafka_event["function_name"] = function_name;
                                            kafka_event["module_name"] = module_name;
                                            kafka_event["action"] = action;
                                            kafka_event["event_type"] = "win_remote_thread";
                                            std::string event_str = kafka_event.dump();
                                            kafka_producer.publishEvent(tableName, event_str, host_identifier);
                                        } catch (const std::exception& e) {
                                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to publish " << tableName
                                                                       << " to Kafka: " << e.what();
                                        }
                                    }

                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "connectivity")
                                {
                                    // Variables to hold column data
                                    long unixTime;
                                    int disconnected, ipv4_no_traffic, ipv6_no_traffic;
                                    int ipv4_subnet, ipv4_local_network, ipv4_internet;
                                    int ipv6_subnet, ipv6_local_network, ipv6_internet;

                                    auto column = entry["columns"];

                                    // Extracting values from JSON and providing default values where necessary
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    disconnected = column.contains("disconnected") ? std::stoi(column["disconnected"].get<std::string>()) : 0;
                                    ipv4_no_traffic = column.contains("ipv4_no_traffic") ? std::stoi(column["ipv4_no_traffic"].get<std::string>()) : 0;
                                    ipv6_no_traffic = column.contains("ipv6_no_traffic") ? std::stoi(column["ipv6_no_traffic"].get<std::string>()) : 0;
                                    ipv4_subnet = column.contains("ipv4_subnet") ? std::stoi(column["ipv4_subnet"].get<std::string>()) : 0;
                                    ipv4_local_network = column.contains("ipv4_local_network") ? std::stoi(column["ipv4_local_network"].get<std::string>()) : 0;
                                    ipv4_internet = column.contains("ipv4_internet") ? std::stoi(column["ipv4_internet"].get<std::string>()) : 0;
                                    ipv6_subnet = column.contains("ipv6_subnet") ? std::stoi(column["ipv6_subnet"].get<std::string>()) : 0;
                                    ipv6_local_network = column.contains("ipv6_local_network") ? std::stoi(column["ipv6_local_network"].get<std::string>()) : 0;
                                    ipv6_internet = column.contains("ipv6_internet") ? std::stoi(column["ipv6_internet"].get<std::string>()) : 0;

                                    // Executing prepared statement to insert data
                                    transaction->exec_prepared("connectivity", host_identifier, unixTime,
                                                              disconnected, ipv4_no_traffic, ipv6_no_traffic,
                                                              ipv4_subnet, ipv4_local_network, ipv4_internet,
                                                              ipv6_subnet, ipv6_local_network, ipv6_internet);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "windows_security_products")
                                {
                                    std::string type, name, state, state_timestamp, remediation_path;
                                    long unixTime;
                                    int signatures_up_to_date;

                                    auto column = entry["columns"];

                                    // Extract values from JSON, with defaults where data might not be available
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    type = column.contains("type") ? column["type"] : "";
                                    name = column.contains("name") ? column["name"] : "";
                                    state = column.contains("state") ? column["state"] : "";
                                    state_timestamp = column.contains("state_timestamp") ? column["state_timestamp"] : "";
                                    remediation_path = column.contains("remediation_path") ? column["remediation_path"] : "";
                                    signatures_up_to_date = column.contains("signatures_up_to_date") ? std::stoi(column["signatures_up_to_date"].get<std::string>()) : 0;

                                    // Executing prepared statement to insert data
                                    transaction->exec_prepared("windows_security_products", host_identifier, unixTime,
                                                              type, name, state, state_timestamp, remediation_path, signatures_up_to_date);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "wmi_bios_info")
                                {
                                    std::string name, value;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    // Extract values from JSON, ensuring to handle cases where data might be missing
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    value = column.contains("value") ? column["value"] : "";

                                    // Executing the prepared statement to insert data
                                    transaction->exec_prepared("wmi_bios_info", host_identifier, unixTime, name, value);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "windows_firewall_rules")
                                {
                                    std::string name, app_name, action_val, grouping, direction, protocol;
                                    std::string local_addresses, remote_addresses, local_ports, remote_ports;
                                    std::string icmp_types_codes, service_name;
                                    long unixTime;
                                    int enabled, profile_domain, profile_private, profile_public;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    name = column.contains("name") ? column["name"] : "";
                                    app_name = column.contains("app_name") ? column["app_name"] : "";
                                    action_val = column.contains("action") ? column["action"] : "";
                                    enabled = column.contains("enabled") ? std::stoi(column["enabled"].get<std::string>()) : 0;
                                    grouping = column.contains("grouping") ? column["grouping"] : "";
                                    direction = column.contains("direction") ? column["direction"] : "";
                                    protocol = column.contains("protocol") ? column["protocol"] : "";
                                    local_addresses = column.contains("local_addresses") ? column["local_addresses"] : "";
                                    remote_addresses = column.contains("remote_addresses") ? column["remote_addresses"] : "";
                                    local_ports = column.contains("local_ports") ? column["local_ports"] : "";
                                    remote_ports = column.contains("remote_ports") ? column["remote_ports"] : "";
                                    icmp_types_codes = column.contains("icmp_types_codes") ? column["icmp_types_codes"] : "";
                                    profile_domain = column.contains("profile_domain") ? std::stoi(column["profile_domain"].get<std::string>()) : 0;
                                    profile_private = column.contains("profile_private") ? std::stoi(column["profile_private"].get<std::string>()) : 0;
                                    profile_public = column.contains("profile_public") ? std::stoi(column["profile_public"].get<std::string>()) : 0;
                                    service_name = column.contains("service_name") ? column["service_name"] : "";

                                    transaction->exec_prepared("windows_firewall_rules", host_identifier, unixTime,
                                                              name, app_name, action_val, enabled, grouping, direction,
                                                              protocol, local_addresses, remote_addresses, local_ports,
                                                              remote_ports, icmp_types_codes, profile_domain,
                                                              profile_private, profile_public, service_name);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "windows_security_center")
                                {
                                    std::string firewall, autoupdate, antivirus, antispyware;
                                    std::string internet_settings, windows_security_center_service, user_account_control;
                                    long unixTime;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    firewall = column.contains("firewall") ? column["firewall"] : "";
                                    autoupdate = column.contains("autoupdate") ? column["autoupdate"] : "";
                                    antivirus = column.contains("antivirus") ? column["antivirus"] : "";
                                    antispyware = column.contains("antispyware") ? column["antispyware"] : "";
                                    internet_settings = column.contains("internet_settings") ? column["internet_settings"] : "";
                                    windows_security_center_service = column.contains("windows_security_center_service") ? column["windows_security_center_service"] : "";
                                    user_account_control = column.contains("user_account_control") ? column["user_account_control"] : "";

                                    transaction->exec_prepared("windows_security_center", host_identifier, unixTime,
                                                              firewall, autoupdate, antivirus, antispyware,
                                                              internet_settings, windows_security_center_service,
                                                              user_account_control);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "windows_update_history")
                                {
                                    std::string client_app_id, description, operation, result_code;
                                    std::string server_selection, service_id, support_url, title, update_id;
                                    long unixTime;
                                    long long date, hresult, update_revision;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    client_app_id = column.contains("client_app_id") ? column["client_app_id"] : "";
                                    date = column.contains("date") ? std::stoll(column["date"].get<std::string>()) : 0;
                                    description = column.contains("description") ? column["description"] : "";
                                    hresult = column.contains("hresult") ? std::stoll(column["hresult"].get<std::string>()) : 0;
                                    operation = column.contains("operation") ? column["operation"] : "";
                                    result_code = column.contains("result_code") ? column["result_code"] : "";
                                    server_selection = column.contains("server_selection") ? column["server_selection"] : "";
                                    service_id = column.contains("service_id") ? column["service_id"] : "";
                                    support_url = column.contains("support_url") ? column["support_url"] : "";
                                    title = column.contains("title") ? column["title"] : "";
                                    update_id = column.contains("update_id") ? column["update_id"] : "";
                                    update_revision = column.contains("update_revision") ? std::stoll(column["update_revision"].get<std::string>()) : 0;

                                    transaction->exec_prepared("windows_update_history", host_identifier, unixTime,
                                                              client_app_id, date, description, hresult, operation,
                                                              result_code, server_selection, service_id, support_url,
                                                              title, update_id, update_revision);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "secureboot")
                                {
                                    long unixTime;
                                    int secure_boot, setup_mode;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    secure_boot = column.contains("secure_boot") ? std::stoi(column["secure_boot"].get<std::string>()) : 0;
                                    setup_mode = column.contains("setup_mode") ? std::stoi(column["setup_mode"].get<std::string>()) : 0;

                                    transaction->exec_prepared("secureboot", host_identifier, unixTime,
                                                              secure_boot, setup_mode);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "security_profile_info")
                                {
                                    long unixTime;
                                    int minimum_password_age, maximum_password_age, minimum_password_length;
                                    int password_complexity, password_history_size, lockout_bad_count;
                                    int logon_to_change_password, force_logoff_when_expire;
                                    std::string new_administrator_name, new_guest_name;
                                    int clear_text_password, lsa_anonymous_name_lookup;
                                    int enable_admin_account, enable_guest_account;
                                    int audit_system_events, audit_logon_events, audit_object_access;
                                    int audit_privilege_use, audit_policy_change, audit_account_manage;
                                    int audit_process_tracking, audit_ds_access, audit_account_logon;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    minimum_password_age = column.contains("minimum_password_age") ? std::stoi(column["minimum_password_age"].get<std::string>()) : 0;
                                    maximum_password_age = column.contains("maximum_password_age") ? std::stoi(column["maximum_password_age"].get<std::string>()) : 0;
                                    minimum_password_length = column.contains("minimum_password_length") ? std::stoi(column["minimum_password_length"].get<std::string>()) : 0;
                                    password_complexity = column.contains("password_complexity") ? std::stoi(column["password_complexity"].get<std::string>()) : 0;
                                    password_history_size = column.contains("password_history_size") ? std::stoi(column["password_history_size"].get<std::string>()) : 0;
                                    lockout_bad_count = column.contains("lockout_bad_count") ? std::stoi(column["lockout_bad_count"].get<std::string>()) : 0;
                                    logon_to_change_password = column.contains("logon_to_change_password") ? std::stoi(column["logon_to_change_password"].get<std::string>()) : 0;
                                    force_logoff_when_expire = column.contains("force_logoff_when_expire") ? std::stoi(column["force_logoff_when_expire"].get<std::string>()) : 0;
                                    new_administrator_name = column.contains("new_administrator_name") ? column["new_administrator_name"] : "";
                                    new_guest_name = column.contains("new_guest_name") ? column["new_guest_name"] : "";
                                    clear_text_password = column.contains("clear_text_password") ? std::stoi(column["clear_text_password"].get<std::string>()) : 0;
                                    lsa_anonymous_name_lookup = column.contains("lsa_anonymous_name_lookup") ? std::stoi(column["lsa_anonymous_name_lookup"].get<std::string>()) : 0;
                                    enable_admin_account = column.contains("enable_admin_account") ? std::stoi(column["enable_admin_account"].get<std::string>()) : 0;
                                    enable_guest_account = column.contains("enable_guest_account") ? std::stoi(column["enable_guest_account"].get<std::string>()) : 0;
                                    audit_system_events = column.contains("audit_system_events") ? std::stoi(column["audit_system_events"].get<std::string>()) : 0;
                                    audit_logon_events = column.contains("audit_logon_events") ? std::stoi(column["audit_logon_events"].get<std::string>()) : 0;
                                    audit_object_access = column.contains("audit_object_access") ? std::stoi(column["audit_object_access"].get<std::string>()) : 0;
                                    audit_privilege_use = column.contains("audit_privilege_use") ? std::stoi(column["audit_privilege_use"].get<std::string>()) : 0;
                                    audit_policy_change = column.contains("audit_policy_change") ? std::stoi(column["audit_policy_change"].get<std::string>()) : 0;
                                    audit_account_manage = column.contains("audit_account_manage") ? std::stoi(column["audit_account_manage"].get<std::string>()) : 0;
                                    audit_process_tracking = column.contains("audit_process_tracking") ? std::stoi(column["audit_process_tracking"].get<std::string>()) : 0;
                                    audit_ds_access = column.contains("audit_ds_access") ? std::stoi(column["audit_ds_access"].get<std::string>()) : 0;
                                    audit_account_logon = column.contains("audit_account_logon") ? std::stoi(column["audit_account_logon"].get<std::string>()) : 0;

                                    transaction->exec_prepared("security_profile_info", host_identifier, unixTime,
                                                              minimum_password_age, maximum_password_age,
                                                              minimum_password_length, password_complexity,
                                                              password_history_size, lockout_bad_count,
                                                              logon_to_change_password, force_logoff_when_expire,
                                                              new_administrator_name, new_guest_name,
                                                              clear_text_password, lsa_anonymous_name_lookup,
                                                              enable_admin_account, enable_guest_account,
                                                              audit_system_events, audit_logon_events,
                                                              audit_object_access, audit_privilege_use,
                                                              audit_policy_change, audit_account_manage,
                                                              audit_process_tracking, audit_ds_access,
                                                              audit_account_logon);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "system_info")
                                {
                                    std::string si_hostname, uuid, cpu_type, cpu_subtype, cpu_brand;
                                    std::string cpu_microcode, hardware_vendor_si, hardware_model_si, hardware_version_si;
                                    std::string hardware_serial, board_vendor, board_model, board_version, board_serial;
                                    std::string computer_name, local_hostname;
                                    long unixTime;
                                    int cpu_physical_cores, cpu_logical_cores, cpu_sockets;
                                    long long physical_memory;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    si_hostname = column.contains("hostname") ? column["hostname"] : "";
                                    uuid = column.contains("uuid") ? column["uuid"] : "";
                                    cpu_type = column.contains("cpu_type") ? column["cpu_type"] : "";
                                    cpu_subtype = column.contains("cpu_subtype") ? column["cpu_subtype"] : "";
                                    cpu_brand = column.contains("cpu_brand") ? column["cpu_brand"] : "";
                                    cpu_physical_cores = column.contains("cpu_physical_cores") ? std::stoi(column["cpu_physical_cores"].get<std::string>()) : 0;
                                    cpu_logical_cores = column.contains("cpu_logical_cores") ? std::stoi(column["cpu_logical_cores"].get<std::string>()) : 0;
                                    cpu_sockets = column.contains("cpu_sockets") ? std::stoi(column["cpu_sockets"].get<std::string>()) : 0;
                                    cpu_microcode = column.contains("cpu_microcode") ? column["cpu_microcode"] : "";
                                    physical_memory = column.contains("physical_memory") ? std::stoll(column["physical_memory"].get<std::string>()) : 0;
                                    hardware_vendor_si = column.contains("hardware_vendor") ? column["hardware_vendor"] : "";
                                    hardware_model_si = column.contains("hardware_model") ? column["hardware_model"] : "";
                                    hardware_version_si = column.contains("hardware_version") ? column["hardware_version"] : "";
                                    hardware_serial = column.contains("hardware_serial") ? column["hardware_serial"] : "";
                                    board_vendor = column.contains("board_vendor") ? column["board_vendor"] : "";
                                    board_model = column.contains("board_model") ? column["board_model"] : "";
                                    board_version = column.contains("board_version") ? column["board_version"] : "";
                                    board_serial = column.contains("board_serial") ? column["board_serial"] : "";
                                    computer_name = column.contains("computer_name") ? column["computer_name"] : "";
                                    local_hostname = column.contains("local_hostname") ? column["local_hostname"] : "";

                                    transaction->exec_prepared("system_info", host_identifier, unixTime,
                                                              si_hostname, uuid, cpu_type, cpu_subtype, cpu_brand,
                                                              cpu_physical_cores, cpu_logical_cores, cpu_sockets,
                                                              cpu_microcode, physical_memory, hardware_vendor_si,
                                                              hardware_model_si, hardware_version_si, hardware_serial,
                                                              board_vendor, board_model, board_version, board_serial,
                                                              computer_name, local_hostname);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "tpm_info")
                                {
                                    long unixTime;
                                    int activated, enabled, owned, manufacturer_id;
                                    std::string manufacturer_version, manufacturer_name, product_name;
                                    std::string physical_presence_version, spec_version;

                                    auto column = entry["columns"];

                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    activated = column.contains("activated") ? std::stoi(column["activated"].get<std::string>()) : 0;
                                    enabled = column.contains("enabled") ? std::stoi(column["enabled"].get<std::string>()) : 0;
                                    owned = column.contains("owned") ? std::stoi(column["owned"].get<std::string>()) : 0;
                                    manufacturer_version = column.contains("manufacturer_version") ? column["manufacturer_version"] : "";
                                    manufacturer_id = column.contains("manufacturer_id") ? std::stoi(column["manufacturer_id"].get<std::string>()) : 0;
                                    manufacturer_name = column.contains("manufacturer_name") ? column["manufacturer_name"] : "";
                                    product_name = column.contains("product_name") ? column["product_name"] : "";
                                    physical_presence_version = column.contains("physical_presence_version") ? column["physical_presence_version"] : "";
                                    spec_version = column.contains("spec_version") ? column["spec_version"] : "";

                                    transaction->exec_prepared("tpm_info", host_identifier, unixTime,
                                                              activated, enabled, owned, manufacturer_version,
                                                              manufacturer_id, manufacturer_name, product_name,
                                                              physical_presence_version, spec_version);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                                else if (tableName == "win_event_log_data")
                                {
                                    std::string datetime, source, provider_name, provider_guid, data, eid;
                                    long unixTime, time;
                                    int eventid, task, level;
                                    long long keywords;

                                    auto column = entry["columns"];

                                    // Extract values from JSON, ensuring to handle cases where data might be missing
                                    unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                    time = entry.contains("time") ? entry["time"].get<long>() : 0;
                                    datetime = column.contains("datetime") ? column["datetime"] : "";
                                    source = column.contains("source") ? column["source"] : "";
                                    provider_name = column.contains("provider_name") ? column["provider_name"] : "";
                                    provider_guid = column.contains("provider_guid") ? column["provider_guid"] : "";
                                    eventid = column.contains("eventid") ? std::stoi(column["eventid"].get<std::string>()) : 0;
                                    task = column.contains("task") ? std::stoi(column["task"].get<std::string>()) : 0;
                                    level = column.contains("level") ? std::stoi(column["level"].get<std::string>()) : 0;
                                    keywords = column.contains("keywords") ? std::stoll(column["keywords"].get<std::string>()) : 0;
                                    data = column.contains("data") ? column["data"] : "";

                                    // Executing the prepared statement to insert data
                                    transaction->exec_prepared("win_event_log_data", host_identifier, unixTime, time, datetime, source,
                                                              provider_name, provider_guid, eventid, task, level,
                                                              keywords, data);
                                    batch_count++;
                                    if (batch_count >= BATCH_SIZE) {
                                        pending_batches.flush_all(*transaction);
                                        transaction->commit();
                                        batch_count = 0;
                                        transaction = std::make_unique<pqxx::work>(*connection);
                                    }
                                }
                            }
                            else if (entry.contains("hostIdentifier") && entry.contains("name") && entry.contains("snapshot"))
                            {
                                if (host_identifier != entry["hostIdentifier"])
                                {
                                    continue;
                                }

                                long unixTime = entry.contains("unixTime") ? entry["unixTime"].get<long>() : 0;
                                std::string query_name = entry["name"];
                                auto snapshot_array = entry["snapshot"];
                                std::string query_result = snapshot_array.dump();

                                // Commit prior entries before this snapshot and flush
                                // again after it (end of this branch): each snapshot
                                // entry runs in its own transaction, so an error inside
                                // it can never leave part of the entry committed nor
                                // drop earlier entries' rows.
                                if (batch_count > 0) {
                                    pending_batches.flush_all(*transaction);
                                    transaction->commit();
                                    batch_count = 0;
                                    transaction = std::make_unique<pqxx::work>(*connection);
                                }

                                transaction->exec_prepared("snapshot_result_add", host_identifier, unixTime, query_name, query_result);
                                batch_count++;

                                // Route snapshot data to dedicated tables so UI/queries work correctly.
                                // These non-event osquery tables come as snapshots (not differential events),
                                // so they bypass the "columns"-based handlers above.
                                if (snapshot_array.is_array() && !snapshot_array.empty())
                                {
                                    if (query_name == "windows_security_products")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string type = row.contains("type") ? row["type"].get<std::string>() : "";
                                            std::string name = row.contains("name") ? row["name"].get<std::string>() : "";
                                            std::string state = row.contains("state") ? row["state"].get<std::string>() : "";
                                            std::string state_timestamp = row.contains("state_timestamp") ? row["state_timestamp"].get<std::string>() : "";
                                            std::string remediation_path = row.contains("remediation_path") ? row["remediation_path"].get<std::string>() : "";
                                            int signatures_up_to_date = 0;
                                            if (row.contains("signatures_up_to_date")) {
                                                try { signatures_up_to_date = std::stoi(row["signatures_up_to_date"].get<std::string>()); } catch (...) {}
                                            }
                                            transaction->exec_prepared("windows_security_products", host_identifier, unixTime,
                                                                      type, name, state, state_timestamp, remediation_path, signatures_up_to_date);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "windows_security_center")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string firewall = row.contains("firewall") ? row["firewall"].get<std::string>() : "";
                                            std::string autoupdate = row.contains("autoupdate") ? row["autoupdate"].get<std::string>() : "";
                                            std::string antivirus = row.contains("antivirus") ? row["antivirus"].get<std::string>() : "";
                                            std::string antispyware = row.contains("antispyware") ? row["antispyware"].get<std::string>() : "";
                                            std::string internet_settings = row.contains("internet_settings") ? row["internet_settings"].get<std::string>() : "";
                                            std::string wsc_service = row.contains("windows_security_center_service") ? row["windows_security_center_service"].get<std::string>() : "";
                                            std::string user_account_control = row.contains("user_account_control") ? row["user_account_control"].get<std::string>() : "";
                                            transaction->exec_prepared("windows_security_center", host_identifier, unixTime,
                                                                      firewall, autoupdate, antivirus, antispyware,
                                                                      internet_settings, wsc_service, user_account_control);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "secureboot")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            int secure_boot = 0, setup_mode = 0;
                                            if (row.contains("secure_boot")) {
                                                try { secure_boot = std::stoi(row["secure_boot"].get<std::string>()); } catch (...) {}
                                            }
                                            if (row.contains("setup_mode")) {
                                                try { setup_mode = std::stoi(row["setup_mode"].get<std::string>()); } catch (...) {}
                                            }
                                            transaction->exec_prepared("secureboot", host_identifier, unixTime,
                                                                      secure_boot, setup_mode);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "wmi_bios_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string name  = row.contains("name")  ? row["name"].get<std::string>()  : "";
                                            std::string value = row.contains("value") ? row["value"].get<std::string>() : "";
                                            transaction->exec_prepared("wmi_bios_info", host_identifier, unixTime, name, value);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "windows_firewall_rules")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string name             = row.contains("name")             ? row["name"].get<std::string>()             : "";
                                            std::string app_name         = row.contains("app_name")         ? row["app_name"].get<std::string>()         : "";
                                            std::string action           = row.contains("action")           ? row["action"].get<std::string>()           : "";
                                            std::string grouping         = row.contains("grouping")         ? row["grouping"].get<std::string>()         : "";
                                            std::string direction        = row.contains("direction")        ? row["direction"].get<std::string>()        : "";
                                            std::string protocol         = row.contains("protocol")         ? row["protocol"].get<std::string>()         : "";
                                            std::string local_addresses  = row.contains("local_addresses")  ? row["local_addresses"].get<std::string>()  : "";
                                            std::string remote_addresses = row.contains("remote_addresses") ? row["remote_addresses"].get<std::string>() : "";
                                            std::string local_ports      = row.contains("local_ports")      ? row["local_ports"].get<std::string>()      : "";
                                            std::string remote_ports     = row.contains("remote_ports")     ? row["remote_ports"].get<std::string>()     : "";
                                            std::string icmp_types_codes = row.contains("icmp_types_codes") ? row["icmp_types_codes"].get<std::string>() : "";
                                            std::string service_name     = row.contains("service_name")     ? row["service_name"].get<std::string>()     : "";
                                            int enabled = 0, profile_domain = 0, profile_private = 0, profile_public = 0;
                                            if (row.contains("enabled"))        { try { enabled        = std::stoi(row["enabled"].get<std::string>());        } catch (...) {} }
                                            if (row.contains("profile_domain")) { try { profile_domain = std::stoi(row["profile_domain"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("profile_private")){ try { profile_private= std::stoi(row["profile_private"].get<std::string>());} catch (...) {} }
                                            if (row.contains("profile_public")) { try { profile_public = std::stoi(row["profile_public"].get<std::string>()); } catch (...) {} }
                                            transaction->exec_prepared("windows_firewall_rules", host_identifier, unixTime,
                                                                      name, app_name, action, enabled, grouping, direction, protocol,
                                                                      local_addresses, remote_addresses, local_ports, remote_ports,
                                                                      icmp_types_codes, profile_domain, profile_private, profile_public, service_name);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "windows_update_history")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string client_app_id  = row.contains("client_app_id")  ? row["client_app_id"].get<std::string>()  : "";
                                            std::string description    = row.contains("description")    ? row["description"].get<std::string>()    : "";
                                            std::string operation      = row.contains("operation")      ? row["operation"].get<std::string>()      : "";
                                            std::string result_code    = row.contains("result_code")    ? row["result_code"].get<std::string>()    : "";
                                            std::string server_sel     = row.contains("server_selection")? row["server_selection"].get<std::string>(): "";
                                            std::string service_id     = row.contains("service_id")     ? row["service_id"].get<std::string>()     : "";
                                            std::string support_url    = row.contains("support_url")    ? row["support_url"].get<std::string>()    : "";
                                            std::string title          = row.contains("title")          ? row["title"].get<std::string>()          : "";
                                            std::string update_id      = row.contains("update_id")      ? row["update_id"].get<std::string>()      : "";
                                            long long date = 0, hresult = 0, update_revision = 0;
                                            if (row.contains("date"))            { try { date            = std::stoll(row["date"].get<std::string>());            } catch (...) {} }
                                            if (row.contains("hresult"))         { try { hresult         = std::stoll(row["hresult"].get<std::string>());         } catch (...) {} }
                                            if (row.contains("update_revision")) { try { update_revision = std::stoll(row["update_revision"].get<std::string>()); } catch (...) {} }
                                            transaction->exec_prepared("windows_update_history", host_identifier, unixTime,
                                                                      client_app_id, date, description, hresult, operation,
                                                                      result_code, server_sel, service_id, support_url,
                                                                      title, update_id, update_revision);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "security_profile_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string new_admin = row.contains("new_administrator_name") ? row["new_administrator_name"].get<std::string>() : "";
                                            std::string new_guest = row.contains("new_guest_name")         ? row["new_guest_name"].get<std::string>()         : "";
                                            int min_pwd_age=0, max_pwd_age=0, min_pwd_len=0, pwd_complexity=0, pwd_history=0;
                                            int lockout=0, logon_change=0, force_logoff=0, clear_text=0, lsa_anon=0;
                                            int ena_admin=0, ena_guest=0;
                                            int aud_sys=0, aud_logon=0, aud_obj=0, aud_priv=0, aud_policy=0;
                                            int aud_acct=0, aud_proc=0, aud_ds=0, aud_acct_logon=0;
                                            auto getint = [&](const char* k) -> int {
                                                if (row.contains(k)) { try { return std::stoi(row[k].get<std::string>()); } catch (...) {} } return 0;
                                            };
                                            min_pwd_age    = getint("minimum_password_age");
                                            max_pwd_age    = getint("maximum_password_age");
                                            min_pwd_len    = getint("minimum_password_length");
                                            pwd_complexity = getint("password_complexity");
                                            pwd_history    = getint("password_history_size");
                                            lockout        = getint("lockout_bad_count");
                                            logon_change   = getint("logon_to_change_password");
                                            force_logoff   = getint("force_logoff_when_expire");
                                            clear_text     = getint("clear_text_password");
                                            lsa_anon       = getint("lsa_anonymous_name_lookup");
                                            ena_admin      = getint("enable_admin_account");
                                            ena_guest      = getint("enable_guest_account");
                                            aud_sys        = getint("audit_system_events");
                                            aud_logon      = getint("audit_logon_events");
                                            aud_obj        = getint("audit_object_access");
                                            aud_priv       = getint("audit_privilege_use");
                                            aud_policy     = getint("audit_policy_change");
                                            aud_acct       = getint("audit_account_manage");
                                            aud_proc       = getint("audit_process_tracking");
                                            aud_ds         = getint("audit_ds_access");
                                            aud_acct_logon = getint("audit_account_logon");
                                            transaction->exec_prepared("security_profile_info", host_identifier, unixTime,
                                                                      min_pwd_age, max_pwd_age, min_pwd_len, pwd_complexity,
                                                                      pwd_history, lockout, logon_change, force_logoff,
                                                                      new_admin, new_guest, clear_text, lsa_anon,
                                                                      ena_admin, ena_guest,
                                                                      aud_sys, aud_logon, aud_obj, aud_priv,
                                                                      aud_policy, aud_acct, aud_proc, aud_ds, aud_acct_logon);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "system_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string hostname         = row.contains("hostname")         ? row["hostname"].get<std::string>()         : "";
                                            std::string uuid             = row.contains("uuid")             ? row["uuid"].get<std::string>()             : "";
                                            std::string cpu_type         = row.contains("cpu_type")         ? row["cpu_type"].get<std::string>()         : "";
                                            std::string cpu_subtype      = row.contains("cpu_subtype")      ? row["cpu_subtype"].get<std::string>()      : "";
                                            std::string cpu_brand        = row.contains("cpu_brand")        ? row["cpu_brand"].get<std::string>()        : "";
                                            std::string cpu_microcode    = row.contains("cpu_microcode")    ? row["cpu_microcode"].get<std::string>()    : "";
                                            std::string hardware_vendor  = row.contains("hardware_vendor")  ? row["hardware_vendor"].get<std::string>()  : "";
                                            std::string hardware_model   = row.contains("hardware_model")   ? row["hardware_model"].get<std::string>()   : "";
                                            std::string hardware_version = row.contains("hardware_version") ? row["hardware_version"].get<std::string>() : "";
                                            std::string hardware_serial  = row.contains("hardware_serial")  ? row["hardware_serial"].get<std::string>()  : "";
                                            std::string board_vendor     = row.contains("board_vendor")     ? row["board_vendor"].get<std::string>()     : "";
                                            std::string board_model      = row.contains("board_model")      ? row["board_model"].get<std::string>()      : "";
                                            std::string board_version    = row.contains("board_version")    ? row["board_version"].get<std::string>()    : "";
                                            std::string board_serial     = row.contains("board_serial")     ? row["board_serial"].get<std::string>()     : "";
                                            std::string computer_name    = row.contains("computer_name")    ? row["computer_name"].get<std::string>()    : "";
                                            std::string local_hostname   = row.contains("local_hostname")   ? row["local_hostname"].get<std::string>()   : "";
                                            int cpu_physical_cores = 0, cpu_logical_cores = 0, cpu_sockets = 0;
                                            long long physical_memory = 0;
                                            if (row.contains("cpu_physical_cores")) { try { cpu_physical_cores = std::stoi(row["cpu_physical_cores"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("cpu_logical_cores"))  { try { cpu_logical_cores  = std::stoi(row["cpu_logical_cores"].get<std::string>());  } catch (...) {} }
                                            if (row.contains("cpu_sockets"))        { try { cpu_sockets        = std::stoi(row["cpu_sockets"].get<std::string>());        } catch (...) {} }
                                            if (row.contains("physical_memory"))    { try { physical_memory    = std::stoll(row["physical_memory"].get<std::string>());   } catch (...) {} }
                                            transaction->exec_prepared("system_info", host_identifier, unixTime,
                                                                      hostname, uuid, cpu_type, cpu_subtype, cpu_brand,
                                                                      cpu_physical_cores, cpu_logical_cores, cpu_sockets,
                                                                      cpu_microcode, physical_memory,
                                                                      hardware_vendor, hardware_model, hardware_version, hardware_serial,
                                                                      board_vendor, board_model, board_version, board_serial,
                                                                      computer_name, local_hostname);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "tpm_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string manufacturer_version        = row.contains("manufacturer_version")        ? row["manufacturer_version"].get<std::string>()        : "";
                                            std::string manufacturer_name           = row.contains("manufacturer_name")           ? row["manufacturer_name"].get<std::string>()           : "";
                                            std::string product_name               = row.contains("product_name")               ? row["product_name"].get<std::string>()               : "";
                                            std::string physical_presence_version  = row.contains("physical_presence_version")  ? row["physical_presence_version"].get<std::string>()  : "";
                                            std::string spec_version               = row.contains("spec_version")               ? row["spec_version"].get<std::string>()               : "";
                                            int activated = 0, enabled = 0, owned = 0, manufacturer_id = 0;
                                            if (row.contains("activated"))       { try { activated       = std::stoi(row["activated"].get<std::string>());       } catch (...) {} }
                                            if (row.contains("enabled"))         { try { enabled         = std::stoi(row["enabled"].get<std::string>());         } catch (...) {} }
                                            if (row.contains("owned"))           { try { owned           = std::stoi(row["owned"].get<std::string>());           } catch (...) {} }
                                            if (row.contains("manufacturer_id")) { try { manufacturer_id = std::stoi(row["manufacturer_id"].get<std::string>()); } catch (...) {} }
                                            transaction->exec_prepared("tpm_info", host_identifier, unixTime,
                                                                      activated, enabled, owned,
                                                                      manufacturer_version, manufacturer_id, manufacturer_name,
                                                                      product_name, physical_presence_version, spec_version);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "disk_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string disk_id        = row.contains("disk_id")        ? row["disk_id"].get<std::string>()        : "";
                                            std::string pnp_device_id  = row.contains("pnp_device_id")  ? row["pnp_device_id"].get<std::string>()  : "";
                                            std::string type           = row.contains("type")           ? row["type"].get<std::string>()           : "";
                                            std::string manufacturer   = row.contains("manufacturer")   ? row["manufacturer"].get<std::string>()   : "";
                                            std::string hardware_model = row.contains("hardware_model") ? row["hardware_model"].get<std::string>() : "";
                                            std::string name           = row.contains("name")           ? row["name"].get<std::string>()           : "";
                                            std::string serial         = row.contains("serial")         ? row["serial"].get<std::string>()         : "";
                                            std::string description    = row.contains("description")    ? row["description"].get<std::string>()    : "";
                                            int partitions = 0, disk_index = 0;
                                            long long disk_size = 0;
                                            if (row.contains("partitions")) { try { partitions  = std::stoi(row["partitions"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("disk_index")) { try { disk_index  = std::stoi(row["disk_index"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("disk_size"))  { try { disk_size   = std::stoll(row["disk_size"].get<std::string>()); } catch (...) {} }
                                            transaction->exec_prepared("disk_info", host_identifier, unixTime,
                                                                      partitions, disk_index, type, disk_id, pnp_device_id,
                                                                      disk_size, manufacturer, hardware_model, name, serial, description);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "disk_encryption")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string name              = row.contains("name")              ? row["name"].get<std::string>()              : "";
                                            std::string uuid              = row.contains("uuid")              ? row["uuid"].get<std::string>()              : "";
                                            std::string type              = row.contains("type")              ? row["type"].get<std::string>()              : "";
                                            std::string encryption_status = row.contains("encryption_status") ? row["encryption_status"].get<std::string>() : "";
                                            std::string uid               = row.contains("uid")               ? row["uid"].get<std::string>()               : "";
                                            std::string user_uuid         = row.contains("user_uuid")         ? row["user_uuid"].get<std::string>()         : "";
                                            std::string filevault_status  = row.contains("filevault_status")  ? row["filevault_status"].get<std::string>()  : "";
                                            int encrypted = 0;
                                            if (row.contains("encrypted")) { try { encrypted = std::stoi(row["encrypted"].get<std::string>()); } catch (...) {} }
                                            transaction->exec_prepared("disk_encryption", host_identifier, unixTime,
                                                                      name, uuid, encrypted, type,
                                                                      encryption_status, uid, user_uuid, filevault_status);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "memory_devices")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string handle               = row.contains("handle")               ? row["handle"].get<std::string>()               : "";
                                            std::string array_handle         = row.contains("array_handle")         ? row["array_handle"].get<std::string>()         : "";
                                            std::string form_factor          = row.contains("form_factor")          ? row["form_factor"].get<std::string>()          : "";
                                            std::string device_locator       = row.contains("device_locator")       ? row["device_locator"].get<std::string>()       : "";
                                            std::string bank_locator         = row.contains("bank_locator")         ? row["bank_locator"].get<std::string>()         : "";
                                            std::string memory_type          = row.contains("memory_type")          ? row["memory_type"].get<std::string>()          : "";
                                            std::string memory_type_details  = row.contains("memory_type_details")  ? row["memory_type_details"].get<std::string>()  : "";
                                            std::string manufacturer         = row.contains("manufacturer")         ? row["manufacturer"].get<std::string>()         : "";
                                            std::string serial_number        = row.contains("serial_number")        ? row["serial_number"].get<std::string>()        : "";
                                            std::string asset_tag            = row.contains("asset_tag")            ? row["asset_tag"].get<std::string>()            : "";
                                            std::string part_number          = row.contains("part_number")          ? row["part_number"].get<std::string>()          : "";
                                            int total_width = 0, data_width = 0, size = 0, set_field = 0;
                                            int max_speed = 0, configured_clock_speed = 0;
                                            int min_voltage = 0, max_voltage = 0, configured_voltage = 0;
                                            if (row.contains("total_width"))            { try { total_width            = std::stoi(row["total_width"].get<std::string>());            } catch (...) {} }
                                            if (row.contains("data_width"))             { try { data_width             = std::stoi(row["data_width"].get<std::string>());             } catch (...) {} }
                                            if (row.contains("size"))                   { try { size                   = std::stoi(row["size"].get<std::string>());                   } catch (...) {} }
                                            if (row.contains("set"))                    { try { set_field              = std::stoi(row["set"].get<std::string>());                    } catch (...) {} }
                                            if (row.contains("max_speed"))              { try { max_speed              = std::stoi(row["max_speed"].get<std::string>());              } catch (...) {} }
                                            if (row.contains("configured_clock_speed")) { try { configured_clock_speed = std::stoi(row["configured_clock_speed"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("min_voltage"))            { try { min_voltage            = std::stoi(row["min_voltage"].get<std::string>());            } catch (...) {} }
                                            if (row.contains("max_voltage"))            { try { max_voltage            = std::stoi(row["max_voltage"].get<std::string>());            } catch (...) {} }
                                            if (row.contains("configured_voltage"))     { try { configured_voltage     = std::stoi(row["configured_voltage"].get<std::string>());     } catch (...) {} }
                                            transaction->exec_prepared("memory_devices", host_identifier, unixTime,
                                                                      handle, array_handle, form_factor,
                                                                      total_width, data_width, size, set_field,
                                                                      device_locator, bank_locator, memory_type, memory_type_details,
                                                                      max_speed, configured_clock_speed,
                                                                      manufacturer, serial_number, asset_tag, part_number,
                                                                      min_voltage, max_voltage, configured_voltage);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "mounts")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string device         = row.contains("device")         ? row["device"].get<std::string>()         : "";
                                            std::string device_alias   = row.contains("device_alias")   ? row["device_alias"].get<std::string>()   : "";
                                            std::string path           = row.contains("path")           ? row["path"].get<std::string>()           : "";
                                            std::string type           = row.contains("type")           ? row["type"].get<std::string>()           : "";
                                            std::string flags          = row.contains("flags")          ? row["flags"].get<std::string>()          : "";
                                            long long blocks_size = 0, blocks = 0, blocks_free = 0, blocks_available = 0;
                                            long long inodes = 0, inodes_free = 0;
                                            if (row.contains("blocks_size"))      { try { blocks_size      = std::stoll(row["blocks_size"].get<std::string>());      } catch (...) {} }
                                            if (row.contains("blocks"))           { try { blocks           = std::stoll(row["blocks"].get<std::string>());           } catch (...) {} }
                                            if (row.contains("blocks_free"))      { try { blocks_free      = std::stoll(row["blocks_free"].get<std::string>());      } catch (...) {} }
                                            if (row.contains("blocks_available")) { try { blocks_available = std::stoll(row["blocks_available"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("inodes"))           { try { inodes           = std::stoll(row["inodes"].get<std::string>());           } catch (...) {} }
                                            if (row.contains("inodes_free"))      { try { inodes_free      = std::stoll(row["inodes_free"].get<std::string>());      } catch (...) {} }
                                            transaction->exec_prepared("mounts", host_identifier, unixTime,
                                                                      device, device_alias, path, type,
                                                                      blocks_size, blocks, blocks_free, blocks_available,
                                                                      inodes, inodes_free, flags);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "bitlocker_info")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string device_id            = row.contains("device_id")            ? row["device_id"].get<std::string>()            : "";
                                            std::string drive_letter         = row.contains("drive_letter")         ? row["drive_letter"].get<std::string>()         : "";
                                            std::string persistent_volume_id = row.contains("persistent_volume_id") ? row["persistent_volume_id"].get<std::string>() : "";
                                            std::string encryption_method    = row.contains("encryption_method")    ? row["encryption_method"].get<std::string>()    : "";
                                            int conversion_status = 0, protection_status = 0, version = 0;
                                            int percentage_encrypted = 0, lock_status = 0;
                                            if (row.contains("conversion_status"))    { try { conversion_status    = std::stoi(row["conversion_status"].get<std::string>());    } catch (...) {} }
                                            if (row.contains("protection_status"))    { try { protection_status    = std::stoi(row["protection_status"].get<std::string>());    } catch (...) {} }
                                            if (row.contains("version"))              { try { version              = std::stoi(row["version"].get<std::string>());              } catch (...) {} }
                                            if (row.contains("percentage_encrypted")) { try { percentage_encrypted = std::stoi(row["percentage_encrypted"].get<std::string>()); } catch (...) {} }
                                            if (row.contains("lock_status"))          { try { lock_status          = std::stoi(row["lock_status"].get<std::string>());          } catch (...) {} }
                                            transaction->exec_prepared("bitlocker_info", host_identifier, unixTime,
                                                                      device_id, drive_letter, persistent_volume_id,
                                                                      conversion_status, protection_status, encryption_method,
                                                                      version, percentage_encrypted, lock_status);
                                            batch_count++;
                                        }
                                    }
                                    else if (query_name == "logical_drives")
                                    {
                                        for (const auto& row : snapshot_array)
                                        {
                                            std::string device_id   = row.contains("device_id")   ? row["device_id"].get<std::string>()   : "";
                                            std::string type        = row.contains("type")        ? row["type"].get<std::string>()        : "";
                                            std::string description = row.contains("description") ? row["description"].get<std::string>() : "";
                                            std::string file_system = row.contains("file_system") ? row["file_system"].get<std::string>() : "";
                                            long long free_space = -1, size = -1;
                                            int boot_partition = 0;
                                            if (row.contains("free_space"))     { try { free_space     = std::stoll(row["free_space"].get<std::string>());     } catch (...) {} }
                                            if (row.contains("size"))           { try { size           = std::stoll(row["size"].get<std::string>());           } catch (...) {} }
                                            if (row.contains("boot_partition")) { try { boot_partition = std::stoi(row["boot_partition"].get<std::string>());  } catch (...) {} }
                                            transaction->exec_prepared("logical_drives", host_identifier, unixTime,
                                                                      device_id, type, description,
                                                                      free_space, size, file_system, boot_partition);
                                            batch_count++;
                                        }
                                    }
                                }

                                // Entry boundary: commit this snapshot entry's rows
                                // atomically (see comment above snapshot_result_add).
                                if (batch_count > 0) {
                                    pending_batches.flush_all(*transaction);
                                    transaction->commit();
                                    batch_count = 0;
                                    transaction = std::make_unique<pqxx::work>(*connection);
                                }
                            }
                            }
                            catch (const nlohmann::json::exception &e)
                            {
                                // Field extraction failed before this entry's
                                // insert completed — skip just this entry. The
                                // transaction is still valid.
                                ++skipped_entries;
                                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping malformed log entry from "
                                                           << host_identifier << ": " << e.what();
                            }
                            catch (const pqxx::sql_error &e)
                            {
                                // The active transaction is aborted: its uncommitted
                                // inserts are lost. Start a fresh transaction so the
                                // rest of the batch still processes. Any rows still
                                // sitting in the R2-2 multi-row buffers were never
                                // sent to the database (they're only flushed right
                                // before a commit), but dropping them here too is
                                // deliberate: re-flushing them into the new
                                // transaction would replay whatever row caused this
                                // error and abort every subsequent flush forever.
                                ++skipped_entries;
                                std::size_t dropped_buffered = pending_batches.total_buffered();
                                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Log entry failed with database error (dropping "
                                                         << batch_count << " uncommitted inserts plus "
                                                         << dropped_buffered << " buffered rows): " << e.what()
                                                         << ". Query was: " << e.query();
                                try { transaction->abort(); } catch (...) {}
                                pending_batches.clear_all();
                                batch_count = 0;
                                transaction = std::make_unique<pqxx::work>(*connection);
                            }
                            catch (const std::exception &e)
                            {
                                // A non-JSON, non-SQL throw during field extraction —
                                // e.g. std::stoi/std::stol on an attacker-supplied
                                // numeric column that is non-numeric or out of range.
                                // These originate before any push_row/DB call, so the
                                // transaction and buffers are still consistent: skip
                                // only this entry instead of letting the throw unwind
                                // the whole loop and discard the entire POST batch
                                // (an agent could otherwise drop a peer's telemetry, or
                                // hide co-batched events, with one malformed field).
                                // Ordered after sql_error so that arm still binds first.
                                ++skipped_entries;
                                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping log entry with invalid field from "
                                                           << host_identifier << ": " << e.what();
                            }
                        }
                        // Commit any remaining batch events
                        if (batch_count > 0 || pending_batches.total_buffered() > 0) {
                            pending_batches.flush_all(*transaction);
                            transaction->commit();
                        }
                        if (skipped_entries > 0) {
                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipped " << skipped_entries
                                                       << " malformed/failed log entries from " << host_identifier;
                        }
                    }
                }
                else if (isKeyValid && logger_data["log_type"] == "status" && logger_data.contains("data"))
                {
                    // osquery TLS logger posts BOTH "result" and "status" logs to
                    // /log. Status logs carry the agent's own INFO/WARNING/ERROR
                    // diagnostics (glog severity, source file/line, message, version
                    // and decorations). Previously these were silently 200'd away and
                    // dropped, so the agent's self-reported failures (denylisted
                    // queries, extension crashes, permission errors) were invisible
                    // server-side. Persist them for operability/forensics.
                    //
                    // NOTE FOR ORCHESTRATOR: this uses a prepared statement
                    // "status_log_add" and a table "status_logs" that must be added
                    // in fleet_main.cpp / schema.sql (see agent report). If the
                    // statement is not yet registered the insert throws and is caught
                    // below, so ingestion of result logs is unaffected.
                    auto status_entries = logger_data["data"];
                    if (status_entries.is_array())
                    {
                        for (const auto &entry : status_entries)
                        {
                            try
                            {
                                // hostIdentifier in the entry is echoed back by the
                                // agent; trust the node_key-derived host_identifier.
                                long unixTime = 0;
                                if (entry.contains("unixTime"))
                                {
                                    const auto &ut = entry["unixTime"];
                                    if (ut.is_number()) unixTime = ut.get<long>();
                                    else if (ut.is_string()) unixTime = atol(ut.get<std::string>().c_str());
                                }
                                if (unixTime == 0) unixTime = std::time(nullptr);

                                long severity = 0;
                                if (entry.contains("severity"))
                                {
                                    const auto &sv = entry["severity"];
                                    if (sv.is_number()) severity = sv.get<long>();
                                    else if (sv.is_string()) severity = atol(sv.get<std::string>().c_str());
                                }

                                long line = 0;
                                if (entry.contains("line"))
                                {
                                    const auto &ln = entry["line"];
                                    if (ln.is_number()) line = ln.get<long>();
                                    else if (ln.is_string()) line = atol(ln.get<std::string>().c_str());
                                }

                                std::string filename = entry.contains("filename") && entry["filename"].is_string()
                                                           ? entry["filename"].get<std::string>() : "";
                                std::string message = entry.contains("message") && entry["message"].is_string()
                                                          ? entry["message"].get<std::string>() : "";
                                std::string version = entry.contains("version") && entry["version"].is_string()
                                                          ? entry["version"].get<std::string>() : "";
                                std::string decorations = entry.contains("decorations")
                                                              ? entry["decorations"].dump() : std::string("{}");

                                transaction->exec_prepared("status_log_add", host_identifier, unixTime,
                                                           severity, filename, line, message, version, decorations);
                            }
                            catch (const nlohmann::json::exception &e)
                            {
                                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping malformed status log entry from "
                                                           << host_identifier << ": " << e.what();
                            }
                        }
                        try { transaction->commit(); }
                        catch (const std::exception &e)
                        {
                            // Most likely the status_logs table / status_log_add
                            // statement is not yet provisioned. Log once; result-log
                            // ingestion is unaffected.
                            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Could not persist status logs from "
                                                       << host_identifier << " (status_logs table/statement missing?): "
                                                       << e.what();
                            try { transaction->abort(); } catch (...) {}
                            transaction = std::make_unique<pqxx::work>(*connection);
                        }
                    }
                }
            }
            catch (pqxx::sql_error const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (std::exception const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (...)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
        }
        else if (!logger_data.contains("node_key"))
        {
            // osquery TLS protocol: a /log POST without a node_key cannot be
            // authenticated. Previously this fell through and returned an empty
            // {} + 200, which osquery treats as an accepted response and keeps
            // retrying with the same (missing) key forever. Signal node_invalid so
            // the agent drops its state and re-enrolls, matching /config, /read
            // and /write.
            log_response["node_invalid"] = true;
        }
    }
    catch (const nlohmann::json::parse_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: could not parse JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (const nlohmann::json::type_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: invalid type encountered in JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (std::exception const &e)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }

    auto end = std::chrono::high_resolution_clock::now();

    // Calculate the elapsed time in different units
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Output the time taken
    BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Endpoint: /log, time taken: " << duration.count() << " microseconds";

    std::string reply = log_response.dump();
    response.status = request_failed ? failure_status : http::status::ok;
    response.body = reply;
    response.header["Content-Type"] = "application/json";
    return response;
}

HTTPMessage distributed_read(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;

    nlohmann::json log_response;
    // Set from a catch below on any server/parse failure so the tail code
    // doesn't unconditionally report success (see logger()'s identical fix
    // for the full rationale).
    bool request_failed = false;
    http::status failure_status = http::status::internal_server_error;

    try
    {
        auto logger_data = nlohmann::json::parse(request.body);
        if (logger_data.contains("node_key"))
        {
            std::string key = logger_data["node_key"];
            std::string host_identifier;

            try
            {
                pqxx::work transaction{*connection};

                pqxx::result result = transaction.exec_prepared("validate_node_key", key);
                if (result.size() == 1)
                {
                    host_identifier = result.at(0)["host_identifier"].as<std::string>();
                    log_response["node_invalid"] = false;
                    // Always present, even when idle: the osquery distributed/read
                    // contract is {"queries": {...}} with an empty object when no
                    // queries are pending. Omitting the key entirely is a spec
                    // deviation some clients handle defensively but not all.
                    log_response["queries"] = nlohmann::json::object();
                    result = transaction.exec_prepared("get_scheduled_query", host_identifier);
                    long last_seen;
                    std::time_t t = std::time(0);
                    last_seen = t;
                    pqxx::result queries = transaction.exec_prepared("update_last_seen", last_seen, host_identifier);
                    transaction.commit();

                    for (int i = 0; i < static_cast<int>(result.size()); ++i)
                    {
                        unsigned long long query_key = result.at(i)["id"].as<unsigned long long>();
                        std::string query = result.at(i)["query"].as<std::string>();

                        // Key the response by the queue id: osquery echoes this key back to
                        // /write, and the UI polls query_result by the same id
                        // (schedule_query_response). /write derives the table name for
                        // dedicated-table routing by looking the id up in query_queue.
                        log_response["queries"][std::to_string(query_key)] = query;

                        long unixTime = std::time(nullptr);

                        pqxx::work update_txn{*connection};
                        update_txn.exec_prepared("stop_scheduled_query", query_key, unixTime);
                        update_txn.commit();
                    }
                }
                else
                {
                    log_response["node_invalid"] = true;
                }
            }
            catch (pqxx::sql_error const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (std::exception const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (...)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
        }
        else
        {
            // osquery TLS protocol: no node_key means the request cannot be
            // authenticated — signal node_invalid like an invalid key does.
            log_response["node_invalid"] = true;
        }
    }
    catch (const nlohmann::json::parse_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: could not parse JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (const nlohmann::json::type_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: invalid type encountered in JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (std::exception const &e)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }

    std::string reply = log_response.dump();
    response.status = request_failed ? failure_status : http::status::ok;
    response.body = reply;
    response.header["Content-Type"] = "application/json";
    return response;
}

HTTPMessage distributed_write(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;
    nlohmann::json log_response;

    int total_queries = 0;
    int successful_inserts = 0;
    int failed_inserts = 0;
    std::string current_table = "unknown";
    // Set from a catch below on any server/parse failure so the tail code
    // doesn't unconditionally report success (see logger()'s identical fix
    // for the full rationale).
    bool request_failed = false;
    http::status failure_status = http::status::internal_server_error;

    try
    {
        auto logger_data = nlohmann::json::parse(request.body);

        // Never log the node_key: it is a per-host bearer credential and log
        // readers could replay a host's identity. Log only its presence.
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "distributed_write called (node_key "
                                << (logger_data.contains("node_key") ? "present" : "MISSING") << ")";

        if (logger_data.contains("node_key"))
        {
            std::string key = logger_data["node_key"];
            std::string host_identifier;
            bool isKeyValid = false;

            try
            {
                pqxx::work transaction{*connection};

                pqxx::result result = transaction.exec_prepared("validate_node_key", key);
                if (result.size() == 1)
                {
                    isKeyValid = true;
                    host_identifier = result.at(0)["host_identifier"].as<std::string>();
                    log_response["node_invalid"] = false;

                    BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Valid node_key for host: " << host_identifier;
                    long last_seen;
                    std::time_t t = std::time(0);
                    last_seen = t;
                    pqxx::result queries = transaction.exec_prepared("update_last_seen", last_seen, host_identifier);
                    transaction.commit();
                }
                else
                {
                    log_response["node_invalid"] = true;
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Invalid node_key in distributed_write (key not logged)";
                    response.body = log_response.dump();
                    response.status = http::status::unauthorized;
                    return response;
                }

                if (isKeyValid && logger_data.contains("queries"))
                {
                    auto entries = logger_data["queries"];

                    // osquery TLS distributed_write payload also carries a per-query
                    // "statuses" object and a human-readable "messages" object, both
                    // keyed by the same query id as "queries". A non-zero status means
                    // that distributed query FAILED on the host and its "queries"
                    // entry is an empty/partial result — storing it as a successful
                    // result silently corrupts the forensic record (H5). Capture both
                    // so the per-query loop can distinguish real 0-row results from
                    // host-side failures.
                    const nlohmann::json empty_obj = nlohmann::json::object();
                    const nlohmann::json &statuses =
                        (logger_data.contains("statuses") && logger_data["statuses"].is_object())
                            ? logger_data["statuses"] : empty_obj;
                    const nlohmann::json &messages =
                        (logger_data.contains("messages") && logger_data["messages"].is_object())
                            ? logger_data["messages"] : empty_obj;

                    if (entries.is_array())
                    {
                        // osquery sends distributed results as an object keyed by query id;
                        // an array here means a protocol mismatch — surface it instead of
                        // silently dropping the batch.
                        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "distributed_write: unexpected array 'queries' payload from "
                                                 << host_identifier << " — batch not processed";
                    }
                    else
                    {
                        for (auto entry : entries.items())
                        {
                            try {
                                std::string query_name = entry.key();
                                std::string query_result = entry.value().dump();
                                current_table = query_name;
                                total_queries++;

                                // Determine whether this query succeeded on the host.
                                // osquery status codes are integers; 0 == success, any
                                // non-zero value == the query failed (SQL error, missing
                                // table, permission denied, etc.). The status may be sent
                                // as a JSON number or as a numeric string.
                                long query_status = 0;
                                if (statuses.contains(query_name))
                                {
                                    const auto &st = statuses.at(query_name);
                                    try {
                                        if (st.is_number_integer())      query_status = st.get<long>();
                                        else if (st.is_number())         query_status = static_cast<long>(st.get<double>());
                                        else if (st.is_string())         query_status = atol(st.get<std::string>().c_str());
                                    } catch (...) { query_status = 0; }
                                }

                                if (query_status != 0)
                                {
                                    // Host-side failure: do NOT record the empty result as a
                                    // success. Persist the failure to the dead_letter_queue so
                                    // it stays queryable for forensics, and skip both the
                                    // dedicated-table routing and the Kafka publish below.
                                    std::string fail_msg = "distributed query failed on host (status="
                                                           + std::to_string(query_status) + ")";
                                    if (messages.contains(query_name))
                                    {
                                        try {
                                            fail_msg += ": " + (messages.at(query_name).is_string()
                                                                    ? messages.at(query_name).get<std::string>()
                                                                    : messages.at(query_name).dump());
                                        } catch (...) {}
                                    }
                                    failed_inserts++;
                                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "distributed query " << query_name
                                                               << " reported FAILED by " << host_identifier
                                                               << " (status=" << query_status << ") — not stored as success";
                                    try {
                                        pqxx::work fail_txn{*connection};
                                        fail_txn.exec_params(
                                            "INSERT INTO dead_letter_queue (event_id, table_name, error_message, event_data) "
                                            "VALUES ($1, $2, $3, $4)",
                                            0, query_name, fail_msg, query_result);
                                        fail_txn.commit();
                                    } catch (...) {
                                        BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                            << "Failed to record failed distributed query to dead_letter_queue";
                                    }
                                    continue;
                                }

                                BOOST_LOG_TRIVIAL(debug) << __SRCREF__ << "Processing query: " << query_name
                                                         << " for host: " << host_identifier
                                                         << " data_size: " << query_result.length();

                                long unixTime = std::time(nullptr);
                                
                                // PRODUCTION EDR: Dual-write pattern for real-time + forensics
                                
                                // 1. Write to PostgreSQL for forensic storage (blocking)
                                {
                                    pqxx::work query_txn{*connection};
                                    query_txn.exec_prepared("query_result_add", host_identifier, unixTime, query_name, query_result);
                                    query_txn.commit();
                                }
                                successful_inserts++;

                                // Derive the routing name. Distributed results arrive keyed by the
                                // query_queue id (so the UI can correlate results); for simple
                                // "select * from TABLE" queries look up the original query text and
                                // extract the table name so results also land in dedicated tables.
                                std::string route_name = query_name;
                                if (!query_name.empty() &&
                                    std::all_of(query_name.begin(), query_name.end(),
                                                [](unsigned char c) { return std::isdigit(c); }))
                                {
                                    try
                                    {
                                        pqxx::work lookup_txn{*connection};
                                        pqxx::result queued = lookup_txn.exec_params(
                                            "select query from query_queue where id = $1", std::stoll(query_name));
                                        lookup_txn.commit();
                                        if (!queued.empty() && !queued.at(0)["query"].is_null())
                                        {
                                            std::string lq = queued.at(0)["query"].as<std::string>();
                                            std::transform(lq.begin(), lq.end(), lq.begin(), ::tolower);
                                            const std::string prefix = "select * from ";
                                            if (lq.rfind(prefix, 0) == 0)
                                            {
                                                std::string tbl = lq.substr(prefix.size());
                                                tbl.erase(0, tbl.find_first_not_of(" \t"));
                                                auto tbl_end = tbl.find_first_of(" \t;\r\n");
                                                if (tbl_end != std::string::npos) tbl = tbl.substr(0, tbl_end);
                                                if (!tbl.empty()) route_name = tbl;
                                            }
                                        }
                                    }
                                    catch (const std::exception &e)
                                    {
                                        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "query_queue lookup failed for id "
                                                                   << query_name << ": " << e.what();
                                    }
                                }

                                // Route initial enrollment snapshot queries to dedicated tables
                                {
                                    nlohmann::json rows;
                                    try { rows = nlohmann::json::parse(query_result); } catch (...) {}
                                    if (rows.is_array() && !rows.empty())
                                    {
                                        if (route_name == "secureboot")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                int secure_boot = 0, setup_mode = 0;
                                                if (row.contains("secure_boot"))  { try { secure_boot = std::stoi(row["secure_boot"].get<std::string>());  } catch (...) {} }
                                                if (row.contains("setup_mode"))   { try { setup_mode  = std::stoi(row["setup_mode"].get<std::string>());   } catch (...) {} }
                                                t.exec_prepared("secureboot", host_identifier, unixTime, secure_boot, setup_mode);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "tpm_info")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string mfr_ver  = row.contains("manufacturer_version")       ? row["manufacturer_version"].get<std::string>()       : "";
                                                std::string mfr_name = row.contains("manufacturer_name")          ? row["manufacturer_name"].get<std::string>()          : "";
                                                std::string prod     = row.contains("product_name")               ? row["product_name"].get<std::string>()               : "";
                                                std::string pp_ver   = row.contains("physical_presence_version")  ? row["physical_presence_version"].get<std::string>()  : "";
                                                std::string spec_ver = row.contains("spec_version")               ? row["spec_version"].get<std::string>()               : "";
                                                int act = 0, ena = 0, own = 0, mfr_id = 0;
                                                if (row.contains("activated"))       { try { act    = std::stoi(row["activated"].get<std::string>());       } catch (...) {} }
                                                if (row.contains("enabled"))         { try { ena    = std::stoi(row["enabled"].get<std::string>());         } catch (...) {} }
                                                if (row.contains("owned"))           { try { own    = std::stoi(row["owned"].get<std::string>());           } catch (...) {} }
                                                if (row.contains("manufacturer_id")) { try { mfr_id = std::stoi(row["manufacturer_id"].get<std::string>()); } catch (...) {} }
                                                t.exec_prepared("tpm_info", host_identifier, unixTime, act, ena, own, mfr_ver, mfr_id, mfr_name, prod, pp_ver, spec_ver);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "windows_firewall_rules")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string name   = row.contains("name")             ? row["name"].get<std::string>()             : "";
                                                std::string app    = row.contains("app_name")         ? row["app_name"].get<std::string>()         : "";
                                                std::string act    = row.contains("action")           ? row["action"].get<std::string>()           : "";
                                                std::string grp    = row.contains("grouping")         ? row["grouping"].get<std::string>()         : "";
                                                std::string dir    = row.contains("direction")        ? row["direction"].get<std::string>()        : "";
                                                std::string proto  = row.contains("protocol")         ? row["protocol"].get<std::string>()         : "";
                                                std::string laddr  = row.contains("local_addresses")  ? row["local_addresses"].get<std::string>()  : "";
                                                std::string raddr  = row.contains("remote_addresses") ? row["remote_addresses"].get<std::string>() : "";
                                                std::string lport  = row.contains("local_ports")      ? row["local_ports"].get<std::string>()      : "";
                                                std::string rport  = row.contains("remote_ports")     ? row["remote_ports"].get<std::string>()     : "";
                                                std::string icmp   = row.contains("icmp_types_codes") ? row["icmp_types_codes"].get<std::string>() : "";
                                                std::string svc    = row.contains("service_name")     ? row["service_name"].get<std::string>()     : "";
                                                int ena=0, pd=0, pp=0, pb=0;
                                                if (row.contains("enabled"))         { try { ena = std::stoi(row["enabled"].get<std::string>());         } catch (...) {} }
                                                if (row.contains("profile_domain"))  { try { pd  = std::stoi(row["profile_domain"].get<std::string>());  } catch (...) {} }
                                                if (row.contains("profile_private")) { try { pp  = std::stoi(row["profile_private"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("profile_public"))  { try { pb  = std::stoi(row["profile_public"].get<std::string>());  } catch (...) {} }
                                                t.exec_prepared("windows_firewall_rules", host_identifier, unixTime, name, app, act, ena, grp, dir, proto, laddr, raddr, lport, rport, icmp, pd, pp, pb, svc);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "windows_update_history")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string app_id  = row.contains("client_app_id")   ? row["client_app_id"].get<std::string>()   : "";
                                                std::string desc    = row.contains("description")     ? row["description"].get<std::string>()     : "";
                                                std::string op      = row.contains("operation")       ? row["operation"].get<std::string>()       : "";
                                                std::string rc      = row.contains("result_code")     ? row["result_code"].get<std::string>()     : "";
                                                std::string ss      = row.contains("server_selection")? row["server_selection"].get<std::string>(): "";
                                                std::string sid     = row.contains("service_id")      ? row["service_id"].get<std::string>()      : "";
                                                std::string url     = row.contains("support_url")     ? row["support_url"].get<std::string>()     : "";
                                                std::string title   = row.contains("title")           ? row["title"].get<std::string>()           : "";
                                                std::string uid     = row.contains("update_id")       ? row["update_id"].get<std::string>()       : "";
                                                long long date = 0, hres = 0, urev = 0;
                                                if (row.contains("date"))            { try { date = std::stoll(row["date"].get<std::string>());            } catch (...) {} }
                                                if (row.contains("hresult"))         { try { hres = std::stoll(row["hresult"].get<std::string>());         } catch (...) {} }
                                                if (row.contains("update_revision")) { try { urev = std::stoll(row["update_revision"].get<std::string>()); } catch (...) {} }
                                                t.exec_prepared("windows_update_history", host_identifier, unixTime, app_id, date, desc, hres, op, rc, ss, sid, url, title, uid, urev);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "disk_info")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string disk_id        = row.contains("disk_id")        ? row["disk_id"].get<std::string>()        : "";
                                                std::string pnp_device_id  = row.contains("pnp_device_id")  ? row["pnp_device_id"].get<std::string>()  : "";
                                                std::string type           = row.contains("type")           ? row["type"].get<std::string>()           : "";
                                                std::string manufacturer   = row.contains("manufacturer")   ? row["manufacturer"].get<std::string>()   : "";
                                                std::string hardware_model = row.contains("hardware_model") ? row["hardware_model"].get<std::string>() : "";
                                                std::string name           = row.contains("name")           ? row["name"].get<std::string>()           : "";
                                                std::string serial         = row.contains("serial")         ? row["serial"].get<std::string>()         : "";
                                                std::string description    = row.contains("description")    ? row["description"].get<std::string>()    : "";
                                                int partitions = 0, disk_index = 0;
                                                long long disk_size = 0;
                                                if (row.contains("partitions")) { try { partitions = std::stoi(row["partitions"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("disk_index")) { try { disk_index = std::stoi(row["disk_index"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("disk_size"))  { try { disk_size  = std::stoll(row["disk_size"].get<std::string>()); } catch (...) {} }
                                                t.exec_prepared("disk_info", host_identifier, unixTime,
                                                                partitions, disk_index, type, disk_id, pnp_device_id,
                                                                disk_size, manufacturer, hardware_model, name, serial, description);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "disk_encryption")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string name              = row.contains("name")              ? row["name"].get<std::string>()              : "";
                                                std::string uuid              = row.contains("uuid")              ? row["uuid"].get<std::string>()              : "";
                                                std::string type              = row.contains("type")              ? row["type"].get<std::string>()              : "";
                                                std::string encryption_status = row.contains("encryption_status") ? row["encryption_status"].get<std::string>() : "";
                                                std::string uid               = row.contains("uid")               ? row["uid"].get<std::string>()               : "";
                                                std::string user_uuid         = row.contains("user_uuid")         ? row["user_uuid"].get<std::string>()         : "";
                                                std::string filevault_status  = row.contains("filevault_status")  ? row["filevault_status"].get<std::string>()  : "";
                                                int encrypted = 0;
                                                if (row.contains("encrypted")) { try { encrypted = std::stoi(row["encrypted"].get<std::string>()); } catch (...) {} }
                                                t.exec_prepared("disk_encryption", host_identifier, unixTime,
                                                                name, uuid, encrypted, type,
                                                                encryption_status, uid, user_uuid, filevault_status);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "memory_devices")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string handle              = row.contains("handle")               ? row["handle"].get<std::string>()               : "";
                                                std::string array_handle        = row.contains("array_handle")         ? row["array_handle"].get<std::string>()         : "";
                                                std::string form_factor         = row.contains("form_factor")          ? row["form_factor"].get<std::string>()          : "";
                                                std::string device_locator      = row.contains("device_locator")       ? row["device_locator"].get<std::string>()       : "";
                                                std::string bank_locator        = row.contains("bank_locator")         ? row["bank_locator"].get<std::string>()         : "";
                                                std::string memory_type         = row.contains("memory_type")          ? row["memory_type"].get<std::string>()          : "";
                                                std::string memory_type_details = row.contains("memory_type_details")  ? row["memory_type_details"].get<std::string>()  : "";
                                                std::string manufacturer        = row.contains("manufacturer")         ? row["manufacturer"].get<std::string>()         : "";
                                                std::string serial_number       = row.contains("serial_number")        ? row["serial_number"].get<std::string>()        : "";
                                                std::string asset_tag           = row.contains("asset_tag")            ? row["asset_tag"].get<std::string>()            : "";
                                                std::string part_number         = row.contains("part_number")          ? row["part_number"].get<std::string>()          : "";
                                                int total_width = 0, data_width = 0, size = 0, set_field = 0;
                                                int max_speed = 0, configured_clock_speed = 0;
                                                int min_voltage = 0, max_voltage = 0, configured_voltage = 0;
                                                if (row.contains("total_width"))            { try { total_width            = std::stoi(row["total_width"].get<std::string>());            } catch (...) {} }
                                                if (row.contains("data_width"))             { try { data_width             = std::stoi(row["data_width"].get<std::string>());             } catch (...) {} }
                                                if (row.contains("size"))                   { try { size                   = std::stoi(row["size"].get<std::string>());                   } catch (...) {} }
                                                if (row.contains("set"))                    { try { set_field              = std::stoi(row["set"].get<std::string>());                    } catch (...) {} }
                                                if (row.contains("max_speed"))              { try { max_speed              = std::stoi(row["max_speed"].get<std::string>());              } catch (...) {} }
                                                if (row.contains("configured_clock_speed")) { try { configured_clock_speed = std::stoi(row["configured_clock_speed"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("min_voltage"))            { try { min_voltage            = std::stoi(row["min_voltage"].get<std::string>());            } catch (...) {} }
                                                if (row.contains("max_voltage"))            { try { max_voltage            = std::stoi(row["max_voltage"].get<std::string>());            } catch (...) {} }
                                                if (row.contains("configured_voltage"))     { try { configured_voltage     = std::stoi(row["configured_voltage"].get<std::string>());     } catch (...) {} }
                                                t.exec_prepared("memory_devices", host_identifier, unixTime,
                                                                handle, array_handle, form_factor,
                                                                total_width, data_width, size, set_field,
                                                                device_locator, bank_locator, memory_type, memory_type_details,
                                                                max_speed, configured_clock_speed,
                                                                manufacturer, serial_number, asset_tag, part_number,
                                                                min_voltage, max_voltage, configured_voltage);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "mounts")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string device        = row.contains("device")         ? row["device"].get<std::string>()         : "";
                                                std::string device_alias  = row.contains("device_alias")   ? row["device_alias"].get<std::string>()   : "";
                                                std::string path          = row.contains("path")           ? row["path"].get<std::string>()           : "";
                                                std::string type          = row.contains("type")           ? row["type"].get<std::string>()           : "";
                                                std::string flags         = row.contains("flags")          ? row["flags"].get<std::string>()          : "";
                                                long long blocks_size = 0, blocks = 0, blocks_free = 0, blocks_available = 0;
                                                long long inodes = 0, inodes_free = 0;
                                                if (row.contains("blocks_size"))      { try { blocks_size      = std::stoll(row["blocks_size"].get<std::string>());      } catch (...) {} }
                                                if (row.contains("blocks"))           { try { blocks           = std::stoll(row["blocks"].get<std::string>());           } catch (...) {} }
                                                if (row.contains("blocks_free"))      { try { blocks_free      = std::stoll(row["blocks_free"].get<std::string>());      } catch (...) {} }
                                                if (row.contains("blocks_available")) { try { blocks_available = std::stoll(row["blocks_available"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("inodes"))           { try { inodes           = std::stoll(row["inodes"].get<std::string>());           } catch (...) {} }
                                                if (row.contains("inodes_free"))      { try { inodes_free      = std::stoll(row["inodes_free"].get<std::string>());      } catch (...) {} }
                                                t.exec_prepared("mounts", host_identifier, unixTime,
                                                                device, device_alias, path, type,
                                                                blocks_size, blocks, blocks_free, blocks_available,
                                                                inodes, inodes_free, flags);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "bitlocker_info")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string device_id            = row.contains("device_id")            ? row["device_id"].get<std::string>()            : "";
                                                std::string drive_letter         = row.contains("drive_letter")         ? row["drive_letter"].get<std::string>()         : "";
                                                std::string persistent_volume_id = row.contains("persistent_volume_id") ? row["persistent_volume_id"].get<std::string>() : "";
                                                std::string encryption_method    = row.contains("encryption_method")    ? row["encryption_method"].get<std::string>()    : "";
                                                int conversion_status = 0, protection_status = 0, version = 0;
                                                int percentage_encrypted = 0, lock_status = 0;
                                                if (row.contains("conversion_status"))    { try { conversion_status    = std::stoi(row["conversion_status"].get<std::string>());    } catch (...) {} }
                                                if (row.contains("protection_status"))    { try { protection_status    = std::stoi(row["protection_status"].get<std::string>());    } catch (...) {} }
                                                if (row.contains("version"))              { try { version              = std::stoi(row["version"].get<std::string>());              } catch (...) {} }
                                                if (row.contains("percentage_encrypted")) { try { percentage_encrypted = std::stoi(row["percentage_encrypted"].get<std::string>()); } catch (...) {} }
                                                if (row.contains("lock_status"))          { try { lock_status          = std::stoi(row["lock_status"].get<std::string>());          } catch (...) {} }
                                                t.exec_prepared("bitlocker_info", host_identifier, unixTime,
                                                                device_id, drive_letter, persistent_volume_id,
                                                                conversion_status, protection_status, encryption_method,
                                                                version, percentage_encrypted, lock_status);
                                            }
                                            t.commit();
                                        }
                                        else if (route_name == "logical_drives")
                                        {
                                            pqxx::work t{*connection};
                                            for (const auto& row : rows)
                                            {
                                                std::string device_id   = row.contains("device_id")   ? row["device_id"].get<std::string>()   : "";
                                                std::string type        = row.contains("type")        ? row["type"].get<std::string>()        : "";
                                                std::string description = row.contains("description") ? row["description"].get<std::string>() : "";
                                                std::string file_system = row.contains("file_system") ? row["file_system"].get<std::string>() : "";
                                                long long free_space = -1, size = -1;
                                                int boot_partition = 0;
                                                if (row.contains("free_space"))     { try { free_space     = std::stoll(row["free_space"].get<std::string>());     } catch (...) {} }
                                                if (row.contains("size"))           { try { size           = std::stoll(row["size"].get<std::string>());           } catch (...) {} }
                                                if (row.contains("boot_partition")) { try { boot_partition = std::stoi(row["boot_partition"].get<std::string>());  } catch (...) {} }
                                                t.exec_prepared("logical_drives", host_identifier, unixTime,
                                                                device_id, type, description,
                                                                free_space, size, file_system, boot_partition);
                                            }
                                            t.commit();
                                        }
                                    }
                                }

                                BOOST_LOG_TRIVIAL(trace) << __SRCREF__ << "Successfully stored " << query_name
                                                         << " in DB for " << host_identifier;

                                // 2. Publish to Kafka for real-time detection (non-blocking, best-effort)
                                auto& kafka_producer = KafkaProducerManager::getInstance();
                                if (kafka_producer.isInitialized())
                                {
                                    // Parse and publish individual events from query result
                                    try {
                                        nlohmann::json result_array = nlohmann::json::parse(query_result);
                                        
                                        if (result_array.is_array() && !result_array.empty())
                                        {
                                            // Derive event_type from query_name for 2-topic routing
                                            std::string event_type_val;
                                            if (route_name == "bpf_process_events") event_type_val = "bpf_process";
                                            else if (route_name == "bpf_socket_events") event_type_val = "bpf_socket";
                                            else if (route_name == "bpf_file_events") event_type_val = "bpf_file";
                                            else if (route_name == "win_process_events") event_type_val = "win_process";
                                            else if (route_name == "win_socket_events") event_type_val = "win_socket";
                                            else if (route_name == "win_file_events") event_type_val = "win_file";
                                            else if (route_name == "win_dns_events") event_type_val = "win_dns";
                                            else if (route_name == "win_dns_response_events") event_type_val = "win_dns_response";
                                            else if (route_name == "win_ssl_events") event_type_val = "win_ssl";
                                            else if (route_name == "win_http_events") event_type_val = "win_http";
                                            else if (route_name == "win_registry_events") event_type_val = "win_registry";
                                            else if (route_name == "win_image_load_events") event_type_val = "win_image_load";

                                            // Safety net: never publish an event without an event_type. A
                                            // downstream Kafka consumer keys on it and will reject/throw on a
                                            // message that lacks it, silently dropping telemetry. For any table
                                            // not explicitly mapped above, derive the type from the table name
                                            // by dropping a trailing "_events".
                                            if (event_type_val.empty())
                                            {
                                                event_type_val = route_name;
                                                static const std::string kEventsSuffix = "_events";
                                                if (event_type_val.size() > kEventsSuffix.size() &&
                                                    event_type_val.compare(event_type_val.size() - kEventsSuffix.size(),
                                                                           kEventsSuffix.size(), kEventsSuffix) == 0)
                                                {
                                                    event_type_val.erase(event_type_val.size() - kEventsSuffix.size());
                                                }
                                            }

                                            int kafka_sent = 0;
                                            for (const auto& event : result_array)
                                            {
                                                nlohmann::json enriched = event;
                                                if (!event_type_val.empty()) {
                                                    enriched["event_type"] = event_type_val;
                                                }
                                                std::string event_str = enriched.dump();
                                                if (kafka_producer.publishEvent(route_name, event_str, host_identifier))
                                                {
                                                    kafka_sent++;
                                                }
                                            }
                                            
                                            BOOST_LOG_TRIVIAL(trace) << __SRCREF__ << "Published " << kafka_sent 
                                                                     << "/" << result_array.size()
                                                                     << " events to Kafka topic for " << query_name;
                                        }
                                    }
                                    catch (const nlohmann::json::exception& e)
                                    {
                                        // Non-blocking: log kafka publish failure but don't fail the request
                                        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Failed to parse/publish to Kafka for " 
                                                                   << query_name << ": " << e.what()
                                                                   << " (data still persisted in DB)";
                                    }
                                }
                            }
                            catch (pqxx::sql_error const &e) {
                                failed_inserts++;
                                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "FAILED to store " << current_table
                                                         << " for " << host_identifier
                                                         << " ERROR: " << e.what()
                                                         << " QUERY: " << e.query();

                                // Log to dead letter queue
                                try {
                                    pqxx::work dlq_txn{*connection};
                                    dlq_txn.exec_params(
                                        "INSERT INTO dead_letter_queue (event_id, table_name, error_message, event_data) "
                                        "VALUES ($1, $2, $3, $4)",
                                        0, current_table, e.what(), entry.value().dump()
                                    );
                                    dlq_txn.commit();
                                } catch (...) {
                                    BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "CRITICAL: Failed to log to dead_letter_queue!";
                                }
                            }
                            catch (const nlohmann::json::exception &e) {
                                // Field extraction failed (e.g. a snapshot row's
                                // column has an unexpected JSON type) before any
                                // DB write for THIS query completed -- skip only
                                // this query and keep processing the rest of the
                                // batch. Without this arm the exception fell
                                // through to the outer pqxx::sql_error/
                                // std::exception handlers below, which abort the
                                // whole `for (auto entry : entries.items())` loop
                                // and silently drop every query still queued
                                // after this one (matches the per-entry isolation
                                // logger() already does for the same failure mode).
                                failed_inserts++;
                                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping malformed distributed_write query "
                                                           << current_table << " for " << host_identifier
                                                           << ": " << e.what();
                            }
                        }
                    }
                }

                BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "distributed_write summary for " << host_identifier
                                        << " - Total: " << total_queries
                                        << " Success: " << successful_inserts
                                        << " Failed: " << failed_inserts;

                if (failed_inserts > 0) {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "DATA LOSS WARNING: " << failed_inserts
                                               << " queries failed for " << host_identifier
                                               << " - Check dead_letter_queue table!";
                }
            }
            catch (pqxx::sql_error const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (std::exception const &e)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
            catch (...)
            {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
                request_failed = true;
                failure_status = http::status::internal_server_error;
            }
        }
        else
        {
            // osquery TLS protocol: no node_key means the request cannot be
            // authenticated — mirror the invalid-node_key response above.
            log_response["node_invalid"] = true;
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Missing node_key in distributed_write";
            response.body = log_response.dump();
            response.status = http::status::unauthorized;
            response.header["Content-Type"] = "application/json";
            return response;
        }
    }
    catch (const nlohmann::json::parse_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: could not parse JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (const nlohmann::json::type_error &error)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Error: invalid type encountered in JSON. Parse error: " << error.what();
        request_failed = true;
        failure_status = http::status::bad_request;
    }
    catch (std::exception const &e)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error: " << e.what();
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error";
        request_failed = true;
        failure_status = http::status::internal_server_error;
    }

    std::string reply = log_response.dump();
    response.status = request_failed ? failure_status : http::status::ok;
    response.body = reply;
    response.header["Content-Type"] = "application/json";
    return response;
}
