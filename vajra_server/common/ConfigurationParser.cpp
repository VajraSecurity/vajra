#include "ConfigurationParser.h"
#include "../3rdparty/json.hpp"

#include <boost/algorithm/string.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

DatabaseConfiguration::DatabaseConfiguration() {
    this->port = 0;
}

DatabaseInternetConfiguration::DatabaseInternetConfiguration() {
    this->port = 0;
}

std::string DatabaseConfiguration::ConnectionString() {
    std::stringstream connection_string;

    connection_string << "postgresql://" << this->username;

    if (this->password != "") {
        connection_string << ":" << this->password;
    }

    connection_string << "@" << this->hostname;

    if (this->port > 0)
        connection_string << ":" << std::to_string(this->port);

    connection_string << "/" << this->database_name;

    return connection_string.str();
}

std::string DatabaseInternetConfiguration::ConnectionVaString() {
    std::stringstream connection_string;

    connection_string << "postgresql://" << this->username;

    if (this->password != "") {
        connection_string << ":" << this->password;
    }

    connection_string << "@" << this->hostname;

    if (this->port > 0)
        connection_string << ":" << std::to_string(this->port);

    connection_string << "/" << this->database_name;

    return connection_string.str();
}

DatabasePoolConfiguration::DatabasePoolConfiguration() {
    this->maximum_connections = 0;
}

RuleEngineKafkaConfiguration::RuleEngineKafkaConfiguration()
    : bootstrap_servers("localhost:9092")
    , consumer_group_id("vajra-engine")
    , security_protocol("PLAINTEXT")
    , session_timeout_ms(30000)
    , max_poll_interval_ms(300000)
{}

ThreatIntelFeedConfiguration::ThreatIntelFeedConfiguration()
    : enabled(true)
    , target_list("deny_ips")
    , refresh_interval_seconds(3600)
    , max_entries(50000)
    , stix_types({"ip"})
{}

ThreatIntelligenceConfiguration::ThreatIntelligenceConfiguration()
    : enabled(false)
    , cache_ttl_seconds(3600)
{}

RuleEngineMetricsConfiguration::RuleEngineMetricsConfiguration()
    : enabled(false)
    , bind_address("127.0.0.1")
    , port(9105)
{}

RuleEngineConfiguration::RuleEngineConfiguration()
    : db_connection_pool_size(10)
{}

ConfigurationParser::ConfigurationParser(std::string path) {
    this->configuration_file = std::move(path);
}

ServerConfiguration::ServerConfiguration() {
    this->port = 1234;
}

LogConfiguration::LogConfiguration() {
    this->log_size = -1;
    this->log_level = 3; // default to warning
    this->console_output = false;
}

AccessControlConfiguration::AccessControlConfiguration()
{
    this->allow_credentials = true;
    this->max_age = 86400;
    this->allow_origin = "*";
}

NodeConfiguration::NodeConfiguration()
{
    this->max_enrolled_devices = 1000;
    this->max_pending_enrollments = 100;
    this->require_enrollment_approval = false;
    this->auto_revoke_inactive_days = 90;
    this->node_key_length = 64;
    this->node_key_expiry_days = 365;
    this->allow_reenrollment = true;
    this->enrollment_rate_limit.enabled = true;
    this->enrollment_rate_limit.max_per_ip_per_hour = 5;
    this->enrollment_rate_limit.max_per_day = 50;
}

bool ConfigurationParser::parse_api_config() {
    // Not currently called by parse() (see api_server's callers for whether
    // that's intentional), but wrapped for the same reason as the sections
    // parse() does call: extensive nlohmann::json field access below with no
    // local exception handling would otherwise throw straight through to
    // whatever ever calls this directly, on the first malformed field.
    try {
    nlohmann::json fleet_config;

    if (config_data.contains("api_server"))
    {
        fleet_config = config_data["api_server"];
    }
    else
    {
        std::cerr << "Fleet server configuration parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (fleet_config.contains("server_configuration"))
    {
        auto server_config = fleet_config["server_configuration"];

        if (server_config.contains("hostname"))
        {
            api_server.server.hostname = server_config["hostname"].get<std::string>();
        }
        else
        {
            api_server.server.hostname = "0.0.0.0";
        }

        if (server_config.contains("port"))
        {
            api_server.server.port = server_config["port"].get<unsigned int>();
        }
        else
        {
            api_server.server.port = 1234;
        }

        if (server_config.contains("ssl_certificate"))
        {
            api_server.ssl_configuration.ssl_certificate_file = server_config["ssl_certificate"].get<std::string>();
        }
        if (server_config.contains("ssl_private_key"))
        {
            api_server.ssl_configuration.ssl_private_key_file = server_config["ssl_private_key"].get<std::string>();
        }
        if (server_config.contains("dh_key"))
        {
            api_server.ssl_configuration.diffie_hellman_key_file = server_config["dh_key"].get<std::string>();
        }
        if (server_config.contains("ssl_password"))
        {
            api_server.ssl_configuration.ssl_password = server_config["ssl_password"].get<std::string>();
        }
    }

    if (fleet_config.contains("db_configuration"))
    {
        auto db_config = fleet_config["db_configuration"];
        if (db_config.contains("hostname") && db_config.contains("port") && db_config.contains("username") && db_config.contains("database_name"))
        {
            api_server.database.hostname = db_config["hostname"].get<std::string>();
            api_server.database.username = db_config["username"].get<std::string>();
            api_server.database.database_name = db_config["database_name"].get<std::string>();

            if (db_config.contains("password"))
            {
                api_server.database.password = db_config["password"].get<std::string>();
            }

            if (db_config.contains("port"))
            {
                if (db_config["port"] != "")
                {
                    api_server.database.port = db_config["port"].get<unsigned int>();
                }
                else
                {
                    api_server.database.port = 0;
                }
            }
        }
        else
        {
            std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (fleet_config.contains("db_pool_configuration"))
    {
        auto pool_config = fleet_config["db_pool_configuration"];
        if (pool_config.contains("max_connections"))
        {
            if (pool_config["max_connections"] != "")
            {
                api_server.database_pool.maximum_connections = pool_config["max_connections"].get<unsigned int>();
            }
            else
            {
                api_server.database_pool.maximum_connections = 10;
            }
        }
        else
        {
            api_server.database_pool.maximum_connections = 10;
        }
    }

    if (fleet_config.contains("access_control_configuration"))
    {
        auto access_control_config = fleet_config["access_control_configuration"];

        if (access_control_config.contains("allow_origin"))
        {
            api_server.access_control_configuration.allow_origin = access_control_config["allow_origin"].get<std::string>();
        }
        if (access_control_config.contains("allow_methods"))
        {
            auto allowed_methods = access_control_config["allow_methods"];

            if (allowed_methods.is_array())
            {
                for (const auto& method : allowed_methods)
                {
                    api_server.access_control_configuration.allow_methods.push_back(method);
                }
            }
            else
                return false;
        }
        if (access_control_config.contains("allow_headers"))
        {
            auto allowed_headers = access_control_config["allow_headers"];

            if (allowed_headers.is_array())
            {
                for (const auto& method : allowed_headers)
                {
                    api_server.access_control_configuration.allow_headers.push_back(method);
                }
            }
            else
                return false;
        }
        if (access_control_config.contains("allow_credentials"))
        {
            api_server.access_control_configuration.allow_credentials = access_control_config["allow_credentials"].get<bool>();
        }
        if (access_control_config.contains("expose_headers"))
        {
            auto exposed_headers = access_control_config["expose_headers"];

            if (exposed_headers.is_array())
            {
                for (const auto& method : exposed_headers)
                {
                    api_server.access_control_configuration.expose_headers.push_back(method);
                }
            }
            else
                return false;
        }
        if (access_control_config.contains("max_age"))
        {
            api_server.access_control_configuration.max_age = access_control_config["max_age"].get<unsigned int>();
        }
    }

    return true;
    } catch (const nlohmann::json::exception& error) {
        std::cerr << "Error: api_server configuration has an invalid field type: " << error.what() << std::endl;
        return false;
    }
}

bool ConfigurationParser::parse_va_config() {
    nlohmann::json va_config;

    if (config_data.contains("va_server"))
    {
        va_config = config_data["va_server"];
    }
    else
    {
        std::cerr << "VA server configuration parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (va_config.contains("server_configuration"))
    {
        auto server_config = va_config["server_configuration"];

        if (server_config.contains("hostname"))
        {
            va_server.server.hostname = server_config["hostname"].get<std::string>();
        }
        else
        {
            va_server.server.hostname = "0.0.0.0";
        }

        if (server_config.contains("port"))
        {
            va_server.server.port = server_config["port"].get<unsigned int>();
        }
        else
        {
            va_server.server.port = 1235;
        }

        if (server_config.contains("ssl_certificate"))
        {
            va_server.ssl_configuration.ssl_certificate_file = server_config["ssl_certificate"].get<std::string>();
        }
        if (server_config.contains("ssl_private_key"))
        {
            va_server.ssl_configuration.ssl_private_key_file = server_config["ssl_private_key"].get<std::string>();
        }
        if (server_config.contains("dh_key"))
        {
            va_server.ssl_configuration.diffie_hellman_key_file = server_config["dh_key"].get<std::string>();
        }
        if (server_config.contains("ssl_password"))
        {
            va_server.ssl_configuration.ssl_password = server_config["ssl_password"].get<std::string>();
        }
    }

    if (va_config.contains("db_configuration"))
    {
        auto db_config = va_config["db_configuration"];
        if (db_config.contains("hostname") && db_config.contains("port") && db_config.contains("username") && db_config.contains("database_name"))
        {
            va_server.database.hostname = db_config["hostname"].get<std::string>();
            va_server.database.username = db_config["username"].get<std::string>();
            va_server.database.database_name = db_config["database_name"].get<std::string>();

            if (db_config.contains("password"))
            {
                va_server.database.password = db_config["password"].get<std::string>();
            }

            if (db_config.contains("port"))
            {
                if (db_config["port"] != "")
                {
                    va_server.database.port = db_config["port"].get<unsigned int>();
                }
                else
                {
                    va_server.database.port = 0;
                }
            }
        }
        else
        {
            std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (va_config.contains("db_pool_configuration"))
    {
        auto pool_config = va_config["db_pool_configuration"];
        if (pool_config.contains("max_connections"))
        {
            if (pool_config["max_connections"] != "")
            {
                va_server.database_pool.maximum_connections = pool_config["max_connections"].get<unsigned int>();
            }
            else
            {
                va_server.database_pool.maximum_connections = 10;
            }
        }
        else
        {
            va_server.database_pool.maximum_connections = 10;
        }
    }
    return true;
}

bool ConfigurationParser::parse_fleet_config() {
    nlohmann::json fleet_config;

    if (config_data.contains("fleet_server"))
    {
        fleet_config = config_data["fleet_server"];
    }
    else
    {
        std::cerr << "Fleet server configuration parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (fleet_config.contains("server_configuration"))
    {
        auto server_config = fleet_config["server_configuration"];

        if (server_config.contains("hostname"))
        {
            fleet_server.server.hostname = server_config["hostname"].get<std::string>();
        }
        else
        {
            fleet_server.server.hostname = "0.0.0.0";
        }

        if (server_config.contains("port"))
        {
            fleet_server.server.port = server_config["port"].get<unsigned int>();
        }
        else
        {
            fleet_server.server.port = 1234;
        }

        if (server_config.contains("ssl_certificate"))
        {
            fleet_server.ssl_configuration.ssl_certificate_file = server_config["ssl_certificate"].get<std::string>();
        }
        if (server_config.contains("ssl_private_key"))
        {
            fleet_server.ssl_configuration.ssl_private_key_file = server_config["ssl_private_key"].get<std::string>();
        }
        if (server_config.contains("dh_key"))
        {
            fleet_server.ssl_configuration.diffie_hellman_key_file = server_config["dh_key"].get<std::string>();
        }
        if (server_config.contains("ssl_password"))
        {
            fleet_server.ssl_configuration.ssl_password = server_config["ssl_password"].get<std::string>();
        }
    }

    if (fleet_config.contains("db_configuration"))
    {
        auto db_config = fleet_config["db_configuration"];
        if (db_config.contains("hostname") && db_config.contains("port") && db_config.contains("username") && db_config.contains("database_name"))
        {
            fleet_server.database.hostname = db_config["hostname"].get<std::string>();
            fleet_server.database.username = db_config["username"].get<std::string>();
            fleet_server.database.database_name = db_config["database_name"].get<std::string>();

            if (db_config.contains("password"))
            {
                fleet_server.database.password = db_config["password"].get<std::string>();
            }

            if (db_config.contains("port"))
            {
                if (db_config["port"] != "")
                {
                    fleet_server.database.port = db_config["port"].get<unsigned int>();
                }
                else
                {
                    fleet_server.database.port = 0;
                }
            }
        }
        else
        {
            std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Database connection parameters are missing in configuration file" << std::endl;
        return false;
    }

    if (fleet_config.contains("db_pool_configuration"))
    {
        auto pool_config = fleet_config["db_pool_configuration"];
        if (pool_config.contains("max_connections"))
        {
            if (pool_config["max_connections"] != "")
            {
                fleet_server.database_pool.maximum_connections = pool_config["max_connections"].get<unsigned int>();
            }
            else
            {
                fleet_server.database_pool.maximum_connections = 10;
            }
        }
        else
        {
            fleet_server.database_pool.maximum_connections = 10;
        }
    }
     if(fleet_config.contains("node_configuration"))
    {
         auto node_config = fleet_config["node_configuration"];
        if (node_config.contains("enrollment_secret"))
        {
            fleet_server.node.enrollment_secret = node_config["enrollment_secret"].get<std::string>();  
        }
        else
        {
            std::cerr << "Secret key parameters are missing from configuration." << std::endl;
            return false;
        }
        
        // Parse enhanced node configuration
        if (node_config.contains("max_enrolled_devices"))
        {
            fleet_server.node.max_enrolled_devices = node_config["max_enrolled_devices"].get<unsigned int>();
        }
        
        if (node_config.contains("max_pending_enrollments"))
        {
            fleet_server.node.max_pending_enrollments = node_config["max_pending_enrollments"].get<unsigned int>();
        }
        
        if (node_config.contains("require_enrollment_approval"))
        {
            fleet_server.node.require_enrollment_approval = node_config["require_enrollment_approval"].get<bool>();
        }
        
        if (node_config.contains("auto_revoke_inactive_days"))
        {
            fleet_server.node.auto_revoke_inactive_days = node_config["auto_revoke_inactive_days"].get<unsigned int>();
        }
        
        if (node_config.contains("node_key_length"))
        {
            fleet_server.node.node_key_length = node_config["node_key_length"].get<unsigned int>();
        }
        
        if (node_config.contains("node_key_expiry_days"))
        {
            fleet_server.node.node_key_expiry_days = node_config["node_key_expiry_days"].get<unsigned int>();
        }
        
        if (node_config.contains("allow_reenrollment"))
        {
            fleet_server.node.allow_reenrollment = node_config["allow_reenrollment"].get<bool>();
        }
        
        // Parse rate limit configuration
        if (node_config.contains("enrollment_rate_limit"))
        {
            auto rate_limit = node_config["enrollment_rate_limit"];
            
            if (rate_limit.contains("enabled"))
            {
                fleet_server.node.enrollment_rate_limit.enabled = rate_limit["enabled"].get<bool>();
            }
            
            if (rate_limit.contains("max_per_ip_per_hour"))
            {
                fleet_server.node.enrollment_rate_limit.max_per_ip_per_hour = rate_limit["max_per_ip_per_hour"].get<unsigned int>();
            }
            
            if (rate_limit.contains("max_per_day"))
            {
                fleet_server.node.enrollment_rate_limit.max_per_day = rate_limit["max_per_day"].get<unsigned int>();
            }
        }
    }
    
    // Parse Kafka producer configuration
    if (fleet_config.contains("kafka_producer"))
    {
        auto kafka_config = fleet_config["kafka_producer"];
        
        if (kafka_config.contains("enabled"))
        {
            fleet_server.kafka_producer.enabled = kafka_config["enabled"].get<bool>();
        }
        
        if (kafka_config.contains("bootstrap_servers"))
        {
            fleet_server.kafka_producer.bootstrap_servers = kafka_config["bootstrap_servers"].get<std::string>();
        }
        
        if (kafka_config.contains("client_id"))
        {
            fleet_server.kafka_producer.client_id = kafka_config["client_id"].get<std::string>();
        }
        
        if (fleet_server.kafka_producer.enabled)
        {
            std::cout << "[Config] Kafka producer enabled - bootstrap servers: " 
                      << fleet_server.kafka_producer.bootstrap_servers << std::endl;
        }
    }

    return true;
}

bool ConfigurationParser::parse_log_config() {
    nlohmann::json log_config;

    if (config_data.contains("log_configuration"))
    {
        log_config = config_data["log_configuration"];

        if (log_config.contains("log_directory"))
        {
            log_configuration.log_directory = log_config["log_directory"].get<std::string>();
        }
        if (log_config.contains("log_file"))
        {
            log_configuration.log_file = log_config["log_file"].get<std::string>();
        }
        if (log_config.contains("log_level"))
        {
            std::string level = log_config["log_level"].get<std::string>();

            if (level == "trace")
                log_configuration.log_level = 0;
            else if (level == "debug")
                log_configuration.log_level = 1;
            else if (level == "info")
                log_configuration.log_level = 2;
            else if (level == "warning")
                log_configuration.log_level = 3;
            else if (level == "error")
                log_configuration.log_level = 4;
            else if (level == "fatal")
                log_configuration.log_level = 5;
            else
            {
                std::cerr<< "Error: unknown log level. Defaulting to \"warning\".";
            }
        }
        if (log_config.contains("console_output"))
        {
            log_configuration.console_output = log_config["console_output"].get<bool>();
        }
        if (log_config.contains("max_log_size"))
        {
            log_configuration.log_size = log_config["max_log_size"].get<long long>();
        }
    }

    return true;
}

bool ConfigurationParser::parse_rule_engine_config() {
    if (!config_data.contains("rule_engine")) {
        return true;  // optional block; keep defaults
    }
    auto engine_config = config_data["rule_engine"];

    if (engine_config.contains("kafka")) {
        // Same fail-safe pattern as the feeds[]/metrics{} blocks below: a
        // mistyped scalar here (e.g. "session_timeout_ms" as a string) must
        // not crash startup -- it resets just this sub-block to defaults.
        try {
            auto kafka_config = engine_config["kafka"];
            if (kafka_config.contains("bootstrap_servers")) {
                rule_engine.kafka.bootstrap_servers = kafka_config["bootstrap_servers"].get<std::string>();
            }
            if (kafka_config.contains("consumer_group_id")) {
                rule_engine.kafka.consumer_group_id = kafka_config["consumer_group_id"].get<std::string>();
            }
            if (kafka_config.contains("security_protocol")) {
                rule_engine.kafka.security_protocol = kafka_config["security_protocol"].get<std::string>();
            }
            if (kafka_config.contains("session_timeout_ms")) {
                rule_engine.kafka.session_timeout_ms = kafka_config["session_timeout_ms"].get<unsigned int>();
            }
            if (kafka_config.contains("max_poll_interval_ms")) {
                rule_engine.kafka.max_poll_interval_ms = kafka_config["max_poll_interval_ms"].get<unsigned int>();
            }
        } catch (const nlohmann::json::exception& error) {
            std::cerr << "Error: rule_engine.kafka has an invalid field type; kafka settings left "
                         "at their defaults: "
                      << error.what() << std::endl;
            rule_engine.kafka = RuleEngineKafkaConfiguration();
        }
    }

    if (engine_config.contains("event_types") && engine_config["event_types"].is_array()) {
        for (const auto& et : engine_config["event_types"]) {
            // Per-entry, like feeds[]/providers[]: one malformed event_type
            // entry must not drop the rest of the array.
            try {
                RuleEngineEventType event_type;
                if (et.contains("name")) event_type.name = et["name"].get<std::string>();
                if (et.contains("kafka_topic")) event_type.kafka_topic = et["kafka_topic"].get<std::string>();
                event_type.enabled = et.contains("enabled") ? et["enabled"].get<bool>() : true;
                if (et.contains("os_filter")) event_type.os_filter = et["os_filter"].get<std::string>();
                rule_engine.event_types.push_back(std::move(event_type));
            } catch (const nlohmann::json::exception& error) {
                std::cerr << "Error: rule_engine.event_types entry has an invalid field type and "
                             "was skipped: "
                          << error.what() << std::endl;
            }
        }
    }

    if (engine_config.contains("threat_intelligence")) {
        auto ti_config = engine_config["threat_intelligence"];
        try {
            if (ti_config.contains("enabled")) {
                rule_engine.threat_intelligence.enabled = ti_config["enabled"].get<bool>();
            }
            if (ti_config.contains("cache_ttl_seconds")) {
                rule_engine.threat_intelligence.cache_ttl_seconds =
                    ti_config["cache_ttl_seconds"].get<unsigned int>();
            }
            if (ti_config.contains("virustotal_api_key")) {
                rule_engine.threat_intelligence.virustotal_api_key =
                    ti_config["virustotal_api_key"].get<std::string>();
            }
            if (ti_config.contains("abuseipdb_api_key")) {
                rule_engine.threat_intelligence.abuseipdb_api_key =
                    ti_config["abuseipdb_api_key"].get<std::string>();
            }
        } catch (const nlohmann::json::exception& error) {
            std::cerr << "Error: rule_engine.threat_intelligence has an invalid field type; its "
                         "scalar settings were left at their defaults (feeds[]/providers[], if "
                         "present, are still parsed below): "
                      << error.what() << std::endl;
        }
        if (ti_config.contains("providers") && ti_config["providers"].is_array()) {
            for (const auto& p : ti_config["providers"]) {
                try {
                    ThreatIntelProviderConfiguration provider;
                    if (p.contains("name")) provider.name = p["name"].get<std::string>();
                    provider.enabled = p.contains("enabled") ? p["enabled"].get<bool>() : false;
                    provider.priority = p.contains("priority") ? p["priority"].get<int>() : 0;
                    rule_engine.threat_intelligence.providers.push_back(std::move(provider));
                } catch (const nlohmann::json::exception& error) {
                    std::cerr << "Error: threat_intelligence.providers entry has an invalid field "
                                 "type and was skipped: "
                              << error.what() << std::endl;
                }
            }
        }
        if (ti_config.contains("feeds") && ti_config["feeds"].is_array()) {
            for (const auto& f : ti_config["feeds"]) {
                // Each feed entry is parsed in isolation: a type error in one
                // malformed entry (e.g. a string where a number is expected)
                // must not abort startup or drop the rest of the feeds[] array.
                try {
                    ThreatIntelFeedConfiguration feed;
                    if (f.contains("name")) feed.name = f["name"].get<std::string>();
                    if (f.contains("format")) feed.format = f["format"].get<std::string>();
                    feed.enabled = f.contains("enabled") ? f["enabled"].get<bool>() : true;
                    if (f.contains("url")) feed.url = f["url"].get<std::string>();
                    if (f.contains("api_key")) feed.api_key = f["api_key"].get<std::string>();
                    if (f.contains("target_list")) {
                        feed.target_list = f["target_list"].get<std::string>();
                    }
                    if (f.contains("refresh_interval_seconds")) {
                        feed.refresh_interval_seconds = f["refresh_interval_seconds"].get<unsigned int>();
                    }
                    if (f.contains("max_entries")) {
                        feed.max_entries = f["max_entries"].get<unsigned int>();
                    }
                    if (f.contains("stix_types") && f["stix_types"].is_array()) {
                        feed.stix_types.clear();
                        for (const auto& t : f["stix_types"]) {
                            feed.stix_types.push_back(t.get<std::string>());
                        }
                    }
                    rule_engine.threat_intelligence.feeds.push_back(std::move(feed));
                } catch (const nlohmann::json::exception& error) {
                    std::cerr << "Error: threat_intelligence.feeds entry has an invalid field type "
                                 "and was skipped: "
                              << error.what() << std::endl;
                }
            }
        }
    }

    if (engine_config.contains("metrics")) {
        // Wrapped like the feeds[] block above: a mistyped scalar (e.g.
        // "port" as a string) must skip just this block, not abort the
        // whole rule_engine config / crash the process at startup.
        try {
            auto metrics_config = engine_config["metrics"];
            if (metrics_config.contains("enabled")) {
                rule_engine.metrics.enabled = metrics_config["enabled"].get<bool>();
            }
            if (metrics_config.contains("bind_address")) {
                rule_engine.metrics.bind_address = metrics_config["bind_address"].get<std::string>();
            }
            if (metrics_config.contains("port")) {
                const unsigned int port = metrics_config["port"].get<unsigned int>();
                if (port == 0 || port > 65535) {
                    std::cerr << "Error: rule_engine.metrics.port " << port
                              << " is outside the valid 1-65535 range; metrics left disabled"
                              << std::endl;
                    rule_engine.metrics = RuleEngineMetricsConfiguration();
                } else {
                    rule_engine.metrics.port = port;
                }
            }
        } catch (const nlohmann::json::exception& error) {
            std::cerr << "Error: rule_engine.metrics has an invalid field type; metrics left "
                         "disabled: "
                      << error.what() << std::endl;
            rule_engine.metrics = RuleEngineMetricsConfiguration();
        }
    }

    if (engine_config.contains("db_connection_pool_size")) {
        try {
            rule_engine.db_connection_pool_size =
                engine_config["db_connection_pool_size"].get<unsigned int>();
        } catch (const nlohmann::json::exception& error) {
            std::cerr << "Error: rule_engine.db_connection_pool_size has an invalid type; left at "
                         "its default: "
                      << error.what() << std::endl;
        }
    }

    return true;
}

bool ConfigurationParser::parse() {

    /*
     * Before we even attempt reading data, we need to check the following:
     * 1. that the given path exists
     * 2. that the given path is a regular file (not special files like sockets, device files etc)
     * 3. that the given path does not point to an empty file
     *
     * If given path is a symlink, we resolve the symlink and run both checks on resolved path.
     */

    try
    {
        if (!std::filesystem::exists(this->configuration_file))
        {
            std::cerr << "Error: configuration file does not exist." << std::endl;
            return false;
        }
        if (std::filesystem::is_symlink(this->configuration_file))
        {
            this->configuration_file = std::filesystem::read_symlink(this->configuration_file);

            if (!std::filesystem::exists(this->configuration_file))
            {
                std::cerr << "Error: configuration file is a symlink resolving to non-existing path." << std::endl;
                return false;
            }
        }
        if (!std::filesystem::is_regular_file(this->configuration_file))
        {
            std::cerr << "Error: configuration file is not a regular file." << std::endl;
            return false;
        }
        if (std::filesystem::is_empty(this->configuration_file))
        {
            std::cerr << "Error: configuration file is empty." << std::endl;
            return false;
        }
    }
    catch (const std::filesystem::filesystem_error& error)
    {
        std::cerr << "Error (" << error.code() << ") while validating configuration file path: " << error.what() << std::endl;
        return false;
    }

    std::ifstream config_file(this->configuration_file);
    std::string str((std::istreambuf_iterator<char>(config_file)), std::istreambuf_iterator<char>());

    try {
        this->config_data = nlohmann::json::parse(str);
    }
    catch (const nlohmann::json::parse_error& error)
    {
        std::cerr << "Error: could not parse JSON. Parse error: " << error.what() << std::endl;
        return false;
    }
    catch (const nlohmann::json::type_error& error)
    {
        std::cerr << "Error: invalid type encountered in JSON. Parse error: " << error.what() << std::endl;
        return false;
    }
    catch(const std::exception& ex)
    {
        std::cerr << "Error: some unknown error occurred. Parse error: " << ex.what() << std::endl;
        return false;
    }

    // The parse_*_config() helpers below index this->config_data extensively
    // (operator[], .at(), .get<T>()) without their own try/catch -- a
    // malformed field (wrong type, missing required key accessed via
    // operator[] on a non-object, etc.) throws nlohmann::json::exception
    // right through this call site. Every caller of parse() (fleet_main.cpp,
    // engine_v2/src/main.cpp) already treats a `false` return as "bad config,
    // exit cleanly" -- catch here so that contract actually holds instead of
    // the process crashing with an unhandled exception on a bad config.json.
    try
    {
        if (parse_fleet_config() && parse_log_config() && parse_va_config() && parse_rule_engine_config())
            return true;
        else
            return false;
    }
    catch (const nlohmann::json::exception& error)
    {
        std::cerr << "Error: invalid configuration value. Parse error: " << error.what() << std::endl;
        return false;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: some unknown error occurred while parsing configuration sections: " << error.what() << std::endl;
        return false;
    }
}

FleetServerConfiguration ConfigurationParser::GetFleetConfiguration() {
    return this->fleet_server;
}

LogConfiguration ConfigurationParser::GetLogConfiguration(const std::string& service_name) {
    boost::replace_all(log_configuration.log_file, "{%service_name%}", service_name);
    return this->log_configuration;
}

ApiServerConfiguration ConfigurationParser::GetApiServerConfiguration() {
    return this->api_server;
}

VaServerConfiguration ConfigurationParser::GetVaServerConfiguration() {
    return this->va_server;
}

RuleEngineConfiguration ConfigurationParser::GetRuleEngineConfiguration() {
    return this->rule_engine;
}
