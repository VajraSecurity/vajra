#ifndef FLEET_CONFIGURATIONPARSER_H
#define FLEET_CONFIGURATIONPARSER_H

#include "../3rdparty/json.hpp"
#include <filesystem>
#include <string>

struct ServerConfiguration
{
    std::string hostname;
    unsigned int port;

    ServerConfiguration();
};

struct LogConfiguration
{
    std::string log_directory;
    std::string log_file;
    char log_level;
    long long log_size;
    // Mirrors log output to stdout (captured by systemd/journalctl) in
    // addition to the file sink, at the SAME log_level threshold -- this
    // does not add a separate/independent filter, it shares the one
    // process-wide filter already set from log_level, so enabling this
    // never bypasses level gating. Off by default: continuous per-request
    // debug output to the journal is a real volume/noise concern on a busy
    // fleet, so an operator opts in deliberately rather than it being on by
    // default.
    bool console_output;

    LogConfiguration();
};

struct AccessControlConfiguration
{
    std::string allow_origin;
    std::vector<std::string> expose_headers;
    unsigned int max_age;
    bool allow_credentials;
    std::vector<std::string> allow_methods;
    std::vector<std::string> allow_headers;

    AccessControlConfiguration();
};

struct SslConfiguration
{
    std::string ssl_certificate_file;
    std::string ssl_private_key_file;
    std::string ssl_password;
    std::string diffie_hellman_key_file;
};

struct NodeConfiguration
{
    std::string enrollment_secret;
    unsigned int max_enrolled_devices;
    unsigned int max_pending_enrollments;
    bool require_enrollment_approval;
    unsigned int auto_revoke_inactive_days;
    unsigned int node_key_length;
    unsigned int node_key_expiry_days;
    bool allow_reenrollment;
    
    struct EnrollmentRateLimit {
        bool enabled;
        unsigned int max_per_ip_per_hour;
        unsigned int max_per_day;
    } enrollment_rate_limit;
    
    NodeConfiguration();
};

struct DatabaseConfiguration
{
    std::string hostname;
    unsigned int port;
    std::string username;
    std::string password;
    std::string database_name;

    std::string ConnectionString();
    DatabaseConfiguration();
};

struct DatabaseInternetConfiguration
{
    std::string hostname;
    unsigned int port;
    std::string username;
    std::string password;
    std::string database_name;

    std::string ConnectionVaString();
    DatabaseInternetConfiguration();
};

struct DatabasePoolConfiguration
{
    unsigned int maximum_connections;
    DatabasePoolConfiguration();
};

struct KafkaProducerConfiguration
{
    bool enabled;
    std::string bootstrap_servers;
    std::string client_id;
    
    KafkaProducerConfiguration() 
        : enabled(false)
        , bootstrap_servers("localhost:9092")
        , client_id("vajra-server")
    {}
};

struct RuleEngineKafkaConfiguration
{
    std::string bootstrap_servers;
    std::string consumer_group_id;
    std::string security_protocol;
    unsigned int session_timeout_ms;
    unsigned int max_poll_interval_ms;

    RuleEngineKafkaConfiguration();
};

struct RuleEngineEventType
{
    std::string name;
    std::string kafka_topic;
    bool enabled = false;
    std::string os_filter;
};

struct ThreatIntelProviderConfiguration
{
    std::string name;
    bool enabled = false;
    int priority = 0;
};

// One configured IOC feed source (rule_engine.threat_intelligence.feeds[]).
// "format" selects which parser/transport the engine uses: "abuseipdb"
// (fixed hardcoded endpoint; url is ignored) or "stix" (a STIX 2.x JSON
// bundle fetched from "url", which IS operator-supplied -- config.json is
// trusted infrastructure config, not attacker/event input).
struct ThreatIntelFeedConfiguration
{
    std::string name;
    std::string format;  // "abuseipdb" | "stix"
    bool enabled;
    std::string url;       // required for "stix"; must be https://
    std::string api_key;   // sent as a header value only, never logged/URL'd
    std::string target_list;
    unsigned int refresh_interval_seconds;
    unsigned int max_entries;
    // "stix" only: which STIX observable types this feed extracts into
    // target_list ("ip", "domain", "hash").
    std::vector<std::string> stix_types;

    ThreatIntelFeedConfiguration();
};

struct ThreatIntelligenceConfiguration
{
    bool enabled;
    unsigned int cache_ttl_seconds;
    // Legacy single-provider fields, superseded by "feeds" below but kept
    // parsed for backward compatibility: if "feeds" is empty and
    // abuseipdb_api_key is set, the engine synthesizes an equivalent single
    // feed from these rather than requiring every existing config.json to
    // migrate immediately.
    std::string virustotal_api_key;
    std::string abuseipdb_api_key;
    std::vector<ThreatIntelProviderConfiguration> providers;
    std::vector<ThreatIntelFeedConfiguration> feeds;

    ThreatIntelligenceConfiguration();
};

// Prometheus-style /metrics HTTP endpoint (see engine_v2/include/vajra_engine/
// Metrics.h). Off by default; when enabled, binds to bind_address:port with
// no authentication, matching how Prometheus exporters are conventionally
// deployed. bind_address defaults to loopback-only so enabling this doesn't
// silently expose the endpoint to the network.
struct RuleEngineMetricsConfiguration
{
    bool enabled;
    std::string bind_address;
    unsigned int port;

    RuleEngineMetricsConfiguration();
};

struct RuleEngineConfiguration
{
    RuleEngineKafkaConfiguration kafka;
    std::vector<RuleEngineEventType> event_types;
    ThreatIntelligenceConfiguration threat_intelligence;
    RuleEngineMetricsConfiguration metrics;
    unsigned int db_connection_pool_size;

    RuleEngineConfiguration();
};

struct FleetServerConfiguration
{
    ServerConfiguration server;
    NodeConfiguration node;
    DatabaseConfiguration database;
    DatabasePoolConfiguration database_pool;
    SslConfiguration ssl_configuration;
    KafkaProducerConfiguration kafka_producer;
};

struct ApiServerConfiguration
{
    ServerConfiguration server;
    DatabaseConfiguration database;
    DatabasePoolConfiguration database_pool;
    SslConfiguration ssl_configuration;
    AccessControlConfiguration access_control_configuration;
};

struct VaServerConfiguration
{
    ServerConfiguration server;
    DatabaseInternetConfiguration database;
    DatabasePoolConfiguration database_pool;
    SslConfiguration ssl_configuration;
    AccessControlConfiguration access_control_configuration;
};

class ConfigurationParser {
private:
    std::filesystem::path configuration_file;
    FleetServerConfiguration fleet_server;
    LogConfiguration log_configuration;
    ApiServerConfiguration api_server;
    VaServerConfiguration va_server;
    RuleEngineConfiguration rule_engine;

    nlohmann::json config_data;
protected:
    //bool isValid();
    bool parse_fleet_config();
    bool parse_api_config();
    bool parse_va_config();
    bool parse_log_config();
    // "rule_engine" is a newer, optional top-level key: an absent block must
    // never fail parse() (all fields keep their defaults), matching this
    // parser's existing tolerant-of-missing-optional-sections behavior.
    bool parse_rule_engine_config();
public:
    bool parse();
    FleetServerConfiguration GetFleetConfiguration();
    ApiServerConfiguration GetApiServerConfiguration();
    VaServerConfiguration GetVaServerConfiguration();
    LogConfiguration GetLogConfiguration(const std::string& service_name);
    RuleEngineConfiguration GetRuleEngineConfiguration();
    ConfigurationParser(std::string path);
};


#endif //FLEET_CONFIGURATIONPARSER_H
