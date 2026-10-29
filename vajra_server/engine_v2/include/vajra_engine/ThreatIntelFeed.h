#ifndef VAJRA_ENGINE_THREAT_INTEL_FEED_H
#define VAJRA_ENGINE_THREAT_INTEL_FEED_H

#include <atomic>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "vajra_engine/Rule.h"

namespace vajra_engine {

// One configured feed source. "format" selects which parser/transport is
// used: "abuseipdb" (fixed hardcoded endpoint -- url is ignored, see
// ThreatIntelFeed.cpp's rationale) or "stix" (a STIX 2.x JSON bundle
// fetched from "url", which IS operator-supplied: config.json is trusted
// infrastructure config, the same trust level already given to DB
// connection strings and Kafka bootstrap servers elsewhere in this
// codebase -- this is NOT attacker/event-controlled input, so an
// operator-chosen URL here (including one pointing at an internal/
// self-hosted STIX server, a normal enterprise deployment pattern) is an
// accepted, intentional difference from the AbuseIPDB case, not an
// oversight).
struct ThreatIntelFeedConfig {
    std::string name;
    std::string format;  // "abuseipdb" | "stix"
    bool enabled = true;
    std::string url;      // required for "stix"; must be https://
    std::string api_key;  // sent as a header value only, never logged/URL'd
    std::string target_list = "deny_ips";
    unsigned int refresh_interval_seconds = 3600;
    std::size_t max_entries = 50000;
    // "stix" only: which STIX observable types this feed extracts into
    // target_list ("ip", "domain", "hash"). A single feed writes to a
    // single target_list, so a STIX bundle mixing IOC types needs one
    // config entry per type/target_list pair.
    std::vector<std::string> stix_types = {"ip"};
};

// One background worker per configured feed: periodically fetches and
// parses its source, then atomically replaces its target ListStore list.
// Never touches RuleEngine's correlation state (rules_/history_/
// tracked_rule_ids_) -- only ListStore's own internally-synchronized
// methods (see Rule.h), so a refresh can never disrupt an in-progress
// correlation window the way a full ruleset reload would.
class ThreatIntelFeed {
public:
    ThreatIntelFeed(ThreatIntelFeedConfig config, ListStore& lists);
    ~ThreatIntelFeed();

    ThreatIntelFeed(const ThreatIntelFeed&) = delete;
    ThreatIntelFeed& operator=(const ThreatIntelFeed&) = delete;

    // No-op (logged, not fatal) if config.enabled is false, the format is
    // unrecognized, or the feed is missing what its format requires (an
    // api_key for "abuseipdb"; a valid https:// url for "stix"). Safe to
    // call start()/stop() repeatedly or from different threads (guarded by
    // an internal mutex), though only one background thread ever runs at a
    // time regardless.
    void start();
    // Idempotent; also called from the destructor.
    void stop();

    const std::string& name() const { return config_.name; }

private:
    void run();
    void refresh_once();

    ThreatIntelFeedConfig config_;
    ListStore& lists_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::mutex lifecycle_mutex_;  // guards start()/stop() against concurrent misuse
};

// Owns and runs one ThreatIntelFeed worker per configured feed. Constructed
// once at startup from the effective feed list (see main.cpp's
// build_feed_configs(), which also handles the legacy single-provider
// config fallback).
class ThreatIntelFeedManager {
public:
    ThreatIntelFeedManager(std::vector<ThreatIntelFeedConfig> configs, ListStore& lists);

    void start();
    void stop();

private:
    std::vector<std::unique_ptr<ThreatIntelFeed>> feeds_;
};

// Parses AbuseIPDB's blacklist response body (a JSON object with a "data"
// array of {"ipAddress": "...", "abuseConfidenceScore": N, ...} entries)
// into a bounded key(ip)->value(confidence score) map. Never throws --
// malformed input (bad JSON, unexpected shape, non-string/empty IPs,
// excessive nesting depth) yields an empty map rather than a partial or
// garbage one, so callers can treat "empty" as "don't trust this response"
// uniformly. Exposed standalone so it's unit-testable without a live
// network call.
std::map<std::string, std::string> parse_abuseipdb_blacklist(const std::string& response_body,
                                                               std::size_t max_entries);

// Parses a STIX 2.x bundle ({"type":"bundle","objects":[...]}) for
// "indicator" objects, extracting simple equality patterns
// (`[ipv4-addr:value = '1.2.3.4']`, `[domain-name:value = 'evil.com']`,
// `[file:hashes.'SHA-256' = '...']` and similar MD5/SHA-1/SHA-256 hash
// forms) whose observable type is in `wanted_types` ("ip"/"domain"/"hash").
// This is NOT a full STIX Patterning grammar interpreter -- only these
// common simple-equality forms are recognized; indicators using boolean
// combinators, comparison operators other than '=', or other STIX Cyber
// Observable types are silently skipped, matching how most real-world
// exported IOC feeds (MISP, OpenCTI, etc.) actually shape their `pattern`
// field. The map value is the indicator's STIX `id` (provenance), if
// present. Never throws.
std::map<std::string, std::string> parse_stix_indicators(const std::string& response_body,
                                                           const std::vector<std::string>& wanted_types,
                                                           std::size_t max_entries);

// Parses response_body per `format` ("abuseipdb"/"stix") and returns the
// resulting entry count ONLY on a genuinely non-empty successful parse, in
// which case target_list in `lists` has already been atomically replaced.
// On any parse failure, unrecognized format, or an empty result, `lists` is
// left completely unchanged and std::nullopt is returned -- this is the
// actual fail-safe decision ThreatIntelFeed::refresh_once() delegates to,
// split out as a free function so it's directly unit-testable without a
// live network call or mocking curl.
std::optional<std::size_t> apply_feed_response(const std::string& format,
                                                const std::string& response_body,
                                                const std::vector<std::string>& stix_types,
                                                std::size_t max_entries, const std::string& target_list,
                                                ListStore& lists);

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_THREAT_INTEL_FEED_H
