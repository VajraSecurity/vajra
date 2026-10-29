#include "vajra_engine/ThreatIntelFeed.h"

#include <curl/curl.h>

#include <chrono>
#include <regex>
#include <set>

#include "../../3rdparty/json.hpp"
#include "../../common/logger.h"
#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {
namespace {

constexpr const char* kAbuseIpDbBlacklistUrl = "https://api.abuseipdb.com/api/v2/blacklist";
// Hard cap on the raw HTTP response body, independent of max_entries -- a
// misbehaving endpoint sending an enormous body must not be read into
// memory in full before we even get to bound the parsed entry count.
constexpr std::size_t kMaxResponseBytes = 20 * 1024 * 1024;  // 20 MiB

std::size_t write_callback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    const std::size_t bytes = size * nmemb;
    if (out->size() + bytes > kMaxResponseBytes) {
        return 0;  // short write -> libcurl aborts the transfer with an error
    }
    out->append(ptr, bytes);
    return bytes;
}

// curl_global_init() is documented as not safe to call concurrently or more
// than once per process; this runs it exactly once regardless of how many
// ThreatIntelFeed instances exist or how many times any of them refresh.
void ensure_curl_global_init() {
    static const int unused = [] {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return 0;
    }();
    (void)unused;
}

bool fetch(const std::string& url, const std::vector<std::string>& headers, std::string& response_out,
           std::string& error_out) {
    ensure_curl_global_init();

    CURL* curl = curl_easy_init();
    if (!curl) {
        error_out = "curl_easy_init failed";
        return false;
    }

    struct curl_slist* header_list = nullptr;
    for (const auto& h : headers) header_list = curl_slist_append(header_list, h.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (header_list) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_out);
    // Never follow redirects: the target is a fixed or operator-configured
    // known-good URL; a redirect means the endpoint is misbehaving or
    // compromised, not a case to blindly follow (and would otherwise be a
    // way to bypass the https:// scheme check done before this is called).
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vajra-engine-threat-intel/1.0");
    // Defense-in-depth beyond the https:// prefix check callers already do:
    // restrict libcurl itself to only ever actually speak HTTPS, regardless
    // of what scheme ends up in the URL string. Every current caller (the
    // hardcoded AbuseIPDB URL, and "stix" URLs already prefix-checked before
    // fetch() is called) is HTTPS already, so this never rejects legitimate
    // use.
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");

    const CURLcode res = curl_easy_perform(curl);
    long http_status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        error_out = curl_easy_strerror(res);
        return false;
    }
    if (http_status < 200 || http_status >= 300) {
        error_out = "HTTP " + std::to_string(http_status);
        return false;
    }
    return true;
}

// exceeds_max_nesting_depth/kMaxJsonNestingDepth now live in JsonSafety.h,
// shared with Envelope::from_json_text's Kafka-message parse path.

std::optional<nlohmann::json> bounded_json_parse(const std::string& body) {
    if (exceeds_max_nesting_depth(body, kMaxJsonNestingDepth)) return std::nullopt;
    try {
        return nlohmann::json::parse(body);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

struct StixMatch {
    std::string type;  // "ip" | "domain" | "hash"
    std::string value;
};

// Harvests every simple equality clause in a STIX pattern string, e.g.
// "[ipv4-addr:value = '1.2.3.4']" or a multi-clause pattern joined by AND/
// OR -- deliberately not evaluating the boolean structure, just collecting
// every named IOC value, which is a safe, conservative simplification for a
// deny-list feed (see ThreatIntelFeed.h's doc comment on parse_stix_indicators).
std::vector<StixMatch> extract_stix_equality_matches(const std::string& pattern) {
    static const std::regex kPatternRegex(
        R"((ipv4-addr:value|ipv6-addr:value|domain-name:value|)"
        R"(file:hashes\.'?(?:MD5|SHA-1|SHA-256|SHA1|SHA256)'?)\s*=\s*['"]([^'"]*)['"])",
        std::regex::icase);
    std::vector<StixMatch> matches;
    for (auto it = std::sregex_iterator(pattern.begin(), pattern.end(), kPatternRegex);
         it != std::sregex_iterator(); ++it) {
        const std::string field = (*it)[1].str();
        const std::string value = (*it)[2].str();
        if (value.empty()) continue;

        std::string type;
        if (field.rfind("ipv4-addr", 0) == 0 || field.rfind("ipv6-addr", 0) == 0) {
            type = "ip";
        } else if (field.rfind("domain-name", 0) == 0) {
            type = "domain";
        } else if (field.rfind("file:hashes", 0) == 0) {
            type = "hash";
        }
        if (!type.empty()) matches.push_back({std::move(type), value});
    }
    return matches;
}

}  // namespace

std::map<std::string, std::string> parse_abuseipdb_blacklist(const std::string& response_body,
                                                               std::size_t max_entries) {
    std::map<std::string, std::string> entries;
    auto doc_opt = bounded_json_parse(response_body);
    if (!doc_opt) return entries;
    const auto& doc = *doc_opt;
    if (!doc.is_object() || !doc.contains("data") || !doc["data"].is_array()) return entries;

    for (const auto& item : doc["data"]) {
        if (entries.size() >= max_entries) break;
        if (!item.is_object() || !item.contains("ipAddress")) continue;
        const auto& ip_field = item["ipAddress"];
        if (!ip_field.is_string()) continue;
        const std::string ip = ip_field.get<std::string>();
        if (ip.empty()) continue;

        std::string score;
        if (item.contains("abuseConfidenceScore") && item["abuseConfidenceScore"].is_number()) {
            try {
                score = std::to_string(item["abuseConfidenceScore"].get<int>());
            } catch (const std::exception&) {
                score.clear();  // out-of-range/malformed score: keep the IP, drop the score
            }
        }
        entries[ip] = score;
    }
    return entries;
}

std::map<std::string, std::string> parse_stix_indicators(const std::string& response_body,
                                                           const std::vector<std::string>& wanted_types,
                                                           std::size_t max_entries) {
    std::map<std::string, std::string> entries;
    auto doc_opt = bounded_json_parse(response_body);
    if (!doc_opt) return entries;
    const auto& doc = *doc_opt;
    if (!doc.is_object() || !doc.contains("objects") || !doc["objects"].is_array()) return entries;

    const std::set<std::string> wanted(wanted_types.begin(), wanted_types.end());

    for (const auto& obj : doc["objects"]) {
        if (entries.size() >= max_entries) break;
        if (!obj.is_object()) continue;
        if (!obj.contains("type") || obj["type"] != "indicator") continue;
        if (!obj.contains("pattern") || !obj["pattern"].is_string()) continue;
        // Only STIX's own pattern mini-language is IOC-extractable this
        // way; other pattern types (e.g. "snort", "yara") are skipped.
        if (obj.contains("pattern_type") && obj["pattern_type"].is_string() &&
            obj["pattern_type"].get<std::string>() != "stix") {
            continue;
        }

        std::string source_id;
        if (obj.contains("id") && obj["id"].is_string()) source_id = obj["id"].get<std::string>();

        const std::string pattern = obj["pattern"].get<std::string>();
        for (const auto& match : extract_stix_equality_matches(pattern)) {
            if (entries.size() >= max_entries) break;
            if (wanted.count(match.type) == 0) continue;
            entries[match.value] = source_id;
        }
    }
    return entries;
}

std::optional<std::size_t> apply_feed_response(const std::string& format,
                                                const std::string& response_body,
                                                const std::vector<std::string>& stix_types,
                                                std::size_t max_entries, const std::string& target_list,
                                                ListStore& lists) {
    std::map<std::string, std::string> entries;
    if (format == "abuseipdb") {
        entries = parse_abuseipdb_blacklist(response_body, max_entries);
    } else if (format == "stix") {
        entries = parse_stix_indicators(response_body, stix_types, max_entries);
    } else {
        return std::nullopt;
    }

    // Never let a suspicious/empty response silently erase a previously-good
    // list -- an invalid key, rate limiting, or a malformed response all
    // parse down to "no usable entries", and none of those should be
    // treated the same as "the provider says there are genuinely zero
    // malicious IOCs right now."
    if (entries.empty()) return std::nullopt;

    const std::size_t count = entries.size();
    lists.replace_list(target_list, std::move(entries));
    return count;
}

ThreatIntelFeed::ThreatIntelFeed(ThreatIntelFeedConfig config, ListStore& lists)
    : config_(std::move(config)), lists_(lists) {}

ThreatIntelFeed::~ThreatIntelFeed() { stop(); }

void ThreatIntelFeed::start() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);

    if (!config_.enabled) {
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: threat-intel feed '" << config_.name
                                 << "' disabled, not starting";
        return;
    }
    if (config_.format == "abuseipdb") {
        if (config_.api_key.empty()) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: threat-intel feed '"
                                        << config_.name
                                        << "' (abuseipdb) has no api_key configured, not starting";
            return;
        }
    } else if (config_.format == "stix") {
        if (config_.url.rfind("https://", 0) != 0) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: threat-intel feed '"
                                        << config_.name
                                        << "' (stix) has no https:// url configured, not starting";
            return;
        }
    } else {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: threat-intel feed '" << config_.name
                                    << "' has unknown format '" << config_.format << "', not starting";
        return;
    }

    if (running_.exchange(true)) return;  // already started
    thread_ = std::thread(&ThreatIntelFeed::run, this);
}

void ThreatIntelFeed::stop() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void ThreatIntelFeed::run() {
    // Refresh immediately on startup (so target_list isn't empty for
    // however long the first interval would otherwise be), then on the
    // configured interval. Sleeps in short slices so stop() takes effect
    // promptly between refreshes rather than only after a full (potentially
    // hours-long) interval -- though a SIGTERM arriving mid-fetch still
    // waits on that fetch's own bounded curl timeout (CURLOPT_TIMEOUT=30s
    // bounds the whole operation, including the CURLOPT_CONNECTTIMEOUT=10s
    // sub-limit within it -- not additive) before stop()'s join() returns.
    while (running_.load(std::memory_order_relaxed)) {
        refresh_once();

        const auto interval = std::chrono::seconds(
            config_.refresh_interval_seconds > 0 ? config_.refresh_interval_seconds : 3600);
        const auto deadline = std::chrono::steady_clock::now() + interval;
        while (running_.load(std::memory_order_relaxed) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

void ThreatIntelFeed::refresh_once() {
    std::string response, error;
    bool ok = false;
    if (config_.format == "abuseipdb") {
        ok = fetch(kAbuseIpDbBlacklistUrl, {"Key: " + config_.api_key, "Accept: application/json"},
                   response, error);
    } else if (config_.format == "stix") {
        std::vector<std::string> headers = {"Accept: application/json"};
        if (!config_.api_key.empty()) headers.push_back("Authorization: Bearer " + config_.api_key);
        ok = fetch(config_.url, headers, response, error);
    } else {
        return;  // unreachable: start() already rejected unknown formats
    }

    if (!ok) {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: threat-intel feed '" << config_.name
                                    << "' refresh failed, keeping existing " << config_.target_list
                                    << ": " << error;
        return;
    }

    const auto count = apply_feed_response(config_.format, response, config_.stix_types,
                                            config_.max_entries, config_.target_list, lists_);
    if (!count) {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: threat-intel feed '" << config_.name
                                    << "' returned no usable entries -- keeping existing "
                                    << config_.target_list << " unchanged";
        return;
    }

    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: threat-intel feed '" << config_.name
                             << "' refreshed " << config_.target_list << " with " << *count
                             << " entries";
}

ThreatIntelFeedManager::ThreatIntelFeedManager(std::vector<ThreatIntelFeedConfig> configs,
                                                ListStore& lists) {
    feeds_.reserve(configs.size());
    for (auto& cfg : configs) {
        feeds_.push_back(std::make_unique<ThreatIntelFeed>(std::move(cfg), lists));
    }
}

void ThreatIntelFeedManager::start() {
    for (auto& feed : feeds_) feed->start();
}

void ThreatIntelFeedManager::stop() {
    for (auto& feed : feeds_) feed->stop();
}

}  // namespace vajra_engine
