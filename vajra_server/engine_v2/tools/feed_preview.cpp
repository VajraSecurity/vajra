// vajra_engine_v2_feed_preview -- offline/online preview tool for a STIX
// Feeds config (API_CONTRACT_V2.md section 3). Gives rule_engine_ui's
// "preview" button real teeth by calling the ENGINE'S OWN real parser
// functions (parse_abuseipdb_blacklist / parse_stix_indicators, declared in
// vajra_engine/ThreatIntelFeed.h and used unmodified by the live engine's
// ThreatIntelFeed::refresh_once()) rather than a reimplementation, exactly
// mirroring correlation_validate.cpp's existing pattern: additive new file,
// additive CMake target, never touches an existing engine_v2/src|include
// file.
//
// Two response sources, selected by which env var is set:
//   - VAJRA_FEED_LOCAL_FILE=<path>   reads a local file's bytes directly (no
//     network) -- lets an operator (or this console) test/preview a feed
//     against a downloaded/example bundle without live network egress.
//   - VAJRA_FEED_URL=<url>           fetches over HTTPS (own small curl
//     wrapper, same safety posture as ThreatIntelFeed.cpp's private fetch():
//     HTTPS-only, no redirects, bounded response size/timeouts, TLS
//     verification on) -- used for "abuseipdb" (fixed hardcoded endpoint,
//     url ignored, matching ThreatIntelFeed.cpp's own documented rationale)
//     and for "stix" (the operator-configured url, https:// required).
//
// Other env vars: VAJRA_FEED_FORMAT ("abuseipdb"|"stix", required),
// VAJRA_FEED_API_KEY (optional), VAJRA_FEED_STIX_TYPES (comma-separated
// subset of "ip,domain,hash", default "ip,domain,hash"), VAJRA_FEED_MAX_ENTRIES
// (optional, default 50000).
//
// Prints one "<type>: <count>" line to stdout per observable type (so a
// caller can parse it the same simple way engine_validate.py already parses
// eval_main.cpp's stderr), and any fetch/parse-input error to stderr with a
// non-zero exit code.

#include <curl/curl.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "vajra_engine/ThreatIntelFeed.h"

namespace {

constexpr const char* kAbuseIpDbBlacklistUrl = "https://api.abuseipdb.com/api/v2/blacklist";
constexpr std::size_t kMaxResponseBytes = 20 * 1024 * 1024;  // 20 MiB, same cap as ThreatIntelFeed.cpp

std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string tok;
    while (std::getline(in, tok, ',')) {
        // trim whitespace
        std::size_t start = tok.find_first_not_of(" \t");
        std::size_t end = tok.find_last_not_of(" \t");
        if (start == std::string::npos) continue;
        out.push_back(tok.substr(start, end - start + 1));
    }
    return out;
}

std::size_t write_callback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    const std::size_t bytes = size * nmemb;
    if (out->size() + bytes > kMaxResponseBytes) return 0;
    out->append(ptr, bytes);
    return bytes;
}

// Minimal standalone HTTPS fetch, deliberately mirroring
// ThreatIntelFeed.cpp's private fetch() safety posture (HTTPS-only, no
// redirects, bounded timeouts/response size, TLS verification on) -- that
// function lives in an anonymous namespace there and isn't callable from
// here, so this is a small, intentional duplicate for this standalone tool
// rather than a shared library change (this tool is additive-only, per
// API_CONTRACT_V2.md's ground rules).
bool fetch(const std::string& url, const std::vector<std::string>& headers, std::string& response_out,
           std::string& error_out) {
    static const int curl_init_once = [] {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        return 0;
    }();
    (void)curl_init_once;

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
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vajra-engine-feed-preview/1.0");
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

std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string format = env_or("VAJRA_FEED_FORMAT", "");
    if (format != "abuseipdb" && format != "stix") {
        std::cerr << "vajra_engine_v2_feed_preview: VAJRA_FEED_FORMAT must be 'abuseipdb' or 'stix' "
                     "(got '"
                  << format << "')\n";
        return 1;
    }

    const std::string local_file = env_or("VAJRA_FEED_LOCAL_FILE", "");
    const std::string url_env = env_or("VAJRA_FEED_URL", "");
    const std::string api_key = env_or("VAJRA_FEED_API_KEY", "");
    const std::size_t max_entries = static_cast<std::size_t>(std::stoul(env_or("VAJRA_FEED_MAX_ENTRIES", "50000")));
    std::vector<std::string> stix_types = split_csv(env_or("VAJRA_FEED_STIX_TYPES", "ip,domain,hash"));
    if (stix_types.empty()) stix_types = {"ip", "domain", "hash"};

    std::string response_body;
    std::string source_description;

    if (!local_file.empty()) {
        std::ifstream in(local_file, std::ios::binary);
        if (!in.is_open()) {
            std::cerr << "vajra_engine_v2_feed_preview: cannot open local file " << local_file << "\n";
            return 1;
        }
        std::ostringstream buf;
        buf << in.rdbuf();
        response_body = buf.str();
        source_description = "local file " + local_file;
    } else {
        std::string url;
        std::vector<std::string> headers;
        if (format == "abuseipdb") {
            url = kAbuseIpDbBlacklistUrl;
            headers = {"Key: " + api_key, "Accept: application/json"};
        } else {
            if (url_env.rfind("https://", 0) != 0) {
                std::cerr << "vajra_engine_v2_feed_preview: 'stix' format requires an https:// url "
                             "(got '"
                          << url_env << "')\n";
                return 1;
            }
            url = url_env;
            headers = {"Accept: application/json"};
            if (!api_key.empty()) headers.push_back("Authorization: Bearer " + api_key);
        }

        std::string error;
        if (!fetch(url, headers, response_body, error)) {
            std::cerr << "vajra_engine_v2_feed_preview: fetch failed: " << error << "\n";
            return 1;
        }
        source_description = "https fetch of " + url;
    }

    std::cerr << "vajra_engine_v2_feed_preview: fetched " << response_body.size() << " byte(s) from "
              << source_description << "\n";

    if (format == "abuseipdb") {
        const auto entries = vajra_engine::parse_abuseipdb_blacklist(response_body, max_entries);
        std::cout << "ip: " << entries.size() << "\n";
    } else {
        // parse_stix_indicators returns one flat map for whichever types are
        // passed in `wanted_types` -- called once PER requested type here so
        // the tool can report a genuine per-type breakdown (the contract
        // asks for "how many indicators of each type"), not just one
        // combined total.
        for (const auto& type : stix_types) {
            const auto entries = vajra_engine::parse_stix_indicators(response_body, {type}, max_entries);
            std::cout << type << ": " << entries.size() << "\n";
        }
    }

    return 0;
}
