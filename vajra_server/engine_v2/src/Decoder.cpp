#include <ctime>
#include "vajra_engine/Decoder.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "../../common/logger.h"
#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {
namespace {

void flatten(const nlohmann::json& j, const std::string& prefix,
             std::map<std::string, std::string>& out) {
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            const std::string key = prefix.empty() ? it.key() : prefix + "." + it.key();
            flatten(it.value(), key, out);
        }
        return;
    }
    if (j.is_null() || prefix.empty()) return;  // drop nulls; never flatten the bare root scalar
    if (j.is_array()) {
        out[prefix] = j.dump();
    } else if (j.is_string()) {
        out[prefix] = j.get<std::string>();
    } else if (j.is_boolean()) {
        out[prefix] = j.get<bool>() ? "true" : "false";
    } else {
        out[prefix] = j.dump();  // numbers
    }
}

// event_type -> { raw wire field -> canonical dotted alias }. Additive only:
// never overwrites a key already present (raw keys always win a collision).
// Grounded in the exact fields server/request_handler.cpp publishes per
// event_type, not guessed.
const std::map<std::string, std::vector<std::pair<std::string, std::string>>>& alias_table() {
    static const std::map<std::string, std::vector<std::pair<std::string, std::string>>> table = {
        {"bpf_process",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"tid", "process.tid"},
          {"uid", "process.uid"},
          {"gid", "process.gid"},
          {"cid", "process.container_id"},
          {"path", "process.executable"},
          {"cwd", "process.cwd"},
          {"cmdline", "process.command_line"},
          {"syscall", "process.syscall"},
          {"md5", "process.hash.md5"},
          {"sha1", "process.hash.sha1"},
          {"sha256", "process.hash.sha256"}}},
        {"bpf_socket",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"tid", "process.tid"},
          {"uid", "process.uid"},
          {"gid", "process.gid"},
          {"cid", "process.container_id"},
          {"path", "process.executable"},
          {"syscall", "process.syscall"},
          {"remote_address", "network.remote_address"},
          {"local_address", "network.local_address"},
          {"remote_port", "network.remote_port"},
          {"local_port", "network.local_port"}}},
        {"bpf_file",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"tid", "process.tid"},
          {"uid", "process.uid"},
          {"gid", "process.gid"},
          {"cid", "process.container_id"},
          {"path", "process.executable"},
          {"file_path", "file.path"},
          {"syscall", "process.syscall"},
          {"flags", "file.flags"}}},
        {"win_process",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"path", "process.executable"},
          {"cmdline", "process.command_line"},
          {"process_guid", "process.guid"},
          {"parent_process_guid", "process.parent_guid"},
          {"parent_path", "process.parent_executable"},
          {"sha256", "process.hash.sha256"},
          {"action", "event.action"}}},
        {"win_socket",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"process_name", "process.name"},
          {"remote_address", "network.remote_address"},
          {"local_address", "network.local_address"},
          {"remote_port", "network.remote_port"},
          {"local_port", "network.local_port"},
          {"protocol", "network.protocol"},
          {"action", "event.action"}}},
        {"win_file",
         {{"pid", "process.pid"},
          {"ppid", "process.parent_pid"},
          {"process_name", "process.name"},
          {"target_path", "file.path"},
          {"md5", "file.hash.md5"},
          {"sha256", "file.hash.sha256"},
          {"action", "event.action"}}},
        {"win_dns",
         {{"pid", "process.pid"},
          {"domain_name", "dns.domain_name"},
          {"request_type", "dns.request_type"},
          {"request_class", "dns.request_class"},
          {"remote_address", "network.remote_address"},
          {"remote_port", "network.remote_port"},
          {"action", "event.action"}}},
        {"win_dns_response",
         {{"pid", "process.pid"},
          {"domain_name", "dns.domain_name"},
          {"resolved_ip", "dns.resolved_ip"},
          {"request_type", "dns.request_type"},
          {"request_class", "dns.request_class"},
          {"remote_address", "network.remote_address"},
          {"remote_port", "network.remote_port"},
          {"action", "event.action"}}},
        {"win_ssl",
         {{"pid", "process.pid"},
          {"process_guid", "process.guid"},
          {"process_name", "process.name"},
          {"dns_names", "ssl.dns_names"},
          {"server_name", "ssl.server_name"},
          {"subject_name", "ssl.subject_name"},
          {"ja3_md5", "ssl.ja3_md5"},
          {"ja3s_md5", "ssl.ja3s_md5"},
          {"remote_address", "network.remote_address"},
          {"remote_port", "network.remote_port"},
          {"action", "event.action"}}},
        {"win_http",
         {{"pid", "process.pid"},
          {"process_guid", "process.guid"},
          {"process_name", "process.name"},
          {"url", "http.url"},
          {"remote_address", "network.remote_address"},
          {"remote_port", "network.remote_port"},
          {"action", "event.action"}}},
        {"win_registry",
         {{"pid", "process.pid"},
          {"process_name", "process.name"},
          {"target_name", "registry.target_name"},
          {"target_new_name", "registry.target_new_name"},
          {"value_type", "registry.value_type"},
          {"value_data", "registry.value_data"},
          {"action", "event.action"}}},
        // Raw Windows Security/Application/Sysmon-provider Event Log entries
        // (server/request_handler.cpp's "windows_eventlog" table). Not
        // scheduled by default -- only present if an operator explicitly
        // enables collection -- but decoded here so that IF it ever is
        // collected, rules written against these canonical fields can match
        // it immediately rather than silently seeing only raw field names.
        // `eventlog.data` is where Sysmon-style providers embed structured
        // event data (e.g. a command line, an image path) as free text --
        // the single field most detections against this table need.
        {"windows_eventlog",
         {{"pid", "process.pid"},
          {"tid", "process.tid"},
          {"channel", "eventlog.channel"},
          {"provider_name", "eventlog.provider_name"},
          {"provider_guid", "eventlog.provider_guid"},
          {"computer_name", "eventlog.computer_name"},
          {"eventid", "eventlog.event_id"},
          {"task", "eventlog.task"},
          {"level", "eventlog.level"},
          {"keywords", "eventlog.keywords"},
          {"data", "eventlog.data"},
          {"datetime", "eventlog.datetime"},
          {"timestamp", "eventlog.timestamp"},
          {"time_range", "eventlog.time_range"},
          {"xpath", "eventlog.xpath"}}},
    };
    return table;
}

std::string derive_os(const std::string& event_type) {
    if (event_type.rfind("win_", 0) == 0) return "windows";
    if (event_type == "windows_eventlog") return "windows";
    if (event_type.rfind("bpf_", 0) == 0) return "linux";
    return "";
}

// Event time in epoch SECONDS. "unixtime" is the server-stamped event time;
// "time"/"utc_time" are osquery columns that can be absent, boot-relative or in
// a finer unit, so they are only trusted when they look like a real epoch.
// Values in ms/us/ns are scaled down. Falls back to the engine's wall clock so
// an alert is never stamped 1970 (which the console renders as ~20755 days old).
std::int64_t to_epoch_seconds(std::int64_t v) {
    if (v >= 100000000000000000LL) return v / 1000000000LL;  // ns
    if (v >= 100000000000000LL) return v / 1000000LL;        // us
    if (v >= 100000000000LL) return v / 1000LL;              // ms
    return v;
}

std::int64_t parse_unix_time(const std::map<std::string, std::string>& fields) {
    for (const char* key : {"unixtime", "unixTime", "time", "utc_time"}) {
        const bool authoritative = key[0] == 'u' && key[1] == 'n';
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) continue;
        try {
            std::size_t pos = 0;
            const std::int64_t raw = static_cast<std::int64_t>(std::stoll(it->second, &pos));
            if (pos != it->second.size()) continue;  // reject partial parses, e.g. "123abc"
            const std::int64_t value = to_epoch_seconds(raw);
            if (value <= 0) continue;
            if (!authoritative && value < 1000000000LL) continue;  // boot-relative, not an epoch
            return value;
        } catch (const std::exception&) {
            continue;
        }
    }
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

void Decoder::load_decoder_rules(std::vector<DecoderRuleConfig> configs) {
    std::vector<DecoderRule> compiled;
    compiled.reserve(configs.size());

    for (auto& cfg : configs) {
        if (cfg.extract.empty() || cfg.source_field.empty()) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: decoder '" << cfg.name
                                        << "' missing required 'source_field'/'extract' -- skipped";
            continue;
        }

        // Load-time pattern screens, applied before compilation: an
        // oversized pattern (accidental or malicious ruleset content) can't
        // cause slow std::regex compilation or an oversized NFA, and a
        // pattern shaped for catastrophic backtracking (e.g. `(a+)+`)
        // never reaches std::regex_search against attacker-controlled event
        // data at all -- see JsonSafety.h's doc comments. Same "skip this
        // one decoder, never block the rest of the load" posture as an
        // outright regex compile failure below.
        if (cfg.extract.size() > kMaxRegexPatternLength || cfg.prematch.size() > kMaxRegexPatternLength) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: decoder '" << cfg.name
                                        << "' prematch/extract pattern exceeds " << kMaxRegexPatternLength
                                        << " bytes -- skipped";
            continue;
        }
        if (looks_like_catastrophic_regex(cfg.extract) || looks_like_catastrophic_regex(cfg.prematch)) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: decoder '" << cfg.name
                                        << "' prematch/extract pattern looks like it can catastrophically "
                                           "backtrack (nested quantifiers) -- skipped";
            continue;
        }

        DecoderRule rule;
        rule.name = cfg.name;
        rule.event_type = cfg.event_type;
        rule.source_field = cfg.source_field;
        rule.captures = cfg.captures;

        try {
            rule.extract_compiled =
                std::make_shared<std::regex>(cfg.extract, std::regex::ECMAScript | std::regex::optimize);
        } catch (const std::regex_error& e) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: invalid extract regex for decoder '"
                                        << cfg.name << "': " << e.what() << " -- skipped";
            continue;
        }

        if (!cfg.prematch.empty()) {
            try {
                rule.prematch_compiled = std::make_shared<std::regex>(
                    cfg.prematch, std::regex::ECMAScript | std::regex::optimize);
            } catch (const std::regex_error& e) {
                BOOST_LOG_TRIVIAL(warning)
                    << __SRCREF__ << "vajra_engine: invalid prematch regex for decoder '" << cfg.name
                    << "': " << e.what() << " -- skipped";
                continue;
            }
        }

        compiled.push_back(std::move(rule));
    }

    decoder_rules_ = std::move(compiled);
}

namespace {

// See the identical rationale in RuleEngine.cpp: decoder prematch/extract
// PATTERNS are operator-authored (trusted), but source_value is a raw event
// field value (attacker/compromised-endpoint-controlled). Bounds worst-case
// std::regex_search input size regardless of how large an attacker makes
// the underlying field -- doesn't eliminate catastrophic backtracking, but
// caps its blast radius to a fixed input size.
constexpr std::size_t kMaxRegexInputBytes = 16384;

// Additive only, like the alias table: a decoder never overwrites a field
// the event already has, whether from raw wire data or an earlier decoder
// in the list.
void apply_decoder_rules(const std::vector<DecoderRule>& decoder_rules, NormalizedEvent& ev) {
    for (const auto& rule : decoder_rules) {
        if (!rule.event_type.empty() && rule.event_type != ev.event_type) continue;
        if (!ev.has(rule.source_field)) continue;
        const std::string& source_value = ev.fields.at(rule.source_field);
        if (source_value.size() > kMaxRegexInputBytes) continue;

        // regex_search_bounded, not a bare std::regex_search: the input-
        // size cap just above bounds POLYNOMIAL worst-case cost, not
        // EXPONENTIAL blowups from a pathological pattern (e.g. ambiguous
        // alternation under a quantifier, `(a|aa)+` -- a shape
        // looks_like_catastrophic_regex()'s load-time screen does not
        // catch; see JsonSafety.h). A timeout here fails closed for just
        // this one decoder rule, not the whole pipeline.
        if (rule.prematch_compiled) {
            const auto outcome = regex_search_bounded(source_value, *rule.prematch_compiled);
            if (outcome == RegexSearchOutcome::TimedOut) {
                BOOST_LOG_TRIVIAL(error)
                    << __SRCREF__ << "vajra_engine: decoder '" << rule.name
                    << "' prematch regex_search timed out (>" << kRegexSearchTimeout.count()
                    << "ms) against field '" << rule.source_field
                    << "' -- treating as no-match; fix or disable this decoder's prematch pattern";
                continue;
            }
            if (outcome == RegexSearchOutcome::NoMatch) continue;
        }

        std::smatch match;
        if (!rule.extract_compiled) continue;
        const auto extract_outcome = regex_search_bounded(source_value, *rule.extract_compiled, &match);
        if (extract_outcome == RegexSearchOutcome::TimedOut) {
            BOOST_LOG_TRIVIAL(error)
                << __SRCREF__ << "vajra_engine: decoder '" << rule.name << "' extract regex_search timed out (>"
                << kRegexSearchTimeout.count() << "ms) against field '" << rule.source_field
                << "' -- treating as no-match; fix or disable this decoder's extract pattern";
            continue;
        }
        if (extract_outcome == RegexSearchOutcome::NoMatch) continue;

        const std::size_t group_count = match.size() > 0 ? match.size() - 1 : 0;
        const std::size_t n = std::min(rule.captures.size(), group_count);
        for (std::size_t i = 0; i < n; ++i) {
            const std::string& dest_field = rule.captures[i];
            if (dest_field.empty() || !match[i + 1].matched) continue;
            if (ev.fields.count(dest_field) != 0) continue;  // additive only
            ev.fields[dest_field] = match[i + 1].str();
        }
    }
}

}  // namespace

NormalizedEvent Decoder::decode(const Envelope& env) const {
    NormalizedEvent ev;
    ev.event_type = env.event_type;
    ev.host_identifier = env.host_identifier;

    flatten(env.payload, "", ev.fields);

    if (auto it = alias_table().find(env.event_type); it != alias_table().end()) {
        for (const auto& [raw_key, canonical] : it->second) {
            if (ev.fields.count(canonical) != 0) continue;  // additive only
            auto raw_it = ev.fields.find(raw_key);
            if (raw_it != ev.fields.end()) ev.fields[canonical] = raw_it->second;
        }
    }

    ev.os = !env.os.empty() ? env.os : derive_os(env.event_type);
    ev.unix_time = parse_unix_time(ev.fields);

    apply_decoder_rules(decoder_rules_, ev);

    return ev;
}

}  // namespace vajra_engine
