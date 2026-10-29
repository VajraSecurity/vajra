// vajra_engine -- the detection engine.
//
// Consumes endpoint telemetry from vajra_windows_events/vajra_linux_events
// (published by vajra_server's KafkaProducerManager), decodes each message,
// evaluates the ruleset, and writes matches into the shared `alerts` table
// that vajranet_server_onprem's console reads directly. Runs as its own
// process/systemd unit (like Wazuh's analysisd alongside the Fleet-style
// manager) but on vajra_server's own ConnectionPool, ConfigurationParser and
// Kafka producer/consumer infra -- no separate config schema, DB pool, or
// Kafka client library.
//
// DEPLOYMENT CONSTRAINT (correlation layer): do not run more than one
// vajra_engine instance under the SAME Kafka consumer group. CorrelationEngine's
// entity-window state is entirely in-process (see CorrelationEngine.h) --
// two instances sharing a `group.id` would each see only a partition subset
// of the traffic and independently compute incomplete, inconsistent
// correlation windows, on top of which a partition-ownership handoff during
// a rebalance can redeliver the same message to a different instance than
// the one that already ingested it (see the redelivery-dedup ring in
// main()'s handler below, which protects a SINGLE instance against a
// same-process redelivery/retry but cannot protect across two separate
// processes/instances). Horizontal scaling of vajra_engine for HA is
// possible in principle (distinct consumer groups each reading the full
// topic, or a partition-aware sharding scheme with per-shard correlation
// state) but is NOT implemented by this engine_v2 correlation layer today --
// see .team/mailbox/re-nyx.md's "open risks" for the full analysis
// (round-2 adversarial review, Sage, Finding 4).

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>

#include "../../common/ConfigurationParser.h"
#include "../../common/ConnectionPool.h"
#include "../../common/logger.h"
#include "../../server/KafkaProducerManager.h"
#include "vajra_engine/AlertWriter.h"
#include "vajra_engine/BuiltinRules.h"
#include "vajra_engine/CorrelationEngine.h"
#include "vajra_engine/Decoder.h"
#include "vajra_engine/Envelope.h"
#include "vajra_engine/IncidentWriter.h"
#include "vajra_engine/KafkaConsumer.h"
#include "vajra_engine/Metrics.h"
#include "vajra_engine/RuleEngine.h"
#include "vajra_engine/RulesetLoader.h"
#include "vajra_engine/ThreatIntelFeed.h"

namespace {
vajra_engine::KafkaConsumer* g_consumer = nullptr;
// Set by the SIGHUP handler (async-signal-safe: only a lock-free atomic
// store, no allocation/logging/I/O), consumed once per poll-loop iteration
// on the single consumer thread via KafkaConsumer::run()'s on_tick hook --
// see main()'s comment at the reload call site for why the actual reload
// work must never run inside the signal handler itself.
std::atomic<bool> g_reload_requested{false};

// CorrelationEngine/IncidentWriter counters. NOT added to Vega's Metrics
// class (engine_v2/include/vajra_engine/Metrics.h is his owned file for
// this engagement -- see .team/charter-rule-engine.md's ownership map), so
// this engine keeps its own small atomic counters here instead, read
// cross-thread from render_metrics() exactly like Metrics's own counters
// (see Metrics.h's doc comment on why atomic is required for that read).
std::atomic<std::uint64_t> g_incidents_written_total{0};
// Bumped on a STARTUP ruleset-load failure (falls back to builtin_rules()).
// Per Vega's flagged gap (.team/mailbox/re-nyx.md): unlike the SIGHUP reload
// path, which already calls metrics.record_reload(false), the initial
// startup load failure previously had no counter at all -- the only signal
// was one ERROR log line, easy to miss in a fleet of engines starting up
// unattended. Exposed via render_metrics() below.
std::atomic<std::uint64_t> g_startup_ruleset_load_failed_total{0};

// Bounded FIFO membership set, keyed on (topic, partition, offset) --
// protects CorrelationEngine::ingest() against a SAME-INSTANCE redelivery of
// a message it already ingested (round-2 adversarial review, Sage's
// Finding 4: `IncidentWriter::write()` never rethrows and nothing else in
// the handler can turn an already-ingested message into a
// HandlerOutcome::RetryableError, so this specific in-process double-ingest
// path was already unreachable within a single run -- but Kafka's own
// at-least-once delivery can still hand the SAME (topic,partition,offset)
// to this SAME process again, e.g. a partition reassigned away and back
// during a rebalance before this instance's offset commit lands. This ring
// closes that gap. It does NOT protect across two separate vajra_engine
// PROCESSES sharing one consumer group -- see this file's top-of-file
// deployment-constraint comment; that is a different, larger problem
// (partition-split correlation state, not just redelivery) this ring does
// not attempt to solve.
//
// Deliberately small and bounded (not persistent, not unbounded): duplicate
// delivery from a rebalance window is inherently near-term, so only a
// recent-history window is needed. Capacity is a plain constant, not
// config-driven -- 4000 entries at ~40-60 bytes each (a short topic name
// string + 2 integers, stored twice: once in the dedup set, once in the
// eviction-order deque) is a few hundred KB, negligible next to
// CorrelationEngine's own bounded state.
class RedeliveryDedupRing {
public:
    // Returns true the FIRST time a given key is seen (caller should
    // proceed with ingest()); false if this exact key was already seen
    // (caller should skip ingest() -- a likely redelivery).
    bool mark_seen(const std::string& topic, std::int32_t partition, std::int64_t offset) {
        const Key key{topic, partition, offset};
        if (!seen_.insert(key).second) return false;
        order_.push_back(key);
        if (order_.size() > kCapacity) {
            seen_.erase(order_.front());
            order_.pop_front();
        }
        return true;
    }

private:
    using Key = std::tuple<std::string, std::int32_t, std::int64_t>;
    static constexpr std::size_t kCapacity = 4000;
    std::set<Key> seen_;
    std::deque<Key> order_;
};

void handle_signal(int) {
    if (g_consumer) g_consumer->stop();
}

void handle_reload_signal(int) { g_reload_requested.store(true, std::memory_order_relaxed); }

std::string render_metrics(const vajra_engine::KafkaConsumer& consumer, const vajra_engine::RuleEngine& rules,
                            const vajra_engine::Metrics& metrics,
                            const vajra_engine::CorrelationEngine& correlation_engine) {
    const auto stats = consumer.stats();
    std::ostringstream out;
    out << "# HELP vajra_engine_events_processed_total Kafka messages successfully processed.\n"
        << "# TYPE vajra_engine_events_processed_total counter\n"
        << "vajra_engine_events_processed_total " << stats.processed << "\n"
        << "# HELP vajra_engine_events_retried_total In-process retry attempts before success or "
           "dead-lettering.\n"
        << "# TYPE vajra_engine_events_retried_total counter\n"
        << "vajra_engine_events_retried_total " << stats.retried << "\n"
        << "# HELP vajra_engine_events_dead_lettered_total Messages published to a .dlq topic.\n"
        << "# TYPE vajra_engine_events_dead_lettered_total counter\n"
        << "vajra_engine_events_dead_lettered_total " << stats.dead_lettered << "\n"
        << "# HELP vajra_engine_events_dropped_total Messages left uncommitted for redelivery "
           "(DLQ publish also failed).\n"
        << "# TYPE vajra_engine_events_dropped_total counter\n"
        << "vajra_engine_events_dropped_total " << stats.dropped << "\n"
        << "# HELP vajra_engine_rule_matches_total Rule matches produced by RuleEngine::eval.\n"
        << "# TYPE vajra_engine_rule_matches_total counter\n"
        << "vajra_engine_rule_matches_total " << metrics.rule_matches_total() << "\n"
        << "# HELP vajra_engine_alerts_written_total Alert rows actually inserted into the alerts "
           "table (post-dedup).\n"
        << "# TYPE vajra_engine_alerts_written_total counter\n"
        << "vajra_engine_alerts_written_total " << metrics.alerts_written_total() << "\n"
        << "# HELP vajra_engine_ruleset_reloads_total Successful SIGHUP ruleset reloads.\n"
        << "# TYPE vajra_engine_ruleset_reloads_total counter\n"
        << "vajra_engine_ruleset_reloads_total " << metrics.ruleset_reloads_total() << "\n"
        << "# HELP vajra_engine_ruleset_reload_failures_total Failed SIGHUP ruleset reloads "
           "(old ruleset kept active).\n"
        << "# TYPE vajra_engine_ruleset_reload_failures_total counter\n"
        << "vajra_engine_ruleset_reload_failures_total " << metrics.ruleset_reload_failures_total() << "\n"
        << "# HELP vajra_engine_active_rules Rules currently loaded.\n"
        << "# TYPE vajra_engine_active_rules gauge\n"
        << "vajra_engine_active_rules " << rules.size() << "\n"
        << "# HELP vajra_engine_active_correlation_rules Correlation (alert-to-incident) rules "
           "currently loaded.\n"
        << "# TYPE vajra_engine_active_correlation_rules gauge\n"
        << "vajra_engine_active_correlation_rules " << correlation_engine.rule_count() << "\n"
        << "# HELP vajra_engine_correlation_tracked_groups Entity groups currently held in "
           "CorrelationEngine's bounded in-process state (see CorrelationEngine.cpp's \"Bounded "
           "memory\" comment).\n"
        << "# TYPE vajra_engine_correlation_tracked_groups gauge\n"
        << "vajra_engine_correlation_tracked_groups " << correlation_engine.tracked_group_count() << "\n"
        << "# HELP vajra_engine_incidents_written_total Incident rows written/updated by "
           "IncidentWriter.\n"
        << "# TYPE vajra_engine_incidents_written_total counter\n"
        << "vajra_engine_incidents_written_total "
        << g_incidents_written_total.load(std::memory_order_relaxed) << "\n"
        << "# HELP vajra_engine_startup_ruleset_load_failed_total Startup (not SIGHUP) ruleset "
           "load failures -- 1 means this instance is running on builtin_rules() instead of its "
           "configured ruleset.\n"
        << "# TYPE vajra_engine_startup_ruleset_load_failed_total counter\n"
        << "vajra_engine_startup_ruleset_load_failed_total "
        << g_startup_ruleset_load_failed_total.load(std::memory_order_relaxed) << "\n"
        << "# HELP vajra_engine_regex_timeout_total Regex searches that hit the execution-time "
           "deadline and were treated as non-match (see JsonSafety.h's regex_search_bounded doc).\n"
        << "# TYPE vajra_engine_regex_timeout_total counter\n"
        << "vajra_engine_regex_timeout_total " << metrics.regex_timeouts_total() << "\n";
    return out.str();
}

// Adapts config-parser types to the engine's ThreatIntelFeedConfig, the
// same "main.cpp adapts config to engine types" pattern already used for
// Kafka topics below. If "feeds" is empty but the legacy singular
// abuseipdb_api_key is set, synthesizes an equivalent single feed so a
// pre-multi-feed config.json keeps working without a manual migration.
std::vector<vajra_engine::ThreatIntelFeedConfig> build_feed_configs(
    const RuleEngineConfiguration& rule_engine_config) {
    std::vector<vajra_engine::ThreatIntelFeedConfig> configs;
    const auto& ti = rule_engine_config.threat_intelligence;
    if (!ti.enabled) return configs;

    if (!ti.feeds.empty()) {
        for (const auto& f : ti.feeds) {
            if (!f.enabled) continue;
            vajra_engine::ThreatIntelFeedConfig cfg;
            cfg.name = f.name.empty() ? f.format : f.name;
            cfg.format = f.format;
            cfg.enabled = true;
            cfg.url = f.url;
            cfg.api_key = f.api_key;
            cfg.target_list = f.target_list.empty() ? "deny_ips" : f.target_list;
            cfg.refresh_interval_seconds =
                f.refresh_interval_seconds > 0 ? f.refresh_interval_seconds : 3600;
            cfg.max_entries = f.max_entries > 0 ? f.max_entries : 50000;
            cfg.stix_types = f.stix_types.empty() ? std::vector<std::string>{"ip"} : f.stix_types;
            configs.push_back(std::move(cfg));
        }
        return configs;
    }

    if (!ti.abuseipdb_api_key.empty()) {
        vajra_engine::ThreatIntelFeedConfig cfg;
        cfg.name = "abuseipdb-legacy";
        cfg.format = "abuseipdb";
        cfg.enabled = true;
        cfg.api_key = ti.abuseipdb_api_key;
        cfg.target_list = "deny_ips";
        cfg.refresh_interval_seconds = ti.cache_ttl_seconds > 0 ? ti.cache_ttl_seconds : 3600;
        configs.push_back(std::move(cfg));
    }
    return configs;
}
}  // namespace

int main(int argc, char** argv) {
    const std::string config_path = argc > 1 ? argv[1] : "config.json";

    ConfigurationParser config_parser(config_path);
    if (!config_parser.parse()) {
        std::cerr << "vajra_engine: failed to parse " << config_path << std::endl;
        return 1;
    }

    FleetServerConfiguration fleet = config_parser.GetFleetConfiguration();
    const RuleEngineConfiguration rule_engine_config = config_parser.GetRuleEngineConfiguration();
    const LogConfiguration log_config = config_parser.GetLogConfiguration("engine");

    std::filesystem::path log_path =
        std::filesystem::path(log_config.log_directory) / log_config.log_file;
    init_logging(log_path.string(), log_config.log_level, log_config.log_size);

    try {
        auto connection_string = fleet.database.ConnectionString();
        const unsigned int pool_size = rule_engine_config.db_connection_pool_size > 0
                                            ? rule_engine_config.db_connection_pool_size
                                            : 10;
        auto pool = std::make_shared<ConnectionPool>(connection_string, pool_size);

        // Empty if unset -- also used later to gate whether SIGHUP has
        // anything to reload from (no ruleset file configured means the
        // process is running on builtin_rules(), which SIGHUP can't refresh).
        const char* rules_path_env = std::getenv("VAJRA_ENGINE_RULES");
        const std::string rules_path = rules_path_env ? rules_path_env : "";

        vajra_engine::RuleEngine rules;
        vajra_engine::Decoder decoder;
        if (!rules_path.empty()) {
            try {
                vajra_engine::load_ruleset_file(rules_path, rules, &decoder);
                BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: loaded ruleset from "
                                         << rules_path;
            } catch (const std::exception& e) {
                g_startup_ruleset_load_failed_total.fetch_add(1, std::memory_order_relaxed);
                auto fallback = vajra_engine::builtin_rules();
                BOOST_LOG_TRIVIAL(error)
                    << __SRCREF__ << "vajra_engine: could not load ruleset " << rules_path << ": "
                    << e.what() << " -- using " << fallback.size()
                    << " builtin rule(s) instead of the configured ruleset -- see "
                       "vajra_engine_startup_ruleset_load_failed_total";
                rules.load(std::move(fallback));
            }
        } else {
            rules.load(vajra_engine::builtin_rules());
        }
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: " << rules.size()
                                 << " rule(s) active, " << decoder.decoder_rule_count()
                                 << " decoder(s) active";

        // Alert-to-incident correlation layer (engine_v2 addition -- see
        // CorrelationEngine.h). Reads the SAME ruleset file's optional
        // "correlations" section, independently of load_ruleset_file above
        // (see CorrelationEngine.h's doc comment on why this loader is
        // separate from Vega's RulesetLoader). Empty/absent "correlations"
        // -- including when no VAJRA_ENGINE_RULES is configured at all --
        // leaves rule_count() == 0, so ingest() is never called and this
        // feature costs nothing for an operator not using it.
        vajra_engine::CorrelationEngine correlation_engine;
        if (!rules_path.empty()) {
            try {
                correlation_engine.load(vajra_engine::load_correlation_rules_file(rules_path));
            } catch (const std::exception& e) {
                BOOST_LOG_TRIVIAL(error)
                    << __SRCREF__ << "vajra_engine: could not load correlation rules from "
                    << rules_path << ": " << e.what() << " -- correlation disabled";
            }
        }
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: " << correlation_engine.rule_count()
                                 << " correlation rule(s) active";

        // Refreshes ListStore's configured lists in the background (its own
        // internal locking, see Rule.h) -- never touches rules/history, so
        // it can't disrupt an in-progress correlation window. One worker
        // per configured feed; no-ops internally for any feed that's
        // disabled or missing required config.
        vajra_engine::ThreatIntelFeedManager threat_intel_manager(build_feed_configs(rule_engine_config),
                                                                    rules.lists());
        threat_intel_manager.start();

        vajra_engine::AlertWriter writer(pool);
        vajra_engine::IncidentWriter incident_writer(pool);
        vajra_engine::Metrics metrics;
        // See RedeliveryDedupRing's doc comment: protects CorrelationEngine::
        // ingest() against a same-instance Kafka redelivery of a message it
        // already ingested.
        RedeliveryDedupRing redelivery_ring;

        // Same broker as the ingest side unless rule_engine.kafka overrides it.
        std::string bootstrap_servers = rule_engine_config.kafka.bootstrap_servers;
        if (bootstrap_servers.empty() || bootstrap_servers == "localhost:9092") {
            bootstrap_servers = fleet.kafka_producer.bootstrap_servers;
        }

        // DLQ producer: the same KafkaProducerManager singleton vajra_server's
        // ingest path uses, reused here rather than duplicated.
        auto& kafka_producer = KafkaProducerManager::getInstance();
        kafka_producer.initialize(bootstrap_servers, "vajra-engine-dlq");

        vajra_engine::ConsumerOptions options;
        options.bootstrap_servers = bootstrap_servers;
        options.group_id = rule_engine_config.kafka.consumer_group_id.empty()
                                ? "vajra-engine"
                                : rule_engine_config.kafka.consumer_group_id;
        options.security_protocol = rule_engine_config.kafka.security_protocol.empty()
                                         ? "PLAINTEXT"
                                         : rule_engine_config.kafka.security_protocol;
        options.session_timeout_ms = rule_engine_config.kafka.session_timeout_ms;
        options.max_poll_interval_ms = rule_engine_config.kafka.max_poll_interval_ms;

        options.topics.clear();
        for (const auto& event_type : rule_engine_config.event_types) {
            if (event_type.enabled && !event_type.kafka_topic.empty()) {
                options.topics.push_back(event_type.kafka_topic);
            }
        }
        if (options.topics.empty()) {
            // Fall back to the confirmed 2-topic architecture
            // (server/KafkaProducerManager.h::initializeTopicMap).
            options.topics = {"vajra_windows_events", "vajra_linux_events"};
        }

        vajra_engine::KafkaConsumer consumer(options);
        g_consumer = &consumer;
        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);
        std::signal(SIGHUP, handle_reload_signal);

        // Off by default (rule_engine.metrics.enabled). render_metrics reads
        // consumer/rules/metrics from the MetricsServer's own accept-loop
        // thread; each of those three is safe for that cross-thread read
        // (KafkaConsumer::Stats/RuleEngine::size()/Metrics's counters are
        // all atomic-backed -- see their respective header comments).
        std::unique_ptr<vajra_engine::MetricsServer> metrics_server;
        if (rule_engine_config.metrics.enabled) {
            metrics_server = std::make_unique<vajra_engine::MetricsServer>(
                rule_engine_config.metrics.bind_address,
                static_cast<unsigned short>(rule_engine_config.metrics.port),
                [&consumer, &rules, &metrics, &correlation_engine]() {
                    return render_metrics(consumer, rules, metrics, correlation_engine);
                });
            metrics_server->start();
        }

        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: consuming " << options.topics.size()
                                 << " topic(s) from " << bootstrap_servers;

        consumer.run(
            [&](const vajra_engine::MessageView& msg) -> vajra_engine::HandlerOutcome {
                using vajra_engine::HandlerOutcome;

                vajra_engine::Envelope env;
                try {
                    env = vajra_engine::Envelope::from_json_text(std::string(msg.value));
                } catch (const std::exception& e) {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "vajra_engine: undecodable message on "
                                                << msg.topic << ": " << e.what();
                    return HandlerOutcome::PermanentError;  // will never decode; dead-letter, don't retry
                }

                try {
                    const auto ev = decoder.decode(env);
                    const auto matches = rules.eval(ev);
                    if (!matches.empty()) {
                        metrics.record_rule_matches(matches.size());
                        const auto write_results = writer.write(ev, matches);
                        std::size_t newly_inserted = 0;
                        for (const auto& r : write_results) {
                            if (r.newly_inserted) ++newly_inserted;
                        }
                        if (newly_inserted > 0) metrics.record_alerts_written(newly_inserted);

                        // Alert-to-incident correlation (engine_v2 addition).
                        // Skipped entirely when no correlation rules are
                        // loaded -- same "untracked costs nothing" posture
                        // RuleEngine's own tracked_rule_ids_ uses. Uses the
                        // SAME clamped event-time clock RuleEngine::eval()
                        // used internally (clamp_correlation_now_ms), so
                        // rule-level and incident-level correlation windows
                        // agree on "now" and share the same
                        // attacker-timestamp clamping.
                        if (correlation_engine.rule_count() > 0) {
                            // Redelivery guard (see RedeliveryDedupRing's doc
                            // comment): a message already ingested by THIS
                            // instance must not be pushed into
                            // CorrelationEngine's windows a second time --
                            // event_count/value_count would double-count a
                            // duplicate ContributingEvent. Gated here, not
                            // inside ingest() itself, so it stays a pure
                            // main.cpp-local concern with zero changes to
                            // CorrelationEngine's public API.
                            if (!redelivery_ring.mark_seen(msg.topic, msg.partition, msg.offset)) {
                                BOOST_LOG_TRIVIAL(warning)
                                    << __SRCREF__ << "vajra_engine: correlation: skipping likely "
                                                     "redelivery of "
                                    << msg.topic << "[" << msg.partition << "]@" << msg.offset
                                    << " -- already ingested by this instance";
                            } else {
                                const std::int64_t wall_clock_ms =
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count();
                                const std::int64_t now_ms =
                                    vajra_engine::clamp_correlation_now_ms(ev.unix_time, wall_clock_ms);
                                const auto incidents =
                                    correlation_engine.ingest(ev, matches, write_results, now_ms);
                                if (!incidents.empty()) {
                                    const int incidents_written = incident_writer.write(incidents);
                                    g_incidents_written_total.fetch_add(
                                        static_cast<std::uint64_t>(incidents_written),
                                        std::memory_order_relaxed);
                                }
                            }
                        }
                    }
                    return HandlerOutcome::Success;
                } catch (const std::exception& e) {
                    // Likely transient (e.g. DB blip): retry, then dead-letter.
                    BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: processing failure: "
                                              << e.what();
                    return HandlerOutcome::RetryableError;
                }
            },
            [&]() {
                // Runs on the same thread as the handler above, once per
                // poll-loop iteration (including idle ticks) -- see
                // KafkaConsumer::run()'s doc comment. Reload work (file I/O,
                // regex compilation, replacing rules_/decoder_rules_) is
                // intentionally NOT done inside handle_reload_signal() itself:
                // that runs in actual signal-handler context, where only
                // async-signal-safe operations (like the atomic store it
                // does) are allowed -- doing the real reload there would risk
                // reentrancy/undefined behavior (e.g. if SIGHUP arrives while
                // the consumer thread is already mid-allocation).
                if (!g_reload_requested.exchange(false, std::memory_order_relaxed)) return;

                if (rules_path.empty()) {
                    BOOST_LOG_TRIVIAL(warning)
                        << __SRCREF__
                        << "vajra_engine: SIGHUP received but no VAJRA_ENGINE_RULES file is "
                           "configured (running on builtin rules) -- nothing to reload";
                    return;
                }

                try {
                    vajra_engine::load_ruleset_file(rules_path, rules, &decoder);
                    metrics.record_reload(true);
                    BOOST_LOG_TRIVIAL(info)
                        << __SRCREF__ << "vajra_engine: SIGHUP reload succeeded from " << rules_path
                        << " -- " << rules.size() << " rule(s), " << decoder.decoder_rule_count()
                        << " decoder(s) active";

                    // Correlation rules reload independently of the above --
                    // a parse failure here must not be reported as an
                    // overall reload failure (the detection ruleset DID
                    // reload successfully) and must not touch
                    // correlation_engine's state at all (see
                    // CorrelationEngine::load()'s doc comment on why a
                    // malformed "correlations" section leaves the previous,
                    // still-valid correlation ruleset -- and its in-flight
                    // group windows -- completely untouched).
                    try {
                        correlation_engine.load(vajra_engine::load_correlation_rules_file(rules_path));
                        BOOST_LOG_TRIVIAL(info)
                            << __SRCREF__ << "vajra_engine: SIGHUP reload: " << correlation_engine.rule_count()
                            << " correlation rule(s) active";
                    } catch (const std::exception& ce) {
                        BOOST_LOG_TRIVIAL(error)
                            << __SRCREF__ << "vajra_engine: SIGHUP reload: correlation rules from "
                            << rules_path << " failed, keeping the previous correlation ruleset: "
                            << ce.what();
                    }
                } catch (const std::exception& e) {
                    metrics.record_reload(false);
                    BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: SIGHUP reload from "
                                              << rules_path << " failed, keeping the previous ruleset: "
                                              << e.what();
                }
            });

        if (metrics_server) metrics_server->stop();
        threat_intel_manager.stop();
        kafka_producer.flush(10000);
        const auto stats = consumer.stats();
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: stopped (processed=" << stats.processed
                                 << ", retried=" << stats.retried
                                 << ", dead_lettered=" << stats.dead_lettered
                                 << ", dropped=" << stats.dropped << ")";

        // std::_Exit, not a normal return, deliberately: KafkaProducerManager
        // (server/KafkaProducerManager.h) has a static-storage-duration
        // singleton whose destructor calls BOOST_LOG_TRIVIAL -- specifically
        // the function-local Meyer's singleton inside getInstance() (NOT the
        // separately-declared `static std::unique_ptr<KafkaProducerManager>
        // instance_` member, which is dead code: nothing in the repo ever
        // assigns it, per the class's own comment marking it "superseded").
        // At normal process exit, C++ runs global/static destructors across
        // ALL translation units and shared libraries in an order the
        // standard leaves UNSPECIFIED across TUs -- confirmed live
        // (production, 2026-09-17): if Boost.Log's own internal statics are
        // torn down before that Meyer's-singleton's destructor runs, the
        // BOOST_LOG_TRIVIAL call inside ~KafkaProducerManager() dereferences
        // an already-destroyed logging core and segfaults during
        // __run_exit_handlers, right as systemctl stop/SIGTERM shutdown
        // reaches this exact point -- see the gdb backtrace this fix was
        // written against (Thread 1: get_logging_enabled() ->
        // KafkaProducerManager::shutdown() -> ~unique_ptr<KafkaProducerManager>
        // -> __run_exit_handlers -> exit; that unique_ptr frame is the
        // Meyer's singleton's own internal storage, not the dead `instance_`
        // member). This is a pre-existing latent bug in the shared
        // KafkaProducerManager class, not introduced by engine_v2 -- fixed
        // here, scoped to this binary only, rather than in the shared
        // header, since vajra_server (which also links it) is out
        // of scope for this engagement and its own shutdown path was never
        // touched. Every explicit, order-sensitive cleanup step (metrics
        // server stop, threat-intel stop, producer flush, final stats log)
        // has already completed above by this point, so skipping the REST of
        // static destruction is safe: the OS reclaims every fd/socket/DB
        // connection/memory page on process exit regardless of whether C++
        // destructors run for them.
        std::_Exit(0);
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "vajra_engine: fatal: " << e.what();
        std::cerr << "vajra_engine: fatal: " << e.what() << std::endl;
        std::_Exit(1);  // same static-destructor-order hazard applies here
    }

    std::_Exit(0);  // same static-destructor-order hazard applies here
}
