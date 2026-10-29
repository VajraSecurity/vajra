#ifndef VAJRA_ENGINE_METRICS_H
#define VAJRA_ENGINE_METRICS_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "vajra_engine/JsonSafety.h"

namespace vajra_engine {

// Plain counters vajra_engine accumulates outside KafkaConsumer::Stats
// (which already tracks processed/retried/dead_lettered/dropped safely --
// see KafkaConsumer.h). Incremented only from the single consumer thread
// (main.cpp's message handler); read from MetricsServer's own thread --
// hence atomic, same reasoning as KafkaConsumer::AtomicStats and
// RuleEngine::size()'s rule_count_.
class Metrics {
public:
    void record_rule_matches(std::size_t n) {
        rule_matches_total_.fetch_add(n, std::memory_order_relaxed);
    }
    void record_alerts_written(std::size_t n) {
        alerts_written_total_.fetch_add(n, std::memory_order_relaxed);
    }
    void record_reload(bool success) {
        if (success) {
            ruleset_reloads_total_.fetch_add(1, std::memory_order_relaxed);
        } else {
            ruleset_reload_failures_total_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::uint64_t rule_matches_total() const {
        return rule_matches_total_.load(std::memory_order_relaxed);
    }
    std::uint64_t alerts_written_total() const {
        return alerts_written_total_.load(std::memory_order_relaxed);
    }
    std::uint64_t ruleset_reloads_total() const {
        return ruleset_reloads_total_.load(std::memory_order_relaxed);
    }
    std::uint64_t ruleset_reload_failures_total() const {
        return ruleset_reload_failures_total_.load(std::memory_order_relaxed);
    }

    // Not a locally-tracked counter -- delegates to JsonSafety.h's
    // regex_search_timeout_count(), the single process-wide counter
    // regex_search_bounded() itself increments (see its doc comment).
    // Exposed here purely so render_metrics() (main.cpp) can read every
    // vajra_engine_* counter through one `Metrics` instance uniformly,
    // without needing a second, differently-shaped source.
    std::uint64_t regex_timeouts_total() const { return regex_search_timeout_count(); }

private:
    std::atomic<std::uint64_t> rule_matches_total_{0};
    std::atomic<std::uint64_t> alerts_written_total_{0};
    std::atomic<std::uint64_t> ruleset_reloads_total_{0};
    std::atomic<std::uint64_t> ruleset_reload_failures_total_{0};
};

// Minimal single-purpose HTTP server exposing a Prometheus text-exposition
// GET /metrics endpoint on its own background thread. Deliberately simple:
// one blocking accept -> read -> respond -> close cycle per request (no
// keep-alive, no routing beyond this one path, no chunked/partial-request
// reassembly), which is all a low-frequency internal Prometheus scrape
// target needs -- not a general-purpose HTTP server. Renders its body from
// a caller-supplied callback rather than owning the counters itself, so one
// server can combine Metrics with KafkaConsumer::Stats and RuleEngine::
// size() without depending on either type.
//
// Off by default (see rule_engine.metrics.enabled in ConfigurationParser);
// when enabled, binds to an operator-configured address (default
// "127.0.0.1", i.e. loopback-only unless explicitly widened) with no
// authentication, matching how Prometheus exporters are conventionally
// deployed (network-restricted, not endpoint-authenticated).
class MetricsServer {
public:
    MetricsServer(std::string bind_address, unsigned short port, std::function<std::string()> render);
    ~MetricsServer();

    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;

    // No-op (logged, not fatal) if the listen socket can't be bound (e.g.
    // the port is already in use, or bind_address doesn't parse as an
    // IPv4 address) -- a metrics endpoint failing to start must never take
    // down event processing. Safe to call repeatedly (guarded by an
    // internal mutex), matching ThreatIntelFeed::start()'s posture.
    void start();
    // Idempotent; also called from the destructor.
    void stop();

private:
    void run();

    std::string bind_address_;
    unsigned short port_;
    std::function<std::string()> render_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::mutex lifecycle_mutex_;  // guards start()/stop() against concurrent misuse
    // Atomic, not plain int: run()'s accept-loop thread reads this (once, at
    // loop start -- see Metrics.cpp) while stop() can concurrently write it
    // from a different thread with no lock shared between the two (the
    // mutex above only serializes start()/stop() against each other). A
    // plain int would make that a data race (confirmed via ThreadSanitizer
    // during this review -- see re-vega.md); atomic makes both accesses
    // well-defined without adding another lock to the hot accept loop.
    std::atomic<int> listen_fd_{-1};
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_METRICS_H
