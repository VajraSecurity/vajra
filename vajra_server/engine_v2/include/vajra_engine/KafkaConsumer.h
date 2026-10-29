#ifndef VAJRA_ENGINE_KAFKA_CONSUMER_H
#define VAJRA_ENGINE_KAFKA_CONSUMER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace RdKafka {
class KafkaConsumer;
class Message;
}  // namespace RdKafka

namespace vajra_engine {

enum class HandlerOutcome { Success, RetryableError, PermanentError };

struct MessageView {
    std::string topic;
    std::int32_t partition = 0;
    std::int64_t offset = 0;
    std::string_view key;
    std::string_view value;
};

using Handler = std::function<HandlerOutcome(const MessageView&)>;

struct ConsumerOptions {
    std::string bootstrap_servers;
    std::string group_id;
    std::vector<std::string> topics;
    std::string security_protocol = "PLAINTEXT";
    unsigned session_timeout_ms = 30000;
    unsigned max_poll_interval_ms = 300000;
    std::string auto_offset_reset = "earliest";
    // Bounded in-process retries (seek-back + short sleep) before a
    // RetryableError message is dead-lettered instead of retried forever.
    unsigned max_attempts = 3;
};

struct BusError : std::runtime_error {
    explicit BusError(const std::string& what) : std::runtime_error(what) {}
};

// Minimal, purpose-built consumer for vajra_engine: manual offset commit
// (only after Success or a successful dead-letter publish -- never after a
// bare drop, so a broker/producer outage cannot silently lose messages),
// bounded in-process retry on RetryableError, and <topic>.dlq routing via
// the existing KafkaProducerManager::publishRaw() rather than a second
// producer implementation.
class KafkaConsumer {
public:
    explicit KafkaConsumer(const ConsumerOptions& options);
    ~KafkaConsumer();

    KafkaConsumer(const KafkaConsumer&) = delete;
    KafkaConsumer& operator=(const KafkaConsumer&) = delete;

    // Blocks until stop() is called from another thread (e.g. a signal
    // handler) or an unrecoverable consumer error occurs. If `on_tick` is
    // set, it's invoked once per poll-loop iteration -- including iterations
    // where consume() timed out with no message -- on the SAME thread that
    // calls `handler`, so it's a safe place to do work that must never run
    // concurrently with message handling (e.g. main.cpp's SIGHUP ruleset
    // reload check: a plain flag set by a signal handler, consumed here).
    // Unlike `handler`, `on_tick` fires even when the topic is idle, so a
    // reload isn't stuck waiting for the next message.
    void run(const Handler& handler, const std::function<void()>& on_tick = {});
    void stop();

    // Plain-integer snapshot of the atomic counters below, safe to read
    // from any thread (e.g. a metrics HTTP endpoint's own thread) while
    // run() is concurrently mutating them from the consumer thread.
    struct Stats {
        std::uint64_t processed = 0;
        std::uint64_t retried = 0;
        std::uint64_t dead_lettered = 0;
        // Both the DLQ producer and the retry budget were exhausted for at
        // least one delivery attempt. Never means "silently discarded": the
        // offset is left uncommitted and redelivered on the next poll, so
        // this counts redelivery events, not lost messages.
        std::uint64_t dropped = 0;
    };
    Stats stats() const;

private:
    struct AtomicStats {
        std::atomic<std::uint64_t> processed{0};
        std::atomic<std::uint64_t> retried{0};
        std::atomic<std::uint64_t> dead_lettered{0};
        std::atomic<std::uint64_t> dropped{0};
    };

    std::unique_ptr<RdKafka::KafkaConsumer> consumer_;
    std::atomic<bool> running_{false};
    unsigned max_attempts_;
    std::unordered_map<std::string, unsigned> local_attempts_;
    AtomicStats stats_;

    void handle_failure(RdKafka::Message& msg, const MessageView& view, HandlerOutcome outcome,
                         const std::string& error);
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_KAFKA_CONSUMER_H
