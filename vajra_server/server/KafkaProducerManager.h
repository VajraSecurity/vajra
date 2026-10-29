#ifndef KAFKA_PRODUCER_MANAGER_H
#define KAFKA_PRODUCER_MANAGER_H

#include <librdkafka/rdkafkacpp.h>
#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <map>
#include "../3rdparty/json.hpp"
#include "../common/logger.h"
#include "../common/HealthMonitor.h"

/**
 * @brief Enterprise-grade Kafka producer manager for EDR event streaming
 * 
 * Features:
 * - Thread-safe singleton producer instance
 * - Automatic topic routing based on event type
 * - Partition key support for ordered processing per host
 * - Production-grade error handling and delivery reports
 * - Connection pooling and reuse
 * - Graceful shutdown with message flushing
 */
class KafkaProducerManager {
private:
    std::unique_ptr<RdKafka::Producer> producer_;
    std::unique_ptr<RdKafka::Conf> conf_;
    std::mutex producer_mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> total_sent_{0};
    std::atomic<uint64_t> total_errors_{0};
    std::atomic<uint64_t> total_dropped_{0};

    // Bounded backpressure knobs for local queue-full (set via initialize(),
    // config keys: fleet_server.kafka_producer.queue_full_retries / queue_full_retry_wait_ms)
    int queue_full_retries_{2};
    int queue_full_retry_wait_ms_{100};

    // Circuit breaker (R2-1): the per-event bounded retry above is fine for a
    // transient blip, but /log publishes one event per row in a loop, so a
    // sustained broker outage would pay queue_full_retries_ *
    // queue_full_retry_wait_ms_ on EVERY row (e.g. ~200ms x 5000 rows ~= 16
    // minutes), stalling the handler while it still holds a pooled DB
    // connection/transaction. Once one event exhausts its retries we assume
    // the broker is still down and open the breaker: subsequent events skip
    // produce/poll entirely and drop-and-count immediately (zero blocking)
    // until circuit_breaker_cooldown_ms_ has elapsed, or until a produce
    // succeeds again (early close). Only atomics are touched on this path —
    // no mutex per event in either the closed or open state.
    std::atomic<int64_t> last_exhausted_ns_{0};      // steady_clock ns of last exhausted/failed produce; 0 = breaker never tripped
    std::atomic<uint32_t> consecutive_failures_{0};  // consecutive produce failures since the breaker last closed (observability)
    int circuit_breaker_cooldown_ms_{2000};          // config key: fleet_server.kafka_producer.circuit_breaker_cooldown_ms

    // Log every Nth dropped event instead of spamming one line per drop
    static constexpr uint64_t kDropLogInterval = 100;

    // Topic routing map: osquery table name -> Kafka topic
    std::map<std::string, std::string> topic_map_;

    // Legacy singleton storage: superseded by the function-local static in
    // getInstance(). Kept declared only because KafkaProducerManager.cpp still
    // defines them; remove both together.
    static std::unique_ptr<KafkaProducerManager> instance_;
    static std::mutex instance_mutex_;
    
    /**
     * @brief Delivery report callback for tracking send success/failure
     */
    class DeliveryReportCb : public RdKafka::DeliveryReportCb {
    public:
        void dr_cb(RdKafka::Message &message) override {
            if (message.err()) {
                BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Message delivery failed: " 
                                         << message.errstr()
                                         << " (topic: " << message.topic_name() 
                                         << ", partition: " << message.partition() << ")";
            } else {
                BOOST_LOG_TRIVIAL(trace) << "[KafkaProducer] Message delivered: "
                                         << "topic=" << message.topic_name()
                                         << " partition=" << message.partition()
                                         << " offset=" << message.offset();
            }
        }
    };
    
    DeliveryReportCb delivery_cb_;
    
    KafkaProducerManager() {
        initializeTopicMap();
    }
    
    /**
     * @brief Initialize osquery table -> Kafka topic mapping
     * 
     * 2-Topic Architecture: All events route to one of two consolidated topics
     * based on OS. The event_type field in the JSON payload handles sub-routing
     * on the consumer side.
     *
     * vajra_windows_events: all win_* tables
     * vajra_linux_events:   all bpf_* / linux audit tables
     */
    void initializeTopicMap() {
        // Windows Sysmon events → single Windows topic
        topic_map_["win_process_events"] = "vajra_windows_events";
        topic_map_["win_file_events"] = "vajra_windows_events";
        topic_map_["win_socket_events"] = "vajra_windows_events";
        topic_map_["win_registry_events"] = "vajra_windows_events";
        topic_map_["win_dns_events"] = "vajra_windows_events";
        topic_map_["win_dns_response_events"] = "vajra_windows_events";
        topic_map_["win_ssl_events"] = "vajra_windows_events";
        topic_map_["win_http_events"] = "vajra_windows_events";
        topic_map_["win_image_load_events"] = "vajra_windows_events";
        topic_map_["win_process_open_events"] = "vajra_windows_events";
        topic_map_["win_remote_thread_events"] = "vajra_windows_events";

        // Linux eBPF events → single Linux topic
        topic_map_["bpf_process_events"] = "vajra_linux_events";
        topic_map_["bpf_socket_events"] = "vajra_linux_events";
        topic_map_["bpf_file_events"] = "vajra_linux_events";
        
        // Legacy Linux audit events (alternative names)
        topic_map_["process_events"] = "vajra_linux_events";
        topic_map_["socket_events"] = "vajra_linux_events";
        
        BOOST_LOG_TRIVIAL(info) << "[KafkaProducer] Initialized 2-topic routing ("
                                << topic_map_.size() << " table mappings)";
    }

    /**
     * @brief Monotonic clock reading in nanoseconds, for the circuit breaker.
     *
     * std::atomic<int64_t> is lock-free on all platforms we target, unlike
     * std::atomic<steady_clock::time_point>, so the breaker stores this
     * integer form rather than the time_point itself.
     */
    static int64_t steadyNowNs() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    /**
     * @brief Single produce() attempt (no retry) - shared by first try and retries
     */
    RdKafka::ErrorCode produceOnce(const std::string& topic,
                                   const std::string& event_json,
                                   const std::string& host_identifier) {
        // producer_ is only non-null once initialize() has set initialized_ =
        // true (and is never reset afterward -- see shutdown()'s comment), so
        // every caller already gates on !initialized_ before reaching here.
        // This guard is therefore defense-in-depth, matching the same
        // if (producer_)/if (!producer_) style already used elsewhere in this
        // class (initialize(), publishBatch(), flush()) rather than a fix for
        // a reachable null dereference.
        if (!producer_) {
            return RdKafka::ERR__STATE;
        }
        return producer_->produce(
            topic,                              // Topic
            RdKafka::Topic::PARTITION_UA,       // Automatic partition selection
            RdKafka::Producer::RK_MSG_COPY,     // Copy payload
            const_cast<char*>(event_json.data()), // Payload
            event_json.size(),                  // Payload size
            host_identifier.empty() ? nullptr : host_identifier.c_str(), // Partition key
            host_identifier.empty() ? 0 : host_identifier.size(),        // Key size
            0,                                  // Timestamp (0 = now)
            nullptr                             // Per-message opaque pointer
        );
    }

public:
    // Delete copy/move constructors for singleton
    KafkaProducerManager(const KafkaProducerManager&) = delete;
    KafkaProducerManager& operator=(const KafkaProducerManager&) = delete;
    KafkaProducerManager(KafkaProducerManager&&) = delete;
    KafkaProducerManager& operator=(KafkaProducerManager&&) = delete;
    
    /**
     * @brief Get singleton instance
     *
     * Meyers singleton: C++11 guarantees thread-safe one-time construction,
     * and after that first call the lookup is lock-free — no global mutex on
     * the per-event hot path (previously a std::lock_guard on every call).
     */
    static KafkaProducerManager& getInstance() {
        static KafkaProducerManager instance;
        return instance;
    }
    
    /**
     * @brief Initialize Kafka producer with configuration
     * 
     * @param bootstrap_servers Kafka broker addresses (comma-separated)
     * @param client_id Client identifier for this producer
     * @param queue_full_retries Bounded re-produce attempts on local queue full
     * @param queue_full_retry_wait_ms poll() wait between those attempts
     * @param circuit_breaker_cooldown_ms Once a produce exhausts its retries (or
     *        otherwise fails), how long subsequent events fast-fail (drop, no
     *        retry loop) before the breaker allows another full attempt.
     *        Defaulted so existing callers built against the 4-arg signature
     *        keep compiling and get the hard default (2000ms) untouched.
     * @return true if initialization successful, false otherwise
     */
    bool initialize(const std::string& bootstrap_servers, const std::string& client_id = "vajra-server",
                    int queue_full_retries = 2, int queue_full_retry_wait_ms = 100,
                    int circuit_breaker_cooldown_ms = 2000) {
        std::lock_guard<std::mutex> lock(producer_mutex_);

        if (initialized_) {
            BOOST_LOG_TRIVIAL(warning) << "[KafkaProducer] Already initialized, skipping";
            return true;
        }

        queue_full_retries_ = queue_full_retries < 0 ? 0 : queue_full_retries;
        queue_full_retry_wait_ms_ = queue_full_retry_wait_ms < 0 ? 0 : queue_full_retry_wait_ms;
        circuit_breaker_cooldown_ms_ = circuit_breaker_cooldown_ms < 0 ? 0 : circuit_breaker_cooldown_ms;

        if (bootstrap_servers.empty()) {
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Bootstrap servers cannot be empty";
            return false;
        }
        
        std::string errstr;
        
        // Create configuration
        conf_.reset(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));
        
        // Essential producer configurations for production EDR
        if (conf_->set("bootstrap.servers", bootstrap_servers, errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("client.id", client_id, errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("compression.type", "snappy", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("batch.size", "65536", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("linger.ms", "10", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("acks", "1", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("retries", "3", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("max.in.flight.requests.per.connection", "5", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("reconnect.backoff.ms", "100", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("reconnect.backoff.max.ms", "10000", errstr) != RdKafka::Conf::CONF_OK ||
            conf_->set("socket.keepalive.enable", "true", errstr) != RdKafka::Conf::CONF_OK) {
            
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Configuration error: " << errstr;
            return false;
        }
        
        // Set delivery report callback
        if (conf_->set("dr_cb", &delivery_cb_, errstr) != RdKafka::Conf::CONF_OK) {
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Failed to set delivery callback: " << errstr;
            return false;
        }
        
        // Create producer instance
        producer_.reset(RdKafka::Producer::create(conf_.get(), errstr));
        if (!producer_) {
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Failed to create producer: " << errstr;
            return false;
        }
        
        initialized_ = true;
        HealthMonitor::getInstance()->registerComponent(
            "kafka_producer", HealthMonitor::ComponentType::KAFKA_PRODUCER, "Kafka Producer");
        BOOST_LOG_TRIVIAL(info) << "[KafkaProducer] Initialized successfully with bootstrap servers: "
                                << bootstrap_servers;
        return true;
    }
    
    /**
     * @brief Publish event to Kafka
     * 
     * @param table_name osquery table name (e.g., "win_process_events")
     * @param event_json JSON event data
     * @param host_identifier Partition key for ordering per host
     * @return true if queued successfully, false otherwise
     */
    bool publishEvent(const std::string& table_name, 
                      const std::string& event_json,
                      const std::string& host_identifier) {
        
        if (!initialized_) {
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Cannot publish - producer not initialized";
            return false;
        }
        
        // Lookup topic for this table
        auto topic_it = topic_map_.find(table_name);
        if (topic_it == topic_map_.end()) {
            BOOST_LOG_TRIVIAL(debug) << "[KafkaProducer] No topic mapping for table: " << table_name 
                                     << " - skipping Kafka publish (will still be in DB)";
            return true; // Not an error - some tables don't need real-time streaming
        }
        
        std::string topic = topic_it->second;

        // Circuit breaker (R2-1): if a recent event already exhausted the
        // bounded retry loop below, assume the broker is still down and
        // fast-fail this event without calling into the producer at all
        // (zero blocking). This is what caps a broker-down /log batch at one
        // retry cycle instead of one retry cycle per row. Two independent
        // atomic reads, no mutex.
        if (isKafkaDegraded()) {
            total_errors_++;
            uint64_t dropped = ++total_dropped_;
            if (dropped == 1 || dropped % kDropLogInterval == 0) {
                BOOST_LOG_TRIVIAL(warning) << "[KafkaProducer] Circuit breaker open - dropping event"
                                           << " without retry (topic: " << topic
                                           << ", total dropped: " << dropped << ")";
                // Throttled to the same cadence as the log line above (not
                // once per event) -- updateComponentHealth() takes a mutex,
                // and this path can be hit at full ingest rate during a
                // sustained outage.
                HealthMonitor::getInstance()->updateComponentHealth(
                    "kafka_producer", HealthMonitor::HealthStatus::DEGRADED,
                    "circuit breaker open - events being dropped without retry (total dropped: " +
                        std::to_string(dropped) + ")");
            }
            return false;
        }

        // Produce message with partition key (host_identifier) for ordered processing
        RdKafka::ErrorCode err = produceOnce(topic, event_json, host_identifier);

        // Local queue full: bounded backpressure — poll() lets delivery callbacks
        // drain the queue, then re-produce. Worst-case stall is
        // queue_full_retries_ * queue_full_retry_wait_ms_ (default 2 * 100ms),
        // never unbounded, so the /log request path cannot hang on Kafka. This
        // loop only runs while the breaker is CLOSED (checked above), so a
        // sustained outage pays this cost once per cooldown window rather than
        // once per event in the batch.
        for (int attempt = 0;
             err == RdKafka::ERR__QUEUE_FULL && attempt < queue_full_retries_;
             ++attempt) {
            if (producer_) producer_->poll(queue_full_retry_wait_ms_);
            err = produceOnce(topic, event_json, host_identifier);
        }

        if (err != RdKafka::ERR_NO_ERROR) {
            total_errors_++;

            // Trip the breaker: any produce failure here (queue-full exhausted
            // or otherwise) marks "now" as the last-exhausted time, so the
            // next event opens the breaker instead of repeating this retry
            // cost. Store-only, no read-modify-write needed.
            last_exhausted_ns_.store(steadyNowNs(), std::memory_order_relaxed);
            consecutive_failures_.fetch_add(1, std::memory_order_relaxed);

            if (err == RdKafka::ERR__QUEUE_FULL) {
                // Still full after bounded retries: drop, count, and log throttled
                // (first drop, then every kDropLogInterval-th) to avoid per-event spam.
                uint64_t dropped = ++total_dropped_;
                if (dropped == 1 || dropped % kDropLogInterval == 0) {
                    BOOST_LOG_TRIVIAL(warning) << "[KafkaProducer] Local queue full after "
                                               << queue_full_retries_ << " retries - dropping event"
                                               << " (topic: " << topic
                                               << ", total dropped: " << dropped
                                               << ", circuit breaker now open for "
                                               << circuit_breaker_cooldown_ms_ << "ms)";
                }
            } else {
                BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Failed to produce to topic " << topic
                                         << ": " << RdKafka::err2str(err)
                                         << " (host: " << host_identifier << ")";
            }
            return false;
        }

        total_sent_++;

        // Successful produce closes the breaker immediately rather than
        // waiting out the rest of the cooldown, so a recovered broker is
        // used again right away.
        if (consecutive_failures_.load(std::memory_order_relaxed) != 0) {
            consecutive_failures_.store(0, std::memory_order_relaxed);
            last_exhausted_ns_.store(0, std::memory_order_relaxed);
            HealthMonitor::getInstance()->updateComponentHealth(
                "kafka_producer", HealthMonitor::HealthStatus::HEALTHY,
                "recovered - producing successfully again");
        }

        // Trigger delivery report callbacks (non-blocking)
        if (producer_) producer_->poll(0);

        BOOST_LOG_TRIVIAL(trace) << "[KafkaProducer] Queued event: topic=" << topic
                                 << " host=" << host_identifier
                                 << " size=" << event_json.size();
        return true;
    }
    
    /**
     * @brief Publish to an explicit topic, bypassing the table_name -> topic
     * lookup used by publishEvent(). For consumers of this same producer
     * infra that need a topic not in topic_map_ (e.g. vajra_engine_v2's
     * <topic>.dlq dead-letter routing) rather than duplicating a second
     * producer wrapper.
     *
     * @param topic Destination topic, used verbatim.
     * @param event_json JSON event data.
     * @param key Partition key (e.g. host_identifier); empty = unkeyed.
     * @return true if queued successfully, false otherwise
     */
    bool publishRaw(const std::string& topic, const std::string& event_json,
                    const std::string& key) {
        if (!initialized_) {
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Cannot publish - producer not initialized";
            return false;
        }

        // Same circuit breaker publishEvent() uses (R2-1) -- added after a
        // review found this method skipped it entirely. Its one caller today
        // is vajra_engine_v2's KafkaConsumer DLQ path, on that engine's single
        // consumer/decode/eval/correlate thread: during a sustained broker
        // outage, every dead-lettered message previously paid the full
        // bounded-retry cost here with no fast-fail, stalling that one
        // thread for the whole outage. Fast-failing here matches
        // publishEvent()'s posture exactly.
        if (isKafkaDegraded()) {
            total_errors_++;
            uint64_t dropped = ++total_dropped_;
            if (dropped == 1 || dropped % kDropLogInterval == 0) {
                BOOST_LOG_TRIVIAL(warning) << "[KafkaProducer] Circuit breaker open - dropping raw event"
                                           << " without retry (topic: " << topic
                                           << ", total dropped: " << dropped << ")";
                HealthMonitor::getInstance()->updateComponentHealth(
                    "kafka_producer", HealthMonitor::HealthStatus::DEGRADED,
                    "circuit breaker open - events being dropped without retry (total dropped: " +
                        std::to_string(dropped) + ")");
            }
            return false;
        }

        RdKafka::ErrorCode err = produceOnce(topic, event_json, key);
        for (int attempt = 0;
             err == RdKafka::ERR__QUEUE_FULL && attempt < queue_full_retries_;
             ++attempt) {
            if (producer_) producer_->poll(queue_full_retry_wait_ms_);
            err = produceOnce(topic, event_json, key);
        }

        if (err != RdKafka::ERR_NO_ERROR) {
            total_errors_++;
            // Trip the breaker, same as publishEvent() — subsequent
            // publishRaw()/publishEvent() calls fast-fail until it closes.
            last_exhausted_ns_.store(steadyNowNs(), std::memory_order_relaxed);
            consecutive_failures_.fetch_add(1, std::memory_order_relaxed);
            BOOST_LOG_TRIVIAL(error) << "[KafkaProducer] Failed to produce (raw) to topic " << topic
                                     << ": " << RdKafka::err2str(err);
            return false;
        }

        total_sent_++;
        // Close the breaker immediately on a successful produce, same as
        // publishEvent() — a recovered broker is used again right away
        // rather than waiting out the rest of the cooldown.
        if (consecutive_failures_.load(std::memory_order_relaxed) != 0) {
            consecutive_failures_.store(0, std::memory_order_relaxed);
            last_exhausted_ns_.store(0, std::memory_order_relaxed);
            HealthMonitor::getInstance()->updateComponentHealth(
                "kafka_producer", HealthMonitor::HealthStatus::HEALTHY,
                "recovered - producing successfully again");
        }
        if (producer_) producer_->poll(0);
        return true;
    }

    /**
     * @brief Publish batch of events efficiently
     * 
     * @param table_name osquery table name
     * @param events Vector of event JSON strings
     * @param host_identifier Partition key
     * @return Number of successfully queued events
     */
    int publishBatch(const std::string& table_name,
                     const std::vector<std::string>& events,
                     const std::string& host_identifier) {
        
        int success_count = 0;
        for (const auto& event_json : events) {
            if (publishEvent(table_name, event_json, host_identifier)) {
                success_count++;
            }
        }
        
        // Poll to trigger callbacks for batch
        if (producer_) {
            producer_->poll(0);
        }

        return success_count;
    }
    
    /**
     * @brief Flush pending messages (call before shutdown)
     * 
     * @param timeout_ms Maximum time to wait for flush
     * @return Number of messages still in queue after timeout
     */
    int flush(int timeout_ms = 10000) {
        if (!initialized_ || !producer_) {
            return 0;
        }
        
        BOOST_LOG_TRIVIAL(info) << "[KafkaProducer] Flushing pending messages (timeout: " 
                                << timeout_ms << "ms)...";
        
        int remaining = producer_->flush(timeout_ms);
        
        if (remaining > 0) {
            BOOST_LOG_TRIVIAL(warning) << "[KafkaProducer] Flush timeout - " << remaining 
                                       << " messages still in queue";
        } else {
            BOOST_LOG_TRIVIAL(info) << "[KafkaProducer] All messages flushed successfully";
        }
        
        return remaining;
    }
    
    /**
     * @brief Get producer statistics
     */
    void getStats(uint64_t& total_sent, uint64_t& total_errors) const {
        total_sent = total_sent_.load();
        total_errors = total_errors_.load();
    }

    /**
     * @brief Events dropped after bounded queue-full retries were exhausted
     */
    uint64_t getTotalDropped() const {
        return total_dropped_.load();
    }

    /**
     * @brief Circuit breaker state (R2-1): true while Kafka is assumed
     * degraded, i.e. less than circuit_breaker_cooldown_ms_ has elapsed
     * since the last exhausted/failed produce. Two relaxed atomic loads, no
     * lock - safe to call from the hot path or from a future /health check.
     */
    bool isKafkaDegraded() const {
        int64_t last = last_exhausted_ns_.load(std::memory_order_relaxed);
        if (last == 0) {
            return false;
        }
        int64_t cooldown_ns = static_cast<int64_t>(circuit_breaker_cooldown_ms_) * 1000000LL;
        return (steadyNowNs() - last) < cooldown_ns;
    }

    /**
     * @brief Consecutive produce failures since the breaker last closed.
     * Observability only; the breaker's open/closed decision is time-based
     * (see isKafkaDegraded()), not count-based.
     */
    uint32_t getConsecutiveFailures() const {
        return consecutive_failures_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Check if producer is initialized and ready
     */
    bool isInitialized() const {
        return initialized_;
    }
    
    /**
     * @brief Shutdown producer gracefully
     */
    void shutdown() {
        std::lock_guard<std::mutex> lock(producer_mutex_);

        if (initialized_) {
            // Mark uninitialized FIRST so new publishEvent() calls fast-return
            // at their `if (!initialized_)` gate instead of entering the body.
            initialized_ = false;

            BOOST_LOG_TRIVIAL(info) << "[KafkaProducer] Shutting down..."
                                    << " (sent: " << total_sent_
                                    << ", errors: " << total_errors_
                                    << ", dropped: " << total_dropped_ << ")";

            // Drain queued messages. Deliberately do NOT reset producer_/conf_
            // here: publishEvent() reads producer_ lock-free (no producer_mutex_
            // on the hot path, by R2-1 design), so a concurrent in-flight caller
            // that already passed the initialized_ gate could otherwise deref a
            // freed producer (use-after-free) during a graceful shutdown with
            // /log requests still in flight. librdkafka's produce()/poll()/flush()
            // are thread-safe, so leaving the producer alive is safe; the object
            // is reclaimed by member teardown at process exit, after all session
            // threads are gone.
            flush(5000);
        }
    }
    
    ~KafkaProducerManager() {
        shutdown();
    }
};

#endif // KAFKA_PRODUCER_MANAGER_H
