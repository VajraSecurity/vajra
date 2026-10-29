#include "vajra_engine/KafkaConsumer.h"

#include <librdkafka/rdkafkacpp.h>

#include <chrono>
#include <thread>

#include "../../common/logger.h"
#include "../../server/KafkaProducerManager.h"

namespace vajra_engine {
namespace {

void set_or_throw(RdKafka::Conf& conf, const std::string& key, const std::string& value) {
    std::string errstr;
    if (conf.set(key, value, errstr) != RdKafka::Conf::CONF_OK) {
        throw BusError("vajra_engine::KafkaConsumer: config '" + key + "': " + errstr);
    }
}

std::string local_key(const std::string& topic, std::int32_t partition, std::int64_t offset) {
    return topic + ":" + std::to_string(partition) + ":" + std::to_string(offset);
}

}  // namespace

KafkaConsumer::KafkaConsumer(const ConsumerOptions& options)
    : max_attempts_(options.max_attempts) {
    if (options.bootstrap_servers.empty()) {
        throw BusError("vajra_engine::KafkaConsumer: bootstrap_servers must not be empty");
    }
    if (options.group_id.empty()) {
        throw BusError("vajra_engine::KafkaConsumer: group_id must not be empty");
    }
    if (options.topics.empty()) {
        throw BusError("vajra_engine::KafkaConsumer: at least one topic is required");
    }

    std::unique_ptr<RdKafka::Conf> conf(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));
    set_or_throw(*conf, "bootstrap.servers", options.bootstrap_servers);
    set_or_throw(*conf, "group.id", options.group_id);
    // At-least-once contract: offsets are committed only by our own routing
    // logic (success or a confirmed dead-letter), never automatically.
    set_or_throw(*conf, "enable.auto.commit", "false");
    set_or_throw(*conf, "auto.offset.reset", options.auto_offset_reset);
    set_or_throw(*conf, "session.timeout.ms", std::to_string(options.session_timeout_ms));
    set_or_throw(*conf, "max.poll.interval.ms", std::to_string(options.max_poll_interval_ms));
    set_or_throw(*conf, "security.protocol", options.security_protocol);

    std::string errstr;
    consumer_.reset(RdKafka::KafkaConsumer::create(conf.get(), errstr));
    if (!consumer_) {
        throw BusError("vajra_engine::KafkaConsumer: create failed: " + errstr);
    }

    const RdKafka::ErrorCode err = consumer_->subscribe(options.topics);
    if (err != RdKafka::ERR_NO_ERROR) {
        throw BusError("vajra_engine::KafkaConsumer: subscribe failed: " + RdKafka::err2str(err));
    }
    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: subscribed (group " << options.group_id
                             << ", " << options.topics.size() << " topic(s))";
}

KafkaConsumer::~KafkaConsumer() {
    stop();
    if (consumer_) consumer_->close();
}

void KafkaConsumer::stop() { running_.store(false, std::memory_order_relaxed); }

KafkaConsumer::Stats KafkaConsumer::stats() const {
    Stats snapshot;
    snapshot.processed = stats_.processed.load(std::memory_order_relaxed);
    snapshot.retried = stats_.retried.load(std::memory_order_relaxed);
    snapshot.dead_lettered = stats_.dead_lettered.load(std::memory_order_relaxed);
    snapshot.dropped = stats_.dropped.load(std::memory_order_relaxed);
    return snapshot;
}

void KafkaConsumer::run(const Handler& handler, const std::function<void()>& on_tick) {
    running_.store(true, std::memory_order_relaxed);

    while (running_.load(std::memory_order_relaxed)) {
        if (on_tick) on_tick();

        std::unique_ptr<RdKafka::Message> msg(consumer_->consume(500));
        if (!msg) continue;

        const auto err = msg->err();
        if (err == RdKafka::ERR__TIMED_OUT || err == RdKafka::ERR__PARTITION_EOF) continue;
        if (err != RdKafka::ERR_NO_ERROR) {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: consume error: "
                                      << msg->errstr();
            continue;
        }

        MessageView view;
        view.topic = msg->topic_name();
        view.partition = msg->partition();
        view.offset = msg->offset();
        if (msg->key_pointer() && msg->key_len() > 0) {
            view.key = std::string_view(static_cast<const char*>(msg->key_pointer()), msg->key_len());
        }
        if (msg->payload() && msg->len() > 0) {
            view.value = std::string_view(static_cast<const char*>(msg->payload()), msg->len());
        }

        std::string error;
        HandlerOutcome outcome;
        try {
            outcome = handler(view);
            if (outcome != HandlerOutcome::Success) error = "handler reported failure";
        } catch (const std::exception& e) {
            outcome = HandlerOutcome::RetryableError;
            error = e.what();
        }

        if (outcome == HandlerOutcome::Success) {
            const auto commit_err = consumer_->commitSync(msg.get());
            if (commit_err != RdKafka::ERR_NO_ERROR) {
                BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: commit failed: "
                                          << RdKafka::err2str(commit_err);
            }
            ++stats_.processed;
            local_attempts_.erase(local_key(view.topic, view.partition, view.offset));
            continue;
        }

        handle_failure(*msg, view, outcome, error);
    }
}

void KafkaConsumer::handle_failure(RdKafka::Message& msg, const MessageView& view,
                                    HandlerOutcome outcome, const std::string& error) {
    const std::string key = local_key(view.topic, view.partition, view.offset);
    unsigned& attempts = local_attempts_[key];
    ++attempts;

    if (outcome == HandlerOutcome::RetryableError && attempts < max_attempts_) {
        std::unique_ptr<RdKafka::TopicPartition> tp(
            RdKafka::TopicPartition::create(view.topic, view.partition, view.offset));
        consumer_->seek(*tp, 5000);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ++stats_.retried;
        return;
    }

    // Either a permanent error, or a retryable one that exhausted its
    // attempts: dead-letter via the existing producer wrapper (reused, not
    // duplicated) so the message isn't silently lost.
    const std::string dlq_topic = view.topic + ".dlq";
    const bool queued = KafkaProducerManager::getInstance().publishRaw(
        dlq_topic, std::string(view.value), std::string(view.key));

    if (queued) {
        const auto commit_err = consumer_->commitSync(&msg);
        if (commit_err != RdKafka::ERR_NO_ERROR) {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                      << "vajra_engine: commit after dead-letter failed: "
                                      << RdKafka::err2str(commit_err);
        }
        ++stats_.dead_lettered;
        // Capture before erase(): `attempts` is a reference into
        // local_attempts_'s storage for `key` and is invalidated the instant
        // that entry is erased, so reading it afterward (as the log line
        // below does) is a dangling-reference read -- this previously logged
        // a garbage attempt count instead of the real one.
        const unsigned final_attempts = attempts;
        local_attempts_.erase(key);
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: dead-lettered " << view.topic
                                  << "[" << view.partition << "]@" << view.offset << " after "
                                  << final_attempts << " attempt(s): " << error;
        return;
    }

    // DLQ publish failed too (producer down/uninitialized): do NOT commit,
    // so the message is redelivered rather than silently dropped. Seek back
    // so the next poll re-consumes it instead of skipping past it.
    std::unique_ptr<RdKafka::TopicPartition> tp(
        RdKafka::TopicPartition::create(view.topic, view.partition, view.offset));
    consumer_->seek(*tp, 5000);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ++stats_.dropped;
    BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: dead-letter publish failed for "
                              << view.topic << "[" << view.partition << "]@" << view.offset
                              << "; will re-consume: " << error;
}

}  // namespace vajra_engine
