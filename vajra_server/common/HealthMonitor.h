#ifndef FLEET_HEALTHMONITOR_H
#define FLEET_HEALTHMONITOR_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "logger.h"

/**
 * Health Monitor for tracking system health, data integrity, and performance metrics
 * 
 * Key features:
 * - Real-time health status tracking
 * - Data loss detection and alerting
 * - Performance metrics collection
 * - Dead letter queue for failed events
 * - Connection pool health monitoring
 * - Automatic alerting on critical issues
 */
class HealthMonitor {
public:
    enum class HealthStatus {
        HEALTHY,        // All systems operational
        DEGRADED,       // Some non-critical issues
        CRITICAL,       // Critical issues affecting data integrity
        DOWN            // System not functioning
    };

    enum class ComponentType {
        EVENT_PROCESSOR,
        DATABASE,
        CONNECTION_POOL,
        API_SERVER,
        RATE_LIMITER,
        NODE_VALIDATOR,
        KAFKA_PRODUCER
    };

    struct ComponentHealth {
        ComponentType type;
        HealthStatus status;
        std::string name;
        std::string message;
        std::chrono::system_clock::time_point last_updated;
        unsigned long long error_count;
        unsigned long long warning_count;
        std::unordered_map<std::string, std::string> metrics;
    };

    struct DeadLetterEntry {
        unsigned long long event_id;
        std::string table_name;
        std::string error_message;
        std::string event_data;
        std::chrono::system_clock::time_point failed_at;
        int retry_count;
        std::chrono::system_clock::time_point last_retry_at;
    };

private:
    std::mutex health_mutex;
    std::mutex dead_letter_mutex;
    
    // Component health tracking
    std::unordered_map<std::string, ComponentHealth> components;
    
    // Dead letter queue for failed events (prevents data loss)
    std::vector<DeadLetterEntry> dead_letter_queue;
    const size_t MAX_DEAD_LETTER_SIZE = 10000;
    
    // Global metrics
    std::atomic<unsigned long long> total_events_processed{0};
    std::atomic<unsigned long long> total_events_failed{0};
    std::atomic<unsigned long long> total_api_requests{0};
    std::atomic<unsigned long long> total_api_errors{0};
    std::atomic<unsigned long long> total_db_errors{0};
    std::atomic<unsigned long long> total_connection_timeouts{0};
    
    std::chrono::system_clock::time_point system_start_time;
    std::chrono::system_clock::time_point last_health_check;
    
    HealthMonitor() : system_start_time(std::chrono::system_clock::now()),
                      last_health_check(std::chrono::system_clock::now()) {}
    
    ~HealthMonitor() = default;
    HealthMonitor(const HealthMonitor&) = delete;
    HealthMonitor& operator=(const HealthMonitor&) = delete;

public:
    static HealthMonitor* getInstance() {
        // Meyers singleton: function-local static initialization is
        // guaranteed thread-safe (guarded with an implicit, one-time
        // lock) since C++11, so no manual double-checked locking is
        // needed here.
        static HealthMonitor instance;
        return &instance;
    }
    
    // Register a component for health monitoring
    void registerComponent(const std::string& id, ComponentType type, const std::string& name) {
        std::lock_guard<std::mutex> lock(health_mutex);
        
        ComponentHealth health;
        health.type = type;
        health.status = HealthStatus::HEALTHY;
        health.name = name;
        health.message = "Component initialized";
        health.last_updated = std::chrono::system_clock::now();
        health.error_count = 0;
        health.warning_count = 0;
        
        components[id] = std::move(health);
        BOOST_LOG_TRIVIAL(info) << "[HealthMonitor] Registered component: " << name << " (" << id << ")";
    }
    
    // Update component health status
    void updateComponentHealth(const std::string& id, HealthStatus status, const std::string& message = "") {
        std::lock_guard<std::mutex> lock(health_mutex);
        
        auto it = components.find(id);
        if (it != components.end()) {
            auto& component = it->second;
            auto old_status = component.status;
            component.status = status;
            component.message = message;
            component.last_updated = std::chrono::system_clock::now();
            
            if (status == HealthStatus::CRITICAL || status == HealthStatus::DOWN) {
                component.error_count++;
                BOOST_LOG_TRIVIAL(error) << "[HealthMonitor] CRITICAL: " << component.name 
                                        << " status changed to " << statusToString(status) 
                                        << ". Message: " << message;
            } else if (status == HealthStatus::DEGRADED) {
                component.warning_count++;
                BOOST_LOG_TRIVIAL(warning) << "[HealthMonitor] WARNING: " << component.name 
                                          << " is degraded. Message: " << message;
            } else if (old_status != HealthStatus::HEALTHY && status == HealthStatus::HEALTHY) {
                BOOST_LOG_TRIVIAL(info) << "[HealthMonitor] RECOVERED: " << component.name 
                                       << " returned to healthy status";
            }
        }
    }
    
    // Add custom metric to component
    void setComponentMetric(const std::string& id, const std::string& metric_name, const std::string& value) {
        std::lock_guard<std::mutex> lock(health_mutex);
        
        auto it = components.find(id);
        if (it != components.end()) {
            it->second.metrics[metric_name] = value;
        }
    }
    
    // Add event to dead letter queue (PREVENTS DATA LOSS!)
    void addToDeadLetterQueue(unsigned long long event_id, const std::string& table_name, 
                             const std::string& error_message, const std::string& event_data) {
        std::lock_guard<std::mutex> lock(dead_letter_mutex);
        
        // Check if event already in queue
        for (auto& entry : dead_letter_queue) {
            if (entry.event_id == event_id && entry.table_name == table_name) {
                entry.retry_count++;
                entry.last_retry_at = std::chrono::system_clock::now();
                entry.error_message = error_message;
                BOOST_LOG_TRIVIAL(warning) << "[DeadLetter] Event " << event_id 
                                          << " from " << table_name 
                                          << " retry count: " << entry.retry_count;
                return;
            }
        }
        
        // Add new entry
        if (dead_letter_queue.size() >= MAX_DEAD_LETTER_SIZE) {
            BOOST_LOG_TRIVIAL(fatal) << "[DeadLetter] QUEUE FULL! Oldest event will be removed. "
                                    << "THIS MAY CAUSE DATA LOSS!";
            dead_letter_queue.erase(dead_letter_queue.begin());
        }
        
        DeadLetterEntry entry;
        entry.event_id = event_id;
        entry.table_name = table_name;
        entry.error_message = error_message;
        entry.event_data = event_data;
        entry.failed_at = std::chrono::system_clock::now();
        entry.retry_count = 1;
        entry.last_retry_at = entry.failed_at;
        
        dead_letter_queue.push_back(entry);
        total_events_failed++;
        
        BOOST_LOG_TRIVIAL(error) << "[DeadLetter] Added event " << event_id 
                                << " from " << table_name 
                                << " to dead letter queue. Error: " << error_message
                                << ". Queue size: " << dead_letter_queue.size();
    }
    
    // Remove from dead letter queue (after successful retry)
    void removeFromDeadLetterQueue(unsigned long long event_id, const std::string& table_name) {
        std::lock_guard<std::mutex> lock(dead_letter_mutex);
        
        dead_letter_queue.erase(
            std::remove_if(dead_letter_queue.begin(), dead_letter_queue.end(),
                [event_id, &table_name](const DeadLetterEntry& entry) {
                    return entry.event_id == event_id && entry.table_name == table_name;
                }),
            dead_letter_queue.end()
        );
        
        BOOST_LOG_TRIVIAL(info) << "[DeadLetter] Successfully recovered event " << event_id 
                               << " from " << table_name;
    }
    
    // Get dead letter queue entries (for retry processing)
    std::vector<DeadLetterEntry> getDeadLetterEntries(int max_retry_count = 5) {
        std::lock_guard<std::mutex> lock(dead_letter_mutex);

        std::vector<DeadLetterEntry> entries;
        for (const auto& entry : dead_letter_queue) {
            if (entry.retry_count < max_retry_count) {
                entries.push_back(entry);
            }
        }
        return entries;
    }

    // Get dead letter queue size (thread-safe; always goes through
    // dead_letter_mutex since dead_letter_queue is that mutex's data).
    size_t getDeadLetterQueueSize() {
        std::lock_guard<std::mutex> lock(dead_letter_mutex);
        return dead_letter_queue.size();
    }

    // Increment global counters
    void incrementEventsProcessed(unsigned long long count = 1) { total_events_processed += count; }
    void incrementEventsFailed(unsigned long long count = 1) { total_events_failed += count; }
    void incrementApiRequests(unsigned long long count = 1) { total_api_requests += count; }
    void incrementApiErrors(unsigned long long count = 1) { total_api_errors += count; }
    void incrementDbErrors(unsigned long long count = 1) { total_db_errors += count; }
    void incrementConnectionTimeouts(unsigned long long count = 1) { total_connection_timeouts += count; }
    
    // Get overall system health
    HealthStatus getSystemHealth() {
        std::lock_guard<std::mutex> lock(health_mutex);
        return getSystemHealthLocked();
    }

    // Get health report as JSON
    std::string getHealthReport() {
        std::lock_guard<std::mutex> lock(health_mutex);

        nlohmann::json report;

        // System status (reuse the already-held health_mutex instead of
        // calling the public, self-locking getSystemHealth() again -
        // that re-lock of a non-recursive mutex was the deadlock).
        report["system"]["status"] = statusToString(getSystemHealthLocked());
        report["system"]["uptime_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - system_start_time).count();
        report["system"]["last_health_check"] = std::chrono::duration_cast<std::chrono::seconds>(
            last_health_check.time_since_epoch()).count();

        // Global metrics
        report["metrics"]["total_events_processed"] = total_events_processed.load();
        report["metrics"]["total_events_failed"] = total_events_failed.load();
        report["metrics"]["total_api_requests"] = total_api_requests.load();
        report["metrics"]["total_api_errors"] = total_api_errors.load();
        report["metrics"]["total_db_errors"] = total_db_errors.load();
        report["metrics"]["total_connection_timeouts"] = total_connection_timeouts.load();

        // Component health
        nlohmann::json components_json = nlohmann::json::array();
        for (const auto& [id, component] : components) {
            nlohmann::json comp;
            comp["id"] = id;
            comp["name"] = component.name;
            comp["type"] = componentTypeToString(component.type);
            comp["status"] = statusToString(component.status);
            comp["message"] = component.message;
            comp["error_count"] = component.error_count;
            comp["warning_count"] = component.warning_count;
            comp["last_updated"] = std::chrono::duration_cast<std::chrono::seconds>(
                component.last_updated.time_since_epoch()).count();
            comp["metrics"] = component.metrics;
            components_json.push_back(comp);
        }
        report["components"] = components_json;

        // Dead letter queue - dead_letter_queue is guarded by
        // dead_letter_mutex, not health_mutex, so it must always be read
        // through a dead_letter_mutex-protected accessor rather than
        // touched directly here.
        size_t dead_letter_size = getDeadLetterQueueSize();
        report["dead_letter_queue"]["size"] = dead_letter_size;
        report["dead_letter_queue"]["max_size"] = MAX_DEAD_LETTER_SIZE;
        report["dead_letter_queue"]["utilization_percent"] =
            (dead_letter_size * 100.0) / MAX_DEAD_LETTER_SIZE;

        last_health_check = std::chrono::system_clock::now();

        return report.dump(2);
    }

private:
    // Assumes health_mutex is already held by the caller. Locks
    // dead_letter_mutex internally (always acquired after health_mutex,
    // never the reverse, so there is no lock-order inversion with the
    // dead-letter methods, which never touch health_mutex).
    HealthStatus getSystemHealthLocked() {
        HealthStatus worst_status = HealthStatus::HEALTHY;

        for (const auto& [id, component] : components) {
            if (component.status > worst_status) {
                worst_status = component.status;
            }
        }

        // Check dead letter queue
        size_t dead_letter_size = getDeadLetterQueueSize();
        if (dead_letter_size > MAX_DEAD_LETTER_SIZE * 0.8) {
            worst_status = HealthStatus::CRITICAL;
        } else if (dead_letter_size > MAX_DEAD_LETTER_SIZE * 0.5) {
            worst_status = std::max(worst_status, HealthStatus::DEGRADED);
        }

        return worst_status;
    }

    std::string statusToString(HealthStatus status) {
        switch (status) {
            case HealthStatus::HEALTHY: return "HEALTHY";
            case HealthStatus::DEGRADED: return "DEGRADED";
            case HealthStatus::CRITICAL: return "CRITICAL";
            case HealthStatus::DOWN: return "DOWN";
            default: return "UNKNOWN";
        }
    }
    
    std::string componentTypeToString(ComponentType type) {
        switch (type) {
            case ComponentType::EVENT_PROCESSOR: return "EVENT_PROCESSOR";
            case ComponentType::DATABASE: return "DATABASE";
            case ComponentType::CONNECTION_POOL: return "CONNECTION_POOL";
            case ComponentType::API_SERVER: return "API_SERVER";
            case ComponentType::RATE_LIMITER: return "RATE_LIMITER";
            case ComponentType::NODE_VALIDATOR: return "NODE_VALIDATOR";
            case ComponentType::KAFKA_PRODUCER: return "KAFKA_PRODUCER";
            default: return "UNKNOWN";
        }
    }
};

#endif //FLEET_HEALTHMONITOR_H
