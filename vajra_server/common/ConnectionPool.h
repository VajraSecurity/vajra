#ifndef FLEET_CONNECTIONPOOL_H
#define FLEET_CONNECTIONPOOL_H

#include <chrono>
#include <condition_variable>
#include <string>
#include <queue>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <pqxx/pqxx>

// The build vendors a C++20-built static libpqxx (see top-level CMakeLists.txt
// for why: the distro libpqxx.so is C++17-built and lacks the
// std::source_location exception-constructor overload C++20 headers declare).
// If a future include-path change lets the system /usr/include/pqxx headers
// shadow the vendored ones, this catches it at compile time instead of
// producing a silent ABI mismatch at link/runtime.
#if !defined(PQXX_HAVE_CONCEPTS)
#error "pqxx headers resolved are not the vendored C++20 build (3rdparty/local/include) " \
       "-- check include order / CMAKE_CXX_STANDARD; see scripts/bootstrap_deps_pqxx.sh"
#endif

class ConnectionPool {
private:
    // A pooled connection remembers when it was last handed back so checkout
    // can limit the round-trip liveness probe to connections that sat idle.
    struct PooledConnection {
        std::shared_ptr<pqxx::connection> conn;
        std::chrono::steady_clock::time_point last_used;
    };

    std::mutex pool_mutex;
    std::condition_variable _condition;
    std::string connection_string;
    unsigned int pool_size, current_pool_count;
    // Connections in existence (queued + checked out). Lets checkout heal a
    // startup deficit instead of waiting on connections that were never made.
    unsigned int total_connections;
    std::chrono::milliseconds wait_timeout{5000};
    std::unordered_map<std::string, std::string> prepared_queries;
    std::queue<PooledConnection> pool;

    std::shared_ptr<pqxx::connection> CreateConnection();
    bool IsHealthy(const std::shared_ptr<pqxx::connection>& connection, bool probe);
public:
    ConnectionPool(std::string connection, unsigned int size);
    ConnectionPool(std::string connection, unsigned int size, std::unordered_map<std::string, std::string> prepared_queries);
    std::shared_ptr<pqxx::connection> GetConnection();
    void ReturnConnection(std::shared_ptr<pqxx::connection> connection);
    // Bounded wait for GetConnection (default 5s). On expiry GetConnection
    // throws std::runtime_error("db_pool_timeout").
    void SetWaitTimeout(std::chrono::milliseconds timeout);
};

// RAII Guard for automatic connection return
class ConnectionGuard {
private:
    std::shared_ptr<ConnectionPool> pool;
    std::shared_ptr<pqxx::connection> conn;
    bool released;

public:
    ConnectionGuard(std::shared_ptr<ConnectionPool> p)
        : pool(p), conn(p->GetConnection()), released(false) {}

    ~ConnectionGuard() {
        if (!released && conn) {
            pool->ReturnConnection(conn);
        }
    }

    // Delete copy operations
    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;

    // Get connection
    std::shared_ptr<pqxx::connection> get() { return conn; }
    std::shared_ptr<pqxx::connection> operator->() { return conn; }

    // Manual release (if needed)
    void release() { released = true; }
};


#endif //FLEET_CONNECTIONPOOL_H
