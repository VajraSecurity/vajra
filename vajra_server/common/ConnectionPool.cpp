#include "ConnectionPool.h"

#include <exception>
#include <iostream>
#include <stdexcept>

namespace {
    // Run the round-trip probe only on connections idle at least this long;
    // is_open() alone cannot see a server-side drop (it reflects local state),
    // but probing every checkout would add a DB round trip to the hot path.
    constexpr std::chrono::seconds IDLE_PROBE_THRESHOLD{30};
}

ConnectionPool::ConnectionPool(std::string connection_string, unsigned int size)
    : ConnectionPool(std::move(connection_string), size, {}) {
}

ConnectionPool::ConnectionPool(std::string connection_string, unsigned int size, std::unordered_map<std::string, std::string> prepared_queries) {
    this->connection_string = std::move(connection_string);
    this->pool_size = size;
    this->current_pool_count = 0;
    this->total_connections = 0;
    this->prepared_queries = std::move(prepared_queries);

    for (unsigned int i = 0; i < pool_size; ++i)
    {
        try {
            pool.push({CreateConnection(), std::chrono::steady_clock::now()});
            ++current_pool_count;
            ++total_connections;
        }
        catch (const std::exception& e)
        {
            std::cerr << "ConnectionPool: failed to open connection " << (i + 1) << "/"
                      << pool_size << ": " << e.what() << std::endl;
        }
    }

    if (current_pool_count == 0)
    {
        // A pool with zero connections can never serve a request; fail startup
        // visibly instead of hanging every caller until their wait times out.
        throw std::runtime_error("ConnectionPool: could not open any database connection (0/"
                                 + std::to_string(pool_size) + "); check db_configuration");
    }

    if (current_pool_count < pool_size)
    {
        std::cerr << "ConnectionPool: WARNING: pool started undersized ("
                  << current_pool_count << "/" << pool_size
                  << "); missing connections will be retried on checkout" << std::endl;
    }
}

std::shared_ptr<pqxx::connection> ConnectionPool::CreateConnection() {
    auto conn = std::make_shared<pqxx::connection>(this->connection_string);
    for (const auto& query : this->prepared_queries)
    {
        conn->prepare(query.first, query.second);
    }
    return conn;
}

bool ConnectionPool::IsHealthy(const std::shared_ptr<pqxx::connection>& connection, bool probe) {
    if (!connection || !connection->is_open())
        return false;

    if (!probe)
        return true;

    try {
        pqxx::nontransaction liveness(*connection);
        liveness.exec("SELECT 1");
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

std::shared_ptr<pqxx::connection> ConnectionPool::GetConnection() {
    std::unique_lock<std::mutex> lock(pool_mutex);

    if (pool.empty() && total_connections < pool_size)
    {
        // Heal a startup deficit: every existing connection is checked out but
        // we are below the configured size, so mint a new one instead of
        // waiting on a connection that was never created.
        ++total_connections; // reserve the slot before releasing the lock
        lock.unlock();
        try {
            return CreateConnection();
        }
        catch (const std::exception& e)
        {
            lock.lock();
            --total_connections;
            std::cerr << "ConnectionPool: failed to heal pool deficit: " << e.what() << std::endl;
            // Fall through to the bounded wait: another thread may still
            // return a live connection in time.
        }
    }

    if (!_condition.wait_for(lock, wait_timeout, [this] { return !pool.empty(); }))
    {
        // Exact message is a cross-component contract: WebServer maps it to 503.
        throw std::runtime_error("db_pool_timeout");
    }

    PooledConnection entry = pool.front();
    pool.pop();
    --current_pool_count;
    lock.unlock();

    // Health check OUTSIDE the mutex to avoid blocking other threads.
    const bool probe = (std::chrono::steady_clock::now() - entry.last_used) >= IDLE_PROBE_THRESHOLD;
    if (IsHealthy(entry.conn, probe))
        return entry.conn;

    // Dead on checkout: replace it so the pool never shrinks.
    try {
        return CreateConnection();
    }
    catch (const std::exception& e)
    {
        std::cerr << "ConnectionPool: reconnect failed: " << e.what() << std::endl;
        // Park the dead connection back so its slot is never lost, but stamp
        // its timestamp stale (>= IDLE_PROBE_THRESHOLD in the past) so the NEXT
        // checkout is FORCED to run the real SELECT-1 probe and reconnect.
        // Going through ReturnConnection() would stamp last_used = now(), and
        // the next checkout would then skip the probe and fall back to
        // is_open() — which reflects only local state and reports a
        // server-dropped connection as live, handing a known-dead connection
        // to a request during a DB flap. While the DB stays down each checkout
        // re-probes, fails, and returns db_unavailable (503) instead of a 500.
        {
            std::unique_lock<std::mutex> park_lock(pool_mutex);
            pool.push({entry.conn,
                       std::chrono::steady_clock::now() - IDLE_PROBE_THRESHOLD});
            ++current_pool_count;
        }
        _condition.notify_one();
        throw std::runtime_error("db_unavailable: reconnect failed");
    }
}

void ConnectionPool::ReturnConnection(std::shared_ptr<pqxx::connection> connection) {
    // Pools without baseline prepared statements (api_server, event_processor)
    // get scrubbed on return: if a handler threw between prepare() and
    // unprepare(), the leftover statement would make the next request's
    // prepare() of the same name fail ("prepared statement already exists").
    // The fleet pool keeps its baseline statements, so it is never scrubbed.
    if (prepared_queries.empty() && connection && connection->is_open()) {
        try {
            pqxx::nontransaction scrub(*connection);
            scrub.exec("DEALLOCATE ALL");
        } catch (const std::exception& e) {
            // Scrub failure leaves us no worse than the old behaviour.
            std::cerr << "ConnectionPool: failed to scrub connection: " << e.what() << std::endl;
        }
    }

    std::unique_lock<std::mutex> lock(pool_mutex);

    pool.push({std::move(connection), std::chrono::steady_clock::now()});
    ++current_pool_count;
    lock.unlock();
    _condition.notify_one();
}

void ConnectionPool::SetWaitTimeout(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(pool_mutex);
    wait_timeout = timeout;
}
