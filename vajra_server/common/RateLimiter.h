#ifndef VAJRA_RATE_LIMITER_H
#define VAJRA_RATE_LIMITER_H

#include <string>
#include <memory>
#include <ctime>
#include <pqxx/pqxx>
#include "../common/ConfigurationParser.h"
#include "../common/logger.h"

namespace VajraRateLimit {

/**
 * @brief Check if an IP address has exceeded enrollment rate limits
 * 
 * @param ip_address The IP address to check
 * @param conn Database connection
 * @param config Node configuration with rate limit settings
 * @return bool True if within limits (allowed), false if exceeded (blocked)
 */
inline bool checkEnrollmentRateLimit(
    const std::string& ip_address,
    std::shared_ptr<pqxx::connection> conn,
    const NodeConfiguration& config)
{
    if (!config.enrollment_rate_limit.enabled) {
        return true; // Rate limiting disabled
    }
    
    try {
        pqxx::work txn(*conn);
        long current_time = std::time(0);
        
        // Check hourly limit. Counts ALL attempts (failed ones included) so a
        // flood of bad-secret requests is throttled too. exec_params instead of
        // prepare/unprepare: an exception between the two used to leave a stale
        // prepared statement on the pooled connection.
        long one_hour_ago = current_time - 3600;
        pqxx::result hourly_result = txn.exec_params(
            "SELECT COUNT(*) FROM enrollment_attempts "
            "WHERE ip_address = $1 AND attempt_time > $2", ip_address, one_hour_ago);

        int hourly_count = hourly_result[0][0].as<int>();
        
        if (hourly_count >= static_cast<int>(config.enrollment_rate_limit.max_per_ip_per_hour)) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Hourly rate limit exceeded for IP: " << ip_address 
                                       << " (Count: " << hourly_count << ")";
            txn.commit();
            return false;
        }
        
        // Check daily limit (all attempts, see above)
        long one_day_ago = current_time - 86400;
        pqxx::result daily_result = txn.exec_params(
            "SELECT COUNT(*) FROM enrollment_attempts "
            "WHERE ip_address = $1 AND attempt_time > $2", ip_address, one_day_ago);

        int daily_count = daily_result[0][0].as<int>();
        
        if (daily_count >= static_cast<int>(config.enrollment_rate_limit.max_per_day)) {
            BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Daily rate limit exceeded for IP: " << ip_address 
                                       << " (Count: " << daily_count << ")";
            txn.commit();
            return false;
        }
        
        txn.commit();
        return true; // Within limits
        
    } catch (const pqxx::sql_error& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error in rate limit check: " << e.what();
        // Fail open: the in-memory pre-auth limiter (InMemoryRateLimiter) still
        // enforces a per-IP cap with no DB dependency, so a DB outage cannot
        // disable rate limiting entirely while enrollment stays available.
        return true;
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error in rate limit check: " << e.what();
        return true; // Fail open behind the in-memory limiter (see above)
    }
}

/**
 * @brief Record an enrollment attempt in the database
 * 
 * @param ip_address The IP address making the attempt
 * @param success Whether the enrollment was successful
 * @param host_identifier The host identifier (if successful)
 * @param failure_reason Reason for failure (if unsuccessful)
 * @param conn Database connection
 */
inline void recordEnrollmentAttempt(
    const std::string& ip_address,
    bool success,
    const std::string& host_identifier,
    const std::string& failure_reason,
    std::shared_ptr<pqxx::connection> conn)
{
    try {
        pqxx::work txn(*conn);
        long current_time = std::time(0);

        txn.exec_params(
            "INSERT INTO enrollment_attempts (ip_address, attempt_time, success, host_identifier, failure_reason) "
            "VALUES ($1, $2, $3, $4, $5)",
            ip_address,
            current_time,
            success,
            success ? host_identifier : "",
            failure_reason);

        txn.commit();

    } catch (const pqxx::sql_error& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Failed to record enrollment attempt: " << e.what();
        // Non-critical error, don't throw
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error recording enrollment attempt: " << e.what();
    }
}

/**
 * @brief Clean up old enrollment attempts (run periodically)
 * 
 * @param days_to_keep Number of days of history to keep
 * @param conn Database connection
 */
inline void cleanupOldEnrollmentAttempts(
    unsigned int days_to_keep,
    std::shared_ptr<pqxx::connection> conn)
{
    try {
        pqxx::work txn(*conn);
        long cutoff_time = std::time(0) - (days_to_keep * 86400);

        pqxx::result result = txn.exec_params(
            "DELETE FROM enrollment_attempts WHERE attempt_time < $1", cutoff_time);
        int deleted_count = result.affected_rows();

        txn.commit();

        if (deleted_count > 0) {
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Cleaned up " << deleted_count 
                                   << " old enrollment attempts";
        }
        
    } catch (const pqxx::sql_error& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Failed to cleanup enrollment attempts: " << e.what();
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error in cleanup: " << e.what();
    }
}

} // namespace VajraRateLimit

#endif // VAJRA_RATE_LIMITER_H
