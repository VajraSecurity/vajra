#ifndef VAJRA_NODE_VALIDATOR_H
#define VAJRA_NODE_VALIDATOR_H

#include <string>
#include <memory>
#include <ctime>
#include <pqxx/pqxx>
#include "../common/logger.h"

namespace VajraNodeValidator {

/**
 * @brief Structure holding node key validation results
 */
struct NodeKeyValidation {
    bool is_valid;              // Overall validity
    bool is_revoked;            // Key is in blacklist
    bool is_expired;            // Key has expired
    bool is_quarantined;        // Node is quarantined
    bool exists;                // Node exists in database
    std::string host_identifier;
    std::string status;         // Node status (ACTIVE, REVOKED, etc.)
    std::string error_message;  // Error description
};

/**
 * @brief Validate node key with enhanced security checks
 * 
 * Performs comprehensive validation:
 * 1. Checks if key is in revoked_node_keys blacklist
 * 2. Checks if node exists in nodes table
 * 3. Validates node status
 * 4. Checks key expiration
 * 5. Checks for quarantine status
 * 
 * @param node_key The node key to validate
 * @param conn Database connection
 * @return NodeKeyValidation Structure with validation results
 */
inline NodeKeyValidation validateNodeKeyEnhanced(
    const std::string& node_key,
    std::shared_ptr<pqxx::connection> conn)
{
    NodeKeyValidation result;
    result.is_valid = false;
    result.is_revoked = false;
    result.is_expired = false;
    result.is_quarantined = false;
    result.exists = false;
    
    try {
        pqxx::work txn(*conn);
        
        // Step 1: Check if key is in revoked blacklist
        conn->prepare("check_revoked_key", 
            "SELECT 1 FROM revoked_node_keys WHERE node_key = $1");
        pqxx::result revoked_result = txn.exec_prepared("check_revoked_key", node_key);
        conn->unprepare("check_revoked_key");
        
        if (!revoked_result.empty()) {
            result.is_revoked = true;
            result.error_message = "Node key has been revoked";
            txn.commit();
            return result;
        }
        
        // Step 2: Get node information from nodes table
        conn->prepare("get_node_info",
            "SELECT host_identifier, status, node_key_expires_at, consecutive_failures "
            "FROM nodes WHERE node_key = $1");
        pqxx::result node_result = txn.exec_prepared("get_node_info", node_key);
        conn->unprepare("get_node_info");
        
        if (node_result.empty()) {
            result.exists = false;
            result.error_message = "Node key not found";
            txn.commit();
            return result;
        }
        
        result.exists = true;
        result.host_identifier = node_result[0]["host_identifier"].as<std::string>();
        result.status = node_result[0]["status"].as<std::string>();
        
        // Step 3: Check status
        if (result.status == "REVOKED") {
            result.is_revoked = true;
            result.error_message = "Node status is REVOKED";
            txn.commit();
            return result;
        }
        
        if (result.status == "QUARANTINED") {
            result.is_quarantined = true;
            result.error_message = "Node is quarantined due to suspicious activity";
            txn.commit();
            return result;
        }
        
        if (result.status == "SUSPENDED") {
            result.error_message = "Node is suspended";
            txn.commit();
            return result;
        }
        
        if (result.status == "PENDING_APPROVAL") {
            result.error_message = "Node enrollment is pending approval";
            txn.commit();
            return result;
        }
        
        // Step 4: Check expiration (if set)
        if (!node_result[0]["node_key_expires_at"].is_null()) {
            long expiration_time = node_result[0]["node_key_expires_at"].as<long>();
            if (expiration_time > 0) {
                long current_time = std::time(0);
                if (current_time >= expiration_time) {
                    result.is_expired = true;
                    result.error_message = "Node key has expired";
                    txn.commit();
                    return result;
                }
            }
        }
        
        // Step 5: Check consecutive failures (auto-quarantine threshold)
        if (!node_result[0]["consecutive_failures"].is_null()) {
            int failures = node_result[0]["consecutive_failures"].as<int>();
            if (failures >= 5) {
                // Auto-quarantine
                conn->prepare("auto_quarantine",
                    "UPDATE nodes SET status = 'QUARANTINED', "
                    "revocation_reason = 'Auto-quarantined due to repeated authentication failures' "
                    "WHERE node_key = $1");
                txn.exec_prepared("auto_quarantine", node_key);
                conn->unprepare("auto_quarantine");
                
                result.is_quarantined = true;
                result.error_message = "Node auto-quarantined due to repeated failures";
                
                BOOST_LOG_TRIVIAL(warning) << __SRCREF__ 
                    << "Node auto-quarantined: " << result.host_identifier 
                    << " (Failures: " << failures << ")";
                
                txn.commit();
                return result;
            }
        }
        
        // All checks passed
        result.is_valid = true;
        txn.commit();
        return result;
        
    } catch (const pqxx::sql_error& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Database error in node key validation: " << e.what();
        result.error_message = "Database error during validation";
        return result;
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error in node key validation: " << e.what();
        result.error_message = "Internal error during validation";
        return result;
    }
}

/**
 * @brief Increment failure counter for a node
 * 
 * @param node_key The node key
 * @param conn Database connection
 */
inline void incrementFailureCounter(
    const std::string& node_key,
    std::shared_ptr<pqxx::connection> conn)
{
    try {
        pqxx::work txn(*conn);
        long current_time = std::time(0);
        
        conn->prepare("increment_failures",
            "UPDATE nodes SET consecutive_failures = consecutive_failures + 1, "
            "last_failure_at = $2 WHERE node_key = $1");
        
        txn.exec_prepared("increment_failures", node_key, current_time);
        txn.commit();
        conn->unprepare("increment_failures");
        
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error incrementing failure counter: " << e.what();
    }
}

/**
 * @brief Reset failure counter for a node (on successful authentication)
 * 
 * @param node_key The node key
 * @param conn Database connection
 */
inline void resetFailureCounter(
    const std::string& node_key,
    std::shared_ptr<pqxx::connection> conn)
{
    try {
        pqxx::work txn(*conn);
        
        conn->prepare("reset_failures",
            "UPDATE nodes SET consecutive_failures = 0, last_failure_at = NULL "
            "WHERE node_key = $1");
        
        txn.exec_prepared("reset_failures", node_key);
        txn.commit();
        conn->unprepare("reset_failures");
        
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Error resetting failure counter: " << e.what();
    }
}

} // namespace VajraNodeValidator

#endif // VAJRA_NODE_VALIDATOR_H
