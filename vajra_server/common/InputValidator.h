#ifndef VAJRA_INPUT_VALIDATOR_H
#define VAJRA_INPUT_VALIDATOR_H

#include <string>
#include <regex>
#include <stdexcept>

namespace VajraValidator {

/**
 * Validates host_identifier format
 * Allows: alphanumeric, hyphens, underscores, dots
 * Length: 1-255 characters
 */
inline bool isValidHostIdentifier(const std::string& host_id) {
    if (host_id.empty() || host_id.length() > 255) {
        return false;
    }
    
    // Only allow safe characters
    static const std::regex pattern("^[a-zA-Z0-9._-]+$");
    return std::regex_match(host_id, pattern);
}

/**
 * Validates node_key format
 * Accepts 20-char (legacy) or 64-char (enhanced) alphanumeric keys
 * 
 * Legacy keys: 20 characters (backward compatibility)
 * Enhanced keys: 64 characters (cryptographically secure)
 */
inline bool isValidNodeKey(const std::string& node_key) {
    size_t length = node_key.length();
    
    // Accept both legacy (20) and enhanced (64) key lengths
    if (length != 20 && length != 64) {
        return false;
    }
    
    // Only alphanumeric characters allowed
    static const std::regex pattern("^[a-zA-Z0-9]+$");
    return std::regex_match(node_key, pattern);
}

/**
 * Sanitizes string for database insertion
 * Removes null bytes and excessive length
 */
inline std::string sanitizeString(const std::string& input, size_t max_length = 65535) {
    std::string result = input;
    
    // Remove null bytes
    result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());
    
    // Truncate if too long
    if (result.length() > max_length) {
        result = result.substr(0, max_length);
    }
    
    return result;
}

/**
 * Validates table name to prevent injection
 */
inline bool isValidTableName(const std::string& table_name) {
    if (table_name.empty() || table_name.length() > 128) {
        return false;
    }
    
    // Only alphanumeric and underscore
    static const std::regex pattern("^[a-z][a-z0-9_]*$");
    return std::regex_match(table_name, pattern);
}

/**
 * Validates JSON payload size
 */
inline bool isValidPayloadSize(size_t size, size_t max_size = 10 * 1024 * 1024) {
    return size > 0 && size <= max_size;
}

/**
 * Validates Unix timestamp (reasonable range)
 */
inline bool isValidUnixTime(long timestamp) {
    // After 2000-01-01 and before 2100-01-01
    return timestamp >= 946684800L && timestamp <= 4102444800L;
}

/**
 * Validates file path (prevent directory traversal)
 * 
 * REVIEW: Check if your legitimate paths contain ".." before enabling strict checking
 */
inline bool isValidFilePath(const std::string& path, bool strict = false) {
    if (path.empty()) {
        return true; // Allow empty paths
    }
    
    if (path.length() > 4096) {
        return false; // Path too long
    }
    
    // Check for null bytes
    if (path.find('\0') != std::string::npos) {
        return false;
    }
    
    if (strict) {
        // REVIEW: Enable this if you want to block potential directory traversal
        // Warning: This may block legitimate paths containing ".."
        if (path.find("..") != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

/**
 * Validates event count in a request (DoS protection)
 * 
 * REVIEW: Adjust max_events based on your typical workload
 * Default 10,000 events per request should handle most scenarios
 */
inline bool isValidEventCount(size_t count, size_t max_events = 10000) {
    return count > 0 && count <= max_events;
}

/**
 * Validates numeric string before conversion
 * 
 * REVIEW: Determine if negative numbers are valid for your use case
 */
inline bool isValidNumericString(const std::string& value, bool allow_negative = true) {
    if (value.empty()) {
        return true; // Allow empty (will be converted to 0)
    }
    
    if (value.length() > 19) { // Max for 64-bit signed integer
        return false;
    }
    
    static const std::regex positive_pattern("^[0-9]+$");
    static const std::regex signed_pattern("^-?[0-9]+$");
    
    if (allow_negative) {
        return std::regex_match(value, signed_pattern);
    } else {
        return std::regex_match(value, positive_pattern);
    }
}

/**
 * Validates IP address format (IPv4 or IPv6)
 * 
 * REVIEW: Check if this validation is too strict for your data
 */
inline bool isValidIPAddress(const std::string& ip) {
    if (ip.empty()) {
        return true; // Allow empty
    }
    
    // Simple IPv4 validation
    static const std::regex ipv4_pattern(
        "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
    );
    
    // Simple IPv6 validation (basic pattern)
    static const std::regex ipv6_pattern(
        "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    );
    
    return std::regex_match(ip, ipv4_pattern) || std::regex_match(ip, ipv6_pattern);
}

/**
 * Validates command line string
 * 
 * REVIEW: This allows most characters as cmdline can contain special chars
 * Adjust if you need stricter validation
 */
inline bool isValidCommandLine(const std::string& cmdline, size_t max_length = 32768) {
    if (cmdline.length() > max_length) {
        return false;
    }

    // Check for null bytes
    if (cmdline.find('\0') != std::string::npos) {
        return false;
    }

    return true;
}

/**
 * Constant-time string comparison for secret/credential values (shared
 * secrets, tokens). A plain == / != short-circuits on the first differing
 * byte and on length mismatch, which leaks timing information an attacker
 * can use to recover the secret. Use this for any comparison against a
 * pre-shared credential (e.g. enroll_secret), not just post-auth session
 * tokens. Leaking the length is acceptable (matches the equivalent
 * constant-time helper in server/api/health.cpp).
 */
inline bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

} // namespace VajraValidator

#endif // VAJRA_INPUT_VALIDATOR_H
