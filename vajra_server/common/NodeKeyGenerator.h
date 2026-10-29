#ifndef VAJRA_NODE_KEY_GENERATOR_H
#define VAJRA_NODE_KEY_GENERATOR_H

#include <string>
#include <random>
#include <stdexcept>
#include <algorithm>
#include <openssl/rand.h>

namespace VajraNodeKey {

/**
 * @brief Generate a cryptographically secure random node key
 * 
 * Uses OpenSSL's RAND_bytes for cryptographically secure random generation.
 * The generated key contains only alphanumeric characters [0-9A-Za-z].
 * 
 * @param length Length of the key to generate (default: 64)
 * @return std::string Secure random node key
 * @throws std::runtime_error if random generation fails
 */
inline std::string generateSecureNodeKey(size_t length = 64) {
    if (length < 32) {
        throw std::invalid_argument("Node key length must be at least 32 characters");
    }
    
    if (length > 256) {
        throw std::invalid_argument("Node key length must not exceed 256 characters");
    }
    
    // Use OpenSSL for cryptographically secure random bytes
    unsigned char buffer[length];
    if (RAND_bytes(buffer, length) != 1) {
        throw std::runtime_error("Failed to generate cryptographically secure random bytes");
    }
    
    // Character set for node key: alphanumeric only
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charset_size = sizeof(charset) - 1; // Exclude null terminator
    
    std::string node_key;
    node_key.reserve(length);
    
    for (size_t i = 0; i < length; i++) {
        node_key += charset[buffer[i] % charset_size];
    }
    
    return node_key;
}

/**
 * @brief Generate node key expiration timestamp
 * 
 * @param expiry_days Number of days until expiration
 * @return long Unix timestamp when key expires
 */
inline long generateExpirationTimestamp(unsigned int expiry_days) {
    long current_time = std::time(0);
    long seconds_in_day = 86400;
    return current_time + (expiry_days * seconds_in_day);
}

/**
 * @brief Check if a node key has expired
 * 
 * @param expiration_timestamp The expiration timestamp to check
 * @return bool True if expired, false otherwise
 */
inline bool isNodeKeyExpired(long expiration_timestamp) {
    if (expiration_timestamp == 0) {
        return false; // No expiration set
    }
    
    long current_time = std::time(0);
    return current_time >= expiration_timestamp;
}

} // namespace VajraNodeKey

#endif // VAJRA_NODE_KEY_GENERATOR_H
