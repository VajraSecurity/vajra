#ifndef VAJRA_IN_MEMORY_RATE_LIMITER_H
#define VAJRA_IN_MEMORY_RATE_LIMITER_H

#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace VajraRateLimit {

/**
 * @brief Header-only per-IP sliding-window rate limiter.
 *
 * Deliberately has no database, configuration, or logging dependencies so it
 * can gate a request before any other subsystem is touched (and keeps working
 * when those subsystems are down).
 */
class InMemoryRateLimiter
{
public:
    InMemoryRateLimiter(size_t max_per_window, unsigned window_seconds)
        : max_per_window_(max_per_window),
          window_(window_seconds)
    {
    }

    /**
     * @brief Check whether a request from this IP is allowed.
     *
     * Thread-safe. Over-limit calls are not recorded, so a blocked client
     * regains access one window after its last accepted request.
     *
     * @param ip The client IP address (any non-empty key works)
     * @return bool True if the request is permitted, false if over limit
     */
    bool allow(const std::string& ip)
    {
        const Clock::time_point now = Clock::now();
        const Clock::time_point cutoff = now - window_;

        std::lock_guard<std::mutex> lock(mutex_);

        pruneStaleEntries(now, cutoff);

        auto& timestamps = windows_[ip];
        while (!timestamps.empty() && timestamps.front() <= cutoff)
        {
            timestamps.pop_front();
        }

        if (timestamps.size() >= max_per_window_)
        {
            return false;
        }
        timestamps.push_back(now);
        return true;
    }

private:
    using Clock = std::chrono::steady_clock;

    // Drop IPs whose entire window has expired so the map cannot grow without
    // bound under an IP-spread attack. Amortised: full sweep at most once per
    // window.
    void pruneStaleEntries(const Clock::time_point& now, const Clock::time_point& cutoff)
    {
        if (now - last_prune_ < window_)
        {
            return;
        }
        last_prune_ = now;
        for (auto it = windows_.begin(); it != windows_.end();)
        {
            if (it->second.empty() || it->second.back() <= cutoff)
            {
                it = windows_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    const size_t max_per_window_;
    const std::chrono::seconds window_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<Clock::time_point>> windows_;
    Clock::time_point last_prune_{Clock::now()};
};

} // namespace VajraRateLimit

#endif // VAJRA_IN_MEMORY_RATE_LIMITER_H
