// Contract tests for the pinned interface (see .team/charter.md / dev1 mailbox):
//   header: common/InMemoryRateLimiter.h
//   class:  VajraRateLimit::InMemoryRateLimiter
//   ctor:   InMemoryRateLimiter(size_t max_per_window, unsigned window_seconds)
//   method: bool allow(const std::string& ip)  — true = permitted; thread-safe
//
// This file is only compiled when the header exists (guarded in tests/CMakeLists.txt),
// so the test suite stays buildable while the implementation lands in parallel.

#include "catch2/catch.hpp"

#include "InMemoryRateLimiter.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using VajraRateLimit::InMemoryRateLimiter;

TEST_CASE("rate limiter allows requests under the limit", "[ratelimit]") {
    InMemoryRateLimiter rl(5, 60);
    for (int i = 0; i < 5; ++i) {
        INFO("request #" << i + 1);
        CHECK(rl.allow("10.0.0.1"));
    }
}

TEST_CASE("rate limiter denies requests over the limit", "[ratelimit]") {
    InMemoryRateLimiter rl(3, 60);
    CHECK(rl.allow("10.0.0.2"));
    CHECK(rl.allow("10.0.0.2"));
    CHECK(rl.allow("10.0.0.2"));
    CHECK_FALSE(rl.allow("10.0.0.2"));
    CHECK_FALSE(rl.allow("10.0.0.2")); // stays denied within the window
}

TEST_CASE("rate limiter tracks each IP independently", "[ratelimit]") {
    InMemoryRateLimiter rl(2, 60);
    CHECK(rl.allow("10.0.0.3"));
    CHECK(rl.allow("10.0.0.3"));
    CHECK_FALSE(rl.allow("10.0.0.3"));   // .3 exhausted
    CHECK(rl.allow("10.0.0.4"));         // .4 unaffected
    CHECK(rl.allow("10.0.0.4"));
    CHECK_FALSE(rl.allow("10.0.0.4"));
}

TEST_CASE("rate limiter re-allows after the window expires", "[ratelimit]") {
    InMemoryRateLimiter rl(2, 1); // 1-second window keeps the test fast
    CHECK(rl.allow("10.0.0.5"));
    CHECK(rl.allow("10.0.0.5"));
    CHECK_FALSE(rl.allow("10.0.0.5"));

    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK(rl.allow("10.0.0.5"));
}

TEST_CASE("rate limiter limit of zero denies everything", "[ratelimit]") {
    InMemoryRateLimiter rl(0, 60);
    CHECK_FALSE(rl.allow("10.0.0.6"));
}

TEST_CASE("rate limiter concurrent calls stay within the limit", "[ratelimit]") {
    constexpr size_t kMax = 100;
    constexpr int kThreads = 8;
    constexpr int kCallsPerThread = 50; // 400 total attempts against a 100 budget

    InMemoryRateLimiter rl(kMax, 60);
    std::atomic<int> allowed{0};

    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&rl, &allowed]() {
            for (int i = 0; i < kCallsPerThread; ++i) {
                if (rl.allow("10.0.0.7")) {
                    allowed.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }

    // Exactly the budget must be granted — no lost updates, no over-admission.
    CHECK(allowed.load() == static_cast<int>(kMax));
}

TEST_CASE("rate limiter concurrent calls across distinct IPs", "[ratelimit]") {
    constexpr int kThreads = 8;
    InMemoryRateLimiter rl(10, 60);
    std::atomic<int> denied{0};

    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&rl, &denied, t]() {
            const std::string ip = "192.168.1." + std::to_string(t);
            for (int i = 0; i < 10; ++i) { // exactly at budget per IP
                if (!rl.allow(ip)) {
                    denied.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }

    CHECK(denied.load() == 0);
}
