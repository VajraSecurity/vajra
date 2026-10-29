// Functional regression tests for Metrics.cpp's MetricsServer. The
// listen_fd_ data race between run() (accept-loop thread) and stop() (fixed
// by making listen_fd_ a std::atomic<int> -- see Metrics.h/Metrics.cpp) was
// proven fixed with an ad hoc ThreadSanitizer driver outside this suite
// (this repo's normal build isn't TSan-instrumented); see re-vega.md for
// that exact command + output. These tests instead cover MetricsServer's
// observable behavior and exercise repeated start()/stop() cycles under
// concurrent traffic as a functional (non-TSan) regression check.
#include "catch2/catch.hpp"

#include "vajra_engine/Metrics.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

using namespace vajra_engine;

namespace {
// Sends `request_line` and returns whatever bytes come back (empty on any
// connection failure).
std::string http_roundtrip(unsigned short port, const std::string& request_line) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    std::string response;
    // The server thread may not have finished bind()/listen() the instant
    // start() returns in a loaded CI environment -- retry briefly rather
    // than flake.
    bool connected = false;
    for (int attempt = 0; attempt < 50 && !connected; ++attempt) {
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            connected = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!connected) {
        ::close(fd);
        return "";
    }
    ::send(fd, request_line.data(), request_line.size(), 0);
    char buf[4096];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n > 0) response.assign(buf, static_cast<std::size_t>(n));
    ::close(fd);
    return response;
}
}  // namespace

TEST_CASE("MetricsServer serves /metrics with the render callback's body", "[engine][metrics]") {
    MetricsServer server("127.0.0.1", 19091, []() { return std::string("hello_metric 1\n"); });
    server.start();
    auto response = http_roundtrip(19091, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();

    REQUIRE_FALSE(response.empty());
    CHECK(response.find("200 OK") != std::string::npos);
    CHECK(response.find("hello_metric 1") != std::string::npos);
}

TEST_CASE("MetricsServer 404s on any path other than exactly /metrics", "[engine][metrics]") {
    MetricsServer server("127.0.0.1", 19092, []() { return std::string("should not appear"); });
    server.start();
    auto response = http_roundtrip(19092, "GET /metrics-other HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();

    REQUIRE_FALSE(response.empty());
    CHECK(response.find("404") != std::string::npos);
    CHECK(response.find("should not appear") == std::string::npos);
}

TEST_CASE("MetricsServer returns 500 (not a crash) when the render callback throws", "[engine][metrics]") {
    MetricsServer server("127.0.0.1", 19093, []() -> std::string { throw std::runtime_error("boom"); });
    server.start();
    auto response = http_roundtrip(19093, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();

    REQUIRE_FALSE(response.empty());
    CHECK(response.find("500") != std::string::npos);
}

TEST_CASE("MetricsServer::start/stop is idempotent and repeatable", "[engine][metrics]") {
    MetricsServer server("127.0.0.1", 19094, []() { return std::string("ok\n"); });
    for (int i = 0; i < 5; ++i) {
        server.start();
        server.start();  // no-op, already running
        server.stop();
        server.stop();  // no-op, already stopped
    }
}

TEST_CASE("MetricsServer::stop() concurrent with active client traffic never hangs or crashes",
          "[engine][metrics]") {
    // Functional analogue of the TSan reproduction: hammer connections from
    // another thread while start()/stop() cycle, repeatedly, and simply
    // require the whole thing to complete promptly (stop() joins run()'s
    // thread internally, so a hang here would time the test out).
    MetricsServer server("127.0.0.1", 19095, []() { return std::string("ok\n"); });
    for (int iter = 0; iter < 10; ++iter) {
        server.start();
        std::atomic<bool> keep_going{true};
        std::thread hammer([&] {
            while (keep_going.load()) {
                auto resp = http_roundtrip(19095, "GET /metrics HTTP/1.1\r\n\r\n");
                (void)resp;
            }
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        server.stop();
        keep_going.store(false);
        hammer.join();
    }
    SUCCEED("all start/stop cycles under concurrent traffic completed");
}
