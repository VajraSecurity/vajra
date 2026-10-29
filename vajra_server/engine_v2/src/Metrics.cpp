#include "vajra_engine/Metrics.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string_view>

#include "../../common/logger.h"

namespace vajra_engine {
namespace {

constexpr int kBacklog = 16;
constexpr std::size_t kMaxRequestBytes = 8192;
// Bounds how long one slow/stalled client can block the single accept loop
// -- this server handles one connection at a time, so without a timeout a
// client that opens a connection and never sends/reads data would wedge the
// metrics endpoint indefinitely for every other scraper.
constexpr int kConnectionTimeoutSeconds = 5;

}  // namespace

MetricsServer::MetricsServer(std::string bind_address, unsigned short port,
                              std::function<std::string()> render)
    : bind_address_(std::move(bind_address)), port_(port), render_(std::move(render)) {}

MetricsServer::~MetricsServer() { stop(); }

void MetricsServer::start() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (running_.exchange(true)) return;  // already running

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__
                                  << "vajra_engine: metrics server socket() failed: " << std::strerror(errno);
        running_.store(false);
        return;
    }

    const int reuse = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (::inet_pton(AF_INET, bind_address_.c_str(), &addr.sin_addr) != 1) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: metrics server bind address '"
                                  << bind_address_ << "' is not a valid IPv4 address -- not starting";
        ::close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return;
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(listen_fd_, kBacklog) != 0) {
        BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "vajra_engine: metrics server bind/listen on "
                                  << bind_address_ << ":" << port_
                                  << " failed: " << std::strerror(errno);
        ::close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return;
    }

    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "vajra_engine: metrics server listening on "
                             << bind_address_ << ":" << port_ << "/metrics";
    thread_ = std::thread(&MetricsServer::run, this);
}

void MetricsServer::stop() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        // shutdown()+close() unblocks a thread parked in accept() on this
        // socket, so run() observes running_==false and exits promptly
        // instead of staying blocked until the next connection arrives.
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (thread_.joinable()) thread_.join();
}

void MetricsServer::run() {
    // Read listen_fd_ exactly once, into a local copy, before the loop
    // starts: run() only ever begins after start() has already set it
    // (under lifecycle_mutex_) and the thread was launched, so this one
    // read happens-after that write with no further synchronization needed.
    // Using this local `fd` for every accept() call (instead of re-reading
    // the listen_fd_ member on each loop iteration) avoids a data race with
    // stop(), which writes listen_fd_ = -1 (also under lifecycle_mutex_,
    // but from a different thread, with no lock shared with this loop) --
    // stop()'s shutdown()+close() on the real OS descriptor still correctly
    // unblocks accept(fd, ...) below regardless of which variable holds
    // that same descriptor number.
    const int fd = listen_fd_;
    while (running_.load(std::memory_order_relaxed)) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        const int conn_fd = ::accept(fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (conn_fd < 0) {
            if (!running_.load(std::memory_order_relaxed)) break;  // stop() closed the listen socket
            continue;
        }

        timeval tv{};
        tv.tv_sec = kConnectionTimeoutSeconds;
        ::setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        char buf[kMaxRequestBytes];
        // A single recv() call is sufficient for the tiny GET requests any
        // real Prometheus scraper or curl sends -- this is not a general
        // HTTP server and doesn't attempt to reassemble a request split
        // across multiple TCP segments.
        const ssize_t n = ::recv(conn_fd, buf, sizeof(buf) - 1, 0);
        std::string request;
        if (n > 0) request.assign(buf, static_cast<std::size_t>(n));

        std::string status_line = "HTTP/1.1 404 Not Found\r\n";
        std::string body = "not found\n";
        // Exact-path match: "GET /metrics" must be followed by a space (the
        // start of " HTTP/1.1") or nothing, not just any string it's a
        // prefix of (e.g. "GET /metrics-other" must 404, not match).
        constexpr std::string_view kMetricsRequestLine = "GET /metrics";
        if (request.rfind(kMetricsRequestLine, 0) == 0 &&
            (request.size() == kMetricsRequestLine.size() ||
             request[kMetricsRequestLine.size()] == ' ')) {
            try {
                body = render_();
                status_line = "HTTP/1.1 200 OK\r\n";
            } catch (const std::exception& e) {
                body = std::string("metrics render failed: ") + e.what() + "\n";
                status_line = "HTTP/1.1 500 Internal Server Error\r\n";
            }
        }

        const std::string response = status_line +
                                      "Content-Type: text/plain; version=0.0.4\r\n"
                                      "Content-Length: " +
                                      std::to_string(body.size()) +
                                      "\r\n"
                                      "Connection: close\r\n\r\n" +
                                      body;
        // send() may write fewer bytes than requested even on a blocking
        // socket (e.g. a signal interruption); loop until the whole
        // response is sent or the connection errors out, so a Content-
        // Length-declaring response is never silently truncated.
        std::size_t sent = 0;
        while (sent < response.size()) {
            const ssize_t written = ::send(conn_fd, response.data() + sent, response.size() - sent, 0);
            if (written <= 0) break;
            sent += static_cast<std::size_t>(written);
        }
        ::shutdown(conn_fd, SHUT_RDWR);
        ::close(conn_fd);
    }
}

}  // namespace vajra_engine
