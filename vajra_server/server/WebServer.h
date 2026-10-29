//
// Created by adhokshajmishra on 12/10/20.
//

#ifndef FLEET_WEBSERVER_H
#define FLEET_WEBSERVER_H

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/config.hpp>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <memory>
#include "../common/ConnectionPool.h"
#include "http_common.h"
#include "RequestRouter.h"

class WebServer {
private:
    std::string ssl_certificate, ssl_private_key, diffie_hellman_key, private_key_password;
    std::string host;
    unsigned short port;
    unsigned int max_sessions = 2048;
    unsigned int handshake_timeout_seconds = 10;
    unsigned int io_timeout_seconds = 60;
    // Per-request body cap (default 16MB — osquery log batches are a few MB).
    std::uint64_t max_request_body_bytes = 16ULL * 1024 * 1024;
    // Whole-session bounds: the per-recv SO_RCVTIMEO cannot stop a slow-drip
    // peer that keeps enough traffic flowing to reset each recv, nor an endless
    // keep-alive request stream. Recycle the connection after a max lifetime or
    // a max number of keep-alive requests, whichever hits first. Zero disables
    // the respective bound.
    unsigned int max_session_seconds = 300;
    unsigned int max_session_requests = 10000;
    std::atomic<unsigned int> active_sessions{0};
    void do_session( boost::asio::ip::tcp::socket& socket, boost::asio::ssl::context& ctx, const std::string& peer_ip);
    template<class Body, class Allocator, class Send> void handle_request(boost::beast::http::request<Body,
            boost::beast::http::basic_fields<Allocator>>&& req, Send&& send, const std::string& peer_ip);
    RequestRouter router;
public:
    WebServer(RequestRouter router, std::string host = "0.0.0.0", unsigned short port = 1234);
    void setTlsCertificates(std::string ssl_certificate, std::string ssl_private_key, std::string diffie_hellman_key, std::string private_key_password);
    // Cap on concurrent sessions (default 2048). Zero is ignored so a missing
    // config key can be passed through without disabling the server.
    void setSessionLimit(unsigned int max_concurrent_sessions);
    // Socket-level timeouts in seconds: handshake bound pre-TLS, io bound for
    // every blocking read/write afterwards (including keep-alive idle waits).
    // Zero disables the respective timeout.
    void setSocketTimeouts(unsigned int handshake_seconds, unsigned int io_seconds);
    // Per-request body cap in bytes (default 16MB). Zero is ignored so an
    // absent/misconfigured key can't leave the server accepting 0-byte
    // bodies only.
    void setRequestBodyLimit(std::uint64_t max_bytes);
    // Whole-session bounds: recycle a keep-alive connection after
    // max_seconds of wall-clock lifetime or max_requests served, whichever
    // comes first — closes the slow-drip gap that per-recv SO_RCVTIMEO
    // cannot cover. Zero disables the respective bound.
    void setSessionDeadline(unsigned int max_seconds, unsigned int max_requests);
    void run();
};


#endif //FLEET_WEBSERVER_H
