#include <cerrno>
#include <chrono>
#include <cstring>
#include <sstream>
#include <boost/asio/io_context.hpp>
#include <boost/tokenizer.hpp>

#include <sys/socket.h>
#include <sys/time.h>

#include "ssl_certificate.h"
#include "WebServer.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

void
abort_server(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Bound every blocking recv/send on the raw fd. The server is synchronous
// (thread-per-connection), so beast's async expirations are unavailable;
// SO_RCVTIMEO/SO_SNDTIMEO make a stalled peer surface as an I/O error instead
// of pinning the session thread forever (slowloris). Zero disables the bound.
static void set_socket_io_timeout(tcp::socket& socket, unsigned int seconds)
{
    if (seconds == 0)
        return;

    timeval tv{};
    tv.tv_sec = seconds;
    // Non-fatal if either fails: worst case this one connection isn't
    // bounded by the configured timeout, not a reason to refuse it.
    if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        std::cerr << "set_socket_io_timeout: SO_RCVTIMEO setsockopt failed: " << std::strerror(errno) << "\n";
    if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        std::cerr << "set_socket_io_timeout: SO_SNDTIMEO setsockopt failed: " << std::strerror(errno) << "\n";
}

// This is the C++11 equivalent of a generic lambda.
// The function object is used to send an HTTP message.
template<class Stream>
struct send_lambda
{
    Stream& stream_;
    bool& close_;
    beast::error_code& ec_;

    explicit
    send_lambda(
            Stream& stream,
            bool& close,
            beast::error_code& ec)
            : stream_(stream)
            , close_(close)
            , ec_(ec)
    {
    }

    template<bool isRequest, class Body, class Fields>
    void
    operator()(http::message<isRequest, Body, Fields>&& msg) const
    {
        // Determine if we should close the connection after
        close_ = msg.need_eof();

        // We need the serializer here because the serializer requires
        // a non-const file_body, and the message oriented version of
        // http::write only works with const messages.
        http::serializer<isRequest, Body, Fields> sr{msg};
        http::write(stream_, sr, ec_);
    }
};

void WebServer::do_session(boost::asio::ip::tcp::socket &socket, boost::asio::ssl::context& ctx, const std::string& peer_ip)
{
    bool close = false;
    beast::error_code ec;

    // Whole-session deadline: SO_RCVTIMEO only bounds each individual
    // recv/send, so a slow-drip peer that keeps trickling bytes just under
    // that timeout (e.g. 1 byte every <io_timeout_seconds) can still pin this
    // thread indefinitely across keep-alive requests. Recycle the session
    // once it has run too long or served too many requests, whichever hits
    // first (checked at the top of every loop iteration, i.e. before
    // blocking on the next read).
    const auto session_start = std::chrono::steady_clock::now();
    unsigned int session_request_count = 0;

    // Construct the stream around the socket
    beast::ssl_stream<tcp::socket&> stream{socket, ctx};

    // Perform the SSL handshake, bounded so a client that stalls mid-handshake
    // cannot hold the thread.
    set_socket_io_timeout(socket, handshake_timeout_seconds);
    stream.handshake(ssl::stream_base::server, ec);
    if(ec)
        return abort_server(ec, "handshake");

    // Post-handshake bound covers stalled reads, stalled writes and idle
    // keep-alive waits alike: each blocking recv/send times out individually.
    set_socket_io_timeout(socket, io_timeout_seconds);

    // This buffer is required to persist across reads
    beast::flat_buffer buffer;
    beast::flat_buffer header_buffer;

    // This lambda is used to send messages
    send_lambda<beast::ssl_stream<tcp::socket&>> lambda{stream, close, ec};

    for(;;)
    {
        // Enforce the whole-session deadline before blocking on the next
        // read: a lifetime bound covers slow-drip stalling, a request-count
        // bound covers an endless (but individually fast) keep-alive stream.
        if ((max_session_seconds != 0 &&
             std::chrono::steady_clock::now() - session_start >=
                 std::chrono::seconds(max_session_seconds)) ||
            (max_session_requests != 0 &&
             session_request_count >= max_session_requests))
        {
            break;
        }

        // Read a request. Cap the body size so a single client cannot exhaust
        // memory; osquery log batches are at most a few MB, so this is a
        // generous bound.
        http::request_parser<http::string_body> parser;
        parser.body_limit(max_request_body_bytes);
        // Byte-count return intentionally discarded -- success/failure is
        // signaled via ec, checked immediately below (standard idiom for
        // this overload of http::read).
        (void)http::read(stream, buffer, parser, ec);

        if(ec == http::error::end_of_stream)
            break;
        else if (ec == boost::asio::ssl::error::stream_truncated)
        {
            /*
             * HTTP clients may not close connection cleanly. This case is to be ignored.
             */
            return;
        }
        else if(ec)
            return abort_server(ec, "read");

        ++session_request_count;

        // Send the response
        auto _req = parser.get();
        handle_request(std::move(_req), lambda, peer_ip);
        if(ec)
            return abort_server(ec, "write");
        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            break;
        }
    }

    // Perform the SSL shutdown
    stream.shutdown(ec);
    if(ec)
        return abort_server(ec, "shutdown");

    // At this point the connection is closed gracefully
}

void WebServer::run()
{
    try
    {
        // The io_context is required for all I/O
        net::io_context ioc{1};
        
        boost::asio::ip::tcp::resolver resolver(ioc);
        auto results = resolver.resolve(this->host, std::to_string(this->port));

        boost::asio::ip::tcp::endpoint endpoint = results.begin()->endpoint();
        std::string ipAddr = endpoint.address().to_string();

        auto const address = net::ip::make_address(ipAddr);

        // The SSL context holds the certificates and must outlive every
        // session thread that uses it. Session threads are detached, so a
        // stack-local ctx captured by reference would dangle the moment run()
        // returns (e.g. on an accept/setup error) while sessions are still
        // live — a use-after-free. Heap-allocate it and hand each thread a
        // shared_ptr copy so its lifetime is tied to the sessions, not to this
        // stack frame.
        auto ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);

        // This holds the self-signed certificate used by the server
        load_server_certificate(*ctx, this->ssl_certificate, this->ssl_private_key, this->diffie_hellman_key, this->private_key_password);

        // The acceptor receives incoming connections
        tcp::acceptor acceptor{ioc, {address, port}};

        for(;;)
        {
            // This will receive the new connection
            tcp::socket socket{ioc};

            // Block until we get a connection
            acceptor.accept(socket);

            // Bound concurrent sessions BEFORE committing a thread or a TLS
            // handshake. No handshake has happened yet, so a clean HTTP 503
            // is not possible — close immediately; the cap protects the
            // resources a 503 would itself consume.
            if (active_sessions.load() >= max_sessions)
            {
                beast::error_code ignored;
                socket.shutdown(tcp::socket::shutdown_both, ignored);
                socket.close(ignored);
                std::cerr << "connection rejected: session limit (" << max_sessions << ") reached" << std::endl;
                continue;
            }

            // Capture the TCP peer BEFORE the handshake: remote_endpoint()
            // can fail on a socket that died right after accept, hence the
            // error_code overload instead of the throwing one.
            beast::error_code ep_ec;
            auto remote = socket.remote_endpoint(ep_ec);
            std::string peer_ip = "unknown";
            if (!ep_ec)
            {
                // to_string() allocates and could in principle throw; keep it
                // out of the outer catch (which would stop the accept loop).
                try { peer_ip = remote.address().to_string(); }
                catch (...) { peer_ip = "unknown"; }
            }

            ++active_sessions;

            // Launch the session, transferring ownership of the socket.
            // The catch-all is essential: an exception escaping a detached
            // thread calls std::terminate and kills the whole server.
            try
            {
                std::thread{[this, ctx, s = std::move(socket), peer_ip = std::move(peer_ip)]() mutable
                            {
                                // RAII: the session slot must be released on
                                // every exit path, including exceptions.
                                struct SessionSlot
                                {
                                    std::atomic<unsigned int>& count;
                                    explicit SessionSlot(std::atomic<unsigned int>& c) : count(c) {}
                                    ~SessionSlot() { --count; }
                                } slot{active_sessions};

                                try
                                {
                                    do_session(s, *ctx, peer_ip);
                                }
                                catch (const std::exception &e)
                                {
                                    std::cerr << "session error: " << e.what() << std::endl;
                                }
                                catch (...)
                                {
                                    std::cerr << "session error: unknown exception" << std::endl;
                                }
                            }}.detach();
            }
            catch (const std::exception &e)
            {
                // Thread creation failed: no thread ran, so release the slot
                // here (the socket is closed by the lambda's destructor).
                --active_sessions;
                std::cerr << "failed to spawn session thread: " << e.what() << std::endl;
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

template<class Body, class Allocator, class Send>
void WebServer::handle_request(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req, Send&& send, const std::string& peer_ip)
{
    // Returns a bad request response
    auto const bad_request =
            [&req](beast::string_view why)
            {
                http::response<http::string_body> res{http::status::bad_request, req.version()};
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "text/html");
                res.keep_alive(req.keep_alive());
                res.body() = std::string(why);
                res.prepare_payload();
                return res;
            };

    HTTPMessage message;
    message.isRequest = true;

    if (req.method() == http::verb::get)
        message.type = RequestType::GET;
    else if (req.method() == http::verb::post)
        message.type = RequestType::POST;
    else if (req.method() == http::verb::delete_)
        message.type = RequestType::DELETE;
    else if (req.method() == http::verb::put)
        message.type = RequestType::PUT;
    else if (req.method() == http::verb::head)
        message.type = RequestType::HEAD;
    else if (req.method() == http::verb::options)
        message.type = RequestType::OPTIONS;
    else
        return send(bad_request("Unsupported HTTP-method"));

    std::stringstream sstr;

    for (auto const& hdr : req)
    {
        // The peer IP header is server-generated only: drop any
        // client-supplied value in any casing before injecting ours, so a
        // spoofed variant cannot survive under a different map key.
        if (beast::iequals(hdr.name_string(), "X-Vajra-Peer-IP"))
            continue;

        sstr.str(std::string());
        sstr << hdr.name();

        std::string name, value;
        name = sstr.str();
        sstr.str(std::string());

        sstr << hdr.value();
        value = sstr.str();

        message.header[name] = std::move(value);
    }

    // Authoritative TCP peer, captured before the TLS handshake in run().
    // Handlers must treat this — never X-Forwarded-For — as the client IP.
    message.header["X-Vajra-Peer-IP"] = peer_ip.empty() ? "unknown" : peer_ip;

    message.body = req.body();
    sstr.str(std::string());
    sstr << req.target();

    std::string target_path = sstr.str();
    std::string query_string;
    boost::escaped_list_separator<char> query_separator("", "?", "\"\'");
    boost::escaped_list_separator<char> query_param_separator("", "&", "\"\'");
    boost::escaped_list_separator<char> key_separator("", "=", "\"\'");
    boost::tokenizer<boost::escaped_list_separator<char>> url_tokens(target_path, query_separator);

    bool target_reset = true;

    for(const auto& it : url_tokens)
    {
        if (target_reset) {
            target_path = it;
            target_reset = false;
        }
        else
            query_string = it;
    }

    boost::tokenizer<boost::escaped_list_separator<char>> query_tokens(query_string, query_param_separator);
    for(const auto& it: query_tokens)
    {
        // Here, we will get a key-value pair in each step. We can split that, and populate HTTPMessage::populate
        bool isKey = true;
        std::string key, value;
        boost::tokenizer<boost::escaped_list_separator<char>> key_value(it, key_separator);
        for(const auto& token : key_value)
        {
            if (isKey)
            {
                key = token;
                isKey = false;
            }
            else
            {
                value = token;
            }
        }

        message.query[key] = std::move(value);
    }

    // A handler exception must not escape onto the session thread (it would
    // tear down the connection, or historically the whole process) — map it
    // to a 500 instead.
    HTTPMessage reply;
    try
    {
        reply = this->router.run(target_path, message);
    }
    catch (const std::exception &e)
    {
        std::cerr << "handler error for [" << target_path << "]: " << e.what() << std::endl;
        // Pool exhaustion / DB outage is a capacity condition, not a server
        // bug — surface it as 503 so clients back off and retry.
        const std::string what = e.what() ? e.what() : "";
        const bool unavailable = what.find("db_pool_timeout") != std::string::npos
                              || what.find("db_unavailable") != std::string::npos;
        reply.isRequest = false;
        reply.status = unavailable ? http::status::service_unavailable
                                   : http::status::internal_server_error;
        reply.body = unavailable ? "{\"message\":\"Service unavailable\"}"
                                 : "{\"message\":\"Internal server error\"}";
        reply.header["Content-Type"] = "application/json";
        if (unavailable)
            reply.header["Retry-After"] = "5";
    }
    catch (...)
    {
        std::cerr << "handler error for [" << target_path << "]: unknown exception" << std::endl;
        reply.isRequest = false;
        reply.status = http::status::internal_server_error;
        reply.body = "{\"message\":\"Internal server error\"}";
        reply.header["Content-Type"] = "application/json";
    }

    http::response<http::string_body> res{reply.status, req.version()};

    for (auto &it : reply.header)
    {
        res.set(it.first, it.second);
    }

    res.body() = reply.body;
    res.content_length(reply.body.length());
    res.keep_alive(req.keep_alive());
    res.prepare_payload();

    return send(std::move(res));
}

WebServer::WebServer(RequestRouter router, std::string host, unsigned short port)
{
    this->router = std::move(router);
    this->host = std::move(host);
    this->port = port;
}

void WebServer::setTlsCertificates(std::string ssl_certificate, std::string ssl_private_key,
                                   std::string diffie_hellman_key, std::string private_key_password)
{
    this->ssl_certificate = std::move(ssl_certificate);
    this->ssl_private_key = std::move(ssl_private_key);
    this->diffie_hellman_key = std::move(diffie_hellman_key);
    this->private_key_password = std::move(private_key_password);
}

void WebServer::setSessionLimit(unsigned int max_concurrent_sessions)
{
    // Zero (absent/unset config key) keeps the built-in default: a cap of
    // zero would reject every connection.
    if (max_concurrent_sessions > 0)
        this->max_sessions = max_concurrent_sessions;
}

void WebServer::setSocketTimeouts(unsigned int handshake_seconds, unsigned int io_seconds)
{
    this->handshake_timeout_seconds = handshake_seconds;
    this->io_timeout_seconds = io_seconds;
}

void WebServer::setRequestBodyLimit(std::uint64_t max_bytes)
{
    // Zero (absent/unset config key) keeps the built-in default: a body
    // limit of zero would reject every request with a body.
    if (max_bytes > 0)
        this->max_request_body_bytes = max_bytes;
}

void WebServer::setSessionDeadline(unsigned int max_seconds, unsigned int max_requests)
{
    // Unlike the body/session-count caps above, zero here is a deliberate
    // "disable this bound" per the header contract, not an ignored sentinel.
    this->max_session_seconds = max_seconds;
    this->max_session_requests = max_requests;
}