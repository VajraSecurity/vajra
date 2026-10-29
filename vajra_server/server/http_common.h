#ifndef FLEET_HTTP_COMMON_H
#define FLEET_HTTP_COMMON_H

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <string>
#include <unordered_map>

enum RequestType
{
    HEAD,
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    // Not a real HTTP method -- the safe default for HTTPMessage::type so a
    // message never carries an indeterminate value. WebServer::handle_request
    // sets type explicitly for every method it recognizes; anything else
    // (TRACE, CONNECT, PATCH, an unparseable method token) is rejected with
    // 400 before a message carrying this value ever reaches ChainRouter.
    UNKNOWN
};

struct HTTPMessage
{
    bool isRequest;
    RequestType type;
    boost::beast::http::status status;
    std::unordered_map<std::string, std::string> header;
    std::unordered_map<std::string, std::string> query;
    std::string body;

    HTTPMessage();
};

#endif //FLEET_HTTP_COMMON_H
