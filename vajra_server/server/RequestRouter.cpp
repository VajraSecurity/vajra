#include "RequestRouter.h"

std::string destination(const ChainRouter& router)
{
    return router.path;
}

bool default_invoke_handler(const std::string& destination, HTTPMessage& request)
{
    return true;
}

HTTPMessage default_req_handler(const std::string& destination, const HTTPMessage& request)
{
    HTTPMessage response;

    std::stringstream ss;
    ss << "Requested destination [" + destination + "] does not exist.\n\nQuery parameters:\n";

    for (const auto& it : request.query)
    {
        ss << it.first << " : " << it.second << std::endl;
    }

    ss << "\nHeaders:\n";
    for (const auto& it : request.header)
    {
        ss << it.first << " : " << it.second << std::endl;
    }

    std::string reply = ss.str();
    response.status = boost::beast::http::status::not_found;
    response.body = std::move(reply);
    response.header["Content-Type"] = "text/plain";
    return response;
}

ChainRouter ChainRouter::route(std::string path)
{
    this->path = std::move(path);
    return *this;
}

ChainRouter ChainRouter::all(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    common_handler.push_back(handler);
    return *this;
}

ChainRouter ChainRouter::put(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    put_handler.push_back(handler);
    return *this;
}

ChainRouter ChainRouter::get(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    get_handler.push_back(handler);
    return *this;
}

ChainRouter ChainRouter::post(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    post_handler.push_back(handler);
    return *this;
}

ChainRouter ChainRouter::delete_(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    delete_handler.push_back(handler);
    return *this;
}

ChainRouter ChainRouter::head(std::function<HTTPMessage(const HTTPMessage&)> handler)
{
    head_handler.push_back(handler);
    return *this;
}

HTTPMessage ChainRouter::operator()(const HTTPMessage& request)
{
    HTTPMessage response, interim_request = request;
    bool isProcessed = false;

    switch(request.type)
    {
        case RequestType::GET:
            for (const auto& handler : get_handler)
            {
                isProcessed = true;
                interim_request = handler(interim_request);
                if (!interim_request.isRequest)
                {
                    response = interim_request;
                    break;
                }
            }
            break;
        case RequestType::PUT:
            for (const auto& handler : put_handler)
            {
                isProcessed = true;
                interim_request = handler(interim_request);
                if (!interim_request.isRequest)
                {
                    response = interim_request;
                    break;
                }
            }
            break;
        case RequestType::POST:
            for (const auto& handler : post_handler)
            {
                isProcessed = true;
                interim_request = handler(interim_request);
                if (!interim_request.isRequest)
                {
                    response = interim_request;
                    break;
                }
            }
            break;
        case RequestType::DELETE:
            for (const auto& handler : delete_handler)
            {
                isProcessed = true;
                interim_request = handler(interim_request);
                if (!interim_request.isRequest)
                {
                    response = interim_request;
                    break;
                }
            }
            break;
        case RequestType::HEAD:
            for (const auto& handler : head_handler)
            {
                isProcessed = true;
                interim_request = handler(interim_request);
                if (!interim_request.isRequest)
                {
                    response = interim_request;
                    break;
                }
            }
            break;
        case RequestType::OPTIONS:
            {
                isProcessed = true;
                std::string allowed_methods= "OPTIONS";
                if (!get_handler.empty())
                    allowed_methods.append(", GET");
                if (!put_handler.empty())
                    allowed_methods.append(", PUT");
                if (!post_handler.empty())
                    allowed_methods.append(", POST");
                if (!delete_handler.empty())
                    allowed_methods.append(", DELETE");
                if (!head_handler.empty())
                    allowed_methods.append(", HEAD");

                response.header["Allow"] = allowed_methods;
                response.header["Access-Control-Allow-Methods"] = std::move(allowed_methods);
            }
            break;
        default:
            isProcessed = true;
            response.status = boost::beast::http::status::not_implemented;
    }

    if (!isProcessed)
    {
        for (const auto& handler : common_handler)
        {
            isProcessed = true;
            interim_request = handler(interim_request);
            if (!interim_request.isRequest)
            {
                response = std::move(interim_request);
                break;
            }
        }
    }

    if (!isProcessed)
        response.status = boost::beast::http::status::not_found;

    return response;
}

RequestRouter RequestRouter::use(const ChainRouter& router)
{
    route_handler[destination(router)] = router;
    return *this;
}

RequestRouter RequestRouter::use(const std::vector<ChainRouter>& routers)
{
    for (const auto& router : routers)
    {
        route_handler[destination(router)] = router;
    }
    return *this;
}

HTTPMessage RequestRouter::run(const std::string& path, HTTPMessage& request)
{
    HTTPMessage response;

    if (this->pre_handler(path, request))
    {
        // Do NOT use operator[] here: it inserts a route for every unknown
        // path, which both grows the map unboundedly (URL scanners) and
        // mutates it concurrently from session threads (data race). The map
        // must stay read-only after setup.
        auto route = route_handler.find(path);
        if (route != route_handler.end())
        {
            response = route->second(request);
        }
        else
        {
            response = this->default_handler(path, request);
            response.isRequest = false;
        }
        this->post_handler(path, response);
    }
    else
    {
        response.status = boost::beast::http::status::unauthorized;
    }

    return response;
}

ChainRouter& RequestRouter::operator[](const std::string& destination)
{
    if (route_handler.find(destination) == route_handler.end())
    {
        auto handler = std::bind(this->default_handler, destination, std::placeholders::_1);
        ChainRouter router;
        router.route(destination);
        route_handler[destination] = std::move(router);
        route_handler[destination].all(handler);
    }

    return route_handler[destination];
}

RequestRouter::RequestRouter()
{
    this->default_handler = default_req_handler;
    this->pre_handler = default_invoke_handler;
    this->post_handler = default_invoke_handler;
}

RequestRouter::RequestRouter(std::function<HTTPMessage(const std::string&, const HTTPMessage&)> default_request_handler,
                             std::function<bool(const std::string &, HTTPMessage &)> pre_invoke_handler,
                             std::function<bool(const std::string &, HTTPMessage &)> post_invoke_handler)
{
    this->default_handler = std::move(default_request_handler);
    this->pre_handler = std::move(pre_invoke_handler);
    this->post_handler = std::move(post_invoke_handler);
}