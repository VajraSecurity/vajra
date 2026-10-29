#ifndef FLEET_REQUEST_HANDLER_H
#define FLEET_REQUEST_HANDLER_H

#include "WebServer.h"
#include "../common/ConfigurationParser.h"

extern std::string enrollment_secret;
extern NodeConfiguration global_node_config;

HTTPMessage enroll(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);
HTTPMessage config(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);
HTTPMessage logger(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);
HTTPMessage distributed_read(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);
HTTPMessage distributed_write(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);

// Health monitoring and diagnostics endpoints
HTTPMessage health_check(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);
HTTPMessage dead_letter_queue(const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection);

// Bearer-token gate for /health/deadletter. Exposed so the router can reject
// unauthorized callers BEFORE checking out a DB connection (a pool slot must
// not be spent on unauthenticated traffic). Fails closed when unconfigured.
bool health_deadletter_authorized(const HTTPMessage& request);

#endif //FLEET_REQUEST_HANDLER_H
