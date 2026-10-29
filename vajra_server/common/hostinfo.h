
#ifndef FLEET_HOSTINFO_H
#define FLEET_HOSTINFO_H

#include "ConnectionPool.h"

#include <memory>

std::string process_files_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection);
std::string process_sockets_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection);
std::string process_pipes_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection);
std::string process_ports_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection);

#endif //FLEET_HOSTINFO_H
