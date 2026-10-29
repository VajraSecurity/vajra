
#include "hostinfo.h"
#include "logger.h"
#include "ConfigurationParser.h"
#include "../3rdparty/json.hpp"
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <bits/stdc++.h>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include<ctime>

#include <memory>
#include <string>

#include <pqxx/pqxx>
#include "../server/request_handler.h"


namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// class host_info
// {
    std::string usr_logged (std::string host_identifier, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        try
        {  
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time)
            {
                connection->prepare("get_usr_logged", "select id,logged_user from logged_in_users where host_identifier = $1 and unixtime >= $2 and unixtime <= $3");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_usr_logged", host_identifier, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_usr_logged");
            }
            else
            {
                connection->prepare("get_usr_logged", "select id,logged_user from logged_in_users where host_identifier = $1");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_usr_logged", host_identifier);
                transaction.commit();
                connection->unprepare("get_usr_logged");
            }
            
            
            for (pqxx::result::const_iterator c = result.begin(); c != result.end(); ++c)
            {
                response_json["logged users"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"logged_user", c["logged_user"].as<std::string>()}
                };
            };
            if(result.size()<=0)
            {
                response_json = "{\n"
                                "  \"status\":\"Fail\",\n"
                                "  \"message\":\"No data available\"\n"
                                "}";
                return response_json;
            }
            else
            {
                // response_json is a JSON OBJECT here (built via ["logged
                // users"] += ... above), not a string -- returning it
                // directly relied on nlohmann::json's implicit conversion to
                // std::string, which only succeeds for a json value that IS
                // already a string and otherwise throws json::type_error
                // (302). That meant this success path threw on every call
                // that actually found data, was caught by this function's
                // own catch(...) below, and silently returned the generic
                // failure message instead of the real result. .dump()
                // serializes any JSON value correctly.
                return response_json.dump();
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Query to get users logged failed due to database error.\"\n"
                            "}";

            return response_json;
        }
        catch(...)
        {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get users logged";
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Failed to get users logged\"\n"
                            "}";
            return response_json;
        }
    }    
        

    std::string usr_groups (std::string host_identifier, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time)
            {
                connection->prepare("get_usr_groups", "select id, username, groupname from suid_bin where host_identifier = $1 and unixtime >= $2 and unixtime <= $3");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_usr_groups", host_identifier, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_usr_groups");
            }
            else
            {
                connection->prepare("get_usr_groups", "select id, username, groupname from suid_bin where host_identifier = $1");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_usr_groups", host_identifier);
                transaction.commit();
                connection->unprepare("get_usr_groups");
            }
            
            for (pqxx::result::const_iterator c = result.begin(); c != result.end(); ++c)
            {
                response_json["logged users"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"username", c["username"].as<std::string>()},
                {"groupname", c["groupname"].as<std::string>()}
                };
            };
            if(result.size()<=0)
            {
                response_json = "{\n"
                                "  \"status\":\"Fail\",\n"
                                "  \"message\":\"No data available\"\n"
                                "}";
                return response_json;
            }
            else
            {
                // See usr_logged()'s identical fix above: response_json is a
                // JSON object here, not a string -- .dump() serializes it
                // correctly instead of relying on an implicit conversion
                // that throws (and was being silently caught below, always
                // returning the generic failure message instead of the data).
                return response_json.dump();
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Query to get users and groups failed due to database error.\"\n"
                            "}";
            return response_json;
        }
        catch(...)
        {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get users and groups";
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Failed to get users and groups\"\n"
                            "}";
            return response_json;
        }   
    }

    std::string suid_bin_list (std::string host_identifier, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time)
            {
                connection->prepare("get_suid_list", "select * from suid_bin where host_identifier = $1 and unixtime >= $2 and unixtime <= $3");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_suid_list", host_identifier, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_suid_list");
            }
            else
            {
                connection->prepare("get_suid_list", "select * from suid_bin where host_identifier = $1");
                pqxx::work transaction{*connection};
                pqxx::result result = transaction.exec_prepared("get_suid_list", host_identifier);
                transaction.commit();
                connection->unprepare("get_suid_list");
            }
            
            
            for (pqxx::result::const_iterator c = result.begin(); c != result.end(); ++c)
            {
                response_json["logged users"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"host_identifier", c["host_identifier"].as<std::string>()},
                {"path", c["path"].as<std::string>()},
                {"username", c["username"].as<std::string>()},
                {"groupname", c["groupname"].as<std::string>()},
                {"permissions", c["permissions"].as<std::string>()},
                {"action", c["action"].as<std::string>()}
                };
            };
            if(result.size()<=0)
            {
                response_json = "{\n"
                                "  \"status\":\"Fail\",\n"
                                "  \"message\":\"No data available\"\n"
                                "}";
                return response_json;
            }
            else
            {
                // See usr_logged()'s identical fix above: response_json is a
                // JSON object here, not a string -- .dump() serializes it
                // correctly instead of relying on an implicit conversion
                // that throws (and was being silently caught below, always
                // returning the generic failure message instead of the data).
                return response_json.dump();
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Query to get suid binaries list failed due to database error.\"\n"
                            "}";
            return response_json;
        }
        catch(...)
        {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get suid binaries list";
            response_json = "{\n"
                            "  \"status\":\"Fail\",\n"
                            "  \"message\":\"Failed to get suid binaries list\"\n"
                            "}";
            return response_json;
        }     
    }

    std::string process_files_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        pqxx::result open_files;
        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time && !pid)
            {
                connection->prepare("get_process_open_files", "select * from process_open_files where host_identifier = $1 and pid = $2 and unixtime >= $3 and unixtime <= $4");
                pqxx::work transaction{*connection};
                open_files = transaction.exec_prepared("get_process_open_files", host_identifier , pid, start_time, end_time);
                connection->unprepare("get_process_open_files");
            }
            else
            {
                connection->prepare("get_process_open_files", "select * from process_open_files where host_identifier = $1 and pid = $2");
                pqxx::work transaction{*connection};
                open_files = transaction.exec_prepared("get_process_open_files", host_identifier, pid);
                connection->unprepare("get_process_open_files");
            }
            
            if (open_files.size()>0)
            {
            for (pqxx::result::const_iterator c = open_files.begin(); c != open_files.end(); ++c)
            {
                response_json["process_open_files"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"host_identifier", c["host_identifier"].as<std::string>()},
                {"pid", c["pid"].as<std::string>()},
                {"fd", c["fd"].as<std::string>()},
                {"path", c["path"].as<std::string>()},
                {"action", c["action"].as<std::string>()}
                };
            };
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
        }
        catch(...)
        {   
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get process opened files";
        }
        return response_json.dump();   
    }

    std::string process_sockets_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        pqxx::result open_sockets;

        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time  && !pid)
            {
                connection->prepare("get_process_open_sockets", "select * from process_open_sockets where host_identifier = $1 and pid = $2 and unixtime >= $3 and unixtime <= $4");
                pqxx::work transaction{*connection};
                open_sockets = transaction.exec_prepared("get_process_open_sockets", host_identifier, pid, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_process_open_sockets");
            }
            else
            {
                connection->prepare("get_process_open_sockets", "select * from process_open_sockets where host_identifier = $1 and pid = $2");
                pqxx::work transaction{*connection};
                open_sockets = transaction.exec_prepared("get_process_open_sockets", host_identifier, pid);
                transaction.commit();
                connection->unprepare("get_process_open_sockets");
            }
            
            if (open_sockets.size()>0)
            {
            for (pqxx::result::const_iterator c = open_sockets.begin(); c != open_sockets.end(); ++c)
            {
                response_json["process_open_sockets"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"host_identifier", c["host_identifier"].as<std::string>()},
                {"pid", c["pid"].as<std::string>()},
                {"fd", c["fd"].as<std::string>()},
                {"socket", c["socket"].as<std::string>()},
                {"family", c["family"].as<std::string>()},
                {"protocol", c["protocol"].as<std::string>()},
                {"local_address", c["local_address"].as<std::string>()},
                {"remote_address", c["remote_address"].as<std::string>()},
                {"local_port", c["local_port"].as<std::string>()},
                {"remote_port", c["remote_port"].as<std::string>()},
                {"path", c["path"].as<std::string>()},
                {"state", c["state"].as<std::string>()},
                {"net_namespace", c["net_namespace"].as<std::string>()},
                {"action", c["action"].as<std::string>()}
                };
            };
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
        }
        catch(...)
        {   
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Unknown Error";
        }   
        return response_json.dump();
    }

    std::string process_pipes_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        pqxx::result open_pipes;
        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time  && !pid)
            {
                connection->prepare("get_process_open_pipes", "select * from process_open_pipes where host_identifier = $1 and pid = $2 and unixtime >= $3 and unixtime <= $4");
                pqxx::work transaction{*connection};
                open_pipes = transaction.exec_prepared("get_process_open_pipes", host_identifier, pid, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_process_open_pipes");
            }
            else
            {
                connection->prepare("get_process_open_pipes", "select * from process_open_pipes where host_identifier = $1 and pid = $2");
                pqxx::work transaction{*connection};
                open_pipes = transaction.exec_prepared("get_process_open_pipes", host_identifier, pid);
                transaction.commit();
                connection->unprepare("get_process_open_pipes");
            }
            
            if (open_pipes.size()>0)
            {
            for (pqxx::result::const_iterator c = open_pipes.begin(); c != open_pipes.end(); ++c)
            {
                response_json["process_open_pipes"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"host_identifier", c["host_identifier"].as<std::string>()},
                {"pid", c["pid"].as<std::string>()},
                {"fd", c["fd"].as<std::string>()},
                {"mode", c["mode"].as<std::string>()},
                {"inode", c["inode"].as<std::string>()},
                {"type", c["type"].as<std::string>()},
                {"partner_pid", c["partner_pid"].as<std::string>()},
                {"partner_fd", c["partner_fd"].as<std::string>()},
                {"partner_mode", c["partner_mode"].as<std::string>()},
                {"action", c["action"].as<std::string>()}
                };
            };
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
        }
        catch(...)
        {   
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get process opened pipes";
        }    
        return response_json.dump();
    }

    std::string process_ports_opened (std::string host_identifier, long long pid, long long start_time, long long end_time, std::shared_ptr<pqxx::connection> connection)
    {
        nlohmann::json response_json;
        pqxx::result open_ports;
        try
        {
            pqxx::result result;
            if (!host_identifier.empty() && !start_time && !end_time && !pid)
            {
                connection->prepare("get_listening_ports", "select * from listening_ports where host_identifier = $1 and pid = $2 and unixtime >= $3 and unixtime <= $4");
                pqxx::work transaction{*connection};
                open_ports = transaction.exec_prepared("get_listening_ports", host_identifier, pid, start_time, end_time);
                transaction.commit();
                connection->unprepare("get_listening_ports");
            }
            else
            {
                connection->prepare("get_listening_ports", "select * from listening_ports where host_identifier = $1 and pid = $2");
                pqxx::work transaction{*connection};
                open_ports = transaction.exec_prepared("get_listening_ports", host_identifier , pid);
                transaction.commit();
                connection->unprepare("get_listening_ports");
            }
            
            if (open_ports.size()>0)
            {
            for (pqxx::result::const_iterator c = open_ports.begin(); c != open_ports.end(); ++c)
            {
                response_json["listening_ports"] += 
                { \
                {"id", c["id"].as<std::string>()},
                {"host_identifier", c["host_identifier"].as<std::string>()},
                {"pid", c["pid"].as<std::string>()},
                {"fd", c["fd"].as<std::string>()},
                {"mode", c["mode"].as<std::string>()},
                {"inode", c["inode"].as<std::string>()},
                {"type", c["type"].as<std::string>()},
                {"partner_pid", c["partner_pid"].as<std::string>()},
                {"partner_fd", c["partner_fd"].as<std::string>()},
                {"partner_mode", c["partner_mode"].as<std::string>()},
                {"action", c["action"].as<std::string>()}
                };
            };
            }
        }
        catch (pqxx::sql_error const &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Database error: " << e.what() << ". Query was: " << e.query();
        }
        catch(...)
        {   
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Unknown error: could not get process opened pipes";
        }    
        return response_json.dump();
    }
// };

// int main()
// {
//     host_info obj;

//     ConfigurationParser config_parser("config.json");
//     if (!config_parser.parse())
//     {
//         BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Cannot read configuration";
//         return -1;
//     }

//     FleetServerConfiguration fleet = config_parser.GetFleetConfiguration();
//     std::shared_ptr<ConnectionPool> connection_pool(new ConnectionPool(fleet.database.ConnectionString(), fleet.database_pool.maximum_connections));

//     auto conn = connection_pool->GetConnection();
//     return 0;
// }
