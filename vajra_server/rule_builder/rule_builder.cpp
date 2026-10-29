#include <iostream>
#include <fstream>
#include <pqxx/pqxx>
#include <sqlite3.h>
#include "../3rdparty/json.hpp"
#include "rule_builder.h"

#include <thread>
#include <utility>
#include <vector>
#include <regex>
#include <sys/wait.h>
#include <unistd.h>
#include "../common/hostinfo.h"
#include "../common/logger.h"
#include "../common/ConfigurationParser.h"

#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <boost/algorithm/string.hpp>

// SQL identifiers (table/column names) may come from untrusted rule definitions
// and cannot be bound as parameters, so validate them against a strict allowlist
// before they are ever interpolated into a query.
namespace
{
    bool is_valid_sql_identifier(const std::string &identifier)
    {
        static const std::regex identifier_pattern("^[A-Za-z_][A-Za-z0-9_]*$");
        return !identifier.empty() && identifier.size() <= 64 &&
               std::regex_match(identifier, identifier_pattern);
    }
}

void send_email(const std::string &to_address, const std::string &subject, const std::map<std::string, std::string> &replacements)
{
    nlohmann::json replacements_json = replacements;
    std::string replacements_str = replacements_json.dump();

    // Do NOT go through a shell: the subject embeds untrusted rule name and
    // hostname, and to_address / replacements come from the database. Passing
    // them as an argv to execvp means they are handed to the script verbatim and
    // can never be interpreted as shell metacharacters (command injection).
    std::vector<std::string> args = {
        "python3",
        "../email/send_email.py",
        to_address,
        subject,
        std::move(replacements_str)};

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (auto &arg : args)
    {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0)
    {
        std::cerr << "Failed to fork process for send_email" << std::endl;
        return;
    }

    if (pid == 0)
    {
        // Child: replace image with the mailer. No shell is involved.
        execvp(argv[0], argv.data());
        // Only reached if execvp fails.
        _exit(127);
    }

    // Parent: wait for the mailer to finish.
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
    {
        std::cerr << "Failed to wait for send_email process" << std::endl;
        return;
    }
    std::cout << "send_email exit status: " << status << std::endl;
}

Rule_Builder::Rule_Builder(std::shared_ptr<ConnectionPool> pool)
{
    this->pool = std::move(pool);
}

nlohmann::json read_config(const std::string &config_file)
{
    std::ifstream file(config_file);
    nlohmann::json config;
    if (file.is_open())
    {
        file >> config;
    }
    else
    {
        std::cerr << "Unable to open config file: " << config_file << std::endl;
    }
    return config;
}

// Helper function to sanitize values
std::string sanitizeValue(const std::string& value) {
    // Check if the value is empty or an escaped empty string
    if (value.empty() || value == "\"\\\"\\\"\"") {
        return "N/A";
    }
    return value;
}

[[noreturn]] void Rule_Builder::run_rule_builder()
{
    while (true)
    {
        try
        {
            auto connection = pool->GetConnection();
            std::string rule_builder, tactics, alerters, platform, table_name;
            std::string name, technique_id, type, link, description, rule_written_by, sql_query;
            nlohmann::json rule_json;
            int severity;
            connection->prepare("rule_builder_rule", "select * from rule_builder_rules");
            pqxx::work transaction{*connection};
            pqxx::result result = transaction.exec_prepared("rule_builder_rule");
            transaction.commit();
            connection->unprepare("rule_builder_rule");
            // SELECT result: use row count, not affected_rows() (0 for SELECT).
            int no_affected_rows = result.size();
            if (no_affected_rows > 0)
            {
                for (int i = 0; i < no_affected_rows; i++)
                {
                    for (pqxx::result::const_iterator c = result.begin(); c != result.end(); ++c)
                    {
                        name = c["name"].as<std::string>();
                        description = c["description"].as<std::string>();
                        link = c["link"].as<std::string>();
                        platform = c["platform"].as<std::string>();
                        severity = c["severity"].as<long>();
                        // nlohmann::json j = nlohmann::json::parse(c["tactics"].as<std::string>());
                        // tactics = j[0]["value"];
                        tactics = "Testing";
                        technique_id = c["technique_id"].as<std::string>();
                        type = c["type"].as<std::string>();
                        rule_written_by = c["rule_written_by"].as<std::string>();
                        alerters = c["alerters"].as<std::string>();
                        rule_builder = c["rule_builder"].as<std::string>();
                        sql_query = c["sql_query"].as<std::string>();
                        std::string _operator, table, match_case;
                        rule_json = nlohmann::json::parse(rule_builder);
                        int no_of_conditions = rule_json["queries"].size();
                        int no_of_tables = 1;
                        for (int n = 1; n < no_of_conditions; n++)
                        {
                            for (int p = 0; p < n; p++)
                            {
                                if (rule_json["queries"][n]["tableName"] == rule_json["queries"][p]["tableName"])
                                {
                                    break;
                                }
                                no_of_tables++;
                            }
                        }
                        // else{
                        std::string operator_rule = rule_json["operator"];
                        table_name = rule_json["queries"][0]["tableName"];
                        std::string column_name = rule_json["queries"][0]["columnName"];

                        std::string conditionType = rule_json["queries"][0]["conditionType"];
                        std::string value = rule_json["queries"][0]["value"];
                        // std::string query;

                        // if (no_of_conditions == 1)
                        // {
                        //     std::string next_part = ")and is_processed_rule_builder = 'f'";
                        //     // change < to >
                        //     query = "select * from " + table_name + " where(";
                        //     for (int j = 0; j < no_of_conditions; j++)
                        //     {
                        //         std::string table_name = rule_json["queries"][j]["tableName"];
                        //         // std::string table_name_2 = rule_json["queries"][i+1]["tableName"];
                        //         std::string column_name = rule_json["queries"][j]["columnName"];
                        //         // std::string column_name_2 = rule_json["queries"][i+1]["columnName"];
                        //         std::string conditionType = rule_json["queries"][j]["conditionType"];
                        //         std::string data_type = rule_json["queries"][j]["dataType"];
                        //         std::string value = rule_json["queries"][j]["value"];
                        //         if (data_type == "string" and conditionType == "contains")
                        //         {
                        //             query += table_name + "." + column_name + " like '%" + value + "%' ";
                        //         }
                        //         else if (data_type == "string" and conditionType == "equal")
                        //         {
                        //             query += table_name + "." + column_name + " = '" + value + "' ";
                        //         }
                        //         else if (data_type == "int" and conditionType == "equal")
                        //         {
                        //             query += table_name + "." + column_name + " = " + value;
                        //         }
                        //         if (j < no_of_conditions - 1)
                        //         {
                        //             query += operator_rule + " ";
                        //         }
                        //         // + " "+table_name+"."+column_name+" like '%"+value+"%' "+operator_rule+ " "+table_name+"."+column_name+" like '%"+value+"%'";
                        //     }
                        //     query += next_part;
                        // }

                        // else
                        // {
                        //     std::string commonColumn1, commonColumn2;
                        //     std::string table_name_2 = rule_json["queries"][1]["tableName"];
                        //     std::string column_name_2 = rule_json["queries"][1]["columnName"];

                        //     std::string conditionType_2 = rule_json["queries"][1]["conditionType"];
                        //     std::string value_2 = rule_json["queries"][1]["value"];
                        //     std::string next_part = ")and " + table_name + ".is_processed_rule_builder = 'f'";
                        //     // change < to >

                        //     if (no_of_tables == 1)
                        //     {
                        //         query = "select * from " + table_name + " where (";
                        //     }
                        //     else if (rule_json["queries"][0].contains("commonColumn"))
                        //     {
                        //         std::string commonColumn1 = rule_json["queries"][0]["commonColumn"];
                        //         std::string commonColumn2 = rule_json["queries"][0]["commonColumn"];

                        //         query = "select * from " + table_name + " join " + table_name_2 + " on " + table_name + "." + commonColumn1 + "=" + table_name_2 + "." + commonColumn2 + " where( " + table_name + ".host_identifier = " + table_name_2 + ".host_identifier and ";
                        //     }
                        //     // else
                        //     // {
                        //     //     query = "select * from " + table_name + " join " + table_name_2 + " on " + table_name + "." + column_name_2 + "=" + table_name_2 + "." + column_name_2 + " where(";
                        //     // }

                        //     for (int k = 0; k < no_of_conditions; k++)
                        //     {
                        //         std::string table_name = rule_json["queries"][k]["tableName"];
                        //         // std::string table_name_2 = rule_json["queries"][i+1]["tableName"];
                        //         std::string column_name = rule_json["queries"][k]["columnName"];
                        //         // std::string column_name_2 = rule_json["queries"][i+1]["columnName"];
                        //         std::string conditionType = rule_json["queries"][k]["conditionType"];
                        //         std::string value = rule_json["queries"][k]["value"];
                        //         std::string data_type = rule_json["queries"][k]["dataType"];

                        //         // for (int m = 0; m < i; m++) {
                        //         // if(table_name == rule_json["queries"][m]["tableName"]){
                        //         //     query+= table_name+"."+column_name+" like '%"+value+ "%' ";
                        //         // }
                        //         // }

                        //         if (data_type == "string" and conditionType == "contains")
                        //         {
                        //             query += table_name + "." + column_name + " like '%" + value + "%' ";
                        //         }
                        //         else if (data_type == "string" and conditionType == "equal")
                        //         {
                        //             query += table_name + "." + column_name + " = '" + value + "' ";
                        //         }
                        //         else if (data_type == "int" and conditionType == "equal")
                        //         {
                        //             query += table_name + "." + column_name + " = " + value;
                        //         }

                        //         // query+= table_name+"."+column_name+" like '%"+value+ "%' ";
                        //         if (k < no_of_conditions - 1)
                        //         {
                        //             query += operator_rule + " ";
                        //         }
                        //         // + " "+table_name+"."+column_name+" like '%"+value+"%' "+operator_rule+ " "+table_name+"."+column_name+" like '%"+value+"%'";
                        //     }
                        //     query += next_part;
                        // }
                        std::cout << sql_query << std::endl;
                        connection->prepare("rule_builder_query", sql_query);
                        pqxx::work transaction{*connection};
                        pqxx::result result_count = transaction.exec_prepared("rule_builder_query");
                        transaction.commit();
                        // SELECT result: use row count, not affected_rows() (0 for SELECT).
                        int no_detection = result_count.size();
                        connection->unprepare("rule_builder_query");
                        if (no_detection > 0)
                        {

                            for (int k = 0; k < no_detection; k++)
                            {
                                nlohmann::json event_metadata;
                                                            // Extract and sanitize values from result_count
                                auto get_sanitized_value = [](const pqxx::row& row, const std::string& column_name) -> std::string {
                                    if (row[column_name].is_null()) {
                                        return ""; // Default to empty string for null values
                                    }
                                    return row[column_name].as<std::string>();
                                };

                                std::string host_identifier = get_sanitized_value(result_count.at(k), "host_identifier");
                                // std::string hostname = get_sanitized_value(result_count.at(k), "hostname");
                                // std::string pid = result_count.at(k)["pid"].is_null() ? "0" : result_count.at(k)["pid"].as<std::string>();
                                std::string hostname =result_count.at(k)["hostname"].as<std::string>();
                                std::cout << hostname;
                                long unixtime = result_count.at(k)["unixTime"].as<long>();
                                bool isAlert = true;

                                try
                                {
                                    for (const auto &column : result_count.at(k))
                                    {
                                        std::string column_name = column.name();

                                        // Check for null before conversion (optional, but recommended)
                                        if (column.is_null())
                                        {
                                            // Handle null value (more on this later)
                                            continue; // Or throw a specific null value exception if needed
                                        }
                                        // Dynamically populate event_metadata with column name and value
                                        event_metadata[column_name] = column.as<std::string>();
                                    }
                                }
                                catch (const pqxx::conversion_error &)
                                {
                                    continue;
                                }

                                //  ProcessEvent process_event;

                                // process_event.entry.pid = result_count.at(k)["pid"].as<long>();
                                // process_event.entry.path = result_count.at(k)["path"].as<std::string>();
                                // process_event.entry.cmdline = result_count.at(k)["cmdline"].as<std::string>();
                                // process_event.entry.cwd = result_count.at(k)["cwd"].as<std::string>();
                                // process_event.entry.parent = result_count.at(k)["parent"].as<long>();
                                // process_event.entry.syscall = result_count.at(k)["syscall"].as<std::string>();
                                // process_event.entry.action = result_count.at(k)["action"].as<std::string>();
                                // process_event.entry.process_guid = result_count.at(k)["process_guid"].as<std::string>();
                                // process_event.entry.parent_process_guid = result_count.at(k)["parent_process_guid"].as<std::string>();
                                // process_event.entry.process_name = result_count.at(k)["process_name"].as<std::string>();
                                // process_event.entry.local_address = result_count.at(k)["local_address"].as<std::string>();
                                // process_event.entry.remote_address = result_count.at(k)["remote_address"].as<std::string>();
                                // process_event.entry.local_port = result_count.at(k)["local_port"].as<int>();
                                // process_event.entry.remote_port = result_count.at(k)["remote_port"].as<int>();
                                // process_event.entry.target_path = result_count.at(k)["target_path"].as<std::string>();
                                // process_event.entry.md5 = result_count.at(k)["md5"].as<std::string>();
                                // process_event.entry.sha256 = result_count.at(k)["sha256"].as<std::string>();
                                // process_event.entry.hashed = result_count.at(k)["hashed"].as<int>();
                                // // event_metadata["user_id"] = result_count.at(k)["user_id"].as<long long>();
                                // process_event.entry.pid = result_count.at(k)["pid"].as<long>();

                                // event_metadata["pid"] = process_event.entry.pid;
                                // event_metadata["path"] = process_event.entry.path;
                                // event_metadata["action"] = process_event.entry.action;
                                // event_metadata["process_name"] = process_event.entry.process_name;
                                // event_metadata["parent_pid"] = process_event.entry.parent;
                                // event_metadata["family"] = process_event.entry.family;
                                // event_metadata["local_address"] = process_event.entry.local_address;
                                // event_metadata["remote_address"] = process_event.entry.remote_address;
                                // event_metadata["local_port"] = process_event.entry.local_port;
                                // event_metadata["remote_port"] = process_event.entry.remote_port;
                                // event_metadata["target_path"] = process_event.entry.target_path;
                                // event_metadata["md5"] = process_event.entry.md5;
                                // event_metadata["sha256"] = process_event.entry.sha256;

                                
                                if (isAlert)
                                {
                                    std::cout << "CODE: " << name << " (" << severity << ")\n";
                                    // std::cout << "METADATA: " << event_metadata["path"].get<std::string>() << ", " << event_metadata["cmdline"].get<std::string>() << std::endl;
                                }
                                
                                for (const auto &column : result_count.at(k))
                                {
                                    std::string column_name = column.name();
                                    event_metadata[column_name] = column.is_null() ? "" : column.as<std::string>();
                                }

                                // Insert sanitized data into alerts
                                connection->prepare(
                                    "insert_alerts",
                                    "insert into alerts (host_identifier, unixtime, event_code, metadata, is_alert, severity, is_open, alert_type, technique, technique_id, link, action, os_name,hostname) "
                                    "values ($1, $2, $3, $4, $5, $6, true, 'Process Alert', $7, $8, $9, 'None', $10,$11)"
                                );

                                pqxx::work transaction{*connection};
                                pqxx::result insert_events = transaction.exec_prepared(
                                    "insert_alerts",
                                    host_identifier,
                                    unixtime,
                                    name,
                                    event_metadata.dump(),
                                    isAlert,
                                    severity,
                                    tactics,
                                    technique_id,
                                    link,
                                    platform,
                                    hostname
                                );

                                transaction.commit();
                                connection->unprepare("insert_alerts");
                                pool->ReturnConnection(connection);

                                // Code to update process events table is_processed flag to true and then send email.
                                int bpf_process_event_table_id = std::stoi(event_metadata["id"].get<std::string>());
                                if (!is_valid_sql_identifier(table_name))
                                {
                                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping is_processed update with invalid table identifier";
                                    continue;
                                }
                                // table_name validated above; id is bound as a parameter.
                                std::string query = "update " + table_name + " set is_processed_rule_builder = 't' where id = $1 and (is_processed_rule_builder is null or is_processed_rule_builder = 'f')";
                                std::cout << query << std::endl;
                                //pqxx::work transaction{*connection};
                                pqxx::result update_count = transaction.exec_params(query, bpf_process_event_table_id);
                                transaction.commit();
                                pool->ReturnConnection(connection);
                                
                                /**
                                 * Start of the section
                                 * Author: Sunita
                                 * Date : 06-08-2024
                                 * Adding Code for sending emails If there is any critical alert
                                 */
                                if (severity == 4 && isAlert)
                                {
                                    try
                                    {

                                        nlohmann::json config = read_config("config.json");

                                        std::string dbname = config["nodejs_user_server"]["db_configuration"]["database_name"];
                                        std::string user = config["nodejs_user_server"]["db_configuration"]["username"];
                                        std::string password = config["nodejs_user_server"]["db_configuration"]["password"];
                                        std::string hostaddr = config["nodejs_user_server"]["db_configuration"]["hostname"];
                                        int port = config["nodejs_user_server"]["db_configuration"]["port"];
                                        std::string str_port = std::to_string(port);

                                        std::string conn_str = "dbname=" + dbname + " user=" + user + " password=" + password +
                                                               " hostaddr=" + hostaddr + " port=" + str_port;
                                        pqxx::connection C(conn_str);
                                        if (C.is_open())
                                        {
                                            pqxx::work W(C);

                                            // Fetch recipient_username from email_configuration table
                                            std::string query1 = "SELECT recipient_username FROM email_configuration WHERE active = TRUE";
                                            pqxx::result result = W.exec(query1);

                                            if (!result.empty())
                                            {

                                                std::cout << "row1: " << result[0]["recipient_username"] << std::endl;
                                                // Parse the JSON string stored in recipient_username
                                                std::string recipient_json_str = result[0]["recipient_username"].as<std::string>();

                                                // Parse JSON
                                                nlohmann::json recipient_json = nlohmann::json::parse(recipient_json_str);

                                                for (auto &[username, email] : recipient_json.items())
                                                {
                                                    std::cout << "Username: " << username << ", Email: " << email << std::endl;

                                                    // Check if email is empty
                                                    if (!email.empty())
                                                    {

                                                        std::string hostname = result_count.at(k)["hostname"].as<std::string>();
                                                        std::string subject = "Critical Alert : " + name + " : " + hostname;
                                                        std::string host_identifier = result_count.at(k)["host_identifier"].as<std::string>();
                                                        long long unixtime = result_count.at(k)["unixtime"].as<long long>();

                                                        nlohmann::json c = nlohmann::json::parse(platform);

                                                        std::string platform_label = c[0].at("label").get<std::string>();

                                                        std::string event_metadata_dump = event_metadata.dump();
                                                        
                                                        std::map<std::string, std::string> replacements = {
                                                            {"alert_name", name},
                                                            {"date_time", std::to_string(unixtime)},
                                                            {"host_name", hostname},
                                                            {"host_identifier", host_identifier},
                                                            {"os_name", platform_label},
                                                            {"technique_id", sanitizeValue(technique_id)},
                                                            {"tactic", sanitizeValue(tactics)},
                                                            // {"meta_data", event_metadata_dump}
                                                        };

                                                        send_email(email, subject, replacements);
                                                    }
                                                    else
                                                    {
                                                        std::cout << "No email found for username: " << username << std::endl;
                                                    }
                                                }
                                            }

                                            // W.commit();
                                            // C.disconnect();
                                        }
                                        else
                                        {
                                            std::cerr << "Can't open database" << std::endl;
                                        }
                                    }
                                    catch (const std::exception &e)
                                    {
                                        std::cerr << e.what() << std::endl;
                                    }
                                }

                                // End of the section
                                // transaction.commit();
                                //connection->unprepare("insert_alerts");
                                // std::time_t t = std::time(0);
                                // int created = t;
                                // std::string query = "update " + table_name + " set is_processed_rule_builder = 't' where unixTime < " + std::to_string(created) + " and is_processed_rule_builder is not true";
                                // connection->prepare("update_is_processed", query);
                                // pqxx::result update_count = transaction.exec_prepared("update_is_processed");
                                // connection->unprepare("update_is_processed");
                                // int no_affected_rows = update_count.affected_rows();
                            }
                        }
                        // }
                    }
                }
                std::time_t t = std::time(0);
                // Y2K38: narrowing time_t (64-bit on this platform) into a 32-bit
                // int reintroduces the 2038 rollover this platform's time_t itself
                // doesn't have. Use a wide type, matching how unixtime is handled
                // everywhere else in this function (long/long long).
                long created = static_cast<long>(t);
                if (is_valid_sql_identifier(table_name))
                {
                    // table_name validated above; created is bound as a parameter.
                    std::string query = "update " + table_name + " set is_processed_rule_builder = 't' where unixTime < $1 and (is_processed_rule_builder is null or is_processed_rule_builder = 'f')";
                    std::cout << query << std::endl;
                    pqxx::work transaction{*connection};
                    pqxx::result update_count = transaction.exec_params(query, created);
                    transaction.commit();
                }
                else
                {
                    BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Skipping is_processed update with invalid table identifier";
                }
                pool->ReturnConnection(std::move(connection));
                std::this_thread::sleep_for(std::chrono::seconds(3));
            }
        }
        catch (const std::exception &e)
        {
            BOOST_LOG_TRIVIAL(fatal) << "General error: " << e.what();
        }
    }
}

void Rule_Builder::run()
{
    std::thread run_rule_builder_thread(&Rule_Builder::run_rule_builder, this);

    run_rule_builder_thread.join();
}