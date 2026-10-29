#include "WebServer.h"
#include "request_handler.h"
#include "RequestRouter.h"
#include "KafkaProducerManager.h"
#include "../3rdparty/json.hpp"
#include "../common/ConnectionPool.h"
#include "../common/ConfigurationParser.h"
#include "../common/logger.h"

#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <chrono>
#include <fstream>
#include <memory>
#include <string>

#include <pqxx/pqxx>

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

HTTPMessage default_handler(const std::string& path, const HTTPMessage& request, std::shared_ptr<pqxx::connection> connection)
{
    HTTPMessage response;

    std::stringstream ss;
    ss << "Requested path [" + path + "] does not exist.\n\nQuery parameters:\n";

    for (const auto &it : request.query)
    {
        ss << it.first << " : " << it.second << std::endl;
    }

    ss << "\nHeaders:\n";
    for (const auto &it : request.header)
    {
        ss << it.first << " : " << it.second << std::endl;
    }

    std::string reply = ss.str();
    response.status = boost::beast::http::status::not_found;
    response.body = std::move(reply);
    response.header["Content-Type"] = "text/plain";
    return response;
}

std::string enrollment_secret;
NodeConfiguration global_node_config;
// Bearer token gating /health/deadletter (server/api/health.cpp). Empty means
// the endpoint stays disabled (health.cpp fails closed with 403).
std::string health_api_token;

int main(int argc, char *argv[])
{
  // Whole body wrapped: previously nothing here was exception-safe (only a
  // narrow inner try/catch existed around the optional-config-keys block),
  // so any exception escaping config parsing, connection-pool construction,
  // or WebServer startup/serving would abort the process with an unhandled
  // exception instead of a logged, clean exit.
  try
  {
    std::unordered_map<std::string, std::string> prepared_queries;

    // Reject revoked/blocked/expired keys at the transport level. A node failing
    // this check receives node_invalid=true and re-enrolls, where the
    // reenroll_allowed flag is the admin-facing gate.
    // NULL-safe: legacy rows with NULL status / NULL expiry stay valid.
    prepared_queries["validate_node_key"] = "select * from nodes where node_key = $1 "
                                            "and (status is null or status not in ('REVOKED', 'QUARANTINED', 'SUSPENDED', 'PENDING_APPROVAL')) "
                                            "and (node_key_expires_at is null or node_key_expires_at = 0 or node_key_expires_at > extract(epoch from now())::bigint) "
                                            "and not exists (select 1 from revoked_node_keys r where r.node_key = nodes.node_key)";
    prepared_queries["update_kernel_to_nodes"] = "update nodes set kernel_version = $1 where host_identifier = $2";
    prepared_queries["process_event_add"] = "insert into process_events "
                                            "(host_identifier, hostname, unixtime, atime, btime, ctime, mtime, time, uptime, "
                                            "auid, egid, euid, fsgid, fsuid, gid, mode, owner_gid, owner_uid, pid, "
                                            "ppid, sgid, suid, uid, cwd, cmdline, path, syscall) "
                                            "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, "
                                            "$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)";
    prepared_queries["socket_event_add"] = "insert into socket_events "
                                           "(host_identifier, hostname, unixTime, time, uptime, action, auid, family, fd, "
                                           "local_address, local_port, remote_address, remote_port, pid, path) "
                                           "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
    prepared_queries["user_event_add"] = "insert into user_events "
                                         "(host_identifier, unixTime, time, uptime, auid, pid, type, uid, "
                                         "path, address, message, terminal) "
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    prepared_queries["process_file_events_add"] = "insert into process_file_events "
                                                  "(host_identifier, operation, pid, ppid, time, executable, partial, cwd, path, dest_path, uid, gid, auid, euid, egid, fsuid, fsgid, suid, sgid, uptime, eid)"
                                                  "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)";
    prepared_queries["file_events"] = "insert into file_events "
                                      "(host_identifier, hostname, unixTime, target_path, category, action, transaction_id, inode, uid, gid, mode, size, atime, mtime, ctime, md5, sha1, sha256, hashed, time, eid)"
                                      "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)";

    prepared_queries["process_envs_add"] = "insert into process_envs "
                                           "(host_identifier, pid, key, value, action)"
                                           "values ($1, $2, $3, $4, $5)";

    prepared_queries["process_open_pipes_add"] = "insert into process_open_pipes "
                                                 "(host_identifier, unixTime, pid, fd, mode, inode, type, partner_pid, partner_fd, partner_mode, action)"
                                                 "values ($1, $2, $3, $4, $5, $6, $7, $8,$9, $10, $11)";
    prepared_queries["process_open_files_add"] = "insert into process_open_files "
                                                 "(host_identifier, unixTime, pid, fd, path, action)"
                                                 "values ($1, $2, $3, $4, $5, $6)";
    prepared_queries["listening_ports_add"] = "insert into listening_ports "
                                              "(host_identifier, unixTime, pid, port, protocol, family, address, fd, socket, path, net_namespace, action)"
                                              "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    prepared_queries["routes_add"] = "insert into routes "
                                     "(host_identifier, destination, netmask, gateway, source, flags, interface, mtu, metric, type, hopcount, action)"
                                     "values ($1, $2, $3, $4, $5, $6, $7, $8,$9, $10, $11, $12)";
    prepared_queries["logged_in_users_add"] = "insert into logged_in_users "
                                              "(host_identifier, unixTime, type, logged_user, tty, host, time, pid, sid, registry_hive, action)"
                                              "values ($1, $2, $3, $4, $5, $6, $7, $8,$9, $10, $11)";
    prepared_queries["arp_cache_add"] = "insert into arp_cache "
                                        "(host_identifier, address, mac, interface, permanent, action)"
                                        "values ($1, $2, $3, $4, $5, $6)";

    prepared_queries["suid_bin_add"] = "insert into suid_bin "
                                       "(host_identifier, unixTime, path, username, groupname, permissions, action)"
                                       "values ($1, $2, $3, $4, $5, $6, $7)";
    prepared_queries["process_open_sockets_add"] = "insert into process_open_sockets "
                                                   "(host_identifier, unixTime, pid, fd, socket, family, protocol, local_address, remote_address, local_port, remote_port, path, state, net_namespace, action)"
                                                   "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
    prepared_queries["users_add"] = "insert into users "
                                    "(host_identifier, uid, gid, uid_signed, gid_signed, is_hidden, username, description, directory, shell, uuid, type, action)"
                                    "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
    prepared_queries["groups_add"] = "insert into groups "
                                     "(host_identifier, gid, gid_signed, is_hidden, groupname, group_sid, comment, action)"
                                     "values ($1, $2, $3, $4, $5, $6, $7, $8)";
    prepared_queries["cpu_time"] = "insert into cpu_time "
                                   "(host_identifier, unixTime, core, users, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice)"
                                   "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
    prepared_queries["memory_info"] = "insert into memory_info "
                                      "(host_identifier, unixTime, memory_total, memory_available, memory_free, buffers, cached, swap_cached, active,  inactive, swap_total, swap_free)"
                                      "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    prepared_queries["bpf_process_events"] = "insert into bpf_process_events "
                                             "(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, probe_error, syscall, path, cwd, cmdline, duration, json_cmdline, ntime, time, eid, md5, sha1, sha256, is_container_process, container_age, container_name, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                             "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, 'f', 'f', 'f')";
    prepared_queries["bpf_socket_events"] = "insert into bpf_socket_events "
                                            "(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, probe_error, syscall, path, fd, family, type, protocol, local_address, remote_address, local_port, remote_port, duration, ntime, time, eid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                            "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, 'f', 'f', 'f')";
    prepared_queries["bpf_file_events"] = "insert into bpf_file_events "
                                          "(host_identifier, hostname, unixTime, tid, pid, parent, uid, gid, cid, exit_code, probe_error, syscall, path, file_path, flags, ntime, duration, time, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                          "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, 'f', 'f', 'f')";
    prepared_queries["docker_events"] = "insert into docker_events "
                                        "(host_identifier, hostname, action, from_column, status, scope, time, type, path, cmdline, pid, container_id, container_image, container_name, privileged, added_capabilities, dropped_capabilities, port_binding)"
                                        "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)";
    prepared_queries["interface_addresses"] = "insert into interface_addresses "
                                              "(host_identifier, unixtime, interface, address, mask, broadcast, point_to_point, type, friendly_name)"
                                              "values ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
    prepared_queries["win_process_events"] = "insert into win_process_events "
                                             "(host_identifier, hostname, unixTime, action, eid, pid, process_guid, path, cmdline, parent_pid, parent_process_guid, parent_path, owner_uid, time, uptime, utc_time, eventid, sha256, is_processed, is_processed_rule_builder, is_processed_py)"
                                             "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, 'f', 'f', 'f')";
    prepared_queries["win_socket_events"] = "insert into win_socket_events "
                                            "(host_identifier, hostname, unixTime, action, eid, time, utc_time, pid, process_guid, process_name, family, protocol, local_address, remote_address, local_port, remote_port, eventid, parent_pid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                            "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, 'f', 'f', 'f')";
    prepared_queries["win_file_events"] = "insert into win_file_events "
                                          "(host_identifier, hostname, unixTime, action, eid, target_path, md5, sha256, hashed, uid, utc_time, time, pe_file, pid, process_guid, process_name, eventid, parent_pid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                          "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, 'f', 'f', 'f')";
    prepared_queries["win_dns_events"] = "insert into win_dns_events "
                                         "(host_identifier, hostname, unixTime, event_type, action, eid, domain_name, request_type, request_class, pid, remote_address, remote_port, time, utc_time, eventid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'f', 'f', 'f')";
    prepared_queries["win_dns_response_events"] = "insert into win_dns_response_events "
                                         "(host_identifier, hostname, unixTime, event_type, action, eid, domain_name, request_type, request_class, resolved_ip, pid, remote_address, remote_port, time, utc_time, eventid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 'f', 'f', 'f')";
    prepared_queries["win_ssl_events"] = "insert into win_ssl_events "
                                         "(host_identifier, hostname, unixTime, event_type, action, eid, subject_name, issuer_name, serial_number, dns_names, server_name, ja3_md5, ja3s_md5, pid, process_guid, process_name, remote_address, remote_port, time, utc_time, eventid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, 'f', 'f', 'f')";
    prepared_queries["win_http_events"] = "insert into win_http_events "
                                         "(host_identifier, hostname, unixTime, event_type, action, eid, url, pid, process_guid, process_name, remote_address, remote_port, time, utc_time, eventid, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'f', 'f', 'f')";
    prepared_queries["win_image_load_events"] = "insert into win_image_load_events "
                                         "(host_identifier, hostname, unixTime, action, eid, pid, process_guid, image_path, md5, uid, time, utc_time, sign_info, trust_info, num_of_certs, cert_type, version, pubkey, pubkey_length, pubkey_signhash_algo, issuer_name, subject_name, serial_number, signature_algo, subject_dn, issuer_dn, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, 'f', 'f', 'f')";
    prepared_queries["win_image_load_process_map"] = "insert into win_image_load_process_map "
                                         "(host_identifier, hostname, unixTime, pid, process_guid, image_size, image_path, md5, image_memory_mode, image_base, time, utc_time, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'f', 'f', 'f')";
    prepared_queries["win_process_open_events"] = "insert into win_process_open_events "
                                         "(host_identifier, hostname, unixTime, action, eid, src_pid, src_process_guid, target_pid, target_process_guid, src_path, target_path, granted_access, granted_access_value, owner_uid, time, utc_time, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 'f', 'f', 'f')";
    prepared_queries["win_remote_thread_events"] = "insert into win_remote_thread_events "
                                         "(host_identifier, hostname, unixTime, eid, action, src_pid, src_process_guid, target_pid, target_process_guid, src_path, target_path, function_name, module_name, owner_uid, time, utc_time, uptime, is_processed, is_processed_rule_builder, is_processed_py)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 'f', 'f', 'f')";
    prepared_queries["chrome_extensions"] = "insert into chrome_extensions "
                                            "(host_identifier, hostname, unixTime, browser_type, uid, name, profile, profile_path, referenced_identifier, identifier, version, description, default_locale, current_locale, update_url, author, persistent, path, permissions, optional_permissions, manifest_hash, referenced, from_webstore, state, install_time, install_timestamp, key, is_processed, is_processed_py)"
                                            "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, 'f', 'f')";
    prepared_queries["file"] = "insert into file "
                               "(host_identifier, hostname, unixTime, path, directory, filename, inode, uid, gid, mode, device, size, block_size, atime, mtime, ctime, btime, hard_links, symlink, type, attributes, volume_serial, file_id, file_version, product_version, original_filename, bsd_flags, pid_with_namespace, mount_namespace_id, is_processed, is_processed_py)"
                               "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, 'f', 'f')";
    prepared_queries["wmi_cli_event_consumers"] = "insert into wmi_cli_event_consumers "
                                                  "(host_identifier, hostname, unixTime, name, command_line_template, executable_path, class, relative_path,  is_processed, is_processed_py)"
                                                  "values ($1, $2, $3, $4, $5, $6, $7, $8, 'f', 'f')";
    prepared_queries["snapshot_result_add"] = "insert into snapshot_result "
                                              "(host_identifier, unixTime, query_name, result) "
                                              "values ($1, $2, $3, $4)";
    prepared_queries["query_result_add"] = "insert into query_result "
                                           "(host_identifier, unixTime, query_name, result) "
                                           "values ($1, $2, $3, $4)";
    // osquery posts log_type "status" self-diagnostics to /log (glog severity,
    // filename, line, message, version, decorations) — persisted so agent-side
    // failures (denylisted queries, extension crashes, permission errors) are
    // visible server-side instead of being silently dropped.
    prepared_queries["status_log_add"] = "insert into status_logs "
                                         "(host_identifier, unixTime, severity, filename, line, message, version, decorations) "
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8)";
    prepared_queries["osquery_schedule"] = "insert into osquery_schedule "
                                           "(host_identifier, hostname, name, query, interval, executions, last_executed, denylisted, output_size, wall_time, wall_time_ms, last_wall_time_ms, user_time, last_user_time, system_time, last_system_time, average_memory, last_memory)"
                                           "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)";
    prepared_queries["etc_hosts"] = "insert into etc_hosts "
                                    "(host_identifier, hostname, unixTime, address, hostnames, pid_with_namespace)"
                                    "values ($1, $2, $3, $4, $5, $6)";
    prepared_queries["uptime"] = "insert into uptime "
                                 "(host_identifier, hostname, unixTime, days, hours, minutes, seconds, total_seconds)"
                                 "values ($1, $2, $3, $4, $5, $6, $7, $8)";
    prepared_queries["startup_items"] = "insert into startup_items "
                                        "(host_identifier, hostname, unixTime, name, path, args, type, source, status, username)"
                                        "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
    prepared_queries["patches"] = "insert into patches "
                                  "(host_identifier, hostname, unixTime, csname, hotfix_id, caption, description, fix_comments, installed_by, install_date, installed_on)"
                                  "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
    prepared_queries["processes32"] = "insert into processes "
                                      "(host_identifier, hostname, unixTime, pid, name, path, cmdline, state, cwd, root, uid, gid, egid, suid, sgid, on_disk, wired_size, resident_size, total_size, user_time, system_time, disk_bytes_read, disk_bytes_written, start_time, parent, pgroup, threads, nice, elevated_token, secure_process, protection_type, virtual_process, elapsed_time, handle_count, percent_processor_time)"
                                      "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35)";
    prepared_queries["programs"] = "insert into programs "
                                   "(host_identifier, hostname, unixTime, name, version, install_location, install_source, language, publisher, uninstall_string, install_date, identifying_number)"
                                   "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    // prepared_queries["common_result_add"] = "insert into common_result "
    //                                         "(host_identifier, hostname, unixTime, query_name, query, query_result) "
    //                                         "values ($1, $2, $3, $4, $5, $6)"; // This table is for getting the results of different tables from osquery and dump it in quert_result column
    prepared_queries["kernel_info"] = "insert into kernel_info "
                                      "(host_identifier, hostname, unixTime, version, arguments, path, device)"
                                      "values ($1, $2, $3, $4, $5, $6, $7)";
    prepared_queries["deb_packages"] = "insert into deb_packages "
                                       "(host_identifier, hostname, unixTime, name, version, source, size, arch, revision, status, maintainer, section, priority, admindir, pid_with_namespace, mount_namespace_id, sanitized_name, sanitized_version, major_release_version)"
                                       "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)";
    prepared_queries["rpm_packages"] = "insert into rpm_packages "
                                       "(host_identifier, hostname, unixTime, name, version, release, source, size, sha1, arch, epoch, install_time, vendor, package_group, pid_with_namespace, mount_namespace_id)"
                                       "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
    prepared_queries["chocolatey_packages"] = "insert into chocolatey_packages "
                                              "(host_identifier, hostname, unixTime, name, version, summary, author, license, path)"
                                              "values ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
    prepared_queries["interface_details"] = "insert into interface_details "
                                            "(host_identifier, hostname, unixTime, interface, mac, type, mtu, metric, flags, ipackets, opackets, ibytes, obytes, ierrors, oerrors, idrops, odrops, collisions, last_change, link_speed, pci_slot, friendly_name, description, manufacturer, connection_id, connection_status, enabled, physical_adapter, speed, service, dhcp_enabled, dhcp_lease_expires, dhcp_lease_obtained, dhcp_server, dns_domain, dns_domain_suffix_search_order, dns_host_name, dns_server_search_order)"
                                            "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)";
    prepared_queries["ie_extensions"] = "insert into ie_extensions "
                                        "(host_identifier, hostname, unixtime, name, registry_path, version, path)"
                                        "values ($1, $2, $3, $4, $5, $6, $7)";
    prepared_queries["firefox_addons"] = "insert into firefox_addons "
                                         "(host_identifier, hostname, unixTime, uid, name, identifier, creator, type, version, description, source_url, visible, active, disabled, autoupdate, location, path)"
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)";
    prepared_queries["npm_packages"] = "insert into npm_packages "
                                       "(host_identifier, hostname, unixTime, name, version, description, author, license, homepage, path, directory, pid_with_namespace, mount_namespace_id)"
                                       "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
    prepared_queries["portage_packages"] = "insert into portage_packages "
                                           "(host_identifier, hostname, unixTime, package, version, slot, build_time, repository, eapi, size, world)"
                                           "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
    prepared_queries["vajra_winprograms"] = "insert into vajra_winprograms "
                                            "(host_identifier, hostname, unixTime, name, version, install_location, publisher)"
                                            "values ($1, $2, $3, $4, $5, $6, $7)";
    prepared_queries["win_event_log_data"] = "insert into win_event_log_data "
                                         "(host_identifier, unixTime, time, datetime, source, provider_name, provider_guid, eventid, task, level, keywords, data) "
                                         "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
    prepared_queries["windows_eventlog"] = "INSERT INTO windows_eventlog "
                                           "(host_identifier, hostname, unixTime, channel, datetime, task, level, "
                                           "provider_name, provider_guid, computer_name, eventid, keywords, data, "
                                           "pid, tid, time_range, timestamp, xpath) "
                                           "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)";


    prepared_queries["registry"] = "insert into registry "
                                   "(host_identifier, hostname, unixTime, key, path, name, type, data, mtime, is_processed)"
                                   "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'f')";
    prepared_queries["etc_services"] = "insert into etc_services "
                                       "(host_identifier, hostname, unixTime, name, port, protocol, aliases, comment, is_processed)"
                                       "values ($1, $2, $3, $4, $5, $6, $7, $8, 'f')";
    prepared_queries["win_registry_events"] = "insert into win_registry_events "
                                       "(host_identifier, hostname, unixTime, action, eid, process_guid, process_name, target_name, target_new_name, value_type, value_data, owner_uid, utc_time,time, pid, eventid, is_processed)"
                                       "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'f')";
    prepared_queries["connectivity"] = "INSERT INTO connectivity (host_identifier, unixTime, disconnected, ipv4_no_traffic, ipv6_no_traffic, ipv4_subnet, ipv4_local_network, ipv4_internet, ipv6_subnet, ipv6_local_network, ipv6_internet) "
                                       "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
    prepared_queries["windows_security_products"] = "INSERT INTO windows_security_products "
                                                 "(host_identifier, unixTime, type, name, state, state_timestamp, "
                                                 "remediation_path, signatures_up_to_date) "
                                                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
    prepared_queries["wmi_bios_info"] = "INSERT INTO wmi_bios_info "
                                    "(host_identifier, unixTime, name, value) "
                                    "VALUES ($1, $2, $3, $4)";
    prepared_queries["windows_firewall_rules"] = "INSERT INTO windows_firewall_rules "
                                                 "(host_identifier, unixTime, name, app_name, action, enabled, grouping, "
                                                 "direction, protocol, local_addresses, remote_addresses, local_ports, "
                                                 "remote_ports, icmp_types_codes, profile_domain, profile_private, "
                                                 "profile_public, service_name) "
                                                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)";
    prepared_queries["windows_security_center"] = "INSERT INTO windows_security_center "
                                                  "(host_identifier, unixTime, firewall, autoupdate, antivirus, "
                                                  "antispyware, internet_settings, windows_security_center_service, "
                                                  "user_account_control) "
                                                  "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
    prepared_queries["windows_update_history"] = "INSERT INTO windows_update_history "
                                                 "(host_identifier, unixTime, client_app_id, date, description, "
                                                 "hresult, operation, result_code, server_selection, service_id, "
                                                 "support_url, title, update_id, update_revision) "
                                                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)";
    prepared_queries["secureboot"] = "INSERT INTO secureboot "
                                     "(host_identifier, unixTime, secure_boot, setup_mode) "
                                     "VALUES ($1, $2, $3, $4)";
    prepared_queries["security_profile_info"] = "INSERT INTO security_profile_info "
                                                "(host_identifier, unixTime, minimum_password_age, maximum_password_age, "
                                                "minimum_password_length, password_complexity, password_history_size, "
                                                "lockout_bad_count, logon_to_change_password, force_logoff_when_expire, "
                                                "new_administrator_name, new_guest_name, clear_text_password, "
                                                "lsa_anonymous_name_lookup, enable_admin_account, enable_guest_account, "
                                                "audit_system_events, audit_logon_events, audit_object_access, "
                                                "audit_privilege_use, audit_policy_change, audit_account_manage, "
                                                "audit_process_tracking, audit_ds_access, audit_account_logon) "
                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)";
    prepared_queries["system_info"] = "INSERT INTO system_info "
                                      "(host_identifier, unixTime, hostname, uuid, cpu_type, cpu_subtype, cpu_brand, "
                                      "cpu_physical_cores, cpu_logical_cores, cpu_sockets, cpu_microcode, "
                                      "physical_memory, hardware_vendor, hardware_model, hardware_version, "
                                      "hardware_serial, board_vendor, board_model, board_version, board_serial, "
                                      "computer_name, local_hostname) "
                                      "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)";
    prepared_queries["tpm_info"] = "INSERT INTO tpm_info "
                                   "(host_identifier, unixTime, activated, enabled, owned, manufacturer_version, "
                                   "manufacturer_id, manufacturer_name, product_name, physical_presence_version, "
                                   "spec_version) "
                                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
    prepared_queries["disk_info"] = "INSERT INTO disk_info "
                                    "(host_identifier, unixTime, partitions, disk_index, type, disk_id, pnp_device_id, "
                                    "disk_size, manufacturer, hardware_model, name, serial, description) "
                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
    prepared_queries["disk_encryption"] = "INSERT INTO disk_encryption "
                                          "(host_identifier, unixTime, name, uuid, encrypted, type, "
                                          "encryption_status, uid, user_uuid, filevault_status) "
                                          "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
    prepared_queries["memory_devices"] = "INSERT INTO memory_devices "
                                         "(host_identifier, unixTime, handle, array_handle, form_factor, "
                                         "total_width, data_width, size, set_field, device_locator, bank_locator, "
                                         "memory_type, memory_type_details, max_speed, configured_clock_speed, "
                                         "manufacturer, serial_number, asset_tag, part_number, "
                                         "min_voltage, max_voltage, configured_voltage) "
                                         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)";
    prepared_queries["mounts"] = "INSERT INTO mounts "
                                 "(host_identifier, unixTime, device, device_alias, path, type, "
                                 "blocks_size, blocks, blocks_free, blocks_available, inodes, inodes_free, flags) "
                                 "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
    prepared_queries["bitlocker_info"] = "INSERT INTO bitlocker_info "
                                         "(host_identifier, unixTime, device_id, drive_letter, persistent_volume_id, "
                                         "conversion_status, protection_status, encryption_method, "
                                         "version, percentage_encrypted, lock_status) "
                                         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
    prepared_queries["logical_drives"] = "INSERT INTO logical_drives "
                                         "(host_identifier, unixTime, device_id, type, description, "
                                         "free_space, size, file_system, boot_partition) "
                                         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
    prepared_queries["get_scheduled_query"] = "select * from query_queue where host_identifier = $1 and sent = false";
    prepared_queries["stop_scheduled_query"] = "update query_queue set sent = true, send_time = $2 where id = $1";

    // Enroll path. Previously prepared/unprepared per request inside the
    // handler, which polluted pooled connections whenever an exception
    // skipped the unprepare.
    prepared_queries["check_existing_node"] = "SELECT * FROM nodes WHERE host_identifier = $1";
    prepared_queries["count_active_nodes"] = "SELECT COUNT(*) FROM nodes WHERE status = 'ACTIVE' OR status IS NULL";
    prepared_queries["check_key_exists"] = "SELECT 1 FROM nodes WHERE node_key = $1 UNION "
                                           "SELECT 1 FROM revoked_node_keys WHERE node_key = $1";
    prepared_queries["update_node_reenroll"] = "UPDATE nodes SET node_key = $1, node_key_expires_at = $2, last_seen = $3, "
                                               "status = 'ACTIVE', consecutive_failures = 0, config_id = $5, codename = $6, address = $7 "
                                               "WHERE host_identifier = $4";
    prepared_queries["host_add"] = "INSERT INTO nodes (host_identifier, os_arch, os_build, os_major, os_minor, os_name, os_platform, "
                                   "osquery_version, node_key, node_invalid, reenroll_allowed, config_id, hardware_vendor, hardware_model, "
                                   "hardware_version, hostname, hardware_cpu_logical_core, hardware_cpu_type, hardware_physical_memory, "
                                   "enrolled_on, last_seen, isolated, original_hostname, agent_online, status, node_key_expires_at, device_group, codename, address) "
                                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)";
    prepared_queries["queue_initial_snapshot"] = "INSERT INTO query_queue (host_identifier, query, sent, send_time) VALUES ($1, $2, false, 0)";

    // /config /log /read /write hot paths (same per-request churn removed)
    prepared_queries["config_ids"] = "select config_id from nodes where node_key = $1";
    prepared_queries["config_queries_bulk"] = "select id, query from config_queries where id = any($1::int[])";
    // Debounced: skip the write (and its WAL/tuple-churn cost) when the existing
    // last_seen is still fresh. A stale-or-null row still updates unconditionally.
    prepared_queries["update_last_seen"] = "update nodes set last_seen = $1 where host_identifier = $2 "
                                            "and (last_seen is null or last_seen < $1 - 30)";
    prepared_queries["get_hostname"] = "select hostname from nodes where node_key = $1";

    ConfigurationParser config_parser("config.json");
    if (!config_parser.parse())
    {
        BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "Cannot read configuration";
        return -1;
    }

    FleetServerConfiguration fleet = config_parser.GetFleetConfiguration();
    enrollment_secret = fleet.node.enrollment_secret;
    global_node_config = fleet.node;  // Store global node configuration
    LogConfiguration log_config = config_parser.GetLogConfiguration("fleet");

    std::filesystem::path log_path = std::filesystem::path(log_config.log_directory) / log_config.log_file;

    init_logging(log_path.string(), log_config.log_level, log_config.log_size, log_config.console_output);
    // init_logging();

    // Keys not yet surfaced by ConfigurationParser structs are read from the
    // raw config with safe defaults: an absent key must never be fatal.
    unsigned int max_concurrent_sessions = 2048;
    unsigned int handshake_timeout_seconds = 10;
    unsigned int socket_io_timeout_seconds = 60;
    unsigned int pool_wait_timeout_ms = 5000;
    int kafka_queue_full_retries = 2;
    int kafka_queue_full_retry_wait_ms = 100;
    int kafka_circuit_breaker_cooldown_ms = 2000;
    std::uint64_t max_request_body_bytes = 16ULL * 1024 * 1024;
    unsigned int max_session_seconds = 300;
    unsigned int max_session_requests = 10000;
    try
    {
        std::ifstream raw_config_file("config.json");
        nlohmann::json raw_config = nlohmann::json::parse(raw_config_file);
        nlohmann::json fleet_json = raw_config.value("fleet_server", nlohmann::json::object());
        nlohmann::json server_json = fleet_json.value("server_configuration", nlohmann::json::object());
        max_concurrent_sessions = server_json.value("max_concurrent_sessions", max_concurrent_sessions);
        handshake_timeout_seconds = server_json.value("handshake_timeout_seconds", handshake_timeout_seconds);
        socket_io_timeout_seconds = server_json.value("socket_io_timeout_seconds", socket_io_timeout_seconds);
        max_request_body_bytes = server_json.value("max_request_body_bytes", max_request_body_bytes);
        max_session_seconds = server_json.value("max_session_seconds", max_session_seconds);
        max_session_requests = server_json.value("max_session_requests", max_session_requests);
        nlohmann::json node_json = fleet_json.value("node_configuration", nlohmann::json::object());
        health_api_token = node_json.value("health_api_token", std::string());
        nlohmann::json pool_json = fleet_json.value("db_pool_configuration", nlohmann::json::object());
        pool_wait_timeout_ms = pool_json.value("wait_timeout_ms", pool_wait_timeout_ms);
        nlohmann::json kafka_json = fleet_json.value("kafka_producer", nlohmann::json::object());
        kafka_queue_full_retries = kafka_json.value("queue_full_retries", kafka_queue_full_retries);
        kafka_queue_full_retry_wait_ms = kafka_json.value("queue_full_retry_wait_ms", kafka_queue_full_retry_wait_ms);
        kafka_circuit_breaker_cooldown_ms = kafka_json.value("circuit_breaker_cooldown_ms", kafka_circuit_breaker_cooldown_ms);
    }
    catch (const std::exception &e)
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Optional config keys unavailable, using defaults: " << e.what();
    }

    // Initialize Kafka producer for real-time event streaming
    if (fleet.kafka_producer.enabled)
    {
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Initializing Kafka producer for real-time EDR event streaming";

        auto& kafka_producer = KafkaProducerManager::getInstance();
        bool kafka_init_success = kafka_producer.initialize(
            fleet.kafka_producer.bootstrap_servers,
            fleet.kafka_producer.client_id,
            kafka_queue_full_retries,
            kafka_queue_full_retry_wait_ms,
            kafka_circuit_breaker_cooldown_ms
        );
        
        if (kafka_init_success)
        {
            BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Kafka producer initialized successfully"
                                    << " - bootstrap servers: " << fleet.kafka_producer.bootstrap_servers
                                    << " - EDR dual-write mode: PostgreSQL (forensics) + Kafka (real-time)";
        }
        else
        {
            BOOST_LOG_TRIVIAL(error) << __SRCREF__ << "Failed to initialize Kafka producer"
                                     << " - Real-time alerts DISABLED, events will only be stored in database";
        }
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << __SRCREF__ << "Kafka producer is DISABLED in configuration"
                                   << " - Events will only be stored in PostgreSQL (no real-time streaming)";
    }

    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Starting connection pool";
    std::shared_ptr<ConnectionPool> connection_pool(new ConnectionPool(fleet.database.ConnectionString(), fleet.database_pool.maximum_connections, std::move(prepared_queries)));
    connection_pool->SetWaitTimeout(std::chrono::milliseconds(pool_wait_timeout_ms));

    RequestRouter router;
    router["/enroll"].post([connection_pool](const HTTPMessage &req) -> HTTPMessage
                           {
                                ConnectionGuard guard(connection_pool);
                                return enroll(req, guard.get()); });
    router["/config"].post([connection_pool](const HTTPMessage &req) -> HTTPMessage
                           {
                                ConnectionGuard guard(connection_pool);
                                return config(req, guard.get()); });
    router["/log"].post([connection_pool](const HTTPMessage &req) -> HTTPMessage
                        {
                                ConnectionGuard guard(connection_pool);
                                return logger(req, guard.get()); });
    router["/read"].post([connection_pool](const HTTPMessage &req) -> HTTPMessage
                         {
                                ConnectionGuard guard(connection_pool);
                                return distributed_read(req, guard.get()); });
    router["/write"].post([connection_pool](const HTTPMessage &req) -> HTTPMessage
                          {
                                ConnectionGuard guard(connection_pool);
                                return distributed_write(req, guard.get()); });
    
    // Health monitoring endpoints.
    // /health is pure liveness and never queries the DB, so it must NOT take a
    // pool slot — otherwise pool exhaustion would make a healthy process report
    // 503 and an orchestrator/LB would drain or kill it during a DB-pressure event.
    router["/health"].get([](const HTTPMessage &req) -> HTTPMessage
                         {
                                return health_check(req, nullptr); });
    // /health/deadletter: reject unauthorized callers BEFORE checking out a
    // connection, so unauthenticated floods cannot contend for pool slots that
    // live ingestion needs. The handler re-checks auth internally as well.
    router["/health/deadletter"].get([connection_pool](const HTTPMessage &req) -> HTTPMessage
                                     {
                                if (!health_deadletter_authorized(req)) {
                                    HTTPMessage forbidden;
                                    forbidden.status = boost::beast::http::status::forbidden;
                                    forbidden.body = "{\"error\":\"forbidden\"}";
                                    forbidden.header["Content-Type"] = "application/json";
                                    return forbidden;
                                }
                                ConnectionGuard guard(connection_pool);
                                return dead_letter_queue(req, guard.get()); });

    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Initializing fleet HTTPS server";
    WebServer server(std::move(router), fleet.server.hostname, fleet.server.port);
    server.setTlsCertificates(fleet.ssl_configuration.ssl_certificate_file, fleet.ssl_configuration.ssl_private_key_file,
                              fleet.ssl_configuration.diffie_hellman_key_file, fleet.ssl_configuration.ssl_password);
    server.setSessionLimit(max_concurrent_sessions);
    server.setSocketTimeouts(handshake_timeout_seconds, socket_io_timeout_seconds);
    server.setRequestBodyLimit(max_request_body_bytes);
    server.setSessionDeadline(max_session_seconds, max_session_requests);

    BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Fleet server initialization complete. Starting server";
    server.run();
    
    // Graceful shutdown: flush Kafka producer before exit
    if (fleet.kafka_producer.enabled)
    {
        BOOST_LOG_TRIVIAL(info) << __SRCREF__ << "Shutting down Kafka producer...";
        auto& kafka_producer = KafkaProducerManager::getInstance();
        kafka_producer.shutdown();
    }

    return 0;
  }
  catch (const std::exception& e)
  {
      BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "fleet_main: fatal: " << e.what();
      return 1;
  }
  catch (...)
  {
      BOOST_LOG_TRIVIAL(fatal) << __SRCREF__ << "fleet_main: fatal: unknown exception";
      return 1;
  }
}
