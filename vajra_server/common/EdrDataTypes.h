#ifndef FLEET_EDRDATATYPES_H
#define FLEET_EDRDATATYPES_H

#include "../3rdparty/json.hpp"

#include <string>
#include <vector>

struct ProcessEntry
{
    int port, success,threads, nice, virtual_process, on_disk, hashed, cid, duration, is_container_process, eid, container_age, probe_error, eventid, persistent, block_size, hard_links, symlink, pid_with_namespace, local_port, remote_port, protocol;
    long auid, elapsed_time,handle_count,percent_processor_time,elevated_token, secure_process, disk_bytes_read, disk_bytes_written, start_time, pgroup, total_size, user_time, system_time, wired_size, resident_size, egid, suid, sgid, inode, pid, ppid, parent, device, size, atime, mtime, ctime, btime;
    long long tid, uid, gid, unixtime, event_time, user_id, effective_user_id, root_pid, uptime, group_id, event_id, effective_group_id, owner_user_id, owner_group_id, referenced, install_timestamp, timestamp, time;
    std::string source, value_data,value_type,target_new_name,target_name,terminal, address, message, _protocol, comment, aliases, key, status, socket, protection_type, root, mount_namespace_id, attributes, volume_serial, file_id, file_version, product_version, original_filename, bsd_flags,type, mode, filename,directory,
    name, profile, profile_path, referenced_identifier, identifier, version, description, default_locale, current_locale, update_url, author, permissions,optional_permissions, manifest_hash, from_webstore,
    state, install_time, ext_key, browser_type, target_path, family, process_name, parent_path, process_guid, action, parent_process_guid, channel, xpath, datetime, provider_name, level, provider_guid, computer_name, data, task,
    fd, path, cmdline, cwd, syscall, file_path, flags, local_address, json_cmdline, remote_address, exit_code, ntime, md5, keywords, sha1, sha256, time_range, container_name, owner_uid, event_type, host_identifier, hostname;

    ProcessEntry();     
};

struct BpfProcessEntry
{
    int protocol, local_port, remote_port, family;
    long pid, ppid;
    long long tid, uid, gid, cid, probe_error, duration, time, eid, is_container_process, container_age, type, timestamp, uptime, parent, root_pid;
    std::string cmdline, exit_code, syscall, path, cwd, md5, sha1, sha256,
        container_name, ntime, json_cmdline, fd, local_address, remote_address, file_path, hostname, flags, host_identifier, event_type;

    BpfProcessEntry();
};
struct WinProcessEntry
{  
    int eventid, hashed,  protocol, local_port, remote_port;
    long long unixtime, pid, ppid, event_time, tid, gid, cid, probe_error, time, is_container_process, container_age, type, timestamp, uptime, parent, root_pid;
    std::string family, eid, action, process_guid, parent_process_guid, parent_path, owner_uid, utc_time, command_line, exit_code, current_working_directory, syscall, path, cwd, cmdline, md5, sha1, sha256,
        container_name, ntime, json_cmdline, fd, local_address, remote_address, file_path, hostname, flags, host_identifier, event_type, process_name, target_path, uid, pe_file;

    WinProcessEntry();
};


struct ProcessEvent
{
    ProcessEntry entry;
    std::vector<ProcessEntry> parents;

    ProcessEvent();
};

struct WinProcessEvent
{
    WinProcessEntry entry;
    std::vector<WinProcessEntry> parents;

    WinProcessEvent();
};

enum FileAccessPermissionType
{
    OPEN_PERMISSION,
    EXEC_PERMISSION
};

struct BlockingEvent
{
    int pid, fd;
    std::string file_path;
    FileAccessPermissionType permission_requested;
    ProcessEntry entry;
    std::vector<ProcessEntry> parents;

    BlockingEvent();
};

struct BlockingResponse
{
    BlockingEvent event;
    bool wasBlocked;
    std::string reason;
    std::string metadata;

    BlockingResponse();
};

enum SeverityLevel
{
    Information,
    Low,
    Medium,
    High,
    Critical
};

enum RemediationPolicy
{
    Allow,
    Deny,
    Log
};

struct Event
{
    std::string code;
    std::string metadata;
    SeverityLevel severity;
    bool isAlert;

    Event();
};

inline BlockingResponse::BlockingResponse()
{
    wasBlocked = false;
}

inline BlockingEvent::BlockingEvent()
{
    permission_requested = FileAccessPermissionType::OPEN_PERMISSION;
    pid = 0;
    fd = -1;
}

inline ProcessEvent::ProcessEvent()
{
    entry.pid = 0;
    entry.ppid = 0;
    entry.path = "";
    entry.cmdline = "";
    entry.cwd = "";
    entry.syscall = "";
    entry.parent = 0;
    entry.root_pid = 0;
}
inline WinProcessEvent::WinProcessEvent()
{
    entry.pid = 0;
    entry.ppid = 0;
    entry.path = "";
    entry.command_line = "";
    entry.current_working_directory = "";
    entry.syscall = "";
    entry.parent = 0;
    entry.root_pid = 0;
}

inline ProcessEntry::ProcessEntry()
{
    pid = 0;
    ppid = 0;
    parent = 0;
    event_time = -1;
    user_id = -1;
    group_id = -1;
    effective_group_id = -1;
    effective_user_id = -1;
    owner_user_id = -1;
    owner_group_id = -1;
    path = "";
    cmdline = "";
    cwd = "";
    syscall = "";
    event_id = -1;
    file_path = "";
    flags = "";
    eventid = 0;
    root_pid = 0;
}

inline BpfProcessEntry::BpfProcessEntry()
{
    pid = 0;
    ppid = 0;
    tid = -1,
    uid = -1,
    gid = -1,
    cid = -1,
    probe_error = -1,
    duration = -1,
    time = -1,
    eid = -1,
    is_container_process = -1,
    container_age = -1,
    path = "",
    cmdline = "",
    exit_code = "",
    cwd = "",
    syscall = "",
    path = "",
    cwd = "",
    cmdline = "",
    md5 = "",
    sha1 = "",
    sha256 = "",
    container_name = "",
    ntime = "",
    json_cmdline = "",
    file_path = "",
    hostname ="",
    flags = "",
    event_type = "",
    remote_address = "",
    local_address = "",
    local_port = -1,
    remote_port = -1,
    protocol = -1;
    root_pid = 0;
}
inline WinProcessEntry::WinProcessEntry()
{
    pid = 0;
    ppid = 0;
    tid = -1,
    uid = -1,
    gid = -1,
    cid = -1,
    action = "",
    process_guid = "",
    parent_process_guid = "",
    parent_path = "",
    owner_uid = "",
    utc_time = "",
    probe_error = -1,
    time = -1,
    eid = -1,
    is_container_process = -1,
    container_age = -1,
    path = "",
    command_line = "",
    exit_code = "",
    current_working_directory = "",
    syscall = "",
    path = "",
    cwd = "",
    cmdline = "",
    md5 = "",
    sha1 = "",
    sha256 = "",
    container_name = "",
    ntime = "",
    json_cmdline = "",
    file_path = "",
    hostname ="",
    flags = "",
    event_type = "";
    remote_address = "",
    local_address = "",
    local_port = -1,
    remote_port = -1,
    protocol = -1;
    root_pid = 0;
}

inline Event::Event()
{
    this->severity = SeverityLevel::Information;
    this->isAlert = false;
}

inline nlohmann::json ProcessEntryListToJson(std::vector<ProcessEntry> list)
{
    nlohmann::json j = nlohmann::json::array();

    for (auto &entry : list)
    {
        nlohmann::json obj;
        obj["pid"] = entry.pid;
        obj["path"] = entry.path;
        obj["cmdline"] = entry.cmdline;
        obj["cwd"] = entry.cwd;
        obj["ppid"] = entry.ppid;
        obj["parent"] = entry.parent;
        obj["syscall"] = entry.syscall;
        obj["event_time"] = entry.event_time;
        obj["user_id"] = entry.user_id;
        obj["group_id"] = entry.group_id;
        obj["effective_gid"] = entry.effective_group_id;
        obj["effective_uid"] = entry.effective_user_id;
        obj["owner_uid"] = entry.owner_user_id;
        obj["owner_gid"] = entry.owner_group_id;
        obj["root_pid"] = entry.root_pid;

        j.push_back(obj);
    }

    return j;
}

inline nlohmann::json BPFProcessEntryListToJson(std::vector<BpfProcessEntry> list)
{
    nlohmann::json j = nlohmann::json::array();

    for (auto &entry : list)
    {
        nlohmann::json obj;
        obj["pid"] = entry.pid;
        obj["parent"] = entry.ppid;
        obj["tid"] = entry.tid;
        obj["uid"] = entry.uid;
        obj["gid"] = entry.gid;
        obj["cid"] = entry.cid;
        obj["exit_code"] = entry.exit_code;
        obj["probe_error"] = entry.probe_error;
        obj["syscall"] = entry.syscall;
        obj["path"] = entry.path;
        obj["cwd"] = entry.cwd;
        obj["cmdline"] = entry.cmdline;
        obj["duration"] = entry.duration;
        obj["json_cmdline"] = entry.json_cmdline;
        obj["ntime"] = entry.ntime;
        obj["time"] = entry.time;
        obj["eid"] = entry.eid;
        obj["md5"] = entry.md5;
        obj["sha1"] = entry.sha1;
        obj["sha256"] = entry.sha256;
        obj["is_container_process"] = entry.is_container_process;
        obj["container_age"] = entry.container_age;
        obj["container_name"] = entry.container_name;
        obj["fd"] = entry.fd;
        obj["family"] = entry.family;
        obj["protocol"] = entry.protocol;
        obj["local_address"] = entry.local_address;
        obj["remote_address"] = entry.remote_address;
        obj["local_port"] = entry.local_port;
        obj["remote_port"] = entry.remote_port;
        obj["uptime"] = entry.uptime;
        obj["file_path"] = entry.file_path;
        obj["root_pid"] = entry.root_pid;


        j.push_back(obj);
    }

    return j;
}

inline nlohmann::json WinProcessEntryListToJson(std::vector<WinProcessEntry> list)
{
    nlohmann::json j = nlohmann::json::array();

    for (auto &entry : list)
    {
        // std::cout<<entry.ppid<<std::endl;
        nlohmann::json obj;

        obj["pid"] = entry.pid;
        obj["parent"] = entry.ppid;
        obj["action"] = entry.action;
        obj["process_guid"] = entry.process_guid;
        obj["parent_process_guid"] = entry.parent_process_guid;
        obj["parent_path"] = entry.parent_path;
        obj["owner_uid"] = entry.owner_uid;
        obj["eventid"] = entry.eventid;        
        obj["tid"] = entry.tid;
        // obj["uid"] = entry.uid;
        obj["gid"] = entry.gid;
        obj["cid"] = entry.cid;
        obj["exit_code"] = entry.exit_code;
        obj["probe_error"] = entry.probe_error;
        obj["syscall"] = entry.syscall;
        obj["path"] = entry.path;
        obj["cwd"] = entry.cwd;
        obj["cmdline"] = entry.cmdline;
        obj["json_cmdline"] = entry.json_cmdline;
        obj["ntime"] = entry.ntime;
        obj["time"] = entry.time;
//      obj["eid"] = entry.eid;
        obj["md5"] = entry.md5;
        obj["sha1"] = entry.sha1;
        obj["sha256"] = entry.sha256;
        obj["is_container_process"] = entry.is_container_process;
        obj["container_age"] = entry.container_age;
        obj["container_name"] = entry.container_name;
        obj["fd"] = entry.fd;
        obj["family"] = entry.family;
        obj["protocol"] = entry.protocol;
        obj["local_address"] = entry.local_address;
        obj["remote_address"] = entry.remote_address;
        obj["local_port"] = entry.local_port;
        obj["remote_port"] = entry.remote_port;
        //obj["uptime"] = entry.uptime;
        obj["file_path"] = entry.file_path;
        obj["root_pid"] = entry.root_pid;
//        std::cout << obj["eid"] << std::endl;
        j.push_back(obj);
    }

    return j;
}

inline std::vector<ProcessEntry> JsonToProcessEntryList(nlohmann::json process_tree)
{
    std::vector<ProcessEntry> process_list;

    if (process_tree.is_array())
    {
        for (auto &process : process_tree)
        {
            ProcessEntry entry;
            entry.pid = process.contains("pid") ? process["pid"].get<long>() : 0;
            entry.ppid = process.contains("ppid") ? process["ppid"].get<long>() : 0;
            entry.parent = process.contains("parent") ? process["parent"].get<long>() : 0;
            //entry.parent = process.contains("parent_pid") ? process["parent_pid"].get<long>() : 0;
            entry.event_time = process.contains("event_time") ? process["event_time"].get<long long>() : -1;
            entry.user_id = process.contains("user_id") ? process["user_id"].get<long long>() : -1;
            entry.group_id = process.contains("group_id") ? process["group_id"].get<long long>() : -1;
            // entry.effective_group_id = process.contains("effective_gid") ? process["effective_gid"].get<long long>() : -1;
            // entry.effective_user_id = process.contains("effective_uid") ? process["effective_uid"].get<long long>() : -1;
            //entry.owner_user_id = process.contains("owner_uid") ? process["owner_uid"].get<long long>() : -1;
            //entry.owner_group_id = process.contains("owner_gid") ? process["owner_gid"].get<long long>() : -1;
            entry.path = process.contains("path") ? process["path"].get<std::string>() : "";
            entry.cmdline = process.contains("cmdline") ? process["cmdline"].get<std::string>() : "";
            entry.cwd = process.contains("cwd") ? process["cwd"].get<std::string>() : "";
            entry.syscall = process.contains("syscall") ? process["syscall"].get<std::string>() : "";
            process_list.push_back(entry);
        }
    }

    return process_list;
}

inline std::vector<BpfProcessEntry> JsonToBpfProcessEntryList(nlohmann::json process_tree)
{
    std::vector<BpfProcessEntry> process_list;

    if (process_tree.is_array())
    {
        for (auto &process : process_tree)
        {
            BpfProcessEntry entry;
            entry.pid = process.contains("pid") ? process["pid"].get<long>() : 0;
            entry.ppid = process.contains("parent") ? process["parent"].get<long>() : 0;
            entry.parent = process.contains("parent") ? process["parent"].get<long>() : 0;
            entry.tid = process.contains("tid") ? process["tid"].get<long long>() : 0;
            entry.uid = process.contains("uid") ? process["uid"].get<long long>() : 0;
            entry.probe_error = process.contains("probe_error") ? process["probe_error"].get<long>() : 0;
            entry.uptime = process.contains("uptime") ? process["uptime"].get<long>() : 0;
            entry.local_port = process.contains("local_port") ? process["local_port"].get<int>() : 0;
            entry.remote_port = process.contains("remote_port") ? process["remote_port"].get<long>() : 0;
            entry.family = process.contains("family") ? process["family"].get<long>() : 0;
            entry.path = process.contains("path") ? process["path"].get<std::string>() : "";
            entry.cmdline = process.contains("cmdline") ? process["cmdline"].get<std::string>() : "";
            entry.cwd = process.contains("cwd") ? process["cwd"].get<std::string>() : "";
            entry.syscall = process.contains("syscall") ? process["syscall"].get<std::string>() : "";
            entry.exit_code = process.contains("exit_code") ? process["exit_code"].get<std::string>() : "";
            entry.md5 = process.contains("md5") ? process["md5"].get<std::string>() : "";
            entry.sha1 = process.contains("sha1") ? process["sha1"].get<std::string>() : "";
            entry.sha256 = process.contains("sha256") ? process["sha256"].get<std::string>() : "";
            entry.local_address = process.contains("local_address") ? process["local_address"].get<std::string>() : "";
            entry.remote_address = process.contains("remote_address") ? process["remote_address"].get<std::string>() : "";
            entry.file_path = process.contains("file_path") ? process["file_path"].get<std::string>() : "";
            entry.event_type = process.contains("event_type") ? process["event_type"].get<std::string>() : "";

            
            process_list.push_back(entry);
        }
    }

    return process_list;
}

inline std::vector<WinProcessEntry> JsonToWinProcessEntryList(nlohmann::json process_tree)
{
    std::vector<WinProcessEntry> process_list;

    if (process_tree.is_array())
    {
        for (auto &process : process_tree)
        {
            WinProcessEntry entry;
            entry.pid = process.contains("pid") ? process["pid"].get<long>() : 0;
            entry.ppid = process.contains("parent_pid") ? process["parent_pid"].get<long>() : 0;
            entry.parent = process.contains("parent_pid") ? process["parent_pid"].get<long>() : 0;
            entry.eventid = process.contains("eventid") ? process["eventid"].get<int>() : 0;
            entry.hashed = process.contains("hashed") ? process["hashed"].get<int>() : 0;
            entry.protocol = process.contains("protocol") ? process["protocol"].get<int>() : 0;
            entry.local_port = process.contains("local_port") ? process["local_port"].get<int>() : 0;
            entry.remote_port = process.contains("remote_port") ? process["remote_port"].get<int>() : 0;
            entry.parent = process.contains("parent") ? process["parent"].get<long>() : 0;
            entry.parent = process.contains("parent") ? process["parent"].get<long>() : 0;
            entry.parent = process.contains("parent") ? process["parent"].get<long>() : 0;
            entry.event_time = process.contains("event_time") ? process["event_time"].get<long long>() : -1;
            entry.path = process.contains("path") ? process["path"].get<std::string>() : "";
            entry.command_line = process.contains("command_line") ? process["command_line"].get<std::string>() : "";
            entry.current_working_directory = process.contains("cwd") ? process["cwd"].get<std::string>() : "";
            entry.syscall = process.contains("syscall") ? process["syscall"].get<std::string>() : "";
            entry.family = process.contains("family") ? process["family"].get<std::string>() : "";
            entry.action = process.contains("action") ? process["action"].get<std::string>() : "";
            entry.process_guid = process.contains("process_guid") ? process["process_guid"].get<std::string>() : "";
            entry.parent_process_guid = process.contains("parent_process_guid") ? process["parent_process_guid"].get<std::string>() : "";
            entry.parent_path = process.contains("parent_path") ? process["parent_path"].get<std::string>() : "";
            entry.exit_code = process.contains("exit_code") ? process["exit_code"].get<std::string>() : "";
            entry.local_address = process.contains("local_address") ? process["local_address"].get<std::string>() : "";
            entry.remote_address = process.contains("remote_address") ? process["remote_address"].get<std::string>() : "";
            entry.file_path = process.contains("file_path") ? process["file_path"].get<std::string>() : "";
            entry.process_name = process.contains("process_name") ? process["process_name"].get<std::string>() : "";

            process_list.push_back(entry);
        }
    }

    return process_list;
}

#endif // FLEET_EDRDATATYPES_H