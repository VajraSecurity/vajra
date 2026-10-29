#include "vajra_engine/BuiltinRules.h"

namespace vajra_engine {

std::vector<Rule> builtin_rules() {
    std::vector<Rule> rules;

    // 100: anchor -- a shell spawned to run an inline "-c" command. Very
    // common and not inherently malicious (IDE integrations, cron, package
    // managers all do this), hence no_log: it exists purely so rule 101 can
    // chain off it via if_sid.
    rules.push_back(Rule{
        .id = 100,
        .level = 3,
        .description = "Shell invoked with an inline command",
        .groups = {"execution"},
        .mitre = {"T1059"},
        .event_type = "bpf_process",
        .os = "",
        .if_sid = std::nullopt,
        .no_log = true,
        .conditions = {FieldCondition{.field = "process.command_line",
                                       .op = FieldCondition::Op::contains,
                                       .value = "sh -c",
                                       .icase = false,
                                       .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    // 101: chained off 100 -- the inline command pipes a network download
    // (curl/wget) into a shell.
    rules.push_back(Rule{
        .id = 101,
        .level = 10,
        .description = "Shell command pipes a network download into execution",
        .groups = {"execution", "command_and_control"},
        .mitre = {"T1059", "T1105"},
        .event_type = "bpf_process",
        .os = "",
        .if_sid = 100,
        .no_log = false,
        .conditions = {FieldCondition{.field = "process.command_line",
                                       .op = FieldCondition::Op::regex,
                                       .value = R"((curl|wget)\s[^|]*\|\s*(sh|bash))",
                                       .icase = true,
                                       .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    // 110: classic Linux reverse-shell one-liners.
    rules.push_back(Rule{
        .id = 110,
        .level = 12,
        .description = "Possible reverse shell",
        .groups = {"command_and_control"},
        .mitre = {"T1059", "T1071"},
        .event_type = "bpf_process",
        .os = "",
        .if_sid = std::nullopt,
        .no_log = false,
        .conditions = {FieldCondition{
            .field = "process.command_line",
            .op = FieldCondition::Op::regex,
            .value = R"((bash\s+-i\s+>&\s*/dev/tcp/|nc\s+-e\s+/bin/(ba)?sh|/bin/(ba)?sh\s+-i\s))",
            .icase = false,
            .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    // 200: Windows PowerShell with an encoded (base64) command -- a common
    // obfuscation technique.
    rules.push_back(Rule{
        .id = 200,
        .level = 10,
        .description = "PowerShell executed with an encoded command",
        .groups = {"execution", "defense_evasion"},
        .mitre = {"T1059.001", "T1027"},
        .event_type = "win_process",
        .os = "windows",
        .if_sid = std::nullopt,
        .no_log = false,
        .conditions = {FieldCondition{.field = "process.command_line",
                                       .op = FieldCondition::Op::regex,
                                       .value = R"(-enc(odedcommand)?\s)",
                                       .icase = true,
                                       .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    // 210: Windows LOLBins (mshta/regsvr32) fetching remote content -- a
    // common living-off-the-land download-and-execute pattern.
    rules.push_back(Rule{
        .id = 210,
        .level = 10,
        .description = "LOLBin (mshta/regsvr32) fetching remote content",
        .groups = {"execution", "defense_evasion"},
        .mitre = {"T1218"},
        .event_type = "win_process",
        .os = "windows",
        .if_sid = std::nullopt,
        .no_log = false,
        .conditions = {FieldCondition{.field = "process.command_line",
                                       .op = FieldCondition::Op::regex,
                                       .value = R"((mshta|regsvr32)(\.exe)?\s[^\s]*https?://)",
                                       .icase = true,
                                       .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    // 300: connection to a deny-listed IP. Fires for any event carrying
    // network.remote_address (bpf_socket, win_socket, win_dns*, win_ssl,
    // win_http), independent of OS-specific event_type. The "deny_ips" list
    // starts empty -- populate via a ruleset's "lists" section, or (once
    // built) the threat-intel/IOC feed refresh.
    rules.push_back(Rule{
        .id = 300,
        .level = 8,
        .description = "Connection to a deny-listed IP",
        .groups = {"command_and_control"},
        .mitre = {"T1071"},
        .event_type = "",
        .os = "",
        .if_sid = std::nullopt,
        .no_log = false,
        .conditions = {FieldCondition{.field = "network.remote_address",
                                       .op = FieldCondition::Op::in_list,
                                       .value = "deny_ips",
                                       .icase = false,
                                       .compiled = nullptr}},
        .enabled = true,
        .event_types = {},
        .frequency = 0,
        .timeframe_seconds = 0,
        .same_field = "",
        .if_matched_sid = {},
    });

    return rules;
}

}  // namespace vajra_engine
