// New-capability tests for the Sigma-parity operators RulesetLoader.cpp
// adds on top of the existing FieldCondition ops: startswith, endswith,
// cidr, windash_contains, base64offset_contains. Each is implemented as a
// load-time rewrite into the existing 'regex' op (see RulesetLoader.h), so
// these are exercised end-to-end through the real public API
// (load_ruleset + RuleEngine::eval), the same way an operator's ruleset
// file would actually use them.
#include "catch2/catch.hpp"

#include "vajra_engine/RuleEngine.h"
#include "vajra_engine/RulesetLoader.h"

using namespace vajra_engine;
using nlohmann::json;

namespace {
NormalizedEvent make_event(std::string event_type, std::map<std::string, std::string> fields) {
    NormalizedEvent ev;
    ev.event_type = std::move(event_type);
    ev.host_identifier = "h1";
    ev.fields = std::move(fields);
    ev.unix_time = 1000;
    return ev;
}

bool fired(RuleEngine& engine, const NormalizedEvent& ev, int rule_id) {
    for (const auto& m : engine.eval(ev)) {
        if (m.rule_id == rule_id) return true;
    }
    return false;
}

// Small local RFC 4648 base64 encoder used ONLY to build test carrier
// strings (simulating a plaintext substring embedded at an arbitrary byte
// offset inside a longer real base64 blob) -- independent of, and not
// exercising, RulesetLoader.cpp's own base64offset implementation, which is
// instead proven correct by checking the REAL engine (via load_ruleset +
// eval) finds the substring in blobs built here.
std::string test_base64_encode(const std::string& bytes) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 3 <= bytes.size()) {
        auto b0 = static_cast<unsigned char>(bytes[i]);
        auto b1 = static_cast<unsigned char>(bytes[i + 1]);
        auto b2 = static_cast<unsigned char>(bytes[i + 2]);
        out += alphabet[b0 >> 2];
        out += alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        out += alphabet[b2 & 0x3F];
        i += 3;
    }
    const std::size_t remaining = bytes.size() - i;
    if (remaining == 1) {
        auto b0 = static_cast<unsigned char>(bytes[i]);
        out += alphabet[b0 >> 2];
        out += alphabet[(b0 & 0x03) << 4];
        out += "==";
    } else if (remaining == 2) {
        auto b0 = static_cast<unsigned char>(bytes[i]);
        auto b1 = static_cast<unsigned char>(bytes[i + 1]);
        out += alphabet[b0 >> 2];
        out += alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += alphabet[(b1 & 0x0F) << 2];
        out += "=";
    }
    return out;
}
}  // namespace

TEST_CASE("startswith matches only a leading literal, anchored", "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "win_process"},
                   {"conditions",
                    {{{"field", "process.command_line"}, {"op", "startswith"}, {"value", "powershell"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    CHECK(fired(engine, make_event("win_process", {{"process.command_line", "powershell -enc AAAA"}}), 1));
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.command_line", "not-powershell -enc"}}), 1));
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.command_line", "cmd /c powershell"}}), 1));
}

TEST_CASE("endswith matches only a trailing literal, anchored", "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "win_process"},
                   {"conditions",
                    {{{"field", "process.executable"}, {"op", "endswith"}, {"value", ".exe"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    CHECK(fired(engine, make_event("win_process", {{"process.executable", R"(C:\Windows\evil.exe)"}}), 1));
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.executable", R"(C:\Windows\evil.exe.bak)"}}), 1));
}

TEST_CASE("startswith/endswith escape regex metacharacters in the literal",
          "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    // "." must match only a literal dot, not "any character".
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "t"},
                   {"conditions", {{{"field", "f"}, {"op", "startswith"}, {"value", "a.b"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));
    CHECK(fired(engine, make_event("t", {{"f", "a.b-rest"}}), 1));
    CHECK_FALSE(fired(engine, make_event("t", {{"f", "aXb-rest"}}), 1));
}

TEST_CASE("cidr matches IPv4 addresses inside a /24 block only", "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_socket"},
                   {"conditions",
                    {{{"field", "network.remote_address"}, {"op", "cidr"}, {"value", "10.1.2.0/24"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "10.1.2.0"}}), 1));
    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "10.1.2.255"}}), 1));
    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "10.1.2.137"}}), 1));
    CHECK_FALSE(fired(engine, make_event("bpf_socket", {{"network.remote_address", "10.1.3.0"}}), 1));
    CHECK_FALSE(fired(engine, make_event("bpf_socket", {{"network.remote_address", "10.1.1.255"}}), 1));
}

TEST_CASE("cidr correctly handles a non-byte-aligned prefix (/27)", "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    // 192.168.5.32/27 -> host range 192.168.5.32-63
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_socket"},
                   {"conditions",
                    {{{"field", "network.remote_address"}, {"op", "cidr"}, {"value", "192.168.5.32/27"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "192.168.5.32"}}), 1));
    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "192.168.5.63"}}), 1));
    CHECK(fired(engine, make_event("bpf_socket", {{"network.remote_address", "192.168.5.50"}}), 1));
    CHECK_FALSE(fired(engine, make_event("bpf_socket", {{"network.remote_address", "192.168.5.31"}}), 1));
    CHECK_FALSE(fired(engine, make_event("bpf_socket", {{"network.remote_address", "192.168.5.64"}}), 1));
}

TEST_CASE("cidr handles /32 (single host) and /0 (everything)", "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine32;
    json doc32 = {{"rules",
                   {{{"id", 1},
                     {"event_type", "bpf_socket"},
                     {"conditions",
                      {{{"field", "network.remote_address"}, {"op", "cidr"}, {"value", "8.8.8.8/32"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc32, engine32));
    CHECK(fired(engine32, make_event("bpf_socket", {{"network.remote_address", "8.8.8.8"}}), 1));
    CHECK_FALSE(fired(engine32, make_event("bpf_socket", {{"network.remote_address", "8.8.8.9"}}), 1));

    RuleEngine engine0;
    json doc0 = {{"rules",
                  {{{"id", 1},
                    {"event_type", "bpf_socket"},
                    {"conditions",
                     {{{"field", "network.remote_address"}, {"op", "cidr"}, {"value", "0.0.0.0/0"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc0, engine0));
    CHECK(fired(engine0, make_event("bpf_socket", {{"network.remote_address", "1.2.3.4"}}), 1));
    CHECK(fired(engine0, make_event("bpf_socket", {{"network.remote_address", "255.255.255.255"}}), 1));
}

TEST_CASE("cidr rejects malformed values at load time", "[engine][ruleset_loader][expressiveness]") {
    auto rejects = [](const std::string& value) {
        RuleEngine engine;
        json doc = {{"rules",
                     {{{"id", 1},
                       {"event_type", "bpf_socket"},
                       {"conditions",
                        {{{"field", "network.remote_address"}, {"op", "cidr"}, {"value", value}}}}}}}};
        CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
    };
    rejects("not-a-cidr");
    rejects("10.0.0/24");         // only 3 octets
    rejects("10.0.0.0.0/24");     // 5 octets
    rejects("999.0.0.0/24");      // out-of-range octet
    rejects("10.0.0.0/33");       // prefix out of range
    rejects("10.0.0.0/-1");
    rejects("10.0.0.0");          // no prefix at all
}

TEST_CASE("windash_contains matches Windows CLI switch-prefix variants",
          "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "win_process"},
                   {"conditions",
                    {{{"field", "process.command_line"},
                      {"op", "windash_contains"},
                      {"value", "-enc"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    CHECK(fired(engine, make_event("win_process", {{"process.command_line", "powershell -enc AAAA"}}), 1));
    CHECK(fired(engine, make_event("win_process", {{"process.command_line", "powershell /enc AAAA"}}), 1));
    // Adjacent string literal concatenation (not one long \x.. run) is
    // required here: C++ hex escapes greedily consume every following hex
    // digit, and 'e' IS a valid hex digit -- "\xE2\x80\x93enc" would parse
    // as "\xE2\x80\x93e" (a bogus out-of-range escape) + "nc", silently
    // corrupting the intended UTF-8 byte sequence instead of just warning.
    CHECK(fired(engine,
                make_event("win_process", {{"process.command_line", "powershell \xE2\x80\x93" "enc AAAA"}}),
                1));  // en dash
    CHECK(fired(engine,
                make_event("win_process", {{"process.command_line", "powershell \xE2\x80\x94" "enc AAAA"}}),
                1));  // em dash
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.command_line", "powershell encoded stuff"}}), 1));
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.command_line", "totally unrelated"}}), 1));
}

TEST_CASE("windash_contains degrades to a plain literal for a non-dash-prefixed value",
          "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "t"},
                   {"conditions", {{{"field", "f"}, {"op", "windash_contains"}, {"value", "mimikatz"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));
    CHECK(fired(engine, make_event("t", {{"f", "load mimikatz now"}}), 1));
    CHECK_FALSE(fired(engine, make_event("t", {{"f", "nothing interesting"}}), 1));
}

TEST_CASE("base64offset_contains finds a plaintext substring embedded at any byte offset",
          "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    const std::string plaintext = "IEX(New-Object Net.WebClient)";
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "win_process"},
                   {"conditions",
                    {{{"field", "process.command_line"},
                      {"op", "base64offset_contains"},
                      {"value", plaintext}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));

    // Embed `plaintext` at each of the 3 possible byte offsets within a
    // longer, realistic surrounding carrier, base64-encode the WHOLE
    // carrier (simulating how it would really appear inside an encoded
    // PowerShell command line), and confirm the engine finds it regardless
    // of alignment.
    for (int offset = 0; offset <= 2; ++offset) {
        const std::string prefix(static_cast<std::size_t>(offset), 'X');
        const std::string carrier = "$s='" + prefix + plaintext + "';IEX $s";
        const std::string encoded = test_base64_encode(carrier);
        auto ev = make_event("win_process",
                              {{"process.command_line", "powershell -enc " + encoded}});
        INFO("offset=" << offset << " encoded=" << encoded);
        CHECK(fired(engine, ev, 1));
    }

    // A base64 blob that never contains the plaintext at all must not match.
    const std::string unrelated_encoded = test_base64_encode("Get-Process | Where-Object Name -eq notepad");
    CHECK_FALSE(fired(engine, make_event("win_process", {{"process.command_line", unrelated_encoded}}), 1));
}

TEST_CASE("base64offset_contains rejects an empty value at load time",
          "[engine][ruleset_loader][expressiveness]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "t"},
                   {"conditions",
                    {{{"field", "f"}, {"op", "base64offset_contains"}, {"value", ""}}}}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}
