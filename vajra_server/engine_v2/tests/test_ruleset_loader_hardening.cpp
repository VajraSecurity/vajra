// Regression tests for RulesetLoader.cpp hardening added in this review:
//  - a value-requiring op with a missing/null "value" is a RulesetError
//    (previously silently compiled to an always-comparing-to-"" condition)
//  - resource-exhaustion caps on rules/conditions/decoders/captures/
//    ip_watch_groups/lists/list-entries/string-field lengths
//  - a "regex" condition (hand-written or Sigma-parity-op-generated) that's
//    oversized or looks catastrophically backtracking is rejected at load
//    time (RulesetError), not silently accepted
#include "catch2/catch.hpp"

#include "vajra_engine/Decoder.h"
#include "vajra_engine/RuleEngine.h"
#include "vajra_engine/RulesetLoader.h"

using namespace vajra_engine;
using nlohmann::json;

TEST_CASE("A value-requiring op with no 'value' is rejected at load time",
          "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json doc = {
        {"rules",
         {{{"id", 1},
           {"event_type", "bpf_process"},
           {"conditions", {{{"field", "process.command_line"}, {"op", "equals"}}}}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("A value-requiring op with a null 'value' is rejected at load time",
          "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_process"},
                   {"conditions",
                    {{{"field", "process.command_line"}, {"op", "contains"}, {"value", nullptr}}}}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("'exists' does not require a 'value' and still loads/matches",
          "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"level", 5},
                   {"event_type", "bpf_process"},
                   {"conditions", {{{"field", "process.command_line"}, {"op", "exists"}}}}}}}};
    REQUIRE_NOTHROW(load_ruleset(doc, engine));
    CHECK(engine.size() == 1);
}

TEST_CASE("More than the max conditions on one rule is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json conditions = json::array();
    for (int i = 0; i < 201; ++i) {
        conditions.push_back({{"field", "process.command_line"}, {"op", "contains"}, {"value", "x"}});
    }
    json doc = {{"rules", {{{"id", 1}, {"event_type", "bpf_process"}, {"conditions", conditions}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("More than the max number of rules is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json rules = json::array();
    for (int i = 0; i < 10001; ++i) {
        rules.push_back({{"id", i}, {"level", 1}, {"event_type", "bpf_process"}});
    }
    json doc = {{"rules", rules}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("More than the max number of decoders is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    Decoder decoder;
    json decoders = json::array();
    for (int i = 0; i < 5001; ++i) {
        decoders.push_back({{"name", "d" + std::to_string(i)},
                             {"source_field", "process.command_line"},
                             {"extract", "(x)"}});
    }
    json doc = {{"decoders", decoders}};
    CHECK_THROWS_AS(load_ruleset(doc, engine, &decoder), RulesetError);
}

TEST_CASE("More than the max captures on one decoder is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    Decoder decoder;
    json captures = json::array();
    for (int i = 0; i < 65; ++i) captures.push_back("decoded.f" + std::to_string(i));
    json doc = {{"decoders",
                 {{{"name", "d"},
                   {"source_field", "process.command_line"},
                   {"extract", "(a)(b)"},
                   {"captures", captures}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine, &decoder), RulesetError);
}

TEST_CASE("More than the max number of named lists is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json lists = json::object();
    for (int i = 0; i < 5001; ++i) lists["list" + std::to_string(i)] = json::array({"x"});
    json doc = {{"lists", lists}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("More than the max entries in one list is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json members = json::array();
    for (int i = 0; i < 100001; ++i) members.push_back("1.2.3." + std::to_string(i % 256));
    json doc = {{"lists", {{"deny_ips", members}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("More than the max ip_watch_groups entries is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json groups = json::array();
    for (int i = 0; i < 5001; ++i) {
        groups.push_back({{"id", i}, {"name", "g" + std::to_string(i)}});
    }
    json doc = {{"ip_watch_groups", groups}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("A string field beyond the length cap is rejected", "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_process"},
                   {"description", std::string(8193, 'a')}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("A hand-written 'regex' condition that looks catastrophic is rejected at load time",
          "[engine][ruleset_loader][hardening][redos]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_process"},
                   {"conditions",
                    {{{"field", "process.command_line"}, {"op", "regex"}, {"value", "(a+)+$"}}}}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("A hand-written 'regex' condition beyond the pattern-length cap is rejected at load time",
          "[engine][ruleset_loader][hardening][redos]") {
    RuleEngine engine;
    json doc = {{"rules",
                 {{{"id", 1},
                   {"event_type", "bpf_process"},
                   {"conditions",
                    {{{"field", "process.command_line"},
                      {"op", "regex"},
                      {"value", std::string(5000, 'a')}}}}}}}};
    CHECK_THROWS_AS(load_ruleset(doc, engine), RulesetError);
}

TEST_CASE("A well-formed ruleset with every section still loads cleanly (non-regression)",
          "[engine][ruleset_loader][hardening]") {
    RuleEngine engine;
    Decoder decoder;
    json doc = {
        {"lists", {{"deny_ips", {"1.2.3.4"}}}},
        {"rules",
         {{{"id", 1},
           {"level", 8},
           {"event_type", "bpf_socket"},
           {"conditions", {{{"field", "network.remote_address"}, {"op", "in_list"}, {"value", "deny_ips"}}}}}}},
        {"decoders",
         {{{"name", "extract-url"},
           {"source_field", "process.command_line"},
           {"prematch", "https?://"},
           {"extract", "(https?://[^\\s]+)"},
           {"captures", {"decoded.url"}}}}},
        {"ip_watch_groups", {{{"id", 900}, {"name", "finance"}}}},
    };
    REQUIRE_NOTHROW(load_ruleset(doc, engine, &decoder));
    CHECK(engine.size() == 2);  // rule 1 + the synthesized ip_watch_groups rule 900
    CHECK(decoder.decoder_rule_count() == 1);
}
