#include "catch2/catch.hpp"

#include <chrono>

#include "../../3rdparty/json.hpp"
#include "vajra_engine/AlertWriter.h"
#include "vajra_engine/BuiltinRules.h"
#include "vajra_engine/CorrelationEngine.h"
#include "vajra_engine/Decoder.h"
#include "vajra_engine/Envelope.h"
#include "vajra_engine/OccurrenceHistory.h"
#include "vajra_engine/RuleEngine.h"

using namespace vajra_engine;

namespace {

NormalizedEvent make_event(std::string event_type, std::map<std::string, std::string> fields,
                            std::string host = "h1") {
    NormalizedEvent ev;
    ev.event_type = std::move(event_type);
    ev.host_identifier = std::move(host);
    ev.fields = std::move(fields);
    return ev;
}

Match make_match(int rule_id, int level = 5, bool no_log = false) {
    Match m;
    m.rule_id = rule_id;
    m.level = level;
    m.description = "test match " + std::to_string(rule_id);
    m.no_log = no_log;
    return m;
}

AlertWriteResult make_result(int rule_id, long long alert_id) {
    AlertWriteResult r;
    r.rule_id = rule_id;
    r.alert_id = alert_id;
    r.newly_inserted = true;
    return r;
}

}  // namespace

// ===========================================================================
// event_count
// ===========================================================================

TEST_CASE("event_count fires only once the threshold is reached, not before", "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 1;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 60;
    rule.threshold = 3;

    CorrelationEngine engine;
    engine.load({rule});
    REQUIRE(engine.rule_count() == 1);

    auto ev = make_event("bpf_process", {});
    auto m = make_match(100);

    auto r1 = engine.ingest(ev, {m}, {make_result(100, 11)}, 1000);
    CHECK(r1.empty());
    auto r2 = engine.ingest(ev, {m}, {make_result(100, 12)}, 2000);
    CHECK(r2.empty());
    auto r3 = engine.ingest(ev, {m}, {make_result(100, 13)}, 3000);
    REQUIRE(r3.size() == 1);
    CHECK(r3[0].correlation_rule_id == 1);
    CHECK(r3[0].contributing.size() == 3);
    CHECK(r3[0].contributing[0].alert_id == 11);
    CHECK(r3[0].contributing[2].alert_id == 13);
}

TEST_CASE("event_count entries older than the timespan are pruned and don't count", "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 2;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 10;  // 10s window
    rule.threshold = 2;

    CorrelationEngine engine;
    engine.load({rule});

    auto ev = make_event("bpf_process", {});
    auto m = make_match(100);

    CHECK(engine.ingest(ev, {m}, {make_result(100, 1)}, 0).empty());
    // 20 seconds later: the first occurrence is outside the 10s window, so
    // this is still only "1 recent occurrence", not 2.
    CHECK(engine.ingest(ev, {m}, {make_result(100, 2)}, 20000).empty());
}

// ===========================================================================
// value_count
// ===========================================================================

TEST_CASE("value_count counts DISTINCT field values, not raw occurrences", "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 3;
    rule.type = CorrelationRule::Type::value_count;
    rule.rule_ids = {200};
    rule.field = "network.remote_address";
    rule.group_by = {"user.name"};
    rule.timespan_seconds = 600;
    rule.threshold = 3;

    CorrelationEngine engine;
    engine.load({rule});

    auto m = make_match(200);
    auto ev_a = make_event("bpf_socket", {{"network.remote_address", "10.0.0.1"}, {"user.name", "alice"}});
    auto ev_b = make_event("bpf_socket", {{"network.remote_address", "10.0.0.1"}, {"user.name", "alice"}});
    auto ev_c = make_event("bpf_socket", {{"network.remote_address", "10.0.0.2"}, {"user.name", "alice"}});
    auto ev_d = make_event("bpf_socket", {{"network.remote_address", "10.0.0.3"}, {"user.name", "alice"}});

    CHECK(engine.ingest(ev_a, {m}, {make_result(200, 1)}, 1000).empty());
    // Repeat of the SAME remote_address must not move the distinct count.
    CHECK(engine.ingest(ev_b, {m}, {make_result(200, 2)}, 1001).empty());
    CHECK(engine.ingest(ev_c, {m}, {make_result(200, 3)}, 1002).empty());
    auto r = engine.ingest(ev_d, {m}, {make_result(200, 4)}, 1003);
    REQUIRE(r.size() == 1);
    CHECK(r[0].group_key.find("alice") != std::string::npos);
}

// ===========================================================================
// group_key collision safety (Sage's round-2 adversarial finding, fixed:
// length-prefixed encoding instead of a bare '\x1f'-separator join)
// ===========================================================================

TEST_CASE("compute_group_key does not collide when a field value itself contains the "
          "former separator byte (0x1F)",
          "[engine][correlation][security]") {
    CorrelationRule rule;
    rule.id = 50;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.group_by = {"process.parent_executable", "process.command_line"};
    rule.timespan_seconds = 3600;
    rule.threshold = 1000;  // never reached; this test only checks group_key distinctness

    CorrelationEngine engine;
    engine.load({rule});

    auto m = make_match(100);
    // Sage's exact PoC tuple: under the old bare '\x1f'-join scheme, both of
    // these joined to the byte-identical string "ab\x1f\x1fcd\x1f" --
    // (parent_executable="ab") + SEP + (command_line="\x1fcd") + SEP
    //   == "ab" + "\x1f" + "\x1f" + "cd" + "\x1f"
    // (parent_executable="ab\x1f") + SEP + (command_line="cd") + SEP
    //   == "ab" + "\x1f" + "\x1f" + "cd" + "\x1f"
    // -- two DIFFERENT entities sharing one GroupWindow. The fixed
    // length-prefixed encoding must keep them distinct.
    auto ev_a = make_event("bpf_process",
                            {{"process.parent_executable", "ab"}, {"process.command_line", "\x1f""cd"}});
    auto ev_b = make_event("bpf_process",
                            {{"process.parent_executable", "ab\x1f"}, {"process.command_line", "cd"}});

    engine.ingest(ev_a, {m}, {make_result(100, 1)}, 1000);
    REQUIRE(engine.tracked_group_count() == 1);
    engine.ingest(ev_b, {m}, {make_result(100, 2)}, 1001);
    // Two genuinely different (field1,field2) tuples must produce two
    // distinct tracked groups, not collapse into one.
    CHECK(engine.tracked_group_count() == 2);
}

TEST_CASE("compute_group_key: single-field group_by (the default) was never affected, "
          "and stays correct after the fix",
          "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 51;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 3600;
    rule.threshold = 2;  // group_by left empty -> defaults to {"host_identifier"}

    CorrelationEngine engine;
    engine.load({rule});
    auto m = make_match(100);

    auto ev_h1 = make_event("bpf_process", {}, "h1");
    auto ev_h2 = make_event("bpf_process", {}, "h2");
    CHECK(engine.ingest(ev_h1, {m}, {make_result(100, 1)}, 1000).empty());
    CHECK(engine.ingest(ev_h2, {m}, {make_result(100, 2)}, 1001).empty());
    REQUIRE(engine.tracked_group_count() == 2);  // h1 and h2 tracked independently
    // Second occurrence for h1 reaches threshold=2 for h1's OWN group only.
    auto r = engine.ingest(ev_h1, {m}, {make_result(100, 3)}, 1002);
    REQUIRE(r.size() == 1);
    CHECK(r[0].contributing.size() == 2);
}

// ===========================================================================
// temporal vs temporal_ordered -- the actual "why this file exists" contrast
// ===========================================================================

TEST_CASE("temporal fires on coverage regardless of order; temporal_ordered requires the configured order",
          "[engine][correlation]") {
    CorrelationRule temporal;
    temporal.id = 10;
    temporal.type = CorrelationRule::Type::temporal;
    temporal.rule_ids = {210, 220, 230};
    temporal.timespan_seconds = 1800;

    CorrelationRule ordered;
    ordered.id = 11;
    ordered.type = CorrelationRule::Type::temporal_ordered;
    ordered.rule_ids = {210, 220, 230};
    ordered.timespan_seconds = 1800;

    CorrelationEngine engine;
    engine.load({temporal, ordered});

    auto ev = make_event("bpf_process", {});
    // Deliberately WRONG order: 230 (lateral movement) before 210 (recon).
    CHECK(engine.ingest(ev, {make_match(230)}, {make_result(230, 1)}, 1000).empty());
    CHECK(engine.ingest(ev, {make_match(220)}, {make_result(220, 2)}, 2000).empty());
    auto r = engine.ingest(ev, {make_match(210)}, {make_result(210, 3)}, 3000);

    // Coverage-only "temporal" fires (all three ids seen)...
    bool temporal_fired = false, ordered_fired = false;
    for (const auto& inc : r) {
        if (inc.correlation_rule_id == 10) temporal_fired = true;
        if (inc.correlation_rule_id == 11) ordered_fired = true;
    }
    CHECK(temporal_fired);
    // ...but "temporal_ordered" must NOT, since 230 happened before 210/220.
    CHECK_FALSE(ordered_fired);
}

// ===========================================================================
// Bounded memory (the explicit DoS-safety requirement)
// ===========================================================================

TEST_CASE("max_tracked_groups bounds distinct-entity cardinality via eviction, not unbounded growth",
          "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 20;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 3600;
    rule.threshold = 1000;  // never actually reached; this test only proves the group-count bound
    rule.max_tracked_groups = 5;

    CorrelationEngine engine;
    engine.load({rule});

    auto m = make_match(100);
    for (int i = 0; i < 500; ++i) {
        auto ev = make_event("bpf_process", {}, "host-" + std::to_string(i));
        engine.ingest(ev, {m}, {make_result(100, i)}, 1000 + i);
        // The cap must hold on every single iteration, not just at the end --
        // an implementation that only enforced it periodically would still
        // be an unbounded-growth-between-sweeps DoS.
        REQUIRE(engine.tracked_group_count() <= 5);
    }
    CHECK(engine.tracked_group_count() == 5);
}

TEST_CASE("max_events_per_group bounds burst growth within one still-open window",
          "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 21;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 3600;  // long window: time-based pruning never kicks in during this test
    rule.threshold = 6;            // deliberately ABOVE max_events_per_group
    rule.max_events_per_group = 5;

    CorrelationEngine engine;
    engine.load({rule});

    auto ev = make_event("bpf_process", {});
    auto m = make_match(100);
    bool any_incident = false;
    for (int i = 0; i < 50; ++i) {
        auto r = engine.ingest(ev, {m}, {make_result(100, i)}, 1000 + i);
        if (!r.empty()) any_incident = true;
    }
    // With the per-group cap at 5 and the threshold at 6, the count can
    // never reach 6 no matter how many matches arrive -- proving the cap is
    // a hard ceiling, not just a slow-down.
    CHECK_FALSE(any_incident);
}

// ===========================================================================
// Reload semantics
// ===========================================================================

TEST_CASE("reloading a correlation rule with the SAME shape preserves in-flight group state",
          "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 30;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 3600;
    rule.threshold = 5;

    CorrelationEngine engine;
    engine.load({rule});
    auto ev = make_event("bpf_process", {});
    auto m = make_match(100);
    engine.ingest(ev, {m}, {make_result(100, 1)}, 1000);
    engine.ingest(ev, {m}, {make_result(100, 2)}, 1001);
    REQUIRE(engine.tracked_group_count() == 1);

    // Reload with the identical shape (as a SIGHUP reload of an unrelated
    // ruleset tweak would do) -- the in-progress window for host h1 must
    // survive, not reset to empty.
    engine.load({rule});
    auto r = engine.ingest(ev, {m}, {make_result(100, 3)}, 1002);
    // Needs 5 total; this is occurrence #3, so still not yet fired --
    // proves the first two occurrences survived the reload.
    CHECK(r.empty());
    engine.ingest(ev, {m}, {make_result(100, 4)}, 1003);
    auto r5 = engine.ingest(ev, {m}, {make_result(100, 5)}, 1004);
    REQUIRE(r5.size() == 1);
    CHECK(r5[0].contributing.size() == 5);
}

TEST_CASE("reloading a correlation rule with a CHANGED shape starts a clean window",
          "[engine][correlation]") {
    CorrelationRule rule;
    rule.id = 31;
    rule.type = CorrelationRule::Type::event_count;
    rule.rule_ids = {100};
    rule.timespan_seconds = 3600;
    rule.threshold = 2;

    CorrelationEngine engine;
    engine.load({rule});
    auto ev = make_event("bpf_process", {});
    auto m = make_match(100);
    engine.ingest(ev, {m}, {make_result(100, 1)}, 1000);
    REQUIRE(engine.tracked_group_count() == 1);

    rule.timespan_seconds = 120;  // shape changed
    engine.load({rule});
    // If stale history had survived, this single new occurrence plus the
    // (wrongly) carried-over one would already satisfy threshold=2. It must
    // NOT -- the window must have reset.
    auto r = engine.ingest(ev, {m}, {make_result(100, 2)}, 1001);
    CHECK(r.empty());
}

// ===========================================================================
// Fail-closed validation (misconfiguration must never fail OPEN)
// ===========================================================================

TEST_CASE("misconfigured correlation rules are skipped (fail closed), not defaulted to active",
          "[engine][correlation]") {
    CorrelationRule no_rules;
    no_rules.id = 40;
    no_rules.type = CorrelationRule::Type::event_count;
    no_rules.timespan_seconds = 60;
    no_rules.threshold = 1;
    // rule_ids left empty -- structurally can never contribute anything.

    CorrelationRule no_timespan;
    no_timespan.id = 41;
    no_timespan.type = CorrelationRule::Type::event_count;
    no_timespan.rule_ids = {100};
    no_timespan.threshold = 1;
    // timespan_seconds left at 0.

    CorrelationRule no_threshold;
    no_threshold.id = 42;
    no_threshold.type = CorrelationRule::Type::event_count;
    no_threshold.rule_ids = {100};
    no_threshold.timespan_seconds = 60;
    // threshold left at 0 -- must NOT be treated as "always satisfied".

    CorrelationEngine engine;
    engine.load({no_rules, no_timespan, no_threshold});
    CHECK(engine.rule_count() == 0);

    // Confirm no_threshold really can never fire: a single match must not
    // produce an incident (which it would if 0 were silently coerced to a
    // fail-OPEN default of "any count satisfies").
    auto ev = make_event("bpf_process", {});
    auto r = engine.ingest(ev, {make_match(100)}, {make_result(100, 1)}, 1000);
    CHECK(r.empty());
}

// ===========================================================================
// JSON ruleset parsing -- the RulesetLoader-style document shape
// ===========================================================================

TEST_CASE("parse_correlation_rules parses a full document matching the documented shape",
          "[engine][correlation]") {
    auto doc = nlohmann::json::parse(R"({
        "correlations": [
            { "id": 5000, "type": "temporal_ordered",
              "description": "Recon -> credential access -> lateral movement",
              "level": 13, "groups": ["lateral_movement"], "mitre": ["TA0043", "TA0006", "TA0008"],
              "rules": [210, 220, 230], "group_by": ["host_identifier"], "timespan": 1800 },
            { "id": 5001, "type": "event_count", "rules": [100, 101], "timespan": 300,
              "condition": {"gte": 3} },
            { "id": 5002, "type": "value_count", "rules": [150], "field": "host_identifier",
              "timespan": 600, "threshold": 5 }
        ]
    })");

    auto rules = parse_correlation_rules(doc);
    REQUIRE(rules.size() == 3);

    CHECK(rules[0].id == 5000);
    CHECK(rules[0].type == CorrelationRule::Type::temporal_ordered);
    CHECK(rules[0].rule_ids == std::vector<int>{210, 220, 230});
    CHECK(rules[0].group_by == std::vector<std::string>{"host_identifier"});
    CHECK(rules[0].timespan_seconds == 1800);
    CHECK(rules[0].mitre.size() == 3);

    CHECK(rules[1].type == CorrelationRule::Type::event_count);
    CHECK(rules[1].threshold == 3);  // from condition.gte

    CHECK(rules[2].type == CorrelationRule::Type::value_count);
    CHECK(rules[2].field == "host_identifier");
    CHECK(rules[2].threshold == 5);  // from flat "threshold" shorthand
}

TEST_CASE("parse_correlation_rules is empty (not an error) when 'correlations' is absent",
          "[engine][correlation]") {
    auto doc = nlohmann::json::parse(R"({"rules": []})");
    CHECK(parse_correlation_rules(doc).empty());
}

TEST_CASE("parse_correlation_rules rejects structurally malformed entries", "[engine][correlation]") {
    CHECK_THROWS_AS(parse_correlation_rules(nlohmann::json::parse(R"({"correlations":[{"type":"event_count","rules":[1]}]})")),
                     CorrelationRulesetError);  // missing id
    CHECK_THROWS_AS(parse_correlation_rules(nlohmann::json::parse(R"({"correlations":[{"id":1,"rules":[1]}]})")),
                     CorrelationRulesetError);  // missing type
    CHECK_THROWS_AS(
        parse_correlation_rules(nlohmann::json::parse(R"({"correlations":[{"id":1,"type":"event_count","rules":[]}]})")),
        CorrelationRulesetError);  // empty rules array
    CHECK_THROWS_AS(parse_correlation_rules(nlohmann::json::parse(
                         R"({"correlations":[{"id":1,"type":"bogus_type","rules":[1]}]})")),
                     CorrelationRulesetError);  // unknown type
    CHECK_THROWS_AS(parse_correlation_rules(nlohmann::json::parse(
                         R"({"correlations":[{"id":1,"type":"value_count","rules":[1]}]})")),
                     CorrelationRulesetError);  // value_count with no 'field'
}

// ===========================================================================
// End-to-end: a realistic multi-stage attack, through the REAL Decoder and
// RuleEngine (wire-format JSON matching what KafkaProducerManager actually
// publishes -- see Envelope.h), produces exactly ONE correlated incident
// from three separate, distinct rule matches. This is the scenario the
// existing engine (Wazuh-style frequency/if_matched_sid) cannot express: 210,
// 220 and 230 are three unrelated, independently-authored detection rules
// with no if_sid/if_matched_sid relationship to each other.
// ===========================================================================

TEST_CASE("recon -> credential access -> lateral movement produces one correlated incident",
          "[engine][correlation][e2e]") {
    RuleEngine rules;
    {
        std::vector<Rule> rs;

        Rule recon;
        recon.id = 210;
        recon.level = 3;
        recon.description = "Recon command executed";
        recon.groups = {"discovery"};
        recon.mitre = {"T1082"};
        recon.event_type = "bpf_process";
        recon.conditions.push_back(
            FieldCondition{"process.command_line", FieldCondition::Op::contains, "whoami", false, nullptr});
        rs.push_back(recon);

        Rule cred_access;
        cred_access.id = 220;
        cred_access.level = 7;
        cred_access.description = "Shadow file read";
        cred_access.groups = {"credential_access"};
        cred_access.mitre = {"T1003"};
        cred_access.event_type = "bpf_process";
        cred_access.conditions.push_back(FieldCondition{"process.command_line", FieldCondition::Op::contains,
                                                          "/etc/shadow", false, nullptr});
        rs.push_back(cred_access);

        Rule lateral;
        lateral.id = 230;
        lateral.level = 9;
        lateral.description = "Outbound connection to internal host";
        lateral.groups = {"lateral_movement"};
        lateral.mitre = {"T1021"};
        lateral.event_type = "bpf_socket";
        lateral.conditions.push_back(FieldCondition{"network.remote_address", FieldCondition::Op::equals,
                                                      "10.0.0.50", false, nullptr});
        rs.push_back(lateral);

        rules.load(std::move(rs));
    }

    CorrelationRule kill_chain;
    kill_chain.id = 9000;
    kill_chain.type = CorrelationRule::Type::temporal_ordered;
    kill_chain.description = "Recon -> credential access -> lateral movement";
    kill_chain.level = 13;
    kill_chain.groups = {"lateral_movement"};
    kill_chain.rule_ids = {210, 220, 230};
    kill_chain.timespan_seconds = 1800;

    CorrelationEngine correlation;
    correlation.load({kill_chain});
    REQUIRE(correlation.rule_count() == 1);

    Decoder decoder;
    long long next_alert_id = 1;
    std::vector<Incident> all_incidents;

    const char* wire_events[] = {
        R"({"event_type":"bpf_process","host_identifier":"host-A","unixtime":1000,"pid":100,)"
        R"("cmdline":"whoami"})",
        R"({"event_type":"bpf_process","host_identifier":"host-A","unixtime":1010,"pid":101,)"
        R"("cmdline":"cat /etc/shadow"})",
        R"({"event_type":"bpf_socket","host_identifier":"host-A","unixtime":1020,"pid":102,)"
        R"("remote_address":"10.0.0.50","remote_port":22})",
    };

    for (const char* raw : wire_events) {
        auto env = Envelope::from_json_text(raw);
        auto ev = decoder.decode(env);
        auto matches = rules.eval(ev);
        REQUIRE(matches.size() == 1);

        std::vector<AlertWriteResult> written = {make_result(matches[0].rule_id, next_alert_id++)};
        // Same clock main.cpp uses: clamp the event's own (attacker-supplied
        // on the real wire) timestamp against the real wall clock. All three
        // synthetic events are stamped in the past (unixtime 1000-1020), so
        // this resolves to their own timestamps, not "now" -- proving the
        // window logic really is event-time based, not just always "now".
        const std::int64_t wall_clock_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();
        auto incidents =
            correlation.ingest(ev, matches, written, clamp_correlation_now_ms(ev.unix_time, wall_clock_ms));
        for (auto& inc : incidents) all_incidents.push_back(std::move(inc));
    }

    REQUIRE(all_incidents.size() == 1);
    const auto& inc = all_incidents[0];
    CHECK(inc.correlation_rule_id == 9000);
    CHECK(inc.group_key.find("host-A") != std::string::npos);
    REQUIRE(inc.contributing.size() == 3);
    CHECK(inc.contributing[0].rule_id == 210);
    CHECK(inc.contributing[1].rule_id == 220);
    CHECK(inc.contributing[2].rule_id == 230);
    // Every stage resolved to a real (fake, in this test) `alerts` row id --
    // proving AlertWriteResult linkage survives into the incident.
    CHECK(inc.contributing[0].alert_id == 1);
    CHECK(inc.contributing[1].alert_id == 2);
    CHECK(inc.contributing[2].alert_id == 3);
}

// ===========================================================================
// OccurrenceHistory per-key entry cap (Sage's round-2 adversarial finding 5,
// optional/recommended hardening: mirrors CorrelationEngine's own bounded-
// growth-within-a-window precedent for the pre-existing frequency/
// if_matched_sid history structure).
// ===========================================================================

TEST_CASE("OccurrenceHistory caps entries per (rule_id, group_key), bounding growth "
          "within a single still-open window",
          "[engine][occurrencehistory][security]") {
    OccurrenceHistory history;
    const auto cap = OccurrenceHistory::kMaxEntriesPerKey;
    // Push well past the cap -- all within what will be treated as one
    // still-open window (see the wide window_ms below), so nothing is
    // reclaimed by TIME-based pruning; only the CAP can be responsible for
    // whatever count comes back.
    for (std::size_t i = 0; i < cap + 500; ++i) {
        history.record(1, "k", static_cast<std::int64_t>(i));
    }

    const auto now_ms = static_cast<std::int64_t>(cap) + 499;
    const auto window_ms = static_cast<std::int64_t>(cap) + 10'000'000;  // wide enough to include everything
    const int count = history.count_recent(1, "k", now_ms, window_ms);

    // Without the cap this would be cap+500 (every push counted); the cap
    // must hold it at exactly `cap`, never above.
    CHECK(count == static_cast<int>(cap));
}

// ===========================================================================
// RuleEngine.cpp's Op::regex ReDoS execution-time bound (Sage's round-2
// adversarial finding 2, "most severe finding" -- fixed by swapping to
// Vega's regex_search_bounded() once it landed in JsonSafety.h).
// ===========================================================================

TEST_CASE("FieldCondition::Op::regex is execution-time bounded against a catastrophic-"
          "backtracking pattern that bypasses the load-time heuristic screen",
          "[engine][rules][security]") {
    ListStore lists;
    // Sage's exact PoC shape (.team/mailbox/re-sage.md Finding 2):
    // "(a|aa)+$" passes looks_like_catastrophic_regex() (no NESTED
    // quantifier -- it's an alternation under a single outer '+', not one
    // quantified group wrapping another) but is genuinely exponential-time
    // against std::regex. Sage measured ~1.8 SECONDS at a 36-byte input
    // using a bare regex_search; this test proves RuleEngine's actual match
    // site no longer blocks anywhere near that long.
    auto compiled =
        std::make_shared<std::regex>("(a|aa)+$", std::regex::ECMAScript | std::regex::optimize);
    FieldCondition cond{"f", FieldCondition::Op::regex, "(a|aa)+$", false, compiled};
    // 40 'a's + a non-matching terminator: pathological for this pattern,
    // well within kMaxRegexInputBytes (16 KiB), and longer than Sage's
    // slowest (36-byte, ~1.8s) measured PoC input -- a bare std::regex_search
    // against this exact input would be dramatically slower still.
    std::string pathological(40, 'a');
    pathological += '!';
    auto ev = make_event("t", {{"f", pathological}});

    const auto start = std::chrono::steady_clock::now();
    const bool matched = cond.matches(ev, lists);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start)
            .count();

    CHECK_FALSE(matched);  // times out -> fails closed as a non-match, never a false positive
    // Must return within roughly regex_search_bounded()'s deadline
    // (kRegexSearchTimeout, 75ms per JsonSafety.h), not the seconds a bare
    // std::regex_search would take against this input. Generous 2s margin
    // for scheduling/CI jitter -- still 1-2 orders of magnitude below what
    // an unbounded search against this exact input would take.
    CHECK(elapsed_ms < 2000);
}
