// verify_alertwriter_dedup -- live-DB regression check for the AlertWriter
// dedup-identity fix (Sage's round-2 adversarial review, Finding 3; see
// .team/mailbox/re-sage.md and .team/mailbox/re-nyx.md).
//
// NOT part of the Catch2 suite (vajra_engine_v2_tests) on purpose: that
// binary is shared with Vega's tests and deliberately never opens a DB/Kafka
// connection during a run (see tests/CMakeLists.txt's own top comment) so it
// stays runnable with no external infra. This tool is the DB-requiring
// counterpart -- same relationship vajra_engine_eval already has to the unit
// suite for the Kafka-free side of the pipeline.
//
// What it proves: before the fix, two rules that both omit `description`
// and both omit `groups` (the ruleset-authoring DEFAULT, zero extra effort)
// would dedupe against each other -- the second rule's detection would
// silently produce ZERO new `alerts` row. After the fix (dedup keyed on
// m.rule_id via metadata->>'rule_id', not on event_code/m.description), two
// different rule ids must always produce two distinct rows.
//
// Usage:
//   vajra_engine_v2_verify_alertwriter_dedup [connection_string]
// Defaults to a fleet_test-only connection string -- NEVER points at
// `fleet`/`fleet1`/any production database by default; pass an explicit
// connection string only to point at another disposable test database.
// Inserts and then deletes its own rows (scoped to a unique, run-specific
// host_identifier) so it leaves the target database exactly as it found it,
// safe to run against a database shared with other concurrent test/dev
// activity.

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "../../common/ConnectionPool.h"
#include "vajra_engine/AlertWriter.h"
#include "vajra_engine/RuleEngine.h"

namespace {

vajra_engine::NormalizedEvent make_event(const std::string& host) {
    vajra_engine::NormalizedEvent ev;
    ev.event_type = "bpf_process";
    ev.os = "linux";
    ev.host_identifier = host;
    ev.unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    return ev;
}

// Two DIFFERENT rules, both using the ruleset-authoring DEFAULTS that Sage's
// Finding 3 showed collide: no `description` (defaults to ""), no `groups`
// (so alert_type defaults to "detection" in AlertWriter::write()). Only
// rule_id differs -- exactly the zero-authoring-effort shape from the
// finding, not a contrived worst case.
vajra_engine::Match make_default_match(int rule_id) {
    vajra_engine::Match m;
    m.rule_id = rule_id;
    m.level = 5;
    // description and groups deliberately left at their defaults ("" / {}).
    return m;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string conn_str =
        argc > 1 ? argv[1] : "host=localhost port=5432 dbname=fleet_test user=vajra password=admin";

    std::cout << "vajra_engine_v2_verify_alertwriter_dedup: connecting (" << conn_str << ")\n";

    auto pool = std::make_shared<ConnectionPool>(conn_str, 2);
    vajra_engine::AlertWriter writer(pool);

    // Unique per run so concurrent/repeated runs against a shared DB never
    // collide with each other or with unrelated data.
    const std::string host = "verify-dedup-host-" +
                              std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                 std::chrono::system_clock::now().time_since_epoch())
                                                 .count());
    auto ev = make_event(host);

    const auto r1 = writer.write(ev, {make_default_match(990001)});
    const auto r2 = writer.write(ev, {make_default_match(990002)});

    bool pass = true;
    auto check = [&](bool cond, const std::string& what) {
        std::cout << (cond ? "[PASS] " : "[FAIL] ") << what << "\n";
        if (!cond) pass = false;
    };

    check(r1.size() == 1 && r2.size() == 1, "both writes returned exactly one AlertWriteResult");
    if (r1.size() == 1 && r2.size() == 1) {
        check(r1[0].newly_inserted, "rule 990001's match was newly inserted");
        check(r2[0].newly_inserted,
              "rule 990002's match was ALSO newly inserted (pre-fix: this was false -- it deduped "
              "against rule 990001's open alert instead)");
        check(r1[0].alert_id >= 0 && r2[0].alert_id >= 0, "both results carry a real alert_id");
        check(r1[0].alert_id != r2[0].alert_id,
              "the two rule ids produced DIFFERENT alert_id values (pre-fix: these were IDENTICAL -- "
              "rule 990002 silently reused rule 990001's row)");
    }

    // Independent confirmation directly against the table, not just via
    // AlertWriter's own return values.
    try {
        auto conn = pool->GetConnection();
        pqxx::work txn(*conn);
        pqxx::result count_res =
            txn.exec_params("SELECT count(*) FROM alerts WHERE host_identifier = $1::text", host);
        const long long row_count = count_res[0][0].as<long long>();
        check(row_count == 2, "exactly 2 distinct `alerts` rows exist for this run's host (found " +
                                   std::to_string(row_count) + ")");

        // Clean up after ourselves -- this DB is shared with other
        // concurrent test/dev activity.
        txn.exec_params("DELETE FROM alerts WHERE host_identifier = $1::text", host);
        txn.commit();
        pool->ReturnConnection(conn);
        std::cout << "(cleaned up " << row_count << " row(s) for host " << host << ")\n";
    } catch (const std::exception& e) {
        std::cout << "[FAIL] could not independently verify/clean up via a direct query: " << e.what()
                   << "\n";
        pass = false;
    }

    std::cout << (pass ? "\nRESULT: PASS\n" : "\nRESULT: FAIL\n");
    return pass ? 0 : 1;
}
