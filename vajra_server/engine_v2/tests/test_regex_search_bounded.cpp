// Direct unit tests for JsonSafety.h's regex_search_bounded(), added in
// response to Sage's finding 2 (re-sage.md) -- the load-time
// looks_like_catastrophic_regex() heuristic does not catch every
// pathological pattern (ambiguous alternation under a quantifier, e.g.
// "(a|aa)+$", is a confirmed exponential-time counter-example against
// std::regex -- see redos_poc.cpp), so regex_search_bounded() is the actual
// execution-time backstop every regex_search against attacker-reachable
// input must go through. See also test_decoder_hardening.cpp's end-to-end
// regression test of the exact same pattern through Decoder::decode().
#include "catch2/catch.hpp"

#include "vajra_engine/JsonSafety.h"

#include <chrono>

using namespace vajra_engine;

TEST_CASE("regex_search_bounded matches and populates captures like a direct regex_search",
          "[engine][jsonsafety][redos]") {
    std::regex re(R"((\d+)-(\d+))");
    std::smatch match;
    // Deliberately a NAMED std::string, not a string literal passed
    // directly: the out-taking overload DELETES its rvalue-string overload
    // (mirroring std::regex_search's own protection) specifically because
    // `match`'s iterators must reference a string that outlives this call
    // -- a temporary wouldn't. See regex_search_bounded's doc comment.
    const std::string input = "order 42-99 confirmed";
    const auto outcome = regex_search_bounded(input, re, &match);
    REQUIRE(outcome == RegexSearchOutcome::Matched);
    REQUIRE(match.size() == 3);
    CHECK(match[1].str() == "42");
    CHECK(match[2].str() == "99");
}

TEST_CASE("regex_search_bounded returns NoMatch (not TimedOut) for an ordinary non-match",
          "[engine][jsonsafety][redos]") {
    std::regex re("zzz");
    // The no-captures (3-arg) overload, not out=nullptr on the 4-arg one --
    // that overload's rvalue-string form is deleted unconditionally (it
    // can't tell "out is null, so a temporary would actually be safe" from
    // "out is real" at the type level), so a temporary is only accepted by
    // the dedicated no-captures overload. See regex_search_bounded's doc
    // comment.
    const auto outcome = regex_search_bounded("nothing to see here", re);
    CHECK(outcome == RegexSearchOutcome::NoMatch);
}

TEST_CASE("regex_search_bounded's 2-arg (no-captures) overload works", "[engine][jsonsafety][redos]") {
    std::regex re("hello");
    CHECK(regex_search_bounded("say hello world", re) == RegexSearchOutcome::Matched);
    CHECK(regex_search_bounded("say goodbye world", re) == RegexSearchOutcome::NoMatch);
}

TEST_CASE("regex_search_bounded returns TimedOut and bumps the counter for a pathological pattern, "
          "in bounded wall-clock time",
          "[engine][jsonsafety][redos]") {
    // Sage's finding 2 counter-example. Confirmed elsewhere
    // (test_decoder_hardening.cpp) that looks_like_catastrophic_regex()
    // does not catch this shape -- this test is about the execution-time
    // backstop, independent of that load-time heuristic.
    std::regex re("(a|aa)+$", std::regex::ECMAScript | std::regex::optimize);
    std::string input(35, 'a');
    input += '!';

    const std::uint64_t before = regex_search_timeout_count();
    const auto start = std::chrono::steady_clock::now();
    const auto outcome = regex_search_bounded(input, re, nullptr, std::chrono::milliseconds(75));
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();

    CHECK(outcome == RegexSearchOutcome::TimedOut);
    CHECK(regex_search_timeout_count() == before + 1);
    // Bounded near the requested 75ms deadline, nowhere near the ~1.8s an
    // unbounded regex_search takes against this exact input (redos_poc.cpp).
    INFO("elapsed_ms=" << elapsed_ms);
    CHECK(elapsed_ms < 500);
}

TEST_CASE("regex_search_bounded honors a custom timeout value", "[engine][jsonsafety][redos]") {
    std::regex re("(a|aa)+$", std::regex::ECMAScript | std::regex::optimize);
    std::string input(40, 'a');
    input += '!';

    const auto start = std::chrono::steady_clock::now();
    const auto outcome = regex_search_bounded(input, re, nullptr, std::chrono::milliseconds(20));
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();
    CHECK(outcome == RegexSearchOutcome::TimedOut);
    // Should return close to the requested 20ms, not the default 75ms.
    CHECK(elapsed_ms < 300);
}
