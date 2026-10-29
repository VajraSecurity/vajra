// Regression tests for ListStore::contains_icase()/get_icase() (Rule.h) --
// groundwork for case-insensitive in_list/in_list_active matching. Not yet
// wired into FieldCondition::matches() (that switch lives in RuleEngine.cpp,
// outside this file's ownership for this engagement -- see re-vega.md and
// re-nyx.md), so exercised directly against ListStore here.
#include "catch2/catch.hpp"

#include "vajra_engine/Rule.h"

using namespace vajra_engine;

TEST_CASE("contains_icase matches regardless of case, for membership-only entries",
          "[engine][liststore][icase]") {
    ListStore lists;
    lists.add("deny_domains", "Evil.Example.COM");

    CHECK(lists.contains_icase("deny_domains", "evil.example.com"));
    CHECK(lists.contains_icase("deny_domains", "EVIL.EXAMPLE.COM"));
    CHECK(lists.contains_icase("deny_domains", "Evil.Example.COM"));
    CHECK_FALSE(lists.contains_icase("deny_domains", "benign.example.com"));
    // Case-sensitive contains() must be unaffected by this addition.
    CHECK_FALSE(lists.contains("deny_domains", "evil.example.com"));
    CHECK(lists.contains("deny_domains", "Evil.Example.COM"));
}

TEST_CASE("contains_icase on a missing list or missing key returns false", "[engine][liststore][icase]") {
    ListStore lists;
    lists.add("some_list", "member");
    CHECK_FALSE(lists.contains_icase("no_such_list", "member"));
    CHECK_FALSE(lists.contains_icase("some_list", "not_a_member"));
}

TEST_CASE("get_icase returns the stored value regardless of key case (CDB-style lists)",
          "[engine][liststore][icase]") {
    ListStore lists;
    lists.set("reputation", "Bad-Host.Example", "malicious");

    REQUIRE(lists.get_icase("reputation", "bad-host.example").has_value());
    CHECK(*lists.get_icase("reputation", "bad-host.example") == "malicious");
    REQUIRE(lists.get_icase("reputation", "BAD-HOST.EXAMPLE").has_value());
    CHECK(*lists.get_icase("reputation", "BAD-HOST.EXAMPLE") == "malicious");
    CHECK_FALSE(lists.get_icase("reputation", "other-host.example").has_value());
    CHECK_FALSE(lists.get_icase("no_such_list", "bad-host.example").has_value());
}

TEST_CASE("get_icase distinguishes a present-but-empty value from an absent key",
          "[engine][liststore][icase]") {
    ListStore lists;
    lists.add("membership_only", "K1");  // add() stores an empty value
    auto v = lists.get_icase("membership_only", "k1");
    REQUIRE(v.has_value());
    CHECK(v->empty());
    CHECK_FALSE(lists.get_icase("membership_only", "k2").has_value());
}
