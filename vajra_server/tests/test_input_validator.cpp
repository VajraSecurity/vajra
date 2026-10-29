#include "catch2/catch.hpp"

#include <algorithm> // InputValidator.h uses std::remove without including <algorithm>
#include "InputValidator.h"

using namespace VajraValidator;

TEST_CASE("isValidHostIdentifier accepts safe identifiers", "[validator]") {
    CHECK(isValidHostIdentifier("host-01"));
    CHECK(isValidHostIdentifier("web.example.com"));
    CHECK(isValidHostIdentifier("HOST_42"));
    CHECK(isValidHostIdentifier("a"));
    CHECK(isValidHostIdentifier(std::string(255, 'a')));
}

TEST_CASE("isValidHostIdentifier rejects unsafe identifiers", "[validator]") {
    CHECK_FALSE(isValidHostIdentifier(""));
    CHECK_FALSE(isValidHostIdentifier(std::string(256, 'a')));
    CHECK_FALSE(isValidHostIdentifier("host id"));           // space
    CHECK_FALSE(isValidHostIdentifier("host;drop table"));   // injection chars
    CHECK_FALSE(isValidHostIdentifier("host'--"));
    CHECK_FALSE(isValidHostIdentifier("host\nid"));
    CHECK_FALSE(isValidHostIdentifier(std::string("host\0id", 7)));
}

TEST_CASE("isValidNodeKey accepts legacy 20-char and enhanced 64-char keys", "[validator]") {
    CHECK(isValidNodeKey(std::string(20, 'a')));
    CHECK(isValidNodeKey(std::string(64, 'Z')));
    CHECK(isValidNodeKey("abcDEF1234567890abcd")); // 20 mixed alnum
}

TEST_CASE("isValidNodeKey rejects wrong length or non-alphanumeric", "[validator]") {
    CHECK_FALSE(isValidNodeKey(""));
    CHECK_FALSE(isValidNodeKey(std::string(19, 'a')));
    CHECK_FALSE(isValidNodeKey(std::string(21, 'a')));
    CHECK_FALSE(isValidNodeKey(std::string(63, 'a')));
    CHECK_FALSE(isValidNodeKey(std::string(65, 'a')));
    CHECK_FALSE(isValidNodeKey(std::string(19, 'a') + "-")); // 20 chars but has '-'
    CHECK_FALSE(isValidNodeKey(std::string(19, 'a') + "'"));
}

TEST_CASE("sanitizeString strips null bytes and truncates", "[validator]") {
    CHECK(sanitizeString("hello") == "hello");
    CHECK(sanitizeString(std::string("he\0llo", 6)) == "hello");
    CHECK(sanitizeString("abcdef", 3) == "abc");
    CHECK(sanitizeString("").empty());
    // default max_length is 65535
    CHECK(sanitizeString(std::string(70000, 'x')).size() == 65535);
}

TEST_CASE("isValidTableName accepts lowercase snake_case", "[validator]") {
    CHECK(isValidTableName("win_process_events"));
    CHECK(isValidTableName("t"));
    CHECK(isValidTableName("a1_b2"));
}

TEST_CASE("isValidTableName rejects injection-prone names", "[validator]") {
    CHECK_FALSE(isValidTableName(""));
    CHECK_FALSE(isValidTableName("1table"));      // must start with letter
    CHECK_FALSE(isValidTableName("_table"));      // must start with lowercase letter
    CHECK_FALSE(isValidTableName("Table"));       // uppercase not allowed
    CHECK_FALSE(isValidTableName("tab le"));
    CHECK_FALSE(isValidTableName("tab;drop"));
    CHECK_FALSE(isValidTableName("tab\"le"));
    CHECK_FALSE(isValidTableName(std::string(129, 'a')));
    CHECK(isValidTableName(std::string(128, 'a'))); // boundary: 128 is allowed
}

TEST_CASE("isValidPayloadSize enforces bounds", "[validator]") {
    CHECK_FALSE(isValidPayloadSize(0));
    CHECK(isValidPayloadSize(1));
    CHECK(isValidPayloadSize(10 * 1024 * 1024));       // exactly at default max
    CHECK_FALSE(isValidPayloadSize(10 * 1024 * 1024 + 1));
    CHECK(isValidPayloadSize(100, 100));
    CHECK_FALSE(isValidPayloadSize(101, 100));
}

TEST_CASE("isValidUnixTime accepts 2000-2100 range", "[validator]") {
    CHECK(isValidUnixTime(946684800L));   // 2000-01-01 boundary
    CHECK(isValidUnixTime(4102444800L));  // 2100-01-01 boundary
    CHECK(isValidUnixTime(1700000000L));  // sane current-era timestamp
    CHECK_FALSE(isValidUnixTime(946684799L));
    CHECK_FALSE(isValidUnixTime(4102444801L));
    CHECK_FALSE(isValidUnixTime(0L));
    CHECK_FALSE(isValidUnixTime(-1L));
}

TEST_CASE("isValidFilePath basic mode", "[validator]") {
    CHECK(isValidFilePath(""));                        // empty allowed by design
    CHECK(isValidFilePath("/usr/bin/osqueryd"));
    CHECK(isValidFilePath("C:\\Windows\\System32\\cmd.exe"));
    CHECK(isValidFilePath("/a/../b"));                 // ".." allowed in non-strict mode
    CHECK_FALSE(isValidFilePath(std::string(4097, 'a')));
    CHECK_FALSE(isValidFilePath(std::string("/tmp/\0evil", 10)));
}

TEST_CASE("isValidFilePath strict mode blocks traversal", "[validator]") {
    CHECK_FALSE(isValidFilePath("/a/../b", true));
    CHECK_FALSE(isValidFilePath("..", true));
    CHECK(isValidFilePath("/plain/path", true));
}

TEST_CASE("isValidEventCount enforces bounds", "[validator]") {
    CHECK_FALSE(isValidEventCount(0));
    CHECK(isValidEventCount(1));
    CHECK(isValidEventCount(10000));       // default max inclusive
    CHECK_FALSE(isValidEventCount(10001));
    CHECK(isValidEventCount(5, 5));
    CHECK_FALSE(isValidEventCount(6, 5));
}

TEST_CASE("isValidNumericString handles signs and length", "[validator]") {
    CHECK(isValidNumericString(""));            // empty allowed by design (-> 0)
    CHECK(isValidNumericString("0"));
    CHECK(isValidNumericString("1234567890"));
    CHECK(isValidNumericString("-42"));
    CHECK_FALSE(isValidNumericString("-42", false)); // negatives disallowed
    CHECK(isValidNumericString("42", false));
    CHECK_FALSE(isValidNumericString("4 2"));
    CHECK_FALSE(isValidNumericString("42a"));
    CHECK_FALSE(isValidNumericString("0x1F"));
    CHECK(isValidNumericString(std::string(19, '9')));       // 19 digits allowed
    CHECK_FALSE(isValidNumericString(std::string(20, '9'))); // 20 digits rejected
}

TEST_CASE("isValidIPAddress handles IPv4 and IPv6 shapes", "[validator]") {
    CHECK(isValidIPAddress(""));               // empty allowed by design
    CHECK(isValidIPAddress("127.0.0.1"));
    CHECK(isValidIPAddress("10.118.5.32"));
    CHECK(isValidIPAddress("fe80::1"));
    CHECK(isValidIPAddress("2001:db8:85a3:0:0:8a2e:370:7334"));
    CHECK_FALSE(isValidIPAddress("localhost"));
    CHECK_FALSE(isValidIPAddress("1.2.3"));
    CHECK_FALSE(isValidIPAddress("1.2.3.4.5"));
    CHECK_FALSE(isValidIPAddress("1.2.3.4; rm -rf /"));
    // NOTE: the simple regex accepts out-of-range octets like 999.999.999.999;
    // documented behaviour, format-only check.
    CHECK(isValidIPAddress("999.999.999.999"));
}

TEST_CASE("isValidCommandLine limits length and null bytes", "[validator]") {
    CHECK(isValidCommandLine(""));
    CHECK(isValidCommandLine("cmd.exe /c \"echo hi & dir\" | findstr x"));
    CHECK(isValidCommandLine(std::string(32768, 'a')));       // at default max
    CHECK_FALSE(isValidCommandLine(std::string(32769, 'a')));
    CHECK_FALSE(isValidCommandLine(std::string("cmd\0evil", 8)));
    CHECK_FALSE(isValidCommandLine("toolong", 3));
}
