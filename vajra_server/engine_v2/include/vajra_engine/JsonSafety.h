#ifndef VAJRA_ENGINE_JSON_SAFETY_H
#define VAJRA_ENGINE_JSON_SAFETY_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace vajra_engine {

// Cheap linear pre-scan (tracks in-string/escaped state so brackets inside
// string literals don't count) that rejects a JSON document with bracket
// nesting deeper than max_depth BEFORE it's handed to nlohmann::json::parse.
// nlohmann's parser is recursive-descent with no built-in depth limit, so
// parsing arbitrarily-nested input directly can exhaust the stack (a crash,
// not a catchable C++ exception) -- this bound applies regardless of the
// document's total byte size. Originally built for ThreatIntelFeed's
// external HTTP responses; also used on Envelope::from_json_text's Kafka
// message path, which is the more attacker-reachable of the two (event
// payloads can originate from a compromised/malicious osquery endpoint, or
// from anyone able to publish directly to the ingest topics).
inline bool exceeds_max_nesting_depth(const std::string& body, int max_depth) {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (char c : body) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
        } else if (c == '[' || c == '{') {
            if (++depth > max_depth) return true;
        } else if (c == ']' || c == '}') {
            --depth;
        }
    }
    return false;
}

// Far beyond anything a legitimate event payload or threat-intel response
// needs (realistically well under 10 levels for either), but small enough
// to definitively bound recursive-descent stack usage regardless of input
// size.
constexpr int kMaxJsonNestingDepth = 64;

// Shared load-time cap on a REGEX PATTERN's own source length (not the
// string it's matched against -- see kMaxRegexInputBytes in Decoder.cpp/
// RuleEngine.cpp for that, separate concern). Applied to every
// operator-authored pattern this engine compiles (rule conditions, decoder
// prematch/extract, and the patterns RulesetLoader's Sigma-parity operators
// -- cidr/startswith/endswith/windash_contains/base64offset_contains --
// generate) so a pathologically long pattern can't cause slow std::regex
// compilation or an oversized compiled NFA. Far beyond any legitimate
// hand-written pattern (realistically well under 500 bytes).
constexpr std::size_t kMaxRegexPatternLength = 4096;

// Heuristic screen for the most common catastrophic-backtracking ("ReDoS")
// regex shapes: a quantified sub-expression (`+`, `*`, or an unbounded/
// ranged `{m,n}`) wrapped in ANOTHER quantifier, e.g. `(a+)+`, `(a*)+`,
// `(a+)*`, `(.*)+`, `([^x]+)+`. This is not a general regex-complexity
// analyzer -- std::regex exposes no compiled-NFA introspection to build a
// precise one -- and it does NOT catch every pathological pattern: in
// particular, AMBIGUOUS/OVERLAPPING ALTERNATION under a quantifier (e.g.
// `(a|aa)+$` -- no nested quantifier at all, just two alternatives that can
// both match the same input, repeated) is a real, independently exploitable
// ReDoS shape this heuristic passes through undetected. Confirmed
// exponential (not merely slow) against `std::regex`: ~1.6x per additional
// input byte, ~1.8 SECONDS at 35 bytes of input -- see
// engine_v2/review_scratch/redos_poc.cpp and re-vega.md's writeup of
// Sage's finding 2.
//
// An EARLIER version of this doc comment claimed the fixed-size match-time
// input cap (kMaxRegexInputBytes in Decoder.cpp/RuleEngine.cpp) bounds
// worst-case execution time "together with" this heuristic. That claim was
// WRONG and has been removed: a byte-size cap only bounds POLYNOMIAL
// worst-case blowups, not EXPONENTIAL ones -- the 16KB cap does nothing to
// stop `(a|aa)+`-shaped patterns, whose cost keeps ~1.6x-ing per byte
// regardless of where the cap sits (a crafted input well under that cap,
// as low as ~35-50 bytes, already takes seconds). The actual
// execution-time bound is regex_search_bounded(), below -- it, not this
// heuristic, is what a caller MUST use for any regex_search against
// attacker-reachable input. This heuristic is retained as a cheap,
// load-time, actionable-immediately (operator gets a rejection at ruleset
// load, not a silent runtime hang) screen for the shapes it DOES catch --
// still worth keeping as a first line of defense -- but must never be
// treated as a sufficient safety net on its own.
//
// Bracket-expression contents (`[...]`) and escaped characters are skipped
// -- a `+`/`*` inside a character class, or escaped in the pattern text
// (`\+`), is literal/class syntax, not a quantifier.
inline bool looks_like_catastrophic_regex(std::string_view pattern) {
    // has_quantifier[depth] tracks whether the group currently open at that
    // nesting depth has, so far, seen a quantifier applied directly inside
    // it (not inside a nested sub-group -- that sub-group is judged on its
    // own, then propagates outward only if IT is also quantified as a
    // whole, e.g. `((a+)b)+`).
    std::vector<bool> has_quantifier;
    has_quantifier.push_back(false);  // depth 0: the whole pattern
    bool in_class = false;
    bool escaped = false;

    for (std::size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (in_class) {
            if (c == ']') in_class = false;
            continue;
        }
        if (c == '[') {
            in_class = true;
            continue;
        }

        if (c == '(') {
            has_quantifier.push_back(false);
            continue;
        }
        if (c == ')') {
            const bool child_was_quantified = !has_quantifier.empty() && has_quantifier.back();
            if (!has_quantifier.empty()) has_quantifier.pop_back();

            const bool followed_by_quantifier =
                i + 1 < pattern.size() &&
                (pattern[i + 1] == '+' || pattern[i + 1] == '*' || pattern[i + 1] == '{');
            if (child_was_quantified && followed_by_quantifier) return true;
            // Propagate "has a quantifier inside it" to the enclosing
            // group whenever EITHER (a) the child's own content already had
            // one (the child's matched text -- and whatever it contains --
            // is part of the parent's content too, so e.g. `((a+)b)+`'s
            // outer group must inherit the inner `a+`even though "(a+)" is
            // only followed by a literal 'b', not another quantifier), or
            // (b) the child group is itself quantified as a whole
            // (`(ab)+`, so a further outer quantifier as in `((ab)+)+`
            // makes it just as catastrophic as `(a+)+` despite "ab" having
            // no quantifier of its own).
            if ((child_was_quantified || followed_by_quantifier) && !has_quantifier.empty()) {
                has_quantifier.back() = true;
            }
            continue;
        }

        if ((c == '+' || c == '*' || c == '{') && !has_quantifier.empty()) {
            has_quantifier.back() = true;
        }
    }
    return false;
}

// Outcome of a bounded regex search: distinguishes a real non-match from a
// deadline expiry so callers can log/count the latter distinctly, rather
// than silently folding it into "didn't match" the way returning a bare
// bool would.
enum class RegexSearchOutcome { Matched, NoMatch, TimedOut };

// ~50-100ms per this fix's review guidance: generous relative to any
// legitimate regex_search call this engine actually makes (realistically
// low-single-digit milliseconds at worst for well-formed operator
// patterns against inputs bounded by kMaxRegexInputBytes), while still
// keeping the worst-case ADDED per-event latency small and fixed even when
// the deadline is hit.
constexpr std::chrono::milliseconds kRegexSearchTimeout{75};

namespace detail {
inline std::atomic<std::uint64_t>& regex_search_timeout_counter() {
    static std::atomic<std::uint64_t> counter{0};
    return counter;
}
}  // namespace detail

// Total regex_search_bounded() calls that hit the timeout since process
// start. Read by Metrics::regex_timeouts_total() (Metrics.h/.cpp) for the
// vajra_engine_regex_timeout_total Prometheus counter -- see main.cpp's
// render_metrics() for where that gets exposed.
inline std::uint64_t regex_search_timeout_count() {
    return detail::regex_search_timeout_counter().load(std::memory_order_relaxed);
}

// Wall-clock-bounded std::regex_search. std::regex has no built-in
// execution-time bound or cancellation mechanism, and a pathological
// pattern -- not necessarily one looks_like_catastrophic_regex() catches;
// see its doc comment above -- can take exponential time against a short,
// perfectly ordinary-looking input well within kMaxRegexInputBytes. Since
// regex matching runs on the single Kafka-consumer thread that ALSO runs
// the SIGHUP reload check (KafkaConsumer::run()'s on_tick hook -- see
// KafkaConsumer.h's doc comment), an unbounded regex_search call can stall
// the entire detection pipeline indefinitely, with no way for an operator
// to even SIGHUP their way out (that check never gets a turn on a wedged
// thread). MUST be used instead of a bare std::regex_search for any regex
// evaluated against attacker/endpoint-reachable event data (both of this
// engine's own call sites -- Decoder.cpp's decoder prematch/extract, and
// RuleEngine.cpp's FieldCondition::Op::regex case -- qualify).
//
// Implementation: runs the actual search on a short-lived worker thread
// and waits up to `timeout` for it to finish, via a std::packaged_task
// (NOT std::async -- a std::future returned directly by std::async has a
// special blocking destructor that would wait for the task to finish
// regardless of `timeout`, defeating the whole point; a future obtained
// from a packaged_task's own get_future() has no such behavior).
//   - Finishes in time: returns Matched/NoMatch; `out` (if non-null) is
//     populated with capture groups exactly as a direct
//     regex_search(str, *out, re) call would populate it.
//   - Doesn't finish in time: returns TimedOut immediately (every caller
//     treats this as "no match" -- fails closed for the ONE
//     condition/decoder that owns this pattern, never for the whole
//     ruleset or pipeline), bumps the timeout counter above, and the
//     worker thread is detached and abandoned mid-search. There is no way
//     to cancel a std::regex_search already in progress, so this is a
//     deliberate, bounded leak: one thread per PATTERN ACTUALLY HIT by
//     pathological input, not one per event -- a benign pattern's worker
//     finishes and cleans itself up normally, well within the deadline, on
//     every call. Callers are expected to log the offending rule/decoder
//     id on TimedOut so an operator can fix or disable the pattern; this
//     is a runtime circuit-breaker for a single bad pattern, not a
//     substitute for fixing the ruleset.
//
// `input` and `re` are copied into the worker's own (shared_ptr-owned)
// storage rather than captured by reference: on a timeout this function
// returns while the worker is still running, so the worker must not
// depend on this function's stack frame -- OR on the caller's `input`/`out`
// objects -- surviving. This is deliberate and load-bearing, not just
// defensive style: std::smatch stores ITERATORS into the string it
// searched, not a copy of the matched text, so if the worker populated a
// smatch pointing into `owned_input` and this function copied that into
// `*out` before returning, `*out`'s iterators would dangle the moment
// `owned_input` is freed -- which happens as soon as BOTH this function's
// local shared_ptr and the (by-then-finished) worker's own copy go out of
// scope, typically immediately after this function returns. (Caught by
// this file's own test suite -- test_regex_search_bounded.cpp -- which
// read back corrupted capture-group text before this was fixed; not
// shipped broken.) Fixed by never handing the caller iterators into the
// worker's private copy at all: the worker's own search (against its own
// copy) only ever answers "does it match, and does it finish in time" --
// see below for how `out` actually gets populated.
inline RegexSearchOutcome regex_search_bounded(const std::string& input, const std::regex& re,
                                                std::smatch* out,
                                                std::chrono::milliseconds timeout = kRegexSearchTimeout) {
    auto owned_input = std::make_shared<std::string>(input);
    auto owned_regex = std::make_shared<std::regex>(re);

    std::packaged_task<bool()> task(
        [owned_input, owned_regex]() { return std::regex_search(*owned_input, *owned_regex); });
    std::future<bool> future = task.get_future();
    std::thread worker([task = std::move(task)]() mutable { task(); });
    worker.detach();

    if (future.wait_for(timeout) != std::future_status::ready) {
        detail::regex_search_timeout_counter().fetch_add(1, std::memory_order_relaxed);
        return RegexSearchOutcome::TimedOut;
    }

    const bool matched = future.get();
    // The worker (against a byte-identical copy of `input`) has already
    // PROVEN this completes well within `timeout` -- std::regex_search is
    // deterministic given the same pattern and the same input bytes, so
    // redoing it here, synchronously, directly against the CALLER's own
    // `input`/`out`, is both cheap (already known-fast) and correct: `out`
    // ends up with iterators into the CALLER's `input`, valid for exactly
    // as long as the caller keeps `input` alive -- the same contract a
    // plain std::regex_search(input, *out, re) call would have, which is
    // what callers actually need `out` for.
    if (matched && out) {
        std::regex_search(input, *out, re);
    }
    return matched ? RegexSearchOutcome::Matched : RegexSearchOutcome::NoMatch;
}

// Deleted, mirroring std::regex_search's OWN protection against exactly
// this mistake (the standard library deletes its rvalue-basic_string
// smatch-populating overload for the identical reason): passing a
// temporary (e.g. a string literal, or any expression that isn't a named
// object) as `input` would populate `*out` with iterators into a string
// destroyed at the end of the full expression -- a real use-after-free the
// instant the caller inspects any capture group, not merely a style
// nit (this is exactly the bug this function's own test suite caught in
// an earlier version of this file -- see the doc comment on the 4-arg
// overload above). Overload resolution prefers this rvalue-reference
// overload over the const-lvalue-reference one above for a temporary
// argument, so this turns the mistake into a compile error instead of a
// latent runtime bug. Callers needing to search a temporary must bind it
// to a named std::string first (exactly the same fix plain
// std::regex_search callers already have to make).
RegexSearchOutcome regex_search_bounded(std::string&& input, const std::regex& re, std::smatch* out,
                                         std::chrono::milliseconds timeout = kRegexSearchTimeout) = delete;

// Convenience overload for callers (e.g. a decoder's optional "prematch"
// check, or FieldCondition::Op::regex's boolean-only test) that don't need
// capture groups. Safe to call with a temporary -- unlike the `out`-taking
// overload above, there's no iterator-into-a-temporary hazard when the
// only output is a bool.
inline RegexSearchOutcome regex_search_bounded(const std::string& input, const std::regex& re,
                                                std::chrono::milliseconds timeout = kRegexSearchTimeout) {
    return regex_search_bounded(input, re, nullptr, timeout);
}

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_JSON_SAFETY_H
