#ifndef VAJRA_ENGINE_RULE_H
#define VAJRA_ENGINE_RULE_H

#include <cctype>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "vajra_engine/NormalizedEvent.h"
#include "vajra_engine/OccurrenceHistory.h"

namespace vajra_engine {

// Per-list key->value store (CDB-style). `add()` records a key with no
// meaningful value (existence-only membership, used by the `in_list`
// condition op); `set()` records an actual value (used by threat-intel/IOC
// lookups that carry e.g. a reputation score or source label alongside the
// key). `contains()` checks presence regardless of how the key was added.
// Populated from a ruleset's "lists" section, or -- unlike every other piece
// of RuleEngine's state -- also from a background threat-intel feed
// refresher thread (see ThreatIntelFeed) running concurrently with the
// single-threaded Kafka consumer loop that calls RuleEngine::eval(). That
// concurrent-write requirement is exactly why this class (and only this
// class) is internally synchronized with a shared_mutex, instead of relying
// on RuleEngine's documented single-threaded assumption: reads (contains/
// get/size, called from eval()) take a shared lock, writes (add/set/
// replace_list, called from ruleset loading OR the feed refresher) take an
// exclusive one.
class ListStore {
public:
    void add(const std::string& list, std::string key) {
        std::unique_lock lock(mutex_);
        lists_[list][std::move(key)] = "";
    }

    void set(const std::string& list, std::string key, std::string value) {
        std::unique_lock lock(mutex_);
        lists_[list][std::move(key)] = std::move(value);
    }

    // Atomically replaces a named list's entire contents (existence-only,
    // like add()) -- used by ThreatIntelFeed so a refresh is all-or-nothing
    // from a reader's perspective: contains()/get() never observe a
    // half-old/half-new list mid-refresh, and entries removed from the
    // upstream feed (e.g. an IP delisted) are actually dropped, not just
    // never-updated.
    void replace_list(const std::string& list, std::map<std::string, std::string> entries) {
        std::unique_lock lock(mutex_);
        lists_[list] = std::move(entries);
    }

    bool contains(const std::string& list, const std::string& key) const {
        std::shared_lock lock(mutex_);
        auto it = lists_.find(list);
        return it != lists_.end() && it->second.count(key) != 0;
    }

    std::optional<std::string> get(const std::string& list, const std::string& key) const {
        std::shared_lock lock(mutex_);
        auto it = lists_.find(list);
        if (it == lists_.end()) return std::nullopt;
        auto key_it = it->second.find(key);
        if (key_it == it->second.end()) return std::nullopt;
        return key_it->second;
    }

    std::size_t size() const {
        std::shared_lock lock(mutex_);
        std::size_t total = 0;
        for (const auto& [name, members] : lists_) total += members.size();
        return total;
    }

    // Case-insensitive counterparts to contains()/get(), for lists whose
    // members are naturally case-insensitive in practice (domain names,
    // process/file names on case-insensitive filesystems, etc.) -- an
    // operator authoring a "deny_domains" list shouldn't have to enumerate
    // every case variant of each entry. NOT currently invoked by
    // FieldCondition::matches()'s in_list/in_list_active handling: that
    // switch is implemented in RuleEngine.cpp, outside this file's
    // ownership boundary for this engagement (see
    // .team/charter-rule-engine.md's roster) -- wiring an "icase" flag
    // through to these two methods there is a one-line addition per case,
    // spec'd in full in .team/mailbox/re-vega.md. Exercised directly (not
    // via FieldCondition) by engine_v2/tests/test_list_store_icase.cpp in
    // the meantime, so the capability itself is proven correct and ready.
    //
    // Linear scan (O(list size)), not a separate indexed structure --
    // add()/set()/replace_list() are deliberately left untouched so
    // ThreatIntelFeed's existing write path (and its performance
    // characteristics for the lists it refreshes) is unaffected by this
    // being present but unused. Revisit with a shadow lowercase-keyed index
    // if/when this is wired up and profiling shows the scan cost matters
    // for very large lists.
    bool contains_icase(const std::string& list, const std::string& key) const {
        std::shared_lock lock(mutex_);
        auto it = lists_.find(list);
        if (it == lists_.end()) return false;
        const std::string lower_key = to_lower_ascii(key);
        for (const auto& [member, value] : it->second) {
            (void)value;
            if (to_lower_ascii(member) == lower_key) return true;
        }
        return false;
    }

    std::optional<std::string> get_icase(const std::string& list, const std::string& key) const {
        std::shared_lock lock(mutex_);
        auto it = lists_.find(list);
        if (it == lists_.end()) return std::nullopt;
        const std::string lower_key = to_lower_ascii(key);
        for (const auto& [member, value] : it->second) {
            if (to_lower_ascii(member) == lower_key) return value;
        }
        return std::nullopt;
    }

private:
    static std::string to_lower_ascii(std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    mutable std::shared_mutex mutex_;
    std::map<std::string, std::map<std::string, std::string>> lists_;
};

struct FieldCondition {
    enum class Op {
        equals,
        not_equals,
        contains,
        not_contains,
        regex,
        exists,
        gt,
        lt,
        gte,
        lte,
        between,  // value = "min,max"; fails closed if either bound or the field isn't fully numeric
        in_list,
        // Like in_list, but additionally requires the key's stored value
        // (ListStore::get) not be the sentinel string "disabled" -- lets an
        // operator suspend monitoring for one entry (e.g. one IP inside an
        // IP group) without removing it from the list, by writing
        // {"<key>": "disabled"} into a CDB-style (object-form) "lists"
        // entry. A membership-only entry (array-form list, added via
        // ListStore::add) stores an empty value, which is != "disabled", so
        // it's active by default.
        in_list_active
    };

    std::string field;
    Op op = Op::equals;
    std::string value;
    bool icase = false;
    std::shared_ptr<std::regex> compiled;  // set by RuleEngine::load() for op == regex

    bool matches(const NormalizedEvent& ev, const ListStore& lists) const;
};

struct Rule {
    int id = 0;
    int level = 0;
    std::string description;
    std::vector<std::string> groups;
    std::vector<std::string> mitre;
    std::string event_type;  // empty = any; ignored if event_types is non-empty (see below)
    std::string os;          // empty = any
    std::optional<int> if_sid;
    bool no_log = false;  // anchor rule: participates in chaining, never alerts
    std::vector<FieldCondition> conditions;
    // Operator on/off switch: a disabled rule is skipped before any
    // condition/regex work and never appears in matched_ids, so it also
    // can't satisfy another rule's if_sid/if_matched_sid dependency --
    // disabling a rule behaves as if it weren't loaded at all, for matching
    // purposes. Still counted by RuleEngine::size() (that reflects "loaded",
    // not "active"). Defaults true so every existing rule construction
    // (hand-written Rule{...} literals, parsed rulesets predating this
    // field) is unaffected.
    bool enabled = true;
    // Additive alternative to the single event_type string above: if
    // non-empty, the event must match one of these types instead of
    // event_type. Lets one rule scope to more than one event type (e.g.
    // ["bpf_socket", "win_socket"]) without a single string field having to
    // support wildcards/lists. Empty (the default) preserves existing
    // single-event_type behavior exactly.
    std::vector<std::string> event_types;

    // Correlation (all optional, disabled by default):
    // - frequency > 1: this rule must have matched `frequency` times within
    //   the last `timeframe_seconds` (including the current match) to fire.
    // - if_matched_sid: fires only if at least one of these rule ids matched
    //   within the last `timeframe_seconds` -- cross-event, unlike if_sid's
    //   same-event chaining. Requires timeframe_seconds > 0 (fails closed
    //   otherwise -- a correlation rule with no window is a misconfiguration,
    //   not "always/never" by accident).
    // - same_field: groups occurrences for both of the above by this field's
    //   value (e.g. "network.remote_address"); empty = group by
    //   host_identifier (i.e. "per host").
    int frequency = 0;
    int timeframe_seconds = 0;
    std::string same_field;
    std::vector<int> if_matched_sid;

    // Scope + field conditions only (event_type/os/if_sid/conditions) --
    // does not consult or mutate correlation state.
    bool base_matches(const NormalizedEvent& ev, const std::set<int>& matched_ids,
                       const ListStore& lists) const;

    // Correlation gate: called only after base_matches() succeeds. Assumes
    // the caller (RuleEngine::eval) has already recorded this occurrence in
    // `history` for tracked rules before calling this, since a frequency
    // check must see the current match as one of the counted occurrences.
    bool correlation_matches(OccurrenceHistory& history, const std::string& group_key,
                              std::int64_t now_ms) const;
};

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_RULE_H
