What was actually wrong
1. It wasn't raw Sigma — it was someone else's already-broken JSON conversion. 573 of 582 entries were a prior translation attempt (only 9 files were genuine untranslated Sigma YAML), and that conversion itself had systematic bugs:

2. Wrong event_type values (the single biggest cause of silently-dead rules). The zip used Postgres/osquery table names — win_process_events, windows_eventlog, process_events — instead of the actual value the engine's decoder puts on the wire: win_process, bpf_process, etc. Matching is exact-string, so these rules loaded fine and simply never matched anything, forever, with no error.

3. op: "endswith" (and "in") aren't real operators — and this fails in the worst possible way. The loader only understands a fixed op list. Hit one unrecognized op anywhere in a combined ruleset file, and the loader doesn't reject just that rule — it silently drops your entire ruleset and falls back to 6 built-in rules. Fixed a fleet on this file thinking you have hundreds of rules active, you'd actually have 6, with only a stderr line as evidence.

4. condition_groups (OR) and not_conditions (negation) aren't understood by the loader at all — and this is worse than "doesn't fire." The loader only reads a flat "conditions" AND-list. Feed it a condition_groups block and it's silently dropped, not rejected — for 108 rules this didn't make them inert, it made them match on far less than intended (a false-positive generator, since the OR-restriction that was supposed to narrow the match just vanishes).

5. Two real bugs baked into the zip's own regex values: (?i) inline case-flags (not valid in C++'s regex grammar — these conditions silently compile-fail and permanently never match, without failing the whole load) and at least one genuinely catastrophic-backtracking pattern.

6. null-valued conditions ({"op":"equals","value":null}) with an undefined "field is absent" intent — the engine's equals requires a real value, so these are just malformed.

7. IDs are only unique within one category folder, not across the whole zip — the same id means two unrelated rules in different files.

Nothing above was a data problem — every one of these is a rule-authoring/tooling defect, fixable by writing correct JSON. Separately, a real chunk of rules target telemetry (windows_eventlog, classic non-eBPF Linux tables) that mostly doesn't reach the engine at all — that's an ingestion-pipeline question, not a rule-writing one.



# Writing a rule for engine_v2 — correct template + the mistakes to avoid

Ground truth for everything below: `engine_v2/include/vajra_engine/RulesetLoader.h`'s
doc comment and `engine_v2/src/RulesetLoader.cpp` (read those directly if anything here
ever looks stale — this file is a snapshot, that source is the live truth). Validate
anything you write with the console's **Add Rule → Validate** button, or directly:

```
VAJRA_ENGINE_RULES=my_rules.json engine_v2/build/vajra_engine_v2_eval /dev/null
```
A correct file prints `N rule(s) active` with N matching your rule count and **no**
`unknown condition op` / `bad ruleset` / fallback-to-builtins line. That absence is
your proof — always check it, don't just eyeball the JSON.

---

## 1. Minimal valid detection rule

```json
{
  "rules": [
    {
      "id": 900001,
      "event_type": "win_process",
      "level": 3,
      "description": "certutil.exe used to decode a file (LOLBin abuse)",
      "groups": ["defense-evasion"],
      "mitre": ["T1140"],
      "conditions": [
        { "field": "process.command_line", "op": "contains", "value": "-decode", "icase": true },
        { "field": "process.executable", "op": "endswith", "value": "\\certutil.exe", "icase": true }
      ]
    }
  ]
}
```
- `id`, `event_type`, `conditions` are **required**. Everything else has a sane default.
- `conditions` is always an **AND list** — there is no OR primitive (see §3).
- Every op except `exists` **requires** `"value"` — a missing/null value is a load-time
  error now (it used to silently mean "matches empty string", which was itself a bug
  fixed earlier this engagement).
- `"value"` is always a JSON **string**, even for something that looks numeric
  (`"value": "5145"`, not `"value": 5145`) — the loader calls `.get<std::string>()` on
  it and a bare number will throw.

## 2. Use the REAL event_type, not the Postgres table name

This is the #1 thing that silently killed rules in the zip. `event_type` is the value
the engine's Kafka consumer actually sees, not the osquery/Postgres table name. Check
`engine_v2/src/Decoder.cpp`'s `alias_table()` for the authoritative list; as of this
writing:

| Real `event_type` | NOT this |
|---|---|
| `win_process` | ~~`win_process_events`~~ |
| `win_socket` | ~~`win_socket_events`~~ |
| `win_file` | ~~`win_file_events`~~ |
| `win_registry` | ~~`win_registry_events`~~ |
| `win_dns` / `win_dns_response` | ~~`win_dns_events`~~ |
| `win_ssl` | ~~`win_ssl_events`~~ |
| `win_http` | ~~`win_http_events`~~ |
| `windows_eventlog` | (this one IS the real table name — an intentional exception, see the Decoder alias table) |
| `bpf_process` | ~~`process_events`~~ (that's the *classic* non-eBPF table — different, and not Kafka-published at all) |
| `bpf_socket` | ~~`socket_events`~~ |
| `bpf_file` | ~~`file_events`~~ |

If you're not sure, grep `engine_v2/rules/ruleset.json` for a working example of the
event_type you need — those rules are already correctly mapped.

## 3. There's no OR — split into multiple rules instead

Sigma's `condition_groups` (any of these branches) has no engine equivalent. **Never
put it in as-is** (the loader silently ignores it, widening your rule). Instead, write
one real rule per OR-branch, sharing the common AND conditions, with the branch number
folded into the id and noted in the description (matches the convention used
throughout `engine_v2/rules/ruleset.json`):

```json
{
  "rules": [
    { "id": 900101, "event_type": "win_process", "level": 3,
      "description": "Suspicious bitsadmin usage [branch1: /transfer]",
      "conditions": [
        { "field": "process.executable", "op": "endswith", "value": "\\bitsadmin.exe", "icase": true },
        { "field": "process.command_line", "op": "contains", "value": "/transfer", "icase": true }
      ]
    },
    { "id": 900102, "event_type": "win_process", "level": 3,
      "description": "Suspicious bitsadmin usage [branch2: /addfile]",
      "conditions": [
        { "field": "process.executable", "op": "endswith", "value": "\\bitsadmin.exe", "icase": true },
        { "field": "process.command_line", "op": "contains", "value": "/addfile", "icase": true }
      ]
    }
  ]
}
```

## 4. Negation

- `NOT field == value` → use `"op": "not_equals"` directly.
- `NOT field contains value` → use `"op": "not_contains"` directly.
- `NOT field startswith/endswith/regex value` → there's no native negated form; write an
  anchored negative-lookahead regex instead, e.g. for "does not start with C:\Windows\":
  `{"field": "process.executable", "op": "regex", "value": "^(?!C:\\\\Windows\\\\)"}`.
  Keep it simple — a wrapped/quantified lookahead can trip the ReDoS screen; a plain
  `^(?!literal)` at the start of the pattern is safe.
- Negating a **multi-condition group** (`NOT (A AND B)`) needs De Morgan's law by hand:
  `NOT(A AND B) = (NOT A) OR (NOT B)` — which, per §3, becomes two branch-rules, one
  requiring `NOT A`, one requiring `NOT B` (both still carry every other positive
  condition the rule needs).

## 5. Field-matching operators, the full real list

`equals | not_equals | contains | not_contains | regex | exists | gt | lt | gte | lte |
between | in_list | in_list_active | startswith | endswith | cidr | windash_contains |
base64offset_contains`

The last five are Sigma-parity sugar (load-time rewritten into `regex` internally —
free to use, no penalty):
- `startswith` / `endswith` — anchored, metacharacter-safe (no regex-injection risk from
  the value itself).
- `cidr` — **IPv4 only** (`"value": "10.0.0.0/8"`), true bitwise membership. An IPv6
  value is a load-time error, not a silent no-op. If you need to match against a list
  of IPs including IPv6, use `in_list`/`in_list_active` instead (plain string
  membership, not CIDR math, so IPv6 strings work fine there).
- `windash_contains` — catches `-enc`, `/enc`, and Unicode-dash obfuscation in one
  condition (Sigma's `windash` modifier).
- `base64offset_contains` — catches a substring base64-encoded at any of the 3 real
  byte-alignment offsets (Sigma's `base64offset` modifier) — one condition instead of
  three manual base64(value) variants.
- `between` — `"value": "min,max"` (a comma-separated string, not an array).
- `icase: true` on any condition makes it case-insensitive — used on ~2/3 of the real
  rule corpus, don't forget it for anything path/command-line-shaped.

## 6. IOC list matching

```json
{
  "rules": [
    { "id": 900201, "event_type": "bpf_socket", "level": 4,
      "description": "Connection to a known-bad IP",
      "conditions": [
        { "field": "network.remote_address", "op": "in_list", "value": "denylist_ips" }
      ]
    }
  ],
  "lists": {
    "denylist_ips": ["185.220.101.45", "45.142.212.61"]
  }
}
```
`in_list_active` = same, but also requires the matched entry not be flagged inactive
(only meaningful for the object/key-value list form, e.g. a threat-intel feed's
`{"ip": "confidence-score"}` shape — plain membership lists like the array form above
are always "active").

## 7. Watching a named group of IPs (the `ip_watch_groups` shortcut)

If all you want is "alert on any connection to these IPs," skip hand-writing the rule
entirely:
```json
{
  "ip_watch_groups": [
    { "id": 900301, "name": "finance_servers", "level": 3,
      "description": "Connection to a monitored finance-segment IP" }
  ],
  "lists": { "watch:finance_servers": ["10.20.30.40"] }
}
```
This synthesizes the `bpf_socket`/`win_socket` + `in_list_active` rule for you. (The
console's IP Watch Groups tab does this exact thing with a UI on top, including CSV
bulk-import for the list.)

## 8. Correlating multiple rules into one incident

```json
{
  "correlations": [
    {
      "id": 950001,
      "type": "temporal_ordered",
      "description": "Recon -> credential access -> lateral movement, one host, in order",
      "rules": [624, 7121, 468001],
      "group_by": ["host_identifier"],
      "timespan": 1800,
      "level": 13,
      "groups": ["kill_chain"],
      "mitre": ["T1482", "T1552.006", "T1021.001"]
    }
  ]
}
```
Four `type`s: `event_count` (≥N matches among the listed rule ids, needs `"threshold"`),
`value_count` (≥N *distinct* values of `"field"`, needs `"field"` + `"threshold"`),
`temporal` (every listed rule id matched at least once, any order), `temporal_ordered`
(same, but in the listed order — the kill-chain shape above). All four need
`"timespan"` (seconds) > 0 or they fail closed. If any rule id you reference is one of
the ~62 that exist under the same number in more than one source file, the console's
validate/create response now returns a `warnings` field naming the collision — check
for it, since `"rules": [349]` can silently mean two unrelated techniques at once.

**Note**: correlation rules are hot-reloadable via SIGHUP the same as detection rules,
but the offline `vajra_engine_v2_eval`/console's Test Event tab does **not** evaluate
them — use the console's Simulate Correlation tab (feeds a real event *sequence*
through the actual correlation engine) to test these instead.

## 9. Checklist before you call a rule done

- [ ] `event_type` is a real wire value (§2), not a table name
- [ ] Every op is from the real list in §5 — no `"in"`, no `"endswith"` typo'd as
      something else
- [ ] No `condition_groups`/`not_conditions` left in as-is — split into branch-rules
      (§3) or translated to `not_contains`/`not_equals`/a lookahead (§4)
- [ ] Every `"value"` is a JSON string, even numeric-looking ones
- [ ] No inline `(?i)` in a regex — use `"icase": true` instead
- [ ] Ran it through Validate (console button, or `vajra_engine_v2_eval` directly) and
      confirmed the active-rule count matches what you expect — not just "it loaded"
