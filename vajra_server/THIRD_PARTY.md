# Third-party components

The MIT license in `LICENSE` covers the Vajra code in this repository. These components keep
their own licenses.

| Component | Where | License |
|---|---|---|
| nlohmann/json | `3rdparty/json.hpp` | MIT |
| Catch2 v2 | `tests/catch2/catch.hpp` | Boost Software License 1.0 |
| libpqxx 7.8.1 | fetched into `3rdparty/local` at build time | BSD-3-Clause |
| Boost | system package | Boost Software License 1.0 |
| librdkafka | system package | BSD-2-Clause |
| OpenSSL, libcurl | system packages | Apache-2.0 (OpenSSL 3), curl license |
| Sigma detection rules | converted rules in `engine_v2/rules/ruleset.json` (descriptions end in `[sigma:NNN]`) | Detection Rule License (DRL) 1.1: attribution to the original rule authors is required |

Notes:

- The Sigma-derived rules keep the credit of their original authors (see the SigmaHQ
  repository for each rule's author). Before publishing, confirm the attribution you provide
  satisfies the DRL, or replace those rules.
- The decoder and correlation design is inspired by Wazuh's approach; no Wazuh code or rule
  files are included.
- This list was written by hand and is not a legal review. Check it against the versions you ship.
