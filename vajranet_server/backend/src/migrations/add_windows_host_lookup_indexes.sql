-- Fleet DB: host-scoped indexes for three hot backend lookups.
--
-- Run this against the `fleet` database (POSTGRES_DB1). Safe to re-run:
-- IF NOT EXISTS guards every statement. CONCURRENTLY cannot run inside a
-- transaction block, so apply with autocommit on, e.g.
-- `psql -f add_windows_host_lookup_indexes.sql`.
--
-- These are pure access-path changes. No query text, result set, or ordering
-- changes anywhere in the application.

-- 1 + 2. security_profile_info and windows_security_center.
--
-- Both are ~1.05M-row append-only telemetry tables, and both carry only their
-- primary key:
--
--   security_profile_info   1,055,977 rows   ->  security_profile_info_pkey
--   windows_security_center 1,055,206 rows   ->  windows_security_center_pkey
--
-- controllers/windows/security_profile_info.ts and .../security_center.ts both
-- run `WHERE host_identifier = $1 ... ORDER BY unixtime DESC LIMIT 1`. With no
-- index leading on host_identifier the only usable path is the primary key, so
-- the planner walks the `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` window —
-- effectively the whole table — and applies host_identifier as a post-filter.
--
-- (host_identifier, unixtime DESC) satisfies both the predicate and the sort,
-- so the plan collapses to an index scan that stops at the first qualifying
-- row. This is the same index shape already proven on windows_security_products
-- and windows_firewall_rules.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_profile_info_host_unixtime
  ON public.security_profile_info (host_identifier, unixtime DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_security_center_host_unixtime
  ON public.windows_security_center (host_identifier, unixtime DESC);

-- 3. nodes, keyed on lower(host_identifier).
--
-- `nodes` holds only 74 rows, but ~18 backend call sites match it with
-- `LOWER(n.host_identifier) = LOWER($1)` — controllers/vulnerabilities/
-- vulnexus_read.ts, utils/patchBundleSelect.ts, controllers/general-graphs/
-- top5_machine_alerts.ts and top5_machine_usb.ts, controllers/nodes/
-- patch_gap.ts. Wrapping the column in lower() makes nodes_pkey unmatchable,
-- so every one of those scans all 74 rows.
--
-- On row count alone that would be trivial. It is not, because the table's
-- heap is heavily bloated: the agent heartbeat drives tens of millions of
-- last_seen UPDATEs, leaving ~39MB of pages behind 74 live rows. A full scan
-- therefore touches thousands of buffers rather than a handful, and these
-- appear as *joins* on dashboard paths, where the cost is paid per query
-- rather than being cut short by a LIMIT.
--
-- INCLUDE (hostname) additionally covers the two top5_* graph endpoints, which
-- read hostname straight off this join and can then take an index-only scan.
--
-- lower(text) is IMMUTABLE, so the expression index is legal and matches the
-- predicate exactly.
--
-- This indexes the bloat away from the query path only; it does not shrink the
-- heap. Reclaiming that needs a VACUUM FULL or pg_repack, which is a DBA
-- maintenance decision, not a code change.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_nodes_lower_host_identifier
  ON public.nodes (lower(host_identifier)) INCLUDE (hostname);
