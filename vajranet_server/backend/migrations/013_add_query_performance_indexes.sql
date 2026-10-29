-- Fleet DB: indexes for a set of missing-index query-performance problems.
-- Every index here is additive: it changes which plan Postgres picks, and no
-- application query text was changed alongside them, so results and ordering
-- are unaffected.
--
-- Index column order must follow each query's actual ORDER BY / DISTINCT ON
-- column, not just its filter: id and unixtime are only near-monotonic in this
-- data and are not interchangeable.
--
-- CONCURRENTLY throughout so these can be applied to the live database without
-- blocking reads or writes. CONCURRENTLY cannot run inside a transaction block,
-- so apply this file with autocommit on (e.g. `psql -f 013_...sql`, not wrapped
-- in BEGIN/COMMIT).

-- windows/firewall_rules.ts's latest-snapshot lookup (ORDER BY unixtime DESC
-- LIMIT 1) and its main CTE (exact unixtime = $2 match) both need unixtime-led
-- access, not id-led: cost ~191,661 -> 1.04..5.79.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_firewall_rules_host_unixtime
  ON windows_firewall_rules (host_identifier, unixtime DESC);

-- windows_security_products (1.7M rows/334MB) is hit by 4 endpoints in two
-- distinct access patterns; one index each.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_security_products_host_name_time
  ON windows_security_products (host_identifier, name, unixtime DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_security_products_name_host_state
  ON windows_security_products (name, host_identifier, state);

-- nodes/node_ip.ts: interface_addresses holds only ~9-15 rows per host, so
-- (host_identifier, id DESC) is enough even though it does not match the
-- query's final ORDER BY. Total cost ~255 once the base filter uses it, and
-- sorting ~15 rows afterwards is negligible.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_interface_addresses_host_id
  ON interface_addresses (host_identifier, id DESC);

-- nodes/node_storage.ts: mounts and disk_encryption are the only 2 of the
-- file's 5 tables big enough to matter (logical_drives, disk_info and
-- bitlocker_info are all under ~4K rows and are deliberately left unindexed).
-- Each needs its own DISTINCT ON grouping column, not just id.
-- mounts: cost 9,131 -> 7,592, the index combining with the id-window filter.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mounts_host_path_unixtime
  ON mounts (host_identifier, path, unixtime DESC);
-- disk_encryption: the planner does not prefer this index today, because the
-- table's cost is already modest either way (~2,660-2,679, nowhere near the
-- tens of thousands the real problems sit at). Kept so it is in place as the
-- table grows; it is not a fix for anything measured today.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_disk_encryption_host_name_unixtime
  ON disk_encryption (host_identifier, name, unixtime DESC);

-- host_identifier LOWER() equality filters (patchBundleSelect.ts,
-- patch_gap.ts, vulnexus_read.ts). Casing is genuinely inconsistent fleet-wide
-- (deb/rpm_packages lowercase, programs uppercase), so the LOWER() calls in the
-- query text are correct and must stay, and only an expression index can serve
-- them.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_deb_packages_host_lower
  ON deb_packages (LOWER(host_identifier));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rpm_packages_host_lower
  ON rpm_packages (LOWER(host_identifier));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_programs_host_lower
  ON programs (LOWER(host_identifier));

-- patch_gap.ts's canonical_pkgs dedupe query needs name/arch/unixtime/id
-- beyond what a single-column expression index covers.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_deb_packages_host_lower_dedupe
  ON deb_packages (LOWER(host_identifier), name, arch, unixtime DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rpm_packages_host_lower_dedupe
  ON rpm_packages (LOWER(host_identifier), name, arch, unixtime DESC, id DESC);

-- idx_deb_packages_host_identifier duplicates idx_deb_packages_host exactly
-- (same single column), so it is pure write overhead.
DROP INDEX CONCURRENTLY IF EXISTS idx_deb_packages_host_identifier;

-- Not fixed by indexing alone.
--
-- wmi_bios_info (58.3M rows/8GB): neither (host_identifier, id DESC) nor
-- (host_identifier, name, id DESC) is chosen by the planner for the real
-- DISTINCT ON (name) query. Only 26 distinct host_identifier values exist here
-- and a single ordinary host can own 2.3M+ rows, so the query must visit a
-- large fraction of one host's history regardless of index shape. That is a
-- data-volume problem — BIOS info re-ingested with no dedup — and a real fix
-- needs ingestion-side deduplication or a query restructure, both out of scope
-- for an index-only pass. The index below is kept because it may help hosts
-- with smaller row counts; it does not help the worst offender.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_wmi_bios_info_host_name_id
  ON wmi_bios_info (host_identifier, name, id DESC);

-- windows_update_history (6.3M rows/3.4GB): the isolated base filter
-- (host_identifier + id range) uses this index cleanly (Index Only Scan, cost
-- ~95,325 against ~950K for a table-wide scan of that step), but the full query
-- — a CTE with a 5-column PARTITION BY plus ROW_NUMBER and a final
-- ORDER BY id DESC — stays on the existing id-ordered access, which avoids a
-- re-sort an index-driven plan would still need. Kept because it helps simpler
-- access patterns; it does not improve this hot path (~218,809).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_windows_update_history_host_id
  ON windows_update_history (host_identifier, id DESC);

-- memory_info (8.9M rows/1.6GB): node_details.ts's simple `ORDER BY id DESC
-- LIMIT 1` lookup matches this index directly and benefits. memory_info.ts's
-- aggregation query (GROUP BY FLOOR(unixtime/N)) benefits partially — the
-- index narrows the scan to this host's rows even though it doesn't match
-- the aggregation's grouping column.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memory_info_host_id
  ON memory_info (host_identifier, id DESC);

-- Deliberately not indexed — cost is trivial at current scale, on the same
-- precedent as the accepted 7,469-row `alerts` seq scan:
--   - alerts.unixtime-only filter (alert_export.ts) and alert_type/is_open
--     filter (clamav_summary.ts) — alerts is 7,469 rows.
--   - endpoint-groups/get_groups.ts's per-group node count — `nodes` is 72
--     rows, and it's a full-population JSONB aggregate no index could help.
--   - node_storage's logical_drives, disk_info, bitlocker_info — all under
--     ~4K rows.
