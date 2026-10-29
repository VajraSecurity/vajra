-- =====================================================
-- Production Performance Indexes (OPTIMIZED)
-- =====================================================
-- Reduced from ~90 indexes to ~45 essential indexes.
--
-- AUDIT FINDINGS (March 2026):
--   - 72 GB of index overhead on 162 GB database (44% bloat!)
--   - 30+ indexes had ZERO scans (never used by any query)
--   - 2 JSONB indexes were INVALID (metadata/event_data are TEXT, not JSONB)
--   - Multiple redundant/overlapping indexes on same columns
--   - Several indexes on columns never used in WHERE/ORDER BY
--
-- WHAT WAS REMOVED AND WHY:
--   REMOVED: idx_*_time_id (unixtime DESC, id) — 6 large indexes (~11 GB)
--     REASON: Zero scans. No query uses ORDER BY unixtime DESC, id.
--             All polling queries use WHERE is_processed = false ORDER BY id ASC.
--
--   REMOVED: idx_*_host_time on event tables (except win_process_events) — 7 indexes
--     REASON: Zero scans on bpf_* and other event tables. The C++ code never
--             queries events by host+unixtime; it processes by is_processed flag.
--             Only win_process_events host_time was kept (833K scans from API).
--
--   REMOVED: idx_bpf_process_events_pid (host_identifier, pid, unixtime DESC)
--     REASON: Redundant with idx_bpf_process_events_pid_host_time which covers
--             the same query pattern. Was 3.2 GB of duplicated index space.
--
--   REMOVED: idx_*_pid_host_unixtime (pid, host_identifier, unixtime) — 6 indexes (~7 GB)
--     REASON: Zero scans. Redundant with existing _pid_host_time indexes.
--
--   REMOVED: idx_bpf_process_events_syscall — 796 MB, zero scans
--     REASON: No C++ query filters by syscall alone.
--
--   REMOVED: idx_bpf_process_events_uid — 735 MB, zero scans
--     REASON: No query filters by uid alone.
--
--   REMOVED: idx_bpf_process_events_cmdline (GIN full-text) — 363 MB, zero scans
--     REASON: No full-text search on cmdline in codebase.
--
--   REMOVED: idx_bpf_socket_events_remote/local — 1.7 GB combined, zero scans
--     REASON: Threat intel IP lookup uses ip_tables, not socket event columns.
--
--   REMOVED: idx_bpf_file_events_path — 889 MB, zero scans
--     REASON: No file event path lookup query found.
--
--   REMOVED: idx_bpf_file_events_pid_host_time — 3.5 GB, zero scans
--     REASON: No query does parent lookup on bpf_file_events.
--
--   REMOVED: idx_win_*_eventid — 86 MB combined, zero scans
--     REASON: No query filters by eventid.
--
--   REMOVED: idx_win_registry_events_target/action — zero scans
--     REASON: No query in codebase uses these columns for filtering.
--
--   REMOVED: idx_alerts_technique_open, idx_alerts_is_open, idx_alerts_host_open — zero scans
--     REASON: Redundant. idx_alerts_host_time covers API queries.
--
--   REMOVED: idx_alerts_event_id_zero, idx_alerts_alert_type — zero scans
--     REASON: UI fallback queries were never executed in practice.
--
--   REMOVED: idx_alerts_metadata_gin — INVALID (metadata is TEXT, not JSONB)
--   REMOVED: idx_dlq_event_data_gin — INVALID (event_data is TEXT, not JSONB)
--
--   REMOVED: idx_nodes_agent_online, idx_nodes_isolated — zero scans
--     REASON: nodes table is tiny; sequential scan is faster.
--
--   REMOVED: idx_*_name_version (programs, deb/rpm_packages) — zero scans
--     REASON: No query filters by name+version.
--
--   REMOVED: idx_query_result_name — zero scans
--   REMOVED: idx_bpf_process_events_tree_processing — 501 MB, zero scans
--   REMOVED: idx_enrollment_attempts_ip_success — zero scans (ip_time covers it)
--   REMOVED: idx_registry_host_processed — zero scans
--   REMOVED: idx_etc_services_host_processed — zero scans
--   REMOVED: idx_win_process_events_parent_guid_host — zero scans
--   REMOVED: idx_win_socket_events_guid_host_time — zero scans
--   REMOVED: idx_win_file_events_guid_host_time — zero scans
--   REMOVED: idx_bpf_socket_events_pid_host_time — zero scans
--
-- ESTIMATED SAVINGS: ~45-50 GB of index space
--
-- DEPLOYMENT:
--   1. Run AFTER schema.sql
--   2. Use CONCURRENTLY to avoid blocking writes
--   3. Run 03_drop_unused_indexes.sql to remove old indexes and reclaim space
--   4. Run VACUUM FULL on large tables during maintenance window
-- =====================================================

-- =====================================================
-- SECTION 1: CRITICAL — Event Processing Polling Indexes
-- =====================================================
-- These are the HOTTEST indexes. Every processing cycle queries:
--   WHERE is_processed = false ORDER BY id ASC LIMIT N
-- Partial indexes keep them small (only unprocessed rows).

-- BPF Process Events (272K scans, 47M tuples read)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_processed
ON bpf_process_events(is_processed, id)
WHERE is_processed = FALSE;

-- BPF Socket Events (282K scans, 281M tuples read)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_socket_events_processed
ON bpf_socket_events(is_processed, id)
WHERE is_processed = FALSE;

-- BPF File Events (278K scans, 131M tuples read)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_file_events_processed
ON bpf_file_events(is_processed, id)
WHERE is_processed = FALSE;

-- Windows Process Events (245K scans)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_processed
ON win_process_events(is_processed, id)
WHERE is_processed = FALSE;

-- Windows Socket Events (245K scans)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_socket_events_processed
ON win_socket_events(is_processed, id)
WHERE is_processed = FALSE;

-- Windows File Events (245K scans)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_file_events_processed
ON win_file_events(is_processed, id)
WHERE is_processed = FALSE;

-- Legacy Process Events
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_events_processed
ON process_events(is_processed, id)
WHERE is_processed = FALSE;

-- Legacy Socket Events
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_socket_events_processed
ON socket_events(is_processed, id)
WHERE is_processed = FALSE;

-- User Events
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_events_processed
ON user_events(is_processed, id)
WHERE is_processed = FALSE;

-- =====================================================
-- SECTION 2: Rule Builder Processing Indexes
-- =====================================================
-- Rule builder polls: WHERE is_processed_rule_builder = false
--
-- ⚠ WARNING: As of March 2026, the rule builder has NEVER processed any BPF rows.
--   All 47M+ rows have is_processed_rule_builder = FALSE, making these "partial"
--   indexes as large as full indexes (~13 GB for BPF tables alone, ZERO scans).
--   RECOMMENDATION: Only create these AFTER the rule builder service is started.
--   If rule builder is not in use, skip this section to save ~13 GB.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_processed_rb
ON bpf_process_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_socket_events_processed_rb
ON bpf_socket_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_file_events_processed_rb
ON bpf_file_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_processed_rb
ON win_process_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_socket_events_processed_rb
ON win_socket_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_file_events_processed_rb
ON win_file_events(is_processed_rule_builder, id)
WHERE is_processed_rule_builder = FALSE;

-- =====================================================
-- SECTION 3: Python Rule Engine Processing Indexes
-- =====================================================
-- Python worker polls: WHERE is_processed_py = false
--
-- ⚠ WARNING: As of March 2026, the Python rule engine has NEVER processed any rows.
--   All rows have is_processed_py = FALSE — these partial indexes are full-table
--   sized (~13 GB for BPF tables, ZERO scans).
--   RECOMMENDATION: Only create these AFTER the Python rule engine is started.
--   If Python engine is not in use, skip this section to save ~13 GB.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_processed_py
ON bpf_process_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_socket_events_processed_py
ON bpf_socket_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_file_events_processed_py
ON bpf_file_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_processed_py
ON win_process_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_socket_events_processed_py
ON win_socket_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_file_events_processed_py
ON win_file_events(is_processed_py, id)
WHERE is_processed_py = FALSE;

-- =====================================================
-- SECTION 4: Process Tree Building Indexes
-- =====================================================
-- ProcessTreeBuilder queries:
--   Backward: WHERE pid = X AND host_identifier = Y ORDER BY time DESC
--   Forward:  WHERE parent = X AND host_identifier = Y ORDER BY time DESC
--   NULL tree: WHERE (process_tree IS NULL OR process_tree = '') LIMIT 500

-- Process tree NULL detection (partial — only rows needing tree)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_events_tree_null
ON process_events(id)
WHERE (process_tree IS NULL OR process_tree = '');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_socket_events_tree_null
ON socket_events(id)
WHERE (process_tree IS NULL OR process_tree = '');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_events_tree_null
ON user_events(id)
WHERE (process_tree IS NULL OR process_tree = '');

-- CRITICAL: Parent process lookup — backward tree (14.2M scans, 17.8M reads)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_pid_host_time
ON bpf_process_events(pid, host_identifier, time DESC);

-- CRITICAL: Child process lookup — forward tree
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_parent_host_time
ON bpf_process_events(parent, host_identifier, time DESC);

-- Legacy process events tree building
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_events_pid_host_time
ON process_events(pid, host_identifier, time DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_process_events_ppid_host_time
ON process_events(ppid, host_identifier, time DESC);

-- Windows process tree building (25K scans, 1.6M reads)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_guid_host_time
ON win_process_events(process_guid, host_identifier, time DESC);

-- Windows forward tree: find children by parent_pid
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_parent_host_time
ON win_process_events(parent_pid, host_identifier, time DESC);

-- =====================================================
-- SECTION 5: Snapshot Result (Process Tree Fallback)
-- =====================================================
-- 13.6M scans — the most frequently used index in the database!

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_result_lookup
ON snapshot_result(host_identifier, query_name, unixtime DESC)
WHERE query_name = 'processes';

-- =====================================================
-- SECTION 6: API / UI Query Indexes
-- =====================================================
-- Only keeping indexes with proven scan activity.

-- win_process_events host_time: 833K scans, 41B tuples read (API queries)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_win_process_events_host_time
ON win_process_events(host_identifier, unixtime DESC);

-- Alerts by host: 430 scans, 3M tuples (API alert listing)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_host_time
ON alerts(host_identifier, unixtime DESC);

-- Alert correlation by pid: 774 scans (detection graph)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_pid
ON alerts(host_identifier, pid, unixtime DESC);

-- =====================================================
-- SECTION 7: Forensic Path Lookup
-- =====================================================
-- bpf_process_events path: 192K scans, 19.7M reads (active usage)

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bpf_process_events_path
ON bpf_process_events(path text_pattern_ops)
WHERE path IS NOT NULL;

-- =====================================================
-- SECTION 8: Server / Authentication Indexes
-- =====================================================
-- nodes.node_key: UNIQUE constraint (1.27M scans) — already exists from schema
-- nodes.host_identifier: PRIMARY KEY — already exists from schema

-- Query queue: 214K scans (distributed query delivery)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_query_queue_host_sent
ON query_queue(host_identifier, sent)
WHERE sent = FALSE;

-- Enrollment rate limiting
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enrollment_attempts_ip_time
ON enrollment_attempts(ip_address, attempt_time);

-- =====================================================
-- SECTION 9: Package / Vulnerability Indexes
-- =====================================================
-- Only host_identifier lookups needed.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_deb_packages_host
ON deb_packages(host_identifier);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rpm_packages_host
ON rpm_packages(host_identifier);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_programs_host
ON programs(host_identifier);

-- =====================================================
-- COMPLETION MESSAGE
-- =====================================================
DO $$
DECLARE
    total_indexes INT;
    db_size TEXT;
    index_size TEXT;
BEGIN
    SELECT COUNT(*) INTO total_indexes
    FROM pg_indexes
    WHERE schemaname = current_schema();

    SELECT pg_size_pretty(pg_database_size(current_database())) INTO db_size;

    SELECT pg_size_pretty(SUM(pg_relation_size(indexrelid))::BIGINT) INTO index_size
    FROM pg_index
    JOIN pg_class ON pg_class.oid = pg_index.indexrelid
    WHERE pg_class.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema());

    RAISE NOTICE '=======================================================';
    RAISE NOTICE 'Optimized Production Indexes Applied';
    RAISE NOTICE '=======================================================';
    RAISE NOTICE 'Total Indexes (incl PKs/UNIQUEs): %', total_indexes;
    RAISE NOTICE 'Database Size: %', db_size;
    RAISE NOTICE 'Index Size: %', index_size;
    RAISE NOTICE '';
    RAISE NOTICE 'Next: Run 03_drop_unused_indexes.sql to reclaim ~45 GB';
    RAISE NOTICE '=======================================================';
END $$;
