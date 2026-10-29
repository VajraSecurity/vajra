-- =====================================================
-- Drop Unused Indexes to Reclaim Disk Space
-- =====================================================
-- Run this AFTER verifying the new optimized indexes are working.
-- Drops ~45 indexes that had ZERO scans or were redundant.
--
-- WARNING: Run during a maintenance window.
-- After dropping, run VACUUM FULL on large tables to reclaim disk.
--
-- ESTIMATED SPACE SAVINGS: ~45-50 GB
-- =====================================================

-- =====================================================
-- SECTION 1: Drop *_time_id indexes (unixtime DESC, id)
-- =====================================================
-- Zero scans on all event tables. No query uses this ordering.
-- Combined size: ~11 GB

DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_time_id;    -- 2.9 GB, 14 scans (negligible)
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_time_id;     -- 3.2 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_file_events_time_id;       -- 4.8 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_process_events_time_id;    -- 72 MB, 2 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_socket_events_time_id;     -- 323 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_file_events_time_id;       -- 65 MB, 156K scans (used by rule builder, but _processed_rb is better)
DROP INDEX CONCURRENTLY IF EXISTS idx_process_events_time_id;        -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_socket_events_time_id;         -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_user_events_time_id;           -- 8 KB, 0 scans

-- =====================================================
-- SECTION 2: Drop *_host_time indexes (host_identifier, unixtime DESC)
-- =====================================================
-- Zero scans on most event tables. Keep only win_process_events (833K scans).
-- Combined size: ~3.5 GB

DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_host_time;  -- 929 MB, 7 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_host_time;   -- 1 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_file_events_host_time;     -- 1.5 GB, 0 scans
-- KEEP: idx_win_process_events_host_time (833K scans)
DROP INDEX CONCURRENTLY IF EXISTS idx_win_socket_events_host_time;   -- 100 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_file_events_host_time;     -- 29 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_process_events_host_time;      -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_socket_events_host_time;       -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_user_events_host_time;         -- 8 KB, 0 scans

-- =====================================================
-- SECTION 3: Drop redundant/overlapping pid indexes
-- =====================================================
-- _pid_host_unixtime indexes are redundant with _pid_host_time
-- Combined size: ~7 GB

DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_pid_host_unixtime;  -- 3.2 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_file_events_pid_host_unixtime;     -- 3.1 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_pid_host_unixtime;   -- 1 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_process_events_pid_host_unixtime;  -- 100 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_socket_events_pid_host_unixtime;   -- 79 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_file_events_pid_host_unixtime;     -- 30 MB, 0 scans

-- idx_bpf_process_events_pid = (host_identifier, pid, unixtime DESC)
-- idx_bpf_process_events_pid_host_time = (pid, host_identifier, time DESC)
-- Despite 26M scans, ALL codebase queries use: WHERE pid=X AND host_identifier=Y ORDER BY time DESC
-- The planner picked _pid opportunistically but _pid_host_time covers the same equality predicates
-- and ALSO satisfies ORDER BY time DESC. After dropping _pid, queries will use _pid_host_time.
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_pid;        -- 3.3 GB, 26M scans (covered by pid_host_time)

-- =====================================================
-- SECTION 4: Drop detection/forensic indexes with zero scans
-- =====================================================
-- These were speculative indexes that no actual query uses.

DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_syscall;    -- 796 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_uid;        -- 735 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_cmdline;    -- 363 MB (GIN full-text), 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_remote;      -- 1 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_local;       -- 722 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_file_events_path;          -- 889 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_file_events_pid_host_time; -- 3.5 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_process_events_tree_processing; -- 501 MB, 0 scans

-- Zero-scan pid_host_time indexes on non-process tables
DROP INDEX CONCURRENTLY IF EXISTS idx_bpf_socket_events_pid_host_time;   -- 1.8 GB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_socket_events_pid_host_time;       -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_user_events_pid_host_time;         -- 8 KB, 0 scans

-- =====================================================
-- SECTION 5: Drop Windows-specific zero-scan indexes
-- =====================================================

DROP INDEX CONCURRENTLY IF EXISTS idx_win_process_events_eventid;        -- 13 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_socket_events_eventid;         -- 47 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_file_events_eventid;           -- 26 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_registry_events_target;        -- 23 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_registry_events_action;        -- 1 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_process_events_parent_guid_host; -- 17 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_socket_events_guid_host_time;  -- 88 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_win_file_events_guid_host_time;    -- 19 MB, 0 scans

-- =====================================================
-- SECTION 6: Drop alert indexes with zero scans
-- =====================================================

DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_technique_open;     -- 8.7 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_is_open;            -- 6.9 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_host_open;          -- 7.1 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_event_id_zero;      -- 15 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_alert_type;         -- 7 MB, 0 scans
-- Note: idx_alerts_metadata_gin and idx_dlq_event_data_gin never existed
-- (they would have failed — metadata and event_data are TEXT, not JSONB)

-- =====================================================
-- SECTION 7: Drop miscellaneous zero-scan indexes
-- =====================================================

DROP INDEX CONCURRENTLY IF EXISTS idx_nodes_agent_online;            -- 16 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_nodes_isolated;                -- 16 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_programs_name_version;         -- 56 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_deb_packages_name_version;     -- 1.3 MB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_rpm_packages_name_version;     -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_query_result_name;             -- 8 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_enrollment_attempts_ip_success; -- 16 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_registry_host_processed;       -- 184 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_etc_services_host_processed;   -- 32 KB, 0 scans

-- execution_graphs: zero scans, zero code references in entire codebase
DROP INDEX CONCURRENTLY IF EXISTS idx_execution_graphs_alert_id;     -- 16 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_execution_graphs_created_at;   -- 16 KB, 0 scans
DROP INDEX CONCURRENTLY IF EXISTS idx_execution_graphs_graph_status; -- 16 KB, 0 scans

-- =====================================================
-- Post-Drop: Reclaim disk space
-- =====================================================
-- IMPORTANT: After dropping indexes, the space is not immediately returned
-- to the OS. Run VACUUM FULL during a maintenance window on the big tables:
--
--   VACUUM FULL bpf_file_events;     -- was 53 GB total
--   VACUUM FULL bpf_process_events;  -- was 51 GB total
--   VACUUM FULL bpf_socket_events;   -- was 33 GB total
--   VACUUM FULL win_socket_events;   -- was 4.7 GB total
--
-- WARNING: VACUUM FULL locks the table exclusively. Plan for downtime.
-- Alternative: Use pg_repack extension for online table repacking.

DO $$
DECLARE
    total_indexes INT;
    index_size TEXT;
BEGIN
    SELECT COUNT(*) INTO total_indexes
    FROM pg_indexes
    WHERE schemaname = current_schema()
    AND indexname NOT LIKE '%_pkey'
    AND indexname NOT LIKE '%_key';

    SELECT pg_size_pretty(SUM(pg_relation_size(indexrelid))::BIGINT) INTO index_size
    FROM pg_index
    JOIN pg_class ON pg_class.oid = pg_index.indexrelid
    WHERE pg_class.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema());

    RAISE NOTICE '=======================================================';
    RAISE NOTICE 'Unused Indexes Dropped Successfully';
    RAISE NOTICE '=======================================================';
    RAISE NOTICE 'Remaining Custom Indexes: %', total_indexes;
    RAISE NOTICE 'Total Index Size (incl PKs): %', index_size;
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '  1. Monitor query performance for 24-48 hours';
    RAISE NOTICE '  2. Run VACUUM FULL on large tables during maintenance';
    RAISE NOTICE '  3. Check pg_stat_user_indexes for any regressions';
    RAISE NOTICE '=======================================================';
END $$;
