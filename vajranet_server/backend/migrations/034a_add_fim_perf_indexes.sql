-- Documentation mirror of FIM_PERF_INDEXES (src/services/fimRegistryService.ts): the backend builds these
-- CONCURRENTLY in the background after boot. Canonical source: vajra_server/sql/migrations/0008a_fim_perf_indexes.sql.
-- Run OUTSIDE a transaction (plain psql -f, not -1).

-- migrate:no-transaction
-- FIM request-probe PERF indexes (vajra_fim). Idempotent. Requires 0008_fim_perf.sql.
--
-- RUN OUTSIDE A TRANSACTION: CREATE INDEX CONCURRENTLY is refused inside a transaction block. Apply
-- with plain psql (NO -1):   psql -v ON_ERROR_STOP=1 -f sql/migrations/0008a_fim_perf_indexes.sql
-- scripts/migrate.sh runs it in autocommit mode because of the first line above. The backend also
-- builds the same indexes CONCURRENTLY in a background step after boot when they are missing; both
-- appliers take the session advisory lock 727300 (not the 727299 DDL lock, so a long build never
-- blocks the transactional FIM DDL), so they never race on the same index.
--
-- WHY: the worker probes every pending Initialize / check-scan request for the newest dead-letter
-- row of its queue id and the newest answer of its (queue id, host). Without these indexes each probe
-- scans the whole table (measured: 200k DLQ rows + 500k query_result rows + 500 requests = 12.95 s per
-- worker tick; with them about 1 ms). The worker keeps working without them (slower) and keeps one
-- open fim_health warning 'FIM perf indexes missing: ...' until both exist and are VALID.
--
-- A CONCURRENTLY build that fails or is cancelled leaves an INVALID index of that name, which IF NOT
-- EXISTS then skips (and the worker keeps warning). Find and redo it:
--     SELECT indexrelid::regclass, indisvalid FROM pg_index
--      WHERE indexrelid::regclass::text IN ('idx_dead_letter_queue_table_id','idx_query_result_qname_host_id');
--     DROP INDEX CONCURRENTLY IF EXISTS idx_dead_letter_queue_table_id;   -- only if indisvalid = false
--     then run this file again.
--
-- This file is embedded verbatim by the backend (TypeScript template literal): keep it free of
-- backslashes, backticks and dollar-brace sequences.

SELECT pg_advisory_lock(727300);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dead_letter_queue_table_id ON dead_letter_queue (table_name, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_query_result_qname_host_id ON query_result (query_name, host_identifier, id);
SELECT pg_advisory_unlock(727300);
