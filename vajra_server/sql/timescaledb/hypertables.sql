-- TimescaleDB hypertables for the high-volume event tables (fleet database).
--
-- Not part of the 0N_*.sql glob: it must run AFTER schema.sql, 02-08, the numbered
-- migrations (0002 uses CREATE INDEX CONCURRENTLY, which hypertables reject) and the
-- backend/db-extras files. docker-compose.yml runs it in the db-timescale service.
-- Safe to re-run. Skips itself on a Postgres without the timescaledb extension.
--
-- Matches the real schema: the time column is "unixtime" bigint = epoch SECONDS, and every
-- table has PRIMARY KEY (id), which is widened to (id, unixtime) because TimescaleDB needs
-- the partition column in every unique index. The id sequence is untouched, so
-- WHERE id = $1 lookups still use the primary-key index.
--
-- alerts is deliberately NOT converted: engine_v2/schema/incidents.sql has a foreign key
-- incident_alerts.alert_id -> alerts(id), and a hypertable cannot be the target of a foreign
-- key. Alerts are low volume anyway.
--
-- Retention is not set here (it deletes data); see sql/migrations/0002_event_retention.sql.

SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') AS has_ts \gset
\if :has_ts

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- "Now" for integer-time policies, in the same unit as unixtime (seconds).
CREATE OR REPLACE FUNCTION public.vajra_unix_now() RETURNS bigint
    LANGUAGE sql STABLE AS $$ SELECT extract(epoch FROM now())::bigint $$;

DO $$
DECLARE
    t text;
    pk text;
    pk_cols text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'bpf_process_events', 'bpf_socket_events', 'bpf_file_events',
        'win_process_events', 'win_socket_events', 'win_file_events',
        'process_events', 'socket_events', 'user_events'
    ] LOOP
        BEGIN
            IF to_regclass('public.' || t) IS NULL THEN
                RAISE NOTICE 'hypertables: % does not exist, skipped', t;
                CONTINUE;
            END IF;

            -- The partition column must be NOT NULL. Rows the server wrote without a time
            -- get the current time rather than 1970.
            EXECUTE format('UPDATE %I SET unixtime = extract(epoch FROM now())::bigint WHERE unixtime IS NULL', t);

            SELECT c.conname, string_agg(a.attname, ',' ORDER BY a.attname)
              INTO pk, pk_cols
              FROM pg_constraint c
              JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
             WHERE c.conrelid = ('public.' || t)::regclass AND c.contype = 'p'
             GROUP BY c.conname;

            IF pk_cols IS DISTINCT FROM 'id,unixtime'
               AND NOT EXISTS (SELECT 1 FROM timescaledb_information.hypertables
                                WHERE hypertable_schema = 'public' AND hypertable_name = t) THEN
                IF pk IS NOT NULL THEN
                    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, pk);
                END IF;
                EXECUTE format('ALTER TABLE %I ADD PRIMARY KEY (id, unixtime)', t);
            END IF;

            PERFORM create_hypertable(('public.' || t)::regclass, 'unixtime',
                                      chunk_time_interval => 86400,  -- 1 day, in seconds
                                      if_not_exists => TRUE, migrate_data => TRUE);
            PERFORM set_integer_now_func(('public.' || t)::regclass, 'public.vajra_unix_now');

            EXECUTE format('ALTER TABLE %I SET (timescaledb.compress, '
                           'timescaledb.compress_orderby = ''unixtime DESC, id DESC'', '
                           'timescaledb.compress_segmentby = ''host_identifier'')', t);
            PERFORM add_compression_policy(('public.' || t)::regclass, 3 * 86400, if_not_exists => TRUE);
            RAISE NOTICE 'hypertables: % converted', t;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'hypertables: % NOT converted: %', t, SQLERRM;
        END;
    END LOOP;
END $$;

-- Events per hour, for dashboards.
CREATE MATERIALIZED VIEW IF NOT EXISTS events_per_hour
WITH (timescaledb.continuous) AS
SELECT time_bucket(3600::bigint, unixtime) AS bucket,
       host_identifier,
       COUNT(*) AS event_count
FROM bpf_process_events
GROUP BY 1, host_identifier
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_per_hour',
    start_offset => 604800::bigint, end_offset => 3600::bigint,
    schedule_interval => INTERVAL '1 hour', if_not_exists => TRUE);

SELECT hypertable_name, num_chunks, compression_enabled
  FROM timescaledb_information.hypertables ORDER BY 1;

\else
\echo 'hypertables: timescaledb extension not available in this Postgres - event tables stay plain tables'
\endif
