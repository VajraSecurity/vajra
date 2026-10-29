-- Network telemetry FQDN-correlation tables (PolyLogyx Windows extension).
--
-- Adds server-side storage + scheduling for three evented tables the sensor
-- already emits (custom_plgx_EnableDns / EnableSSL / EnableHttp are already true
-- in the win_config blob) but which had no landing tables:
--   win_dns_response_events  DNS answer: domain_name -> resolved_ip (has eid,
--                            shared with win_dns_events for exact query<->answer join)
--   win_ssl_events           TLS cert seen per connection: dns_names (SAN),
--                            server_name (SNI), ja3/ja3s, process_guid
--   win_http_events          HTTP request URL per connection, with process_guid
--
-- Purpose: attribute a destination FQDN (not just an IP) to each outbound
-- connection + owning process, for forensic root-cause. Column order/types match
-- hecg119/osq-ext-bin tables-schema and the existing win_dns_events pattern.
--
-- Idempotent and additive only. Safe to run on the live fleet DB: no existing
-- table, index, or config row is altered or dropped.

CREATE TABLE IF NOT EXISTS win_dns_response_events (
    id bigserial PRIMARY KEY,
    host_identifier varchar(40),
    hostname TEXT,
    unixTime bigint,
    event_type TEXT,
    action TEXT,
    eid TEXT,
    domain_name TEXT,
    request_type integer,
    request_class integer,
    resolved_ip TEXT,
    pid bigint,
    remote_address TEXT,
    remote_port integer,
    time bigint,
    utc_time TEXT,
    eventid integer,
    uptime bigint,
    is_processed boolean,
    is_processed_py boolean,
    is_processed_rule_builder boolean
);

CREATE TABLE IF NOT EXISTS win_ssl_events (
    id bigserial PRIMARY KEY,
    host_identifier varchar(40),
    hostname TEXT,
    unixTime bigint,
    event_type TEXT,
    action TEXT,
    eid TEXT,
    subject_name TEXT,
    issuer_name TEXT,
    serial_number TEXT,
    dns_names TEXT,
    server_name TEXT,
    ja3_md5 TEXT,
    ja3s_md5 TEXT,
    pid bigint,
    process_guid TEXT,
    process_name TEXT,
    remote_address TEXT,
    remote_port integer,
    time bigint,
    utc_time TEXT,
    eventid integer,
    uptime bigint,
    is_processed boolean,
    is_processed_py boolean,
    is_processed_rule_builder boolean
);

CREATE TABLE IF NOT EXISTS win_http_events (
    id bigserial PRIMARY KEY,
    host_identifier varchar(40),
    hostname TEXT,
    unixTime bigint,
    event_type TEXT,
    action TEXT,
    eid TEXT,
    url TEXT,
    pid bigint,
    process_guid TEXT,
    process_name TEXT,
    remote_address TEXT,
    remote_port integer,
    time bigint,
    utc_time TEXT,
    eventid integer,
    uptime bigint,
    is_processed boolean,
    is_processed_py boolean,
    is_processed_rule_builder boolean
);

-- Indexes supporting the correlation queries (Part 10/11 of the design doc).
-- Plain (non-CONCURRENTLY) CREATE INDEX is used deliberately: the tables are
-- empty at creation, so the index build is instant and takes no meaningful lock.
-- This also lets the whole file run inside a single transaction if desired
-- (CONCURRENTLY would forbid that). Run with:  psql -d fleet -f 07_add_network_fqdn_tables.sql
CREATE INDEX IF NOT EXISTS idx_win_dns_response_host_ip_time
    ON win_dns_response_events (host_identifier, resolved_ip, unixtime DESC);
CREATE INDEX IF NOT EXISTS idx_win_dns_response_eid
    ON win_dns_response_events (eid);
CREATE INDEX IF NOT EXISTS idx_win_ssl_events_host_time
    ON win_ssl_events (host_identifier, unixtime DESC);
CREATE INDEX IF NOT EXISTS idx_win_ssl_events_guid
    ON win_ssl_events (process_guid, host_identifier);
CREATE INDEX IF NOT EXISTS idx_win_http_events_host_time
    ON win_http_events (host_identifier, unixtime DESC);
CREATE INDEX IF NOT EXISTS idx_win_http_events_guid
    ON win_http_events (process_guid, host_identifier);

-- Scheduling + UI registration. Guarded so re-running does not create duplicates.
INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch)
SELECT '{"schedule":{"win_dns_response_events":{"interval":30,"query":"select * from win_dns_response_events","snapshot": false}}}', 'win_dns_response_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_queries WHERE query_name = 'win_dns_response_events');

INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch)
SELECT '{"schedule":{"win_ssl_events":{"interval":30,"query":"select * from win_ssl_events","snapshot": false}}}', 'win_ssl_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_queries WHERE query_name = 'win_ssl_events');

INSERT INTO config_queries (query, query_name, os_name, kernel_version, os_arch)
SELECT '{"schedule":{"win_http_events":{"interval":30,"query":"select * from win_http_events","snapshot": false}}}', 'win_http_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_queries WHERE query_name = 'win_http_events');

INSERT INTO config_table_name (table_name, os_name, kernel_version, os_arch)
SELECT 'win_dns_response_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_table_name WHERE table_name = 'win_dns_response_events');

INSERT INTO config_table_name (table_name, os_name, kernel_version, os_arch)
SELECT 'win_ssl_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_table_name WHERE table_name = 'win_ssl_events');

INSERT INTO config_table_name (table_name, os_name, kernel_version, os_arch)
SELECT 'win_http_events', 'Windows', '', '64'
WHERE NOT EXISTS (SELECT 1 FROM config_table_name WHERE table_name = 'win_http_events');

-- NOTE: creating the config_queries rows above does NOT push the schedule to any
-- node by itself. Existing nodes only run the config IDs listed in their
-- nodes.config_id column, so the new IDs must be appended there.
--
-- On this prod DB the new rows will get IDs 70, 71, 72 (current max id = 69).
-- Confirm first:
--   SELECT id, query_name FROM config_queries
--   WHERE query_name IN ('win_dns_response_events','win_ssl_events','win_http_events')
--   ORDER BY id;
--
-- Then append to each Windows node. Use a comma-delimited exact-match guard
-- (',' || config_id || ',') so partial-number matches (e.g. id 7 inside 70) can't
-- cause a skip or a duplicate. Substitute the real IDs for 70,71,72:
--   UPDATE nodes SET config_id = config_id || ',70,71,72'
--   WHERE os_platform ILIKE '%windows%'
--     AND (',' || config_id || ',') NOT LIKE '%,70,%';
--
-- For FUTURE enrollments, also add these IDs to the Windows default config_id
-- string in server/request_handler.cpp (search: os_platform == "windows").
-- That is a code change (behaviour-affecting) and is intentionally left out of
-- this data-only migration.
