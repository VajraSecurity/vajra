-- 0003_status_logs.sql
-- Adds the status_logs table for osquery log_type "status" self-diagnostics
-- (glog severity/filename/line/message/version/decorations) posted to /log.
-- Safe to run against an existing populated database: additive, IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS status_logs (
    id bigserial PRIMARY KEY,
    host_identifier varchar(40),
    unixTime bigint,
    severity bigint,
    filename TEXT,
    line bigint,
    message TEXT,
    version TEXT,
    decorations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_status_logs_host_time ON status_logs (host_identifier, unixTime);
