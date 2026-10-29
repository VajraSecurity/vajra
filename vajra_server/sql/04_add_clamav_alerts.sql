-- Migration: ClamAV alerts table for the Linux agent integration.
--
-- The Linux extension pushes ClamAV detections (manual SCAN/CONTSCAN/INSTREAM
-- results and on-access clamonacc detections) to the websocket server with
-- rid = 'clamav_push'.  The server persists each detection here and mirrors it
-- into the generic alerts table (alert_type = 'ClamAV Alert').
--
-- Apply with:  psql -d <vajra_db> -f 04_add_clamav_alerts.sql

CREATE TABLE IF NOT EXISTS clamav_alerts (
    id bigserial PRIMARY KEY,
    host_identifier varchar(40),
    source TEXT,
    scan_type TEXT,
    path TEXT,
    signature TEXT,
    status TEXT,
    detected_at TEXT,
    created_at timestamptz DEFAULT now(),
    -- The agent buffers alerts while the server is unreachable and re-sends on
    -- reconnect; this constraint (+ ON CONFLICT DO NOTHING in the server) makes
    -- replays idempotent.
    UNIQUE (host_identifier, path, signature, detected_at)
);

CREATE INDEX IF NOT EXISTS idx_clamav_alerts_host ON clamav_alerts (host_identifier);
CREATE INDEX IF NOT EXISTS idx_clamav_alerts_created ON clamav_alerts (created_at);
