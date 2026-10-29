-- Add server-populated unixTime to listening_ports (parity with the event tables).
-- The server fills this from the osquery log entry's unixTime, enabling freshness
-- tracking and use as a dedup/time dimension (the table has no natural key).
ALTER TABLE listening_ports ADD COLUMN IF NOT EXISTS unixTime bigint;
