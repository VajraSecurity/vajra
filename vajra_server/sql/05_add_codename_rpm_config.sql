-- Add codename column to nodes table (populated from osquery os_version.codename at enrollment)
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS codename TEXT;

-- Add rpm_packages config (id=39) to existing Linux nodes that are missing it
UPDATE nodes
SET config_id = config_id || ',39'
WHERE os_platform != 'windows'
  AND config_id NOT LIKE '%39%';
