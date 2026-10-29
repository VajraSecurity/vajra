-- 0004_drop_siem_forwarder.sql
-- The SIEM (syslog) forwarder was removed. This drops its checkpoint and failure tables and
-- the triggers that fed it. Safe on fresh installs (nothing to drop) and on upgrades.
DROP TRIGGER IF EXISTS trg_alerts_siem_notify ON alerts;
DROP TRIGGER IF EXISTS trg_clamav_alerts_siem_notify ON clamav_alerts;
DROP FUNCTION IF EXISTS siem_forward_notify();
DROP TABLE IF EXISTS siem_forward_failures;
DROP TABLE IF EXISTS siem_forward_checkpoint;
