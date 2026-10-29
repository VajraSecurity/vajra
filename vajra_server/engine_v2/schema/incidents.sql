-- Incident correlation tables for vajra_engine's alert-to-alert correlation
-- layer (CorrelationEngine / IncidentWriter, engine_v2/). NEW path,
-- deliberately NOT sql/schema.sql or schema/ -- see
-- .team/charter-rule-engine.md: this engagement never touches the live
-- schema. Apply manually against a test/staging DB (e.g. fleet_test) to try
-- this out; nothing in vajra_engine's normal startup path runs this file
-- automatically, and it depends on `alerts` already existing (sql/
-- schema.sql) via the incident_alerts.alert_id foreign key below.
--
-- Design rationale (DB-backed vs. in-process-only): see the top comment in
-- engine_v2/src/IncidentWriter.cpp.

CREATE TABLE IF NOT EXISTS incidents (
    id bigserial PRIMARY KEY,
    correlation_rule_id integer NOT NULL,
    description TEXT,
    severity TEXT,          -- same vocabulary as alerts.severity (see AlertWriter::severity_text)
    level integer,
    groups TEXT,             -- comma-joined, same convention as alerts.technique
    mitre TEXT,               -- comma-joined ATT&CK ids, same convention as alerts.technique_id
    group_by_fields TEXT,     -- comma-joined field names this incident was scoped by (e.g. "host_identifier")
    group_key TEXT NOT NULL,  -- the actual entity value(s), e.g. the host_identifier or user name
    first_seen_time bigint,
    last_seen_time bigint,
    is_open boolean NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- At most one OPEN incident per (correlation_rule_id, group_key) -- mirrors
-- alerts' own (host_identifier, alert_type, event_code, is_open) dedup
-- convention. This is a defense-in-depth guard; IncidentWriter's own
-- INSERT ... WHERE NOT EXISTS is the primary dedup mechanism (a single
-- vajra_engine instance/consumer thread at a time -- running more than one
-- concurrently against the same DB is out of scope, see re-nyx.md's open
-- risks).
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_open_unique
    ON incidents (correlation_rule_id, group_key)
    WHERE is_open = true;

CREATE INDEX IF NOT EXISTS idx_incidents_group_key ON incidents (group_key);

-- Links an incident to the specific `alerts` rows that make it up -- lets a
-- console walk from one incident to every underlying alert (and, via each
-- alert's own metadata column, back to the raw matched event fields) the
-- way Microsoft Defender for Endpoint's alert->incident graph or
-- CrowdStrike's IOA chain view does.
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id bigint NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    rule_id integer NOT NULL,
    matched_at bigint,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id);
