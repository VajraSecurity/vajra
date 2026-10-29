-- Fleet DB. Latest firewall state per host, written by the backend when an agent sends a
-- firewall_status_push message (websocket/node.ts) and read by GET /api/nodes/firewall-status.
-- Nothing else creates this table. Idempotent.
CREATE TABLE IF NOT EXISTS firewall_status (
  host_identifier    TEXT PRIMARY KEY,
  manager            TEXT        NOT NULL DEFAULT 'none',
  active             BOOLEAN     NOT NULL DEFAULT FALSE,
  enabled_on_boot    BOOLEAN     NOT NULL DEFAULT FALSE,
  default_policy_in  TEXT        NOT NULL DEFAULT 'unknown',
  default_policy_out TEXT        NOT NULL DEFAULT 'unknown',
  zone_or_profile    TEXT,
  installed          JSONB       NOT NULL DEFAULT '[]'::jsonb,
  distro             TEXT,
  init_system        TEXT,
  details            TEXT,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
