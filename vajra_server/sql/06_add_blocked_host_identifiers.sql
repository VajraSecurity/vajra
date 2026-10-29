-- Permanently block specific host_identifiers from enrolling.
-- Rows here cause the enroll endpoint to return node_invalid=true regardless
-- of whether a nodes row exists, so deletion + re-enrollment is also blocked.
CREATE TABLE IF NOT EXISTS blocked_host_identifiers (
    id          SERIAL PRIMARY KEY,
    host_identifier VARCHAR(40) NOT NULL UNIQUE,
    reason      TEXT,
    blocked_at  BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE INDEX IF NOT EXISTS idx_blocked_host_identifiers_host
    ON blocked_host_identifiers (host_identifier);
