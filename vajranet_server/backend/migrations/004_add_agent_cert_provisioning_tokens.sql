-- Fleet DB: provisioning tokens for agent mTLS certificate issuance.
--
-- NOT osquery's own enrollment (that's the separate C++ fleet server's
-- enroll_secret -> node_key flow, a different TLS listener entirely). This
-- table only backs the mTLS client certificate the Go extension presents on
-- its WebSocket connections to this Node.js backend (/ws/ext, /ws/terminal).
--
-- An admin issues a token bound to one host_identifier (MFA-gated); the agent
-- presents it once, with a CSR, to /api/agent/provision-cert to receive a
-- signed client certificate. Only token_hash is stored — the bearer token
-- itself is never persisted, same principle as an API-key table.
CREATE TABLE IF NOT EXISTS agent_cert_provisioning_tokens (
  id              BIGSERIAL PRIMARY KEY,
  token_hash      VARCHAR(64) NOT NULL UNIQUE,   -- sha256(token), hex
  host_identifier VARCHAR(255) NOT NULL,
  issued_by_id    INTEGER NOT NULL,
  issued_by_email VARCHAR(255) NOT NULL,
  status          VARCHAR(20) NOT NULL DEFAULT 'active', -- active | used | revoked
  issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  revoked_by_id   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_acpt_host_identifier ON agent_cert_provisioning_tokens (host_identifier);
CREATE INDEX IF NOT EXISTS idx_acpt_status ON agent_cert_provisioning_tokens (status);
