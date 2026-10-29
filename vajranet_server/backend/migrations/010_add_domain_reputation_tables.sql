-- Fleet DB: Domain/IP Reputation feature tables.
-- Backs orm/entities/fleet/DomainReputationProviderConfig.ts,
-- DomainReputationTarget.ts, and DomainReputationCheckResult.ts. Any install
-- that never ran TypeORM synchronize has none of these tables (it fails with
-- "relation domain_reputation_provider_configs does not exist"), so the DDL
-- has to be applied explicitly.

-- One row per provider ('manual' | 'virustotal' | 'abuseipdb') holding its
-- API key (encrypted) and connection settings. See providerConfigController.ts.
CREATE TABLE IF NOT EXISTS domain_reputation_provider_configs (
  id                 BIGSERIAL    PRIMARY KEY,
  provider           VARCHAR(32)  NOT NULL,
  base_url           VARCHAR(500),
  auth_mode          VARCHAR(16)  NOT NULL DEFAULT 'bearer',
  auth_header_name   VARCHAR(100) NOT NULL DEFAULT 'X-API-Key',
  api_key_encrypted  TEXT,
  api_key_iv         VARCHAR(64),
  api_key_auth_tag   VARCHAR(64),
  api_key_suffix     VARCHAR(8)   NOT NULL DEFAULT '',
  is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
  created_by_user_id BIGINT,
  created_by_name    VARCHAR(255),
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_drpc_provider_active ON domain_reputation_provider_configs (provider, is_active);

-- Threat Intel tab's scheduled watchlist (VirusTotal/AbuseIPDB only).
CREATE TABLE IF NOT EXISTS domain_reputation_targets (
  id                 BIGSERIAL    PRIMARY KEY,
  value              VARCHAR(255) NOT NULL,
  type               VARCHAR(10)  NOT NULL,
  providers          JSONB        NOT NULL,
  cron_expression    VARCHAR(100) NOT NULL,
  is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
  last_verdict       VARCHAR(20),
  last_checked_at    TIMESTAMPTZ,
  created_by_user_id BIGINT,
  created_by_name    VARCHAR(255),
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_drt_active ON domain_reputation_targets (is_active);

-- Append-only history of every check, manual or scheduled.
CREATE TABLE IF NOT EXISTS domain_reputation_check_results (
  id                BIGSERIAL    PRIMARY KEY,
  target_id         BIGINT,
  value             VARCHAR(255) NOT NULL,
  type              VARCHAR(10)  NOT NULL,
  provider          VARCHAR(32)  NOT NULL,
  verdict           VARCHAR(20)  NOT NULL,
  score             NUMERIC,
  summary           TEXT,
  raw_response      JSONB,
  triggered_by      VARCHAR(10)  NOT NULL,
  checked_by_user_id BIGINT,
  checked_by_name   VARCHAR(255),
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_drcr_value_provider ON domain_reputation_check_results (value, provider);
CREATE INDEX IF NOT EXISTS idx_drcr_target ON domain_reputation_check_results (target_id);
