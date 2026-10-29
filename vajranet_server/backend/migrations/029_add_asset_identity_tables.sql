-- Documentation-only mirror: nothing in this codebase executes
-- migrations/*.sql automatically. The schema below is applied for real on every
-- server boot (including production, where TypeORM synchronize is disabled) by
-- the idempotent bootstrap block in backend/src/index.ts (search for
-- "asset_identity schema up to date"). Keep the two in sync if either changes —
-- entity-vs-bootstrap drift is the classic bug in this pattern.
--
-- Fleet DB: asset identity resolution.
-- Backs orm/entities/fleet/Asset.ts, AssetIdentity.ts, AssetObservation.ts and
-- AssetFeedState.ts.
--
-- Agent-reported hosts live in `nodes`; agentless scans live in
-- `network_scan_history` / `nuclei_scan_history`, and OpenVAS reports are
-- fetched live from GVM and never persisted at all. Nothing tied "the machine
-- at 10.0.5.40 that OpenVAS scanned" to "the agent node DESKTOP-EXAMPLE".
-- These four tables add that link plus a per-asset timeline of every scan that
-- ever observed the host.
--
-- Identity is resolved by WEIGHTED MATCHING (bios_uuid 100, mac 80,
-- hostname 40, os 10, ip 5; see backend/src/consts/assets.ts), never by hashing
-- attributes into a derived id: an unauthenticated scanner cannot read SMBIOS,
-- so every source sees a different subset of a machine's attributes, and
-- IP/hostname change over time. asset_uuid is therefore random on first sight
-- and never changes.
--
-- gen_random_uuid() is native from Postgres 13 on (this deployment runs 18.6),
-- so no pgcrypto extension is required.

CREATE TABLE IF NOT EXISTS assets (
  asset_uuid           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  first_seen           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  last_seen            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  -- Weight of the strongest anchor ever seen: 100|80|40|5|0. Ratchets upward
  -- only, and the matcher's ip-only attach rule must never raise it above 5.
  identity_confidence  SMALLINT     NOT NULL DEFAULT 0,
  needs_review         BOOLEAN      NOT NULL DEFAULT FALSE,
  -- Soft, reversible merge pointer to the surviving asset. Deliberately not a
  -- foreign key: it points into this same table and a bad merge must be
  -- repairable with a single UPDATE. Rows are never DELETEd.
  merged_into          UUID,
  -- Soft reference to the fleet DB's nodes_groups.group_id (no FK — groups live
  -- in a separate DataSource), same pattern as every other group-scoped fleet
  -- table. NULL = "unassigned / discovered": an asset only agentless scanners
  -- have seen carries no group until it merges with an agent-backed asset.
  owner_group_id       VARCHAR(255)
);

-- Partial: the review queue is a handful of rows out of the whole fleet, so the
-- index only needs to cover the ones that are actually flagged.
CREATE INDEX IF NOT EXISTS idx_assets_needs_review ON assets (needs_review) WHERE needs_review;
CREATE INDEX IF NOT EXISTS idx_assets_owner_group ON assets (owner_group_id);
CREATE INDEX IF NOT EXISTS idx_assets_merged_into ON assets (merged_into);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets (last_seen);

-- Identities are MULTI-VALUED and ACCUMULATE: four NICs give four `mac` rows,
-- and a changed IP adds a row instead of overwriting one, so last_seen per
-- value is that value's history. Nothing is overwritten but last_seen.
CREATE TABLE IF NOT EXISTS asset_identities (
  -- CASCADE, not because assets are ever deleted (they aren't -- rows are
  -- never DELETEd, only soft-merged via merged_into), but as a DB-level
  -- backstop for that invariant: without it, a future DELETE FROM assets
  -- silently orphans identity rows instead of failing loudly or cleaning up.
  asset_uuid   UUID          NOT NULL REFERENCES assets(asset_uuid) ON DELETE CASCADE,
  -- bios_uuid | mac | hostname | os | ip | osquery_uuid.
  -- osquery_uuid is weight 0 and never scored: nodes.host_identifier on the
  -- Linux agents is osquery-generated, not hardware, and must never be stored
  -- as a bios_uuid.
  -- No CHECK against this closed enum (kind IN (...)), deliberately: this
  -- table's own value_norm/kind pairing already has no other integrity net
  -- worth adding to for one column, and no other VARCHAR "closed enum" column
  -- elsewhere in this schema (e.g. patch_jobs.status, network_scan_history
  -- .status) has one either -- adding it only here would be an inconsistent
  -- one-off, not a real hardening pass. IdentityKind in types/assetIdentity.ts
  -- is the actual source of truth; a bad value here is a code bug, not
  -- untrusted input (values are normalizer output, never copied from a raw
  -- scan report verbatim).
  kind         VARCHAR(32)   NOT NULL,
  value_norm   VARCHAR(255)  NOT NULL,
  -- Copy of the weight in effect at insert time, so a recorded match_reason
  -- stays explainable after the weights in consts/assets.ts are retuned.
  weight       SMALLINT      NOT NULL DEFAULT 0,
  first_seen   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  last_seen    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  PRIMARY KEY (asset_uuid, kind, value_norm)
);

-- Idempotent add-if-missing: on a DB where this table already existed before
-- the FK was introduced, CREATE TABLE IF NOT EXISTS above is a no-op and
-- would silently skip the constraint forever without this.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_asset_identities_asset') THEN
    ALTER TABLE asset_identities
      ADD CONSTRAINT fk_asset_identities_asset
      FOREIGN KEY (asset_uuid) REFERENCES assets(asset_uuid) ON DELETE CASCADE;
  END IF;
END $$;

-- THIS index is the matcher. resolveAsset() issues exactly one indexed lookup
-- per observation: WHERE (kind, value_norm) IN (...). The PK is asset-first and
-- cannot serve that query.
CREATE INDEX IF NOT EXISTS idx_asset_identities_kind_value ON asset_identities (kind, value_norm);

-- Concurrency backstop: two feeders resolving the same machine at once can both
-- miss the candidate query and both mint an asset. This makes the loser's
-- insert fail loudly instead of silently creating a duplicate. Restricted to
-- the globally-unique kinds — a hostname, os family or IP is legitimately
-- shared by many assets.
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_identities_strong_unique
  ON asset_identities (kind, value_norm)
  WHERE kind IN ('bios_uuid', 'mac');

CREATE TABLE IF NOT EXISTS asset_observations (
  id            BIGSERIAL     PRIMARY KEY,
  -- Nullable: the matcher also records observations it declined to resolve
  -- ('skipped_no_identities' / 'skipped_no_mint'), which is exactly what
  -- answers "why is this host not in Assets?". FK is CASCADE for the same
  -- backstop reason as asset_identities.asset_uuid above; a NULL value is
  -- exempt from the constraint, so undecided observations are unaffected.
  asset_uuid    UUID REFERENCES assets(asset_uuid) ON DELETE CASCADE,
  -- agent | nmap | openvas | nuclei | arp. No CHECK against this closed enum
  -- -- see asset_identities.kind's comment above for why (same reasoning
  -- applies here and to asset_feed_state.source below).
  source        VARCHAR(32)   NOT NULL,
  -- Per-HOST, never per-scan: 'nsh:<id>:<ip>', 'ovas:<report-uuid>:<ip>',
  -- 'agent:<host_identifier>'.
  source_ref    VARCHAR(512)  NOT NULL,
  observed_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  -- Raw, un-normalized attributes as the feeder read them, kept so a
  -- normalization bug can be replayed without re-scanning the network.
  attrs         JSONB         NOT NULL DEFAULT '{}'::jsonb,
  match_score   SMALLINT      NOT NULL DEFAULT 0,
  match_reason  JSONB
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_asset_observations_asset') THEN
    ALTER TABLE asset_observations
      ADD CONSTRAINT fk_asset_observations_asset
      FOREIGN KEY (asset_uuid) REFERENCES assets(asset_uuid) ON DELETE CASCADE;
  END IF;
END $$;

-- Makes a replayed feed a no-op: feeders insert ON CONFLICT DO NOTHING, so
-- resetting a watermark in asset_feed_state re-ingests without duplicating.
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_obs_source_ref
  ON asset_observations (source, source_ref);
-- Backs the per-asset timeline in the Assets detail view.
CREATE INDEX IF NOT EXISTS idx_asset_obs_asset_observed
  ON asset_observations (asset_uuid, observed_at);
CREATE INDEX IF NOT EXISTS idx_asset_obs_source_observed
  ON asset_observations (source, observed_at);

-- One row per feeder. Deleting a row (or zeroing last_source_id) is the
-- intended way to force a full re-ingest.
CREATE TABLE IF NOT EXISTS asset_feed_state (
  source          VARCHAR(32)  PRIMARY KEY,
  -- Highest source-table id already ingested (e.g. network_scan_history.id).
  -- NULL for feeders with no monotonic source id: the agent feeder re-reads all
  -- of `nodes` each tick, and OpenVAS is driven lazily by report views rather
  -- than polling GVM.
  last_source_id  BIGINT,
  last_run_at     TIMESTAMPTZ,
  last_error      TEXT
);
