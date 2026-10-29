-- Fleet DB: adds group-scoped RBAC to AbuseIPDB/VirusTotal provider configs
-- and to the scheduled watchlist. See orm/entities/fleet/DomainReputationProviderConfig.ts,
-- DomainReputationTarget.ts, controllers/domain-reputation/*, utils/nodeScope.ts.
--
-- group_id is a soft reference (varchar, no FK) to nodes_groups.group_id /
-- user_group_memberships.group_id — groups, users, and fleet data live in
-- separate PostgreSQL DataSources, so a real foreign key isn't possible
-- (same pattern as user_group_memberships.group_id itself).
--
-- The Vajra Reputation Engine ('manual') provider is entirely unaffected:
-- its row(s) always have group_id NULL and no code path ever sets it to
-- anything else.
--
-- NULL group_id means:
--   - domain_reputation_provider_configs: the org-wide default, usable/
--     writable only by Super Administrator.
--   - domain_reputation_targets: an org-wide watchlist entry — visible
--     read-only to every Group Admin, writable only by Super Administrator
--     (mirrors target_mode:'all' policies in policy_management.ts).
--
-- Existing rows in both tables get group_id = NULL and are deliberately not
-- backfilled to a specific group: group membership lives in the primary
-- DataSource, not this (fleet) one, so a SQL migration cannot join to it. The
-- resulting upgrade behaviour is intended — an existing VirusTotal/AbuseIPDB
-- key becomes the Super Admin org-wide default rather than being lost, each
-- group starts unconfigured until someone sets a config for it, and existing
-- watchlist targets become org-wide Super-Admin-managed entries.
--
-- This file uses CREATE/DROP INDEX CONCURRENTLY, which cannot run inside a
-- transaction block — apply with autocommit on, e.g. `psql -f 014_...sql`.

ALTER TABLE domain_reputation_provider_configs
  ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);

ALTER TABLE domain_reputation_targets
  ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);

-- Replaces idx_drpc_provider_active, which was a plain lookup index: the
-- "one active row per provider" invariant was only ever enforced app-side, by
-- an UPDATE ... SET is_active=false before every INSERT in
-- providerConfigController.ts. This makes it a real database constraint, scoped
-- per (provider, group) instead of per provider. COALESCE(group_id,'')
-- collapses the org-wide NULL slot to a single indexed value so Postgres's
-- default "NULLs never collide in a unique index" behavior can't produce two
-- simultaneously-active org-wide rows for the same provider. group_id values
-- are always non-empty real group ids (see EndpointGroup.groupId /
-- UserGroupMembership.groupId), so '' can never collide with a real group.
DROP INDEX CONCURRENTLY IF EXISTS idx_drpc_provider_active;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_drpc_provider_group_active
  ON domain_reputation_provider_configs (provider, COALESCE(group_id, ''))
  WHERE is_active = true;

-- Lookup index for listProviderConfigs (fetches all active rows per
-- provider) and getProviderConfig's (provider, group_id) point lookup.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drpc_provider_group
  ON domain_reputation_provider_configs (provider, group_id);

-- Watchlist: no uniqueness needed (unchanged — a group may still watch the
-- same value under multiple targets), just a filter index for listTargets'
-- scope check.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drt_group
  ON domain_reputation_targets (group_id);

-- Check history: listHistory (checkController.ts) is a read of every check
-- ever run, including full raw_response bodies from the upstream providers,
-- so it needs the same scoping the watchlist and provider configs get.
-- target_id is NULL for every ad-hoc check and is unpopulated for manual
-- ones, so a group can't be derived by joining domain_reputation_targets
-- after the fact — the group is stamped on insert instead (manualCheck's
-- resolved write group, or the target's own group_id for a scheduled run).
--
-- NULL group_id here means an ungrouped check: the Vajra Reputation Engine
-- ('manual') provider, a Super Administrator's own check, or a row written
-- before this column existed. Unlike a NULL-group target (org-wide, visible
-- read-only to every Group Admin), a NULL-group result is NOT shown org-wide
-- — listHistory only returns such a row to the caller who ran it, so
-- pre-existing rows fail closed rather than becoming visible fleet-wide.
ALTER TABLE domain_reputation_check_results
  ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);

-- Filter index for listHistory's scope check, mirroring idx_drt_group.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drcr_group
  ON domain_reputation_check_results (group_id);
