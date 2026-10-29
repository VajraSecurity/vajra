-- Fleet DB: Patch Bundle content-model tables.
--
-- A "Patch Bundle" is a signed, versioned snapshot of OS packages (Phase 1
-- scope: deb/rpm only) — the offline-capable counterpart to the "native"
-- patch_jobs flow added in 005_add_patch_management_tables.sql. Bundles are
-- produced OFFLINE by backend/src/scripts/sign-patch-bundle.ts (a separate
-- ECDSA key pair from the agent-update signer — see
-- backend/src/utils/patchBundle.ts's header comment for the trust model) and
-- uploaded via POST /api/patch/bundles, which verifies the signature
-- server-side before ever inserting a row (fail-closed: a bad signature is
-- never stored).
--
-- The full verified manifest (including the per-package name/version/arch/
-- filename/sha256 list) is stored as jsonb in manifest_json rather than a
-- separate normalized packages table — this phase doesn't need per-package
-- querying performance, just storage/serving of the bundle as a whole; that
-- can be revisited if/when a later phase needs it (e.g. per-package indexed
-- lookup for the agent-side apply pipeline).
--
-- Same case-insensitive host_identifier convention as the rest of this
-- codebase's patch-management tables applies wherever this table is later
-- joined against host data (see controllers/nodes/patch_gap.ts) — this
-- table itself carries no host_identifier column.
CREATE TABLE IF NOT EXISTS patch_bundles (
  id                BIGSERIAL    PRIMARY KEY,
  bundle_id         TEXT         NOT NULL UNIQUE, -- uuid, from the manifest
  version           TEXT         NOT NULL,        -- e.g. "2024-07-20.1"
  family            TEXT         NOT NULL,        -- 'deb' | 'rpm' (Phase 1 scope)
  os_match          TEXT         NOT NULL,        -- e.g. "ubuntu-22.04", "rhel-9" (free text)
  channel           TEXT         NOT NULL,        -- e.g. "stable"
  manifest_json     JSONB        NOT NULL,        -- the full verified manifest, packages included
  signature_valid   BOOLEAN      NOT NULL DEFAULT true, -- always true for a stored row (fail-closed insert path); kept as an explicit column for audit/reporting rather than implied
  packages_count    INTEGER      NOT NULL,        -- derived from manifest_json.packages length at insert time
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  created_by_id     INTEGER,
  created_by_email  TEXT
);

CREATE INDEX IF NOT EXISTS idx_patch_bundles_family ON patch_bundles (family);
CREATE INDEX IF NOT EXISTS idx_patch_bundles_family_os_match ON patch_bundles (family, os_match);
CREATE INDEX IF NOT EXISTS idx_patch_bundles_released ON patch_bundles (created_at DESC);
-- GIN index so a future phase can efficiently query manifest_json->'packages'
-- (e.g. "find bundles containing package X") without a normalized table.
CREATE INDEX IF NOT EXISTS idx_patch_bundles_manifest_gin ON patch_bundles USING GIN (manifest_json);
