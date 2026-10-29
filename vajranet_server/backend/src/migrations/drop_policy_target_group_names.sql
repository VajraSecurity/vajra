-- DESTRUCTIVE AND ONE-WAY. This drops `policies.target_group_names`, the
-- name-keyed targeting column superseded by `target_group_ids` (see
-- add_policy_target_group_ids.sql). A second run is a harmless no-op
-- (IF EXISTS), but there is no undo: once the column is dropped, its data
-- exists only in a prior backup.
--
-- Kept separate from the add/backfill script on purpose. Run it only after all
-- three of:
--   1. add_policy_target_group_ids.sql has been run against this database,
--   2. its NOTICE output has been reviewed for ambiguous or unmatched group
--      names and the resulting target_group_ids confirmed correct, and
--   3. the backend build being deployed no longer reads target_group_names
--      (policy_management.ts and Policy.ts have moved to target_group_ids).

ALTER TABLE policies DROP COLUMN IF EXISTS target_group_names;
