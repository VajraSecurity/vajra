-- Adds `policies.target_group_ids`, resolving it from the existing
-- `policies.target_group_names` (display name) column.
--
-- Why: `nodes_groups.name` has no uniqueness constraint — two groups can
-- share a name — so a policy that targets a group "by name" is ambiguous:
-- scope checks and target resolution in policy_management.ts can't always
-- tell which physical group (`nodes_groups.group_id`, which IS unique) was
-- meant. `target_group_ids` replaces name-based targeting with id-based
-- targeting, matching how nodeScope.ts already keys everything off group id.
--
-- Backfill rule: for each name in a policy's target_group_names, resolve it
-- to the OLDEST matching nodes_groups.group_id (by created_at, then id).
-- Where a name is ambiguous (matches >1 group) or unmatched (matches 0 —
-- e.g. a deleted group), this script RAISEs NOTICE listing the specifics so
-- an operator can review before relying on the result. It does not fail or
-- block on ambiguity — it makes a deterministic best-effort choice and
-- surfaces what it did.
--
-- Run this against the `fleet` database (POSTGRES_DB1) BEFORE deploying the
-- backend build that reads target_group_ids, since the app runs with
-- synchronize: false in production and will not create this column itself.
--
-- Safe to re-run: a second run recomputes the same backfill. It does not drop
-- target_group_names — that is drop_policy_target_group_names.sql, a separate
-- one-way step to run only after reviewing the NOTICEs from this script and
-- confirming the deployed code no longer reads the column.

ALTER TABLE policies ADD COLUMN IF NOT EXISTS target_group_ids text[] NOT NULL DEFAULT '{}'::text[];

-- Report ambiguous group names up front (informational only).
DO $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN
    SELECT name, count(*) AS n
    FROM nodes_groups
    WHERE name IS NOT NULL
    GROUP BY name
    HAVING count(*) > 1
  LOOP
    RAISE NOTICE 'Ambiguous group name "%" matches % different group_ids — any policy targeting it by name will backfill to the oldest matching group. Review the affected policies manually.', rec.name, rec.n;
  END LOOP;
END $$;

-- Backfill target_group_ids from target_group_names.
WITH ranked_groups AS (
  SELECT
    name,
    group_id,
    row_number() OVER (PARTITION BY name ORDER BY created_at ASC, id ASC) AS rn
  FROM nodes_groups
  WHERE name IS NOT NULL
),
resolved AS (
  SELECT name, group_id FROM ranked_groups WHERE rn = 1
)
UPDATE policies p
SET target_group_ids = COALESCE(
  (
    SELECT array_agg(DISTINCT r.group_id)
    FROM unnest(p.target_group_names) AS tn(name)
    JOIN resolved r ON r.name = tn.name
  ),
  '{}'::text[]
)
WHERE array_length(p.target_group_names, 1) > 0;

-- Report policies where a name had no matching group at all (stale/deleted
-- group) — target_group_ids will be missing that entry entirely.
DO $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN
    SELECT id, name AS policy_name, target_group_names, target_group_ids
    FROM policies
    WHERE array_length(target_group_names, 1) > 0
      AND COALESCE(array_length(target_group_ids, 1), 0) < array_length(target_group_names, 1)
  LOOP
    RAISE NOTICE 'Policy % ("%") has % target_group_names but only resolved % target_group_ids — one or more names had no matching group and were dropped. Review manually before relying on this policy''s group targeting.',
      rec.id, rec.policy_name, array_length(rec.target_group_names, 1), COALESCE(array_length(rec.target_group_ids, 1), 0);
  END LOOP;
END $$;
