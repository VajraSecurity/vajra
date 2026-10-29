-- Fleet DB: clear references to deleted groups from `nodes`, then add the FK.
--
-- MODIFIES DATA.
--
-- State before this ran: of 74 nodes, 16 have a non-null owner_group_id and 7 of
-- those name a group absent from nodes_groups. A further 7 rows carry dead ids
-- inside the group_ids jsonb array.
--
-- Such a node is invisible from both directions: scope checks resolve
-- owner_group_id against group membership, and nobody can be a member of a deleted
-- group, so no scoped user sees it — yet it is not counted as unassigned either,
-- because the column is non-null. Setting it to NULL restores the ungrouped state
-- the application already handles. No node or telemetry is deleted.
--
-- delete_group.ts clears both columns correctly today, so this is pre-existing
-- residue. The FK prevents recurrence from any writer, including the fleet server,
-- which also writes `nodes`. ON DELETE SET NULL reproduces what delete_group.ts
-- does by hand, making its step 2 redundant rather than conflicting.
--
-- The FK covers owner_group_id only; group_ids is jsonb and cannot carry one. That
-- the same reference is modelled three ways (text, jsonb, and text[] on policies)
-- is why the dead ids in the array went unnoticed, and is not addressed here.
--
-- Feasibility: nodes_groups.group_id carries nodes_groups_groupId_key, so the
-- reference is valid. NULL is permitted, so the fleet server's enrollment insert —
-- which sets no owner group — is unaffected.
--
-- Ordering is load-bearing: both UPDATEs must complete before ADD CONSTRAINT, or
-- existing rows violate it and the statement is rejected.
--
-- Rollback: ALTER TABLE nodes DROP CONSTRAINT fk_nodes_owner_group. The cleared
-- references pointed at groups that no longer exist, so there is nothing to restore.
--
-- Verify — both must be 0:
--   SELECT count(*) FROM nodes n WHERE n.owner_group_id IS NOT NULL
--     AND NOT EXISTS (SELECT 1 FROM nodes_groups g WHERE g.group_id = n.owner_group_id);
--   SELECT count(*) FROM nodes n WHERE EXISTS (
--     SELECT 1 FROM jsonb_array_elements_text(n.group_ids) e
--      WHERE NOT EXISTS (SELECT 1 FROM nodes_groups g WHERE g.group_id = e));

UPDATE nodes n
   SET owner_group_id = NULL
 WHERE n.owner_group_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM nodes_groups g WHERE g.group_id = n.owner_group_id);

-- Rebuild group_ids with only the surviving ids. COALESCE keeps the column's shape
-- when every element is dropped: an empty array, never NULL, matching what the
-- application writes elsewhere.
UPDATE nodes n
   SET group_ids = COALESCE(
         (SELECT jsonb_agg(e)
            FROM jsonb_array_elements_text(n.group_ids) e
           WHERE EXISTS (SELECT 1 FROM nodes_groups g WHERE g.group_id = e)),
         '[]'::jsonb)
 WHERE n.group_ids IS NOT NULL
   AND EXISTS (
         SELECT 1 FROM jsonb_array_elements_text(n.group_ids) e
          WHERE NOT EXISTS (SELECT 1 FROM nodes_groups g WHERE g.group_id = e));

ALTER TABLE nodes
  ADD CONSTRAINT fk_nodes_owner_group
  FOREIGN KEY (owner_group_id)
  REFERENCES nodes_groups (group_id)
  ON DELETE SET NULL;
