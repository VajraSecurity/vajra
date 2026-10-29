-- Primary DB
CREATE TABLE IF NOT EXISTS user_group_memberships (
  id          BIGSERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES vajra_users(id) ON DELETE CASCADE,
  group_id    VARCHAR(255) NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_ugm_user_id  ON user_group_memberships (user_id);
CREATE INDEX IF NOT EXISTS idx_ugm_group_id ON user_group_memberships (group_id);

UPDATE vajra_users SET role = 'Group Admin' WHERE role = 'Administrator';

-- Fleet DB
CREATE INDEX IF NOT EXISTS idx_nodes_group_ids ON nodes USING GIN (group_ids);
