-- Optional clean-up for installs upgraded from an earlier version. Fresh installs never
-- create these tables, so there is nothing to do for them.
--
-- Drops the tables of features that were removed from the open-source edition: the remote
-- shell (terminal_logs, terminal_activity), the in-app platform updater
-- (platform_update_state, platform_update_dismissals) and agent self-update
-- (agent_releases, node_agent_versions, agent_devops_component_baseline) and the agent
-- uninstall tokens (uninstall_tokens; Linux and Windows uninstall now need no token).
--
-- DESTRUCTIVE: the data in these tables is deleted. Back up first if you need the history.
-- Safe to run against either database (app or fleet): every statement uses IF EXISTS.
--
--   psql -h localhost -U vajra -d vajra_db -f backend/migrations/035_drop_removed_feature_tables.sql
--   psql -h localhost -U vajra -d fleet    -f backend/migrations/035_drop_removed_feature_tables.sql

DROP TABLE IF EXISTS terminal_logs;
DROP TABLE IF EXISTS terminal_activity;
DROP TABLE IF EXISTS platform_update_dismissals;
DROP TABLE IF EXISTS platform_update_state;
DROP TABLE IF EXISTS node_agent_versions;
DROP TABLE IF EXISTS agent_releases;
DROP TABLE IF EXISTS agent_devops_component_baseline;
DROP TABLE IF EXISTS uninstall_tokens;
