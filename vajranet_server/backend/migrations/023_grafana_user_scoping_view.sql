-- Primary DB (vajra_db): credential-free view of vajra_users for the Grafana
-- FDW bridge.
--
-- Metadata only. Creates no table and copies no data.
--
-- This is one of the two halves of the Grafana group-scoping design that
-- ormconfig-setup.ts already implements but that has never run on this
-- deployment. setupDatabase() creates this view via
-- DATABASE_SETUP_QUERIES.createGrafanaUserScopingView; the fleet-side half is
-- migration 024. Until both exist, grafana_group_visible() cannot resolve and
-- every scoped panel errors.
--
-- Why a view rather than importing vajra_users directly: that table carries
-- password_hash, mfa_secret, recovery_codes and both security_answer hashes,
-- and IMPORT FOREIGN SCHEMA has no column-level filter — it can only limit
-- which tables are imported. Importing the raw table would expose every
-- credential column to grafana_reader across the bridge. This exposes id,
-- email and role, which is all the scoping predicates read.
--
-- Ownership is set to vajra explicitly. Applied by a superuser the view would
-- otherwise be owned by postgres, and the FDW connects as vajra: this leaves
-- exactly the state the application's own setup path would have produced.
--
-- Rollback: DROP VIEW public.grafana_user_scoping. Migration 024 must be rolled
-- back first — its foreign table depends on this view existing.
--
-- Verify — one row, and readable as the FDW's user:
--   SELECT count(*) FROM public.grafana_user_scoping;
--   SELECT has_table_privilege('vajra','public.grafana_user_scoping','SELECT');

CREATE OR REPLACE VIEW public.grafana_user_scoping AS
SELECT id, email, role FROM public.vajra_users;

ALTER VIEW public.grafana_user_scoping OWNER TO vajra;
