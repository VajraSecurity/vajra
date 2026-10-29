-- Primary DB (vajra_db): narrow grafana_reader's access to vajra_users.
--
-- The role holds table-wide SELECT, which includes password_hash, mfa_secret,
-- recovery_codes and both security_answer hashes. It also has rolbypassrls, and
-- grafana.ini enables auth.proxy with auto_sign_up, so every authenticated Vajra
-- user gets a Grafana session backed by this role. Dashboards need only
-- (id, email, role) for user attribution.
--
-- The ALTER DEFAULT PRIVILEGES line is required: without it, tables created later
-- in `public` become SELECT-able automatically and the narrowed grant regresses
-- silently. It does not affect grants already made.
--
-- Deliberately NOT revoking rolbypassrls. The group-scoping design it belongs to is
-- unprovisioned — grafana_group_visible()/grafana_scan_visible() do not exist,
-- there is no postgres_fdw extension or foreign server, and the deployed dashboards
-- do not reference them. Revoking it now empties every dashboard. Separate change.
--
-- Runs against POSTGRES_DB (vajra_db), not fleet. Metadata only. Reversible with
-- GRANT SELECT ON public.vajra_users TO grafana_reader.
--
-- Verify — false, true, false:
--   SELECT has_table_privilege('grafana_reader','public.vajra_users','SELECT');
--   SELECT has_column_privilege('grafana_reader','public.vajra_users','email','SELECT');
--   SELECT has_column_privilege('grafana_reader','public.vajra_users','password_hash','SELECT');

REVOKE ALL ON public.vajra_users FROM grafana_reader;

GRANT SELECT (id, email, role) ON public.vajra_users TO grafana_reader;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM grafana_reader;
