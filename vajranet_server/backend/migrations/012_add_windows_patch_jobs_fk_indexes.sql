-- Fleet DB: supporting indexes for windows_patch_jobs' two FK-referencing
-- columns (maintained_app_id -> maintained_apps(id), maintained_app_version_id
-- -> maintained_app_versions(id)). Postgres does not auto-create an index on
-- the referencing side of a foreign key, and windows_patch_management.ts's
-- listJobs() joins on both columns in every branch (host-scoped,
-- unrestricted, and group-scoped). Backs
-- orm/entities/fleet/WindowsPatchJob.ts's idx_wpj_maintained_app_id /
-- idx_wpj_maintained_app_version_id.
--
-- CONCURRENTLY cannot run inside a transaction block, so apply with autocommit
-- on, e.g. `psql -f 012_...sql`.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_wpj_maintained_app_id ON windows_patch_jobs (maintained_app_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_wpj_maintained_app_version_id ON windows_patch_jobs (maintained_app_version_id);
