-- Fleet DB: single-shot scheduling and bundle version pinning for Patch
-- Management.
--
-- scheduled_at: optional single-shot scheduling for a patch_jobs row, claimed
-- by sweepScheduledPatchJobs() in controllers/nodes/patch_management.ts. NULL
-- means "dispatch immediately", so existing jobs are unaffected. With a future
-- timestamp, createPatchJob creates the patch_job_nodes rows but leaves them
-- 'queued'; the sweep atomically clears scheduled_at and dispatches the queued
-- nodes exactly once. Deliberately single-shot, not a recurring maintenance
-- window.
--
-- bundle_id: which patch_bundles row a 'bundle'-source patch_jobs row is pinned
-- to. NULL keeps the fallback behaviour (POST /api/patch/apply/fallback), where
-- no bundle is selected. Set only by POST /api/patch/bundles/:id/apply, so a
-- rollback pins one exact bundle version instead of letting patch_gap.ts's
-- newest-bundle auto-selection run. Recording it here means a pinned job has an
-- unambiguous answer without re-deriving it from patch_gap.ts's os_match
-- heuristic.
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS bundle_id BIGINT REFERENCES patch_bundles(id);

CREATE INDEX IF NOT EXISTS idx_patch_jobs_scheduled_at ON patch_jobs (scheduled_at) WHERE scheduled_at IS NOT NULL;
