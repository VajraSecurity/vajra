-- Fleet DB: return the three Windows EDR event tables to the postgres role.
--
-- Metadata only. Changes ownership, not data.
--
-- ALREADY APPLIED IN PRODUCTION. Recorded here after the fact — the change was
-- made during an incident and the file was never committed, so the repo showed
-- no trace of it. Re-running it is a no-op if the owners already match.
--
-- Reverts migration 018, which handed these tables to vajra so the ingest path
-- could write to them again. That worked, and the volume was the problem: the
-- restored ingest ran at roughly 300 rows/sec, about 12 GB/day, taking the
-- disk from ~62 days of runway to under 5. The earlier estimate of ~23,700
-- rows/day had been derived from counting rejection lines in the log, which
-- undercounted by about three orders of magnitude.
--
-- Moving ownership back to postgres restores the permission error that was
-- silently discarding these events, which is what stopped the ingest. That is
-- a workaround, not a fix: roughly 25.7M events/day are still being dropped,
-- and the ~816,000 rows collected during the window the ingest was live are
-- retained and readable.
--
-- Re-enabling this needs a retention plan first, not just an ownership change.
-- At 12 GB/day the 180-day CERT-In floor implies about 2.1 TB, against a
-- 193 GB host — so it needs partitioning with a short local window, an
-- off-host destination, or a narrower set of captured event types.
--
-- Rollback: migration 018 (ALTER TABLE ... OWNER TO vajra). Do not run it
-- without the retention decision above.
--
-- Verify — all three must report postgres:
--   SELECT relname, pg_get_userbyid(relowner) FROM pg_class
--    WHERE relname IN ('win_dns_response_events','win_http_events','win_ssl_events');

ALTER TABLE win_dns_response_events OWNER TO postgres;
ALTER TABLE win_http_events         OWNER TO postgres;
ALTER TABLE win_ssl_events          OWNER TO postgres;
