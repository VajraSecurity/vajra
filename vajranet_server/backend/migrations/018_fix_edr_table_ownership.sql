-- Fleet DB: transfer three Windows EDR event tables to the `vajra` role.
--
-- RLS is enabled on all 31 HUNT_HOST_KEYED_TABLES with a single group_scope policy
-- that is FOR SELECT only. Ingest works on the other 28 because Postgres exempts a
-- table's owner from RLS and those are owned by `vajra`. These three are owned by
-- `postgres`, so the app role is a non-owner with NOBYPASSRLS, no INSERT policy
-- applies, and the rewriter supplies WITH CHECK (false) — every insert is rejected.
--
-- The INSERT grant is already held; only ownership is wrong. Ownership is preferred
-- over adding an INSERT policy so these three match the other 28 rather than
-- becoming a special case.
--
-- Metadata only: no rows read, written or deleted. Brief ACCESS EXCLUSIVE lock per
-- table. Reversible by naming `postgres`. Requires superuser.
--
-- Verify:
--   SELECT relname, pg_get_userbyid(relowner) FROM pg_class
--    WHERE relname IN ('win_dns_response_events','win_http_events','win_ssl_events');
--   SELECT count(*) FROM win_http_events;   -- must begin rising

ALTER TABLE win_dns_response_events OWNER TO vajra;
ALTER TABLE win_http_events         OWNER TO vajra;
ALTER TABLE win_ssl_events          OWNER TO vajra;
