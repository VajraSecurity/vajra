-- Fleet DB: the NOTIFY side of the alerts LISTEN/NOTIFY pair.
--
-- backend/src/websocket/liveWeb.ts runs `LISTEN new_alert` on a dedicated raw
-- pg client (setupNotifications), but nothing issues a matching NOTIFY: there
-- is no pg_notify call anywhere in backend/src, and without this trigger there
-- are none on public.alerts either. The whole push path is then dead code and
-- the live dashboard's alertStatus.new stays permanently 0.
--
-- Database: fleet (the secondary / PG_*1 database, the one that owns
-- public.alerts and public.nodes). Not the primary auth database. This copies
-- the pattern already in production on public.programs, public.deb_packages and
-- public.rpm_packages (notify_new_program, notify_new_deb_package,
-- notify_new_rpm_package).
--
-- A trigger rather than pg_notify() calls in the app: alerts are inserted from
-- at least 7 sites in Node (websocket/node.ts x5,
-- services/domainReputation/scheduler.ts, services/scanSchedulerService.ts) and
-- possibly from the C++ fleet server and event processor as well. A row trigger
-- covers every writer in every language with one definition; per-call-site
-- pg_notify would silently miss any writer added later or living outside the
-- Node process.
--
-- Cost. This runs inside every alert INSERT's transaction, on the agent ingest
-- path, so it has to be trivially cheap. The WHEN clause is evaluated by the
-- executor without entering plpgsql, so explicitly-closed rows cost essentially
-- nothing. The body is one plpgsql statement with no query, no catalog lookup
-- and no allocation beyond the ~60 byte payload; payload construction measures
-- under 0.2 us/row, trigger dispatch is ~1-3 us and the pg_notify enqueue ~1-2
-- us, against an INSERT that already writes WAL and maintains 7 indexes on
-- public.alerts. One residual risk worth flagging: notifications are flushed
-- into the shared async queue at COMMIT under NotifyQueueLock. At the observed
-- rate (~80 alerts/day, largest single-second burst ever recorded 177 rows)
-- that is not measurable, and it would only matter at sustained thousands of
-- committing alert transactions per second.
--
-- Payload: '<alerts.id>|<alerts.host_identifier>', e.g.
-- '8927|58893c23-d57f-e838-a5aa-5811220e3dbf'. Around 60 bytes against
-- pg_notify's 8000 byte limit. host_identifier is a UUID so it can never
-- contain the '|' separator. Deliberately not the full row: the browser
-- refetches through the scoped REST endpoints anyway, so shipping severity,
-- alert_type or metadata here would only add bytes to work done inside the
-- inserting transaction. The server needs exactly two things — the host, to
-- decide which UI clients may be told, and the id, for logging.
--
-- WHEN clause: `NEW.is_open IS NOT FALSE` fires for TRUE and for NULL and skips
-- only rows inserted explicitly closed. The UI poll this push accelerates
-- queries is_open=true (controllers/alerts/alert_list.ts), so this can never
-- push something the poll would not surface, and errs open on NULL so it can
-- never miss something the poll would.
--
-- Idempotent: safe to run more than once. Reversible: see the rollback block at
-- the bottom.

BEGIN;

CREATE OR REPLACE FUNCTION public.notify_new_alert() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('new_alert', NEW.id::text || '|' || COALESCE(NEW.host_identifier, ''));
    -- AFTER ... FOR EACH ROW ignores the return value; NULL is the documented
    -- form and makes it explicit that this trigger cannot alter the row.
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS alerts_insert_notify_trigger ON public.alerts;

CREATE TRIGGER alerts_insert_notify_trigger
    AFTER INSERT ON public.alerts
    FOR EACH ROW
    WHEN (NEW.is_open IS NOT FALSE)
    EXECUTE FUNCTION public.notify_new_alert();

COMMIT;

-- Verify:
--   SELECT tgname, pg_get_triggerdef(t.oid)
--     FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
--    WHERE c.relname = 'alerts' AND NOT t.tgisinternal;
--
-- Observe live (in psql, then insert an alert from another session):
--   LISTEN new_alert;
--
-- Rollback:
--   DROP TRIGGER IF EXISTS alerts_insert_notify_trigger ON public.alerts;
--   DROP FUNCTION IF EXISTS public.notify_new_alert();
