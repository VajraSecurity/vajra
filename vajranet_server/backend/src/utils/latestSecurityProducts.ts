import { RECENT_ROWS_ID_WINDOW } from '../consts/database';

/**
 * SQL for "the latest state of every security product, for a set of hosts".
 *
 * `windows_security_products` is append-only telemetry: the fleet server
 * inserts a fresh row per product per poll and never updates, so the table
 * holds ~2M rows describing only ~64 distinct (host_identifier, name) pairs.
 *
 * The obvious ROW_NUMBER() OVER (PARTITION BY host, name) formulation with an
 * `id > MAX(id) - RECENT_ROWS_ID_WINDOW` guard performs badly: the guard makes
 * `id` the driving indexed predicate, so Postgres walks the primary key across
 * the id window and applies `host_identifier` as a post-filter, reading
 * hundreds of thousands of rows and spilling to temp files to return a few
 * dozen — on an endpoint polled every 10 seconds.
 *
 * This instead enumerates the handful of real (host, name) pairs with a
 * recursive loose index scan and fetches one row per pair. Both halves ride
 * `idx_windows_security_products_host_name_time (host_identifier, name,
 * unixtime DESC, id DESC)`.
 *
 * Keep the `id > MAX(id) - RECENT_ROWS_ID_WINDOW` predicate: it is load-bearing
 * for output equivalence, not an optimisation. It excludes hosts whose newest
 * row has fallen outside the id window, so dropping it changes which rows the
 * endpoint returns.
 *
 * $1 is the host_identifier array, exactly as before.
 */
export const LATEST_SECURITY_PRODUCTS_QUERY = `
  WITH RECURSIVE lo AS (
    SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} AS min_id
    FROM windows_security_products
  ),
  hosts AS (
    -- DISTINCT is load-bearing, not decorative. The predicate this replaced was
    -- 'host_identifier = ANY($1)', a semi-join: a host listed twice matched its
    -- rows once. 'unnest' is set-returning, so without DISTINCT a duplicated
    -- entry produces two driver rows and the LATERAL below emits every
    -- (host, product) pair twice — which would surface as duplicated entries in
    -- the node-list JSON and the export CSV.
    -- Both current callers build $1 from 'nodes' (host_identifier is its primary
    -- key, so the array is duplicate-free), but this is an exported helper and
    -- the next caller may well pass a request-supplied list.
    SELECT DISTINCT unnest($1::text[]) AS hid
  ),
  pairs AS (
    SELECT h.hid,
           (SELECT w.name
              FROM windows_security_products w
             WHERE w.host_identifier = h.hid
             ORDER BY w.name
             LIMIT 1) AS nm
      FROM hosts h
    UNION ALL
    SELECT p.hid,
           (SELECT w.name
              FROM windows_security_products w
             WHERE w.host_identifier = p.hid AND w.name > p.nm
             ORDER BY w.name
             LIMIT 1)
      FROM pairs p
     WHERE p.nm IS NOT NULL
  )
  SELECT s.host_identifier, s.name, s.state
    FROM pairs p
    CROSS JOIN lo
    CROSS JOIN LATERAL (
      SELECT w.host_identifier, w.name, w.state
        FROM windows_security_products w
       WHERE w.host_identifier = p.hid
         AND w.name = p.nm
         AND w.id > lo.min_id
       ORDER BY w.unixtime DESC
       LIMIT 1
    ) s
   WHERE p.nm IS NOT NULL

  UNION ALL

  -- The recursive walk above seeds with 'ORDER BY w.name LIMIT 1' (NULLS LAST)
  -- and steps with 'w.name > p.nm', so a NULL-named group is unreachable by it.
  -- The ROW_NUMBER() form this replaced emitted that group like any other, so
  -- without this branch a NULL product name would silently vanish from the
  -- response. 'name' has no NOT NULL constraint, and production currently has
  -- zero NULL names — this is latent, not live, but the sibling loose index
  -- scan in controllers/nodes/node_storage.ts carries the same branch and this
  -- one should not be the odd one out.
  SELECT s.host_identifier, s.name, s.state
    FROM hosts h
    CROSS JOIN lo
    CROSS JOIN LATERAL (
      SELECT w.host_identifier, w.name, w.state
        FROM windows_security_products w
       WHERE w.host_identifier = h.hid
         AND w.name IS NULL
         AND w.id > lo.min_id
       ORDER BY w.unixtime DESC
       LIMIT 1
    ) s
  ORDER BY host_identifier, name
`;
