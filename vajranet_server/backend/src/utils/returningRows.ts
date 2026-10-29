/**
 * Normalises the result of a raw `.query()` that uses `RETURNING`.
 *
 * TypeORM's Postgres driver does NOT return a uniform shape from
 * `DataSource.query()` / `EntityManager.query()`. See
 * `node_modules/typeorm/driver/postgres/PostgresQueryRunner.js`:
 *
 *   switch (raw.command) {
 *     case "DELETE":
 *     case "UPDATE":
 *       result.raw = [raw.rows, raw.rowCount];  // <- tuple
 *       break;
 *     default:
 *       result.raw = raw.rows;                  // <- plain row array
 *   }
 *
 * So an `UPDATE ... RETURNING` / `DELETE ... RETURNING` yields
 * `[rows, rowCount]` — an array whose `.length` is *always* 2, even when zero
 * rows matched (`[[], 0]`). `INSERT ... RETURNING` and `SELECT` yield the row
 * array directly. Treating the tuple as a row array therefore makes every
 * `rows.length === 0` guard permanently false and every `rows[0]` the nested
 * row array rather than a row.
 *
 * Why a shape sniff rather than TypeORM's structured result: the unambiguous
 * `useStructuredResult` flag lives on `QueryRunner.query(sql, params, true)`,
 * but the third parameter of `DataSource.query(query, parameters, queryRunner)`
 * is a QueryRunner — passing `true` there throws
 * `usedQueryRunner.query is not a function`. Using the structured API would
 * mean hand-managing a QueryRunner (and therefore a pooled connection) at
 * every call site, which is a bigger change to connection-pool behaviour than
 * the bug warrants.
 *
 * The sniff is unambiguous for these queries: node-postgres runs in object
 * row mode, so every element of a genuine row array is a plain row object,
 * never an array — even when a RETURNING column is itself array-typed
 * (a `text[]` column comes back as `[{ tags: ['x','y'] }]`, so element 0 is
 * still an object). A first element that is an Array can therefore only be
 * the `[rows, rowCount]` tuple.
 */
export function returningRows<T = any>(raw: unknown): T[] {
  if (!Array.isArray(raw)) return [];
  // [rows, rowCount] tuple from an UPDATE/DELETE.
  if (raw.length === 2 && Array.isArray(raw[0]) && typeof raw[1] === 'number') {
    return raw[0] as T[];
  }
  // Plain row array from an INSERT ... RETURNING or SELECT.
  return raw as T[];
}

/**
 * Row count for a raw `.query()` result, correct for both shapes above.
 * Prefer this over `result.length` anywhere a count is logged or persisted.
 */
export function returningRowCount(raw: unknown): number {
  if (!Array.isArray(raw)) return 0;
  if (raw.length === 2 && Array.isArray(raw[0]) && typeof raw[1] === 'number') {
    return raw[1];
  }
  return raw.length;
}
