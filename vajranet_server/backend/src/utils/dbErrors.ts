/** Shared Postgres error-shape helpers (no env). */

/**
 * True when `err` is a Postgres "undefined_table" error (SQLSTATE 42P01),
 * whether raised directly by the driver or wrapped in TypeORM's
 * QueryFailedError (`driverError.code`). Used by read paths that should
 * degrade to an empty result instead of a 500 when an optional/late-migrated
 * table doesn't exist yet.
 */
export function isPgUndefinedTableError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const o = err as { code?: string; driverError?: { code?: string } };
  return o.code === '42P01' || o.driverError?.code === '42P01';
}
