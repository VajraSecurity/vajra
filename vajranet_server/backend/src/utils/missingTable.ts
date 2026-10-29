/**
 * Marks a 500 as "the vulnerability tables do not exist".
 *
 * The vulnexus_* tables are filled by the separate CVE-matching engine, which this edition does not
 * ship. Endpoints that read them still answer with a real 500 when the tables are missing, but add
 * VULNERABILITY_DATA_MISSING to the response's `errors` list so the web console can show "no
 * vulnerability data" instead of a generic failure.
 */
export const VULNERABILITY_DATA_MISSING = 'VULNERABILITY_DATA_MISSING';

/** True when a Postgres error is "relation does not exist" (SQLSTATE 42P01). TypeORM wraps the driver error. */
export function isMissingTableError(err: unknown): boolean {
  const e = err as { code?: string; driverError?: { code?: string } } | null | undefined;
  return e?.code === '42P01' || e?.driverError?.code === '42P01';
}

/** The `errors` list for the 500 response: the marker when a table is missing, otherwise null. */
export function missingTableErrors(err: unknown): string[] | null {
  return isMissingTableError(err) ? [VULNERABILITY_DATA_MISSING] : null;
}
