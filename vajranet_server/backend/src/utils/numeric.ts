/**
 * Coerces a value to a finite number for a numeric DB column, or null.
 *
 * `Number(x)` alone turns a malformed (non-numeric, non-null) client value
 * into NaN rather than null. Postgres rejects the literal 'NaN' for an
 * INTEGER column (a loud 500), but silently accepts and stores it for a
 * FLOAT/DOUBLE PRECISION column — which then reads back as `null` via
 * JSON.stringify(NaN), masking a bad payload as "no data" instead of
 * surfacing the error. Always route optional numeric fields through this
 * instead of a bare `Number(x) : null` ternary.
 */
export function toFiniteNumberOrNull(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}
