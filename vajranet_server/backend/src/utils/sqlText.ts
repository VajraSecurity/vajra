/** Removes whitespace and statement-ending semicolons from the end of a query, in linear time. */
export function stripTrailingStatementEnd(sql: string): string {
  const trimmed = sql.trim();
  let end = trimmed.length;
  while (end > 0 && (trimmed[end - 1] === ';' || trimmed[end - 1].trim() === '')) end--;
  return trimmed.slice(0, end);
}
