/**
 * Self-contained test for guardrails.ts's validateSql, which filters the SQL
 * reaching the threat-hunting ad-hoc console
 * (controllers/threat-hunting/run_query.ts) and the AI SQL tool. No test
 * framework required:
 *
 *   node_modules/.bin/ts-node src/test/mcp/guardrails.selftest.ts
 *
 * The central case is the backslash bypass. A backslash before a closing quote
 * is read as an escaped quote by validateSql's string-stripping regex and by
 * node-sql-parser's Postgres tokenizer, but not by Postgres itself under
 * standard_conforming_strings=on, where a string ends at the very next quote.
 * That lets a well-formed, non-stacked UNION SELECT against vajra_users hide
 * inside what both guardrail layers take for string content and survive
 * run_query.ts's `SELECT * FROM (${query}) __q LIMIT ${rowLimit}` wrapping.
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';
import { validateSql } from '../../mcp/guardrails';

function main() {
  // ── Happy path — realistic threat-hunting queries must keep working ─────
  const legit = [
    `SELECT hostname, os FROM nodes WHERE hostname = 'web-server-01' LIMIT 100`,
    `SELECT hostname FROM nodes WHERE hostname = 'O''Brien-server' LIMIT 50`, // SQL-standard doubled-quote escape
    `SELECT id, hostname FROM nodes WHERE last_seen > '2026-01-01' ORDER BY last_seen DESC LIMIT 200`,
    `WITH recent AS (SELECT hostname FROM nodes WHERE last_seen > '2026-01-01') SELECT * FROM recent LIMIT 50`,
  ];
  for (const q of legit) {
    assert.strictEqual(validateSql(q, [], 'secondary').valid, true, `legitimate query must pass: ${q}`);
  }

  // The backslash bypass payload: must be rejected.
  const bypassPayload =
    `SELECT hostname FROM nodes WHERE hostname = 'a\\' UNION SELECT password_hash FROM vajra_users) xx LIMIT 5 -- '`;
  const bypassResult = validateSql(bypassPayload, [], 'secondary');
  assert.strictEqual(bypassResult.valid, false, 'the backslash/UNION guardrail-bypass payload must be rejected');
  assert.strictEqual(
    bypassResult.reason,
    'Backslash characters are not allowed in SQL',
    'rejection must come from the backslash check, not a coincidental later check',
  );

  // ── Any literal backslash is rejected outright, independent of shape ────
  for (const q of [
    `SELECT hostname FROM nodes WHERE hostname = 'a\\b' LIMIT 5`,
    `SELECT hostname FROM nodes WHERE hostname LIKE 'server\\_01' LIMIT 5`,
  ]) {
    assert.strictEqual(validateSql(q, [], 'secondary').valid, false, `any raw backslash must be rejected: ${q}`);
  }

  // ── Direct (untricked) sensitive-column access still blocked by the AST layer ──
  assert.strictEqual(
    validateSql(`SELECT password_hash FROM vajra_users LIMIT 5`, [], 'secondary').valid,
    false,
    'direct password_hash access must still be blocked',
  );
  assert.strictEqual(
    validateSql(`SELECT * FROM vajra_users LIMIT 5`, [], 'secondary').valid,
    false,
    'SELECT * on vajra_users must still be blocked',
  );

  // ── Pre-existing checks unaffected by this change ────────────────────────
  assert.strictEqual(validateSql(`DELETE FROM nodes`, [], 'secondary').valid, false, 'forbidden keyword still blocked');
  assert.strictEqual(
    validateSql(`SELECT 1; SELECT 2`, [], 'secondary').valid,
    false,
    'multi-statement still blocked',
  );
  assert.strictEqual(
    validateSql(`SELECT hostname FROM nodes -- comment`, [], 'secondary').valid,
    false,
    'comments still blocked',
  );
  assert.strictEqual(
    validateSql(`SELECT hostname FROM nodes`, [], 'secondary').valid,
    false,
    'missing LIMIT still blocked',
  );

  console.log('guardrails.selftest: all checks passed');
}

main();
