import { describe, expect, it } from 'vitest';
import { escapeIlikeSearchTerm } from '../../../utils/sanitization';
import { stripTrailingStatementEnd } from '../../../utils/sqlText';
import { assertRegistrySqlShape, likeMatch } from '../../../utils/fim/fimRegistrySql';

describe('escapeIlikeSearchTerm', () => {
  it('escapes wildcards', () => {
    expect(escapeIlikeSearchTerm('50%_off')).toBe('50\\%\\_off');
  });
  it('escapes backslashes so a term cannot escape the closing wildcard', () => {
    expect(escapeIlikeSearchTerm('abc\\')).toBe('abc\\\\');
    expect(escapeIlikeSearchTerm('\\%')).toBe('\\\\\\%');
  });
});

describe('stripTrailingStatementEnd', () => {
  it.each([
    ['SELECT 1;', 'SELECT 1'],
    ['  SELECT 1 ;; \n', 'SELECT 1'],
    ['SELECT 1; ;', 'SELECT 1'],
    ["SELECT ';' FROM t", "SELECT ';' FROM t"],
    [';;', ''],
  ])('%j', (input, expected) => {
    expect(stripTrailingStatementEnd(input)).toBe(expected);
  });
  it('handles long whitespace runs quickly', () => {
    const start = Date.now();
    expect(stripTrailingStatementEnd(`SELECT 1;${' ;'.repeat(200_000)}x`)).toContain('x');
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('likeMatch', () => {
  it('matches SQL LIKE patterns', () => {
    expect(likeMatch('HKEY_LOCAL_MACHINE\\%', 'hkey_local_machine\\software')).toBe(true);
    expect(likeMatch('abc', 'abd')).toBe(false);
  });
  it('refuses non-string input', () => {
    expect(likeMatch({ length: 1e9 } as unknown as string, 'x')).toBe(false);
  });
});

describe('assertRegistrySqlShape', () => {
  it('rejects a whitespace-heavy bad query quickly', () => {
    const sql = `SELECT path, name, type, data FROM registry WHERE key LIKE 'x'${' '.repeat(10_000)}!`;
    const start = Date.now();
    expect(() => assertRegistrySqlShape(sql)).toThrow();
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
