import { describe, it, expect } from 'vitest';

import { sanitizeString, sanitizeObject, normalizeEmail } from '../../../utils/sanitization';

describe('sanitizeString', () => {
  it('trims leading and trailing whitespace', () => {
    expect(sanitizeString('  hello  ')).toBe('hello');
  });

  it('escapes HTML-significant characters to prevent XSS', () => {
    expect(sanitizeString('<script>alert(1)</script>')).toBe(
      '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;',
    );
  });

  it('escapes quotes and ampersands', () => {
    expect(sanitizeString(`O'Brien & "quoted"`)).toBe('O&#x27;Brien &amp; &quot;quoted&quot;');
  });

  it('returns an empty string for an empty input', () => {
    expect(sanitizeString('')).toBe('');
  });

  it('returns an empty string for non-string input', () => {
    // @ts-expect-error deliberately passing a non-string to test the runtime guard
    expect(sanitizeString(null)).toBe('');
    // @ts-expect-error deliberately passing a non-string to test the runtime guard
    expect(sanitizeString(undefined)).toBe('');
  });
});

describe('sanitizeObject', () => {
  it('sanitizes all top-level string values', () => {
    const input = { name: '  <b>Bob</b>  ', bio: `it's "cool"` };

    const result = sanitizeObject(input);

    expect(result.name).toBe('&lt;b&gt;Bob&lt;&#x2F;b&gt;');
    expect(result.bio).toBe('it&#x27;s &quot;cool&quot;');
  });

  it('leaves non-string top-level values untouched', () => {
    const input = { age: 30, active: true, tags: ['<x>', 'safe'] };

    const result = sanitizeObject(input);

    expect(result.age).toBe(30);
    expect(result.active).toBe(true);
    expect(result.tags).toEqual(['<x>', 'safe']);
  });

  it('does not recursively sanitize nested object values', () => {
    const input = { profile: { bio: '<script>evil()</script>' } };

    const result = sanitizeObject(input);

    // sanitizeObject only inspects top-level keys; nested strings pass through unchanged.
    expect(result.profile.bio).toBe('<script>evil()</script>');
  });

  it('does not mutate the original object', () => {
    const input = { name: '<b>x</b>' };

    sanitizeObject(input);

    expect(input.name).toBe('<b>x</b>');
  });
});

describe('normalizeEmail', () => {
  it('lowercases and trims the local and domain parts', () => {
    expect(normalizeEmail('  Test.User@Example.com  ')).toBe('test.user@example.com');
  });

  it('applies gmail-specific normalization (strips dots and subaddress tags)', () => {
    expect(normalizeEmail('Test.User+tag@gmail.com')).toBe('testuser@gmail.com');
  });

  it('returns an empty string for an empty input', () => {
    expect(normalizeEmail('')).toBe('');
  });

  it('does not throw for an unparsable email, delegating to validator.normalizeEmail as-is', () => {
    // validator.normalizeEmail treats a string with no '@' as an empty local part,
    // so it returns '@not-an-email' rather than '' or the original input unchanged.
    expect(normalizeEmail('not-an-email')).toBe('@not-an-email');
  });
});
