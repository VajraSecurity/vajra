import { describe, expect, it } from 'vitest';
import { cn, formatUnixTimestamp, secureUUID } from '@/lib/utils';

describe('cn', () => {
  it('joins truthy class names', () => {
    expect(cn('a', 'b')).toBe('a b');
  });

  it('drops falsy values', () => {
    expect(cn('a', false, undefined, null, '', 'b')).toBe('a b');
  });

  it('lets a later Tailwind utility win over a conflicting earlier one', () => {
    // tailwind-merge's whole job: last conflicting class in the list wins,
    // rather than both being emitted (which is what plain clsx would do).
    expect(cn('px-2', 'px-4')).toBe('px-4');
  });
});

describe('secureUUID', () => {
  it('returns a well-formed v4 UUID', () => {
    const uuid = secureUUID();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('does not repeat across calls', () => {
    // Not a statistical randomness test — just confirms two calls don't
    // hand back the same buffer/string (e.g. from a broken CSPRNG fallback).
    const seen = new Set(Array.from({ length: 20 }, () => secureUUID()));
    expect(seen.size).toBe(20);
  });
});

describe('formatUnixTimestamp', () => {
  it('formats a unix-seconds timestamp (string or number) as a locale date/time', () => {
    // 2024-01-15T12:30:00Z
    const seconds = 1705321800;
    const fromNumber = formatUnixTimestamp(seconds);
    const fromString = formatUnixTimestamp(String(seconds));
    expect(fromNumber).toBe(fromString);
    expect(fromNumber).toContain('2024');
    expect(fromNumber).toContain('Jan');
  });

  it("returns 'N/A' for empty/falsy input", () => {
    expect(formatUnixTimestamp('')).toBe('N/A');
    expect(formatUnixTimestamp(0)).toBe('N/A');
  });
});
