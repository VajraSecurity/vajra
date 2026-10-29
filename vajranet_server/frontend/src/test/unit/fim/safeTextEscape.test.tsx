import { cleanup, render } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { csvCell, hasInvisible, safeText, safeTokens } from '@/features/FileIntegrity/safeText';
import { RegText } from '@/features/FileIntegrity/UntrustedText';

afterEach(cleanup);

const RLO = String.fromCodePoint(0x202e);
/** The 10 literal characters an attacker can put in data to imitate an escape. */
const FAKE = '\u27E8U+202E\u27E9';

describe('safeText: escape markers cannot be imitated by data', () => {
  it('escapes a literal ⟨ so a literal "⟨U+202E⟩" is distinguishable from a real U+202E', () => {
    const real = safeText(`a${RLO}b`);
    const fake = safeText(`a${FAKE}b`);
    expect(real).toBe('a\u27E8U+202E\u27E9b');
    expect(fake).toBe('a\u27E8U+27E8\u27E9U+202E\u27E8U+27E9\u27E9b');
    expect(fake).not.toBe(real);
  });

  it('does not report a literal "⟨U+202E⟩" string as invisible', () => {
    expect(hasInvisible(`Run${FAKE}exe.lld`)).toBe(false);
    expect(hasInvisible(`Run${RLO}exe.lld`)).toBe(true);
  });

  it('returns structured tokens: hidden escape vs escaped literal bracket vs text', () => {
    expect(safeTokens(`x${RLO}y`)).toEqual([
      { kind: 'text', text: 'x' },
      expect.objectContaining({ kind: 'escape', codePoint: 0x202e, hex: 'U+202E', hidden: true, name: 'RIGHT-TO-LEFT OVERRIDE', description: 'Hidden character U+202E (RIGHT-TO-LEFT OVERRIDE)' }),
      { kind: 'text', text: 'y' },
    ]);
    const t = safeTokens(FAKE);
    expect(t[0]).toMatchObject({ kind: 'escape', codePoint: 0x27e8, hidden: false });
    expect(t[1]).toEqual({ kind: 'text', text: 'U+202E' });
    expect(t[2]).toMatchObject({ kind: 'escape', codePoint: 0x27e9, hidden: false, reason: 'lookalike' });
  });

  it('CSV export carries the unambiguous form', () => {
    expect(csvCell(FAKE)).toBe('"\u27E8U+27E8\u27E9U+202E\u27E8U+27E9\u27E9"');
  });
});

describe('RegText renders escapes as a distinct styled element', () => {
  it('renders a real U+202E as a styled hidden-character token with title and aria-label', () => {
    const { container } = render(<RegText value={`Run${RLO}exe.lld`} />);
    const marks = container.querySelectorAll('[data-fim-escape]');
    expect(marks).toHaveLength(1);
    const m = marks[0] as HTMLElement;
    expect(m.tagName).toBe('SPAN');
    expect(m).toHaveClass('fim-escape');
    expect(m.getAttribute('data-fim-hidden')).toBe('true');
    expect(m).toHaveAttribute('title', 'Hidden character U+202E (RIGHT-TO-LEFT OVERRIDE)');
    expect(m).toHaveAttribute('aria-label', 'Hidden character U+202E (RIGHT-TO-LEFT OVERRIDE)');
    expect(m.textContent).toBe('\u27E8U+202E\u27E9');
    // The real character itself never reaches the DOM.
    expect(container.textContent).not.toContain(RLO);
    expect(container.textContent).toContain('hidden chars');
  });

  it('renders a literal "⟨U+202E⟩" in data as text plus an escaped-bracket token, not as a hidden-character token', () => {
    const { container } = render(<RegText value={`Run${FAKE}exe.lld`} />);
    const marks = Array.from(container.querySelectorAll('[data-fim-escape]')) as HTMLElement[];
    expect(marks).toHaveLength(2);
    expect(marks[0].getAttribute('data-fim-escape')).toBe('U+27E8');
    expect(marks[1].getAttribute('data-fim-escape')).toBe('U+27E9');
    expect(marks[0].getAttribute('data-fim-hidden')).toBe('false');
    expect(container.querySelector('[data-fim-hidden="true"]')).toBeNull();
    expect(container.textContent).not.toContain('hidden chars');
  });

  it('leaves ordinary text as plain text', () => {
    const { container } = render(<RegText value={'C:\\Windows\\System32'} />);
    expect(container.querySelector('[data-fim-escape]')).toBeNull();
    expect(container.textContent).toBe('C:\\Windows\\System32');
  });
});
