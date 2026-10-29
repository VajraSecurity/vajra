import { describe, it, expect } from 'vitest';

import { encrypt, decrypt } from '../../../utils/encryption';

describe('encrypt/decrypt round-trip', () => {
  it.each([
    ['a simple ascii string', 'hello world'],
    ['an empty string', ''],
    ['a unicode string', '日本語テスト 🔒 emoji + accénts'],
  ])('decrypts back to the original plaintext for %s', (_label, plaintext) => {
    const { ciphertext, iv, authTag } = encrypt(plaintext);

    expect(decrypt(ciphertext, iv, authTag)).toBe(plaintext);
  });
});

describe('encrypt randomness', () => {
  it('produces a different iv and ciphertext for the same plaintext on repeated calls', () => {
    const first = encrypt('same plaintext');
    const second = encrypt('same plaintext');

    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });
});

describe('tamper detection', () => {
  it('throws when the ciphertext is modified', () => {
    const { ciphertext, iv, authTag } = encrypt('sensitive data');
    const tampered = flipHexChar(ciphertext);

    expect(() => decrypt(tampered, iv, authTag)).toThrow();
  });

  it('throws when the authTag is modified', () => {
    const { ciphertext, iv, authTag } = encrypt('sensitive data');
    const tampered = flipHexChar(authTag);

    expect(() => decrypt(ciphertext, iv, tampered)).toThrow();
  });

  it('throws when the iv is modified', () => {
    const { ciphertext, iv, authTag } = encrypt('sensitive data');
    const tampered = flipHexChar(iv);

    expect(() => decrypt(ciphertext, tampered, authTag)).toThrow();
  });
});

// Flips one hex digit so the resulting string is still valid hex of the same length,
// but decodes to different bytes.
function flipHexChar(hex: string): string {
  const chars = hex.split('');
  const idx = 0;
  const original = chars[idx];
  const replacement = original === '0' ? '1' : '0';
  chars[idx] = replacement;
  return chars.join('');
}
