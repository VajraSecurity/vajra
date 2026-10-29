import { describe, it, expect } from 'vitest';

import { VajraUser } from '../../../orm/entities/users/Users';
import { makeUser } from '../../factories';

describe('VajraUser.hashPassword', () => {
  it('replaces the plaintext password_hash with a hashed value', async () => {
    const plaintext = 'Sup3rSecret!Password';
    const user = makeUser({ password_hash: plaintext });

    await user.hashPassword();

    expect(user.password_hash).not.toBe(plaintext);
  });

  it('produces a value with a valid bcrypt hash prefix', async () => {
    const plaintext = 'Sup3rSecret!Password';
    const user = makeUser({ password_hash: plaintext });

    await user.hashPassword();

    expect(user.password_hash).toMatch(/^\$2/);
  });

  it('is a no-op that does not throw when password_hash is null', async () => {
    const user = makeUser({ password_hash: null });

    await expect(user.hashPassword()).resolves.not.toThrow();
    expect(user.password_hash).toBeNull();
  });
});

describe('VajraUser.checkIfPasswordMatch', () => {
  it('resolves to true when the plaintext password matches the hashed password_hash', async () => {
    const plaintext = 'Sup3rSecret!Password';
    const user = makeUser({ password_hash: plaintext });
    await user.hashPassword();

    await expect(user.checkIfPasswordMatch(plaintext)).resolves.toBe(true);
  });

  it('resolves to false when the plaintext password does not match the hashed password_hash', async () => {
    const plaintext = 'Sup3rSecret!Password';
    const user = makeUser({ password_hash: plaintext });
    await user.hashPassword();

    await expect(user.checkIfPasswordMatch('totally-wrong-password')).resolves.toBe(false);
  });

  it('resolves to false without throwing when password_hash is null', async () => {
    const user = makeUser({ password_hash: null });

    await expect(user.checkIfPasswordMatch('any-password')).resolves.toBe(false);
  });
});

describe('VajraUser construction', () => {
  it('can be constructed directly without a repository or database', () => {
    const user = new VajraUser();

    expect(user).toBeInstanceOf(VajraUser);
  });
});
